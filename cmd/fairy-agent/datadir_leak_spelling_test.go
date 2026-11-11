package main

// Audit 4, T-38: the Windows repair makes new tokens when another account could read a token file. Whether a
// token file was among the readable ones was looked up by the path's spelling: the repair's own spelling of
// the file against the spelling in config.yaml (token_file / control_token_file). With "/" for "\", another
// letter case or a "." in config.yaml the same file was not found: its permissions were repaired, the token
// that may have been read stayed in use, and nothing said "pair again".

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The whole repair on the test file system: config.yaml names the token file in another spelling of the same
// path. The token another account could read is replaced, and the output says so.
func TestLeakedTokenIsReplacedHoweverConfigSpellsItsPath(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	const old = "read-token-of-the-paired-panel-0123456789\r\n"
	sep := string(filepath.Separator)
	// other spellings of the same file that config.yaml may use (tokenPathProblem): on Windows forward slashes
	// (another letter case is judged in TestLeakedLookupKnowsWindowsSpellings), elsewhere a dot or a doubled
	// separator
	spellings := map[string]func(dir string) string{
		"as the repair spells it":  func(dir string) string { return filepath.Join(dir, "token") },
		"with a dot":               func(dir string) string { return dir + sep + "." + sep + "token" },
		"with a doubled separator": func(dir string) string { return dir + sep + sep + "token" },
	}
	if runtime.GOOS == "windows" {
		spellings = map[string]func(dir string) string{
			"as the repair spells it": func(dir string) string { return filepath.Join(dir, "token") },
			"with forward slashes":    func(dir string) string { return filepath.ToSlash(filepath.Join(dir, "token")) },
		}
	}
	for name, spell := range spellings {
		p := newPC(t)
		p.installed(t)
		p.put(t, "token", sddlHandRead, old) // another account has read access to the token file
		if why := tokenPathProblem(p.dir, spell(p.dir), runtime.GOOS == "windows"); why != "" {
			t.Fatalf("%s: not a spelling config.yaml may use on this system: %s", name, why)
		}
		p.put(t, "config.yaml", sddlDataFile, "token_file: '"+spell(p.dir)+"'\n")
		rep, out, err := p.run(t)
		if err != nil {
			t.Fatal(name, err)
		}
		if !rep.Leaked[filepath.Join(p.dir, "token")] {
			t.Fatalf("%s: the repair did not see the token as readable by others: %+v", name, rep)
		}
		if got := p.read(t, "token"); got == old {
			t.Errorf("%s: the token another account could read is still in use\n%s", name, out)
		}
		if !strings.Contains(out, "new token in") || !strings.Contains(out, "IMPORTANT: the tokens are new") {
			t.Errorf("%s: the output does not say that the token is new and the PC must be paired again:\n%s", name, out)
		}
	}
	// a file that was not readable by others keeps its token: the control token here
	p := newPC(t)
	p.installed(t)
	p.put(t, "token", sddlHandRead, old)
	ctl := p.read(t, "control-token")
	if _, _, err := p.run(t); err != nil {
		t.Fatal(err)
	}
	if p.read(t, "control-token") != ctl {
		t.Error("the control token, which nobody else could read, was replaced too")
	}
}

// The spellings Windows takes for one file, judged on every system: what config.yaml may say for
// C:\ProgramData\fairy-agent\token (tokenPathProblem accepts all of these) is found among the readable files.
func TestLeakedLookupKnowsWindowsSpellings(t *testing.T) {
	const dir = `C:\ProgramData\fairy-agent`
	rep := dirReport{Leaked: map[string]bool{dir + `\token`: true}}
	for _, s := range []string{`C:\ProgramData\fairy-agent\token`, `C:/ProgramData/fairy-agent/token`, `c:\programdata\FAIRY-AGENT\token`,
		`C:\ProgramData\fairy-agent\TOKEN`, `C:/programdata\fairy-agent/Token`} {
		if why := tokenPathProblem(dir, s, true); why != "" {
			t.Errorf("%s is not a spelling config.yaml may use: %s", s, why)
		}
		if !rep.leaked(s, true) {
			t.Errorf("%s: not found among the files another account could read (%v)", s, rep.Leaked)
		}
	}
	// the walk may have found the file under another case than config.yaml says
	if rep := (dirReport{Leaked: map[string]bool{`C:\ProgramData\fairy-agent\Token`: true}}); !rep.leaked(dir+`\token`, true) {
		t.Error("a file found as Token is not the token file of config.yaml")
	}
	for _, s := range []string{dir + `\control-token`, dir + `\token2`, dir + `\logs\token`, `C:\ProgramData\other\token`, dir} {
		if rep.leaked(s, true) {
			t.Errorf("%s was taken for the readable token file", s)
		}
	}
	// elsewhere a path is compared as it is, cleaned: case matters
	unix := dirReport{Leaked: map[string]bool{"/etc/fairy-agent/token": true}}
	if !unix.leaked("/etc/fairy-agent/./token", false) || !unix.leaked("/etc//fairy-agent/token", false) || unix.leaked("/etc/fairy-agent/TOKEN", false) {
		t.Error("the lookup for other systems")
	}
	if (dirReport{}).leaked(dir+`\token`, true) {
		t.Error("an empty report")
	}
}

// Review of the fix (R10): on Windows a token path with a "." part or a doubled separator never reached the
// lookup above. The check of what config.yaml may name (tokenPathProblem) refuses these spellings, so the file
// was left out of the list of token files, and a token another account could read kept its value. They mean
// nothing to the system, so they are taken out before the check. Judged with Windows' rules on every system:
// from the spelling in config.yaml to "is among the readable files".
func TestTokenFilesOfConfigWithDotsAndDoubledSeparators(t *testing.T) {
	const dir = `C:\ProgramData\fairy-agent`
	rep := dirReport{Leaked: map[string]bool{dir + `\token`: true}} // as the repair spells the file it found readable
	for _, s := range []string{
		`C:\ProgramData\fairy-agent\token`,
		`C:\ProgramData\fairy-agent\.\token`,
		`C:\ProgramData\fairy-agent\\token`,
		`C:\ProgramData\fairy-agent\.\.\\.\token`,
		`C:\ProgramData\.\fairy-agent\token`,
		`C:\\ProgramData\\fairy-agent\\token`,
		`C:/ProgramData/fairy-agent/./token`,
		`C:/ProgramData//fairy-agent/token`,
		`c:\PROGRAMDATA\.\Fairy-Agent\\TOKEN`,
	} {
		files := tokenFilesNamed(dir, []string{s}, true)
		if len(files) != 1 {
			t.Errorf("%s: not taken as a token file in the folder (%v)", s, files)
			continue
		}
		if why := tokenPathProblem(dir, files[0], true); why != "" {
			t.Errorf("%s became %s, which %s", s, files[0], why)
		}
		if !rep.leaked(files[0], true) {
			t.Errorf("%s (as %s): not found among the files another account could read", s, files[0])
		}
	}
	// Everything else that the check refuses is still refused: nothing is opened or written at such a path.
	for _, s := range []string{
		`C:\ProgramData\fairy-agent\logs\..\token`, `C:\ProgramData\fairy-agent\..\fairy-agent\token`, `C:\ProgramData\fairy-agent\..`,
		`C:\ProgramData\fairy-agent\token.`, `C:\ProgramData\fairy-agent\token `, `C:\ProgramData\fairy-agent\token::$DATA`,
		`\\?\C:\ProgramData\fairy-agent\token`, `\\server\share\token`, `//server/share/token`, `\\.\pipe\x`,
		`C:\PROGRA~3\fairy-agent\token`, `C:\ProgramData\fairy-agent\logs\.\token`, `C:\ProgramData\fairy-agent2\.\token`,
		`C:\ProgramData\fairy-agent\token\`, `C:\ProgramData\fairy-agent\.`, `C:\ProgramData\fairy-agent\\`, `token`, `.\token`, ``,
	} {
		if files := tokenFilesNamed(dir, []string{s}, true); len(files) != 0 {
			t.Errorf("%q is taken as a token file in the folder: %v", s, files)
		}
	}
	// a path with nothing to take out is passed on letter for letter
	if got := tokenFilesNamed(dir, []string{`C:/ProgramData/fairy-agent/token`, `c:\programdata\FAIRY-AGENT\control-token`}, true); len(got) != 2 ||
		got[0] != `C:/ProgramData/fairy-agent/token` || got[1] != `c:\programdata\FAIRY-AGENT\control-token` {
		t.Errorf("plain spellings were changed: %q", got)
	}
	// Known and still open: the file's own short (8.3) name is accepted as a token path and is not matched.
	short := tokenFilesNamed(dir, []string{`C:\ProgramData\fairy-agent\CONTRO~1`}, true)
	if len(short) != 1 || (dirReport{Leaked: map[string]bool{dir + `\control-token`: true}}).leaked(short[0], true) {
		t.Errorf("the short name case changed (%v): correct the comment at pathKey and the guide", short)
	}
	// elsewhere nothing changes: the check there cleans the path itself
	d := t.TempDir()
	sep := string(filepath.Separator)
	if runtime.GOOS != "windows" {
		for _, s := range []string{filepath.Join(d, "token"), d + sep + "." + sep + "token", d + sep + sep + "token"} {
			if got := tokenFilesNamed(d, []string{s}, false); len(got) != 1 || got[0] != s {
				t.Errorf("%s: %q", s, got)
			}
		}
	}
}
