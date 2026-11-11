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
