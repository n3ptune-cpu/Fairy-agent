package main

// N1 (review of the Windows side, L2 reopened): install and setup-self-update run as Administrator, with the
// privileges that take over any file switched on. The agent's own account may create, delete and change
// everything in logs\, state\ and update\stage\, so it can turn a folder there into a junction between the
// moment the installer looks at a name and the moment it uses it. These tests play that account against the
// repair, at every point where the repair looks at something: whatever the account does, nothing is changed
// by a name that leads through one of its folders, nothing outside the data folder is touched, and no
// permissions are passed on into anything it can write.
//
// The fake stands for NTFS in exactly the properties the attack needs: listing a folder and opening a path
// follow a link in the middle of the path (only the last name is opened "itself"), and a folder can become a
// link between two calls. On Windows the attacker stops the installer at the moment of its choice with an
// oplock on a bait file; here a hook on Stat and List does.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// racingFS runs a hook before every look (Stat, List): the agent's account, acting between two calls.
type racingFS struct {
	*fakeFS
	onStat func(path string)
	onList func(dir string)
}

func (r *racingFS) Stat(path string) (secObj, error) {
	if r.onStat != nil {
		r.onStat(path)
	}
	return r.fakeFS.Stat(path)
}

func (r *racingFS) List(dir string) ([]string, error) {
	if r.onList != nil {
		r.onList(dir)
	}
	return r.fakeFS.List(dir)
}

// agentMadeDir: a folder the agent's account made in one of its own folders (it owns what it creates there).
const agentMadeDir = "O:" + tSvc + "D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1301bf;;;" + tSvc + ")"

// outsideWorld is what the attacker aims at: C:\Program Files\Fairy with the program LocalSystem runs, and a
// file of the administrator's elsewhere. untouched fails the test when any of it was changed.
type outsideWorld struct {
	pf, exe, secret string
	sddl            map[string]string
}

func newOutside(t *testing.T, p *pc) *outsideWorld {
	t.Helper()
	w := &outsideWorld{pf: filepath.Join(p.root, "Program Files"), sddl: map[string]string{}}
	w.exe = filepath.Join(w.pf, "Fairy", "fairy-agent.exe")
	w.secret = filepath.Join(p.root, "Users", "admin", "secret.txt")
	for path, content := range map[string]string{w.exe: "the program LocalSystem runs", w.secret: "the administrator's own"} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	w.sddl[w.pf] = sddlProgramFiles
	w.sddl[filepath.Dir(w.exe)] = sddlProgramFiles
	w.sddl[w.exe] = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"
	w.sddl[filepath.Dir(w.secret)] = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	w.sddl[w.secret] = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)"
	for path, s := range w.sddl {
		p.fs.sddl[path] = s
	}
	return w
}

// seenThrough makes the outside world's security readable through a link at path that points to target, as
// the look would read it on Windows (the fake's table is keyed by the path as written).
func (w *outsideWorld) seenThrough(p *pc, link, target string) {
	for path, s := range w.sddl {
		if path == target || strings.HasPrefix(path, target+string(filepath.Separator)) {
			p.fs.sddl[link+strings.TrimPrefix(path, target)] = s
		}
	}
}

func (w *outsideWorld) untouched(t *testing.T, p *pc) {
	t.Helper()
	if b, err := os.ReadFile(w.exe); err != nil || string(b) != "the program LocalSystem runs" {
		t.Errorf("the program outside the data folder was moved or changed: %q %v", b, err)
	}
	if b, err := os.ReadFile(w.secret); err != nil || string(b) != "the administrator's own" {
		t.Errorf("a file outside the data folder was moved or changed: %q %v", b, err)
	}
	for path, s := range w.sddl {
		if p.fs.sddl[path] != s {
			t.Errorf("the permissions of %s (outside the data folder) were changed to %s", path, p.fs.sddl[path])
		}
	}
	for path, s := range p.fs.sddl { // also under the name the attacker's link gave it
		if strings.HasSuffix(path, filepath.Join("Fairy", "fairy-agent.exe")) || strings.HasSuffix(path, "Fairy") {
			if strings.Contains(s, "0x1301bf;;;"+tSvc) {
				t.Errorf("the agent's account now has Modify on %s: %s", path, s)
			}
		}
	}
}

// onlyInDataFolder: every changing call was on something that really is in the data folder, or next to it
// under the names the repair itself uses there (the old data folder moved aside, a folder parked for a moment).
func onlyInDataFolder(t *testing.T, p *pc) {
	t.Helper()
	real := func(path string) string {
		d, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return path
		}
		return filepath.Join(d, filepath.Base(path))
	}
	dir, _ := filepath.EvalSymlinks(p.pd)
	dir = filepath.Join(dir, dataFolderName)
	check := func(op, path string) {
		r := real(path)
		switch {
		case r == dir || strings.HasPrefix(r, dir+string(filepath.Separator)):
		case filepath.Dir(r) == filepath.Dir(dir) && (strings.HasPrefix(filepath.Base(r), dataFolderName+parkMark) || strings.HasPrefix(filepath.Base(r), dataFolderName+asideMark)):
		default:
			t.Errorf("the repair did %q on %s, which is outside the data folder (really %s)", op, path, r)
		}
	}
	for _, c := range p.fs.calls {
		op, path, _ := strings.Cut(c, " ")
		check(op, path)
	}
	for _, m := range p.fs.moves {
		check("move to", m[1])
	}
}

// The reviewer's proof, kept as it was written (it failed on b59a2d0: the walk set permissions on
// C:\Program Files\Fairy through the link, gave the agent's account Modify there and renamed the program).
// The walk is inside logs\aaa when logs\zz, looked at a moment ago, becomes a junction to C:\Program Files.
func TestRepairWalkDoesNotFollowAFolderThatBecameALink(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	p.put(t, "logs/aaa/", agentMadeDir, "")
	bait := p.put(t, "logs/aaa/0000", sddlAgentFile, "x")
	zz := p.put(t, "logs/zz/", agentMadeDir, "")

	// "C:\Program Files\Fairy\fairy-agent.exe", outside the data folder
	pf := filepath.Join(p.root, "Program Files")
	exe := filepath.Join(pf, "Fairy", "fairy-agent.exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("the program LocalSystem runs"), 0o755); err != nil {
		t.Fatal(err)
	}
	// their real security, as the walk will read it through the link
	p.fs.sddl[filepath.Join(zz, "Fairy")] = sddlProgramFiles
	p.fs.sddl[filepath.Join(zz, "Fairy", "fairy-agent.exe")] = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"

	flipped := false
	fs := &racingFS{fakeFS: p.fs}
	fs.onStat = func(path string) {
		if path == bait && !flipped { // the walk is inside logs\aaa; logs\zz was looked at a moment ago
			flipped = true
			if err := os.Remove(zz); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(pf, zz); err != nil {
				t.Skip("no symbolic links here:", err)
			}
		}
	}
	_, err := repairDataDir(fs, p.cfgPath, tSvc)
	t.Logf("repairDataDir: err=%v", err)
	if !flipped {
		t.Fatal("the hook never ran: the walk changed, adapt the test")
	}
	inside := func(path string) bool {
		real, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return true
		}
		dir, _ := filepath.EvalSymlinks(p.dir)
		return real == dir || strings.HasPrefix(real, dir+string(filepath.Separator))
	}
	for _, c := range p.fs.calls {
		op, path, _ := strings.Cut(c, " ")
		if !inside(path) {
			real, _ := filepath.EvalSymlinks(filepath.Dir(path))
			t.Errorf("the repair did %q on %s, which is outside the data folder (really %s)", op, path, filepath.Join(real, filepath.Base(path)))
		}
	}
	if _, err := os.Stat(exe); err != nil {
		t.Errorf("the program outside the data folder was moved: %v", err)
	}
	if s := p.fs.sddl[filepath.Join(zz, "Fairy")]; strings.Contains(s, "0x1301bf;;;"+tSvc) {
		t.Errorf("the agent's account now has Modify on %s: %s", filepath.Join(pf, "Fairy"), s)
	}
	// and what the repair did instead: nothing through the link, logs\ replaced as a whole
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(p.fs.calls, "\n"); strings.Contains(got, "secure ") || strings.Contains(got, "remove ") || strings.Contains(got, "rewrite ") {
		t.Errorf("calls:\n%s", got)
	}
}

// A junction is swapped in between check and use, at every look the repair makes. Each run is a healthy PC
// plus one empty folder the agent's account made in one of its folders; at look number n that folder (or the
// agent's folder itself, when it is empty) becomes a link to C:\Program Files or to the administrator's
// folder, and the run goes on. Whatever n is, the rules hold.
func TestJunctionSwappedInBetweenCheckAndUse(t *testing.T) {
	if err := os.Symlink(t.TempDir(), filepath.Join(t.TempDir(), "l")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	type scenario struct {
		name string
		prep func(p *pc)             // what the PC looks like before the run
		swap func(p *pc) (at string) // the path that becomes a link
	}
	scenarios := []scenario{
		{"a folder in logs\\", func(p *pc) { p.put(t, "logs/aaa/", agentMadeDir, ""); p.put(t, "logs/aaa/sub/", agentMadeDir, "") },
			func(p *pc) string { return filepath.Join(p.dir, "logs", "aaa", "sub") }},
		{"a folder in state\\", func(p *pc) { p.put(t, "state/x/", agentMadeDir, "") },
			func(p *pc) string { return filepath.Join(p.dir, "state", "x") }},
		{"a folder in update\\stage\\", func(p *pc) { p.put(t, "update/stage/dl/", agentMadeDir, "") },
			func(p *pc) string { return filepath.Join(p.dir, "update", "stage", "dl") }},
		{"the agent's folder itself, emptied", func(p *pc) { _ = os.Remove(filepath.Join(p.dir, "state", "pairing.json")) },
			func(p *pc) string { return filepath.Join(p.dir, "state") }},
		// the data folder needs its permissions set (someone else could read it): Windows passes them on, so the
		// agent's folders are moved out for that moment; the swap also happens while they are out
		{"a folder in logs\\, while the data folder's permissions are set", func(p *pc) {
			p.put(t, "logs/aaa/", agentMadeDir, "")
			p.fs.sddl[p.dir] = sddlDataDir + "(A;OICI;0x1200a9;;;BU)"
		}, func(p *pc) string { return filepath.Join(p.dir, "logs", "aaa") }},
		{"update\\stage\\ itself, while the permissions of update\\ are set", func(p *pc) {
			_ = os.Remove(filepath.Join(p.dir, "update", "stage", "request.json"))
			p.fs.sddl[filepath.Join(p.dir, "update")] = strings.Replace(sddlDataDir, "O:BA", "O:SY", 1) + "(A;OICI;0x1200a9;;;BU)"
		}, func(p *pc) string { return filepath.Join(p.dir, "update", "stage") }},
	}
	for _, sc := range scenarios {
		for _, toAdmin := range []bool{false, true} {
			looks, swapped := 0, 0
			for n := 1; n <= 400; n++ {
				p := newPC(t)
				p.installed(t)
				out := newOutside(t, p)
				sc.prep(p)
				at := sc.swap(p)
				target := out.pf
				if toAdmin {
					target = filepath.Dir(out.secret)
				}
				count, done := 0, false
				fs := &racingFS{fakeFS: p.fs}
				flip := func(string) {
					if count++; count != n || done {
						return
					}
					done = true
					// the agent's account may delete an empty folder it can write and put a link in its place only
					// where it may create names; the folder itself it can turn into a junction wherever it is
					cur := at
					if _, err := os.Lstat(cur); err != nil { // parked next to the data folder at this moment?
						for _, m := range p.fs.moves {
							if rest, ok := strings.CutPrefix(at, m[0]); ok {
								if _, err := os.Lstat(m[1] + rest); err == nil {
									cur = m[1] + rest
								}
							}
						}
					}
					if err := os.Remove(cur); err != nil {
						return // not there, or not empty (any more): the account cannot make it a junction now
					}
					if err := os.Symlink(target, cur); err != nil {
						t.Fatal(err)
					}
					out.seenThrough(p, cur, target)
					out.seenThrough(p, at, target)
					swapped++
				}
				fs.onStat, fs.onList = flip, flip
				_, err := repairDataDir(fs, p.cfgPath, tSvc)
				if n > count {
					looks = count
				}
				out.untouched(t, p)
				onlyInDataFolder(t, p)
				if t.Failed() {
					t.Fatalf("%s, link to %s, swapped in at look %d of the run (err %v)\ncalls:\n%s", sc.name, target, n, err, strings.Join(p.fs.calls, "\n"))
				}
				// whatever happened, running it again (the agent's account keeps still) ends with a folder that can be used
				p.fs.calls = nil
				if _, err := repairDataDir(p.fs, p.cfgPath, tSvc); err != nil {
					t.Fatalf("%s, swapped in at look %d: the next run fails: %v", sc.name, n, err)
				}
				out.untouched(t, p)
				onlyInDataFolder(t, p)
				if err := checkDataDir(p.fs, p.cfgPath, tSvc, "update", "helper", "logs", "state", "update/stage"); err != nil {
					t.Fatalf("%s, swapped in at look %d: after the next run: %v", sc.name, n, err)
				}
				if p.read(t, "token") != "read-token-of-the-paired-panel-0123456789\r\n" && !strings.Contains(sc.name, "permissions are set") {
					t.Fatalf("%s, swapped in at look %d: the token was replaced", sc.name, n)
				}
				if looks != 0 {
					break // n is past the last look of a run
				}
			}
			if looks == 0 || swapped < 3 {
				t.Fatalf("%s: the run made %d looks and the swap happened %d times: the test does not test anything", sc.name, looks, swapped)
			}
		}
	}
}

// A hard link inside one of the agent's folders: a second name of some file elsewhere (the agent's account
// can give a file it may write a second name). The repair does not set permissions on it, rename it or delete
// it under that name, as it did before (a file has one set of permissions, whatever name is used): the folder
// is replaced as a whole.
func TestHardLinkInsideAnAgentFolder(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	out := newOutside(t, p)
	second := filepath.Join(p.dir, "state", "other-name")
	if err := os.Link(out.secret, second); err != nil {
		t.Skip("no hard links here:", err)
	}
	p.fs.sddl[second] = out.sddl[out.secret] // the same file: the same owner and permissions
	p.fs.links[second], p.fs.links[out.secret] = 2, 2
	rep, err := repairDataDir(p.fs, p.cfgPath, tSvc)
	if err != nil {
		t.Fatal(err)
	}
	out.untouched(t, p)
	onlyInDataFolder(t, p)
	if len(rep.Zones) != 1 || rep.Zones[0] != "state" || !strings.Contains(strings.Join(rep.Notes, "\n"), "more than one name") {
		t.Fatalf("%v\n%v", rep.Zones, rep.Notes)
	}
	// the only calls: the folder for what is moved aside, the move of state\ as a whole, a new state\
	want := []string{"mkdir " + filepath.Join(p.dir, asideDir+p.fs.Stamp()), "move " + filepath.Join(p.dir, "state"), "mkdir " + filepath.Join(p.dir, "state")}
	if strings.Join(p.fs.calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(p.fs.calls, "\n"), strings.Join(want, "\n"))
	}
	// the second name went with the folder; the file is what it was
	if _, err := os.Lstat(filepath.Join(rep.Aside[0], "other-name")); err != nil {
		t.Fatal(err)
	}
}

// A file is replaced by a folder (or by a link to one) between the look at it and what follows: state\
// pairing.json and logs\agent.log are files when the run starts.
func TestFileReplacedByAFolder(t *testing.T) {
	for _, asLink := range []bool{false, true} {
		for _, rel := range []string{"state/pairing.json", "logs/agent.log", "update/stage/request.json"} {
			for n := 1; n <= 3; n++ { // at the first, second, third look at that name or its folder
				p := newPC(t)
				p.installed(t)
				out := newOutside(t, p)
				victim := filepath.Join(p.dir, filepath.FromSlash(rel))
				count := 0
				fs := &racingFS{fakeFS: p.fs}
				flip := func(path string) {
					if path != victim && path != filepath.Dir(victim) {
						return
					}
					if count++; count != n {
						return
					}
					if err := os.Remove(victim); err != nil {
						t.Fatal(err)
					}
					if asLink {
						if err := os.Symlink(filepath.Dir(out.exe), victim); err != nil {
							t.Skip("no symbolic links here:", err)
						}
						out.seenThrough(p, victim, filepath.Dir(out.exe))
						return
					}
					if err := os.MkdirAll(filepath.Join(victim, "deeper"), 0o755); err != nil {
						t.Fatal(err)
					}
					p.fs.sddl[victim], p.fs.sddl[filepath.Join(victim, "deeper")] = agentMadeDir, agentMadeDir
				}
				fs.onStat, fs.onList = flip, flip
				if _, err := repairDataDir(fs, p.cfgPath, tSvc); err != nil {
					t.Fatalf("%s (link %v) at look %d: %v", rel, asLink, n, err)
				}
				out.untouched(t, p)
				onlyInDataFolder(t, p)
				for _, c := range p.fs.calls {
					if strings.HasPrefix(c, "secure ") || strings.HasPrefix(c, "remove ") || strings.HasPrefix(c, "rewrite ") || strings.HasPrefix(c, "setowner ") {
						t.Errorf("%s (link %v) at look %d: %s", rel, asLink, n, c)
					}
				}
			}
		}
	}
}

// Deep nesting in one of the agent's folders, with a link at the bottom or a link that appears on the way
// down: the walk does not go down without end, does not fail (the agent's account could otherwise stop every
// installer run), and changes nothing below the folder.
func TestDeepNestingInAnAgentFolder(t *testing.T) {
	deep := func(levels int) string {
		rel := "logs"
		for i := 0; i < levels; i++ {
			rel += "/d"
		}
		return rel
	}
	// deeper than the walk goes
	p := newPC(t)
	p.installed(t)
	out := newOutside(t, p)
	bottom := p.put(t, deep(repairMaxDepth+6)+"/", agentMadeDir, "")
	for d := bottom; d != filepath.Join(p.dir, "logs"); d = filepath.Dir(d) {
		p.fs.sddl[d] = agentMadeDir
	}
	if err := os.Symlink(out.pf, filepath.Join(bottom, "link")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	rep, err := repairDataDir(p.fs, p.cfgPath, tSvc)
	if err != nil || len(rep.Zones) != 1 || rep.Zones[0] != "logs" {
		t.Fatal(err, rep.Zones, rep.Notes)
	}
	out.untouched(t, p)
	onlyInDataFolder(t, p)
	if _, err := os.Lstat(filepath.Join(rep.Aside[0], filepath.FromSlash(strings.TrimPrefix(deep(repairMaxDepth+6), "logs/")), "link")); err != nil {
		t.Fatalf("the nested folders did not move as they were: %v", err)
	}
	// within the depth the walk goes to: every level is looked at, and the link at the bottom is found
	p = newPC(t)
	p.installed(t)
	out = newOutside(t, p)
	bottom = p.put(t, deep(repairMaxDepth-1)+"/", agentMadeDir, "")
	for d := bottom; d != filepath.Join(p.dir, "logs"); d = filepath.Dir(d) {
		p.fs.sddl[d] = agentMadeDir
	}
	if rep, err := repairDataDir(p.fs, p.cfgPath, tSvc); err != nil || len(rep.Zones) != 0 || len(p.fs.calls) != 0 {
		t.Fatalf("folders the agent's account made, nested %d deep, are not a fault: %v %v %v", repairMaxDepth-1, err, rep.Zones, p.fs.calls)
	}
	_ = os.Symlink(out.pf, filepath.Join(bottom, "link"))
	rep, err = repairDataDir(p.fs, p.cfgPath, tSvc)
	if err != nil || len(rep.Zones) != 1 || !strings.Contains(strings.Join(rep.Notes, "\n"), "is a link") {
		t.Fatal(err, rep.Zones, rep.Notes)
	}
	out.untouched(t, p)
	onlyInDataFolder(t, p)
	// a folder stuffed with more names than the walk counts
	if testing.Short() {
		return
	}
	p = newPC(t)
	p.installed(t)
	stuffed := filepath.Join(p.dir, "update", "stage", "many")
	if err := os.Mkdir(stuffed, 0o755); err != nil {
		t.Fatal(err)
	}
	p.fs.sddl[stuffed] = agentMadeDir
	for i := 0; i < repairMaxEntries+10; i++ {
		if err := os.WriteFile(filepath.Join(stuffed, "f"+strings.Repeat("0", 5-len(itoa(i)))+itoa(i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p.fs.sddl[filepath.Join(stuffed, "f00000")] = sddlAgentFile
	rep, err = repairDataDir(&ownedByAgent{p.fs, stuffed}, p.cfgPath, tSvc)
	if err != nil || len(rep.Zones) != 1 || rep.Zones[0] != "update/stage" || !strings.Contains(strings.Join(rep.Notes, "\n"), "holds more than") {
		t.Fatal(err, rep.Zones, rep.Notes)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	s := ""
	for ; i > 0; i /= 10 {
		s = string(rune('0'+i%10)) + s
	}
	return s
}

// ownedByAgent answers for everything below dir like a file the agent's account made (20000 table entries
// would only slow the test down).
type ownedByAgent struct {
	*fakeFS
	dir string
}

func (f *ownedByAgent) Stat(path string) (secObj, error) {
	if filepath.Dir(path) != f.dir {
		return f.fakeFS.Stat(path)
	}
	if _, err := os.Lstat(path); err != nil {
		return secObj{}, err
	}
	o := parseSDDL(f.t, sddlAgentFile)
	o.Links = 1
	return o, nil
}

// What the owner keeps and loses when one of the agent's folders is replaced: everything that was in it is in
// the folder moved aside, byte for byte and untouched; config.yaml and the tokens are not affected (the PC
// stays paired); the output says what is gone; and the next run changes nothing.
func TestReplacedAgentFolderKeepsItsContentAside(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	p.put(t, "logs/planted.txt", sddlPlantedFile, "by someone else")
	p.put(t, "state/x/", agentMadeDir, "")
	if err := os.Symlink(p.root, filepath.Join(p.dir, "state", "x", "j")); err != nil {
		t.Skip("no symbolic links here:", err)
	}
	tok, ctl, cfg := p.read(t, "token"), p.read(t, "control-token"), p.read(t, "config.yaml")
	rep, out, err := p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(rep.Zones, ",") != "logs,state" || len(rep.Aside) != 2 {
		t.Fatalf("%v %v", rep.Zones, rep.Aside)
	}
	asideAt := filepath.Join(p.dir, asideDir+p.fs.Stamp())
	for path, want := range map[string]string{"logs/agent.log": "log\n", "logs/agent.log.1": "older log\n", "logs/planted.txt": "by someone else",
		"state/pairing.json": `{"closed":"paired"}`} {
		if b, err := os.ReadFile(filepath.Join(asideAt, filepath.FromSlash(path))); err != nil || string(b) != want {
			t.Errorf("%s is not in the folder moved aside as it was: %q %v", path, b, err)
		}
	}
	if st, err := os.Lstat(filepath.Join(asideAt, "state", "x", "j")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was not left as it was in the folder moved aside: %v", err)
	}
	// the permissions of what was moved are not touched (nothing is passed on into what was prepared)
	if s := p.fs.sddl[filepath.Join(asideAt, "logs")]; s != sddlAgentDir {
		t.Errorf("the moved folder's permissions: %s", s)
	}
	if s := p.fs.sddl[filepath.Join(asideAt, "logs", "planted.txt")]; s != sddlPlantedFile {
		t.Errorf("the planted file's permissions: %s", s)
	}
	// update\stage\ had nothing wrong in it: it is exactly as it was
	if p.read(t, "update/stage/request.json") != "{}" {
		t.Error("update\\stage\\ was touched")
	}
	if p.read(t, "token") != tok || p.read(t, "control-token") != ctl || p.read(t, "config.yaml") != cfg ||
		strings.Contains(out, "IMPORTANT") || strings.Contains(out, "new token") {
		t.Fatalf("the PC was unpaired because of something in the agent's own folders:\n%s", out)
	}
	for _, want := range []string{"the whole folder was moved", "the old log files are in the moved folder", "The tokens are not affected", asideAt} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	p.usable(t)
	p.fs.calls = nil
	if _, out, err := p.run(t); err != nil || out != "" || len(p.fs.calls) != 0 {
		t.Fatalf("second run: %v %q %v", err, out, p.fs.calls)
	}
	// a later run with something new to move aside uses a folder of its own and still does not look into the first
	p.put(t, "state/again", sddlPlantedFile, "x")
	rep, _, err = p.run(t)
	if err != nil || len(rep.Aside) != 1 || filepath.Dir(rep.Aside[0]) != asideAt+"-2" {
		t.Fatal(err, rep.Aside)
	}
}

// update\ as 0.3 to 0.4.2 made it: the service's account may write it, and it downloaded into it. An
// administrator's repair does not set its permissions in place (they would be passed on into what the agent's
// account can still change in that moment): the folder is moved aside as a whole and a new one is made.
func TestUpdateFolderOf042IsReplaced(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	p.fs.sddl[filepath.Join(p.dir, "update")] = sddlAgentDir
	p.put(t, "update/fairy-agent-windows-amd64.exe", sddlLocalServiceFile, "MZ")
	tok := p.read(t, "token")
	rep, out, err := p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.fs.did("move"); len(got) != 1 || got[0] != filepath.Join(p.dir, "update") || len(p.fs.did("secure")) != 0 {
		t.Fatalf("%v", p.fs.calls)
	}
	if len(rep.Zones) != 0 || p.read(t, "token") != tok || strings.Contains(out, "IMPORTANT") {
		t.Fatalf("%+v\n%s", rep, out)
	}
	p.usable(t)
}

// The moment a folder's permissions are set is the only one in which Windows passes anything on. When one of
// the agent's folders cannot be moved out for it (a file in it is open: the agent is still running), nothing
// is set, what was already moved out is put back, and the message says what to stop.
func TestParkingFailsCleanly(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	p.fs.sddl[p.dir] = sddlDataDir + "(A;OICI;0x1200a9;;;BU)"
	fs := &failingMove{fakeFS: p.fs, fail: filepath.Join(p.dir, "state")}
	_, err := repairDataDir(fs, p.cfgPath, tSvc)
	if err == nil || !strings.Contains(err.Error(), "Stop-Service") || !strings.Contains(err.Error(), filepath.Join(p.dir, "state")) {
		t.Fatal(err)
	}
	if len(p.fs.did("secure")) != 0 {
		t.Fatalf("permissions were set although state\\ was still below: %v", p.fs.calls)
	}
	if p.read(t, "logs/agent.log") != "log\n" || p.read(t, "state/pairing.json") != `{"closed":"paired"}` {
		t.Fatal("what was moved out was not put back")
	}
	if ents, _ := os.ReadDir(p.pd); len(ents) != 1 {
		t.Fatalf("something was left next to the data folder: %v", ents)
	}
	// with the services stopped it goes through
	if _, _, err := p.run(t); err != nil {
		t.Fatal(err)
	}
	p.usable(t)
}

type failingMove struct {
	*fakeFS
	fail string
}

func (f *failingMove) Move(from, to string) error {
	if from == f.fail {
		return errors.New("The process cannot access the file because it is being used by another process.")
	}
	return f.fakeFS.Move(from, to)
}

// ensure, which join, setup-self-update and the migration use for single folders, goes into one of the
// agent's folders even less: it does not look inside, removes nothing there, and sets no permissions that
// would be passed on. (Before, it removed every link below such a folder by name and then set permissions.)
func TestEnsureNeverGoesInsideAnAgentFolder(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	out := newOutside(t, p)
	state := filepath.Join(p.dir, "state")
	p.put(t, "state/a/b/", agentMadeDir, "")
	p.fs.sddl[filepath.Join(state, "a")] = agentMadeDir
	links := []string{filepath.Join(state, "junction"), filepath.Join(state, "a", "b", "deep")}
	for _, l := range links {
		if err := os.Symlink(filepath.Dir(out.exe), l); err != nil {
			t.Skip("no symbolic links here:", err)
		}
	}
	looked := 0
	fs := &racingFS{fakeFS: p.fs}
	fs.onList = func(string) { looked++ }
	fs.onStat = func(path string) {
		if path != state {
			looked++
		}
	}
	var notes []string
	f := folders{fs: fs, hint: repairHint, note: func(format string, a ...any) { notes = append(notes, format) }}
	// the folder belongs to the agent's account: only its owner is set
	p.fs.sddl[state] = strings.Replace(sddlAgentDir, "O:BA", "O:"+tSvc, 1)
	if err := f.ensure(state, folderSpec{tSvc, true}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(p.fs.calls, "\n") != "setowner "+state || looked != 0 || len(notes) != 0 {
		t.Fatalf("calls: %v, looks inside: %d, notes: %v", p.fs.calls, looked, notes)
	}
	// as it should be: not written to at all, links inside or not
	p.fs.calls = nil
	if err := f.ensure(state, folderSpec{tSvc, true}); err != nil || len(p.fs.calls) != 0 || looked != 0 {
		t.Fatal(err, p.fs.calls, looked)
	}
	// other permissions: refused, nothing changed
	p.fs.sddl[state] = sddlAgentDir + "(A;OICI;0x1200a9;;;BU)"
	if err := f.ensure(state, folderSpec{tSvc, true}); err == nil || !strings.Contains(err.Error(), "setup-self-update") || len(p.fs.calls) != 0 || looked != 0 {
		t.Fatal(err, p.fs.calls, looked)
	}
	for _, l := range links {
		if st, err := os.Lstat(l); err != nil || st.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("%s was touched: %v", l, err)
		}
	}
	out.untouched(t, p)
	// install / setup-self-update then replace the folder as a whole
	rep, err := repairDataDir(p.fs, p.cfgPath, tSvc)
	if err != nil || strings.Join(rep.Zones, ",") != "state" {
		t.Fatal(err, rep.Zones)
	}
	out.untouched(t, p)
	onlyInDataFolder(t, p)
}

// Another --config folder (not ...\fairy-agent): nothing in it is moved, also not one of the agent's folders.
func TestOtherConfigFolderKeepsItsAgentFolders(t *testing.T) {
	p := newPC(t)
	other := filepath.Join(p.root, "FairyData")
	p.fs.dataDir = other
	if err := os.MkdirAll(filepath.Join(other, "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	p.fs.sddl[other] = sddlDataDir
	p.fs.sddl[filepath.Join(other, "logs")] = sddlAgentDir
	_ = os.WriteFile(filepath.Join(other, "logs", "x"), []byte("x"), 0o644)
	p.fs.sddl[filepath.Join(other, "logs", "x")] = sddlPlantedFile
	_, err := repairDataDir(p.fs, filepath.Join(other, "config.yaml"), tSvc)
	if err == nil || !strings.Contains(err.Error(), "not the standard data folder") || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
}
