//go:build windows

package main

// The Win32 side of the data folder checks (datadir_windows.go), run against the PC the tests run on. The
// decisions are tested with real permission lists as fixtures on every system (datadir_test.go); these tests
// are about what only Windows itself can show: that a junction is seen as a link, that a new folder gets its
// permissions in the call that creates it, and that a file written into a folder takes that folder's
// permissions. They need no administrator rights and no installed service: every folder is the test's own, in
// its temporary folder, with permissions that name the user who runs the test.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// currentUserSID is the account the tests run as.
func currentUserSID(t *testing.T) string {
	t.Helper()
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return u.User.Sid.String()
}

// A junction is what an ordinary user can put where a folder or a file belongs. The Win32 side opens every
// object itself and must report it as a link: the checks then refuse it whatever it leads to (judge), and the
// repair removes the link and never what it points to.
func TestWindowsSeesAJunctionAsALink(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(target, "config.yaml")
	if err := os.WriteFile(inside, []byte("x: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// plain things first: a folder and a file, each with an owner and a permission list that can be read
	for path, dir := range map[string]bool{target: true, inside: false} {
		o, err := winFS{}.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if o.Dir != dir || o.Reparse || o.Owner == "" || o.NullDACL || len(o.ACEs) == 0 || (!dir && o.Links != 1) {
			t.Fatalf("%s: %+v", path, o)
		}
	}
	if _, err := (winFS{}).Stat(filepath.Join(base, "missing")); !os.IsNotExist(err) {
		t.Fatalf("a missing file: %v", err)
	}
	// a junction under a folder's name and under config.yaml's name
	for _, name := range []string{"fairy-agent", "config.yaml"} {
		link := filepath.Join(base, name)
		if err := mklink(target, link); err != nil {
			t.Skip("no junction could be made here:", err)
		}
		o, err := winFS{}.Stat(link)
		if err != nil {
			t.Fatal(err)
		}
		if !o.Reparse {
			t.Fatalf("%s is a junction and was not seen as a link: %+v", link, o)
		}
		for _, wantDir := range []bool{true, false} {
			if lv, why := judge(o, wantDir, false, false, ""); lv != lvForeign || !strings.Contains(why, "is a link") {
				t.Fatalf("%s as a link (folder wanted: %v): level %d, %q", name, wantDir, lv, why)
			}
		}
		// the repair's Remove takes the link away and leaves what it points to
		if err := (winFS{}).Remove(link); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(link); !os.IsNotExist(err) {
			t.Fatalf("the link is still there: %v", err)
		}
		if b, err := os.ReadFile(inside); err != nil || string(b) != "x: 1\n" {
			t.Fatalf("removing the link touched what it pointed to: %q %v", b, err)
		}
	}
	// and Remove is for links only
	if err := (winFS{}).Remove(target); err == nil || !strings.Contains(err.Error(), "is not a link") {
		t.Fatalf("Remove on a plain folder: %v", err)
	}
	if _, err := os.Stat(inside); err != nil {
		t.Fatal(err)
	}
}

// The real check on a folder it must refuse: a temporary folder belongs to the user who made it, or can be
// changed by that user. Nothing is changed by the check.
func TestWindowsCheckRefusesAFolderOfTheTestsUser(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("power_control: {enabled: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o, err := winFS{}.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	err = trustedDataDir(cfg)
	if lv, _ := judge(o, true, false, false, ""); lv < lvAgent && err == nil {
		// e.g. run as SYSTEM in a folder only administrators can change: there is nothing to refuse
		t.Skip("this temporary folder can only be changed by administrators")
	}
	if err == nil {
		t.Fatalf("the check accepts a folder that someone other than administrators controls: %+v", o)
	}
	if !strings.Contains(err.Error(), "cannot be trusted") || !strings.Contains(err.Error(), "setup-self-update") {
		t.Fatal(err)
	}
	if err := updateDirTrusted(cfg); err == nil {
		t.Fatal("the updater's check accepts it")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("the check changed the folder: %v", ents)
	}
	// a path that is not on a local drive is refused before anything is opened
	for _, p := range []string{`\\server\share\fairy-agent\config.yaml`, `\\?\C:\ProgramData\fairy-agent\config.yaml`} {
		if err := trustedDataDir(p); err == nil || !strings.Contains(err.Error(), "local drive") {
			t.Errorf("%s: %v", p, err)
		}
	}
}

// What protects the files in the data folder on Windows is the folder: a file has no mode bits, it takes the
// permissions its folder passes on. This makes a folder the way the installer does (the permissions are given
// in the call that creates it), and then writes into it the way the product does: the pairing state as join
// writes it and as the running agent writes it, and a file that is rewritten because someone else could read
// it. Every one of them must end up with exactly what the folder passes on and nothing of its own.
func TestWindowsFilesTakeTheFoldersPermissions(t *testing.T) {
	me := currentUserSID(t)
	state := filepath.Join(t.TempDir(), "state")
	// the folder's own, protected list: full control for the user who runs the test, passed on to everything
	// inside; nothing from the folder above
	if err := (winFS{}).Mkdir(state, "D:PAI(A;OICI;FA;;;"+me+")"); err != nil {
		t.Fatal(err)
	}
	o, err := winFS{}.Stat(state)
	if err != nil {
		t.Fatal(err)
	}
	if !o.Dir || o.Reparse || o.NullDACL || !o.Protected || len(o.ACEs) != 1 ||
		o.ACEs[0] != (collect.ACE{Kind: collect.ACEAllow, Flags: 0x3, SID: me, Mask: rtFileAll}) {
		t.Fatalf("the new folder does not have the permissions it was created with: %+v", o)
	}
	if err := (winFS{}).Mkdir(state, "D:PAI(A;OICI;FA;;;"+me+")"); !os.IsExist(err) {
		t.Fatalf("creating it again: %v", err)
	}
	inherited := func(what, path string) {
		t.Helper()
		o, err := winFS{}.Stat(path)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		const inheritedACE = 0x10
		if o.Dir || o.Reparse || o.Links != 1 || o.NullDACL || o.Protected || len(o.ACEs) != 1 ||
			o.ACEs[0] != (collect.ACE{Kind: collect.ACEAllow, Flags: inheritedACE, SID: me, Mask: rtFileAll}) {
			t.Fatalf("%s: the file does not have exactly what its folder passes on: %+v", what, o)
		}
	}
	st := stateForTest()
	// join: through the opened folder
	if err := writePairingState(state, st); err != nil {
		t.Fatal(err)
	}
	inherited("the pairing state as join writes it", filepath.Join(state, "pairing.json"))
	// the running agent: enroll.WriteState, over the file that is there
	if err := enroll.WriteState(filepath.Join(state, "pairing.json"), st); err != nil {
		t.Fatal(err)
	}
	inherited("the pairing state as the agent writes it", filepath.Join(state, "pairing.json"))
	// a file with a list of its own that lets everyone read it: rewritten, it is a new file with the folder's
	// permissions (what the repair does with a file someone else could read)
	leaky := filepath.Join(state, "token")
	if err := os.WriteFile(leaky, []byte("a-token\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (winFS{}).Secure(leaky, "D:PAI(A;;FA;;;"+me+")(A;;FR;;;WD)"); err != nil {
		t.Fatal(err)
	}
	o, err = winFS{}.Stat(leaky)
	if err != nil || !o.Protected || len(o.ACEs) != 2 {
		t.Fatalf("the file's own permissions were not set: %+v %v", o, err)
	}
	if lv, why := judge(o, false, false, false, ""); lv != lvForeign && lv != lvLeak {
		t.Fatalf("a file everyone may read is not held against it: %d %q", lv, why)
	}
	before := fileItself(t, leaky)
	if err := (winFS{}).Rewrite(leaky); err != nil {
		t.Fatal(err)
	}
	inherited("the rewritten file", leaky)
	if b, _ := os.ReadFile(leaky); string(b) != "a-token\r\n" || os.SameFile(before, fileItself(t, leaky)) {
		t.Fatalf("not a new file with the same content: %q", b)
	}
	if ents, _ := os.ReadDir(state); len(ents) != 2 {
		t.Fatalf("temporary files were left behind: %v", ents)
	}
}
