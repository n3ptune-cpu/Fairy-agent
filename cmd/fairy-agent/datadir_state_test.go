package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

func stateForTest() enroll.State {
	return enroll.State{Version: 1, Panel: "100.64.0.10", CreatedAt: 1_800_000_000, ExpiresAt: 1_800_000_900, Key2: strings.Repeat("ab", 32)}
}

// N11 (review of the Windows side): join put pairing.json into state\ by path, as Administrator, after a
// check of that folder. The agent's account can write state\: it can empty it and turn it into a junction
// between the check and the write, and the administrator's file then replaces a pairing.json in a folder of
// that account's choosing. The file is now written relative to the opened folder, and the opened folder must
// be the plain folder that is under the name.
func TestPairingStateIsWrittenIntoTheFolderItself(t *testing.T) {
	st := stateForTest()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o755); err != nil {
		t.Fatal(err)
	}
	// 1. the plain case: the same bytes enroll.WriteState writes, an existing file replaced in one step
	ref := filepath.Join(t.TempDir(), "pairing.json")
	if err := enroll.WriteState(ref, st); err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile(ref)
	_ = os.WriteFile(filepath.Join(state, "pairing.json"), []byte("old"), 0o600)
	if err := writePairingState(state, st); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(state, "pairing.json")); string(got) != string(want) || len(want) == 0 {
		t.Fatalf("not what enroll.WriteState writes:\n%s\n%s", got, want)
	}
	if ents, _ := os.ReadDir(state); len(ents) != 1 {
		t.Fatalf("a temporary file was left behind: %v", ents)
	}
	if got, err := enroll.ReadState(filepath.Join(state, "pairing.json")); err != nil || got.Panel != st.Panel || got.Key2 != st.Key2 {
		t.Fatal(got, err)
	}

	// what the attacker aims at: a folder only the administrator writes, with a pairing.json of its own
	elsewhere := filepath.Join(base, "administrators-only")
	_ = os.Mkdir(elsewhere, 0o755)
	victim := filepath.Join(elsewhere, "pairing.json")
	_ = os.WriteFile(victim, []byte("do not replace me"), 0o600)
	untouched := func(what string) {
		t.Helper()
		if b, _ := os.ReadFile(victim); string(b) != "do not replace me" {
			t.Fatalf("%s: the file in the other folder was replaced: %q", what, b)
		}
		if ents, _ := os.ReadDir(elsewhere); len(ents) != 1 {
			t.Fatalf("%s: something was written into the other folder: %v", what, ents)
		}
	}
	swap := func() { // the agent's account: state\ is emptied and becomes a link to the other folder
		if err := os.RemoveAll(state); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, state); err != nil {
			t.Skip("no symbolic links here:", err)
		}
	}
	defer func() { beforeFolderOpened, afterFolderOpened = nil, nil }()

	// 2. the swap between the look at the folder and its opening (the window the old code left open)
	beforeFolderOpened = swap
	err := writePairingState(state, st)
	beforeFolderOpened = nil
	if err == nil || !strings.Contains(err.Error(), "became a link") || !strings.Contains(err.Error(), "setup-self-update") {
		t.Fatal(err)
	}
	untouched("swapped between check and open")

	// 3. a link from the start: refused before anything is opened
	if err := writePairingState(state, st); err == nil || !strings.Contains(err.Error(), "not a plain folder") {
		t.Fatal(err)
	}
	untouched("a link from the start")

	// 4. the swap after the folder was opened: the file goes into the folder that was opened, wherever the
	//    name leads by then
	_ = os.Remove(state)
	_ = os.Mkdir(state, 0o755)
	moved := filepath.Join(base, "state-moved")
	afterFolderOpened = func() {
		if err := os.Rename(state, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(elsewhere, state); err != nil {
			t.Fatal(err)
		}
	}
	err = writePairingState(state, st)
	afterFolderOpened = nil
	if err != nil {
		t.Fatal(err)
	}
	untouched("swapped after the folder was opened")
	if got, _ := os.ReadFile(filepath.Join(moved, "pairing.json")); string(got) != string(want) {
		t.Fatalf("the file is not in the folder that was opened: %q", got)
	}

	// 5. inside the folder: a link under the final name is replaced, never followed; a folder there is an error
	_ = os.Remove(state)
	_ = os.Mkdir(state, 0o755)
	if err := os.Symlink(victim, filepath.Join(state, "pairing.json")); err != nil {
		t.Fatal(err)
	}
	if err := writePairingState(state, st); err != nil {
		t.Fatal(err)
	}
	untouched("a link under the final name")
	if fi, _ := os.Lstat(filepath.Join(state, "pairing.json")); fi == nil || !fi.Mode().IsRegular() {
		t.Fatal("the link under the final name was not replaced by the file")
	}
	_ = os.Remove(filepath.Join(state, "pairing.json"))
	_ = os.MkdirAll(filepath.Join(state, "pairing.json", "x"), 0o755)
	if err := writePairingState(state, st); err == nil {
		t.Fatal("a folder under the final name was replaced")
	}
	if ents, _ := os.ReadDir(state); len(ents) != 1 {
		t.Fatalf("a temporary file was left behind after the failure: %v", ents)
	}
	untouched("a folder under the final name")

	// 6. only a plain name directly in the folder
	for _, name := range []string{"../x", "a/b", "..", ".", ""} {
		if err := writeInFolder(state, name, ".t-", []byte("x")); err == nil {
			t.Errorf("%q accepted as a file name", name)
		}
	}
	// 7. a folder that does not exist, a file where the folder should be
	if err := writePairingState(filepath.Join(base, "missing"), st); err == nil {
		t.Fatal("no error for a missing folder")
	}
	file := filepath.Join(base, "file")
	_ = os.WriteFile(file, []byte("x"), 0o600)
	if err := writePairingState(file, st); err == nil || !strings.Contains(err.Error(), "not a plain folder") {
		t.Fatal(err)
	}
}
