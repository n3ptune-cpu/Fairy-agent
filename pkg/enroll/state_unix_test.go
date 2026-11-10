//go:build unix

package enroll

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func ownerOf(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

// otherIDs is an owner that differs from the test process where the system allows one: any uid / gid as root,
// another group of this user otherwise (fchown to one's own groups needs no privilege).
func otherIDs() (uid, gid int, differs bool) {
	if os.Geteuid() == 0 {
		return 65534, 65534, true
	}
	uid, gid = os.Getuid(), os.Getgid()
	groups, _ := os.Getgroups()
	for _, g := range groups {
		if g != gid {
			return uid, g, true
		}
	}
	return uid, gid, false
}

func testState() State {
	now := time.Unix(1_800_000_000, 0)
	return State{Version: 1, Verifier: "ab", Panel: "100.64.0.1", CreatedAt: now.Unix(), ExpiresAt: now.Add(TTL).Unix()}
}

// M6: the state folder belongs to the agent's account, the writer may be root. Whatever that account puts
// under the names in the folder, the writer changes the owner of the file it made itself and of nothing else.
func TestWriteStateOwnedNeverFollowsALink(t *testing.T) {
	uid, gid, differs := otherIDs()
	dir, outside := t.TempDir(), t.TempDir()
	victim := filepath.Join(outside, "shadow")
	if err := os.WriteFile(victim, []byte("root:secret\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	vuid, vgid := ownerOf(t, victim)
	untouched := func(when string) {
		t.Helper()
		b, err := os.ReadFile(victim)
		fi, _ := os.Lstat(victim)
		u, g := ownerOf(t, victim)
		if err != nil || string(b) != "root:secret\n" || fi.Mode().Perm() != 0o640 || u != vuid || g != vgid {
			t.Fatalf("%s: the file outside the folder changed: %q %v owner %d:%d (was %d:%d) %v", when, b, fi.Mode(), u, g, vuid, vgid, err)
		}
	}
	path := filepath.Join(dir, "pairing.json")

	// 1. the final name is already a link to the other file: it is replaced, not followed
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	if err := WriteStateOwned(path, testState(), uid, gid); err != nil {
		t.Fatal(err)
	}
	untouched("link under the final name")
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("state file: %v %v", fi, err)
	}
	if u, g := ownerOf(t, path); int(u) != uid || int(g) != gid {
		t.Fatalf("state file owner %d:%d, want %d:%d", u, g, uid, gid)
	} else if !differs {
		t.Log("no second uid / gid available to this user: the owner check is trivial here")
	}
	if got, err := ReadState(path); err != nil || got != testState() {
		t.Fatalf("round trip: %+v %v", got, err)
	}

	// 2. the race of the audit: the folder's owner swaps a name for a link while the writer is between two
	// steps. The owner was already set on the open file, so the swap gains nothing: the link itself is renamed.
	var made string
	beforeRename = func(tmp string) {
		made = tmp + ".moved"
		if err := os.Rename(tmp, made); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(victim, tmp); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeRename = nil })
	if err := WriteStateOwned(path, testState(), uid, gid); err != nil {
		t.Fatal(err)
	}
	beforeRename = nil
	untouched("temporary name swapped for a link")
	if u, g := ownerOf(t, made); int(u) != uid || int(g) != gid {
		t.Fatalf("the file the writer made has owner %d:%d, want %d:%d", u, g, uid, gid)
	}
	if fi, _ := os.Lstat(path); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected the planted link under the final name, got %v", fi.Mode())
	}
	if _, err := ReadState(path); err == nil {
		t.Fatal("ReadState followed a link")
	}
	untouched("after reading through the link")

	// 3. a write that fails leaves no temporary file behind
	if err := WriteStateOwned(filepath.Join(dir, "sub", "pairing.json"), testState(), uid, gid); err == nil {
		t.Fatal("missing folder accepted")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "pairing.json" && e.Name() != filepath.Base(made) {
			t.Fatalf("left behind: %s", e.Name())
		}
	}
}

// Without the right to give a file away the write fails and the old state stays (non-root only).
func TestWriteStateOwnedFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root may give a file to anyone")
	}
	path := filepath.Join(t.TempDir(), "pairing.json")
	if err := WriteState(path, testState()); err != nil {
		t.Fatal(err)
	}
	other := testState()
	other.Panel = "100.64.0.2"
	if err := WriteStateOwned(path, other, 0, 0); err == nil {
		t.Fatal("chown to root as an ordinary user succeeded")
	}
	if got, err := ReadState(path); err != nil || got != testState() {
		t.Fatalf("old state: %+v %v", got, err)
	}
	if ents, _ := os.ReadDir(filepath.Dir(path)); len(ents) != 1 {
		t.Fatalf("temporary file left behind: %v", ents)
	}
}

// ReadState (root's `fairy-agent pair-status` reads the agent's folder) opens only a regular file: no link,
// no FIFO (which would block the reader), no folder.
func TestReadStateOnlyRegularFiles(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := WriteState(real, testState()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	sub := filepath.Join(dir, "dir.json")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{link, fifo, sub} {
		done := make(chan error, 1)
		go func() { _, err := ReadState(p); done <- err }()
		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s: read", filepath.Base(p))
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: ReadState blocks", filepath.Base(p))
		}
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, make([]byte, maxStateSize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadState(big); err == nil {
		t.Error("oversized state read")
	}
	if got, err := ReadState(real); err != nil || got != testState() {
		t.Fatalf("%+v %v", got, err)
	}
}
