//go:build !windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

func fileOwner(t *testing.T, path string) (int, int) {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return int(st.Uid), int(st.Gid)
}

// M6: join (root) writes the pairing state into the agent account's folder. A link planted under the state's
// name by that account is replaced, never followed, and the file behind it keeps its owner. As root the agent
// is uid / gid 65534 here; as an ordinary user it is the user itself (the hand-over is then a no-op that still
// runs through the same code).
func TestJoinStateNeverFollowsALink(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	uid, gid := os.Getuid(), os.Getgid()
	if os.Geteuid() == 0 {
		uid, gid = 65534, 65534
	}
	old := agentIDs
	agentIDs = func() (int, int, bool) { return uid, gid, true }
	t.Cleanup(func() { agentIDs = old })

	dir, state, outside := t.TempDir(), filepath.Join(t.TempDir(), "state"), t.TempDir()
	victim := filepath.Join(outside, "shadow")
	if err := os.WriteFile(victim, []byte("root:secret\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	vuid, vgid := fileOwner(t, victim)
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, "pairing.json")
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	code, _ := enroll.NewCode()
	var out bytes.Buffer
	o := joinOpts{code: code, panel: "100.64.0.10", cfgPath: filepath.Join(dir, "config.yaml"), stateDir: state}
	if err := join(o, &out); err != nil {
		t.Fatal(err, out.String())
	}
	if b, _ := os.ReadFile(victim); string(b) != "root:secret\n" {
		t.Fatalf("join wrote through the link: %q", b)
	}
	if u, g := fileOwner(t, victim); u != vuid || g != vgid {
		t.Fatalf("join gave the linked file away: owner %d:%d, was %d:%d", u, g, vuid, vgid)
	}
	fi, err := os.Lstat(path)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o600 {
		t.Fatalf("pairing.json: %v %v", fi, err)
	}
	if u, g := fileOwner(t, path); u != uid || g != gid {
		t.Fatalf("pairing.json owner %d:%d, want the agent %d:%d", u, g, uid, gid)
	}
	if u, g := fileOwner(t, state); u != uid || g != gid {
		t.Fatalf("state folder owner %d:%d, want the agent %d:%d", u, g, uid, gid)
	}
	if st, err := enroll.ReadState(path); err != nil || st.Panel != "100.64.0.10" {
		t.Fatalf("%+v %v", st, err)
	}
	if ents, _ := os.ReadDir(state); len(ents) != 1 {
		t.Fatalf("temporary files left in the state folder: %v", ents)
	}
	// pair-status (root in the installer) does not read through a link either
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, path); err != nil {
		t.Fatal(err)
	}
	var so, se bytes.Buffer
	if rc := pairStatus([]string{"--state-dir", state}, &so, &se); rc != 1 || strings.Contains(so.String()+se.String(), "secret") {
		t.Fatalf("pair-status through a link: %d %q %q", rc, so.String(), se.String())
	}
}

func TestPrepareStateDirRefusesALink(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := prepareStateDir(real); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(real); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", fi, err)
	}
	if err := prepareStateDir(real); err != nil {
		t.Fatal("second run:", err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDir(link); err == nil || !strings.Contains(err.Error(), "not a folder") {
		t.Fatalf("a link to a folder was accepted: %v", err)
	}
	file := filepath.Join(base, "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareStateDir(file); err == nil {
		t.Fatal("a file was accepted")
	}
}
