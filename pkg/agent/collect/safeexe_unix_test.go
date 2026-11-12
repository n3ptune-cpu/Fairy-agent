//go:build !windows

package collect

import (
	"fmt"
	"github.com/n3ptune-cpu/Fairy-agent/internal/roottest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestTrustedExecutableUnix(t *testing.T) {
	// The test folder and file get explicit modes, so the umask does not matter. As a normal user (the GitHub
	// runner is uid/gid 1001) they are owned by that user and group: allowed for the owner (the agent's own user),
	// but group write then counts (only group root may write), so each case below sets one permission bit alone.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "ipmitool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	chmodDir := func(mode os.FileMode) {
		t.Helper()
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	// refused checks that the walk stopped at the test folder (not at the file, not above it) with want.
	refused := func(what, want string) {
		t.Helper()
		err := TrustedExecutable(bin)
		if err == nil || !strings.HasPrefix(err.Error(), dir+" ") || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: got %v, want %q about %s", what, err, want, dir)
		}
	}
	chmodDir(0o755)
	// The good case: the file and its folder must pass. The folders above the test folder (TMPDIR and up) are
	// the machine's, not the test's: if one of them is refused, that is the check working, not a failure here.
	if err := TrustedExecutable(bin); err != nil {
		if strings.HasPrefix(err.Error(), bin+" ") || strings.HasPrefix(err.Error(), dir+" ") {
			t.Fatal(err)
		}
		t.Logf("good case not checked, a folder above the test folder is refused: %v", err)
	}
	chmodDir(0o757) // a folder anyone may write into (no sticky bit)
	refused("other-writable folder", "everyone")
	chmodDir(0o777)
	refused("world-writable folder", "writable by")
	st, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	gid := st.Sys().(*syscall.Stat_t).Gid
	chmodDir(0o775)
	if gid != 0 {
		refused("group-writable folder", fmt.Sprintf("writable by group %d", gid))
	} else if err := TrustedExecutable(bin); err != nil && (strings.HasPrefix(err.Error(), bin+" ") || strings.HasPrefix(err.Error(), dir+" ")) {
		t.Fatalf("folder writable by group root refused: %v", err)
	}
	chmodDir(0o755)
	if err := TrustedExecutable("ipmitool"); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := TrustedExecutable(dir); err == nil {
		t.Fatal("a folder accepted")
	}
	if os.Geteuid() == 0 {
		roottest.NeedOtherUsers(t) // the checks above ran; what follows needs a file of another user
		if err := os.Chown(bin, 1234, 0); err != nil {
			t.Fatal(err)
		}
		if err := TrustedExecutable(bin); err == nil || !strings.Contains(err.Error(), "uid 1234") {
			t.Fatal(err)
		}
	}
}
