//go:build !windows

package approval_test

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// The administrator's command runs as root and the service, as it is shipped, does not. A lock file the
// command made is root's, with the group of the folder and readable by it, exactly as the record the command
// writes: the service can open it and lock it. The service itself never changes an owner.
func TestRunRecordLockFileOfTheAdministratorsCommand(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: a file is handed to another group")
	}
	const group = 1001
	r := newRunRig(t)
	dir := filepath.Dir(r.files.RunPath())
	if err := os.Remove(lockPath(r)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, -1, group); err != nil {
		t.Fatal(err)
	}
	r.armed(runA) // the service (no "Prepare"): root's file as it was made, nothing handed on
	st, err := os.Lstat(lockPath(r))
	if err != nil {
		t.Fatal(err)
	}
	if sys := st.Sys().(*syscall.Stat_t); st.Mode().Perm() != 0o600 || sys.Gid == group {
		t.Errorf("the service's lock file: %v, group %d", st.Mode(), sys.Gid)
	}
	for _, there := range []bool{true, false} { // one that was there and could not be opened by the service, and none
		if !there {
			if err := os.Remove(lockPath(r)); err != nil {
				t.Fatal(err)
			}
		}
		admin := r.files
		admin.Prepare = approval.UnixAdminPrepare(dir)
		if _, _, err := admin.RunCancel(r.stamp()); err != nil {
			t.Fatal(err)
		}
		st, err = os.Lstat(lockPath(r))
		if err != nil {
			t.Fatal(err)
		}
		if sys := st.Sys().(*syscall.Stat_t); st.Mode().Perm() != 0o640 || sys.Uid != 0 || sys.Gid != group || st.Size() != 0 {
			t.Errorf("the command's lock file (was there: %v): %v, user %d, group %d", there, st.Mode(), sys.Uid, sys.Gid)
		}
	}
}
