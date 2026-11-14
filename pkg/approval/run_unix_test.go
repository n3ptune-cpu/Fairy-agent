//go:build !windows

package approval_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// The run record gets the trust file's checks on a real system: its folder and the file itself must belong to
// root or to the service's own user, be writable by nobody else, and the file must have one name.
func TestRunRecordUnixChecks(t *testing.T) {
	setup := func(t *testing.T) *runRig {
		r := newRunRig(t)
		dir := filepath.Dir(r.files.Path)
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		u := approval.UnixFiles(r.files.Path)
		r.files.CheckDir, r.files.CheckFile = u.CheckDir, u.CheckFile
		r.restart()
		r.armed(runA)
		if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1800)); ref != nil {
			t.Fatal(ref)
		}
		if exists, err := r.files.RunRecordCheck(); !exists || err != nil {
			t.Fatalf("the service's own record fails the checks: %v", err)
		}
		return r
	}
	unusable := func(t *testing.T, r *runRig) {
		t.Helper()
		r.restart()
		if exists, err := r.files.RunRecordCheck(); !exists || err == nil {
			t.Errorf("the record still passes: %v, %v", exists, err)
		}
		if _, ref := r.g.AdmitRun(update, runA); ref == nil {
			t.Error("an update of the run was let through")
		}
		if r.run() != nil {
			t.Errorf("run block %+v", r.run())
		}
	}
	t.Run("the group can write the file", func(t *testing.T) {
		r := setup(t)
		os.Chmod(r.files.RunPath(), 0o660)
		unusable(t, r)
	})
	t.Run("others can write the file", func(t *testing.T) {
		r := setup(t)
		os.Chmod(r.files.RunPath(), 0o602)
		unusable(t, r)
	})
	t.Run("the file has a second name", func(t *testing.T) {
		r := setup(t)
		if err := os.Link(r.files.RunPath(), filepath.Join(filepath.Dir(r.files.Path), "copy")); err != nil {
			t.Fatal(err)
		}
		unusable(t, r)
	})
	t.Run("the file belongs to another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("only root can give a file away")
		}
		r := setup(t)
		if err := os.Chown(r.files.RunPath(), 4242, 4242); err != nil {
			t.Fatal(err)
		}
		unusable(t, r)
	})
	t.Run("others can write the folder", func(t *testing.T) {
		r := setup(t)
		os.Chmod(filepath.Dir(r.files.Path), 0o777)
		r.restart()
		if _, ref := r.g.AdmitRun(update, runA); ref == nil || ref.Code != api.CodeApprovalUnavailable {
			t.Errorf("an update of the run: %v", ref) // the trust file is in that folder: everything is refused
		}
		r.ticks(5 * time.Second)
		if r.run() != nil {
			t.Errorf("run block %+v", r.run())
		}
	})
}
