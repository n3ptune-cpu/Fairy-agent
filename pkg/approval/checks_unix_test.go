//go:build !windows

package approval_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// TestUnixFileChecks: the trust file counts only in a folder and as a file that nobody but root and the agent's
// own user can write; everything else is "broken", never "off".
func TestUnixFileChecks(t *testing.T) {
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o700))
	f := approval.UnixFiles(filepath.Join(dir, approval.TrustFileName))
	state := func() string { st, _, _, _ := f.Load(); return st }
	if state() != api.ApprovalOff {
		t.Fatalf("empty folder: %s", state())
	}
	tr, err := approval.FromInit(approvaltest.New().Init(), nowForTests, nil)
	must(t, err)
	must(t, f.Create(tr))
	if st, _ := os.Stat(f.Path); st.Mode().Perm() != 0o600 {
		t.Errorf("the first-time set wrote the file with mode %04o", st.Mode().Perm())
	}
	if state() != api.ApprovalRequired {
		t.Fatalf("after the set: %s", state())
	}
	for name, c := range map[string]struct{ do, undo func() error }{
		"file writable by its group": {func() error { return os.Chmod(f.Path, 0o660) }, func() error { return os.Chmod(f.Path, 0o600) }},
		"file writable by others":    {func() error { return os.Chmod(f.Path, 0o602) }, func() error { return os.Chmod(f.Path, 0o600) }},
		"folder writable by group":   {func() error { return os.Chmod(dir, 0o770) }, func() error { return os.Chmod(dir, 0o700) }},
		"folder writable by others":  {func() error { return os.Chmod(dir, 0o707) }, func() error { return os.Chmod(dir, 0o700) }},
		"file with a second name":    {func() error { return os.Link(f.Path, f.Path+".copy") }, func() error { return os.Remove(f.Path + ".copy") }},
	} {
		must(t, c.do())
		if state() != api.ApprovalBroken {
			t.Errorf("%s: state %s, want broken", name, state())
		}
		must(t, c.undo())
		if state() != api.ApprovalRequired {
			t.Errorf("%s undone: state %s", name, state())
		}
	}
	// readable by the group is fine (root:fairy-agent 0640 after helper-trust set)
	must(t, os.Chmod(f.Path, 0o640))
	if state() != api.ApprovalRequired {
		t.Errorf("mode 0640: %s", state())
	}
	// an unsafe folder without a file is broken too
	must(t, f.Remove())
	must(t, os.Chmod(dir, 0o777))
	if state() != api.ApprovalBroken {
		t.Errorf("unsafe empty folder: %s", state())
	}
	if err := f.Create(tr); err == nil {
		t.Error("trust was written into a folder others can write")
	}
	// the administrator's write: mode 0640 as root, 0600 otherwise
	must(t, os.Chmod(dir, 0o700))
	f.Prepare = approval.UnixAdminPrepare(dir)
	must(t, f.Replace(tr))
	want := os.FileMode(0o600)
	if os.Geteuid() == 0 {
		want = 0o640
	}
	if st, _ := os.Stat(f.Path); st.Mode().Perm() != want {
		t.Errorf("the administrator's file has mode %04o, want %04o", st.Mode().Perm(), want)
	}
	if state() != api.ApprovalRequired {
		t.Errorf("after the administrator's write: %s", state())
	}
}
