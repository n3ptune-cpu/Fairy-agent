//go:build !windows

package approval_test

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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

// owned is a file as the system would describe it, with an owner and a group of the test's choosing.
type owned struct {
	os.FileInfo
	uid, gid uint32
}

func (o owned) Sys() any {
	sys := *o.FileInfo.Sys().(*syscall.Stat_t)
	sys.Uid, sys.Gid = o.uid, o.gid
	return &sys
}

// chowns counts the changes of owner the code under test asks for; none of them reaches the system.
type chowns struct {
	n    int
	last string
	err  error
}

func (c *chowns) lchown(path string, uid, gid int) error {
	c.n++
	c.last = fmt.Sprintf("%s %d:%d", filepath.Base(path), uid, gid)
	return c.err
}

// TestMachineIDOfRootsFileIsNotAddedByAnotherUser (audit 5, r2-a1-01 = r2-a2-04): an agent that does not run as
// root and finds a trust file without machine id that is not its own (root's, after `helper-trust set`) must
// not ask the system to change an owner, not even to be told no: under the shipped unit's system call filter
// that call ends the process (SIGSYS) at every start. It must say "broken" with the reason, write nothing (no
// temporary file is ever made: the folder is not touched) and leave the file as it was.
func TestMachineIDOfRootsFileIsNotAddedByAnotherUser(t *testing.T) {
	dir, err := os.MkdirTemp("", "ta") // a short name; how long the whole path is, the temporary folder decides
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	must(t, os.Chmod(dir, 0o700))
	path := filepath.Join(dir, approval.TrustFileName)
	old := legacyFile(t)
	must(t, os.WriteFile(path, old, 0o640))
	// this process plays an agent whose user is another one than the file's (which is really this process's)
	me, mine := os.Geteuid()+54321, os.Getegid()+54321
	calls := &chowns{err: errors.New("the test's lchown: not permitted")}
	approval.PretendUser(t, me, mine, calls.lchown)
	time.Sleep(20 * time.Millisecond) // a file made in the folder from here on would change the folder's time
	before, err := os.Stat(dir)
	must(t, err)

	log := &syncBuf{}
	g := approval.NewGate(approval.Options{Files: approval.UnixFiles(path), EnforcedBy: api.EnforcedByAgent,
		Now: func() time.Time { return nowForTests }, Log: slog.New(slog.NewTextHandler(log, nil))})
	st := g.Status()
	const hint = approvaltest.NoIDHint
	why := fmt.Sprintf("the trust file belongs to user %d, group %d, but this service is user %d, group %d: only root can keep the owner", os.Geteuid(), os.Getegid(), me, mine)
	if st.State != api.ApprovalBroken || st.MachineID != "" {
		t.Fatalf("state: %+v", st)
	}
	// the text carries the file's path, and the path of a test's folder is as long as TMPDIR makes it: the
	// reason is whole where it fits and cut where it does not (the second review's runs with a TMPDIR of 16
	// characters or more failed on a comparison with the whole text)
	if problem := approvaltest.NoIDTextProblem(st.Error, path, why); problem != "" {
		t.Fatalf("%s\nthe error: %s", problem, st.Error)
	}
	if calls.n != 0 {
		t.Fatalf("%d changes of owner were asked for (the last: %s); under the unit's filter the first one kills the agent", calls.n, calls.last)
	}
	after, err := os.Stat(dir)
	must(t, err)
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("something was written into the folder (a temporary file was made and removed)")
	}
	if left := tempFiles(t, dir); len(left) != 0 {
		t.Errorf("files left behind: %v", left)
	}
	if now, _ := os.ReadFile(path); !bytes.Equal(now, old) {
		t.Error("the file changed")
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o640 {
		t.Errorf("the file's mode changed: %04o", fi.Mode().Perm())
	}
	if ref := g.Precheck(power("shutdown", 60), false); ref == nil || ref.Status != 503 || ref.Code != api.CodeApprovalUnavailable {
		t.Errorf("a request without approval while the id is missing: %v", ref)
	}
	if strings.Contains(log.String(), "one was added") {
		t.Error("the log claims an id was added")
	}
	// the next looks (every 5 s) are the same: still no call, still nothing written
	for i := 0; i < 3; i++ {
		if st := g.StatusNow(); st.State != api.ApprovalBroken {
			t.Fatalf("look %d: %+v", i+2, st)
		}
	}
	if calls.n != 0 || len(tempFiles(t, dir)) != 0 {
		t.Fatalf("later looks: %d changes of owner asked for, files %v", calls.n, tempFiles(t, dir))
	}
	// on a standard install, with user and group numbers of five digits, the whole text fits
	std := "/var/lib/fairy-agent/" + approval.TrustFileName + ": the trust file has no machine_id, and adding one failed: " +
		"the trust file belongs to user 0, group 54321, but this service is user 54321, group 54321: only root can keep the owner" + hint
	if len(std) > 300 {
		t.Errorf("on a standard install the reason is %d characters long, the answer holds 300", len(std))
	}
	// and where it does not (a long path), the reason gives way, not what to do. Each folder's name is as long
	// as it takes for a trust file path of that many characters, whatever the temporary folder's own path is:
	// 150 (the reason is cut), 160 (the longest path that still leaves room for a reason) and 200 (no room).
	cut := 0
	for _, n := range []int{150, 160, 200} {
		pad := n - len(filepath.Join(dir, "d", approval.TrustFileName)) + 1
		if pad < 1 {
			t.Logf("a trust file path of %d characters: not possible under %s (%d characters)", n, dir, len(dir))
			continue
		}
		deep := filepath.Join(dir, strings.Repeat("d", pad))
		must(t, os.Mkdir(deep, 0o700))
		far := approval.UnixFiles(filepath.Join(deep, approval.TrustFileName))
		must(t, os.WriteFile(far.Path, old, 0o640))
		st = approval.NewGate(approval.Options{Files: far, EnforcedBy: api.EnforcedByAgent, Log: slog.New(slog.NewTextHandler(log, nil))}).Status()
		if st.State != api.ApprovalBroken || len(far.Path) != n {
			t.Fatalf("a path of %d characters (%d): %+v", n, len(far.Path), st)
		}
		if problem := approvaltest.NoIDTextProblem(st.Error, far.Path, why); problem != "" {
			t.Errorf("a path of %d characters: %s\nthe error (%d characters): %s", n, problem, len(st.Error), st.Error)
		}
		if n <= 160 {
			cut++
			if len(st.Error) != 300 || !strings.HasSuffix(st.Error, "..."+hint) || !strings.Contains(st.Error, "adding one failed: t") {
				t.Errorf("a path of %d characters: %d characters, want 300 with a cut reason and the hint: %s", n, len(st.Error), st.Error)
			}
		}
	}
	if cut == 0 && len(dir) < 100 {
		t.Errorf("no long path was tried under %s", dir)
	}
	if calls.n != 0 {
		t.Errorf("a long path: %d changes of owner asked for", calls.n)
	}
}

// TestUnixCanKeep: who may add the machine id, decided before anything is written. Root always; another user
// only for a file that is that user's and of the group a new file in the folder gets.
func TestUnixCanKeep(t *testing.T) {
	dir := t.TempDir()
	must(t, os.Chmod(dir, 0o700))
	fi, err := os.Lstat(dir)
	must(t, err)
	dirGID := fi.Sys().(*syscall.Stat_t).Gid
	calls := &chowns{}
	for name, c := range map[string]struct {
		uid, gid   int    // who the process is
		fuid, fgid uint32 // whose the trust file is
		setgid     bool   // the folder hands its group on
		ok         bool
	}{
		"its own file": {1000, 1000, 1000, 1000, false, true},
		"root's file, the agent's group (helper-trust)": {1000, 1000, 0, 1000, false, false},
		"root's file, root's group":                     {1000, 1000, 0, 0, false, false},
		"its own file, another group":                   {1000, 1000, 1000, 7, false, false},
		"another user's file":                           {1000, 1000, 1001, 1000, false, false},
		"its own file, the folder's group, setgid":      {1000, 1000, 1000, dirGID, true, true},
		"its own file, its own group, setgid folder":    {1000, int(dirGID) + 5, 1000, dirGID + 5, true, false},
		"root, root's file":                             {0, 0, 0, 0, false, true},
		"root, the agent's file":                        {0, 0, 1000, 1000, false, true},
		"root, root's file of the agent's group":        {0, 0, 0, 1000, false, true},
	} {
		mode := os.FileMode(0o700)
		if c.setgid {
			mode |= os.ModeSetgid
		}
		must(t, os.Chmod(dir, mode))
		approval.PretendUser(t, c.uid, c.gid, calls.lchown)
		err := approval.UnixCanKeep(dir, owned{fi, c.fuid, c.fgid})
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", name, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), fmt.Sprintf("belongs to user %d, group %d, but this service is user %d, group ", c.fuid, c.fgid, c.uid)) {
			t.Errorf("%s: the reason does not say whose the file is and who writes: %v", name, err)
		}
	}
	if calls.n != 0 {
		t.Errorf("UnixCanKeep asked for %d changes of owner", calls.n)
	}
}

// TestUnixKeepChangesAnOwnerOnlyAsRootAndOnlyWhenItDiffers: the owner is compared first; the call that changes
// it is made only by root and only for a file whose owner or group really differs.
func TestUnixKeepChangesAnOwnerOnlyAsRootAndOnlyWhenItDiffers(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, ".approval-trust-1.tmp")
	must(t, os.WriteFile(tmp, []byte("{}"), 0o600))
	fi, err := os.Lstat(tmp)
	must(t, err)
	sys := fi.Sys().(*syscall.Stat_t)
	oldMode := func(o owned) os.FileInfo { return modeInfo{o, 0o640} }
	for name, c := range map[string]struct {
		euid       int
		fuid, fgid uint32
		lchownErr  error
		calls      int
		ok         bool
	}{
		"not root, the same owner":                  {1000, sys.Uid, sys.Gid, nil, 0, true},
		"root, the same owner":                      {0, sys.Uid, sys.Gid, nil, 0, true},
		"not root, another owner":                   {1000, sys.Uid + 1, sys.Gid, nil, 0, false},
		"not root, another group":                   {1000, sys.Uid, sys.Gid + 1, nil, 0, false},
		"root, another owner":                       {0, sys.Uid + 1, sys.Gid, nil, 1, true},
		"root, another group":                       {0, sys.Uid, sys.Gid + 1, nil, 1, true},
		"root, another owner, the system says no":   {0, sys.Uid + 1, sys.Gid, errors.New("invalid argument"), 1, false},
		"not root, another owner and another group": {1000, sys.Uid + 1, sys.Gid + 1, nil, 0, false},
	} {
		must(t, os.Chmod(tmp, 0o600))
		calls := &chowns{err: c.lchownErr}
		approval.PretendUser(t, c.euid, c.euid, calls.lchown)
		err := approval.UnixKeep(tmp, oldMode(owned{fi, c.fuid, c.fgid}))
		if (err == nil) != c.ok || calls.n != c.calls {
			t.Errorf("%s: %v with %d changes of owner asked for, want ok=%v with %d", name, err, calls.n, c.ok, c.calls)
		}
		if c.calls == 1 && calls.last != fmt.Sprintf("%s %d:%d", filepath.Base(tmp), c.fuid, c.fgid) {
			t.Errorf("%s: asked for %q", name, calls.last)
		}
		now, _ := os.Stat(tmp)
		if want := map[bool]os.FileMode{true: 0o640, false: 0o600}[c.ok]; now.Mode().Perm() != want {
			t.Errorf("%s: mode %04o afterwards, want %04o", name, now.Mode().Perm(), want)
		}
	}
}

// modeInfo is a file with another mode than it has.
type modeInfo struct {
	os.FileInfo
	mode os.FileMode
}

func (m modeInfo) Mode() os.FileMode { return m.mode }
