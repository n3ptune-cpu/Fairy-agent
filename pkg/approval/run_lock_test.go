package approval_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

func lockPath(r *runRig) string {
	return filepath.Join(filepath.Dir(r.files.RunPath()), approval.RunLockName)
}

// The moment that was left after the review's T7: the service has looked at the record, found it to be the
// one it knows, and is about to give the new one its name. A cancel of the administrator's command that
// landed exactly there was written over: the command had returned "cancelled", and the run was live again.
// The look and the rename are one step under the writers' lock now, and the command holds the same lock for
// its read, change and write. So the command waits for the rename, reads what the service wrote, and cancels
// that. (Not parallel: it changes what a rename is for the whole package.)
func TestCancelOnTheMachineCannotLandBetweenTheServicesLookAndItsRename(t *testing.T) {
	for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
		r := newRunRig(t)
		r.armed(runA)
		if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
			t.Fatal(ref)
		}
		var hook, early atomic.Bool
		type result struct {
			changed bool
			err     error
		}
		done := make(chan result, 2)
		restore := approval.SetRunRename(func(from, to string) error {
			if hook.CompareAndSwap(true, false) {
				// the service's rename: its look at the record is behind it
				go func() {
					_, changed, err := r.files.RunCancel(r.stamp())
					done <- result{changed, err}
				}()
				select {
				case res := <-done:
					early.Store(true)
					done <- res
				case <-time.After(80 * time.Millisecond):
				}
			}
			return os.Rename(from, to)
		}, func(error) bool { return false }, 60*time.Millisecond, 400*time.Millisecond, 5*time.Millisecond)
		hook.Store(true)
		_, ref := r.g.AdmitRun(req, runA) // the service writes "used up" (the update) or "done" (the shutdown)
		var res result
		select {
		case res = <-done:
		case <-time.After(10 * time.Second):
			restore()
			t.Fatal("the cancel never returned")
		}
		restore()
		if hook.Load() {
			t.Fatal("the service never wrote: the test tests nothing")
		}
		if res.err != nil {
			t.Fatalf("%s: helper-run cancel: %v", req.Verb, res.err)
		}
		if early.Load() {
			t.Errorf("%s: the cancel was written between the service's look at the record and its rename", req.Verb)
		}
		if ref != nil {
			t.Errorf("%s was made before the cancel and refused: %v", req.Verb, ref)
		}
		// the command read what the service wrote: a run whose update is used up is cancelled, a run that is
		// over with its shutdown is left as it is; a live run is in the record in neither case
		v := r.files.RunShow()
		want, state := api.RunCancelled, api.RunCancelled
		if isShutdown := req.Verb != api.ApproveApplyUpdate; isShutdown {
			want, state = api.RunDone, api.RunDone
		}
		if v.ID != "" || v.LastState != want || res.changed != (want == api.RunCancelled) {
			t.Errorf("%s: the command returned (changed: %v) and the record says: %+v", req.Verb, res.changed, v)
		}
		r.w.Tick()
		if st := r.state(); st != state {
			t.Errorf("%s: the run is %q, want %q", req.Verb, st, state)
		}
		for _, later := range []api.ApprovalRequest{update, power("shutdown", 30)} {
			if _, ref := r.g.AdmitRun(later, runA); ref == nil {
				t.Errorf("after the cancel during %s: %s let through", req.Verb, later.Verb)
			}
		}
	}
}

// Somebody else holds the lock and does not let go. The service writes nothing while that lasts, so it takes
// nothing of a run (and tries again later); the administrator's cancel is written all the same, because
// keeping the machine on comes first.
func TestRunRecordLockHeldBySomebodyElse(t *testing.T) {
	defer approval.SetRunLockWait(40*time.Millisecond, 120*time.Millisecond)()
	r := newRunRig(t)
	release, err := r.files.RunLockHold()
	if err != nil {
		t.Fatal(err)
	}
	_, ref := r.w.Arm(r.ticket(runA, r.up()+100*time.Second))
	runRefused(t, "a ticket while the lock is held", ref, 503, api.CodeRunUnavailable, "")
	if r.touched() {
		t.Error("something of the ticket was written without the lock")
	}
	release()
	r.armed(runA) // the same run: nothing of it was used up
	if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
		t.Fatal(ref)
	}

	release, err = r.files.RunLockHold()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Error("the run's update was let through although it could not be written down as used up")
	}
	start := time.Now()
	was, changed, err := r.files.RunCancel(r.stamp())
	if err != nil || !changed || was.State != api.RunConfirmed {
		t.Fatalf("helper-run cancel while the lock was held: %+v %v %v", was, changed, err)
	}
	if d := time.Since(start); d < 100*time.Millisecond || d > 5*time.Second {
		t.Errorf("the command waited %s for the lock, want about 120 ms", d)
	}
	if v := r.files.RunShow(); v.ID != "" || v.LastState != api.RunCancelled {
		t.Errorf("the record after the cancel without the lock: %+v", v)
	}
	r.w.Tick()
	if st := r.state(); st != api.RunCancelled {
		t.Errorf("the run is %q", st)
	}
	for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
		if _, ref := r.g.AdmitRun(req, runA); ref == nil {
			t.Errorf("%s let through after the cancel", req.Verb)
		}
	}
}

// The lock is a file of its own next to the record: it holds nothing, only its owner can open it, it is never
// removed, and it is never taken through a link. Reading the record and showing it need no lock and make none.
func TestRunRecordLockFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the file's owner and access list on Windows are its folder's (TEST-ON-WINDOWS.md)")
	}
	defer approval.SetRunLockWait(40*time.Millisecond, 3*time.Second)()
	r := newRunRig(t)
	st, err := os.Lstat(lockPath(r))
	if err != nil {
		t.Fatalf("no lock file after the service wrote its record: %v", err)
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 || st.Size() != 0 {
		t.Errorf("the lock file: %v, %d bytes", st.Mode(), st.Size())
	}
	r.armed(runA)
	if _, changed, err := r.files.RunCancel(r.stamp()); err != nil || !changed {
		t.Fatal(changed, err)
	}
	st2, err := os.Lstat(lockPath(r))
	if err != nil || !os.SameFile(st, st2) || st2.Size() != 0 {
		t.Errorf("the lock file after an arm and a cancel is another one, or not empty: %v %v", st2, err)
	}

	// no folder: nothing is made, and nobody waits
	none := r.files
	none.Path = filepath.Join(t.TempDir(), "gone", approval.TrustFileName)
	start := time.Now()
	if _, changed, err := none.RunCancel(r.stamp()); changed || err != nil {
		t.Errorf("helper-run cancel without a folder: %v %v", changed, err)
	}
	if _, err := os.Lstat(filepath.Dir(none.Path)); !os.IsNotExist(err) || time.Since(start) > time.Second {
		t.Errorf("without a folder: %v after %s", err, time.Since(start))
	}
	// a folder without a record: showing it makes no lock
	bare := r.files
	bare.Path = filepath.Join(t.TempDir(), approval.TrustFileName)
	_ = bare.RunShow()
	if ents, _ := os.ReadDir(filepath.Dir(bare.Path)); len(ents) != 0 {
		t.Errorf("helper-run show made %v", ents)
	}

	// a link under the lock's name: not followed, nothing made at its other end; the service writes nothing,
	// the cancel is written
	r = newRunRig(t)
	r.armed(runA)
	target := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Remove(lockPath(r)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lockPath(r)); err != nil {
		t.Fatal(err)
	}
	if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref == nil {
		t.Error("the service wrote the record with a link in the place of its lock")
	}
	start = time.Now()
	if _, changed, err := r.files.RunCancel(r.stamp()); err != nil || !changed {
		t.Errorf("helper-run cancel with a link in the place of the lock: %v %v", changed, err)
	}
	if time.Since(start) > time.Second {
		t.Errorf("the command waited %s for a lock that is a link", time.Since(start))
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("the link was followed: %v", err)
	}
	if v := r.files.RunShow(); v.ID != "" || v.LastState != api.RunCancelled {
		t.Errorf("the record: %+v", v)
	}

	// something else than a file under the lock's name (a folder): the same, and nobody waits
	r = newRunRig(t)
	r.armed(runA)
	if err := os.Remove(lockPath(r)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lockPath(r), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref == nil {
		t.Error("the service wrote the record with a folder in the place of its lock")
	}
	start = time.Now()
	if _, changed, err := r.files.RunCancel(r.stamp()); err != nil || !changed || time.Since(start) > time.Second {
		t.Errorf("helper-run cancel with a folder in the place of the lock: %v %v after %s", changed, err, time.Since(start))
	}
}

// The service could not write (the record was open elsewhere, or the lock was held): it is ahead of the file
// with what it would have written, and tries again at every look. If the administrator's command changes the
// record in that time, the file wins: the service drops what it was ahead with and takes the cancel. Before,
// it tried its own write for ever, was refused each time because the file was another one, and never looked:
// it let nothing through, but it showed the run as live and took no ticket until it was started again.
// (Not parallel: it changes what a rename is for the whole package.)
func TestServiceThatCouldNotWriteTakesTheCancelOnTheMachine(t *testing.T) {
	errBusy := errors.New("The process cannot access the file because it is being used by another process.")
	var busy atomic.Bool
	restore := approval.SetRunRename(func(from, to string) error {
		if busy.Load() {
			return errBusy
		}
		return os.Rename(from, to)
	}, func(err error) bool { return errors.Is(err, errBusy) }, 30*time.Millisecond, 400*time.Millisecond, 5*time.Millisecond)
	defer restore()
	r := newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
		t.Fatal(ref)
	}
	busy.Store(true)
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Fatal("the update was let through although it could not be written down as used up")
	}
	r.w.Tick() // still busy: the service stays ahead, and shows the run it has
	if st := r.state(); st != api.RunConfirmed {
		t.Fatalf("the run while the record cannot be written: %q", st)
	}
	busy.Store(false)
	if _, changed, err := r.files.RunCancel(r.stamp()); err != nil || !changed {
		t.Fatalf("helper-run cancel: %v %v", changed, err)
	}
	r.ticks(2 * time.Second)
	if st := r.state(); st != api.RunCancelled {
		t.Errorf("the run after the cancel on the machine: %q", st)
	}
	if v := r.files.RunShow(); v.ID != "" || v.LastState != api.RunCancelled {
		t.Errorf("the record: %+v", v)
	}
	for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
		if _, ref := r.g.AdmitRun(req, runA); ref == nil {
			t.Errorf("%s let through after the cancel", req.Verb)
		}
	}
	// and the service is not stuck: after the next start of the machine it takes a ticket
	r.reboot(time.Hour, 60*time.Second)
	if _, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second)); ref != nil {
		t.Errorf("a ticket in the next boot: %v", ref)
	}
}
