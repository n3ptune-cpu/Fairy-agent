package approval_test

import (
	"bytes"
	"encoding/json"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// Rules of the runs that were right by reading and that no test held (second review of the runs: the changes
// A23, A26, A20 and A11 to the code were found by nothing). Each has its test here.

// A ticket whose acceptance cannot be written down is not accepted: the answer is 503, nothing is armed for
// the service that is running (no self-off at the end of the wait), nothing of it is on record, and the
// ticket is not used up: presented again when the record can be written, it arms the machine.
func TestTicketThatCannotBeWrittenDownIsNotAccepted(t *testing.T) {
	r := newRunRig(t)
	tk := r.ticket(runA, r.up()+100*time.Second)
	r.w.Tick() // the service has looked and noted the clock: the record is as the service holds it
	tries, works := noSpace(t)
	ans, ref := r.w.Arm(tk) // the one write that fails is the ticket's own
	runRefused(t, "a ticket that cannot be written down", ref, 503, api.CodeRunUnavailable, "")
	if tries.Load() != 1 {
		t.Fatalf("%d writes were tried, want the ticket's one", tries.Load())
	}
	if ans.State != "" || ans.Run != "" {
		t.Errorf("the answer names a run: %+v", ans)
	}
	if st := r.run(); st != nil {
		t.Errorf("the status shows a run: %+v", st)
	}
	if r.touched() {
		t.Error("something of the ticket is on record")
	}
	r.ticks(1100 * time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("a ticket that was answered 503 switched the machine off: %+v", r.scheduled)
	}
	works()
	r.reboot(time.Minute, 30*time.Second)
	tk2 := r.ticket(runA, time.Second)
	if _, ref := r.w.Arm(tk2); ref != nil {
		t.Errorf("a ticket of the same run once the record can be written: %v", ref)
	}
}

// The service knew of no record (there was none when it looked) and is about to write its first one. A record
// that appeared in that moment (the administrator's command put one there, or one was copied back) is not
// written over: nothing is written, the next look takes the file, and what that file refuses stays refused.
func TestServiceDoesNotWriteOverARecordThatAppearedWhileItWroteItsFirst(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	if _, err := r.w.Cancel("x"); err != nil {
		t.Fatal(err)
	}
	theirs := r.record(t) // a record that knows run A and a closed boot
	if err := os.Remove(r.files.RunPath()); err != nil {
		t.Fatal(err)
	}
	appeared := false
	r.files.Prepare = func(string) error { // between the service's look at the folder and its write
		if !appeared {
			appeared = true
			return os.WriteFile(r.files.RunPath(), theirs, 0o600)
		}
		return nil
	}
	r.restart() // a service that finds no record
	r.w.Tick()  // and makes one
	if !appeared {
		t.Fatal("the service never wrote: the test tests nothing")
	}
	if now := r.record(t); !bytes.Equal(now, theirs) {
		t.Fatalf("the record that appeared was written over:\n%s\nwas\n%s", now, theirs)
	}
	r.ticks(3 * time.Second)
	if v := r.files.RunShow(); v.LastID != runA || v.LastState != api.RunCancelled {
		t.Errorf("the record after the next looks: %+v", v)
	}
	r.reboot(time.Hour, 30*time.Second)
	_, ref := r.w.Arm(r.ticket(runA, time.Second))
	runRefused(t, "a ticket of a run the record that appeared knows", ref, 409, api.CodeRunRefused, api.RunReasonRunUsed)
}

// `fairy-agent helper-run cancel` that could not get the writers' lock writes its cancel all the same, and
// then looks again: a writer that did not see the cancel (it holds no lock either) may have put the run back.
// The command cancels what it finds, until the record stays without a live run.
func TestCancelOnTheMachineWithoutTheLockLooksAgain(t *testing.T) {
	defer approval.SetRunLockWait(20*time.Millisecond, 40*time.Millisecond)()
	r := newRunRig(t)
	r.armed(runA)
	armed := r.record(t)
	release, err := r.files.RunLockHold() // somebody else holds the lock: the command goes on without it
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	var renames, putBack atomic.Int32
	restore := approval.SetRunRename(func(from, to string) error {
		if err := os.Rename(from, to); err != nil {
			return err
		}
		if renames.Add(1) <= 2 { // twice: the run is put back right after the command's cancel took the name
			putBack.Add(1)
			return os.WriteFile(to, armed, 0o600)
		}
		return nil
	}, func(error) bool { return false }, time.Millisecond, time.Millisecond, time.Millisecond)
	defer restore()
	was, changed, err := r.files.RunCancel(r.stamp())
	if err != nil || !changed || was.State != api.RunArmed {
		t.Fatalf("helper-run cancel: %+v %v %v", was, changed, err)
	}
	if putBack.Load() != 2 || renames.Load() != 3 {
		t.Errorf("the run was put back %d times and the command wrote %d times, want 2 and 3", putBack.Load(), renames.Load())
	}
	if v := r.files.RunShow(); v.ID != "" || v.LastState != api.RunCancelled {
		t.Errorf("the command returned \"cancelled\" and the record says: %+v", v)
	}
}

// An armed run has no time at which its shutdown was scheduled; one that is counting down has one, and it is
// not before the time the ticket was taken. A record that says otherwise is not one this program wrote, and is
// not believed (nothing is armed by it and nothing switched off).
func TestRunRecordWhoseStateDoesNotFitItsTimes(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA) // at 60 s of uptime
	good := r.record(t)
	edit := func(f func(run map[string]any)) []byte {
		t.Helper()
		var rec map[string]any
		if err := json.Unmarshal(good, &rec); err != nil {
			t.Fatal(err)
		}
		f(rec["run"].(map[string]any))
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for name, b := range map[string][]byte{
		"armed, with the time of a shutdown":              edit(func(run map[string]any) { run["off_up_ms"] = 60000 }),
		"counting down, without the time it began":        edit(func(run map[string]any) { run["state"] = api.RunOffPending }),
		"counting down since before the ticket was taken": edit(func(run map[string]any) { run["state"] = api.RunOffPending; run["off_up_ms"] = 59999 }),
	} {
		if err := os.WriteFile(r.files.RunPath(), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := r.files.RunRecordCheck(); err == nil {
			t.Errorf("%s: the record is believed", name)
		}
		r.restart()
		r.ticks(1200 * time.Second)
		if st := r.run(); st != nil || len(r.scheduled) != 0 {
			t.Errorf("%s: run %+v, switched off %+v", name, st, r.scheduled)
		}
	}
	// the two that are this program's
	for name, b := range map[string][]byte{
		"armed":         good,
		"counting down": edit(func(run map[string]any) { run["state"] = api.RunOffPending; run["off_up_ms"] = 60000 }),
	} {
		if err := os.WriteFile(r.files.RunPath(), b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := r.files.RunRecordCheck(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
