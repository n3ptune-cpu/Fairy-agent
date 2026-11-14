package approval_test

import (
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// noSpace makes every rename of the run record fail, as a full disk or a read-only file system does, and
// counts the tries. (The tests that use it are not parallel: it changes what a rename is for the whole package.)
func noSpace(t *testing.T) (tries *atomic.Int32, works func()) {
	t.Helper()
	tries = new(atomic.Int32)
	var ok atomic.Bool
	restore := approval.SetRunRename(func(from, to string) error {
		tries.Add(1)
		if ok.Load() {
			return os.Rename(from, to)
		}
		return errors.New("no space left on device")
	}, func(error) bool { return false }, time.Millisecond, time.Millisecond, time.Millisecond)
	t.Cleanup(restore)
	return tries, func() { ok.Store(true) }
}

// A machine with trust and no run at all, whose record cannot be written for a while (a full disk, a read-only
// file system, the lock held): the service is behind with its ten-minute note of the clock. A cancel of the
// pending power action, which ends a run when there is one, has nothing to end, and said "the end of the run
// could not be written down; cancel again" all the same: every Cancel in the panel was an error although the
// countdown was stopped (second review of the runs, U1; v0.8.0 answered 200). The error is the write's only
// when the record on disk still holds a live run.
func TestCancelWithoutARunIsNoErrorWhileTheRecordCannotBeWritten(t *testing.T) {
	r := newRunRig(t)
	noSpace(t)
	r.ticks(11 * time.Minute) // the ten-minute look at the clock tries to write and cannot
	if r.run() != nil {
		t.Fatal("there is a run")
	}
	for i := 0; i < 3; i++ {
		if was, err := r.w.Cancel("a cancel of the pending power action"); was != "" || err != nil {
			t.Fatalf("cancel %d on a machine without a run whose record cannot be written: was %q, %v", i, was, err)
		}
	}
	if was, err := r.g.DisarmRun("the same, asked of the gate"); was != "" || err != nil {
		t.Fatalf("DisarmRun: %q %v", was, err)
	}
}

// What stays an error: the end of a live run that could not be written down. The file still says the run is
// live, so a service that starts again would find it; the cancel is not answered "cancelled", this time and
// every time until the end is on disk (T1 and R42 of the first review).
func TestCancelOfARunThatCannotBeWrittenDownStaysAnError(t *testing.T) {
	for _, state := range []string{api.RunArmed, api.RunConfirmed} {
		r := newRunRig(t)
		if state == api.RunArmed {
			r.armed(runA)
		} else if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
			t.Fatal(ref)
		}
		_, works := noSpace(t)
		was, err := r.w.Cancel("panel")
		if was != state || err == nil {
			t.Fatalf("%s: the cancel whose end could not be written: was %q, %v", state, was, err)
		}
		// what the machine says of itself: the run as the file has it, until its end is written (a Windows
		// agent asks the helper this to know whether a cancel must go to it)
		if st := r.state(); st != state {
			t.Errorf("%s: the status says %q while the end of the run is not written", state, st)
		}
		for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} { // and it is over all the same
			if _, ref := r.g.AdmitRun(req, runA); ref == nil {
				t.Errorf("%s: %s let through after the cancel", state, req.Verb)
			}
		}
		r.ticks(1200 * time.Second)
		if len(r.scheduled) != 0 {
			t.Fatalf("%s: the service that took the cancel switched the machine off: %+v", state, r.scheduled)
		}
		for i := 0; i < 3; i++ { // again: nothing live in memory any more, and the file still has the run
			r.wait(time.Second)
			if was, err := r.w.Cancel("panel"); was != "" || err == nil {
				t.Fatalf("%s: cancel again while the file still holds the run: was %q, %v", state, was, err)
			}
		}
		if v := r.files.RunShow(); v.ID != runA || v.State != state {
			t.Fatalf("%s: the record: %+v", state, v)
		}
		works()
		if was, err := r.w.Cancel("panel"); was != "" || err != nil {
			t.Errorf("%s: cancel once the disk has room: was %q, %v", state, was, err)
		}
		if v := r.files.RunShow(); v.ID != "" || v.LastState != api.RunCancelled {
			t.Errorf("%s: the record after it: %+v", state, v)
		}
		if st := r.state(); st != api.RunCancelled {
			t.Errorf("%s: the status once the end is written: %q", state, st)
		}
	}
}

// Not knowing counts as "it does": when the record cannot be read back either, the cancel of a machine that
// is behind with a write stays an error.
func TestCancelIsAnErrorWhenNobodyCanSayWhatTheRecordHolds(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	noSpace(t)
	if _, err := r.w.Cancel("panel"); err == nil {
		t.Fatal("the end of the run was not written and the cancel says nothing")
	}
	r.dirErr = errors.New("the folder cannot be looked at")
	if was, err := r.w.Cancel("panel"); was != "" || err == nil {
		t.Fatalf("cancel with a record nobody can read: was %q, %v", was, err)
	}
}

// While the record cannot be written the service does not try at every look (once a second) and at every
// status question, and does not write a line each time (about 70 a minute): it tries every quarter of a minute,
// says so once, and says once when it works again. A request that needs the record tries at once.
func TestRecordThatCannotBeWrittenIsTriedWithAPauseAndSaidOnce(t *testing.T) {
	const line, again = "the run record could not be written", "the run record is written again"
	r := newRunRig(t)
	tries, works := noSpace(t)
	r.ticks(11 * time.Minute)
	if n := strings.Count(r.log.String(), line); n != 1 {
		t.Fatalf("%d lines %q after the first failure, want 1", n, line)
	}
	before := tries.Load()
	r.ticks(60 * time.Second)
	for i := 0; i < 10; i++ {
		r.g.Status() // GET /metrics
	}
	if n := tries.Load() - before; n < 3 || n > 5 {
		t.Errorf("%d tries in a minute of looks and ten status questions, want one every %s", n, approval.RunRetryEvery)
	}
	if n := strings.Count(r.log.String(), line); n != 1 {
		t.Errorf("%d lines %q after another minute, want still 1", n, line)
	}
	// a ticket is a request that needs the record: tried at once, refused, and no new line
	before = tries.Load()
	_, ref := r.w.Arm(r.ticket(runA, time.Second))
	runRefused(t, "a ticket while the record cannot be written", ref, 503, api.CodeRunUnavailable, "")
	if tries.Load() == before {
		t.Error("the ticket was refused without a try")
	}
	works()
	r.ticks(approval.RunRetryEvery + time.Second)
	if n := strings.Count(r.log.String(), again); n != 1 {
		t.Errorf("%d lines %q, want 1:\n%s", n, again, r.log.String())
	}
	r.ticks(time.Minute)
	if n, m := strings.Count(r.log.String(), line), strings.Count(r.log.String(), again); n != 1 || m != 1 {
		t.Errorf("after it worked again: %d and %d lines", n, m)
	}
	// and the next time it fails it is said again
}
