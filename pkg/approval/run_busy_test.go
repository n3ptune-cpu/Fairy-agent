package approval_test

import (
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// On Windows the new record cannot take the record's name while another program has the record open without
// sharing it for that (a program that reads it the plain way, a virus scanner). The record's own readers
// share it now (openShared); for everybody else the writers try again: the service for a moment, the
// administrator's cancel for a few seconds instead of failing at once. (Not parallel: it changes what a
// rename is for the whole package.)
func TestRunRecordWritersTryAgainWhileTheFileIsOpenElsewhere(t *testing.T) {
	errBusy := errors.New("The process cannot access the file because it is being used by another process.")
	var fails atomic.Int32 // how many renames still fail
	var tries atomic.Int32
	restore := approval.SetRunRename(func(from, to string) error {
		tries.Add(1)
		if fails.Load() > 0 {
			fails.Add(-1)
			return errBusy
		}
		return os.Rename(from, to)
	}, func(err error) bool { return errors.Is(err, errBusy) }, 60*time.Millisecond, 400*time.Millisecond, 5*time.Millisecond)
	defer restore()

	// the administrator's cancel: the file is busy for a while, and the cancel goes through
	r := newRunRig(t)
	r.armed(runA)
	fails.Store(20) // 100 ms
	tries.Store(0)
	was, changed, err := r.files.RunCancel(r.stamp())
	if err != nil || !changed || was.State != api.RunArmed {
		t.Fatalf("helper-run cancel while the record was open elsewhere: %+v %v %v", was, changed, err)
	}
	if tries.Load() < 21 {
		t.Fatalf("%d tries", tries.Load())
	}
	r.w.Tick()
	if r.state() != api.RunCancelled {
		t.Fatalf("the run after the cancel: %q", r.state())
	}
	// busy for longer than the command waits: it fails, with the reason, in bounded time, and nothing is left behind
	r = newRunRig(t)
	r.armed(runA)
	fails.Store(1 << 20)
	start := time.Now()
	_, changed, err = r.files.RunCancel(r.stamp())
	if err == nil || changed || !errors.Is(err, errBusy) {
		t.Fatalf("helper-run cancel with the record open elsewhere for good: %v %v", changed, err)
	}
	if d := time.Since(start); d < 300*time.Millisecond || d > 5*time.Second {
		t.Errorf("the command gave up after %s, want about 400 ms", d)
	}
	ents, _ := os.ReadDir(r.files.RunPath() + "/..")
	for _, e := range ents {
		if e.Name() != approval.RunFileName && e.Name() != approval.TrustFileName && e.Name() != approval.RunLockName {
			t.Errorf("left behind: %s", e.Name())
		}
	}
	// the service: a write that fails is tried again at the next step, and until then nothing of a run is taken
	fails.Store(0)
	r = newRunRig(t)
	fails.Store(1 << 20)
	_, ref := r.w.Arm(r.ticket(runA, r.up()+100*time.Second))
	runRefused(t, "a ticket that cannot be written down", ref, 503, api.CodeRunUnavailable, "")
	fails.Store(3) // a moment only: the service's own short wait covers it
	if _, ref := r.w.Arm(r.ticket(runA, r.up()+100*time.Second)); ref != nil {
		t.Fatalf("a ticket while the record was open elsewhere for a moment: %v", ref)
	}
	// another error than "busy" is not tried again
	fails.Store(0)
	r = newRunRig(t)
	r.armed(runA)
	tries.Store(0)
	restore2 := approval.SetRunRename(func(string, string) error { tries.Add(1); return errors.New("disk full") },
		func(err error) bool { return errors.Is(err, errBusy) }, 60*time.Millisecond, 400*time.Millisecond, 5*time.Millisecond)
	_, _, err = r.files.RunCancel(r.stamp())
	restore2()
	if err == nil || tries.Load() != 1 {
		t.Fatalf("an error that is not \"busy\": %v after %d tries", err, tries.Load())
	}
}
