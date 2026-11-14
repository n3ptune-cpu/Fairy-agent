package approval_test

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// The administrator's command looks at the record again a moment after it wrote (approval.Files.RunCancel);
// in the tests that moment is a millisecond.
func TestMain(m *testing.M) {
	approval.SetRunCancelSettle(time.Millisecond)
	os.Exit(m.Run())
}

// `fairy-agent helper-run cancel` writes the record; the service saw that at the next look of its watch, up
// to a second later. In between, the run's one update and its one shutdown were still let through from what
// the service remembered: the cancel on the machine could lose against a request that arrived after it
// (review of fd6d3be, T7). The admission now reads the record itself.
func TestRunAdmissionSeesTheCancelOnTheMachineAtOnce(t *testing.T) {
	for _, req := range []api.ApprovalRequest{power("shutdown", 30), update} {
		for _, use := range []bool{true, false} {
			r := newRunRig(t)
			r.armed(runA)
			if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
				t.Fatal(ref)
			}
			if _, changed, err := r.files.RunCancel(r.stamp()); err != nil || !changed {
				t.Fatalf("helper-run cancel: %v %v", changed, err)
			}
			// no look of the watch in between
			var ref error
			if use {
				_, rf := r.g.AdmitRun(req, runA)
				if rf != nil {
					ref = rf
				}
			} else if _, rf := r.g.RunCovers(req, runA); rf != nil {
				ref = rf
			}
			if ref == nil {
				t.Errorf("%s (used up: %v) of the run was let through after helper-run cancel had returned", req.Verb, use)
			}
			if st := r.state(); st != api.RunCancelled {
				t.Errorf("%s: the run is %q after the cancel on the machine", req.Verb, st)
			}
		}
	}
}

// The same with real concurrency: the administrator's command and requests of the run at the same moment, the
// watch looking all the while. Whatever the order, a request that is made after the command returned is
// refused; and what the run let through is at most its one update and its one shutdown.
func TestRunAdmissionAgainstTheCancelOnTheMachine(t *testing.T) {
	rounds := 150
	if testing.Short() {
		rounds = 20
	}
	for round := 0; round < rounds; round++ {
		r := newRunRig(t)
		h := &lockedPower{}
		w := h.watch(r)
		if _, ref := w.Arm(r.ticket(runA, r.up()+100*time.Second)); ref != nil {
			t.Fatal(ref)
		}
		if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
			t.Fatal(ref)
		}
		var cancelled atomic.Bool
		var after, updates, shutdowns atomic.Int32
		var wg sync.WaitGroup
		stop := make(chan struct{})
		wg.Add(1)
		go func() { // the watch
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					w.Tick()
				}
			}
		}()
		start := make(chan struct{})
		var reqs sync.WaitGroup
		for i := 0; i < 8; i++ {
			reqs.Add(1)
			go func(i int) {
				defer reqs.Done()
				<-start
				for n := 0; n < 6; n++ {
					req := update
					if (i+n)%2 == 0 {
						req = power("shutdown", 30)
					}
					was := cancelled.Load() // the command had returned before this request was made
					if _, ref := r.g.AdmitRun(req, runA); ref == nil {
						if was {
							after.Add(1)
						}
						if req.Verb == api.ApproveApplyUpdate {
							updates.Add(1)
						} else {
							shutdowns.Add(1)
						}
					}
				}
			}(i)
		}
		reqs.Add(1)
		go func() {
			defer reqs.Done()
			<-start
			if round%3 > 0 {
				time.Sleep(time.Duration(round%7) * 50 * time.Microsecond)
			}
			if _, _, err := r.files.RunCancel(r.stamp()); err != nil {
				t.Errorf("helper-run cancel: %v", err)
			}
			cancelled.Store(true)
		}()
		close(start)
		reqs.Wait()
		close(stop)
		wg.Wait()
		if after.Load() != 0 {
			t.Fatalf("round %d: %d requests of the run were let through after helper-run cancel had returned", round, after.Load())
		}
		if updates.Load() > 1 || shutdowns.Load() > 1 {
			t.Fatalf("round %d: %d updates and %d shutdowns of one run", round, updates.Load(), shutdowns.Load())
		}
		for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
			if _, ref := r.g.AdmitRun(req, runA); ref == nil {
				t.Fatalf("round %d: %s let through when everything was over", round, req.Verb)
			}
		}
	}
}

// lockedPower is a machine's power part with a lock of its own, for the tests with real concurrency.
type lockedPower struct {
	mu        sync.Mutex
	pending   bool
	scheduled int
	cancels   int
}

func (h *lockedPower) watch(r *runRig) *approval.RunWatch {
	return approval.NewRunWatch(r.g, approval.RunHooks{
		Pending: func() bool { h.mu.Lock(); defer h.mu.Unlock(); return h.pending },
		Shutdown: func(time.Duration, string, string) error {
			h.mu.Lock()
			defer h.mu.Unlock()
			h.scheduled++
			h.pending = true
			return nil
		},
		Cancel: func() error { h.mu.Lock(); defer h.mu.Unlock(); h.cancels++; h.pending = false; return nil },
	})
}

// The other half of the race: the service has looked at the record and is about to write (the run's update
// is used up), and the administrator's cancel lands in that moment. The service never writes over a record
// it has not read: the cancel stays, the request is not let through, and the run is over.
func TestServiceDoesNotWriteOverACancelItHasNotSeen(t *testing.T) {
	for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
		r := newRunRig(t)
		r.armed(runA)
		if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
			t.Fatal(ref)
		}
		// the cancel lands after the service's look at the folder and before its write
		landed := false
		r.files.Prepare = func(string) error {
			if !landed {
				landed = true
				if _, changed, err := r.files.RunCancel(r.stamp()); err != nil || !changed {
					t.Errorf("helper-run cancel: %v %v", changed, err)
				}
			}
			return nil
		}
		r.restart() // the service with the hook in its files; it takes the confirmed run over from the record
		if _, ref := r.g.AdmitRun(req, runA); ref == nil {
			t.Errorf("%s was let through although the cancel was on disk before the service wrote", req.Verb)
		}
		if !landed {
			t.Fatal("the cancel never landed: the test tests nothing")
		}
		if v := r.files.RunShow(); v.ID != "" || v.LastState != api.RunCancelled {
			t.Errorf("%s: the cancel was written over: %+v", req.Verb, v)
		}
		for _, later := range []api.ApprovalRequest{update, power("shutdown", 30)} {
			if _, ref := r.g.AdmitRun(later, runA); ref == nil {
				t.Errorf("after the cancel that landed during %s: %s let through", req.Verb, later.Verb)
			}
		}
		if st := r.state(); st != api.RunCancelled {
			t.Errorf("%s: the run is %q", req.Verb, st)
		}
	}
}
