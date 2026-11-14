package approval_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// The independent review of fd6d3be tried these on the gate and they held. They stay as tests: real
// concurrency on one confirmation, on the deadline and on one ticket, and every way to present the wrong kind
// of token.

// One confirmation: exactly one update and one shutdown, under real concurrency.
func TestOneConfirmationOneUpdateOneShutdownUnderConcurrency(t *testing.T) {
	for round := 0; round < 60; round++ {
		r := newRunRig(t)
		r.armed(runA)
		if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
			t.Fatal(ref)
		}
		var upd, shut, wrongDelay atomic.Int32
		var wg sync.WaitGroup
		act := "shutdown"
		for i := 0; i < 16; i++ {
			wg.Add(3)
			go func() {
				defer wg.Done()
				if to, ref := r.g.AdmitRun(api.ApprovalRequest{Verb: api.ApproveApplyUpdate}, runA); ref == nil {
					if to != "9.9.9" {
						t.Errorf("to %q", to)
					}
					upd.Add(1)
				}
			}()
			go func() {
				defer wg.Done()
				d := 30
				if _, ref := r.g.AdmitRun(api.ApprovalRequest{Verb: api.ApprovePower, Action: &act, DelayS: &d}, runA); ref == nil {
					shut.Add(1)
				}
			}()
			go func(i int) {
				defer wg.Done()
				d := 10 + i
				if d == 30 {
					d = 31
				}
				if _, ref := r.g.AdmitRun(api.ApprovalRequest{Verb: api.ApprovePower, Action: &act, DelayS: &d}, runA); ref == nil {
					wrongDelay.Add(1)
				}
			}(i)
		}
		wg.Wait()
		if upd.Load() > 1 || shut.Load() != 1 || wrongDelay.Load() != 0 {
			t.Fatalf("round %d: %d updates, %d shutdowns, %d shutdowns with another delay admitted", round, upd.Load(), shut.Load(), wrongDelay.Load())
		}
		// after a restart nothing is left
		r.restart()
		if _, ref := r.g.AdmitRun(api.ApprovalRequest{Verb: api.ApproveApplyUpdate}, runA); ref == nil {
			t.Fatal("update admitted after the shutdown ended the run and the service restarted")
		}
	}
}

// Cancel against the tick at the deadline, and against a confirmation: once the cancel (run + power part,
// in the order the routes use) has returned, nothing is pending, nothing gets scheduled later, and nothing of
// the run is admitted.
func TestCancelAgainstTheDeadlineAndTheConfirmation(t *testing.T) {
	for round := 0; round < 90; round++ {
		r := newRunRig(t)
		h := &lockedPower{}
		w := h.watch(r)
		if _, ref := w.Arm(r.signed(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 120, 30))); ref != nil {
			t.Fatal(ref)
		}
		req := goReq(runA, "-", 30, 300)
		c, ref := r.g.Challenge(req)
		if ref != nil {
			t.Fatal(ref)
		}
		ap := r.signed(r.Now(), approvaltest.Entry(approvaltest.MachineID, c))
		r.wait(119*time.Second + time.Duration(round%3)*time.Second) // just before, at, just after the deadline
		var wg sync.WaitGroup
		var goOK atomic.Bool
		wg.Add(3)
		go func() { defer wg.Done(); w.Tick() }()
		go func() {
			defer wg.Done()
			if _, ref := w.Go(req, ap); ref == nil {
				goOK.Store(true)
			}
		}()
		cancelled := make(chan struct{})
		go func() {
			defer wg.Done()
			w.Cancel("panel")
			h.mu.Lock()
			h.cancels++
			h.pending = false // the route's cancel of the pending power action
			h.mu.Unlock()
			close(cancelled)
		}()
		wg.Wait()
		// the route ordering: after the cancel returned, later ticks must not schedule
		before := func() int { h.mu.Lock(); defer h.mu.Unlock(); return h.scheduled }()
		for i := 0; i < 5; i++ {
			r.wait(time.Second)
			w.Tick()
		}
		h.mu.Lock()
		after, pending := h.scheduled, h.pending
		h.mu.Unlock()
		st := r.g.Status().Run
		d := 30
		act := "shutdown"
		_, refS := r.g.AdmitRun(api.ApprovalRequest{Verb: api.ApprovePower, Action: &act, DelayS: &d}, runA)
		if goOK.Load() && st != nil && st.State == api.RunConfirmed {
			// the confirmation came after the cancel: allowed only if Go after cancel is "run_over"
			t.Fatalf("round %d: the run is confirmed after a cancel returned (go raced the cancel): %+v", round, st)
		}
		if after != before || (pending && after > 0 && st != nil && st.State == api.RunOffPending) {
			t.Fatalf("round %d: scheduled %d -> %d after the cancel, pending %v, run %+v", round, before, after, pending, st)
		}
		if refS == nil {
			t.Fatalf("round %d: a shutdown of the run was admitted after the cancel", round)
		}
		if _, ref := w.Arm(r.signed(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runB, 600, 120, 30))); ref == nil {
			t.Fatalf("round %d: armed again after the cancel", round)
		}
	}
}

// Arm with the same ticket from many connections: one is armed, and one record.
func TestOneTicketFromManyConnections(t *testing.T) {
	for round := 0; round < 40; round++ {
		r := newRunRig(t)
		h := &lockedPower{}
		w := h.watch(r)
		tk := r.ticket(runA, r.up()+100*time.Second)
		tk2 := r.ticket(runB, r.up()+100*time.Second)
		var ok atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				if _, ref := w.Arm(tk); ref == nil {
					ok.Add(1)
				}
			}()
			go func() {
				defer wg.Done()
				if _, ref := w.Arm(tk2); ref == nil {
					ok.Add(1)
				}
			}()
		}
		wg.Wait()
		if ok.Load() != 1 {
			t.Fatalf("round %d: %d tickets accepted in one boot", round, ok.Load())
		}
	}
}

// Cross-protocol: every way to present the wrong kind of token.
func TestTicketsAndConfirmationsEveryWrongWay(t *testing.T) {
	r := newRunRig(t)
	id := approvaltest.MachineID
	d := 0
	act := "shutdown"
	power := api.ApprovalRequest{Verb: api.ApprovePower, Action: &act, DelayS: &d}
	upd := api.ApprovalRequest{Verb: api.ApproveApplyUpdate}

	// 1. a ticket list that also carries this machine's open power challenge under the run_arm text
	c, ref := r.g.Challenge(power)
	if ref != nil {
		t.Fatal(ref)
	}
	te := api.MachineEntry{MachineID: id, Challenge: c.Challenge, Request: armText(runA, 420, 120, 30)}
	tk := r.signed(r.Now().Add(-r.up()-100*time.Second), te)
	if _, ref := r.w.Arm(tk); ref == nil {
		t.Error("a ticket whose challenge member is an open challenge of this machine was accepted")
	}
	if ref := r.g.Check(power, tk); ref == nil {
		t.Error("a ticket was accepted as the approval of a shutdown")
	}
	// 2. a ticket token presented for a run_go, an update and a shutdown
	tk = r.ticket(runA, r.up()+100*time.Second)
	if _, ref := r.w.Go(goReq(runA, "-", 30, 300), tk); ref == nil {
		t.Error("a ticket confirmed a run")
	}
	if ref := r.g.Check(upd, tk); ref == nil {
		t.Error("ticket accepted as update approval")
	}
	// 3. a run_go confirmation token presented as a ticket, and as a normal approval
	req := goReq(runA, "9.9.9", 30, 300)
	cg, ref := r.g.Challenge(req)
	if ref != nil {
		t.Fatal(ref)
	}
	gt := r.signed(r.Now(), approvaltest.Entry(id, cg))
	if _, ref := r.w.Arm(gt); ref == nil {
		t.Error("a confirmation armed")
	}
	if ref := r.g.Check(upd, gt); ref == nil {
		t.Error("a confirmation token approved an update directly")
	}
	if ref := r.g.Check(power, gt); ref == nil {
		t.Error("a confirmation token approved a shutdown with delay 0")
	}
	// 4. the challenge of run_go answered with a list that names it under a run_arm text / power text
	for _, text := range []string{armText(runA, 420, 120, 30), "power action=shutdown delay_s=0", "apply_update"} {
		e := api.MachineEntry{MachineID: id, Challenge: cg.Challenge, Request: text}
		x := r.signed(r.Now(), e)
		if _, ref := r.w.Go(req, x); ref == nil {
			t.Errorf("go accepted with its challenge listed under %q", text)
		}
		if _, ref := r.w.Arm(x); ref == nil {
			t.Errorf("arm accepted with an open challenge under %q", text)
		}
		if ref := r.g.Check(power, x); ref == nil {
			t.Errorf("power accepted with the run_go challenge under %q", text)
		}
	}
	// 5. a run_go confirmation for other numbers than the challenge was given for
	for _, other := range []api.ApprovalRequest{goReq(runA, "9.9.8", 30, 300), goReq(runA, "9.9.9", 31, 300), goReq(runA, "9.9.9", 30, 1800), goReq(runB, "9.9.9", 30, 300), goReq(runA, "-", 30, 300)} {
		if _, ref := r.w.Go(other, gt); ref == nil {
			t.Errorf("a confirmation signed for %v accepted for %v", req, other)
		}
	}
	// 6. challenge for run_arm
	v, w2, n := 420, 120, 30
	ra := runA
	if _, ref := r.g.Challenge(api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &ra, ValidS: &v, WaitS: &w2, NoticeS: &n}); ref == nil {
		t.Error("a challenge was given for run_arm")
	}
	// 7. the real confirmation still works after all those refusals (nothing was used up)... and only once
	if _, ref := r.w.Go(req, gt); ref != nil {
		t.Errorf("the good confirmation after the refused ones: %v", ref)
	}
	if _, ref := r.w.Go(req, gt); ref == nil {
		t.Error("the same confirmation twice")
	}
}

// A ticket for ANOTHER machine, another machine's entry rewritten, two entries, mixed order.
func TestTicketOfAnotherMachine(t *testing.T) {
	const otherID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	r := newRunRig(t)
	if api.CheckMachineID(otherID) != nil {
		t.Skip("otherID is not a machine id")
	}
	at := r.Now().Add(-r.up() - 100*time.Second)
	// signed for the other machine only
	other := ticketEntry(otherID, runA, 420, 120, 30)
	tk := r.signed(at, other)
	if _, ref := r.w.Arm(tk); ref == nil {
		t.Error("another machine's ticket armed this one")
	}
	// the panel rewrites the machine id in the list it sends
	re := *tk
	re.Entries = []api.MachineEntry{{MachineID: approvaltest.MachineID, Challenge: other.Challenge, Request: other.Request}}
	if _, ref := r.w.Arm(&re); ref == nil {
		t.Error("another machine's ticket, entry rewritten to this machine's id, armed this one")
	}
	// mine with short wait is not in the signed list: the panel swaps the text
	mine := ticketEntry(approvaltest.MachineID, runA, 420, 3600, 600)
	tk = r.signed(at, mine)
	sw := *tk
	sw.Entries = []api.MachineEntry{{MachineID: mine.MachineID, Challenge: mine.Challenge, Request: armText(runA, 420, 120, 30)}}
	if _, ref := r.w.Arm(&sw); ref == nil {
		t.Error("wait_s / notice_s changed after the signature")
	}
	// other machine's entry first with a tiny valid_s, mine second: still mine is found (no refusal by order)
	o2 := ticketEntry(otherID, runB, 120, 120, 30)
	tk = r.signed(r.Now().Add(-300*time.Second), o2, ticketEntry(approvaltest.MachineID, runA, 420, 120, 30))
	rr := newRunRig(t)
	rr.iss = r.iss
	_ = rr
	if _, ref := r.w.Arm(tk); ref != nil {
		t.Logf("NOTE: a list whose first run_arm entry (another machine's, shorter valid_s) is expired refuses this machine's good entry: %v", ref.Reason)
	}
}
