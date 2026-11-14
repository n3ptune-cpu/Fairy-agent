package approval_test

import (
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Rules that only the random sequences held (review of fd6d3be: the changes R02, R07, R08, R09 to the gate were
// found by TestRandomRunSequences alone, or by nothing). Each has its own test here, to the value.

// A run that is armed and not confirmed lets nothing through: not its update, not its shutdown, not with the
// look that uses nothing up and not with the one that does. And it stays armed.
func TestArmedRunLetsNothingThrough(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	for _, req := range []api.ApprovalRequest{update, power("shutdown", 30), power("shutdown", 120), power("reboot", 30)} {
		if _, ref := r.g.RunCovers(req, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
			t.Errorf("an armed run covers %s: %v", req.Verb, ref)
		}
		if _, ref := r.g.AdmitRun(req, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
			t.Errorf("an armed run let %s through: %v", req.Verb, ref)
		}
	}
	if st := r.state(); st != api.RunArmed {
		t.Errorf("the run is %q", st)
	}
	// counting down: the same
	r.ticks(961 * time.Second)
	if st := r.state(); st != api.RunOffPending {
		t.Fatalf("the run is %q", st)
	}
	for _, req := range []api.ApprovalRequest{update, power("shutdown", 120)} {
		if _, ref := r.g.AdmitRun(req, runA); ref == nil {
			t.Errorf("a run that is counting down let %s through", req.Verb)
		}
	}
}

// The run's one shutdown is the one the confirmation named: a shutdown, with exactly its delay. Not a longer
// delay (the moment would be the panel's to choose), not a shorter one, not a reboot or a sleep with that
// delay, not for another run. None of the refused requests uses the shutdown up.
func TestRunShutdownIsExactlyTheOneConfirmed(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "-", 45, 600)); ref != nil {
		t.Fatal(ref)
	}
	for _, c := range []struct {
		what string
		req  api.ApprovalRequest
		run  string
	}{
		{"a longer delay", power("shutdown", 46), runA}, {"a much longer delay", power("shutdown", 86400), runA},
		{"a shorter delay", power("shutdown", 44), runA}, {"no delay", power("shutdown", 0), runA},
		{"a reboot with the delay", power("reboot", 45), runA}, {"a sleep with the delay", power("sleep", 45), runA},
		{"another run", power("shutdown", 45), runB}, {"a run id that is none", power("shutdown", 45), "00000000000000AA"},
		{"an update (the confirmation named none)", update, runA},
	} {
		for _, use := range []bool{false, true} {
			var ref error
			if use {
				if _, rf := r.g.AdmitRun(c.req, c.run); rf != nil {
					ref = rf
				}
			} else if _, rf := r.g.RunCovers(c.req, c.run); rf != nil {
				ref = rf
			}
			if ref == nil {
				t.Errorf("%s was let through (used up: %v)", c.what, use)
			}
		}
	}
	if st := r.state(); st != api.RunConfirmed {
		t.Fatalf("after the refused requests the run is %q", st)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 45), runA); ref != nil {
		t.Fatalf("the shutdown that was confirmed: %v", ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 45), runA); ref == nil {
		t.Fatal("the run's shutdown was let through twice")
	}
	if st := r.state(); st != api.RunDone {
		t.Errorf("after its shutdown the run is %q", st)
	}
}

// The update of a run is handed the version the confirmation named, and no other.
func TestRunUpdateIsHandedTheVersionConfirmed(t *testing.T) {
	r := newRunRig(t)
	if _, ref := r.confirm(goReq(runA, "9.9.9-rc1+b", 45, 600)); ref != nil {
		t.Fatal(ref)
	}
	if to, ref := r.g.RunCovers(update, runA); ref != nil || to != "9.9.9-rc1+b" {
		t.Fatalf("the look: %q %v", to, ref)
	}
	if to, ref := r.g.AdmitRun(update, runA); ref != nil || to != "9.9.9-rc1+b" {
		t.Fatalf("the update: %q %v", to, ref)
	}
	if to, ref := r.g.AdmitRun(update, runA); ref == nil || to != "" {
		t.Fatalf("a second update: %q %v", to, ref)
	}
}
