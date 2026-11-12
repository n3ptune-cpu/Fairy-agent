package approval_test

// Audit 5, round 1: the gate's part of the fixes.

import (
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// admitted checks that ref is nil and returns the pass.
func admitted(t *testing.T, what string, pass *approval.Pass, ref *approval.Refusal) *approval.Pass {
	t.Helper()
	if ref != nil {
		t.Fatalf("%s: refused: %v", what, ref)
	}
	return pass
}

func needsApproval(t *testing.T, what string, g *approval.Gate, req api.ApprovalRequest) {
	t.Helper()
	_, ref := g.Admit(req, nil)
	refused(t, what, ref, api.CodeApprovalRequired, "")
	if c, cref := g.Challenge(req); cref != nil || !c.Needed {
		t.Errorf("%s: the challenge says no approval is needed: %+v, %v", what, c, cref)
	}
}

// TestFanWindowOpensOnlyWhenTheChangeWasApplied (r1-a1-04, r1-a2-02): an accepted approval of a fan change used
// to open the 30 s fan window at once. A request the machine then refused (a duty under the minimum: 400), or
// that changed nothing (not in "full" mode: 409), left every other fan change unapproved for 30 s. The window
// now opens when the caller says the change was applied, and counts from the moment the approval was accepted.
func TestFanWindowOpensOnlyWhenTheChangeWasApplied(t *testing.T) {
	r := newRig(t, true)

	// accepted, then refused by the fan controller: the caller never calls Applied
	req := fanSet(0, 5)
	ap := r.approve(req)
	pass, ref := r.g.Admit(req, ap)
	if admitted(t, "approved fan_set", pass, ref) == nil {
		t.Fatal("an accepted approval of a fan change gave no pass")
	}
	needsApproval(t, "fan mode after an approved request that was not applied", r.g, fanMode("full"))
	needsApproval(t, "fan duty after an approved request that was not applied", r.g, fanSet(1, 30))
	_, ref = r.g.Admit(req, ap)
	refused(t, "the approval is used up all the same", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// accepted and applied: open, for fans only
	req = fanMode("full")
	pass, ref = r.g.Admit(req, r.approve(req))
	admitted(t, "approved fan_mode", pass, ref)
	needsApproval(t, "before Applied", r.g, fanSet(0, 60))
	r.wait(12 * time.Second) // the BMC took its time
	pass.Applied()
	if p, ref := r.g.Admit(fanSet(0, 60), nil); ref != nil || p != nil {
		t.Fatalf("fan change inside the window: pass %v, refusal %v", p, ref)
	}
	if c, cref := r.g.Challenge(fanSet(1, 70)); cref != nil || c.Needed || c.Reason != "fan_window" {
		t.Errorf("challenge in the window: %+v, %v", c, cref)
	}
	needsApproval(t, "shutdown in the fan window", r.g, power("shutdown", 60))
	if !strings.Contains(r.log.String(), "fan window open, the approved fan change was applied") {
		t.Errorf("the log does not say that the window was opened:\n%s", r.log.String())
	}
	// counted from the acceptance, not from Applied: 12 s are gone already
	r.wait(17 * time.Second)
	if _, ref := r.g.Admit(fanSet(0, 61), nil); ref != nil {
		t.Fatalf("29 s after the approval was accepted: %v", ref)
	}
	r.wait(time.Second)
	needsApproval(t, "30 s after the approval was accepted", r.g, fanSet(0, 62))
	// a second Applied of the same pass does not open it again
	pass.Applied()
	needsApproval(t, "Applied twice", r.g, fanSet(0, 62))

	// a change that passes inside the window gives no pass, so it cannot stretch the window
	req = fanMode("optimal")
	pass, ref = r.g.Admit(req, r.approve(req))
	admitted(t, "approved again", pass, ref).Applied()
	r.wait(20 * time.Second)
	p, ref := r.g.Admit(fanSet(0, 70), nil)
	admitted(t, "inside", p, ref).Applied() // nil pass: nothing happens
	r.wait(10 * time.Second)
	needsApproval(t, "the window was not stretched", r.g, fanSet(0, 71))

	// an approved shutdown or update gives no pass at all
	for _, q := range []api.ApprovalRequest{power("shutdown", 60), update} {
		if p, ref := r.g.Admit(q, r.approve(q)); ref != nil || p != nil {
			t.Errorf("%v: pass %v, refusal %v", q.Verb, p, ref)
		}
	}
	needsApproval(t, "fan after an approved shutdown", r.g, fanSet(0, 50))
}

// TestFanWindowNotOpenedUnderAChangedTrust: the approval was accepted under one trust file; when the change is
// reported as applied, the administrator has changed the file (another user list, the window switched off).
// What was given under the old file does not count under the new one.
func TestFanWindowNotOpenedUnderAChangedTrust(t *testing.T) {
	r := newRig(t, true)
	req := fanMode("full")
	pass, ref := r.g.Admit(req, r.approve(req))
	admitted(t, "approved", pass, ref)
	r.setLocal(func(tr *approval.Trust) { tr.Users = []string{"someone-else"} })
	r.g.Status() // the gate has seen the new file
	pass.Applied()
	needsApproval(t, "fan change after the trust changed", r.g, fanSet(0, 60))

	// fan_window_s 0: Applied opens nothing
	r2 := newRig(t, true)
	r2.setLocal(func(tr *approval.Trust) { tr.FanWindowS = ip(0) })
	pass, ref = r2.g.Admit(req, r2.approve(req))
	admitted(t, "approved, window off", pass, ref).Applied()
	needsApproval(t, "window off", r2.g, fanSet(0, 60))
}
