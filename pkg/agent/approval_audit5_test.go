package agent_test

// Audit 5, round 1: regression tests built from the auditors' proofs (audit5/r1-a1/poc, audit5/r1-a2/poc), over
// the agent's real HTTP handler: the Linux agent with its own gate (newLinuxRig) and the Windows agent in front
// of the real helper code (newApprovalRig).

import (
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// trusted sets the trust of a rig's machine the way the panel does (first-time set with its proof).
func (r *lrig) trusted(t *testing.T) *lrig {
	t.Helper()
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	return r
}

func (r *aprig) trusted(t *testing.T) *aprig {
	t.Helper()
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	r.approvalBlock(t, api.ApprovalRequired)
	return r
}

// fanWindowClosed checks, over HTTP, that no fan change runs without an approval right now and that the fan
// window never lets a shutdown through.
func fanWindowClosed(t *testing.T, when string, post func(*testing.T, string, any) (int, map[string]any)) {
	t.Helper()
	st, b := post(t, "/fan/mode", map[string]any{"mode": "full"})
	wantRefusal(t, when+": fan mode without approval", st, b, 403, api.CodeApprovalRequired)
	st, b = post(t, "/fan/duty", map[string]any{"zone": 1, "percent": 30})
	wantRefusal(t, when+": fan duty without approval", st, b, 403, api.CodeApprovalRequired)
	st, c := post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "heavyio"})
	if st != 200 || c["needed"] != true {
		t.Errorf("%s: a challenge says that no approval is needed: %d %v", when, st, c)
	}
	st, b = post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, when+": shutdown without approval", st, b, 403, api.CodeApprovalRequired)
}

// TestFanWindowNeedsAnAppliedFanChange (r1-a1-04, r1-a2-02), on the Linux agent. The auditors' two runs:
// an approved fan_set of 5 % that the fan controller refuses (400: the lowest duty is 30 %), and an approved
// fan_set while the fan mode is not "full" (409: nothing changes). After either, fan changes without approval
// ran for 30 s. Only an approved change that was applied opens the window.
func TestFanWindowNeedsAnAppliedFanChange(t *testing.T) {
	r := newLinuxRig(t, true).trusted(t)
	if r.mode(t) == "full" {
		t.Fatal("the test needs a fan mode other than full at the start")
	}
	start := r.mode(t)

	// r1-a1-04: approved, then refused by the fan controller
	low := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 5})
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 5, "approval": low}); st != 400 {
		t.Fatalf("approved fan_set of 5 %%: %d %v, want 400", st, b)
	}
	fanWindowClosed(t, "after an approved fan_set the machine refused (400)", r.post)

	// r1-a2-02 (S8): approved, and nothing changes because the mode is not "full"
	full := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 100})
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": full}); st != 409 {
		t.Fatalf("approved fan_set while the mode is %s: %d %v, want 409", start, st, b)
	}
	fanWindowClosed(t, "after an approved fan_set that changed nothing (409)", r.post)
	if r.mode(t) != start {
		t.Fatalf("the fan mode changed without an approval: %s", r.mode(t))
	}

	// an approved change that is applied opens it, for fan changes only
	mode := r.approve(t, map[string]any{"verb": "fan_mode", "mode": "full"})
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full", "approval": mode}); st != 200 || r.mode(t) != "full" {
		t.Fatalf("approved fan mode: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 1, "percent": 60}); st != 200 {
		t.Errorf("fan duty inside the window: %d %v", st, b)
	}
	if st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "optimal"}); st != 200 || c["needed"] != false || c["reason"] != "fan_window" {
		t.Errorf("challenge inside the window: %d %v", st, c)
	}
	st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown inside the fan window", st, b, 403, api.CodeApprovalRequired)
}

// TestFanWindowNeedsAnAppliedFanChangeThroughTheHelper: the same on Windows, where the helper checks and holds
// the window: an approved fan_set that the helper's fan controller answers with 409 (the mode is not "full")
// opens nothing.
func TestFanWindowNeedsAnAppliedFanChangeThroughTheHelper(t *testing.T) {
	r := newApprovalRig(t).trusted(t)
	full := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 100})
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": full}); st != 409 {
		t.Fatalf("approved fan_set while the mode is not full: %d %v, want 409", st, b)
	}
	fanWindowClosed(t, "after an approved fan_set that changed nothing (409)", r.post)

	mode := r.approve(t, map[string]any{"verb": "fan_mode", "mode": "full"})
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full", "approval": mode}); st != 200 {
		t.Fatalf("approved fan mode: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 1, "percent": 60}); st != 200 {
		t.Errorf("fan duty inside the window: %d %v", st, b)
	}
}
