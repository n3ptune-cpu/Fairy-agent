package approval_test

import (
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// The worst-case numbers of a run, measured on the gate itself. They are the table in AGENT.md ("Runs: the
// numbers"); a change of a limit that moves one of them fails here first.
func TestRunWorstCaseNumbers(t *testing.T) {
	arm := func(up, age time.Duration, valid int, clockAhead time.Duration) bool {
		r := newRunRig(t)
		r.mu.Lock()
		r.uptime = up
		r.mu.Unlock()
		r.restart()
		tk := r.signed(r.Now().Add(-age), ticketEntry(approvaltest.MachineID, runA, valid, 120, 30))
		r.jump(clockAhead)
		_, ref := r.w.Arm(tk)
		return ref == nil
	}
	// 1. a ticket is usable for at most valid_s + 60 s after it was signed: 660 s at the most (480 s with the
	//    panel's 420)
	for _, c := range []struct{ valid, oldest int }{{api.RunValidMaxS, 660}, {420, 480}, {api.RunValidMinS, 180}} {
		if !arm(time.Second, time.Duration(c.oldest)*time.Second, c.valid, 0) {
			t.Errorf("valid_s %d: a ticket of %d s is refused", c.valid, c.oldest)
		}
		if arm(time.Second, time.Duration(c.oldest+1)*time.Second, c.valid, 0) {
			t.Errorf("valid_s %d: a ticket of %d s is taken", c.valid, c.oldest+1)
		}
	}
	// 2. a machine that started at most 60 s before the signature can be armed (the clock allowance) ...
	if !arm(70*time.Second, 10*time.Second, 420, 0) || arm(71*time.Second, 10*time.Second, 420, 0) {
		t.Error("a machine that started 60 s before the signature is armed, one that started 61 s before is not")
	}
	// ... and whatever its clock says, never one that has been up for 600 s: with the machine's clock AHEAD the
	// start looks later than it was, and the uptime is what bounds it
	worst := time.Duration(0)
	for ahead := time.Duration(0); ahead <= 12*time.Minute; ahead += 2 * time.Minute {
		for upAtSig := 5 * time.Minute; upAtSig <= 11*time.Minute; upAtSig += 15 * time.Second {
			// the ticket is presented 5 s after it was signed
			if arm(upAtSig+5*time.Second, 5*time.Second, 420, ahead) && upAtSig > worst {
				worst = upAtSig
			}
		}
	}
	if worst >= api.RunArmUptimeS*time.Second || worst < 400*time.Second {
		t.Errorf("with its clock ahead, a machine that had been up for %s when the ticket was signed was armed; the limit is the uptime of %d s", worst, api.RunArmUptimeS)
	}
	// 3. armed: the self-off begins wait_s after the arming, 3600 s at the most; 4. the confirmation is good
	//    for within_s, 1800 s at the most (both by the uptime)
	r := newRunRig(t)
	if _, ref := r.w.Arm(r.signed(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, api.RunWaitMaxS, api.RunNoticeMaxS))); ref != nil {
		t.Fatal(ref)
	}
	r.ticks(api.RunWaitMaxS*time.Second - time.Second)
	if len(r.scheduled) != 0 {
		t.Fatal("off before the longest wait was over")
	}
	r.ticks(time.Second)
	if len(r.scheduled) != 1 || r.scheduled[0].delay != api.RunNoticeMaxS*time.Second {
		t.Fatalf("at the end of the longest wait: %+v", r.scheduled)
	}
	r = newRunRig(t)
	if _, ref := r.confirm(goReq(runA, "9.9.9", 30, api.RunWithinMaxS)); ref != nil {
		t.Fatal(ref)
	}
	r.wait(api.RunWithinMaxS*time.Second - time.Second)
	if _, ref := r.g.RunCovers(update, runA); ref != nil {
		t.Errorf("a second before the longest within_s: %v", ref)
	}
	r.wait(time.Second)
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Error("the update was let through 1800 s after the confirmation")
	}
}
