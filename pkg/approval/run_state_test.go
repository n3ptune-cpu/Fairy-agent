package approval_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// arm -> the wait -> the notice -> off. Nobody confirms.
func TestRunSelfOff(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA) // at 60 s of uptime, wait 960 s, notice 120 s
	r.ticks(959 * time.Second)
	if len(r.scheduled) != 0 || r.state() != api.RunArmed {
		t.Fatalf("one second before the wait is over: %+v, %s", r.scheduled, r.state())
	}
	r.ticks(time.Second)
	if len(r.scheduled) != 1 {
		t.Fatalf("when the wait is over: %+v", r.scheduled)
	}
	s := r.scheduled[0]
	want := "Fairy: this PC was started for an update by neptune and nobody confirmed it. Shutdown in 120 seconds. To keep it on: shutdown /a"
	if s.delay != 120*time.Second || s.message != want || s.who != "run "+runA || s.up != 1020*time.Second {
		t.Errorf("scheduled %+v", s)
	}
	run := r.run()
	if run == nil || run.State != api.RunOffPending || run.OffAt != r.Now().Add(120*time.Second).Unix() {
		t.Errorf("run block %+v", run)
	}
	if !strings.Contains(r.log.String(), `msg="approval: run self-off scheduled"`) {
		t.Errorf("log: %s", r.log.String())
	}
	// once: neither the watch nor a restarted service schedules a second one
	r.ticks(30 * time.Second)
	r.restart()
	r.ticks(30 * time.Second)
	if len(r.scheduled) != 1 {
		t.Fatalf("scheduled again: %+v", r.scheduled)
	}
	// a confirmation now is too late
	_, ref := r.confirm(goReq(runA, "19-abc", 30, 1500))
	runRefused(t, "a confirmation during the countdown", ref, 409, api.CodeRunRefused, api.RunReasonTooLate)
	// the machine is still running a minute after the countdown ended: it was kept on (shutdown /a)
	r.ticks(60*time.Second + approval.RunOffGrace - time.Second)
	if r.state() != api.RunOffPending {
		t.Fatalf("one second before the grace is over: %s", r.state())
	}
	r.ticks(time.Second)
	if r.state() != api.RunCancelled || r.cancels != 0 {
		t.Fatalf("after the grace: %s, %d cancels", r.state(), r.cancels)
	}
	r.ticks(3600 * time.Second)
	if len(r.scheduled) != 1 {
		t.Fatalf("scheduled again after it was kept on: %+v", r.scheduled)
	}
	_, ref = r.w.Arm(r.ticket(runB, 0))
	if ref == nil {
		t.Error("armed again in the boot in which it was kept on")
	}
}

// The name in the notice is the cleaned preferred_username of whoever signed the ticket; its hyphens cannot
// begin a word that looks like a switch.
func TestRunNotice(t *testing.T) {
	if got := approval.RunNotice("test-admin -x", 30); got != "Fairy: this PC was started for an update by test‑admin ‑x and nobody confirmed it. Shutdown in 30 seconds. To keep it on: shutdown /a" {
		t.Errorf("%q", got)
	}
	if got := approval.RunNotice("", 120); !strings.Contains(got, "by an administrator and") {
		t.Errorf("%q", got)
	}
}

// arm -> confirm -> the one update -> the one shutdown.
func TestRunConfirmedUpdateAndShutdown(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	r.ticks(600 * time.Second)
	// before the confirmation nothing of the run is let through
	if _, ref := r.g.RunCovers(update, runA); ref == nil || ref.Code != api.CodeApprovalRequired || ref.Status != 403 {
		t.Fatalf("update before the confirmation: %v", ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Fatalf("shutdown before the confirmation: %v", ref)
	}
	ans, ref := r.confirm(goReq(runA, "19-abc1234", 30, 1500))
	if ref != nil || ans != (api.RunAnswer{Run: runA, State: api.RunConfirmed, WithinS: 1500}) {
		t.Fatalf("go: %+v, %v", ans, ref)
	}
	if run := r.run(); run == nil || run.State != api.RunConfirmed || run.OffAt != 0 {
		t.Fatalf("run block %+v", run)
	}
	if !strings.Contains(r.log.String(), `msg="approval: run confirmed"`) {
		t.Errorf("log: %s", r.log.String())
	}
	// the self-off is off: the wait ends and nothing is scheduled
	r.ticks(600 * time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("a confirmed run switched the machine off: %+v", r.scheduled)
	}
	// what the confirmation does not cover is refused like any request without approval
	for name, c := range map[string]struct {
		req api.ApprovalRequest
		run string
	}{
		"another run": {update, runB}, "no run id": {update, ""}, "a run id that is none": {update, "zz"},
		"a shorter delay": {power("shutdown", 29), runA}, "a longer delay": {power("shutdown", 31), runA}, "no delay": {power("shutdown", 0), runA},
		"a reboot": {power("reboot", 30), runA}, "a sleep": {power("sleep", 30), runA},
		"a fan change": {fanSet(0, 50), runA}, "a fan mode": {fanMode("full"), runA},
	} {
		for _, f := range []func(api.ApprovalRequest, string) (string, *approval.Refusal){r.g.RunCovers, r.g.AdmitRun} {
			if _, ref := f(c.req, c.run); ref == nil || ref.Status != 403 || ref.Code != api.CodeApprovalRequired {
				t.Errorf("%s: %v", name, ref)
			}
		}
	}
	// the look uses nothing up
	for i := 0; i < 3; i++ {
		if to, ref := r.g.RunCovers(update, runA); ref != nil || to != "19-abc1234" {
			t.Fatalf("RunCovers(update): %q, %v", to, ref)
		}
		if _, ref := r.g.RunCovers(power("shutdown", 30), runA); ref != nil {
			t.Fatalf("RunCovers(shutdown): %v", ref)
		}
	}
	// exactly one update, to exactly the version named
	to, ref := r.g.AdmitRun(update, runA)
	if ref != nil || to != "19-abc1234" {
		t.Fatalf("the update: %q, %v", to, ref)
	}
	for _, f := range []func(api.ApprovalRequest, string) (string, *approval.Refusal){r.g.RunCovers, r.g.AdmitRun} {
		if _, ref := f(update, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
			t.Errorf("a second update: %v", ref)
		}
	}
	if r.state() != api.RunConfirmed {
		t.Fatalf("after the update: %s", r.state())
	}
	// exactly one shutdown, with exactly the delay named
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref != nil {
		t.Fatalf("the shutdown: %v", ref)
	}
	for _, f := range []func(api.ApprovalRequest, string) (string, *approval.Refusal){r.g.RunCovers, r.g.AdmitRun} {
		if _, ref := f(power("shutdown", 30), runA); ref == nil || ref.Code != api.CodeApprovalRequired {
			t.Errorf("a second shutdown: %v", ref)
		}
	}
	if r.state() != api.RunDone {
		t.Fatalf("after the shutdown: %s", r.state())
	}
	// and the ordinary gate was never opened by any of it
	if ref := r.g.Precheck(update, false); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Errorf("an update without anything after the run: %v", ref)
	}
	if _, ref := r.g.Admit(power("shutdown", 30), nil); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Errorf("a shutdown without anything after the run: %v", ref)
	}
	r.noTokenAnywhere(t)
}

// "to" "-": the confirmation lets no update through, only the shutdown.
func TestRunConfirmedWithoutUpdate(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, api.RunNoUpdate, 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	if _, ref := r.g.AdmitRun(update, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Errorf("an update of a run that named none: %v", ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref != nil {
		t.Errorf("the shutdown: %v", ref)
	}
}

// The shutdown ends the run: an update that was not used is gone with it.
func TestRunShutdownEndsTheRun(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref != nil {
		t.Fatal(ref)
	}
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Error("an update after the run's shutdown")
	}
}

// within_s, counted on the uptime: after it nothing of the run is let through, whatever the clock says.
func TestRunConfirmationRunsOut(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 300)); ref != nil {
		t.Fatal(ref)
	}
	r.jump(-2 * time.Hour) // the clock is set back: the time does not start again
	r.ticks(299 * time.Second)
	if _, ref := r.g.RunCovers(update, runA); ref != nil {
		t.Fatalf("one second before within_s is over: %v", ref)
	}
	r.wait(time.Second)
	if _, ref := r.g.AdmitRun(update, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Errorf("an update after within_s: %v", ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Errorf("a shutdown after within_s: %v", ref)
	}
	if r.state() != api.RunDone {
		t.Errorf("state %s", r.state())
	}
	// the same with the clock set forward instead: it does not end early
	r = newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 300)); ref != nil {
		t.Fatal(ref)
	}
	r.jump(2 * time.Hour)
	if _, ref := r.g.AdmitRun(update, runA); ref != nil {
		t.Errorf("an update inside within_s after the clock was set forward: %v", ref)
	}
}

// The confirmation is an approval like every other: it needs one, for exactly this request, once.
func TestRunGoNeedsItsOwnApproval(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	req := goReq(runA, "19-abc", 30, 1500)
	_, ref := r.w.Go(req, nil)
	runRefused(t, "go without approval", ref, 403, api.CodeApprovalRequired, "")
	_, ref = r.w.Go(req, r.ticket(runA, 0))
	runRefused(t, "go with the ticket", ref, 403, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	_, ref = r.w.Go(req, r.approve(update))
	runRefused(t, "go with the approval of an update", ref, 403, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	// an approval of a confirmation with other values
	c, _ := r.g.Challenge(goReq(runA, "19-abc", 600, 1500))
	other := r.signed(r.Now(), approvaltest.Entry(approvaltest.MachineID, c))
	_, ref = r.w.Go(req, other)
	runRefused(t, "go with the approval of another delay", ref, 403, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	other.Entries[0].Request, _ = req.Canonical()
	_, ref = r.w.Go(req, other)
	runRefused(t, "the same with the entry rewritten", ref, 403, api.CodeApprovalRefused, approval.ReasonEntries)
	// a challenge that is too old
	c, _ = r.g.Challenge(req)
	late := r.signed(r.Now(), approvaltest.Entry(approvaltest.MachineID, c))
	r.wait(approval.ChallengeTTL)
	_, ref = r.w.Go(req, late)
	runRefused(t, "go with an expired challenge", ref, 403, api.CodeApprovalRefused, approval.ReasonExpired)
	if r.state() != api.RunArmed {
		t.Fatalf("after the refused confirmations: %s", r.state())
	}
	// a good one, and then the same again
	c, _ = r.g.Challenge(req)
	good := r.signed(r.Now(), approvaltest.Entry(approvaltest.MachineID, c))
	if _, ref := r.w.Go(req, good); ref != nil {
		t.Fatal(ref)
	}
	_, ref = r.w.Go(req, good)
	runRefused(t, "the same confirmation again", ref, 409, api.CodeRunRefused, api.RunReasonConfirmed)
	_, ref = r.confirm(req)
	runRefused(t, "a second confirmation", ref, 409, api.CodeRunRefused, api.RunReasonConfirmed)
	// it gave one update and one shutdown, not two of each
	r.g.AdmitRun(update, runA)
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Error("two updates")
	}
	// a request for a run_go is not carried out with a wrong body
	_, ref = r.w.Go(update, good)
	if ref == nil || ref.Status != 400 {
		t.Errorf("Go with another verb: %v", ref)
	}
	bad := goReq(runA, "19-abc", 5, 1500)
	if _, ref = r.w.Go(bad, good); ref == nil || ref.Status != 400 {
		t.Errorf("Go with a delay outside the limits: %v", ref)
	}
}

// A confirmation on a machine that no ticket armed (the panel could not arm it, and the person confirmed all
// the same): taken, and no self-off ever comes of it. What does not go: another run while one is live, a run
// whose wait is over, a run that was cancelled here.
func TestRunGoWithoutArmAndItsRefusals(t *testing.T) {
	r := newRunRig(t)
	r.wait(2 * time.Hour) // long past the time in which a ticket would arm it
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatalf("go without arm: %v", ref)
	}
	if _, ref := r.g.AdmitRun(update, runA); ref != nil {
		t.Errorf("the update: %v", ref)
	}
	r.ticks(1200 * time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("a confirmation alone switched the machine off: %+v", r.scheduled)
	}
	_, ref := r.confirm(goReq(runB, "19-abc", 30, 1500))
	runRefused(t, "another run while one is confirmed", ref, 409, api.CodeRunRefused, api.RunReasonOtherRun)

	r = newRunRig(t)
	r.armed(runA)
	_, ref = r.confirm(goReq(runB, "19-abc", 30, 1500))
	runRefused(t, "another run while one is armed", ref, 409, api.CodeRunRefused, api.RunReasonOtherRun)
	// the challenge is asked before the wait is over, the approval comes after: too late, to the second
	req := goReq(runA, "19-abc", 30, 1500)
	c, _ := r.g.Challenge(req)
	r.wait(959 * time.Second)
	c2, _ := r.g.Challenge(req)
	r.wait(time.Second) // the wait is over; the watch has not looked yet
	_, ref = r.w.Go(req, r.signed(r.Now(), approvaltest.Entry(approvaltest.MachineID, c2)))
	runRefused(t, "a confirmation when the wait is over", ref, 409, api.CodeRunRefused, api.RunReasonTooLate)
	if _, ref := r.g.Challenge(req); ref == nil || ref.Reason != api.RunReasonTooLate {
		t.Errorf("a challenge for a confirmation when the wait is over: %v", ref)
	}
	_ = c
	r.w.Tick()
	if len(r.scheduled) != 1 {
		t.Fatalf("the self-off after a confirmation that came too late: %+v", r.scheduled)
	}

	r = newRunRig(t)
	r.minDelay = 60
	r.restart()
	r.armed(runA)
	_, ref = r.confirm(goReq(runA, "19-abc", 59, 1500))
	runRefused(t, "a shutdown delay under this machine's shortest", ref, 409, api.CodeRunRefused, api.RunReasonLimits)
	if _, ref := r.confirm(goReq(runA, "19-abc", 60, 1500)); ref != nil {
		t.Errorf("the shortest delay itself: %v", ref)
	}
}

// arm -> cancel. The machine stays on, nothing of the run is let through, and nothing arms it again in this
// boot: not the same ticket, not another, not after the service restarted, and no confirmation of that run.
func TestRunCancel(t *testing.T) {
	for _, when := range []string{"armed", "counting down", "confirmed"} {
		t.Run(when, func(t *testing.T) {
			r := newRunRig(t)
			ticket := r.ticket(runA, 160*time.Second)
			if _, ref := r.w.Arm(ticket); ref != nil {
				t.Fatal(ref)
			}
			want := api.RunArmed
			switch when {
			case "counting down":
				r.ticks(960 * time.Second)
				want = api.RunOffPending
			case "confirmed":
				if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
					t.Fatal(ref)
				}
				want = api.RunConfirmed
			}
			was, err := r.w.Cancel("test")
			if was != want || err != nil {
				t.Fatalf("cancel: was %q, %v", was, err)
			}
			if r.state() != api.RunCancelled || !strings.Contains(r.log.String(), `msg="approval: run cancelled"`) {
				t.Fatalf("after the cancel: %s", r.state())
			}
			if was, err := r.w.Cancel("again"); was != "" || err != nil {
				t.Errorf("a second cancel: %q, %v", was, err)
			}
			n := len(r.scheduled)
			for i := 0; i < 2; i++ {
				_, ref := r.w.Arm(ticket)
				_, ref2 := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
				if when == "counting down" { // the tickets are too old by now, and the machine up for too long
					if ref == nil || ref2 == nil {
						t.Errorf("a ticket after the cancel: %v, %v", ref, ref2)
					}
				} else {
					runRefused(t, "the same ticket after the cancel", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
					runRefused(t, "another ticket after the cancel", ref2, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
				}
				_, ref = r.confirm(goReq(runA, "19-abc", 30, 1500))
				runRefused(t, "a confirmation of the cancelled run", ref, 409, api.CodeRunRefused, api.RunReasonOver)
				for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
					if _, ref := r.g.AdmitRun(req, runA); ref == nil {
						t.Errorf("%s of the cancelled run was let through", req.Verb)
					}
				}
				r.restart()
				if r.state() != api.RunCancelled {
					t.Errorf("after a restart: %s", r.state())
				}
			}
			r.ticks(3000 * time.Second)
			if len(r.scheduled) != n {
				t.Errorf("a cancelled run switched the machine off: %+v", r.scheduled)
			}
			if r.cancels != 0 {
				t.Errorf("the cancel route stops the countdown itself; the watch did it %d times", r.cancels)
			}
		})
	}
}

// The service restarts (on Windows the update restarts the helper): the wait goes on where it was, by the
// uptime; what is left of a confirmation is exactly what was left before.
func TestRunSurvivesARestartOfTheService(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA) // at 60 s
	r.ticks(500 * time.Second)
	r.restart()
	if !strings.Contains(r.log.String(), "run taken over from the record") {
		r.w.Tick()
	}
	if run := r.run(); run == nil || run.State != api.RunArmed || run.OffAt != r.Now().Add(460*time.Second).Unix() {
		t.Fatalf("after the restart: %+v", run)
	}
	r.ticks(459 * time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("early: %+v", r.scheduled)
	}
	r.ticks(time.Second)
	if len(r.scheduled) != 1 || r.scheduled[0].up != 1020*time.Second {
		t.Fatalf("after the restart the wait ended at %+v", r.scheduled)
	}

	// the helper restarts between the confirmation, the update and the shutdown
	r = newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	r.restart()
	if to, ref := r.g.AdmitRun(update, runA); ref != nil || to != "19-abc" {
		t.Fatalf("the update after a restart: %q, %v", to, ref)
	}
	r.restart() // the update restarts the service
	r.ticks(120 * time.Second)
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Fatal("the restart gave the update back")
	}
	if _, ref := r.g.RunCovers(power("shutdown", 30), runA); ref != nil {
		t.Fatalf("the shutdown is still there after the restart: %v", ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref != nil {
		t.Fatal(ref)
	}
	r.restart()
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref == nil {
		t.Fatal("the restart gave the shutdown back")
	}
	if r.state() != api.RunDone {
		t.Errorf("state %s", r.state())
	}
	// within_s is not started again by a restart
	r = newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 300)); ref != nil {
		t.Fatal(ref)
	}
	r.ticks(200 * time.Second)
	r.restart()
	r.ticks(100 * time.Second)
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Error("a restart started within_s again")
	}
}

// Another boot: nothing of the run is left. With the system's boot id (Linux), and without one (Windows),
// where the uptime and the moment of the start decide.
func TestRunEndsWithTheBoot(t *testing.T) {
	for _, bootID := range []string{"boot-1", ""} {
		for _, state := range []string{api.RunArmed, api.RunConfirmed, api.RunOffPending} {
			t.Run(state+" boot id "+bootID, func(t *testing.T) {
				r := newRunRig(t)
				r.bootID = bootID
				r.restart()
				r.armed(runA)
				switch state {
				case api.RunConfirmed:
					if _, ref := r.confirm(goReq(runA, "19-abc", 30, 3600)); ref != nil {
						t.Fatal(ref)
					}
				case api.RunOffPending:
					r.ticks(960 * time.Second)
				}
				if r.state() != state {
					t.Fatalf("state %s", r.state())
				}
				n := len(r.scheduled)
				// the machine was off for five minutes and has now been up for longer than it had been
				r.reboot(5*time.Minute, r.up()+30*time.Second)
				if run := r.run(); run != nil {
					t.Errorf("a run in the next boot: %+v", run)
				}
				for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
					if _, ref := r.g.AdmitRun(req, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
						t.Errorf("%s in the next boot: %v", req.Verb, ref)
					}
				}
				r.ticks(2000 * time.Second)
				if len(r.scheduled) != n {
					t.Errorf("the run of the last boot switched the machine off: %+v", r.scheduled)
				}
				if !strings.Contains(r.log.String(), "run record of an earlier boot removed") {
					t.Errorf("log: %s", r.log.String())
				}
			})
		}
	}
}

// Without a boot id (Windows): a smaller uptime than on record is another boot, whatever the clock says; and
// a restart of the service after the clock was set by more than two minutes ends the run (the safe side: the
// machine stays on), while a correction within that keeps it.
func TestRunBootWithoutBootID(t *testing.T) {
	r := newRunRig(t)
	r.bootID = ""
	r.restart()
	r.armed(runA) // at 60 s
	// started again one minute later, with the clock set so that the start looks like the same moment
	r.mu.Lock()
	r.uptime = 30 * time.Second
	r.now = r.now.Add(-30 * time.Second)
	r.mu.Unlock()
	r.restart()
	if run := r.run(); run != nil {
		t.Errorf("the uptime went backwards and the run is still there: %+v", run)
	}

	for _, c := range []struct {
		jump time.Duration
		kept bool
	}{{approval.BootSlack, true}, {-approval.BootSlack, true}, {approval.BootSlack + time.Second, false}, {-approval.BootSlack - time.Second, false}, {10 * time.Minute, false}} {
		r := newRunRig(t)
		r.bootID = ""
		r.restart()
		r.armed(runA)
		r.ticks(100 * time.Second)
		r.jump(c.jump)
		r.restart()
		if kept := r.state() == api.RunArmed; kept != c.kept {
			t.Errorf("clock set by %s, then a restart of the service: kept %v, want %v", c.jump, kept, c.kept)
		}
		// a ticket of another run does not arm this boot again, whichever way it went
		if _, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second+max(c.jump, 0))); ref == nil && c.jump <= approval.BootSlack {
			t.Errorf("clock set by %s: armed a second time in one boot", c.jump)
		}
	}
}

// The wait is counted on the uptime. The clock is set forward by ten minutes after the arming (the first time
// synchronisation after weeks without power), or back by an hour: the self-off begins when 960 s of uptime
// have passed, not earlier and not later. With a restart of the service in between as well, where the system
// has a boot id.
func TestRunWaitIsCountedOnTheUptime(t *testing.T) {
	for _, jump := range []time.Duration{10 * time.Minute, -time.Hour, 24 * time.Hour} {
		for _, restart := range []bool{false, true} {
			r := newRunRig(t)
			r.armed(runA)
			r.ticks(100 * time.Second)
			r.jump(jump)
			if restart {
				r.restart()
			}
			r.ticks(859 * time.Second)
			if len(r.scheduled) != 0 {
				t.Fatalf("clock set by %s (restart %v): the self-off began early, at %s of uptime", jump, restart, r.scheduled[0].up)
			}
			if run := r.run(); run == nil || run.OffAt != r.Now().Add(time.Second).Unix() {
				t.Errorf("clock set by %s: off_at %+v, want one second from now by today's clock", jump, run)
			}
			r.ticks(time.Second)
			if len(r.scheduled) != 1 {
				t.Fatalf("clock set by %s (restart %v): no self-off when the wait was over", jump, restart)
			}
		}
	}
}

// What holds the self-off back when the wait is over.
func TestRunVetoesAtTheDeadline(t *testing.T) {
	t.Run("another power action is pending", func(t *testing.T) {
		r := newRunRig(t)
		r.armed(runA)
		r.ticks(900 * time.Second)
		r.pending = true
		r.ticks(120 * time.Second)
		if len(r.scheduled) != 0 || r.state() != api.RunCancelled {
			t.Fatalf("%+v, %s", r.scheduled, r.state())
		}
		r.pending = false
		r.ticks(3000 * time.Second)
		if len(r.scheduled) != 0 {
			t.Errorf("the self-off came back: %+v", r.scheduled)
		}
	})
	for name, set := range map[string]func(r *runRig){
		"a guest runs":                     func(r *runRig) { r.guests = true },
		"whether a guest runs is not told": func(r *runRig) { r.guestsErr = errors.New("/proc cannot be read") },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRunRig(t)
			r.armed(runA)
			r.ticks(900 * time.Second)
			set(r)
			r.ticks(120 * time.Second)
			if len(r.scheduled) != 0 || r.state() != api.RunCancelled {
				t.Fatalf("%+v, %s", r.scheduled, r.state())
			}
			r.guests, r.guestsErr = false, nil // the guest stops an hour later: the machine does not go off then
			r.ticks(4000 * time.Second)
			if len(r.scheduled) != 0 {
				t.Errorf("the self-off came back: %+v", r.scheduled)
			}
		})
	}
	t.Run("a guest that stopped before the wait was over holds nothing back", func(t *testing.T) {
		r := newRunRig(t)
		r.armed(runA)
		r.guests = true
		r.ticks(959 * time.Second)
		r.guests = false
		r.ticks(time.Second)
		if len(r.scheduled) != 1 {
			t.Fatalf("%+v", r.scheduled)
		}
	})
	t.Run("an update is being installed", func(t *testing.T) {
		r := newRunRig(t)
		r.armed(runA)
		r.updating = true
		r.ticks(960*time.Second + 5*time.Minute)
		if len(r.scheduled) != 0 || r.state() != api.RunArmed {
			t.Fatalf("during the update: %+v, %s", r.scheduled, r.state())
		}
		r.updating = false
		r.ticks(time.Second)
		if len(r.scheduled) != 1 {
			t.Fatalf("after the update: %+v", r.scheduled)
		}
	})
	t.Run("an update that does not end", func(t *testing.T) {
		r := newRunRig(t)
		r.armed(runA)
		r.updating = true
		r.ticks(960*time.Second + approval.RunUpdateWait - time.Second)
		if len(r.scheduled) != 0 {
			t.Fatalf("before the 15 minutes are over: %+v", r.scheduled)
		}
		r.ticks(time.Second)
		if len(r.scheduled) != 1 {
			t.Fatalf("after 15 minutes: %+v", r.scheduled)
		}
	})
	t.Run("the shutdown cannot be scheduled", func(t *testing.T) {
		r := newRunRig(t)
		r.armed(runA)
		r.shutdownErr = errors.New("no privilege")
		r.ticks(1000 * time.Second)
		if r.state() != api.RunCancelled {
			t.Fatalf("state %s", r.state())
		}
		r.shutdownErr = nil
		r.ticks(3000 * time.Second)
		if len(r.scheduled) != 0 {
			t.Errorf("tried again later: %+v", r.scheduled)
		}
	})
}

// The trust is changed or removed on the machine while a run is live: the run ends, and a countdown that is
// running is stopped.
func TestRunEndsWhenTheTrustChanges(t *testing.T) {
	for _, state := range []string{api.RunArmed, api.RunOffPending, api.RunConfirmed} {
		for _, removed := range []bool{true, false} {
			r := newRunRig(t)
			r.armed(runA)
			switch state {
			case api.RunOffPending:
				r.ticks(960 * time.Second)
			case api.RunConfirmed:
				if _, ref := r.confirm(goReq(runA, "19-abc", 30, 3600)); ref != nil {
					t.Fatal(ref)
				}
			}
			n := len(r.scheduled)
			if removed {
				if err := os.Remove(r.files.Path); err != nil {
					t.Fatal(err)
				}
			} else { // an administrator takes the fan window away: another trust file
				tr := trustOf(t, r.files)
				w := 0
				tr.FanWindowS = &w
				nt, err := approval.NewTrust(*tr)
				if err != nil {
					t.Fatal(err)
				}
				if err := r.files.Replace(nt); err != nil {
					t.Fatal(err)
				}
			}
			r.ticks(10 * time.Second) // the trust file is looked at again within five
			if run := r.run(); run != nil && run.State != api.RunCancelled {
				t.Errorf("%s, trust removed %v: %+v", state, removed, run)
			}
			if want := map[bool]int{true: 1, false: 0}[state == api.RunOffPending]; r.cancels != want {
				t.Errorf("%s, trust removed %v: the countdown was stopped %d times, want %d", state, removed, r.cancels, want)
			}
			if !removed {
				for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
					if _, ref := r.g.AdmitRun(req, runA); ref == nil {
						t.Errorf("%s was let through after the trust changed", req.Verb)
					}
				}
			}
			r.ticks(3000 * time.Second)
			if len(r.scheduled) != n {
				t.Errorf("%s, trust removed %v: the self-off came after the trust changed", state, removed)
			}
		}
	}
}

func trustOf(t *testing.T, f approval.Files) *approval.Trust {
	t.Helper()
	_, tr, _, err := f.Load()
	if err != nil || tr == nil {
		t.Fatalf("trust file: %v", err)
	}
	return tr
}

// boot_shutdown_s, the machine's own setting for one shutdown without approval shortly after boot, has no
// part in a run: a request that names a run stands on the run alone. And for a request that names none,
// nothing changed.
func TestRunDoesNotUseTheShutdownAfterBoot(t *testing.T) {
	r := newRunRig(t)
	tr := trustOf(t, r.files)
	tr.BootShutdownS = 900
	nt, err := approval.NewTrust(*tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.files.Replace(nt); err != nil {
		t.Fatal(err)
	}
	r.restart() // up for 60 s: inside the setting
	for _, f := range []func(api.ApprovalRequest, string) (string, *approval.Refusal){r.g.RunCovers, r.g.AdmitRun} {
		if _, ref := f(power("shutdown", 30), runA); ref == nil || ref.Code != api.CodeApprovalRequired {
			t.Errorf("a shutdown that names a run nobody confirmed, inside boot_shutdown_s: %v", ref)
		}
	}
	// a ticket does not use it either: it is refused or taken by its own rules, and the setting is still unused
	r.armed(runA)
	if ref := r.g.Precheck(power("shutdown", 30), false); ref != nil {
		t.Errorf("the setting itself, for a request without a run: %v", ref)
	}
	if _, ref := r.g.Admit(power("shutdown", 30), nil); ref != nil {
		t.Errorf("the one shutdown after boot: %v", ref)
	}
	if _, ref := r.g.Admit(power("shutdown", 30), nil); ref == nil {
		t.Error("a second one")
	}
}

// A machine with the check on that no ticket ever reaches behaves as before: no record, no file read at every
// look of the watch, nothing scheduled, and every request needs its approval.
func TestNoTicketNoChange(t *testing.T) {
	r := newRunRig(t)
	looks := 0 // at the folder: once for every look at the trust file (every five seconds) or at the run record
	r.files.CheckDir = func(string) error { looks++; return nil }
	r.restart()
	r.ticks(600 * time.Second)
	if len(r.scheduled) != 0 || r.cancels != 0 || r.run() != nil {
		t.Fatalf("%+v, %d, %+v", r.scheduled, r.cancels, r.run())
	}
	if looks > 600/5+5 {
		t.Errorf("%d looks at the folder in 600 s on a machine without a run: the watch reads the run record at every look", looks)
	}
	if exists, _ := r.files.RunRecordCheck(); exists {
		t.Error("a run record without a ticket")
	}
	if ref := r.g.Precheck(power("shutdown", 60), false); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Errorf("a shutdown without approval: %v", ref)
	}
	if ref := r.g.Check(power("shutdown", 60), r.approve(power("shutdown", 60))); ref != nil {
		t.Errorf("an approved shutdown: %v", ref)
	}
}

// A confirmation that no ticket came before, then a cancel: the boot is closed for tickets all the same.
func TestRunCancelOfAConfirmationWithoutTicketClosesTheBoot(t *testing.T) {
	r := newRunRig(t)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	if was, err := r.w.Cancel("test"); was != api.RunConfirmed || err != nil {
		t.Fatalf("cancel: %q, %v", was, err)
	}
	for i := 0; i < 2; i++ {
		_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
		runRefused(t, "a ticket after the cancel", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
		r.restart()
	}
	// the same when the cancel was made on the machine
	r = newRunRig(t)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	if _, changed, err := r.files.RunCancel(); !changed || err != nil {
		t.Fatal(err)
	}
	r.w.Tick()
	for i := 0; i < 2; i++ {
		_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
		runRefused(t, "a ticket after helper-run cancel", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
		r.restart()
	}
}

// The Windows agent's gate: it only reads the helper's files. It can say, before an update is downloaded,
// whether the confirmed run covers it and for which version; it uses nothing up, takes no ticket and no
// confirmation, ends nothing, and says nothing of runs in its own status.
func TestRunGateThatOnlyReads(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 300)); ref != nil {
		t.Fatal(ref)
	}
	helper, helperWatch := r.g, r.w
	r.readOnly = true
	r.restart()
	agent := r.g
	if st := agent.Status(); st.Runs != 0 || st.Run != nil {
		t.Errorf("status of a gate that only reads: runs %d, run %+v", st.Runs, st.Run)
	}
	for i := 0; i < 3; i++ {
		if to, ref := agent.RunCovers(update, runA); ref != nil || to != "19-abc" {
			t.Fatalf("the look: %q, %v", to, ref)
		}
	}
	if _, ref := agent.RunCovers(update, runB); ref == nil {
		t.Error("another run is covered")
	}
	if _, ref := agent.AdmitRun(update, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
		t.Errorf("a gate that only reads let an update through: %v", ref)
	}
	if was, err := agent.DisarmRun("test"); was != "" || err != nil {
		t.Errorf("a gate that only reads ended a run: %q, %v", was, err)
	}
	_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
	runRefused(t, "a ticket", ref, 404, api.CodeApprovalDisabled, "")
	if _, ref := agent.Challenge(goReq(runB, "-", 30, 300)); ref == nil || ref.Code != api.CodeApprovalDisabled {
		t.Errorf("a challenge for a confirmation: %v", ref)
	}
	r.w.Tick()
	// the helper uses the update up: the agent's next look sees that
	if _, ref := helper.AdmitRun(update, runA); ref != nil {
		t.Fatal(ref)
	}
	if _, ref := agent.RunCovers(update, runA); ref == nil {
		t.Error("the look still says the update is there")
	}
	if _, ref := agent.RunCovers(power("shutdown", 30), runA); ref != nil {
		t.Errorf("the shutdown: %v", ref)
	}
	r.wait(300 * time.Second)
	if _, ref := agent.RunCovers(power("shutdown", 30), runA); ref == nil {
		t.Error("the look says the shutdown is there after within_s")
	}
	_ = helperWatch
	// another boot
	r2 := newRunRig(t)
	r2.armed(runA)
	if _, ref := r2.confirm(goReq(runA, "19-abc", 30, 3600)); ref != nil {
		t.Fatal(ref)
	}
	r2.readOnly = true
	r2.reboot(time.Minute, 30*time.Second)
	if _, ref := r2.g.RunCovers(update, runA); ref == nil {
		t.Error("the look says the update of the last boot's run is there")
	}
}

// Between the watch's look ("armed, and the wait is over") and the moment it schedules the shutdown, it asks the
// machine's parts, and the run can end in that time. What it is about to switch off is looked at again, under
// the gate's lock, immediately before: here the armed run is ended in between and another run is confirmed (a
// confirmation needs no ticket). Nothing is scheduled, and the confirmed run is untouched.
func TestRunSelfOffLooksAgainBeforeItSchedules(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	r.ticks(959 * time.Second)
	c, ref := r.g.Challenge(goReq(runB, "19-abc", 30, 1500)) // asked while run A is live: refused, so ask after
	if ref == nil || c.Challenge != "" {
		t.Fatalf("challenge for another run while one is armed: %+v, %v", c, ref)
	}
	between := false
	r.w = approval.NewRunWatch(r.g, approval.RunHooks{
		Pending: func() bool { return false },
		Shutdown: func(d time.Duration, msg, who string) error {
			r.scheduled = append(r.scheduled, sched{d, msg, who, r.up()})
			return nil
		},
		Guests: func() (bool, error) { // the last question before the shutdown is scheduled
			if was, err := r.g.DisarmRun("in between"); was != api.RunArmed || err != nil {
				t.Errorf("disarm in between: %q, %v", was, err)
			}
			if _, ref := r.confirm(goReq(runB, "19-abc", 30, 1500)); ref != nil {
				t.Errorf("the confirmation of another run in between: %v", ref)
			}
			between = true
			return false, nil
		},
	})
	r.wait(time.Second)
	r.w.Tick()
	if !between {
		t.Fatal("the hook was not asked")
	}
	if len(r.scheduled) != 0 {
		t.Fatalf("scheduled %+v for a run that had ended", r.scheduled)
	}
	if run := r.run(); run == nil || run.ID != runB || run.State != api.RunConfirmed {
		t.Fatalf("the confirmed run after it: %+v", run)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runB); ref != nil {
		t.Errorf("its shutdown: %v", ref)
	}
}
