package approval_test

import (
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// A time that passed while nothing looked ends in "stays on" or "refused", never in a late action.

// The ticket says "switch yourself off wait_s after the arming". When the checker does not run at that moment
// (the Windows helper stopped with POST /helper/stop, which needs the control token and no approval; an agent
// on Linux that crashed or was stopped; a PC that slept, or was "shut down" with Fast Startup, over the
// deadline), the self-off began whenever the checker next looked in the same boot: hours or days later, at a
// moment whoever can start the helper picks, on Linux with no notice at all (review of fd6d3be, T2).
func TestArmedRunDoesNotFireWhenTheCheckerRunsAgainLater(t *testing.T) {
	for _, bootID := range []string{"boot-1", ""} { // Linux, Windows
		for _, away := range []time.Duration{72 * time.Hour, 20 * time.Minute, 121 * time.Second} {
			r := newRunRig(t)
			r.bootID = bootID
			r.restart()
			if _, ref := r.w.Arm(r.signed(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 120, 30))); ref != nil {
				t.Fatal(ref)
			}
			r.wait(60 * time.Second)
			r.w.Tick()
			r.wait(away) // the helper is stopped, or the PC sleeps; the people in the house use the PC
			r.restart()  // POST /helper/start
			for i := 0; i < 3; i++ {
				r.w.Tick()
				r.wait(time.Second)
			}
			if len(r.scheduled) != 0 {
				t.Errorf("boot id %q, away %s: a ticket with wait_s 120 switched the machine off %s after the arming: %+v", bootID, away, r.up()-60*time.Second, r.scheduled[0])
			}
			if st := r.state(); st != api.RunCancelled {
				t.Errorf("boot id %q, away %s: the run is %q, want cancelled (it stays on for good)", bootID, away, st)
			}
			if !strings.Contains(r.log.String(), "while nothing looked") {
				t.Errorf("boot id %q, away %s: the log does not say why the machine stays on", bootID, away)
			}
		}
	}
}

// The same without a restart of the service: the machine slept over the deadline and the uptime went on.
func TestArmedRunDoesNotFireAfterTheMachineSleptOverTheDeadline(t *testing.T) {
	r := newRunRig(t)
	r.w.Arm(r.signed(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 120, 30)))
	r.ticks(100 * time.Second)
	r.wait(3 * time.Hour) // asleep: nothing looks
	r.ticks(5 * time.Second)
	if len(r.scheduled) != 0 || r.state() != api.RunCancelled {
		t.Fatalf("after three hours of sleep over the deadline: scheduled %+v, run %q", r.scheduled, r.state())
	}
	if _, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second)); ref == nil {
		t.Fatal("armed again in the boot in which the wait ended while nothing looked")
	}
	_, ref := r.confirm(goReq(runA, "-", 30, 300))
	runRefused(t, "a confirmation of the run that stayed on", ref, 409, api.CodeRunRefused, api.RunReasonOver)
}

// How late is "late": a look within runOffGrace of the deadline still switches the machine off (the service
// was busy for a moment, or restarted by the update), one at runOffGrace or later does not.
func TestArmedRunLateLooks(t *testing.T) {
	for _, c := range []struct {
		late time.Duration
		off  bool
	}{{0, true}, {time.Second, true}, {approval.RunOffGrace - time.Second, true}, {approval.RunOffGrace, false}, {approval.RunOffGrace + time.Second, false},
		{approval.RunUpdateWait, false}, {approval.RunUpdateWait + approval.RunOffGrace, false}} {
		for _, restart := range []bool{false, true} {
			r := newRunRig(t)
			r.w.Arm(r.signed(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 120, 30)))
			r.wait(120*time.Second + c.late)
			if restart {
				r.restart()
			}
			r.w.Tick()
			if got := len(r.scheduled) == 1; got != c.off {
				t.Errorf("first look %s after the deadline (service restarted: %v): switched off %v, want %v", c.late, restart, got, c.off)
			}
			if want := map[bool]string{true: api.RunOffPending, false: api.RunCancelled}[c.off]; r.state() != want {
				t.Errorf("first look %s after the deadline: run %q, want %q", c.late, r.state(), want)
			}
		}
	}
}

// A self-off that this service put off for an update is the one that may come later than runOffGrace: when
// the update is done, and RunUpdateWait after its time at the latest. A service that did not see the deadline
// itself (it was restarted during the update) does not take that over: the machine stays on.
func TestArmedRunPutOffForAnUpdate(t *testing.T) {
	arm := func() *runRig {
		r := newRunRig(t)
		r.w.Arm(r.signed(r.Now().Add(-r.up()-100*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 120, 30)))
		r.ticks(110 * time.Second)
		r.updating = true
		r.ticks(15 * time.Second) // the deadline passes while the update is being installed
		if len(r.scheduled) != 0 || r.state() != api.RunArmed {
			t.Fatalf("at the deadline, with an update being installed: %+v %q", r.scheduled, r.state())
		}
		return r
	}
	// the update ends five minutes later: off then, with the ticket's notice
	r := arm()
	r.ticks(5 * time.Minute)
	if len(r.scheduled) != 0 {
		t.Fatalf("switched off while the update was being installed: %+v", r.scheduled)
	}
	r.updating = false
	r.ticks(2 * time.Second)
	if len(r.scheduled) != 1 || r.scheduled[0].delay != 30*time.Second {
		t.Fatalf("after the update: %+v", r.scheduled)
	}
	// an update that never ends: off RunUpdateWait after the deadline, not later, and not "armed for ever"
	r = arm()
	r.ticks(approval.RunUpdateWait - 6*time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("switched off before the wait for the update was over: %+v at %s", r.scheduled, r.scheduled[0].up)
	}
	r.ticks(3 * time.Second)
	if len(r.scheduled) != 1 || r.scheduled[0].up != 180*time.Second+approval.RunUpdateWait {
		t.Fatalf("an update that never ends: %+v, want one self-off at %s", r.scheduled, 180*time.Second+approval.RunUpdateWait)
	}
	// the service restarts while it waits (the update restarts the helper) and is back a minute or more after the
	// deadline: it did not see the deadline, so it switches nothing off
	r = arm()
	r.ticks(60 * time.Second)
	r.restart()
	r.updating = false
	r.ticks(3 * time.Second)
	if len(r.scheduled) != 0 || r.state() != api.RunCancelled {
		t.Fatalf("a service that came back %s after the deadline: %+v %q", r.up()-180*time.Second, r.scheduled, r.state())
	}
	// the watch stood still while it waited, past RunUpdateWait + runOffGrace: nothing
	r = arm()
	r.wait(approval.RunUpdateWait + approval.RunOffGrace)
	r.w.Tick()
	if len(r.scheduled) != 0 || r.state() != api.RunCancelled {
		t.Fatalf("a look %s after the deadline: %+v %q", r.up()-180*time.Second, r.scheduled, r.state())
	}
}

// The confirmation: its one update and its one shutdown are refused once within_s is over, also when nothing
// looked in between (the service was stopped when the time ran out), and the block says so at the first look.
func TestConfirmationThatRanOutWhileNothingLooked(t *testing.T) {
	for _, bootID := range []string{"boot-1", ""} {
		r := newRunRig(t)
		r.bootID = bootID
		r.restart()
		r.armed(runA)
		if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 300)); ref != nil {
			t.Fatal(ref)
		}
		r.wait(299 * time.Second)
		if _, ref := r.g.RunCovers(update, runA); ref != nil {
			t.Fatalf("a second before within_s: %v", ref)
		}
		r.wait(time.Second) // within_s is over; nothing looked at that moment
		r.wait(6 * time.Hour)
		r.restart()
		if st := r.state(); st == api.RunConfirmed {
			t.Errorf("boot id %q: the block says confirmed %s after the confirmation", bootID, r.up())
		}
		if _, ref := r.g.AdmitRun(update, runA); ref == nil {
			t.Errorf("boot id %q: the run's update was let through hours after within_s", bootID)
		}
		if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref == nil {
			t.Errorf("boot id %q: the run's shutdown was let through hours after within_s", bootID)
		}
		r.ticks(3 * time.Second)
		if len(r.scheduled) != 0 {
			t.Errorf("boot id %q: something was scheduled: %+v", bootID, r.scheduled)
		}
	}
}
