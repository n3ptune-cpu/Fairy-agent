package approval_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// A ticket answers no challenge: how old it is, and whether the machine started after it was signed, are told
// by the machine's clock. These are the tests of what the machine does about a clock that was set, and of how
// it tells its boots apart (review of fd6d3be, T3).

// An old ticket that was never presented (the panel withheld it) is presented a month later on a machine
// whose clock was set back to the minutes of the signature (a time server on the LAN, a clock battery and a
// chosen time). It armed the machine.
func TestOldTicketIsNotTakenAfterTheClockWasSetBack(t *testing.T) {
	r := newRunRig(t)
	t0 := r.Now()
	old := r.signed(t0, ticketEntry(approvaltest.MachineID, runA, 420, 120, 30))
	r.reboot(30*24*time.Hour, 60*time.Second) // a month later, a fresh boot, the clock is right
	_, ref := r.w.Arm(old)
	if ref == nil {
		t.Fatal("a month-old ticket armed a machine whose clock is right")
	}
	// the clock is set to t0 + 100 s (uptime 60 s: "started" at t0 + 40 s, after the signature)
	r.jump(t0.Add(100 * time.Second).Sub(r.Now()))
	ans, ref := r.w.Arm(old)
	if ref == nil {
		t.Fatalf("a 30 days old ticket armed the machine after its clock was set back: %+v", ans)
	}
	runRefused(t, "an old ticket with the clock set back", ref, 409, api.CodeRunRefused, api.RunReasonClockBack)
	if !strings.Contains(ref.Msg, "stays on") || !strings.Contains(ref.Msg, "ends by itself") {
		t.Errorf("the refusal does not say what happens next: %s", ref.Msg)
	}
	if r.touched() || len(r.scheduled) != 0 {
		t.Fatal("something of the ticket is on record")
	}
	// a good ticket of today is not taken either while the clock is back: nothing is judged by that clock
	_, ref = r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
	runRefused(t, "any ticket with the clock set back", ref, 409, api.CodeRunRefused, api.RunReasonClockBack)
}

// The same when the clock was set back while the machine was off, before the service looked in that boot: what
// counts is the latest time the machine showed in any boot before (written when the service starts, when it
// stops, every ten minutes, and with every ticket and confirmation it takes).
func TestOldTicketIsNotTakenAfterTheClockWasSetBackWhileOff(t *testing.T) {
	for _, seen := range []string{"the service started", "the service stopped", "ten minutes passed"} {
		r := newRunRig(t)
		t0 := r.Now()
		old := r.signed(t0, ticketEntry(approvaltest.MachineID, runA, 420, 120, 30))
		r.reboot(24*time.Hour, 60*time.Second) // the next day the machine runs for a while, with a right clock
		switch seen {
		case "the service started":
			r.w.Tick() // the first look of the watch
		case "the service stopped":
			r.g.Status()
			r.wait(5 * time.Minute)
			r.g.RunStop()
		case "ten minutes passed":
			r.w.Tick()
			r.ticks(approval.RunClockEvery + 2*time.Second)
			if got, want := r.files.RunClockSeen(), r.Now().Unix(); got < want-2 || got > want {
				t.Fatalf("the clock on record after ten minutes: %d, now %d", got, want)
			}
		}
		// a month later: the clock is set to the minutes of the signature before the machine starts
		r.reboot(30*24*time.Hour, 60*time.Second)
		r.jump(t0.Add(100 * time.Second).Sub(r.Now()))
		r.restart()
		r.w.Tick()
		_, ref := r.w.Arm(old)
		runRefused(t, "an old ticket, the clock set back while the machine was off ("+seen+")", ref, 409, api.CodeRunRefused, api.RunReasonClockBack)
	}
}

// How far back is "back": two minutes behind the latest time on record are let pass (a time synchronisation
// that corrects a little), more is not.
func TestClockBackTolerance(t *testing.T) {
	for _, c := range []struct {
		back time.Duration
		ok   bool
	}{{0, true}, {60 * time.Second, true}, {approval.RunClockBack, true}, {approval.RunClockBack + time.Second, false}, {time.Hour, false}} {
		r := newRunRig(t)
		r.w.Tick() // the service starts: the clock is on record
		r.jump(-c.back)
		_, ref := r.w.Arm(r.ticket(runA, r.up()+10*time.Second))
		if (ref == nil) != c.ok {
			t.Errorf("clock set back by %s: %v", c.back, ref)
		}
		if ref != nil && ref.Reason != api.RunReasonClockBack {
			t.Errorf("clock set back by %s: reason %q", c.back, ref.Reason)
		}
	}
}

// A machine whose clock was wrong AHEAD and is put right. In that boot no ticket is taken (it is not armed,
// it stays on). Once it has been up for ten minutes the record takes the clock as it is, with a line in the
// log; after the next start tickets are taken again. Nobody has to do anything.
func TestClockPutRightBackwardsRecoversByItself(t *testing.T) {
	r := newRunRig(t)
	right := r.Now()
	r.jump(400 * 24 * time.Hour) // the machine starts with a clock that is more than a year ahead
	r.w.Tick()
	r.jump(right.Sub(r.Now())) // the time service puts it right
	_, ref := r.w.Arm(r.ticket(runA, r.up()+10*time.Second))
	runRefused(t, "a ticket in the boot in which the clock went back", ref, 409, api.CodeRunRefused, api.RunReasonClockBack)
	seen := r.files.RunClockSeen()
	r.ticks(9 * time.Minute) // up for 10 minutes now (it started 60 s before the rig)
	if got := r.files.RunClockSeen(); got != seen {
		t.Fatalf("the clock on record moved from %d to %d while the machine could still be armed in this boot", seen, got)
	}
	r.ticks(approval.RunClockEvery)
	if got, now := r.files.RunClockSeen(), r.Now().Unix(); got > now || got < now-int64(approval.RunClockEvery/time.Second) {
		t.Fatalf("after ten minutes of uptime the clock on record is %d, the clock is %d", got, now)
	}
	if !strings.Contains(r.log.String(), "the clock is taken as it is from here on") {
		t.Error("the log does not say that the clock on record went back")
	}
	_, ref = r.w.Arm(r.ticket(runA, 100*time.Second))
	runRefused(t, "a ticket after ten minutes of uptime", ref, 409, api.CodeRunRefused, api.RunReasonNotFresh)
	r.reboot(8*time.Hour, 60*time.Second)
	if _, ref := r.w.Arm(r.ticket(runA, r.up()+10*time.Second)); ref != nil {
		t.Fatalf("a ticket after the next start: %v", ref)
	}
}

// The clock on record never follows the clock down while the machine can still be armed in this boot: not at
// the start of the service, not when it stops, not with the ten-minute look, not with a write for something
// else. (Whoever holds the control token can stop and start the Windows helper as often as he likes.)
func TestClockOnRecordDoesNotGoBackWhileTheMachineIsFresh(t *testing.T) {
	r := newRunRig(t)
	r.mu.Lock()
	r.uptime = 5 * time.Second
	r.mu.Unlock()
	r.restart()
	r.w.Tick()
	seen := r.files.RunClockSeen()
	if seen != r.Now().Unix() {
		t.Fatalf("at the start of the service: clock on record %d, clock %d", seen, r.Now().Unix())
	}
	r.jump(-3 * time.Hour)
	for i := 0; i < 40; i++ { // 5 s .. 590 s of uptime
		switch i % 4 {
		case 0:
			r.restart()
			r.w.Tick()
		case 1:
			r.g.RunStop()
		case 2:
			r.w.Cancel("test")
			r.confirm(goReq(runC, "-", 30, 300)) // a confirmation writes the record
			r.w.Cancel("test")
		case 3:
			r.ticks(15 * time.Second)
			continue
		}
		r.wait(15 * time.Second)
		if got := r.files.RunClockSeen(); got < seen {
			t.Fatalf("step %d, uptime %s: the clock on record went back from %d to %d", i, r.up(), seen, got)
		}
		if _, ref := r.w.Arm(r.ticket(runA, r.up()+10*time.Second)); ref == nil || (ref.Reason != api.RunReasonClockBack && ref.Reason != api.RunReasonArmedThisBoot) {
			t.Fatalf("step %d, uptime %s: a ticket with the clock three hours back: %v", i, r.up(), ref)
		}
	}
}

// Windows had no id of its boot: "the same boot" was told from the clock and the uptime. After a cancel, a
// clock that was behind at the arming and is set right afterwards (the first time synchronisation after the
// start) plus a restart of the helper (POST /helper/stop and /helper/start need the control token and no
// approval) let a second ticket arm the machine in the same boot. With the helper's own boot id it does not.
func TestNoSecondTicketAfterCancelClockStepAndServiceRestart(t *testing.T) {
	for _, bootID := range []string{winBoot, "boot-1"} {
		r := newRunRig(t)
		r.bootID = bootID
		r.restart()
		real := r.Now()
		// both tickets were signed 330 s ago (two runs started in the same minute)
		t1 := r.signed(real.Add(-330*time.Second), ticketEntry(approvaltest.MachineID, runA, 420, 120, 30))
		t2 := r.signed(real.Add(-330*time.Second), ticketEntry(approvaltest.MachineID, runB, 420, 120, 30))
		r.jump(-300 * time.Second) // the machine's clock is 5 minutes behind
		if _, ref := r.w.Arm(t1); ref != nil {
			t.Fatalf("first arm with the clock behind: %v", ref)
		}
		if was, err := r.w.Cancel("the person at the PC"); was != api.RunArmed || err != nil {
			t.Fatalf("cancel: %q %v", was, err)
		}
		if _, ref := r.w.Arm(t2); ref == nil {
			t.Fatal("armed again right after the cancel")
		}
		r.jump(300 * time.Second) // time sync
		r.wait(20 * time.Second)
		r.restart() // POST /helper/stop, /helper/start
		ans, ref := r.w.Arm(t2)
		if ref == nil {
			t.Fatalf("boot id %q: after a cancel, a clock step and a restart of the service the machine was armed again in the same boot: %+v", bootID, ans)
		}
		runRefused(t, "a second ticket in the boot of a cancel", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
	}
}

// A live run does not cross a boot, however quickly the machine comes back (two boots that began within two
// minutes by the clock counted as one on Windows): armed 40 s after the start and restarted at once.
func TestArmedRunDoesNotCrossAQuickRestartOfTheMachine(t *testing.T) {
	for _, bootID := range []string{winBoot, "boot-1"} {
		r := newRunRig(t)
		r.bootID = bootID
		r.mu.Lock()
		r.uptime = 40 * time.Second
		r.mu.Unlock()
		r.restart()
		r.armed(runA)
		r.wait(10 * time.Second)
		r.reboot(15*time.Second, 45*time.Second) // Windows restarted (an update of Windows, a person): the helper is up at 45 s
		r.w.Tick()
		if st := r.state(); st != "" {
			t.Errorf("boot id %q: the armed run of the boot before is %q in this boot", bootID, st)
		}
		r.ticks(2000 * time.Second)
		if len(r.scheduled) != 0 {
			t.Errorf("boot id %q: the run of the boot before switched the machine off: %+v", bootID, r.scheduled)
		}
	}
}

// And a confirmation is "in this boot": confirmed 30 s after the start (no ticket), restarted at once.
func TestConfirmedRunDoesNotCrossAQuickRestartOfTheMachine(t *testing.T) {
	for _, bootID := range []string{winBoot, "boot-1"} {
		r := newRunRig(t)
		r.bootID = bootID
		r.mu.Lock()
		r.uptime = 30 * time.Second
		r.mu.Unlock()
		r.restart()
		if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 1800)); ref != nil {
			t.Fatalf("confirm: %v", ref)
		}
		r.wait(5 * time.Second)
		r.reboot(20*time.Second, 40*time.Second)
		for _, req := range []api.ApprovalRequest{power("shutdown", 30), update} {
			if _, ref := r.g.AdmitRun(req, runA); ref == nil {
				t.Errorf("boot id %q: the confirmation of the boot before let %s through in this boot", bootID, req.Verb)
			}
		}
		if st := r.state(); st != "" {
			t.Errorf("boot id %q: the run of the boot before is %q in this boot", bootID, st)
		}
	}
}

// What the watch costs a machine every second: nothing it did not cost before. Without trust it reads no
// record and asks for no boot id (on Windows that is a look into the registry); with trust and no run it does
// neither between two looks at the clock, ten minutes apart.
func TestWatchReadsNothingEverySecond(t *testing.T) {
	for _, trust := range []bool{false, true} {
		r := newRunRig(t)
		if !trust {
			if err := os.Remove(r.files.Path); err != nil {
				t.Fatal(err)
			}
		}
		folder, boots := 0, 0
		r.files.CheckDir = func(string) error { folder++; return nil }
		r.restart()
		g := approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByHelper, Now: r.Now, Runs: true,
			Uptime: func() (time.Duration, error) { return r.up(), nil },
			BootID: func() (string, error) { boots++; return "boot-1", nil }})
		w := approval.NewRunWatch(g, approval.RunHooks{})
		w.Tick() // the start of the service
		folder, boots = 0, 0
		for i := 0; i < 590; i++ {
			r.wait(time.Second)
			w.Tick()
		}
		if folder > 590/5+5 {
			t.Errorf("trust %v: %d looks at the folder in 590 s without a run (the trust file is looked at every 5 s, nothing else)", trust, folder)
		}
		if boots > 2 {
			t.Errorf("trust %v: the id of the boot was asked for %d times in 590 s without a run", trust, boots)
		}
	}
}
