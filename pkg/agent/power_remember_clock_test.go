package agent

// The Windows side while the PC's time of day is set (review of the panel's fix7r2, R2-04 and R2-02 "way 2").
// These run everywhere: "Windows" is the fakeOS of power_remember_test.go, which goes on counting a shutdown
// down whatever happens to the programs, and the helper's power part is the real RememberedPower with its
// record in a file. What only a Windows PC can show is in the report of this change.

import (
	"path/filepath"
	"testing"
	"time"
)

// steadyOf is a steady clock for Power that goes with c: it moves when time passes (advance) and stands still
// when the time of day is set (correct), as the PC's uptime does.
func steadyOf(c *clock) func() time.Time {
	return func() time.Time { return time.Unix(0, 0).Add(c.now.Sub(c.boot)) }
}

// agentOver is one run of the agent service over a power part.
func agentOver(exec PowerExec, c *clock) *Power {
	p := NewPower(exec, 10)
	p.now, p.steady = c.Now, steadyOf(c)
	return p
}

var windowsClockSteps = []time.Duration{10 * time.Minute, 365 * 24 * time.Hour, -time.Hour}

// 30 s into a countdown of 120 s the PC's clock is set. The agent that asked for the shutdown, an agent that
// was restarted since, and the helper's own record all still show it, for 90 s from now by the new time, and
// Cancel reaches Windows once.
func TestWindowsPendingShutdownIsShownAndCancelledWhateverTheClockIsSetTo(t *testing.T) {
	for _, step := range windowsClockSteps {
		win, c := &fakeOS{}, newClock()
		store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
		helper := start(win, store, c)
		first := agentOver(helper, c)
		d := 120
		if st, b := first.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "wake-update"}); st != 200 {
			t.Fatal(st, b)
		}
		c.advance(30 * time.Second)
		c.correct(step)
		want := float64(c.now.Add(90*time.Second).UnixMilli()) / 1000
		restarted := agentOver(helper, c)
		for name, a := range map[string]*Power{"the agent that asked": first, "an agent restarted since": restarted,
			"agent and helper both restarted": agentOver(start(win, store, c), c)} {
			pend, ok := a.State()["pending"].(Pending)
			if !ok || !a.Scheduled() {
				t.Fatalf("clock set by %s, %s: nothing pending is shown (Windows still counts down)", step, name)
			}
			if pend.Action != "shutdown" || pend.DelayS != 120 || pend.RequestedBy != "wake-update" || pend.At != want {
				t.Errorf("clock set by %s, %s: shown %+v, want the shutdown at %v (90 s from now)", step, name, pend, want)
			}
			if st, _ := a.Handle(PowerRequest{Action: "reboot", DelayS: &d}); st != 409 {
				t.Errorf("clock set by %s, %s: a second action was taken (%d)", step, name, st)
			}
		}
		if rec, ok := helper.PendingAction(); !ok || rec.At != want {
			t.Errorf("clock set by %s: the helper's record: %+v %v", step, rec, ok)
		}
		if st, b := first.Handle(PowerRequest{Action: "cancel"}); st != 200 || b["pending"] != nil || win.cancels != 1 {
			t.Fatalf("clock set by %s: cancel answered %d %v and asked Windows to abort %d time(s), want 1", step, st, b, win.cancels)
		}
		for name, a := range map[string]*Power{"the agent that asked": first, "an agent restarted since": restarted} {
			if a.State()["pending"] != nil {
				t.Errorf("clock set by %s, %s: still shown after the cancel", step, name)
			}
			if st, _ := a.Handle(PowerRequest{Action: "cancel"}); st != 200 || win.cancels != 1 {
				t.Errorf("clock set by %s, %s: one more cancel: %d, Windows asked %d time(s) in all", step, name, st, win.cancels)
			}
		}
	}
}

// The same, and nobody cancels. The shutdown's time passes by the PC's own count (somebody aborted it on the PC
// itself, so the PC is still up): both records end together, a minute after, wherever the clock is. A cancel
// from the panel after that asks Windows nothing, although the agent still has "something of mine was never
// stopped" in mind: a shutdown pending then is somebody else's.
func TestWindowsRecordsEndTogetherAndALateCancelAbortsNothing(t *testing.T) {
	for _, step := range windowsClockSteps {
		win, c := &fakeOS{}, newClock()
		store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
		helper := start(win, store, c)
		a := agentOver(helper, c)
		d := 120
		if st, b := a.Handle(PowerRequest{Action: "shutdown", DelayS: &d}); st != 200 {
			t.Fatal(st, b)
		}
		c.advance(30 * time.Second)
		c.correct(step)
		c.advance(150 * time.Second) // its time, and the minute of grace
		if _, ok := helper.PendingAction(); !ok || !a.Scheduled() {
			t.Fatalf("clock set by %s: dropped inside the minute of grace", step)
		}
		c.advance(time.Second)
		if _, ok := helper.PendingAction(); ok || a.Scheduled() {
			t.Fatalf("clock set by %s: still shown more than a minute after its time", step)
		}
		for i := 0; i < 2; i++ {
			if st, b := a.Handle(PowerRequest{Action: "cancel"}); st != 200 || b["pending"] != nil {
				t.Fatal(st, b)
			}
		}
		if win.cancels != 0 {
			t.Fatalf("clock set by %s: Windows was asked to abort %d time(s) for a shutdown of Fairy's whose time has passed", step, win.cancels)
		}
	}
}

// cachedHelper stands in for the helper's client: what it says is pending is the helper's status as the agent
// last read it, up to a few seconds old, with the time the helper gave it then.
type cachedHelper struct {
	fakeOS
	status Pending
}

func (h *cachedHelper) PendingAction() (Pending, bool) { return h.status, h.status.Action != "" }

// R2-02 "way 2", what is left of it. The agent was restarted while the helper's shutdown counts down, so it
// has no record of its own and shows the helper's. Then the clock is set forward by more than the rest plus a
// minute. Until the helper's next status (2 s as a rule) the agent holds the old one, whose time is far in the
// past by the new clock, and shows nothing. That gap is still there. A cancel in it used to be answered 200
// without the helper being asked; now the helper is asked.
func TestWindowsCancelReachesTheHelperWhileItsStatusIsFromBeforeTheClockWasSet(t *testing.T) {
	c := newClock()
	h := &cachedHelper{status: Pending{Action: "shutdown", At: float64(c.now.Unix() + 90), DelayS: 120, RequestedBy: "wake-update"}}
	a := agentOver(h, c)
	if a.State()["pending"] == nil {
		t.Fatal("the helper's shutdown is not shown by the restarted agent")
	}
	c.correct(21 * 24 * time.Hour)
	t.Logf("the helper's status is from before the clock was set: pending shown: %v", a.Scheduled())
	if st, b := a.Handle(PowerRequest{Action: "cancel", RequestedBy: "wake-update"}); st != 200 || b["pending"] != nil {
		t.Fatal(st, b)
	}
	if h.cancels != 1 {
		t.Fatalf("cancel answered 200 and the helper was asked %d time(s): Windows still counts down", h.cancels)
	}
	// the helper's next status says nothing is pending; nothing is asked again
	h.status = Pending{}
	if st, _ := a.Handle(PowerRequest{Action: "cancel"}); st != 200 || h.cancels != 1 || a.Scheduled() {
		t.Fatal(st, h.cancels)
	}

	// set back: nothing is hidden at all (the old status's time is in the future by the new clock)
	c = newClock()
	h = &cachedHelper{status: Pending{Action: "shutdown", At: float64(c.now.Unix() + 90), DelayS: 120, RequestedBy: "wake-update"}}
	a = agentOver(h, c)
	c.correct(-time.Hour)
	if !a.Scheduled() {
		t.Fatal("clock set back: the helper's shutdown is not shown")
	}
	if st, _ := a.Handle(PowerRequest{Action: "cancel"}); st != 200 || h.cancels != 1 {
		t.Fatal(st, h.cancels)
	}
}
