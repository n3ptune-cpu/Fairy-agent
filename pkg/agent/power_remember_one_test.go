package agent

// Audit 6, r4-a1-02: the helper's power part keeps to "one action at a time" itself. "Windows" is a stand-in
// that keeps to what power_windows.go does (read, not run here), step for step: a shutdown is counted down by
// Windows and a second one is refused; a sleep is a timer of the helper's own, kept in the product's
// pendingSleep as power_windows.go keeps it; a sleep that still waits is dropped when a shutdown is taken;
// Cancel stops the sleep that is still to come and returns, and aborts the shutdown only otherwise. The three
// Windows calls are counters.

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type winOS struct {
	// sleep is the product's own piece (power.go), used as power_windows.go uses it.
	sleep pendingSleep
	// fast, when set, makes a sleep's timer run after this long instead of after its delay.
	fast time.Duration

	mu        sync.Mutex
	shutdown  string // what Windows counts down ("": nothing): InitiateSystemShutdownEx
	suspended int    // SetSuspendState was called
	aborts    int    // AbortSystemShutdown was called
}

func (w *winOS) Schedule(action string, delay time.Duration, _ string) error {
	if action == "sleep" {
		if w.fast > 0 {
			delay = w.fast
		}
		w.sleep.set(delay, func() {
			w.mu.Lock()
			w.suspended++
			w.mu.Unlock()
		})
		return nil
	}
	w.mu.Lock()
	if w.shutdown != "" {
		w.mu.Unlock()
		return errors.New("A system shutdown has already been scheduled.")
	}
	w.shutdown = action
	w.mu.Unlock()
	w.sleep.stop() // a sleep that still waits is dropped when a shutdown is taken
	return nil
}

func (w *winOS) Cancel() error {
	if w.sleep.stop() {
		return nil
	}
	w.mu.Lock()
	w.aborts++
	w.shutdown = ""
	w.mu.Unlock()
	return nil
}
func (w *winOS) CanSleep() (bool, string) { return true, "" }

// sleepWaiting reports whether a sleep is still to come.
func (w *winOS) sleepWaiting() bool {
	w.sleep.mu.Lock()
	defer w.sleep.mu.Unlock()
	return w.sleep.timer != nil
}

// Snap is what "Windows" was asked so far (for tests outside this package).
func (w *winOS) Snap() (suspended, aborts int, counting string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.suspended, w.aborts, w.shutdown
}

// WindowsStandIn is winOS for the tests outside this package.
type WindowsStandIn = winOS

// statusClient stands in for the agent's client of the helper: requests go to the helper at once, what is
// pending is the helper's status as the agent last read it (refresh: its next status answer).
type statusClient struct {
	helper *RememberedPower
	status Pending
	has    bool
}

func (c *statusClient) refresh() { c.status, c.has = c.helper.PendingAction() }
func (c *statusClient) Schedule(a string, d time.Duration, m string) error {
	return c.helper.Schedule(a, d, m)
}
func (c *statusClient) ScheduleBy(a string, d time.Duration, who string) error {
	return c.helper.ScheduleBy(a, d, who)
}
func (c *statusClient) Cancel() error                  { return c.helper.Cancel() }
func (c *statusClient) CanSleep() (bool, string)       { return c.helper.CanSleep() }
func (c *statusClient) PendingAction() (Pending, bool) { return c.status, c.has }

// The power part refuses a second action while its record of the first is running, whatever the two are, and
// the record, its file and the first action stay as they were.
func TestRememberedPowerTakesOneActionAtATime(t *testing.T) {
	for _, first := range []string{"shutdown", "reboot", "sleep"} {
		for _, second := range []string{"shutdown", "reboot", "sleep"} {
			win, c := &winOS{}, newClock()
			store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
			r := start(win, store, c)
			if err := r.ScheduleBy(first, time.Hour, "alice"); err != nil {
				t.Fatal(first, err)
			}
			c.advance(10 * time.Minute)
			err := r.ScheduleBy(second, time.Minute, "bob")
			if err == nil || err.Error() != "a "+first+" is already pending; cancel it first" {
				t.Fatalf("%s over %s: %v", second, first, err)
			}
			rec, ok := r.PendingAction()
			if !ok || rec.Action != first || rec.RequestedBy != "alice" || rec.DelayS != 3600 {
				t.Fatalf("%s over %s: the record is now %+v (%v)", second, first, rec, ok)
			}
			if first != "sleep" { // kept in the file: a restarted helper still has it
				if rec, ok := start(win, store, c).PendingAction(); !ok || rec.Action != first {
					t.Fatalf("%s over %s: after a restart %+v (%v)", second, first, rec, ok)
				}
				if win.sleepWaiting() {
					t.Fatalf("%s over %s: a sleep timer runs next to the %s", second, first, first)
				}
			}
			// after a cancel, and after the first one's time, the next action is taken
			if err := r.Cancel(); err != nil {
				t.Fatal(err)
			}
			if err := r.ScheduleBy(second, time.Minute, "bob"); err != nil {
				t.Fatalf("%s after the %s was cancelled: %v", second, first, err)
			}
			c.advance(time.Minute + powerRecordGrace + time.Second)
			win.shutdown = "" // its time has passed
			if err := r.ScheduleBy(first, time.Minute, "carol"); err != nil {
				t.Fatalf("%s after the %s's time: %v", first, second, err)
			}
			win.sleep.stop() // no timer of this round is left behind
		}
	}
}

// The gap the finding names: an agent restarted during a shutdown's countdown shows nothing for a few seconds
// after the clock was set forward. A sleep asked for in that gap is refused by the helper; the shutdown is
// shown again with the helper's next status, and Cancel reaches Windows.
func TestASleepInTheClockGapDoesNotHideTheShutdown(t *testing.T) {
	win, c := &winOS{}, newClock()
	store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	helper := start(win, store, c)
	cl := &statusClient{helper: helper}
	d := 3600
	if st, b := agentOver(cl, c).Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "alice"}); st != 200 {
		t.Fatal(st, b)
	}
	c.advance(10 * time.Minute)
	cl.refresh()
	a := agentOver(cl, c) // the agent service restarted; the helper and Windows go on
	if a.State()["pending"] == nil {
		t.Fatal("the restarted agent does not show the helper's shutdown")
	}
	c.correct(21 * 24 * time.Hour) // the clock is set; the helper's status is from before
	if a.State()["pending"] != nil {
		t.Skip("no gap: the agent shows the shutdown although the helper's status is from before the clock was set")
	}
	s := 60
	st, b := a.Handle(PowerRequest{Action: "sleep", DelayS: &s, RequestedBy: "bob"})
	text, _ := b["error"].(string)
	if st == 200 || !strings.Contains(text, "a shutdown is already pending; cancel it first") {
		t.Fatalf("a sleep in the gap: %d %v; want a refusal that names the pending shutdown", st, b)
	}
	if win.sleepWaiting() {
		t.Fatal("a sleep timer runs in the helper")
	}
	cl.refresh() // the helper's next status answer
	p, _ := a.State()["pending"].(Pending)
	if p.Action != "shutdown" || p.RequestedBy != "alice" {
		t.Fatalf("after the helper's next status the agent shows %v; want the shutdown", a.State()["pending"])
	}
	if st, b := a.Handle(PowerRequest{Action: "cancel", RequestedBy: "bob"}); st != 200 || win.aborts != 1 || win.shutdown != "" {
		t.Fatalf("cancel: %d %v; Windows was asked to abort %d time(s) and counts down %q", st, b, win.aborts, win.shutdown)
	}
	cl.refresh()
	if a.State()["pending"] != nil {
		t.Fatalf("pending after the cancel: %v", a.State()["pending"])
	}
}

// The same when the cancel comes inside the gap, before the helper's next status: it reaches Windows.
func TestACancelRightAfterTheRefusedSleepReachesWindows(t *testing.T) {
	win, c := &winOS{}, newClock()
	helper := start(win, PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}, c)
	cl := &statusClient{helper: helper}
	d := 3600
	if st, b := agentOver(cl, c).Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "alice"}); st != 200 {
		t.Fatal(st, b)
	}
	c.advance(10 * time.Minute)
	cl.refresh()
	a := agentOver(cl, c)
	a.State()
	c.correct(21 * 24 * time.Hour)
	s := 60
	if st, b := a.Handle(PowerRequest{Action: "sleep", DelayS: &s}); st == 200 {
		t.Fatal(st, b)
	}
	if st, b := a.Handle(PowerRequest{Action: "cancel"}); st != 200 || win.aborts != 1 || win.shutdown != "" {
		t.Fatalf("cancel in the gap: %d %v; Windows was asked to abort %d time(s) and counts down %q", st, b, win.aborts, win.shutdown)
	}
}
