package agent

// The agent's own record of the action it scheduled, while the machine's time of day is set (review of the
// panel's fix7r2, R2-04). The exec of these tests is a stand-in; nothing is shut down.

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

type countingExec struct{ scheduled, cancelled int }

func (e *countingExec) Schedule(string, time.Duration, string) error { e.scheduled++; return nil }
func (e *countingExec) Cancel() error                                { e.cancelled++; return nil }
func (e *countingExec) CanSleep() (bool, string)                     { return false, "no" }

// The reviewer's proof of R2-04 as it was written (TestReview7r2AClockSetForwardHidesAPendingShutdownAndIts
// CancelDoesNothing; only the names are new). It failed before the fix: "pending shown: false; cancel answers
// 200; the timer was asked to stop 0 time(s)". The steady clock is the real one here, on which no time passes.
func TestAClockSetForwardHidesNoPendingShutdownAndItsCancelStopsIt(t *testing.T) {
	ex := &countingExec{}
	p := NewPower(ex, 0)
	now := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC) // the machine's clock, three weeks behind
	p.now = func() time.Time { return now }
	d := 120
	if code, body := p.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "wake-update"}); code != 200 {
		t.Fatalf("shutdown: %d %v", code, body)
	}
	if !p.Scheduled() {
		t.Fatal("not pending after it was scheduled")
	}
	now = now.Add(30 * time.Second).Add(21 * 24 * time.Hour) // 30 s into the countdown the time server sets the clock
	pendingShown := p.Scheduled()
	code, body := p.Handle(PowerRequest{Action: "cancel", RequestedBy: "wake-update"})
	t.Logf("30 s into a 120 s countdown, after the clock was set forward: pending shown: %v; cancel answers %d %v; the timer was asked to stop %d time(s)", pendingShown, code, body, ex.cancelled)
	if !pendingShown || ex.cancelled != 1 {
		t.Errorf("the agent shows pending=%v and its cancel stopped the timer %d time(s) (answer %d), while the shutdown it scheduled still runs: it switches the machine off 90 s later", pendingShown, ex.cancelled, code)
	}
}

// What the record's end is counted from must be a reading with Go's steady clock in it. time.Time.Round(0)
// takes that part off, so a reading that has it differs from its own Round(0).
func TestPowerKeepsTheSteadyReadingOfItsRequest(t *testing.T) {
	p := NewPower(&countingExec{}, 0)
	d := 120
	if code, body := p.Handle(PowerRequest{Action: "shutdown", DelayS: &d}); code != 200 {
		t.Fatal(code, body)
	}
	if p.since.IsZero() || p.since == p.since.Round(0) {
		t.Fatalf("the reading kept for the pending action has no steady part: %v", p.since)
	}
}

// timerExec stands in for the Linux power part: a timer that counts on the steady clock, as time.AfterFunc
// does, and writes down what it would have run.
type timerExec struct {
	steady  func() time.Time
	action  string
	due     time.Time // zero: no timer is running
	fired   []string
	cancels int // Cancel was called
	stopped int // ... and found a timer to stop
}

func (e *timerExec) Schedule(action string, delay time.Duration, _ string) error {
	e.action, e.due = action, e.steady().Add(delay)
	return nil
}

func (e *timerExec) Cancel() error {
	e.cancels++
	if !e.due.IsZero() {
		e.stopped++
	}
	e.due = time.Time{}
	return nil
}

func (e *timerExec) CanSleep() (bool, string) { return true, "" }

// machine is a Linux machine with an agent: a time of day that can be set, a steady clock that cannot, and
// the power part's timer.
type machine struct {
	wall, steady time.Time
	ex           *timerExec
	p            *Power
}

func newMachine() *machine {
	m := &machine{wall: time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC), steady: time.Unix(5000, 0)}
	m.ex = &timerExec{steady: func() time.Time { return m.steady }}
	m.p = NewPower(m.ex, 0)
	m.p.now, m.p.steady = func() time.Time { return m.wall }, func() time.Time { return m.steady }
	return m
}

// pass lets d of time pass: both clocks move, and the timer runs when its time has come.
func (m *machine) pass(d time.Duration) {
	m.wall, m.steady = m.wall.Add(d), m.steady.Add(d)
	if !m.ex.due.IsZero() && !m.steady.Before(m.ex.due) {
		m.ex.fired, m.ex.due = append(m.ex.fired, m.ex.action), time.Time{}
	}
}

// set sets the time of day forward (or back) by d. No time passes.
func (m *machine) set(d time.Duration) { m.wall = m.wall.Add(d) }

func (m *machine) ask(t *testing.T, action string, delay int) (int, map[string]any) {
	t.Helper()
	return m.p.Handle(PowerRequest{Action: action, DelayS: &delay, RequestedBy: "wake-update"})
}

// shown is the pending action as /metrics has it (nil: none).
func (m *machine) shown() *Pending {
	if c, ok := m.p.State()["pending"].(Pending); ok {
		return &c
	}
	return nil
}

// in is how far from now, by the machine's time of day, the shown action happens.
func (m *machine) in(c *Pending) time.Duration {
	return time.Duration(math.Round((c.At-float64(m.wall.UnixMilli())/1000)*1000)) * time.Millisecond
}

var clockSteps = []struct {
	name string
	by   time.Duration
}{
	{"not set at all", 0},
	{"set forward by 10 minutes", 10 * time.Minute},
	{"set forward by 1 year", 365 * 24 * time.Hour},
	{"set back by 1 hour", -time.Hour},
}

// 30 s into a countdown of 120 s the time of day is set. The shutdown is still shown, for 90 s from now by the
// new time; a second action is still refused; Cancel stops the timer, and nothing runs afterwards.
func TestPendingActionIsShownAndCancelledWhateverTheClockIsSetTo(t *testing.T) {
	for _, step := range clockSteps {
		t.Run(step.name, func(t *testing.T) {
			m := newMachine()
			if code, body := m.ask(t, "shutdown", 120); code != 200 {
				t.Fatal(code, body)
			}
			first := *m.shown()
			m.pass(30 * time.Second)
			m.set(step.by)

			c := m.shown()
			if c == nil || !m.p.Scheduled() {
				t.Fatalf("nothing pending is shown; the timer runs the shutdown in 90 s")
			}
			if c.Action != "shutdown" || c.DelayS != 120 || c.RequestedBy != "wake-update" || m.in(c) != 90*time.Second {
				t.Errorf("shown: %+v, which is in %s by the machine's clock; want the shutdown in 1m30s", *c, m.in(c))
			}
			if step.by == 0 && c.At != first.At {
				t.Errorf("the time shown moved from %v to %v without the clock being set", first.At, c.At)
			}
			if code, _ := m.ask(t, "reboot", 60); code != 409 {
				t.Errorf("a second action while the first counts down: %d, want 409", code)
			}
			code, body := m.p.Handle(PowerRequest{Action: "cancel", RequestedBy: "wake-update"})
			if code != 200 || body["pending"] != nil || m.ex.stopped != 1 {
				t.Fatalf("cancel: %d %v; it stopped the timer %d time(s), want 1", code, body, m.ex.stopped)
			}
			if m.shown() != nil {
				t.Errorf("still shown after the cancel: %+v", *m.shown())
			}
			for _, d := range []time.Duration{89 * time.Second, 2 * time.Second, time.Minute, 2 * time.Hour} {
				m.pass(d)
				if len(m.ex.fired) != 0 || m.shown() != nil {
					t.Fatalf("after the cancel: ran %v, shown %v", m.ex.fired, m.shown())
				}
			}
			m.set(-step.by) // the correction is taken back: nothing comes back with it
			if len(m.ex.fired) != 0 || m.shown() != nil {
				t.Fatalf("after the clock was set back to where it was: ran %v, shown %v", m.ex.fired, m.shown())
			}
		})
	}
}

// The same without a cancel: the action runs once, 120 s after it was asked for by the steady clock and not a
// millisecond earlier, wherever the time of day is; it is shown until then and for the minute of grace after.
func TestPendingActionRunsOnceAtItsSteadyTimeWhateverTheClockIsSetTo(t *testing.T) {
	for _, step := range clockSteps {
		t.Run(step.name, func(t *testing.T) {
			m := newMachine()
			if code, body := m.ask(t, "shutdown", 120); code != 200 {
				t.Fatal(code, body)
			}
			m.pass(30 * time.Second)
			m.set(step.by)
			m.pass(90*time.Second - time.Millisecond)
			if c := m.shown(); len(m.ex.fired) != 0 || c == nil || m.in(c) != time.Millisecond {
				t.Fatalf("1 ms before its time: ran %v, shown %+v", m.ex.fired, c)
			}
			m.pass(time.Millisecond)
			if len(m.ex.fired) != 1 || m.ex.fired[0] != "shutdown" {
				t.Fatalf("at its time, 120 s after the request: ran %v, want the shutdown once", m.ex.fired)
			}
			// the machine is going down now; whoever still asks is told so for a minute
			m.pass(60 * time.Second)
			if c := m.shown(); c == nil || m.in(c) != -60*time.Second {
				t.Fatalf("a minute after its time: shown %+v, want the shutdown, a minute ago", c)
			}
			m.pass(time.Millisecond)
			if m.shown() != nil || m.p.Scheduled() {
				t.Fatalf("more than a minute after its time it is still shown: %+v", *m.shown())
			}
			m.pass(3 * time.Hour)
			m.set(-step.by)
			if len(m.ex.fired) != 1 || m.shown() != nil {
				t.Fatalf("later: ran %v, shown %v", m.ex.fired, m.shown())
			}
			if code, body := m.ask(t, "reboot", 60); code != 200 { // had the shutdown failed: the next action is taken
				t.Fatal(code, body)
			}
		})
	}
}

// Sleep is the one action after which this process is still there. On Linux the steady clock stands still
// while the machine sleeps, so by it the sleep would stay "pending" for the minute of grace after the machine
// woke up, and a new action would be refused for that minute. As before, the time of day ends it then. Before
// its time nothing but the steady clock decides, also for a sleep.
func TestASleepIsOverWhenTheMachineWokeUp(t *testing.T) {
	m := newMachine()
	if code, body := m.ask(t, "sleep", 60); code != 200 {
		t.Fatal(code, body)
	}
	m.pass(30 * time.Second)
	m.set(365 * 24 * time.Hour)
	if c := m.shown(); c == nil || c.Action != "sleep" || m.in(c) != 30*time.Second {
		t.Fatalf("30 s into a sleep's countdown, clock set forward: shown %+v", c)
	}
	m.set(-365 * 24 * time.Hour)
	m.pass(30 * time.Second)
	if len(m.ex.fired) != 1 || m.shown() == nil {
		t.Fatalf("at its time: ran %v, shown %v", m.ex.fired, m.shown())
	}
	m.pass(2 * time.Second) // going to sleep ...
	m.set(8 * time.Hour)    // ... asleep for eight hours: the time of day moved, the steady clock did not
	if m.shown() != nil || m.p.Scheduled() {
		t.Fatalf("after the machine woke up its sleep is still shown as pending: %+v", *m.shown())
	}
	if code, body := m.ask(t, "shutdown", 60); code != 200 {
		t.Fatalf("a shutdown right after the machine woke up: %d %v", code, body)
	}

	// a sleep of a few seconds only: on record for the rest of the minute of grace, as before
	m = newMachine()
	if code, body := m.ask(t, "sleep", 60); code != 200 {
		t.Fatal(code, body)
	}
	m.pass(62 * time.Second)
	m.set(20 * time.Second)
	if m.shown() == nil {
		t.Fatal("20 s of sleep ended the record inside the minute of grace")
	}
	m.pass(58*time.Second + time.Millisecond)
	if m.shown() != nil {
		t.Fatalf("still shown after the minute of grace: %+v", *m.shown())
	}
}

// Cancel with nothing on record. What this process scheduled itself, and never asked the power part to stop,
// is stopped all the same: the record is what this process believes, the timer is the power part's. (After
// the change above no way is known in which the record is gone while the timer runs; the test takes the
// record away by hand.) The answer is 200 as it always was, and the log says nothing.
func TestCancelStopsWhatThisProcessScheduledAlsoWithNothingOnRecord(t *testing.T) {
	m := newMachine()
	if code, body := m.ask(t, "shutdown", 120); code != 200 {
		t.Fatal(code, body)
	}
	m.pass(30 * time.Second)
	m.p.pending = nil // the record is wrong, whatever made it so
	if m.shown() != nil {
		t.Fatal("still shown")
	}
	logs := captureLog(t)
	code, body := m.p.Handle(PowerRequest{Action: "cancel", RequestedBy: "wake-update"})
	if code != 200 || body["action"] != "cancel" || body["pending"] != nil || len(body) != 2 {
		t.Fatalf("cancel: %d %v", code, body)
	}
	if m.ex.stopped != 1 {
		t.Fatalf("cancel answered 200 and stopped the timer %d time(s): the machine goes off in 90 s", m.ex.stopped)
	}
	m.pass(3 * time.Hour)
	if len(m.ex.fired) != 0 {
		t.Fatalf("ran after the cancel: %v", m.ex.fired)
	}
	// asked once: the next cancel finds nothing of this process's and asks nobody
	if code, _ := m.p.Handle(PowerRequest{Action: "cancel"}); code != 200 || m.ex.cancels != 1 {
		t.Fatalf("a second cancel: %d, the power part was asked %d time(s) in all, want 1", code, m.ex.cancels)
	}
	if logs.String() != "" {
		t.Fatalf("a cancel with nothing on record wrote to the log:\n%s", logs.String())
	}
}

// A process that scheduled nothing asks the power part nothing, as before: there is nothing of its own to
// stop, and a shutdown somebody else started is not the panel's to cancel. Nor is anything asked twice.
func TestCancelWithNothingOfItsOwnAsksNobody(t *testing.T) {
	m := newMachine()
	logs := captureLog(t)
	for i := 0; i < 3; i++ {
		if code, body := m.p.Handle(PowerRequest{Action: "cancel"}); code != 200 || body["pending"] != nil {
			t.Fatal(code, body)
		}
	}
	if m.ex.cancels != 0 || logs.String() != "" {
		t.Fatalf("the power part was asked %d time(s); log:\n%s", m.ex.cancels, logs.String())
	}
	// an action that was cancelled is stopped once, not once more by every later cancel
	if code, body := m.ask(t, "reboot", 120); code != 200 {
		t.Fatal(code, body)
	}
	for i := 0; i < 3; i++ {
		if code, _ := m.p.Handle(PowerRequest{Action: "cancel"}); code != 200 {
			t.Fatal(code)
		}
	}
	if m.ex.cancels != 1 || m.ex.stopped != 1 {
		t.Fatalf("three cancels of one action: asked %d time(s), stopped %d", m.ex.cancels, m.ex.stopped)
	}
	// an action that ran its time (here: a sleep the machine woke up from) leaves nothing to stop; the one
	// cancel that still asks does nothing and says ok
	if code, body := m.ask(t, "sleep", 60); code != 200 {
		t.Fatal(code, body)
	}
	m.pass(62 * time.Second)
	m.set(8 * time.Hour)
	if code, body := m.p.Handle(PowerRequest{Action: "cancel"}); code != 200 || body["pending"] != nil {
		t.Fatal(code, body)
	}
	if m.ex.cancels != 2 || m.ex.stopped != 1 || len(m.ex.fired) != 1 {
		t.Fatalf("asked %d, stopped %d, ran %v", m.ex.cancels, m.ex.stopped, m.ex.fired)
	}
}

// failingExec cannot cancel while err is set.
type failingExec struct {
	timerExec
	err error
}

func (e *failingExec) Cancel() error {
	if e.err != nil {
		return e.err
	}
	return e.timerExec.Cancel()
}

// When the power part cannot be asked, a cancel with nothing on record does not answer "ok" either: nobody
// knows then whether the action is stopped. It can be asked again.
func TestCancelWithNothingOnRecordSaysSoWhenThePowerPartFails(t *testing.T) {
	steady := time.Unix(5000, 0)
	ex := &failingExec{timerExec: timerExec{steady: func() time.Time { return steady }}}
	p := NewPower(ex, 0)
	p.steady = ex.steady
	d := 120
	if code, body := p.Handle(PowerRequest{Action: "shutdown", DelayS: &d}); code != 200 {
		t.Fatal(code, body)
	}
	p.pending = nil
	captureLog(t)
	ex.err = errors.New("access denied")
	if code, body := p.Handle(PowerRequest{Action: "cancel"}); code != 500 || body["error"] != "could not cancel: access denied" {
		t.Fatalf("cancel while the power part fails: %d %v", code, body)
	}
	ex.err = api.ErrHelperStopped
	if code, body := p.Handle(PowerRequest{Action: "cancel"}); code != 503 || body["code"] != api.ReasonHelperStopped {
		t.Fatalf("cancel while the helper is stopped: %d %v", code, body)
	}
	ex.err = nil
	if code, _ := p.Handle(PowerRequest{Action: "cancel"}); code != 200 || ex.stopped != 1 {
		t.Fatalf("cancel once the power part answers again: %d, stopped %d", code, ex.stopped)
	}
}
