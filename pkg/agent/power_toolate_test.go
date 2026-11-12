package agent

// Audit 6, r4-a1-03: a cancel that comes after the power part carried the action out. The power part here is a
// stand-in that behaves as the Linux one does after this change (its timer runs, then Cancel says errTooLate);
// the Linux one itself is in power_linux_test.go.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

type lateExec struct {
	steady  func() time.Time
	verb    string
	due     time.Time // zero: no timer
	ran     string
	cancels int
}

func (e *lateExec) Schedule(action string, delay time.Duration, _ string) error {
	e.verb, e.due, e.ran = map[string]string{"shutdown": "poweroff", "reboot": "reboot", "sleep": "suspend"}[action], e.steady().Add(delay), ""
	return nil
}

func (e *lateExec) Cancel() error {
	e.cancels++
	if e.ran != "" {
		return fmt.Errorf("%w: systemctl %s was already run", errTooLate, e.ran)
	}
	e.due = time.Time{}
	return nil
}
func (e *lateExec) CanSleep() (bool, string) { return true, "" }

type lateMachine struct {
	wall, steady time.Time
	ex           *lateExec
	p            *Power
}

func newLateMachine() *lateMachine {
	m := &lateMachine{wall: time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC), steady: time.Unix(5000, 0)}
	m.ex = &lateExec{steady: func() time.Time { return m.steady }}
	m.p = NewPower(m.ex, 10)
	m.p.now, m.p.steady = func() time.Time { return m.wall }, func() time.Time { return m.steady }
	return m
}

// pass lets d of time pass; the timer runs when its time has come.
func (m *lateMachine) pass(d time.Duration) {
	m.wall, m.steady = m.wall.Add(d), m.steady.Add(d)
	if !m.ex.due.IsZero() && !m.steady.Before(m.ex.due) {
		m.ex.ran, m.ex.due = m.ex.verb, time.Time{}
	}
}

func (m *lateMachine) shutdownIn(t *testing.T, s int) {
	t.Helper()
	if st, b := m.p.Handle(PowerRequest{Action: "shutdown", DelayS: &s, RequestedBy: "alice"}); st != 200 {
		t.Fatal(st, b)
	}
}

func (m *lateMachine) cancel() (int, map[string]any) {
	return m.p.Handle(PowerRequest{Action: "cancel", RequestedBy: "bob"})
}

// In the minute after the timer ran, the action is still on record. A cancel then is answered 409 with the
// reason, never 200 "cancelled", and the record stays for its minute.
func TestACancelAfterTheActionWasCarriedOutSaysTooLate(t *testing.T) {
	m := newLateMachine()
	m.shutdownIn(t, 60)
	m.pass(61 * time.Second) // systemctl poweroff was run a second ago; the machine is still going down
	if m.p.State()["pending"] == nil {
		t.Fatal("the shutdown is not on record in the minute after its time")
	}
	for i := 0; i < 2; i++ {
		st, body := m.cancel()
		text, _ := body["error"].(string)
		if st != 409 || !strings.Contains(text, "too late to cancel") || !strings.Contains(text, "systemctl poweroff was already run") {
			t.Fatalf("cancel %d after the timer ran: %d %v; want 409 and the reason", i+1, st, body)
		}
		if _, has := body["action"]; has || len(body) != 1 {
			t.Fatalf("the answer looks like a cancel that worked: %v", body)
		}
		if m.p.State()["pending"] == nil {
			t.Fatal("the record is gone after a cancel that stopped nothing")
		}
	}
	d := 60
	if st, b := m.p.Handle(PowerRequest{Action: "reboot", DelayS: &d}); st != 409 {
		t.Fatalf("a new action inside the minute: %d %v", st, b)
	}
	// the minute is over: nothing is pending, a cancel is "nothing to cancel" again, and nobody is asked
	m.pass(60 * time.Second)
	asked := m.ex.cancels
	if st, body := m.cancel(); st != 200 || body["action"] != "cancel" || body["pending"] != nil || m.ex.cancels != asked {
		t.Fatalf("cancel after the minute: %d %v, the power part was asked %d more time(s)", st, body, m.ex.cancels-asked)
	}
	if st, b := m.p.Handle(PowerRequest{Action: "reboot", DelayS: &d}); st != 200 {
		t.Fatalf("a new action after the minute: %d %v", st, b)
	}
	if st, body := m.cancel(); st != 200 || m.p.State()["pending"] != nil {
		t.Fatalf("the new action's cancel: %d %v", st, body)
	}
}

// Nobody cancelled during the minute. A cancel afterwards, with nothing on record, asks the power part once
// (this process scheduled something it never stopped), hears "too late", and is answered as a cancel with
// nothing pending: 200. The next one asks nobody.
func TestACancelLongAfterTheActionIsACancelWithNothingPending(t *testing.T) {
	m := newLateMachine()
	m.shutdownIn(t, 60)
	m.pass(3 * time.Minute)
	if m.p.State()["pending"] != nil {
		t.Fatal("still on record three minutes later")
	}
	for i, want := range []int{1, 1, 1} {
		if st, body := m.cancel(); st != 200 || body["action"] != "cancel" || m.ex.cancels != want {
			t.Fatalf("cancel %d: %d %v, the power part was asked %d time(s) in all; want 200 and %d", i+1, st, body, m.ex.cancels, want)
		}
	}
}

// A cancel in time is what it was: 200, the timer stopped, nothing runs later.
func TestACancelInTimeIsStillACancel(t *testing.T) {
	m := newLateMachine()
	m.shutdownIn(t, 60)
	m.pass(59 * time.Second)
	if st, body := m.cancel(); st != 200 || body["action"] != "cancel" || m.p.State()["pending"] != nil {
		t.Fatalf("%d %v", st, body)
	}
	m.pass(time.Hour)
	if m.ex.ran != "" {
		t.Fatalf("systemctl %s ran after the cancel", m.ex.ran)
	}
}
