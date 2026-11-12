package agent

// Review of fix7, RF7-02 (and RF7-04): the minute after a request the helper did not answer. The helper here
// is a stand-in that shows the one thing the finding is about: a request can sit inside the helper for a
// while BEFORE its power part takes it, and the helper's status says "nothing pending" meanwhile, truthfully.
// The same order through the agent's HTTP API and the helper's real server is the reviewer's proof
// (reviews/agent-fix7-rev/zz, TestRF7_Unanswered_HelperSlowBeforeItsRecord), run again in the report.

import (
	"strings"
	"testing"
	"time"
)

// heldHelper is the helper as Power sees it through the agent's client.
type heldHelper struct {
	now      func() time.Time
	silent   bool     // the next request gets no answer and is held
	held     []string // requests the helper has and has not taken yet
	record   *Pending // the helper's own record
	copy     *Pending // the agent's copy of the helper's status
	asks     int      // the copy was thrown away and the helper asked (AskAgain)
	cancels  int      // cancels that reached the helper
	aborts   int      // ... and found something to abort
	requests int
}

func (h *heldHelper) Schedule(action string, delay time.Duration, _ string) error {
	h.requests++
	if h.silent {
		h.held = append(h.held, action)
		return &HelperUnanswered{Err: errPipe}
	}
	h.record = &Pending{Action: action, At: float64(h.now().Add(delay).Unix()), DelayS: int(delay / time.Second), RequestedBy: "wake-update"}
	return nil
}

// take is the helper's power part taking a request it held.
func (h *heldHelper) take() {
	h.record = &Pending{Action: h.held[0], At: float64(h.now().Add(time.Minute).Unix()), DelayS: 60, RequestedBy: "wake-update"}
	h.held = h.held[1:]
}

func (h *heldHelper) Cancel() error {
	h.cancels++
	if h.record != nil {
		h.aborts++
		h.record = nil
	}
	return nil
}
func (h *heldHelper) CanSleep() (bool, string) { return true, "" }
func (h *heldHelper) PendingAction() (Pending, bool) {
	if h.copy == nil {
		return Pending{}, false
	}
	return *h.copy, true
}

// AskAgain: the agent asks the helper now. refresh is the same done by the agent's status loop (every 2 s).
func (h *heldHelper) AskAgain() { h.asks++; h.refresh() }
func (h *heldHelper) refresh() {
	h.copy = nil
	if h.record != nil {
		c := *h.record
		h.copy = &c
	}
}

type maybeRig struct {
	m *lateMachine // its two clocks
	h *heldHelper
	p *Power
}

func newMaybeRig() *maybeRig {
	m := newLateMachine()
	h := &heldHelper{now: func() time.Time { return m.wall }}
	p := NewPower(h, 10)
	p.now, p.steady = func() time.Time { return m.wall }, func() time.Time { return m.steady }
	return &maybeRig{m: m, h: h, p: p}
}

func (r *maybeRig) pass(d time.Duration) { r.m.wall, r.m.steady = r.m.wall.Add(d), r.m.steady.Add(d) }

// noAnswer asks for a shutdown that the helper holds and does not answer.
func (r *maybeRig) noAnswer(t *testing.T) {
	t.Helper()
	r.h.silent = true
	d := 60
	if st, b := r.p.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "wake-update"}); st != 504 {
		t.Fatalf("%d %v", st, b)
	}
	r.h.silent = false
}

func (r *maybeRig) cancel() (int, string) {
	st, b := r.p.Handle(PowerRequest{Action: "cancel", RequestedBy: "wake-update"})
	text, _ := b["error"].(string)
	if st == 200 && (b["action"] != "cancel" || b["pending"] != nil) {
		return -1, "a 200 that is not the cancel's answer"
	}
	return st, text
}

// The order of the finding. The helper holds the request; a cancel comes and finds nothing; the helper then
// takes the request. That cancel is not "ok, nothing pending", and the next one reaches the shutdown although
// the agent's copy of the helper's status still says nothing.
func TestAfterNoAnswerACancelThatFoundNothingIsNotOKAndTheNextOneReachesTheAction(t *testing.T) {
	r := newMaybeRig()
	r.noAnswer(t)
	st, text := r.cancel()
	if st != 409 || !strings.Contains(text, "the shutdown that got no answer a moment ago may still be scheduled") || !strings.Contains(text, "send the cancel again") {
		t.Fatalf("a cancel while the helper holds the request: %d %q; want 409 and the reason", st, text)
	}
	if r.h.cancels != 1 || r.h.asks != 1 {
		t.Fatalf("the helper was asked for its status %d time(s) and got %d cancel(s); want 1 and 1", r.h.asks, r.h.cancels)
	}
	r.pass(time.Second)
	r.h.take() // the helper schedules the shutdown now, after it answered that cancel
	if r.p.State()["pending"] != nil {
		t.Fatal("the test wants the moment in which the agent's copy of the status is from before")
	}
	st, text = r.cancel()
	if st != 200 || r.h.aborts != 1 || r.h.record != nil {
		t.Fatalf("the cancel after the helper scheduled: %d %q, %d abort(s); want 200 and 1", st, text, r.h.aborts)
	}
	// settled: the helper showed the action and it was cancelled. A cancel with nothing pending asks nobody.
	if st, _ := r.cancel(); st != 200 || r.h.cancels != 2 || r.h.asks != 2 {
		t.Fatalf("a further cancel: %d; the helper got %d cancels and %d status questions in all", st, r.h.cancels, r.h.asks)
	}
}

// The request never comes. For a minute every cancel is passed on and answered 409; after the minute a cancel
// is a cancel with nothing pending again, and then nobody is asked.
func TestAfterNoAnswerTheMinuteEnds(t *testing.T) {
	r := newMaybeRig()
	r.noAnswer(t)
	for i, at := range []time.Duration{5 * time.Second, 25 * time.Second, 29 * time.Second} {
		r.pass(at)
		if st, text := r.cancel(); st != 409 || r.h.cancels != i+1 {
			t.Fatalf("cancel %d, inside the minute: %d %q, the helper got %d cancel(s)", i+1, st, text, r.h.cancels)
		}
	}
	r.pass(2 * time.Second) // 61 s after the request
	if st, text := r.cancel(); st != 200 || r.h.cancels != 4 {
		t.Fatalf("the cancel after the minute: %d %q, the helper got %d cancel(s); want 200 and 4", st, text, r.h.cancels)
	}
	if st, _ := r.cancel(); st != 200 || r.h.cancels != 4 {
		t.Fatalf("a cancel after that asked the helper again (%d)", r.h.cancels)
	}
}

// The helper took the request and the agent's status loop saw it: it is shown, the minute is over at once, and
// its cancel is a plain cancel.
func TestAfterNoAnswerTheActionTheHelperShowsIsCancelledAsUsual(t *testing.T) {
	r := newMaybeRig()
	r.noAnswer(t)
	r.pass(time.Second)
	r.h.take()
	r.h.refresh()
	if p, _ := r.p.State()["pending"].(Pending); p.Action != "shutdown" {
		t.Fatalf("pending = %v", r.p.State()["pending"])
	}
	if st, text := r.cancel(); st != 200 || r.h.aborts != 1 {
		t.Fatalf("%d %q, %d abort(s)", st, text, r.h.aborts)
	}
	r.h.refresh()
	if st, _ := r.cancel(); st != 200 || r.h.cancels != 1 {
		t.Fatalf("a cancel with nothing pending afterwards: %d, the helper got %d cancels", st, r.h.cancels)
	}
}

// RF7-04: a shutdown is cancelled; a new request for the same time gets no answer and is carried out. What
// the helper then reports is the new shutdown, not the echo of the cancelled one: it is shown.
func TestARequestWithoutAnAnswerIsNotTakenForTheEchoOfTheCancelledOne(t *testing.T) {
	r := newMaybeRig()
	d := 60
	if st, b := r.p.Handle(PowerRequest{Action: "shutdown", DelayS: &d}); st != 200 {
		t.Fatal(st, b)
	}
	r.h.refresh()
	if st, text := r.cancel(); st != 200 {
		t.Fatal(st, text)
	}
	r.h.refresh()
	r.noAnswer(t) // the same second: its time is the cancelled one's
	r.h.take()
	r.h.refresh()
	if p, _ := r.p.State()["pending"].(Pending); p.Action != "shutdown" {
		t.Fatalf("the helper has a shutdown and the agent shows %v", r.p.State()["pending"])
	}
	if st, text := r.cancel(); st != 200 || r.h.aborts != 2 {
		t.Fatalf("%d %q, %d abort(s) in all; want 200 and 2", st, text, r.h.aborts)
	}
}

// A second request that the helper accepts inside the minute does not end it: when that one is cancelled, the
// first can still be taken, and a cancel that finds nothing still says so.
func TestAfterNoAnswerALaterRequestDoesNotEndTheMinute(t *testing.T) {
	r := newMaybeRig()
	r.noAnswer(t)
	r.pass(2 * time.Second)
	d := 600
	if st, b := r.p.Handle(PowerRequest{Action: "reboot", DelayS: &d}); st != 200 {
		t.Fatal(st, b)
	}
	if st, text := r.cancel(); st != 200 || r.h.aborts != 1 {
		t.Fatalf("the cancel of the accepted reboot: %d %q, %d abort(s)", st, text, r.h.aborts)
	}
	r.h.refresh()
	if st, text := r.cancel(); st != 409 {
		t.Fatalf("a cancel with nothing shown, 2 s after a request that got no answer: %d %q; want 409", st, text)
	}
}
