package agent

// Audit 6, r4-a1-01, at Power: a power part that says "the helper has the request and did not answer"
// (*HelperUnanswered). The power part here is a stand-in; the helper's client that makes that error, and the
// HTTP answers, are in helper_unanswered_test.go.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// silentExec is a power part whose requests go out and may get no answer.
type silentExec struct {
	scheduleErr, cancelErr error
	schedules, cancels     int
}

func (s *silentExec) Schedule(string, time.Duration, string) error {
	s.schedules++
	return s.scheduleErr
}
func (s *silentExec) Cancel() error {
	s.cancels++
	return s.cancelErr
}
func (s *silentExec) CanSleep() (bool, string) { return true, "" }

var errPipe = errors.New("read pipe: i/o timeout")

// A shutdown the helper did not answer: 504 with words that say it may be scheduled, nothing made up on
// record, and from then on every cancel reaches the power part although nothing is shown.
func TestPowerSaysNoAnswerAndACancelStillReachesThePowerPart(t *testing.T) {
	ex := &silentExec{scheduleErr: &HelperUnanswered{Err: errPipe}}
	p := NewPower(ex, 10)
	d := 60
	st, body := p.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "wake-update"})
	text, _ := body["error"].(string)
	if st != 504 || !strings.Contains(text, "the helper was sent the shutdown and did not answer in time") ||
		!strings.Contains(text, "may be scheduled all the same") || strings.Contains(text, "could not schedule") {
		t.Fatalf("%d %v", st, body)
	}
	if len(body) != 1 {
		t.Fatalf("the answer has more than its words: %v", body)
	}
	if p.State()["pending"] != nil {
		t.Fatal("a countdown nobody knows of is on record")
	}
	// Every cancel of the next minute reaches the power part. One that found nothing there is not "ok": the
	// request may still be on its way (review of fix7, RF7-02; this test held "200" for the first of them and
	// "nobody is asked" for the second, which is what was wrong). The minute itself: power_maybe_test.go.
	for i := 1; i <= 2; i++ {
		if st, body := p.Handle(PowerRequest{Action: "cancel"}); st != 409 || ex.cancels != i {
			t.Fatalf("cancel %d with nothing shown: %d %v, the power part was asked %d time(s); want 409 and %d", i, st, body, ex.cancels, i)
		}
	}
	// a plain failure is still "could not schedule", 500, and asks nobody afterwards
	ex2 := &silentExec{scheduleErr: errors.New("access denied")}
	p2 := NewPower(ex2, 10)
	if st, body := p2.Handle(PowerRequest{Action: "shutdown", DelayS: &d}); st != 500 || !strings.Contains(body["error"].(string), "could not schedule the shutdown") {
		t.Fatalf("%d %v", st, body)
	}
	if st, _ := p2.Handle(PowerRequest{Action: "cancel"}); st != 200 || ex2.cancels != 0 {
		t.Fatalf("cancel after a request that failed: %d, asked %d time(s)", st, ex2.cancels)
	}
}

// A cancel the helper did not answer is neither "cancelled" nor "could not cancel": 504, the action stays on
// record, and the cancel can be sent again.
func TestACancelWithoutAnAnswerIsNeitherCancelledNorFailed(t *testing.T) {
	ex := &silentExec{}
	p := NewPower(ex, 10)
	d := 60
	if st, body := p.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "alice"}); st != 200 {
		t.Fatal(st, body)
	}
	ex.cancelErr = &HelperUnanswered{Err: errPipe}
	st, body := p.Handle(PowerRequest{Action: "cancel"})
	text, _ := body["error"].(string)
	if st != 504 || !strings.Contains(text, "the helper was sent the cancel and did not answer in time") || strings.Contains(text, "could not cancel") {
		t.Fatalf("%d %v", st, body)
	}
	if p.State()["pending"] == nil {
		t.Fatal("the action is off the record after a cancel nobody answered")
	}
	ex.cancelErr = nil
	if st, body := p.Handle(PowerRequest{Action: "cancel"}); st != 200 || ex.cancels != 2 || p.State()["pending"] != nil {
		t.Fatalf("the cancel sent again: %d %v, asked %d time(s), pending %v", st, body, ex.cancels, p.State()["pending"])
	}
}
