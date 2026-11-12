package agent_test

// Audit 6, r4-a1-01: what the agent says about a request it handed to the Windows helper and got no answer to.
// These run everywhere. The agent's HTTP API, Power, the helper's client and (where named) the helper's real
// server with its remembering power part are the product's code; "Windows" is a stand-in that counts what it
// is asked and can be made slow, and the pipe is net.Pipe, where needed behind a wrapper that treats deadlines
// as the real pipe is read to treat them (pkg/helper/winpipe: a small write completes at once whatever the
// deadline, a read ends at it). Nothing here ran on Windows.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

// slowWindows stands in for Windows' own shutdown countdown. Schedule waits at gate (nil: not at all) before
// it takes the shutdown, as an InitiateSystemShutdownEx that is slow to return.
type slowWindows struct {
	mu        sync.Mutex
	gate      chan struct{}
	took      time.Duration
	scheduled []string
	aborts    int
}

func (w *slowWindows) Schedule(action string, delay time.Duration, _ string) error {
	if w.gate != nil {
		<-w.gate
	}
	time.Sleep(w.took)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.scheduled = append(w.scheduled, action+"@"+delay.String())
	return nil
}
func (w *slowWindows) Cancel() error            { w.mu.Lock(); w.aborts++; w.mu.Unlock(); return nil }
func (w *slowWindows) CanSleep() (bool, string) { return true, "" }
func (w *slowWindows) asked() (schedules, aborts int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.scheduled), w.aborts
}

// heldPower is the helper's power part with a cancel that can be held: the one way here to keep the helper
// busy with a call for a known time (in the field: a fan change at a slow BMC).
type heldPower struct {
	*agent.RememberedPower
	entered chan struct{} // one value per Cancel that came in
	release chan struct{} // nil: Cancel is not held
	before  chan struct{} // nil: a request goes to the power part at once; else it waits here first
}

// ScheduleBy holds a request up BEFORE the power part takes it (in the helper: its request budget, the
// approval's check). The helper's status says "nothing pending" meanwhile, and that is true.
func (h *heldPower) ScheduleBy(action string, delay time.Duration, who string) error {
	if h.before != nil {
		<-h.before
	}
	return h.RememberedPower.ScheduleBy(action, delay, who)
}

func (h *heldPower) Cancel() error {
	if h.release != nil {
		h.entered <- struct{}{}
		<-h.release
	}
	return h.RememberedPower.Cancel()
}

// pipeLikeConn treats deadlines as winpipe.Conn does: only an operation that does not complete at once looks
// at the deadline. A request frame completes at once, so Write goes out whatever the deadline says; Read waits
// for the answer and ends at it.
type pipeLikeConn struct{ net.Conn }

func (c pipeLikeConn) SetDeadline(t time.Time) error { return c.Conn.SetReadDeadline(t) }

type unansweredRig struct {
	base    string
	windows *slowWindows
	part    *heldPower
	client  *agent.HelperClient
	dialGap time.Duration // how long a new connection takes
}

// newUnansweredRig is an agent over the helper's real server. No status loop runs: the agent's copy of the
// helper's status is renewed only when the client itself decides to, so what a test sees does not depend on
// when a timer fired. Every is the product's 2 s (the copy counts as fresh for 2*Every+Timeout).
func newUnansweredRig(t *testing.T, timeout time.Duration, pipeLike bool) *unansweredRig {
	t.Helper()
	cfg, err := agent.Parse([]byte("power_control: {enabled: true}\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &unansweredRig{windows: &slowWindows{}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r.part = &heldPower{RememberedPower: agent.RememberPower(r.windows, nil, func(a string) bool { return a != "sleep" }, nil),
		entered: make(chan struct{}, 4)}
	srv := helper.New(helper.Parts{Version: "test", Power: r.part, MinDelayS: cfg.PowerControl.MinDelayS,
		Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	scm := &fakeSCM{state: api.HelperRunning, srv: srv}
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		time.Sleep(r.dialGap)
		a, c := net.Pipe()
		go func() { srv.ServeConn(ctx, a, "test"); a.Close() }()
		if pipeLike {
			return pipeLikeConn{c}, nil
		}
		return c, nil
	}
	r.client = agent.NewHelperClient(dial, scm, true)
	r.client.Timeout = timeout
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: r.client,
		Power: agent.NewPower(r.client.Power(), cfg.PowerControl.MinDelayS), HelperSources: []string{api.FeaturePower}}
	hs := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(hs.Close)
	r.base = hs.URL
	return r
}

// firstStatus is the helper's first status answer, as after the agent's start (it opens the connection).
func (r *unansweredRig) firstStatus(t *testing.T) {
	t.Helper()
	if st, m := do(t, r.base, "GET", "/metrics", readTok, nil); st != 200 || m["helper"].(map[string]any)["state"] != api.HelperRunning {
		t.Fatal(st, m["helper"])
	}
}

func (r *unansweredRig) pending(t *testing.T) any {
	t.Helper()
	time.Sleep(260 * time.Millisecond) // past the 250 ms the agent keeps a /metrics answer
	_, m := do(t, r.base, "GET", "/metrics", readTok, nil)
	pc, _ := m["power_control"].(map[string]any)
	return pc["pending"]
}

// waitSchedules waits until "Windows" has been asked for n shutdowns.
func (r *unansweredRig) waitSchedules(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if got, _ := r.windows.asked(); got >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Windows was not asked for %d shutdown(s)", n)
}

var shutdownIn60 = map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "wake-update"}

// A power request that waits for the one connection behind another call gets its whole time once it has the
// connection. Before, its time ran while it waited: it went out with three tenths of it left, "Windows" took
// longer than that, and POST /power answered 500 "could not schedule" for a shutdown that was counting down.
func TestARequestThatWaitedForTheHelperGetsItsWholeTime(t *testing.T) {
	const limit = time.Second
	r := newUnansweredRig(t, limit, false)
	r.firstStatus(t)
	r.windows.took = 500 * time.Millisecond // longer than what was left before (300 ms), well inside the limit
	r.part.release = make(chan struct{})
	held := make(chan error, 1)
	go func() { // the call that keeps the helper busy
		a, by := "cancel", "test"
		_, err := r.client.Call(context.Background(), proto.Request{Verb: proto.VerbPower, Action: &a, By: &by})
		held <- err
	}()
	<-r.part.entered
	type answer struct {
		st   int
		body map[string]any
	}
	got := make(chan answer, 1)
	go func() {
		st, b := do(t, r.base, "POST", "/power", ctlTok, shutdownIn60)
		got <- answer{st, b}
	}()
	time.Sleep(limit * 7 / 10) // the shutdown request waits for the connection for seven tenths of its limit
	close(r.part.release)
	a := <-got
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && a.st != 200; i++ { // not accepted: was it carried out all the same?
		if n, _ := r.windows.asked(); n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	n, _ := r.windows.asked()
	if a.st != 200 || n != 1 {
		t.Fatalf("POST /power answered %d %v, and Windows was asked for %d shutdown(s); want 200 and 1", a.st, a.body, n)
	}
	if p, _ := a.body["pending"].(map[string]any); p["action"] != "shutdown" {
		t.Fatalf("the answer has no countdown: %v", a.body)
	}
	if p, _ := r.pending(t).(map[string]any); p["action"] != "shutdown" {
		t.Fatalf("/metrics does not show the shutdown: %v", p)
	}
}

// The helper has the request and does not answer in its time. POST /power answers 504, the status that means
// "passed on, no answer", not 500 "could not schedule": Windows is counting down. The next /metrics asks the
// helper again instead of using its copy of the status from before, so the shutdown is shown, and a cancel
// reaches Windows.
func TestAShutdownTheHelperDidNotAnswerIsNotCalledFailed(t *testing.T) {
	r := newUnansweredRig(t, 300*time.Millisecond, false)
	r.firstStatus(t)
	r.windows.gate = make(chan struct{})
	st, body := do(t, r.base, "POST", "/power", ctlTok, shutdownIn60)
	text, _ := body["error"].(string)
	if st != 504 || !strings.Contains(text, "did not answer in time") || !strings.Contains(text, "may be scheduled all the same") {
		t.Fatalf("POST /power answered %d %v; want 504 and words that say it may be scheduled", st, body)
	}
	if strings.Contains(text, "could not schedule") {
		t.Fatalf("the answer says the shutdown could not be scheduled: %q", text)
	}
	if _, has := body["code"]; has { // helper_stopped / helper_error would make a panel read "the helper is stopped"
		t.Fatalf("the answer has a code: %v", body)
	}
	if _, has := body["pending"]; has { // nobody knows: the agent does not make a countdown up
		t.Fatalf("the answer has a countdown: %v", body)
	}
	close(r.windows.gate) // "Windows" takes the shutdown now, after the agent stopped waiting
	r.waitSchedules(t, 1)
	p, _ := r.pending(t).(map[string]any)
	if p["action"] != "shutdown" || p["requested_by"] != "wake-update" {
		t.Fatalf("/metrics after the helper carried the request out: pending = %v; want the shutdown", p)
	}
	if st, b := do(t, r.base, "POST", "/power", ctlTok, map[string]any{"action": "reboot", "delay_s": 60}); st != 409 {
		t.Fatalf("a second action over it: %d %v", st, b)
	}
	st, body = do(t, r.base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"})
	if _, aborts := r.windows.asked(); st != 200 || aborts != 1 {
		t.Fatalf("cancel: %d %v, Windows was asked to abort %d time(s); want 200 and 1", st, body, aborts)
	}
	if p := r.pending(t); p != nil {
		t.Fatalf("pending after the cancel: %v", p)
	}
}

// Review of fix7, RF7-02. The helper holds the request up before its power part has it, and answers nothing in
// time: 504. A cancel then finds nothing at the helper. It is not answered "ok, nothing pending": the helper
// schedules the shutdown a moment later. The cancel sent again reaches Windows, although the agent's copy of
// the helper's status is still the one that says nothing (no status loop runs in this rig).
func TestACancelWhileTheHelperStillHoldsTheRequestIsNotOK(t *testing.T) {
	r := newUnansweredRig(t, 300*time.Millisecond, false)
	r.firstStatus(t)
	r.part.before = make(chan struct{})
	if st, body := do(t, r.base, "POST", "/power", ctlTok, shutdownIn60); st != 504 {
		t.Fatalf("POST /power: %d %v", st, body)
	}
	st, body := do(t, r.base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"})
	text, _ := body["error"].(string)
	if st != 409 || !strings.Contains(text, "may still be scheduled") || !strings.Contains(text, "send the cancel again") {
		t.Fatalf("a cancel while the helper holds the request: %d %v; want 409 and the reason", st, body)
	}
	if n, aborts := r.windows.asked(); n != 0 || aborts != 0 {
		t.Fatalf("Windows was asked for %d shutdown(s) and %d abort(s) so far", n, aborts)
	}
	close(r.part.before) // the helper's power part takes the request now
	r.waitSchedules(t, 1)
	st, body = do(t, r.base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"})
	if _, aborts := r.windows.asked(); st != 200 || body["action"] != "cancel" || aborts != 1 {
		t.Fatalf("the cancel sent again: %d %v, Windows was asked to abort %d time(s); want 200 and 1", st, body, aborts)
	}
	if p := r.pending(t); p != nil {
		t.Fatalf("pending after the cancel: %v", p)
	}
	st, body = do(t, r.base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"})
	if _, aborts := r.windows.asked(); st != 200 || aborts != 1 {
		t.Fatalf("a cancel with nothing pending, the action seen and cancelled: %d %v, %d abort(s)", st, body, aborts)
	}
}

// Nothing is written to the helper once the request's time is over. The pipe takes a small write whatever the
// deadline, so before, a request whose time had gone (here: the new connection took too long) still went out,
// was carried out, and was answered "helper not answering".
func TestNothingIsWrittenToTheHelperOnceTheTimeIsOver(t *testing.T) {
	const limit = 200 * time.Millisecond
	r := newUnansweredRig(t, limit, true)
	r.dialGap = limit + 100*time.Millisecond // no connection yet: this request opens it
	err := r.client.Power().ScheduleBy("shutdown", time.Minute, "wake-update")
	var un *agent.HelperUnanswered
	if err == nil || errors.As(err, &un) {
		t.Fatalf("the request's error is %v; want a plain error: nothing was sent", err)
	}
	time.Sleep(300 * time.Millisecond)
	if n, _ := r.windows.asked(); n != 0 {
		t.Fatalf("Windows was asked for %d shutdown(s) by a request whose time was over before it was written", n)
	}
}

// A caller that gave up while its request waited for the connection sends nothing.
func TestACallerThatGaveUpWhileWaitingSendsNothing(t *testing.T) {
	r := newUnansweredRig(t, 2*time.Second, true)
	r.firstStatus(t)
	r.part.release = make(chan struct{})
	held := make(chan error, 1)
	go func() {
		a, by := "cancel", "test"
		_, err := r.client.Call(context.Background(), proto.Request{Verb: proto.VerbPower, Action: &a, By: &by})
		held <- err
	}()
	<-r.part.entered
	ctx, giveUp := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		a, d, by := "shutdown", 60, "wake-update"
		_, err := r.client.Call(ctx, proto.Request{Verb: proto.VerbPower, Action: &a, DelayS: &d, By: &by})
		done <- err
	}()
	time.Sleep(100 * time.Millisecond) // it waits for the connection
	giveUp()
	close(r.part.release)
	if err := <-held; err != nil {
		t.Fatal(err)
	}
	err := <-done
	var un *agent.HelperUnanswered
	if err == nil || errors.As(err, &un) {
		t.Fatalf("the request's error is %v; want a plain error: nothing was sent", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n, _ := r.windows.asked(); n != 0 {
		t.Fatalf("Windows was asked for %d shutdown(s) by a caller that had given up", n)
	}
}

// silentHelper answers the status question and nothing else: it reads every other request and then either
// keeps quiet or, for the verbs drop says yes to, closes the connection. got is what it read, by verb.
type silentHelper struct {
	mu   sync.Mutex
	drop func(verb string) bool
	got  map[string]int
}

func (s *silentHelper) serve(conn net.Conn) {
	defer conn.Close()
	for {
		f, _, err := proto.ReadRequest(conn)
		if err != nil {
			return
		}
		var req struct {
			Verb string `json:"verb"`
		}
		_ = json.Unmarshal(f, &req)
		s.mu.Lock()
		s.got[req.Verb]++
		s.mu.Unlock()
		if req.Verb == proto.VerbStatus {
			b, _ := json.Marshal(proto.OK(proto.StatusData{Version: "test", Features: []string{api.FeatureFans, api.FeaturePower},
				Proto: proto.Version3, Approval: &api.ApprovalStatus{State: api.ApprovalOff, EnforcedBy: api.EnforcedByHelper, Proto: api.ApprovalProto}}))
			if proto.WriteFrame(conn, b, proto.MaxResponse) != nil {
				return
			}
			continue
		}
		if s.drop(req.Verb) {
			return
		}
	}
}

func (s *silentHelper) read(verb string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.got[verb]
}

func newSilentHelper(t *testing.T, drop func(verb string) bool) (*silentHelper, *agent.HelperClient) {
	t.Helper()
	s := &silentHelper{drop: drop, got: map[string]int{}}
	scm := &fakeSCM{state: api.HelperRunning}
	c := agent.NewHelperClient(func(context.Context) (io.ReadWriteCloser, error) {
		a, c := net.Pipe()
		go s.serve(a)
		return c, nil
	}, scm, true)
	c.Timeout = 150 * time.Millisecond
	return s, c
}

// Every route that hands the helper a request that changes something answers 504 with words of its own when
// the helper has the request and does not answer: the fans, the question about an approval (the first-time set
// of the trust goes the same way, with words of its own: "it may be written all the same"), shutdown and cancel. None of them answers 503 "helper_error", which a
// panel reads as "the helper is stopped, nothing was done".
func TestRoutesAnswer504WhenTheHelperHasTheRequestAndIsSilent(t *testing.T) {
	// (the connection is closed on a fan change, so the test does not wait out the 25 s a fan change may take)
	s, c := newSilentHelper(t, func(verb string) bool { return verb == proto.VerbFanMode || verb == proto.VerbFanSet })
	ctx := context.Background()
	check := func(what string, st int, body any, words string) {
		t.Helper()
		m, _ := body.(map[string]any)
		text, _ := m["error"].(string)
		if st != 504 || !strings.Contains(text, "did not answer in time") || !strings.Contains(text, words) || m["code"] != nil {
			t.Errorf("%s: %d %v; want 504, no code, and %q", what, st, body, words)
		}
	}
	st, fb := c.Fan(agent.FanConfig{}).SetMode(ctx, "full", "panel")
	check("fan mode", st, fb, "the fans may have been changed all the same")
	st, fb = c.Fan(agent.FanConfig{}).SetDuty(ctx, 0, 60, "panel")
	check("fan duty", st, fb, "the fans may have been changed all the same")
	action, delay := "shutdown", 60
	st, ab := c.Challenge(ctx, api.ApprovalRequest{Verb: api.ApprovePower, Action: &action, DelayS: &delay})
	check("approval question", st, ab, "the helper was sent the question about an approval and did not answer in time: nothing was done; ask again")
	st, ab = c.TrustInit(ctx, approvaltest.New().Init())
	check("first-time trust", st, ab, "the helper was sent the trust and did not answer in time: it may be written all the same")

	err := c.Power().Cancel()
	var un *agent.HelperUnanswered
	if !errors.As(err, &un) || errors.Is(err, api.ErrHelperStopped) {
		t.Errorf("power cancel: %v; want a HelperUnanswered", err)
	}
	for verb, want := range map[string]int{proto.VerbFanMode: 1, proto.VerbFanSet: 1, proto.VerbChallenge: 1, proto.VerbTrustInit: 1, proto.VerbPower: 1} {
		if n := s.read(verb); n != want {
			t.Errorf("the helper read %d %s request(s); want %d", n, verb, want)
		}
	}
	// a question that changes nothing is not one of these: as before
	fs := c.Fan(agent.FanConfig{}).Status(ctx)
	if fs["available"] != false || fs["reason"] != api.ReasonHelperError {
		t.Errorf("fan status from a silent helper: %v", fs)
	}
}

// A request that changes something is written once. When the connection breaks after the helper has read it,
// it is not sent a second time (the first may have been carried out), and the error says "no answer". A
// question that changes nothing is asked again on a new connection, as before.
func TestARequestThatChangesSomethingIsWrittenOnce(t *testing.T) {
	s, c := newSilentHelper(t, func(string) bool { return true })
	err := c.Power().ScheduleBy("shutdown", time.Minute, "wake-update")
	var un *agent.HelperUnanswered
	if !errors.As(err, &un) {
		t.Fatalf("shutdown: %v; want a HelperUnanswered", err)
	}
	if n := s.read(proto.VerbPower); n != 1 {
		t.Fatalf("the helper read the shutdown %d times; want once", n)
	}
	c.Fan(agent.FanConfig{}).Status(context.Background())
	if n := s.read(proto.VerbFanStatus); n != 2 {
		t.Fatalf("the helper read the fan status question %d times; want twice (asked again on a new connection)", n)
	}
}
