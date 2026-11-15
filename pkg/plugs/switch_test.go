package plugs

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs/hatest"
)

// admitter stands for the passkey check: it counts how often it was asked, and says yes or no.
type admitter struct {
	asked int
	no    bool
	then  func() // called when asked, before the answer
}

func (a *admitter) admit() bool {
	a.asked++
	if a.then != nil {
		a.then()
	}
	return !a.no
}

// quick makes the two timeouts of a switch short, for the tests where Home Assistant does not answer.
func (r *prig) quick(t *testing.T) {
	t.Helper()
	r.p = New(Options{HA: r.p.HA(), Sockets: testSockets(), Switching: true, MinGap: 10 * time.Second, ReadTimeout: 300 * time.Millisecond,
		SwitchTimeout: 300 * time.Millisecond, Now: r.clk.Now, Pause: r.clk.Pause, Log: r.p.o.Log})
}

// The one request: POST to turn_off for off and turn_on for on, once, with the entity of the config; before
// it one state read, after it the reads that confirm. Also when the socket is in that state already.
func TestSwitchSendsOneRequest(t *testing.T) {
	for _, c := range []struct {
		socket, entity, was string
		on                  bool
		path, state         string
	}{
		{"ch1", bar1, "on", false, "/api/services/switch/turn_off", "off"},
		{"ch2", bar2, "off", true, "/api/services/switch/turn_on", "on"},
		{"ch1", bar1, "on", true, "/api/services/switch/turn_on", "on"},     // on already, and asked to be on
		{"ch2", bar2, "off", false, "/api/services/switch/turn_off", "off"}, // off already
	} {
		r := newRig(t, true)
		ad := &admitter{}
		res := r.p.Switch(bg(), "desk-bar", c.socket, c.on, ad.admit)
		if res.Code != "" || !res.Spent || res.Was != c.was || res.State != c.state || !res.Confirmed || ad.asked != 1 || res.Socket.Entity != c.entity {
			t.Fatalf("%s to on=%v: %+v, admit asked %d times", c.socket, c.on, res, ad.asked)
		}
		want := []string{"GET /api/states/" + c.entity, "POST " + c.path, "GET /api/states/" + c.entity}
		if got := paths(r.srv.Requests()); !slices.Equal(got, want) {
			t.Errorf("%s to on=%v: Home Assistant was asked %v, want %v", c.socket, c.on, got, want)
		}
		if posts := r.srv.Posts(); len(posts) != 1 || posts[0].Body != `{"entity_id":"`+c.entity+`"}` || !posts[0].TokenOK {
			t.Errorf("%s to on=%v: %+v", c.socket, c.on, posts)
		}
		if r.srv.Problems() != "" || r.srv.State(c.entity) != c.state {
			t.Errorf("%s; the fake says %q", r.srv.Problems(), r.srv.State(c.entity))
		}
		if res.Took != ConfirmFirst { // by the test's clock: the first look, half a second after the request
			t.Errorf("took %v", res.Took)
		}
		// the row shows the new state without waiting for the reader's next round
		for _, row := range r.p.Rows("desk-bar") {
			if row.ID == c.socket && (row.State != c.state || row.Error != "") {
				t.Errorf("the row of %s says %s (%s)", c.socket, row.State, row.Error)
			}
		}
		if log := r.log.String(); !strings.Contains(log, `msg="plug: switching"`) || !strings.Contains(log, "entity="+c.entity) || strings.Contains(log, hatest.Token()) {
			t.Errorf("log:\n%s", log)
		}
	}
}

// What this machine's config forbids is refused here too, whatever the caller checked, for on and for off:
// no request to Home Assistant at all, and the approval is not even asked for.
func TestSwitchRefusesWhatTheConfigForbids(t *testing.T) {
	for _, on := range []bool{true, false} {
		r := newRig(t, true)
		for _, c := range []struct{ source, socket, code string }{
			{"desk-bar", "ch3", api.CodeNotAllowed},
			{"server-corner", "main", api.CodeFeedsSelf},
			{"own-plug", "main", api.CodeFeedsSelf}, // in switch_allow, and its meter says system_hint: self
			{"desk-bar", "ch9", api.CodeUnknownSocket},
			{"desk", "ch1", api.CodeUnknownSocket},
			{"", "", api.CodeUnknownSocket},
			{"desk-bar", bar1, api.CodeUnknownSocket}, // an entity id is not a socket's id
		} {
			ad := &admitter{}
			res := r.p.Switch(bg(), c.source, c.socket, on, ad.admit)
			if res.Code != c.code || res.Spent || ad.asked != 0 {
				t.Errorf("%s/%s on=%v: %+v, admit asked %d times", c.source, c.socket, on, res, ad.asked)
			}
		}
		off := newRig(t, false) // home_assistant.switching: false
		for _, s := range testSockets() {
			ad := &admitter{}
			if res := off.p.Switch(bg(), s.Source, s.ID, on, ad.admit); res.Code != api.CodePlugSwitchingDisabled || ad.asked != 0 {
				t.Errorf("switching off, %s/%s: %+v", s.Source, s.ID, res)
			}
		}
		if r.srv.Count() != 0 || off.srv.Count() != 0 {
			t.Fatalf("Home Assistant was asked: %v %v", paths(r.srv.Requests()), paths(off.srv.Requests()))
		}
		// feeds_self holds also for a socket that is in switch_allow as well
		both := New(Options{HA: r.p.HA(), Switching: true, Sockets: []Socket{sock("corner", "main", "Corner", corner, true, true, false)}, Now: r.clk.Now, Pause: r.clk.Pause})
		if res := both.Switch(bg(), "corner", "main", on, (&admitter{}).admit); res.Code != api.CodeFeedsSelf || r.srv.Count() != 0 {
			t.Errorf("in both lists: %+v", res)
		}
	}
}

// A socket Home Assistant does not reach, or has no state for, is refused before the approval is touched:
// one state read, no switch request. Home Assistant would answer the switch request with 200 and do nothing.
func TestSwitchRefusesASocketWithoutAState(t *testing.T) {
	for said, want := range map[string]string{"unavailable": "unavailable", "unknown": "unknown", "heating": "unknown", "": "unknown", "ON": "unknown"} {
		r := newRig(t, true)
		r.srv.Set(bar1, said)
		ad := &admitter{}
		res := r.p.Switch(bg(), "desk-bar", "ch1", false, ad.admit)
		if res.Code != api.CodeSocketUnavailable || res.Spent || ad.asked != 0 || res.Was != want {
			t.Errorf("Home Assistant says %q: %+v, admit asked %d times", said, res, ad.asked)
		}
		if got := paths(r.srv.Requests()); !slices.Equal(got, []string{"GET /api/states/" + bar1}) {
			t.Errorf("Home Assistant says %q: asked %v", said, got)
		}
		// the socket comes back: the same call now goes through, and only now is the approval asked for
		r.srv.Set(bar1, "on")
		if res := r.p.Switch(bg(), "desk-bar", "ch1", false, ad.admit); res.Code != "" || !res.Confirmed || ad.asked != 1 {
			t.Errorf("after it came back: %+v", res)
		}
	}
}

// No state at all before the switch: refused, nothing sent that changes anything, the approval not asked for.
func TestSwitchRefusesWhenTheStateCannotBeRead(t *testing.T) {
	for name, c := range map[string]struct {
		do        func(r *prig)
		code, why string
		gets      int
	}{
		"no answer":          {func(r *prig) { r.srv.HangState(true) }, api.CodeHAUnreachable, "timeout", 1},
		"http 500":           {func(r *prig) { r.srv.AnswerState(500) }, api.CodeHAUnreachable, "http 500", 1},
		"the entity is gone": {func(r *prig) { r.srv.Remove(bar1) }, api.CodeHAUnreachable, "entity not found", 1},
		"a redirect":         {func(r *prig) { r.srv.Redirect("http://192.0.2.99:8123") }, api.CodeHAUnreachable, "http 307", 1},
		"another entity":     {func(r *prig) { r.srv.AnswerAs(corner) }, api.CodeHAUnreachable, "home assistant answered for another entity", 1},
		"the token refused":  {func(r *prig) { r.srv.AnswerState(401) }, api.CodeHAUnreachable, "home assistant refused the token", 1},
		"no token":           {func(r *prig) { t.Setenv(tokenEnv, "") }, api.CodeNoSwitchToken, "the variable " + tokenEnv + " holds no token for Home Assistant", 0},
	} {
		r := newRig(t, true)
		r.quick(t)
		c.do(r)
		ad := &admitter{}
		res := r.p.Switch(bg(), "desk-bar", "ch1", false, ad.admit)
		if res.Code != c.code || !strings.HasPrefix(res.Why, c.why) || res.Spent || ad.asked != 0 {
			t.Errorf("%s: %+v, admit asked %d times", name, res, ad.asked)
		}
		if len(r.srv.Posts()) != 0 || len(r.srv.Gets()) != c.gets {
			t.Errorf("%s: Home Assistant was asked %v", name, paths(r.srv.Requests()))
		}
		t.Setenv(tokenEnv, hatest.Token())
	}
}

// The approval is asked for exactly once, after the state was read and before anything is sent; a no sends
// nothing, and the try does not start the gap.
func TestSwitchSendsNothingWithoutTheApproval(t *testing.T) {
	r := newRig(t, true)
	ad := &admitter{no: true, then: func() {
		if got := paths(r.srv.Requests()); !slices.Equal(got, []string{"GET /api/states/" + bar1}) {
			t.Errorf("when the approval was asked for, Home Assistant had been asked %v", got)
		}
	}}
	res := r.p.Switch(bg(), "desk-bar", "ch1", false, ad.admit)
	if res.Code != CodeNotAdmitted || res.Spent || res.Was != "on" || ad.asked != 1 {
		t.Fatalf("%+v, admit asked %d times", res, ad.asked)
	}
	if len(r.srv.Posts()) != 0 || r.srv.Count() != 1 || r.srv.State(bar1) != "on" {
		t.Fatalf("asked %v; the socket is %s", paths(r.srv.Requests()), r.srv.State(bar1))
	}
	yes := &admitter{}
	if res := r.p.Switch(bg(), "desk-bar", "ch1", false, yes.admit); res.Code != "" || !res.Confirmed {
		t.Fatalf("right after a refused try: %+v", res)
	}
}

// Home Assistant answers 200 and the socket does not follow (it left the entity out, or the plug is slow):
// the answer says so. Success is only ever what a state read showed.
func TestSwitchIsConfirmedByTheStateOnly(t *testing.T) {
	t.Run("never", func(t *testing.T) {
		for name, c := range map[string]struct {
			before func(*hatest.Server) // how the fake behaves from the start
			after  func(*hatest.Server) // what happens between the state read and the request
			state  string               // the state the answer names
		}{
			"the request is ignored":    {before: func(s *hatest.Server) { s.IgnoreSwitch(true) }, state: "on"},
			"the plug does not follow":  {before: func(s *hatest.Server) { s.NeverChange() }, state: "on"},
			"it follows after 11 looks": {before: func(s *hatest.Server) { s.ChangeAfterReads(11) }, state: "on"},
			"it became unavailable":     {after: func(s *hatest.Server) { s.Set(bar1, "unavailable") }, state: "unavailable"},
			"the looks all fail":        {before: func(s *hatest.Server) { s.NeverChange() }, after: func(s *hatest.Server) { s.AnswerState(500) }, state: "unknown"},
		} {
			r := newRig(t, true)
			if c.before != nil {
				c.before(r.srv)
			}
			ad := &admitter{}
			if c.after != nil {
				ad.then = func() { c.after(r.srv) }
			}
			res := r.p.Switch(bg(), "desk-bar", "ch1", false, ad.admit)
			if res.Code != "" || res.Confirmed || !res.Spent || res.Was != "on" || res.State != c.state {
				t.Errorf("%s: %+v", name, res)
			}
			// ten looks: after 0.5 s and then every second, the last at 9.5 s
			if gets, posts := len(r.srv.Gets()), len(r.srv.Posts()); gets != 11 || posts != 1 {
				t.Errorf("%s: %d GETs and %d POSTs, want the read before, one request and ten looks", name, gets, posts)
			}
			if res.Took != 9500*time.Millisecond {
				t.Errorf("%s: took %v by the test's clock", name, res.Took)
			}
			if want := []time.Duration{ConfirmFirst, ConfirmEvery, ConfirmEvery}; len(r.clk.pauses) != 10 || !slices.Equal(r.clk.pauses[:3], want) {
				t.Errorf("%s: the waits were %v", name, r.clk.pauses)
			}
		}
	})
	t.Run("late", func(t *testing.T) {
		r := newRig(t, true)
		r.srv.ChangeAfterReads(4) // the fourth look sees it: 3.5 s after the request
		res := r.p.Switch(bg(), "desk-bar", "ch1", false, (&admitter{}).admit)
		if res.Code != "" || !res.Confirmed || res.State != "off" || res.Took != 3500*time.Millisecond {
			t.Errorf("%+v", res)
		}
		if gets, posts := len(r.srv.Gets()), len(r.srv.Posts()); gets != 5 || posts != 1 {
			t.Errorf("%d GETs and %d POSTs", gets, posts)
		}
	})
	t.Run("the last look", func(t *testing.T) {
		r := newRig(t, true)
		r.srv.ChangeAfterReads(10)
		if res := r.p.Switch(bg(), "desk-bar", "ch1", false, (&admitter{}).admit); res.Code != "" || !res.Confirmed || res.Took != 9500*time.Millisecond {
			t.Errorf("%+v", res)
		}
	})
}

// The switch request gets no answer: it may have arrived. It is never sent again. If the socket shows the new
// state, that is a switch; if it does not within ten seconds, the answer is no_answer. Either way the
// approval is spent.
func TestSwitchWithoutAnAnswer(t *testing.T) {
	for name, c := range map[string]struct {
		do        func(*hatest.Server)
		code      string
		confirmed bool
	}{
		"no answer, and it did not arrive":   {func(s *hatest.Server) { s.HangSwitch(false) }, api.CodeNoAnswer, false},
		"no answer, and it arrived":          {func(s *hatest.Server) { s.HangSwitch(true) }, "", true},
		"the connection cut, not arrived":    {func(s *hatest.Server) { s.CutSwitch(false) }, api.CodeNoAnswer, false},
		"the connection cut, arrived":        {func(s *hatest.Server) { s.CutSwitch(true) }, "", true},
		"an answer too late, arrived":        {func(s *hatest.Server) { s.LateSwitch(2*time.Second, true) }, "", true},
		"arrived, and the plug follows late": {func(s *hatest.Server) { s.CutSwitch(true); s.ChangeAfterReads(3) }, "", true},
	} {
		r := newRig(t, true)
		r.quick(t)
		c.do(r.srv)
		res := r.p.Switch(bg(), "desk-bar", "ch1", false, (&admitter{}).admit)
		if res.Code != c.code || res.Confirmed != c.confirmed || !res.Spent || res.Was != "on" {
			t.Errorf("%s: %+v", name, res)
		}
		time.Sleep(50 * time.Millisecond)
		if posts := r.srv.Posts(); len(posts) != 1 {
			t.Errorf("%s: %d switch requests", name, len(posts))
		}
		if c.code == api.CodeNoAnswer && len(r.srv.Gets()) != 11 {
			t.Errorf("%s: %d state reads, want the one before and ten looks", name, len(r.srv.Gets()))
		}
		// the gap counts from a request that was sent, answered or not
		if again := r.p.Switch(bg(), "desk-bar", "ch1", true, (&admitter{}).admit); again.Code != api.CodeTooSoon && c.code == api.CodeNoAnswer {
			t.Errorf("%s: a second switch right after it: %+v", name, again)
		}
	}
}

// Home Assistant answers the switch request with an error: ha_refused, nothing more is sent (no look at the
// state, no second request), and the approval is spent. A refusal of the token starts the reader's long wait.
func TestSwitchRefusedByHomeAssistant(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 405, 500, 502, 503, 307, 204} {
		r := newRig(t, true)
		ad := &admitter{then: func() { // the state read before was answered honestly
			if status == 307 {
				r.srv.Redirect("http://192.0.2.99:8123")
			} else {
				r.srv.AnswerSwitch(status)
			}
		}}
		res := r.p.Switch(bg(), "desk-bar", "ch1", false, ad.admit)
		if res.Code != api.CodeHARefused || !res.Spent || res.Confirmed || res.Was != "on" || ad.asked != 1 {
			t.Fatalf("http %d: %+v", status, res)
		}
		if tokenRefused := status == 401 || status == 403; tokenRefused != (res.Why == "home assistant refused the token") ||
			(!tokenRefused && res.Why != "home assistant answered http "+strconv.Itoa(status)) {
			t.Errorf("http %d: %q", status, res.Why)
		}
		if got := paths(r.srv.Requests()); !slices.Equal(got, []string{"GET /api/states/" + bar1, "POST /api/services/switch/turn_off"}) {
			t.Errorf("http %d: asked %v", status, got)
		}
		// after a refused token nothing is asked for a while: not by the reader, not by the next switch
		r.srv.Honest()
		r.srv.Forget()
		r.p.PollOnce(bg())
		r.clk.add(time.Minute) // past the gap
		next := r.p.Switch(bg(), "desk-bar", "ch1", false, (&admitter{}).admit)
		if status == 401 || status == 403 {
			if r.srv.Count() != 0 || next.Code != api.CodeHAUnreachable || next.Spent || next.RetryAfter <= 0 || next.RetryAfter > 5*time.Minute {
				t.Errorf("http %d: after the refusal Home Assistant was asked %v; the next switch: %+v", status, paths(r.srv.Requests()), next)
			}
			for _, row := range r.p.Rows("desk-bar") {
				if row.State != api.SocketStateUnknown || row.Error != "home assistant refused the token" {
					t.Errorf("http %d: row %s says %s (%s)", status, row.ID, row.State, row.Error)
				}
			}
		} else if next.Code != "" || !next.Confirmed {
			t.Errorf("http %d: the next switch: %+v", status, next)
		}
	}
}

// One socket is switched at most every MinGap; the gap is each socket's own, starts with a request that was
// sent, and a try that is too soon asks nothing of anybody.
func TestSwitchGap(t *testing.T) {
	r := newRig(t, true)
	sw := func(socket string, on bool) (Result, int) {
		ad := &admitter{}
		res := r.p.Switch(bg(), "desk-bar", socket, on, ad.admit)
		return res, ad.asked
	}
	if res, _ := sw("ch1", false); res.Code != "" {
		t.Fatalf("%+v", res)
	}
	r.srv.Forget() // the switch took 0.5 s by the test's clock
	res, asked := sw("ch1", true)
	if res.Code != api.CodeTooSoon || res.RetryAfter != 9500*time.Millisecond || res.Spent || asked != 0 || r.srv.Count() != 0 {
		t.Fatalf("right after: %+v, admit asked %d times, %d requests", res, asked, r.srv.Count())
	}
	if res, _ := sw("ch2", true); res.Code != "" { // another socket has its own gap
		t.Fatalf("another socket: %+v", res)
	}
	r.clk.add(8 * time.Second) // 9 s after the first switch
	if res, _ := sw("ch1", true); res.Code != api.CodeTooSoon || res.RetryAfter != time.Second {
		t.Fatalf("after 9 s: %+v", res)
	}
	r.clk.add(time.Second)
	if res, _ := sw("ch1", true); res.Code != "" || !res.Confirmed {
		t.Fatalf("after 10 s: %+v", res)
	}
	// a try that was refused before anything was sent starts no gap
	r.clk.add(time.Minute)
	r.srv.Set(bar1, "unavailable")
	if res, _ := sw("ch1", false); res.Code != api.CodeSocketUnavailable {
		t.Fatalf("%+v", res)
	}
	r.srv.Set(bar1, "on")
	if res, _ := sw("ch1", false); res.Code != "" {
		t.Fatalf("right after a try that sent nothing: %+v", res)
	}
	// a clock that was set back does not lock a socket for longer than the gap
	r.clk.add(-time.Hour)
	if res, _ := sw("ch1", true); res.Code != "" {
		t.Fatalf("after the clock was set back: %+v", res)
	}
	if r.p.MinGap() != 10*time.Second {
		t.Fatal(r.p.MinGap())
	}
}

// One switch at a time on this agent: a second one, for any socket, is refused at once and asks nothing.
func TestSwitchOneAtATime(t *testing.T) {
	r := newRig(t, true)
	r.srv.HangState(true) // the first switch waits for its state read
	first := make(chan Result, 1)
	go func() { first <- r.p.Switch(bg(), "desk-bar", "ch1", false, (&admitter{}).admit) }()
	for i := 0; i < 400 && r.srv.Count() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if r.srv.Count() != 1 {
		t.Fatal("the first switch did not start")
	}
	for _, socket := range []string{"ch1", "ch2"} {
		ad := &admitter{}
		start := time.Now()
		res := r.p.Switch(bg(), "desk-bar", socket, true, ad.admit)
		if res.Code != api.CodeSwitchInProgress || res.Spent || ad.asked != 0 || time.Since(start) > time.Second {
			t.Errorf("%s while another switch runs: %+v", socket, res)
		}
	}
	if r.srv.Count() != 1 {
		t.Errorf("the refused switches asked Home Assistant: %v", paths(r.srv.Requests()))
	}
	r.srv.Close() // the first one's read ends
	select {
	case res := <-first:
		if res.Code != api.CodeHAUnreachable || res.Spent {
			t.Errorf("the first switch: %+v", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the first switch did not end")
	}
	// and the lock is free again
	if res := r.p.Switch(bg(), "desk-bar", "ch3", true, (&admitter{}).admit); res.Code != api.CodeNotAllowed {
		t.Errorf("%+v", res)
	}
}

// A caller that hangs up after the approval was spent does not stop the request from being sent.
func TestSwitchGoesOnWhenTheCallerHangsUp(t *testing.T) {
	r := newRig(t, true)
	ctx, cancel := context.WithCancel(bg())
	defer cancel()
	ad := &admitter{then: cancel}
	res := r.p.Switch(ctx, "desk-bar", "ch1", false, ad.admit)
	if res.Code != "" || !res.Spent || !res.Confirmed || r.srv.State(bar1) != "off" || len(r.srv.Posts()) != 1 {
		t.Fatalf("%+v; the socket is %s after %v", res, r.srv.State(bar1), paths(r.srv.Requests()))
	}
	// one that hung up before: nothing is read, nothing is sent, nothing is spent
	gone, cancel2 := context.WithCancel(bg())
	cancel2()
	r.clk.add(time.Minute)
	r.srv.Forget()
	ad = &admitter{}
	if res := r.p.Switch(gone, "desk-bar", "ch1", true, ad.admit); res.Code != api.CodeHAUnreachable || res.Spent || ad.asked != 0 || len(r.srv.Posts()) != 0 {
		t.Fatalf("%+v", res)
	}
}
