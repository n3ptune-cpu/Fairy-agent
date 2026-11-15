package plugs

import (
	"bytes"
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs/hatest"
)

const (
	bar3   = "switch.desk_bar_socket_3"
	corner = "switch.server_corner_socket"
	own    = "switch.own_plug"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

// clock is a clock the test moves: Pause moves it on and never waits.
type clock struct {
	mu     sync.Mutex
	now    time.Time
	pauses []time.Duration
	stop   func() // called by Pause after `rounds` pauses
	rounds int
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
func (c *clock) Pause(ctx context.Context, d time.Duration) bool {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.pauses = append(c.pauses, d)
	done := c.stop != nil && len(c.pauses) >= c.rounds
	c.mu.Unlock()
	if done {
		c.stop()
		return false
	}
	return ctx.Err() == nil
}

// sock is a socket as the agent's config would describe it.
func sock(source, id, name, entity string, allowed, feeds, self bool) Socket {
	return Socket{Source: source, SourceName: "Meter " + source, ID: id, Name: name, Entity: entity, Tag: api.SocketTag(source, id, name, entity),
		Allowed: allowed, FeedsSelf: feeds, SelfHint: self}
}

// the sockets of the tests: a powerbar with three sockets (two allowed), the plug that feeds everything
// (feeds_self), and the plug of the machine itself (allowed, but its meter says system_hint: self).
func testSockets() []Socket {
	return []Socket{
		sock("desk-bar", "ch1", "Left monitor", bar1, true, false, false),
		sock("desk-bar", "ch2", "ch2", bar2, true, false, false),
		sock("desk-bar", "ch3", "Lamp", bar3, false, false, false),
		sock("server-corner", "main", "Server corner", corner, false, true, false),
		sock("own-plug", "main", "This machine", own, true, false, true),
	}
}

type prig struct {
	srv *hatest.Server
	p   *Plugs
	clk *clock
	log *syncBuf
}

func newRig(t *testing.T, switching bool) *prig {
	t.Helper()
	srv := hatest.New(map[string]string{bar1: "on", bar2: "off", bar3: "on", corner: "on", own: "on"})
	t.Cleanup(srv.Close)
	t.Setenv(tokenEnv, hatest.Token())
	r := &prig{srv: srv, clk: &clock{now: time.Unix(1794000000, 0)}, log: &syncBuf{}}
	r.p = New(Options{HA: newHA(t, srv.URL, ""), Sockets: testSockets(), Switching: switching, MinGap: 10 * time.Second,
		Now: r.clk.Now, Pause: r.clk.Pause, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	return r
}

func (r *prig) states(source string) string {
	var out []string
	for _, row := range r.p.Rows(source) {
		s := row.ID + "=" + row.State
		if row.Error != "" {
			s += " (" + row.Error + ")"
		}
		out = append(out, s)
	}
	return strings.Join(out, ", ")
}

func paths(reqs []hatest.Request) []string {
	var out []string
	for _, q := range reqs {
		out = append(out, q.Method+" "+q.Path)
	}
	return out
}

// Before the first round nothing is known and nothing was asked; one round is one GET for each socket, in
// config order, with the token for switching.
func TestReaderAsksEachSocketOnce(t *testing.T) {
	r := newRig(t, true)
	if got := r.states("desk-bar"); got != "ch1=unknown (not read yet), ch2=unknown (not read yet), ch3=unknown (not read yet)" || r.srv.Count() != 0 {
		t.Fatalf("before the first read: %s; %d requests", got, r.srv.Count())
	}
	r.p.PollOnce(bg())
	want := []string{"GET /api/states/" + bar1, "GET /api/states/" + bar2, "GET /api/states/" + bar3, "GET /api/states/" + corner, "GET /api/states/" + own}
	if got := paths(r.srv.Requests()); !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	for _, q := range r.srv.Requests() {
		if !q.TokenOK || q.Body != "" {
			t.Errorf("%s: token as expected %v, body %q", q.Path, q.TokenOK, q.Body)
		}
	}
	if got := r.states("desk-bar"); got != "ch1=on, ch2=off, ch3=on" {
		t.Errorf("%s", got)
	}
	if got := r.states("server-corner") + "; " + r.states("own-plug") + "; " + r.states("no-such-source"); got != "main=on; main=on; " {
		t.Errorf("%s", got)
	}
	// the button on the plug, Home Assistant losing a socket, an entity that is gone: the next round follows
	r.srv.Set(bar1, "off")
	r.srv.Set(bar2, "unavailable")
	r.srv.Set(corner, "heating")
	r.srv.Remove(bar3)
	r.p.PollOnce(bg())
	if got := r.states("desk-bar"); got != "ch1=off, ch2=unavailable, ch3=unknown (entity not found)" {
		t.Errorf("%s", got)
	}
	if got := r.states("server-corner"); got != "main=unknown" {
		t.Errorf("%s", got)
	}
	if r.srv.Problems() != "" || len(r.srv.Posts()) != 0 {
		t.Errorf("%s; %d POSTs", r.srv.Problems(), len(r.srv.Posts()))
	}
	// one socket's trouble is its own: the others were read (ten requests in two rounds)
	if n := r.srv.Count(); n != 10 {
		t.Errorf("%d requests in two rounds of five sockets", n)
	}
}

func TestFindAndLock(t *testing.T) {
	r := newRig(t, true)
	s, ok := r.p.Find("desk-bar", "ch1")
	if !ok || s.Entity != bar1 || s.Name != "Left monitor" || s.Tag != api.SocketTag("desk-bar", "ch1", "Left monitor", bar1) {
		t.Fatalf("%+v %v", s, ok)
	}
	for _, miss := range [][2]string{{"desk-bar", "ch9"}, {"desk-ba", "ch1"}, {"", ""}, {"ch1", "desk-bar"}, {"desk-bar", "CH1"}, {"desk-bar", bar1}, {"own-plug", "ch1"}} {
		if _, ok := r.p.Find(miss[0], miss[1]); ok {
			t.Errorf("found %v", miss)
		}
	}
	locks := func(p *Plugs) string {
		var out []string
		for _, s := range p.Sockets() {
			out = append(out, s.Source+"/"+s.ID+"="+p.Lock(s))
		}
		return strings.Join(out, " ")
	}
	if got := locks(r.p); got != "desk-bar/ch1= desk-bar/ch2= desk-bar/ch3=not_allowed server-corner/main=feeds_self own-plug/main=feeds_self" {
		t.Errorf("switching on: %s", got)
	}
	// feeds_self counts before the allow list, in both orders of being listed
	both := sock("x", "a", "a", "switch.a", true, true, false)
	if r.p.Lock(both) != api.WhyFeedsSelf {
		t.Errorf("a socket in both lists: %q", r.p.Lock(both))
	}
	off := newRig(t, false)
	if got := locks(off.p); strings.Count(got, "=switching_off") != 5 || off.p.Switching() {
		t.Errorf("switching off: %s", got)
	}
	var none *Plugs
	if none.Switching() || !none.Empty() || none.Rows("desk-bar") != nil || none.Sockets() != nil {
		t.Error("no sockets at all")
	}
	if _, ok := none.Find("desk-bar", "ch1"); ok {
		t.Error("found a socket of nothing")
	}
	// what comes out is a copy
	list := r.p.Sockets()
	list[0].Entity, list[0].Allowed = corner, false
	if s, _ := r.p.Find("desk-bar", "ch1"); s.Entity != bar1 || !s.Allowed {
		t.Error("the caller changed a socket")
	}
}

// A token that Home Assistant refuses is sent once, not once for each socket, and then not again for 5
// minutes, 15 minutes, an hour, an hour: each refused request counts as a failed login there.
func TestReaderWaitsLongAfterARefusedToken(t *testing.T) {
	r := newRig(t, true)
	r.p.PollOnce(bg())
	r.srv.Forget()
	t.Setenv(tokenEnv, "a-token-that-was-revoked")
	ctx, cancel := context.WithCancel(bg())
	defer cancel()
	r.clk.stop, r.clk.rounds = cancel, 5
	r.p.Run(ctx)
	want := []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour, time.Hour}
	if !slices.Equal(r.clk.pauses, want) {
		t.Fatalf("the waits after refusals were %v, want %v", r.clk.pauses, want)
	}
	if n := r.srv.Count(); n != 5 {
		t.Fatalf("%d requests with the refused token in five rounds, want one a round", n)
	}
	for _, src := range []string{"desk-bar", "server-corner", "own-plug"} {
		for _, row := range r.p.Rows(src) {
			if row.State != api.SocketStateUnknown || row.Error != "home assistant refused the token" {
				t.Errorf("%s/%s: %s (%s)", src, row.ID, row.State, row.Error)
			}
		}
	}
	if log := r.log.String(); strings.Count(log, "msg=\"plugs: home assistant refused the token") != 5 || strings.Contains(log, "revoked") || !strings.Contains(log, tokenEnv) {
		t.Errorf("log:\n%s", log)
	}
	// while the wait is on, a round asks nothing (the test's clock moved on with the fifth wait: a sixth
	// refusal starts the wait this looks at)
	r.p.PollOnce(bg())
	r.srv.Forget()
	for i := 0; i < 3; i++ {
		r.clk.add(19 * time.Minute)
		r.p.PollOnce(bg())
	}
	if r.srv.Count() != 0 {
		t.Fatalf("%d requests during the wait", r.srv.Count())
	}
	// the token is repaired (in truth: a restart); after the wait the states come back and the count starts anew
	t.Setenv(tokenEnv, hatest.Token())
	r.clk.add(4 * time.Minute)
	r.p.PollOnce(bg())
	if got := r.states("desk-bar"); got != "ch1=on, ch2=off, ch3=on" {
		t.Fatalf("%s", got)
	}
	t.Setenv(tokenEnv, "a-token-that-was-revoked")
	r.clk.pauses, r.clk.rounds = nil, 1
	ctx, cancel = context.WithCancel(bg())
	defer cancel()
	r.clk.stop = cancel
	r.p.Run(ctx)
	if !slices.Equal(r.clk.pauses, []time.Duration{5 * time.Minute}) {
		t.Errorf("after a round that worked the first wait is %v, want 5 minutes", r.clk.pauses)
	}
}

// A Home Assistant that does not answer is asked once in a round, not once for every socket with a timeout
// each; and a variable without a token makes no request at all. The round is over at the normal interval.
func TestReaderDoesNotWaitForEverySocket(t *testing.T) {
	r := newRig(t, true)
	r.srv.HangState(true)
	start := time.Now()
	wait := r.p.round(bg())
	if took := time.Since(start); took > 2*StateTimeout {
		t.Errorf("a round against a silent Home Assistant took %v", took)
	}
	if wait != DefaultInterval || r.srv.Count() != 1 {
		t.Errorf("wait %v, %d requests", wait, r.srv.Count())
	}
	if got := r.states("desk-bar") + "; " + r.states("own-plug"); got != "ch1=unknown (timeout), ch2=unknown (timeout), ch3=unknown (timeout); main=unknown (timeout)" {
		t.Errorf("%s", got)
	}
	r.srv.Honest()
	r.srv.Forget()
	t.Setenv(tokenEnv, "")
	if wait := r.p.round(bg()); wait != DefaultInterval || r.srv.Count() != 0 {
		t.Errorf("without a token: wait %v, %d requests", wait, r.srv.Count())
	}
	want := "the variable " + tokenEnv + " holds no token for Home Assistant"
	for _, row := range r.p.Rows("desk-bar") {
		if row.State != api.SocketStateUnknown || !strings.HasPrefix(row.Error, want) {
			t.Errorf("%s: %s (%s)", row.ID, row.State, row.Error)
		}
	}
	// an error status for one socket is that socket's: the others are asked
	t.Setenv(tokenEnv, hatest.Token())
	r.srv.AnswerState(500)
	r.srv.Forget()
	r.p.round(bg())
	if r.srv.Count() != 5 || r.states("desk-bar") != "ch1=unknown (http 500), ch2=unknown (http 500), ch3=unknown (http 500)" {
		t.Errorf("%d requests; %s", r.srv.Count(), r.states("desk-bar"))
	}
}

func TestReaderInterval(t *testing.T) {
	if DefaultInterval != 10*time.Second || MinInterval != 5*time.Second {
		t.Fatalf("%v %v", DefaultInterval, MinInterval)
	}
	for asked, want := range map[time.Duration]time.Duration{0: 10 * time.Second, time.Second: 5 * time.Second, 5 * time.Second: 5 * time.Second, time.Minute: time.Minute} {
		r := newRig(t, true)
		p := New(Options{HA: r.p.HA(), Sockets: testSockets(), Interval: asked, Now: r.clk.Now, Pause: r.clk.Pause})
		ctx, cancel := context.WithCancel(bg())
		r.clk.stop, r.clk.rounds = cancel, 3
		p.Run(ctx)
		cancel()
		if !slices.Equal(r.clk.pauses, []time.Duration{want, want, want}) || r.srv.Count() != 15 {
			t.Errorf("interval %v: waits %v, %d requests", asked, r.clk.pauses, r.srv.Count())
		}
	}
	// no sockets: the loop does not run and asks nothing
	r := newRig(t, true)
	empty := New(Options{HA: r.p.HA(), Switching: true})
	empty.Run(bg())
	empty.PollOnce(bg())
	if !empty.Empty() || r.srv.Count() != 0 {
		t.Errorf("%d requests for no sockets", r.srv.Count())
	}
	// a loop whose context ends stops, with the real wait
	p := New(Options{HA: r.p.HA(), Sockets: testSockets()[:1]})
	ctx, cancel := context.WithCancel(bg())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	for i := 0; i < 200 && r.srv.Count() == 0; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not stop")
	}
	if r.srv.Count() != 1 {
		t.Errorf("%d requests", r.srv.Count())
	}
}
