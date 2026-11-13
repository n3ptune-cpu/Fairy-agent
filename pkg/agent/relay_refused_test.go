package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// Review of the Home Assistant source (F2): a token that Home Assistant refuses was sent again every 10 s for
// as long as the agent ran. Home Assistant counts each as a failed login and can ban the agent's address.
//
// These tests run the relay's real loop (Run) with a clock of their own: Relay.pause records how long the
// loop wants to wait and returns at once, so the waits are seen without waiting.

// scriptedHA answers GET /api/states/<entity> with the next status of its script (the last one for ever) and
// counts the requests. 200 is a reading of 41.7 W.
type scriptedHA struct {
	mu     sync.Mutex
	script []int
	served int
}

func (h *scriptedHA) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.mu.Lock()
	code := h.script[min(h.served, len(h.script)-1)]
	h.served++
	h.mu.Unlock()
	if code != http.StatusOK {
		w.WriteHeader(code)
		return
	}
	_, _ = io.WriteString(w, `{"state":"41.7","attributes":{"unit_of_measurement":"W","device_class":"power"}}`)
}

func (h *scriptedHA) requests() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.served
}

// runWithClock runs the relay's loops until stop says so. stop is asked after every reading with the wait the
// loop asked for and the time that has passed on the test's clock before that wait. It returns every wait.
func runWithClock(t *testing.T, relay *Relay, stop func(wait, passed time.Duration) bool) []time.Duration {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var waits []time.Duration
	var passed time.Duration
	relay.pause = func(_ context.Context, d time.Duration) bool {
		mu.Lock()
		defer mu.Unlock()
		if ctx.Err() != nil {
			return false
		}
		waits = append(waits, d)
		if stop(d, passed) {
			cancel()
			return false
		}
		passed += d
		return true
	}
	done := make(chan struct{})
	go func() { relay.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cancel()
		t.Fatal("the relay's loop did not come to its end")
	}
	mu.Lock()
	defer mu.Unlock()
	return slices.Clone(waits)
}

func haRelay(t *testing.T, url, more string) *Relay {
	t.Helper()
	t.Setenv(haTestEnv, fakeHAToken())
	cfg := mustParse(t, `power_sources:
  - {id: desk-plug, type: homeassistant, url: "`+url+`", token_env: `+haTestEnv+`, entity: sensor.desk_plug_power`+more+`}
`)
	relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
	if err != nil {
		t.Fatal(err)
	}
	return relay
}

// The waits after each answer: 5 minutes after the first refusal, 15 minutes after the second in a row, an hour
// after the third and after each further one, the normal interval again after the first reading that
// succeeds, and 5 minutes again for a refusal after that. One request for each reading, none in between.
func TestRelayWaitsLongAfterHomeAssistantRefusedTheToken(t *testing.T) {
	const iv = 10 * time.Second // the default interval of a homeassistant source
	script := []int{401, 401, 403, 401, 403, 200, 200, 401, 200, 200}
	want := []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour, time.Hour, iv, iv, 5 * time.Minute, iv, iv}
	ha := &scriptedHA{script: script}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	relay := haRelay(t, srv.URL, "")

	n := 0
	waits := runWithClock(t, relay, func(time.Duration, time.Duration) bool {
		// the row while the source waits: the refusal's text, and a reading again after the first success
		ps, _ := relay.Rows()
		code := script[n]
		n++
		switch {
		case len(ps) != 1:
			t.Errorf("after answer %d: %d rows", n, len(ps))
		case code == 200 && (ps[0]["ok"] != true || ps[0]["watts"] != 41.7 || ps[0]["error"] != nil):
			t.Errorf("after answer %d (200): %v", n, ps[0])
		case code != 200 && (ps[0]["ok"] != false || ps[0]["watts"] != nil || ps[0]["error"] != "home assistant refused the token"):
			t.Errorf("after answer %d (%d): %v", n, code, ps[0])
		}
		return n == len(script)
	})
	if !slices.Equal(waits, want) {
		t.Errorf("the waits were %v, want %v", waits, want)
	}
	if got := ha.requests(); got != len(script) {
		t.Errorf("%d requests for %d readings", got, len(script))
	}
}

// How many requests a revoked token makes: 3 in the first hour (at once, after 5 and after 20 minutes), 5 in
// the first three hours and 26 in the first day, one an hour from the third on, where the interval of 10 s
// made 360 an hour. And a restart of the agent starts the waits anew: the count of refusals is in the running
// agent's memory only, so the agent that was restarted reads at once and, refused again, waits 5 minutes.
func TestRelayRequestsWhileTheTokenStaysRefused(t *testing.T) {
	ha := &scriptedHA{script: []int{401}}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	relay := haRelay(t, srv.URL, "")
	inFirstHour, inThreeHours := 0, 0
	waits := runWithClock(t, relay, func(wait, passed time.Duration) bool {
		if passed < time.Hour {
			inFirstHour++
		}
		if passed < 3*time.Hour {
			inThreeHours++
		}
		return passed+wait >= 24*time.Hour // the next reading would be after the first day
	})
	if inFirstHour != 3 || inThreeHours != 5 || len(waits) != 26 || ha.requests() != 26 {
		t.Errorf("%d readings in the first hour (want 3), %d in three hours (want 5), %d in a day (want 26), %d requests (want 26)",
			inFirstHour, inThreeHours, len(waits), ha.requests())
	}
	if last := waits[len(waits)-1]; last != time.Hour || slices.Max(waits) != time.Hour {
		t.Errorf("after a day of refusals the source waits %v (the longest wait was %v), want an hour", last, slices.Max(waits))
	}

	// The agent is restarted (a relay is built anew, as Run does) while Home Assistant still refuses: one request
	// at once, then 5 minutes and 15 minutes again, not the hour the agent before it had come to.
	relay = haRelay(t, srv.URL, "")
	before, n := ha.requests(), 0
	waits = runWithClock(t, relay, func(_, passed time.Duration) bool {
		if n++; n == 1 && (passed != 0 || ha.requests() != before+1) {
			t.Errorf("after a restart the first reading was not made at once: %v passed, %d requests", passed, ha.requests()-before)
		}
		return n == 3
	})
	if want := []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour}; !slices.Equal(waits, want) {
		t.Errorf("after a restart the waits were %v, want %v", waits, want)
	}
	// Restarted with a token that works (the owner stored a new one and restarted): read at once, and at the
	// normal interval from then on.
	good := &scriptedHA{script: []int{200}}
	srvGood := httptest.NewServer(good)
	defer srvGood.Close()
	relay = haRelay(t, srvGood.URL, "")
	n = 0
	waits = runWithClock(t, relay, func(_, passed time.Duration) bool {
		if n++; n == 1 && (passed != 0 || good.requests() != 1) {
			t.Errorf("restarted with a working token, the first reading was not made at once: %v passed, %d requests", passed, good.requests())
		}
		return n == 2
	})
	if want := []time.Duration{10 * time.Second, 10 * time.Second}; !slices.Equal(waits, want) {
		t.Errorf("restarted with a working token the waits were %v, want %v", waits, want)
	}
	if ps, _ := relay.Rows(); len(ps) != 1 || ps[0]["ok"] != true || ps[0]["watts"] != 41.7 {
		t.Errorf("restarted with a working token: %v", ps)
	}

	// a longer interval of the entry is still the least a source waits; after a refusal it waits the same 5 and 15 minutes
	ha = &scriptedHA{script: []int{401, 401, 200, 200}}
	srv2 := httptest.NewServer(ha)
	defer srv2.Close()
	relay = haRelay(t, srv2.URL, ", interval: 300")
	n = 0
	waits = runWithClock(t, relay, func(time.Duration, time.Duration) bool { n++; return n == 4 })
	if want := []time.Duration{5 * time.Minute, 15 * time.Minute, 5 * time.Minute, 5 * time.Minute}; !slices.Equal(waits, want) {
		t.Errorf("with interval: 300 the waits were %v, want %v", waits, want)
	}
}

// Every failure that is not a refusal of the token is asked again at the normal interval, as before: also
// between two refusals, where it does not start the count of refusals again (only a reading that succeeds does).
func TestRelayOtherFailuresOfHomeAssistantKeepTheInterval(t *testing.T) {
	const iv = 10 * time.Second
	script := []int{404, 500, 429, 302, 401, 502, 401, 200, 401}
	want := []time.Duration{iv, iv, iv, iv, 5 * time.Minute, iv, 15 * time.Minute, iv, 5 * time.Minute}
	ha := &scriptedHA{script: script}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	relay := haRelay(t, srv.URL, "")
	n := 0
	waits := runWithClock(t, relay, func(time.Duration, time.Duration) bool { n++; return n == len(script) })
	if !slices.Equal(waits, want) {
		t.Errorf("the waits were %v, want %v", waits, want)
	}
}

// refusingSource is a source whose Read returns the errors of its script, one after the other.
type refusingSource struct {
	power.Defaults
	mu     sync.Mutex
	script []error
	reads  int
}

func (s *refusingSource) Info() power.Base { return power.Base{ID: "strip", Type: "test"} }
func (s *refusingSource) Read(context.Context, time.Duration) ([]power.Reading, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.script[min(s.reads, len(s.script)-1)]
	s.reads++
	if err != nil {
		return nil, err
	}
	w := 40.0
	return []power.Reading{{SourceID: "strip", Watts: &w}}, nil
}

type saysRefused bool

func (e saysRefused) Error() string { return "the device says no" }
func (e saysRefused) Refused() bool { return bool(e) }

// The long wait is for an error that says so itself (a method Refused() that returns true, also when it is
// wrapped), which is how another source type can opt in. No other type does today: a Shelly that answers 401
// is asked again at its interval, as before.
func TestRelayTimingOfOtherSourcesIsUnchanged(t *testing.T) {
	const iv = 2 * time.Second // power.Defaults
	src := &refusingSource{script: []error{
		errors.New("http 401"), saysRefused(false), fmt.Errorf("read: %w", saysRefused(false)), nil,
		saysRefused(true), fmt.Errorf("read: %w", saysRefused(true)), nil, nil}}
	want := []time.Duration{iv, iv, iv, iv, 5 * time.Minute, 15 * time.Minute, iv, iv}
	relay := &Relay{rows: map[string]map[string]any{}, sources: []relaySource{{src: src}}}
	n := 0
	waits := runWithClock(t, relay, func(time.Duration, time.Duration) bool { n++; return n == len(want) })
	if !slices.Equal(waits, want) {
		t.Errorf("a source that opts in: the waits were %v, want %v", waits, want)
	}

	var hits int
	var mu sync.Mutex
	plug := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer plug.Close()
	for _, entry := range []string{
		`{id: p, type: shelly, url: "` + plug.URL + `", gen: "2"}`,
		`{id: p, type: tasmota, url: "` + plug.URL + `"}`,
		`{id: p, type: redfish, url: "` + plug.URL + `", username: u, password_env: ` + haTestEnv + `}`,
	} {
		t.Setenv(haTestEnv, fakeHAToken())
		cfg := mustParse(t, "power_sources:\n  - "+entry+"\n")
		relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
		if err != nil {
			t.Fatal(err)
		}
		normal := interval(relay.sources[0].src)
		n := 0
		waits := runWithClock(t, relay, func(time.Duration, time.Duration) bool { n++; return n == 4 })
		if !slices.Equal(waits, []time.Duration{normal, normal, normal, normal}) || normal > time.Minute {
			t.Errorf("%s answered 401 four times: the waits were %v, its interval is %v", entry, waits, normal)
		}
		ps, _ := relay.Rows()
		if len(ps) != 1 || ps[0]["ok"] != false || ps[0]["error"] == "home assistant refused the token" {
			t.Errorf("%s: %v", entry, ps)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if hits < 12 {
		t.Errorf("the plugs were asked %d times for 12 readings", hits)
	}
}

// The real wait between two readings: as long as asked, and over at once when the agent stops.
func TestRelayPauseEndsWithTheAgent(t *testing.T) {
	start := time.Now()
	if !pauseFor(context.Background(), 30*time.Millisecond) || time.Since(start) < 30*time.Millisecond {
		t.Errorf("a pause of 30 ms was over after %v", time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	start = time.Now()
	if pauseFor(ctx, 15*time.Minute) || time.Since(start) > 10*time.Second {
		t.Errorf("a pause of 15 minutes did not end when the agent stopped (%v)", time.Since(start))
	}
	// the relay as the agent runs it (no clock of the test's): Run ends with its context, also while a source
	// waits out a refusal
	ha := &scriptedHA{script: []int{401}}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	relay := haRelay(t, srv.URL, "")
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { relay.Run(ctx); close(done) }()
	for deadline := time.Now().Add(10 * time.Second); ha.requests() == 0 && time.Now().Before(deadline); {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not end while a source waited out a refusal")
	}
	if got := ha.requests(); got != 1 {
		t.Errorf("%d requests in the first moments after a refusal, want 1", got)
	}
}
