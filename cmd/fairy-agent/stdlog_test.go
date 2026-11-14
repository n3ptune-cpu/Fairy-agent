package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// repeatingHost stands in for a device, or for something between the agent and the device, that sends every
// request back after its answer: the answer is complete (its Content-Length is the JSON's), and the request
// line and the header lines follow it on the same connection, which stays open. Go's HTTP client finds those
// bytes on a connection it keeps and writes them to the log package's standard logger ("Unsolicited response
// received on idle HTTP channel starting with ..."): the Authorization header, or the address with a
// password in it.
type repeatingHost struct {
	answers map[string]string          // the path asked -> the JSON answered
	repeats func(r *http.Request) bool // after which answers the request is sent back

	mu   sync.Mutex
	sent []string // what was sent back
}

func (h *repeatingHost) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, known := h.answers[r.URL.Path]
	if !known {
		http.NotFound(w, r)
		return
	}
	if !h.repeats(r) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
		return
	}
	request, _ := httputil.DumpRequest(r, false)
	c, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	h.mu.Lock()
	h.sent = append(h.sent, string(request))
	h.mu.Unlock()
	// one write: the answer and what follows it arrive together, so the client has the extra bytes when it has
	// read the answer
	_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s%s", len(body), body, request)
	go func() { // until the client hangs up
		_, _ = io.Copy(io.Discard, c)
		c.Close()
	}()
}

func (h *repeatingHost) sentBack() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Join(h.sent, "")
}

// agentLog sets the agent's log up as serve does (setupLogging, into a file) and returns how to read it.
func agentLog(t *testing.T) func() string {
	t.Helper()
	oldSlog, oldOut, oldFlags := slog.Default(), log.Writer(), log.Flags()
	path := filepath.Join(t.TempDir(), "logs", "agent.log")
	closer, err := setupLogging(&agent.Config{LogFile: path}, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		slog.SetDefault(oldSlog)
		log.SetOutput(oldOut)
		log.SetFlags(oldFlags)
		closer.Close()
	})
	return func() string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

// S1 of the review of 0.9.0's Home Assistant values, found with the real agent: a host that sends a request's
// header lines back after its answer got the token into the agent's log, through a line that Go's HTTP client
// writes by itself. With the log set up as the agent sets it up, and Go's real client, the log now has fixed
// words for it: for a homeassistant source with the watts alone and with the optional values, and for a
// source of another type (a Tasmota plug has its password in the address). The reading itself is not
// disturbed, and the agent's other lines are in the log as before.
func TestNoHostCanPutASecretIntoTheLog(t *testing.T) {
	secret := strings.Join([]string{"made", "up", "marker", "token"}, "-")
	const tokenEnv, passwordEnv = "STDLOG_TEST_HA_TOKEN", "STDLOG_TEST_PLUG_PW"
	t.Setenv(tokenEnv, secret)
	t.Setenv(passwordEnv, secret)
	state := func(state, unit, class, stateClass string) string {
		return fmt.Sprintf(`{"state":%q,"attributes":{"unit_of_measurement":%q,"device_class":%q,"state_class":%q}}`, state, unit, class, stateClass)
	}
	answers := map[string]string{
		"/api/states/sensor.lab_plug_power":   state("95.5", "W", "power", "measurement"),
		"/api/states/sensor.lab_plug_voltage": state("229.8", "V", "voltage", "measurement"),
		"/api/states/sensor.lab_plug_current": state("0.41", "A", "current", "measurement"),
		"/api/states/sensor.lab_plug_energy":  state("12.5", "kWh", "energy", "total_increasing"),
		"/cm":                                 `{"StatusSNS":{"Time":"2026-01-01T00:00:00","ENERGY":{"Total":12.5,"Power":95.5,"Voltage":230,"Current":0.41}}}`,
	}
	always := func(*http.Request) bool { return true }
	afterTheLast := func(r *http.Request) bool { return strings.HasSuffix(r.URL.Path, "_energy") }
	ha := map[string]any{"id": "lab-plug", "type": "homeassistant", "token_env": tokenEnv, "entity": "sensor.lab_plug_power"}
	withExtras := map[string]any{"voltage_entity": "sensor.lab_plug_voltage", "current_entity": "sensor.lab_plug_current",
		"energy_entity": "sensor.lab_plug_energy"}

	for _, c := range []struct {
		name    string
		entry   map[string]any
		more    map[string]any
		repeats func(*http.Request) bool
		all     bool // every value of the reading must be there (no request can meet another one's extra bytes)
	}{
		{"homeassistant, the watts alone", ha, nil, always, true},
		{"homeassistant with the optional values, after the last answer", ha, withExtras, afterTheLast, true},
		// here a request may be sent on the connection that still holds the bytes after the answer before:
		// such a value is missing in the reading ("connection failed"), and the log has nothing of it either
		{"homeassistant with the optional values, after every answer", ha, withExtras, always, false},
		{"tasmota with a password", map[string]any{"id": "lab-plug", "type": "tasmota", "password_env": passwordEnv}, nil, always, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			readLog := agentLog(t)
			host := &repeatingHost{answers: answers, repeats: c.repeats}
			srv := httptest.NewServer(host)
			defer srv.Close()
			entry := map[string]any{"url": srv.URL}
			for _, m := range []map[string]any{c.entry, c.more} {
				for k, v := range m {
					entry[k] = v
				}
			}
			src, err := power.Build(entry, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer src.Close()

			slog.Info("fairy-agent listening", "version", "dev", "listen", "127.0.0.1:18200")
			rs, err := src.Read(context.Background(), 30*time.Second)
			if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != 95.5 {
				t.Fatalf("the reading: %+v %v", rs, err)
			}
			if c.all && c.more != nil && (rs[0].Voltage == nil || rs[0].Current == nil || rs[0].EnergyKWhTotal == nil) {
				t.Errorf("the reading lacks a value: %+v", rs[0])
			}
			log.Print("a line of some package of Go")

			// the host did send the secret back, and Go's client has written its line about it (it writes it
			// when it finds the bytes, a moment after the reading)
			if sent := host.sentBack(); !strings.Contains(sent, secret) {
				t.Fatalf("the host sent back %q: the secret is not in it, the test proves nothing", sent)
			}
			var logged string
			for end := time.Now().Add(60 * time.Second); ; time.Sleep(5 * time.Millisecond) {
				// the fixed words, or (the guard is not there) the secret itself: that fails below
				if logged = readLog(); strings.Contains(logged, agent.StdLogUnasked) || strings.Contains(logged, secret) {
					break
				}
				if time.Now().After(end) {
					t.Fatalf("Go's client wrote nothing about the bytes after the answer (did its line change?). The log:\n%s", logged)
				}
			}
			for _, part := range []string{secret, "Bearer", "Authorization", "password", "sensor.", "/cm", "Unsolicited", "starting with"} {
				if strings.Contains(logged, part) {
					t.Errorf("the log has %q, a part of what the host sent back:\n%s", part, logged)
				}
			}
			lines := strings.Split(strings.TrimSuffix(logged, "\n"), "\n")
			var about, others []string
			for _, line := range lines {
				_, rest, _ := strings.Cut(line, " ") // after time=...
				if rest == `level=INFO msg="`+agent.StdLogUnasked+`"` {
					about = append(about, rest)
				} else {
					others = append(others, rest)
				}
			}
			want := []string{`level=INFO msg="fairy-agent listening" version=dev listen=127.0.0.1:18200`, `level=INFO msg="a line of some package of Go"`}
			if fmt.Sprint(others) != fmt.Sprint(want) {
				t.Errorf("the other lines of the log are\n%q, want\n%q", others, want)
			}
			if n := strings.Count(host.sentBack(), "HTTP/1.1\r\n"); len(about) > n {
				t.Errorf("%d lines for %d answers", len(about), n)
			}
		})
	}
}
