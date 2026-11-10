package agent

import (
	"context"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// fakePlug answers every request with this JSON body (a Tasmota or Shelly on the agent's network).
func fakePlug(t *testing.T, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// agentWithRelay is a running agent (fake collector) that relays these devices; get fetches a path with the
// read token and returns the status and the raw body.
func agentWithRelay(t *testing.T, relay *Relay) (get func(path string) (int, []byte)) {
	t.Helper()
	a := New(mustParse(t, ""), Tokens{Read: readTok}, Deps{Collector: agenttest.NewCollector(), GPU: agenttest.GPU{},
		Version: "test", Relay: relay})
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return func(path string) (int, []byte) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		req.Header.Set("Authorization", "Bearer "+readTok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, b
	}
}

// Audit 3, M2 (agent side): a plug on the agent's network that reports {"Power":[1e308,1e308]} made the whole
// /metrics answer fail (500), so the panel showed the machine as unreachable. Now the answer stays valid, the
// plug's impossible values are unknown and its good ones are kept.
func TestMetricsSurvivesImpossiblePlugNumbers(t *testing.T) {
	tasmota := fakePlug(t, `{"StatusSNS":{"ENERGY":{"Power":[1e308,1e308],"Voltage":230,"Current":[1e308,1e308],"Total":1e308}}}`)
	shelly := fakePlug(t, `{"apower":1e308,"voltage":229.8,"current":0.41,"aenergy":{"total":1e308}}`)
	good := fakePlug(t, `{"apower":95.5,"voltage":229.8,"current":0.41,"aenergy":{"total":12000}}`)
	relay, err := NewRelay([]map[string]any{
		{"id": "hostile-tasmota", "type": "tasmota", "url": tasmota},
		{"id": "hostile-shelly", "type": "shelly", "url": shelly, "gen": "2"},
		{"id": "desk-plug", "type": "shelly", "url": good, "gen": "2"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	relay.PollOnce(context.Background())
	st, body := agentWithRelay(t, relay)("/metrics")
	var m map[string]any
	if st != 200 || json.Unmarshal(body, &m) != nil {
		t.Fatalf("/metrics with a hostile plug: status %d, body %.200s", st, body)
	}
	rows, _ := m["power_sources"].([]any)
	if len(rows) != 3 || m["cpu"] == nil || m["memory"] == nil {
		t.Fatalf("%.400s", body)
	}
	tas, sh, ok := rows[0].(map[string]any), rows[1].(map[string]any), rows[2].(map[string]any)
	if tas["ok"] != true || tas["watts"] != nil || tas["current"] != nil || tas["energy_kwh_total"] != nil || tas["voltage"] != 230.0 {
		t.Errorf("tasmota row: %v", tas)
	}
	if sh["ok"] != true || sh["watts"] != nil || sh["energy_kwh_total"] != nil || sh["voltage"] != 229.8 || sh["current"] != 0.41 {
		t.Errorf("shelly row: %v", sh)
	}
	if ok["ok"] != true || ok["watts"] != 95.5 || ok["energy_kwh_total"] != 12.0 {
		t.Errorf("the good plug next to them: %v", ok)
	}
}

// multiSource is a power source with several readings (as a multi-outlet device has).
type multiSource struct {
	power.Defaults
	base  power.Base
	watts []float64
}

func (s *multiSource) Info() power.Base { return s.base }
func (s *multiSource) Read(context.Context, time.Duration) ([]power.Reading, error) {
	var out []power.Reading
	for _, w := range s.watts {
		// built by hand on purpose: not every source goes through power.NewReading
		out = append(out, power.Reading{SourceID: s.base.ID, Watts: &w, Voltage: &w, Current: &w, EnergyKWhTotal: &w})
	}
	return out, nil
}

// The relay adds the readings of one source: the sum is checked again, whatever each reading was.
func TestRelaySumIsChecked(t *testing.T) {
	cases := map[string]struct {
		watts []float64
		want  any
	}{
		"1e308 + 1e308 (+Inf as a float)":          {[]float64{1e308, 1e308}, nil},
		"possible values, impossible sum":          {[]float64{devices.MaxMagnitude, devices.MaxMagnitude}, nil},
		"one reading that is not a number":         {[]float64{40, math.NaN()}, nil},
		"an infinity":                              {[]float64{math.Inf(1)}, nil},
		"two outlets":                              {[]float64{40, 55.5}, 95.5},
		"a negative reading (feed-in) is a number": {[]float64{-120}, -120.0},
	}
	for name, c := range cases {
		r := &Relay{rows: map[string]map[string]any{}}
		src := relaySource{src: &multiSource{base: power.Base{ID: "strip", Type: "test"}, watts: c.watts}}
		r.sources = []relaySource{src}
		r.PollSource(context.Background(), src, time.Second)
		ps, _ := r.Rows()
		if len(ps) != 1 || ps[0]["ok"] != true || ps[0]["watts"] != c.want {
			t.Errorf("%s: %v", name, ps)
		}
		if _, err := json.Marshal(ps); err != nil {
			t.Errorf("%s: row cannot be written: %v", name, err)
		}
		if len(c.watts) == 1 && c.want == nil && (ps[0]["voltage"] != nil || ps[0]["current"] != nil || ps[0]["energy_kwh_total"] != nil) {
			t.Errorf("%s: other impossible values kept: %v", name, ps[0])
		}
	}
}
