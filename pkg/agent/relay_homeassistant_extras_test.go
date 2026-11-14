package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// The optional values of a homeassistant entry (voltage_entity, current_entity, energy_entity) in the agent's
// row of /metrics, and what a panel that was built before them makes of that row.

// plugHA is a Home Assistant with the sensors of a few plugs: entity id -> the answer (a state object, or a
// status when the text is three digits). It answers only GET /api/states/<entity> with the right token and
// records every request line.
type plugHA struct {
	mu      sync.Mutex
	answers map[string]string
	lines   []string
}

func (h *plugHA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.lines = append(h.lines, r.Method+" "+r.URL.RequestURI())
	answer, known := h.answers[strings.TrimPrefix(r.URL.Path, "/api/states/")]
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	var code int
	switch {
	case r.Header.Get("Authorization") != "Bearer "+fakeHAToken():
		w.WriteHeader(http.StatusUnauthorized)
	case r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/states/"):
		w.WriteHeader(http.StatusMethodNotAllowed)
	case !known:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Entity not found."}`)
	case len(answer) == 3 && func() bool { _, err := fmt.Sscanf(answer, "%d", &code); return err == nil }():
		w.WriteHeader(code)
	default:
		_, _ = io.WriteString(w, answer)
	}
}

func (h *plugHA) set(entity, answer string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.answers[entity] = answer
}

func (h *plugHA) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

func sensorState(state, unit, class, stateClass string) string {
	attrs := map[string]any{"unit_of_measurement": unit, "device_class": class}
	if stateClass != "" {
		attrs["state_class"] = stateClass
	}
	b, _ := json.Marshal(map[string]any{"state": state, "attributes": attrs})
	return string(b)
}

func rowKeys(r map[string]any) []string {
	var ks []string
	for k := range r {
		ks = append(ks, k)
	}
	slices.Sort(ks)
	return ks
}

// A Home Assistant plug with the optional members is still one row of /metrics with the members every relayed
// plug's row has: the volts, amperes and energy total are in "voltage", "current" and "energy_kwh_total", where
// a Shelly's are. A value whose sensor gave nothing is null, the row stays ok with its watts, and only then
// the row has one more member, "missing", with a fixed text for each such value. A refusal for one of the
// sensors and a failure of the watts are failed rows as before. No row shows the token, an address or an
// entity id.
func TestMetricsRelaysTheExtraValuesOfAHomeAssistantPlug(t *testing.T) {
	ha := &plugHA{answers: map[string]string{
		"sensor.lab_plug_power":   sensorState("95.5", "W", "power", "measurement"),
		"sensor.lab_plug_voltage": sensorState("229800", "mV", "voltage", "measurement"),
		"sensor.lab_plug_current": sensorState("410", "mA", "current", "measurement"),
		"sensor.lab_plug_energy":  sensorState("12500", "Wh", "energy", "total_increasing"),

		"sensor.shed_plug_power":   sensorState("7", "W", "power", "measurement"),
		"sensor.shed_plug_voltage": sensorState("unavailable", "V", "voltage", "measurement"),
		"sensor.shed_plug_current": sensorState("0.03", "A", "current", "measurement"),
		// sensor.shed_plug_energy: Home Assistant has no such sensor

		"sensor.attic_plug_power":   sensorState("unavailable", "W", "power", "measurement"),
		"sensor.attic_plug_voltage": sensorState("231", "V", "voltage", "measurement"),

		"sensor.yard_plug_power":   sensorState("3", "W", "power", "measurement"),
		"sensor.yard_plug_voltage": sensorState("230", "V", "voltage", "measurement"),
		"sensor.yard_plug_current": "401", // the token's user may not read this one
		"sensor.yard_plug_energy":  sensorState("1", "kWh", "energy", "total"),

		"sensor.hall_plug_power":  sensorState("11", "W", "power", "measurement"),
		"sensor.hall_plug_energy": sensorState("11", "W", "power", "measurement"), // a power sensor named as the energy
	}}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	t.Setenv(haTestEnv, fakeHAToken())
	shelly := fakePlug(t, `{"apower":95.5,"voltage":229.8,"current":0.41,"aenergy":{"total":12000}}`)
	cfg := mustParse(t, `power_sources:
  - {id: lab-plug, type: homeassistant, name: "Lab plug", url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.lab_plug_power,
     voltage_entity: sensor.lab_plug_voltage, current_entity: sensor.lab_plug_current, energy_entity: sensor.lab_plug_energy, system_hint: self}
  - {id: shed-plug, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.shed_plug_power,
     voltage_entity: sensor.shed_plug_voltage, current_entity: sensor.shed_plug_current, energy_entity: sensor.shed_plug_energy}
  - {id: attic-plug, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.attic_plug_power, voltage_entity: sensor.attic_plug_voltage}
  - {id: yard-plug, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.yard_plug_power,
     voltage_entity: sensor.yard_plug_voltage, current_entity: sensor.yard_plug_current, energy_entity: sensor.yard_plug_energy}
  - {id: hall-plug, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.hall_plug_power, energy_entity: sensor.hall_plug_energy}
  - {id: shelly-1, type: shelly, url: "`+shelly+`", gen: "2"}
`)
	relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
	if err != nil {
		t.Fatal(err)
	}
	relay.PollOnce(context.Background())
	st, body := agentWithRelay(t, relay)("/metrics")
	var m map[string]any
	if st != 200 || json.Unmarshal(body, &m) != nil {
		t.Fatalf("/metrics: status %d, body %.300s", st, body)
	}
	rows, _ := m["power_sources"].([]any)
	if len(rows) != 6 {
		t.Fatalf("%d rows: %.900s", len(rows), body)
	}
	row := func(i int) map[string]any { r, _ := rows[i].(map[string]any); return r }
	plain := rowKeys(row(5)) // the Shelly's row: what every relayed plug has
	withMissing := append(slices.Clone(plain), "missing")
	slices.Sort(withMissing)
	for i, want := range []struct {
		id      string
		ok      bool
		watts   any
		voltage any
		current any
		energy  any
		errText any
		missing map[string]any // nil: the row has no such member
	}{
		{"lab-plug", true, 95.5, 229.8, 0.41, 12.5, nil, nil},
		{"shed-plug", true, 7.0, nil, 0.03, nil, nil, map[string]any{"voltage": "the sensor is unavailable", "energy_kwh_total": "entity not found"}},
		{"attic-plug", false, nil, nil, nil, nil, "home assistant: the sensor is unavailable", nil},
		{"yard-plug", false, nil, nil, nil, nil, "home assistant refused the token (asked for current_entity)", nil},
		{"hall-plug", true, 11.0, nil, nil, nil, nil, map[string]any{"energy_kwh_total": "the sensor's unit is not a unit of energy (kWh, Wh, MWh)"}},
	} {
		r := row(i)
		if r["id"] != want.id || r["type"] != "homeassistant" || r["ok"] != want.ok || r["watts"] != want.watts || r["voltage"] != want.voltage ||
			r["current"] != want.current || r["energy_kwh_total"] != want.energy || r["error"] != want.errText {
			t.Errorf("row %d: %v", i, r)
		}
		got, has := r["missing"]
		switch {
		case want.missing == nil && has:
			t.Errorf("row %d has a member \"missing\" (%v) and nothing is missing", i, got)
		case want.missing == nil:
			if keys := rowKeys(r); !slices.Equal(keys, plain) {
				t.Errorf("row %d has the members %v, a Shelly's row %v", i, keys, plain)
			}
		default:
			gotMap, _ := got.(map[string]any)
			if len(gotMap) != len(want.missing) {
				t.Errorf("row %d: missing is %v, want %v", i, got, want.missing)
			}
			for k, v := range want.missing {
				if gotMap[k] != v {
					t.Errorf("row %d: missing[%s] is %v, want %v", i, k, gotMap[k], v)
				}
			}
			if keys := rowKeys(r); !slices.Equal(keys, withMissing) {
				t.Errorf("row %d has the members %v, want a Shelly's and \"missing\": %v", i, keys, withMissing)
			}
		}
	}
	if r := row(5); r["type"] != "shelly" || r["ok"] != true || r["watts"] != 95.5 || r["voltage"] != 229.8 || r["current"] != 0.41 || r["energy_kwh_total"] != 12.0 {
		t.Errorf("the Shelly next to them: %v", r)
	}
	text := string(body)
	for what, s := range map[string]string{"the token": fakeHAToken(), "the header": "Bearer", "the variable's name": haTestEnv,
		"Home Assistant's address": strings.TrimPrefix(srv.URL, "http://"), "the request's path": "/api/states", "an entity id": "sensor.",
		"a member of the entry": "_entity\""} {
		if strings.Contains(text, s) {
			t.Errorf("/metrics shows %s", what)
		}
	}
	// what Home Assistant was sent: the watts of each plug, then its optional sensors, until a refusal
	lines := ha.seen()
	slices.Sort(lines)
	want := []string{
		"GET /api/states/sensor.attic_plug_power", // the watts failed: the voltage was not asked for
		"GET /api/states/sensor.hall_plug_energy", "GET /api/states/sensor.hall_plug_power",
		"GET /api/states/sensor.lab_plug_current", "GET /api/states/sensor.lab_plug_energy", "GET /api/states/sensor.lab_plug_power", "GET /api/states/sensor.lab_plug_voltage",
		"GET /api/states/sensor.shed_plug_current", "GET /api/states/sensor.shed_plug_energy", "GET /api/states/sensor.shed_plug_power", "GET /api/states/sensor.shed_plug_voltage",
		"GET /api/states/sensor.yard_plug_current", "GET /api/states/sensor.yard_plug_power", "GET /api/states/sensor.yard_plug_voltage", // refused: the energy was not asked for
	}
	if !slices.Equal(lines, want) {
		t.Errorf("Home Assistant was sent %v", lines)
	}
	// the config check's facts name the sensors
	checks := relay.Checks()
	if len(checks) != 5 || checks[0].Reads != "sensor.lab_plug_power" ||
		checks[0].Also != "voltage sensor.lab_plug_voltage, current sensor.lab_plug_current, energy sensor.lab_plug_energy" ||
		checks[2].Also != "voltage sensor.attic_plug_voltage" || checks[4].Also != "energy sensor.hall_plug_energy" {
		t.Errorf("%+v", checks)
	}

	// the sensor that was missing is back: the row has its value and no member "missing" any more
	ha.set("sensor.shed_plug_voltage", sensorState("228.5", "V", "voltage", "measurement"))
	ha.set("sensor.shed_plug_energy", sensorState("0.5", "kWh", "energy", "total_increasing"))
	relay.PollOnce(context.Background())
	ps, _ := relay.Rows()
	if r := ps[1]; r["ok"] != true || r["watts"] != 7.0 || r["voltage"] != 228.5 || r["current"] != 0.03 || r["energy_kwh_total"] != 0.5 ||
		!slices.Equal(rowKeys(r), plain) {
		t.Errorf("after the sensors came back: %v", r)
	}
	// and the other way round: a value that was there is null again, never the one of the reading before
	ha.set("sensor.lab_plug_current", "500")
	relay.PollOnce(context.Background())
	ps, _ = relay.Rows()
	if r := ps[0]; r["ok"] != true || r["watts"] != 95.5 || r["voltage"] != 229.8 || r["current"] != nil || r["energy_kwh_total"] != 12.5 ||
		fmt.Sprint(r["missing"]) != "map[current:http 500]" {
		t.Errorf("after the current sensor failed: %v", r)
	}
}

// A refusal for one of the optional sensors is a refusal of the source: the relay waits 5 minutes, 15 minutes
// and then an hour before it asks again, as after a refusal for the watts, and each such reading sends the
// token twice (the watts, which Home Assistant answers, and the sensor it refuses), not once more for the
// sensors after it.
func TestRelayWaitsLongAfterARefusalForAnExtraValue(t *testing.T) {
	const iv = 10 * time.Second
	ha := &plugHA{answers: map[string]string{
		"sensor.desk_plug_power":   sensorState("41.7", "W", "power", "measurement"),
		"sensor.desk_plug_voltage": "403",
		"sensor.desk_plug_energy":  sensorState("3", "kWh", "energy", "total"),
	}}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	relay := haRelay(t, srv.URL, ", voltage_entity: sensor.desk_plug_voltage, energy_entity: sensor.desk_plug_energy")
	n := 0
	waits := runWithClock(t, relay, func(time.Duration, time.Duration) bool {
		ps, _ := relay.Rows()
		n++
		refusedNow := n <= 4
		switch {
		case len(ps) != 1:
			t.Errorf("after reading %d: %d rows", n, len(ps))
		case refusedNow && (ps[0]["ok"] != false || ps[0]["watts"] != nil || ps[0]["energy_kwh_total"] != nil ||
			ps[0]["error"] != "home assistant refused the token (asked for voltage_entity)"):
			t.Errorf("after reading %d (refused): %v", n, ps[0])
		case !refusedNow && (ps[0]["ok"] != true || ps[0]["watts"] != 41.7 || ps[0]["voltage"] != 230.0 || ps[0]["energy_kwh_total"] != 3.0 || ps[0]["error"] != nil):
			t.Errorf("after reading %d: %v", n, ps[0])
		}
		if n == 4 { // the user may read the sensor again
			ha.set("sensor.desk_plug_voltage", sensorState("230", "V", "voltage", "measurement"))
		}
		return n == 6
	})
	if want := []time.Duration{5 * time.Minute, 15 * time.Minute, time.Hour, time.Hour, iv, iv}; !slices.Equal(waits, want) {
		t.Errorf("the waits were %v, want %v", waits, want)
	}
	lines := ha.seen()
	var want []string
	for i := 0; i < 4; i++ {
		want = append(want, "GET /api/states/sensor.desk_plug_power", "GET /api/states/sensor.desk_plug_voltage")
	}
	for i := 0; i < 2; i++ {
		want = append(want, "GET /api/states/sensor.desk_plug_power", "GET /api/states/sensor.desk_plug_voltage", "GET /api/states/sensor.desk_plug_energy")
	}
	if !slices.Equal(lines, want) {
		t.Errorf("Home Assistant was sent %d requests: %v", len(lines), lines)
	}

	// a missing value is not a refusal and not a failure: the source is read at its interval
	ha.set("sensor.desk_plug_voltage", sensorState("unavailable", "V", "voltage", "measurement"))
	relay = haRelay(t, srv.URL, ", voltage_entity: sensor.desk_plug_voltage, energy_entity: sensor.desk_plug_energy")
	n = 0
	waits = runWithClock(t, relay, func(time.Duration, time.Duration) bool { n++; return n == 3 })
	if want := []time.Duration{iv, iv, iv}; !slices.Equal(waits, want) {
		t.Errorf("with a missing value the waits were %v, want %v", waits, want)
	}
}

// partialSource is a power.Partial that says what the test tells it to.
type partialSource struct {
	power.Defaults
	readings []power.Reading
	missing  map[string]string
	err      error
	reads    int // through Read, which the relay must not use for a Partial
}

func (s *partialSource) Info() power.Base { return power.Base{ID: "p", Type: "test"} }
func (s *partialSource) Read(context.Context, time.Duration) ([]power.Reading, error) {
	s.reads++
	return s.readings, s.err
}
func (s *partialSource) ReadPartial(context.Context, time.Duration) ([]power.Reading, map[string]string, error) {
	return s.readings, s.missing, s.err
}

// The row's "missing" is there for a reading that came with reasons, and only then: not with an empty list of
// reasons, and never in a failed row.
func TestRelayRowHasMissingOnlyWithAReadingAndAReason(t *testing.T) {
	w := 5.0
	reading := []power.Reading{{Watts: &w}}
	for name, c := range map[string]struct {
		src  partialSource
		want string // the row's "missing" as text, "" for no such member
	}{
		"a reading, nothing missing":    {partialSource{readings: reading}, ""},
		"a reading, an empty list":      {partialSource{readings: reading, missing: map[string]string{}}, ""},
		"a reading, one reason":         {partialSource{readings: reading, missing: map[string]string{"voltage": "timeout"}}, `{"voltage":"timeout"}`},
		"a reading, two reasons":        {partialSource{readings: reading, missing: map[string]string{"voltage": "a", "current": "b"}}, `{"current":"b","voltage":"a"}`},
		"an error, with reasons":        {partialSource{err: fmt.Errorf("x"), missing: map[string]string{"voltage": "timeout"}}, ""},
		"no reading at all, and a list": {partialSource{missing: map[string]string{"voltage": "timeout"}}, ""},
	} {
		src := c.src
		r := &Relay{rows: map[string]map[string]any{}}
		_ = r.PollSource(context.Background(), relaySource{src: &src}, time.Second)
		row := r.rows["p"]
		got := ""
		if m, has := row["missing"]; has {
			b, _ := json.Marshal(m)
			got = string(b)
		}
		if got != c.want || src.reads != 0 {
			t.Errorf("%s: missing is %q, want %q (row %v, %d readings through Read)", name, got, c.want, row, src.reads)
		}
		if _, err := json.Marshal(row); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The row as it is on the wire, and what the panels that exist make of it.
//
// The values of the optional sensors go into members every row has had since the first relayed plug ("voltage",
// "current", "energy_kwh_total", null when unknown), so no panel has to learn a new name for them. The one new
// member is "missing", and only in a row that lacks a value.
//
// The panel does not decode an agent's answer into a struct that could refuse an unknown member. In the
// released panel (build 13, commit 45f6206 of Fairy-dashboard) and in the candidate for build 14 (69b9d8a) the
// code is the same:
//
//   - internal/poller/httpbackend.go:165-173, decodeJSON: json.Unmarshal into a map (jsonx.M), no
//     DisallowUnknownFields; getJSON (:184-226) returns that map; agentMetrics (:566) asks only for
//     "agent_version" as text and "platform" as an object;
//   - internal/poller/agents.go:205 (build 13) / :278 (candidate): jsonx.Objs(payload["power_sources"]), the
//     rows as maps (internal/jsonx/jsonx.go:127);
//   - internal/power/remote.go:98-148 (build 13) / :139-194 (candidate), remoteState: reads row["id"], "name",
//     "type", "ok", "error", "system_hint", "watts", "voltage", "current", "energy_kwh_total" by name and
//     nothing else; a number is taken only when it is a JSON number (jsonNumber, :181 / :227);
//   - internal/power/manager.go:75-88 (build 13) / :88-101 (candidate), cleanReadings: watts, volts and amperes
//     within +-1e9, the energy within +-1e12, else dropped; watts outside make the row a failed one;
//   - internal/web/static/app.js:1590 (build 13) / :1615 (candidate): the Power page's table shows
//     readings[0].voltage, .current and .energy_kwh_total in its columns Volts, Amps and kWh.
//
// panelReads below is that path, copied: a row with the new values and with "missing" is read by it as a good
// reading with all four numbers, and "missing" changes nothing.
func TestPanelsOfBuild13And14ReadTheRow(t *testing.T) {
	ha := &plugHA{answers: map[string]string{
		"sensor.lab_plug_power":   sensorState("95.5", "W", "power", "measurement"),
		"sensor.lab_plug_voltage": sensorState("229.8", "V", "voltage", "measurement"),
		"sensor.lab_plug_current": sensorState("0.41", "A", "current", "measurement"),
		"sensor.lab_plug_energy":  sensorState("12.5", "kWh", "energy", "total_increasing"),
		"sensor.shed_plug_power":  sensorState("7", "W", "power", "measurement"),
		// the shed plug's voltage sensor is not in Home Assistant, its energy total is impossible
		"sensor.shed_plug_current": sensorState("30", "mA", "current", "measurement"),
		"sensor.shed_plug_energy":  sensorState("-1", "kWh", "energy", "total"),
	}}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	t.Setenv(haTestEnv, fakeHAToken())
	cfg := mustParse(t, `power_sources:
  - {id: lab-plug, type: homeassistant, name: "Lab plug", url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.lab_plug_power,
     voltage_entity: sensor.lab_plug_voltage, current_entity: sensor.lab_plug_current, energy_entity: sensor.lab_plug_energy, system_hint: self}
  - {id: shed-plug, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.shed_plug_power,
     voltage_entity: sensor.shed_plug_voltage, current_entity: sensor.shed_plug_current, energy_entity: sensor.shed_plug_energy}
  - {id: bare-plug, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.lab_plug_power}
`)
	relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
	if err != nil {
		t.Fatal(err)
	}
	relay.PollOnce(context.Background())
	st, body := agentWithRelay(t, relay)("/metrics")
	if st != 200 {
		t.Fatalf("/metrics: status %d", st)
	}

	// the rows as text, member by member as the agent writes them
	var wire struct {
		PowerSources []json.RawMessage `json:"power_sources"`
	}
	if err := json.Unmarshal(body, &wire); err != nil || len(wire.PowerSources) != 3 {
		t.Fatalf("%v, %d rows", err, len(wire.PowerSources))
	}
	golden := []string{
		`{"current":0.41,"energy_kwh_total":12.5,"error":null,"id":"lab-plug","name":"Lab plug","ok":true,"system_hint":"self","type":"homeassistant","voltage":229.8,"watts":95.5}`,
		`{"current":0.03,"energy_kwh_total":null,"error":null,"id":"shed-plug","missing":{"energy_kwh_total":"the sensor's value is not a possible energy total (0 to 1e9 kWh)","voltage":"entity not found"},"name":"shed-plug","ok":true,"system_hint":null,"type":"homeassistant","voltage":null,"watts":7}`,
		// an entry without the optional members: the row of the released agent (v0.8.0), byte for byte
		`{"current":null,"energy_kwh_total":null,"error":null,"id":"bare-plug","name":"bare-plug","ok":true,"system_hint":null,"type":"homeassistant","voltage":null,"watts":95.5}`,
	}
	for i, want := range golden {
		if got := string(wire.PowerSources[i]); got != want {
			t.Errorf("row %d on the wire:\n got %s\nwant %s", i, got, want)
		}
	}

	// what a panel keeps of them
	kept, ok := panelReads(body)
	if !ok || len(kept) != 3 {
		t.Fatalf("the panel's reader takes the answer: %v, %d rows", ok, len(kept))
	}
	num := func(p *float64) any {
		if p == nil {
			return nil
		}
		return *p
	}
	for i, want := range []struct {
		id      string
		linked  bool
		watts   any
		voltage any
		current any
		energy  any
	}{
		{"lab-plug", true, 95.5, 229.8, 0.41, 12.5},
		{"shed-plug", false, 7.0, nil, 0.03, nil},
		{"bare-plug", false, 95.5, nil, nil, nil},
	} {
		k := kept[i]
		if k.id != want.id || k.typ != "homeassistant" || k.status != "ok" || k.errText != "" || k.linkedToAgent != want.linked ||
			num(k.watts) != want.watts || num(k.voltage) != want.voltage || num(k.current) != want.current || num(k.energy) != want.energy {
			t.Errorf("the panel's reader, row %d: %+v (watts %v, voltage %v, current %v, energy %v)", i, k, num(k.watts), num(k.voltage), num(k.current), num(k.energy))
		}
	}
	// a row with "missing" and the same row without it are the same to a panel
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	shed := m["power_sources"].([]any)[1].(map[string]any)
	if _, has := shed["missing"]; !has {
		t.Fatal("the test's row has no member \"missing\"")
	}
	delete(shed, "missing")
	without, _ := json.Marshal(m)
	if keptWithout, ok := panelReads(without); !ok || fmt.Sprintf("%+v", describe(keptWithout)) != fmt.Sprintf("%+v", describe(kept)) {
		t.Errorf("\"missing\" changes what the panel's reader keeps:\nwith    %+v\nwithout %+v", describe(kept), describe(keptWithout))
	}
	// the largest numbers the agent can send for the three values are inside what the panels accept
	// (cleanReadings: +-1e9 for volts and amperes, +-1e12 for the energy)
	if 1000 > panelMaxReading || 1e9 > panelMaxEnergyKWh {
		t.Error("the agent's ranges are wider than the panel's")
	}
}

// What follows is a copy of the panel's reader of an agent's power rows, as it is in build 13 (45f6206) and in
// the candidate for build 14 (69b9d8a) of Fairy-dashboard; the comment of TestPanelsOfBuild13And14ReadTheRow
// names the files and lines. Only what decides about a row is copied: the limits on the number of rows and on
// the length of texts are left out.

const (
	panelMaxReading   = 1e9  // internal/normalise/finite.go:18, MaxReading
	panelMaxEnergyKWh = 1e12 // internal/normalise/finite.go:28, MaxEnergyKWh
)

type panelRow struct {
	id, name, typ, status, errText  string
	linkedToAgent                   bool
	watts, voltage, current, energy *float64
}

func describe(rows []panelRow) (out []string) {
	show := func(p *float64) string {
		if p == nil {
			return "null"
		}
		return fmt.Sprint(*p)
	}
	for _, r := range rows {
		out = append(out, fmt.Sprintf("%s %s %s %s %q %v %s %s %s %s", r.id, r.name, r.typ, r.status, r.errText, r.linkedToAgent,
			show(r.watts), show(r.voltage), show(r.current), show(r.energy)))
	}
	return out
}

// panelReads is FetchAgentMetrics + UpdateRemote/remoteState + cleanReadings for one answer of /metrics.
func panelReads(body []byte) (rows []panelRow, ok bool) {
	var payload map[string]any // httpbackend.go decodeJSON: json.Unmarshal(body, v), v a *jsonx.M
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, false
	}
	_, version := payload["agent_version"].(string) // httpbackend.go agentMetrics
	_, platform := payload["platform"].(map[string]any)
	if !version || !platform {
		return nil, false
	}
	list, _ := payload["power_sources"].([]any) // jsonx.Objs
	for _, x := range list {
		row, isObj := x.(map[string]any)
		if !isObj {
			continue
		}
		jsonString := func(v any) string { // remote.go jsonString
			switch x := v.(type) {
			case nil:
				return ""
			case string:
				return x
			case float64:
				if x == math.Trunc(x) {
					return fmt.Sprintf("%d", int64(x))
				}
			}
			return fmt.Sprint(v)
		}
		jsonNumber := func(v any) *float64 { // remote.go jsonNumber
			if x, ok := v.(float64); ok {
				return &x
			}
			return nil
		}
		finite := func(v *float64, lo, hi float64) *float64 { // normalise.Finite
			if v == nil || !(*v >= lo && *v <= hi) {
				return nil
			}
			return v
		}
		rid := jsonString(row["id"])
		if rid == "" {
			continue
		}
		r := panelRow{id: rid, name: jsonString(row["name"]), typ: jsonString(row["type"])}
		if r.name == "" {
			r.name = rid
		}
		if r.typ == "" {
			r.typ = "unknown"
		}
		r.linkedToAgent = jsonString(row["system_hint"]) == "self"
		ok, _ := row["ok"].(bool)
		rowErr := jsonString(row["error"])
		if ok {
			watts, voltage, current, energy := jsonNumber(row["watts"]), jsonNumber(row["voltage"]), jsonNumber(row["current"]), jsonNumber(row["energy_kwh_total"])
			invalid := watts != nil && finite(watts, -panelMaxReading, panelMaxReading) == nil // manager.go cleanReadings
			r.watts, r.voltage, r.current = finite(watts, -panelMaxReading, panelMaxReading), finite(voltage, -panelMaxReading, panelMaxReading),
				finite(current, -panelMaxReading, panelMaxReading)
			r.energy = finite(energy, -panelMaxEnergyKWh, panelMaxEnergyKWh)
			if invalid {
				ok, rowErr = false, "the agent relayed a value that is not a possible reading"
			}
		}
		if ok {
			r.status = "ok"
		} else {
			r.status, r.watts, r.voltage, r.current, r.energy = "unreachable", nil, nil, nil, nil
			if r.errText = rowErr; r.errText == "" {
				r.errText = "error"
			}
		}
		rows = append(rows, r)
	}
	return rows, true
}
