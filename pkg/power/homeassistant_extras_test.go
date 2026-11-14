package power

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// The optional values of a homeassistant entry: voltage_entity, current_entity, energy_entity. Each is one
// more sensor of the same plug, read with one more GET after the watts.

// The four sensors of the plug these tests read, and the member of the entry that names each.
const (
	labPower   = "sensor.lab_plug_power"
	labVoltage = "sensor.lab_plug_voltage"
	labCurrent = "sensor.lab_plug_current"
	labEnergy  = "sensor.lab_plug_energy"
)

var labExtras = []struct{ member, value, entity string }{
	{"voltage_entity", "voltage", labVoltage},
	{"current_entity", "current", labCurrent},
	{"energy_entity", "energy_kwh_total", labEnergy},
}

// What the lab plug's sensors say when a test does not say otherwise.
const labWatts, labVolts, labAmps, labKWh = 95.5, 229.8, 0.41, 12.5

// The reasons of pkg/devices' ParseHAValue that these tests name.
const (
	missUnavail = "the sensor is unavailable"
	missUnknown = "the sensor's state is unknown"
	missNumber  = "the sensor's state is not a number"
	missOld     = "the sensor's value is older than max_age_s"
	missNoTime  = "the sensor's state has no time (max_age_s is set)"
	missTotal   = "the sensor is not a total (its state_class is not total or total_increasing)"
)

// missingWords are all the reasons a value can be missing with, apart from "http <status>": the fixed texts of
// devices.ParseHAValue, of a failed request and of this package. A reason outside this list is not a fixed one.
var missingWords = map[string]bool{
	"the sensor has no state": true, missUnavail: true, missUnknown: true, missNumber: true, missTotal: true, missNoTime: true, missOld: true,
	"the sensor has no unit and is not a voltage sensor": true, "the sensor's unit is not a unit of voltage (V, mV)": true,
	"the sensor is not a voltage sensor": true, "the sensor's value is not a possible voltage (0 to 1000 V)": true,
	"the sensor has no unit and is not a current sensor": true, "the sensor's unit is not a unit of current (A, mA)": true,
	"the sensor is not a current sensor": true, "the sensor's value is not a possible current (0 to 1000 A)": true,
	"the sensor has no unit (an energy total needs kWh, Wh or MWh)": true, "the sensor's unit is not a unit of energy (kWh, Wh, MWh)": true,
	"the sensor is not an energy sensor": true, "the sensor's value is not a possible energy total (0 to 1e9 kWh)": true,
	"entity not found": true, "timeout": true, "connection failed": true, "tls verification failed": true, "request failed": true,
	"invalid JSON from device": true, "answer from device is too large (over 256 KiB)": true,
	"answer from device has too many values (over 8192)": true, "answer from device is nested too deep (over 32 levels)": true,
	haNoTimeLeft: true,
}

var missingStatus = regexp.MustCompile(`^http [1-5][0-9][0-9]$`)

func fixedMissing(reason string) bool {
	return missingWords[reason] || missingStatus.MatchString(reason)
}

// labState is a sensor's state object as GET /api/states/<entity id> answers it. class and stateClass are left
// out when empty; reported is last_reported and last_updated.
func labState(state, unit, class, stateClass string, reported time.Time) string {
	attrs := map[string]any{"unit_of_measurement": unit, "friendly_name": "Lab plug"}
	if class != "" {
		attrs["device_class"] = class
	}
	if stateClass != "" {
		attrs["state_class"] = stateClass
	}
	stamp := reported.UTC().Format("2006-01-02T15:04:05.000000+00:00")
	b, _ := json.Marshal(map[string]any{"state": state, "attributes": attrs, "last_changed": stamp, "last_reported": stamp, "last_updated": stamp})
	return string(b)
}

// labPlug stands in for a Home Assistant with the four sensors of one plug. It records every request in the
// order they arrive and every connection that is opened, and answers GET /api/states/<entity> as Home
// Assistant does (401 without the token, 404 for an entity it does not have, 405 for another method).
// answers[entity], when set, answers for that sensor instead.
type labPlug struct {
	answers map[string]func(w http.ResponseWriter, r *http.Request)

	mu    sync.Mutex
	reqs  []haRequest
	conns atomic.Int32 // connections opened
	busy  atomic.Int32 // requests being answered right now
	most  atomic.Int32 // the most at one moment
}

func (h *labPlug) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if n := h.busy.Add(1); n > h.most.Load() {
		h.most.Store(n)
	}
	defer h.busy.Add(-1)
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.reqs = append(h.reqs, haRequest{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), r.Header.Get("Accept"), len(body)})
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	entity := strings.TrimPrefix(r.URL.Path, "/api/states/")
	now := time.Now().Add(-2 * time.Second)
	usual := map[string]string{
		labPower:   labState("95.5", "W", "power", "measurement", now),
		labVoltage: labState("229.8", "V", "voltage", "measurement", now),
		labCurrent: labState("0.41", "A", "current", "measurement", now),
		labEnergy:  labState("12.5", "kWh", "energy", "total_increasing", now),
	}
	switch {
	case r.Header.Get("Authorization") != "Bearer "+fakeHAToken():
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "401: Unauthorized")
	case !strings.HasPrefix(r.URL.Path, "/api/states/"):
		http.NotFound(w, r)
	case r.Method != http.MethodGet:
		w.WriteHeader(http.StatusMethodNotAllowed)
	case h.answers[entity] != nil:
		h.answers[entity](w, r)
	case usual[entity] == "":
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Entity not found."}`)
	default:
		_, _ = io.WriteString(w, usual[entity])
	}
}

func (h *labPlug) seen() []haRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]haRequest(nil), h.reqs...)
}

// startLab runs the lab plug's Home Assistant and sets the token's variable.
func startLab(t *testing.T, answers map[string]func(w http.ResponseWriter, r *http.Request)) (*labPlug, *httptest.Server) {
	t.Helper()
	ha := &labPlug{answers: answers}
	srv := httptest.NewUnstartedServer(ha)
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			ha.conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	t.Setenv(haTokenEnv, fakeHAToken())
	return ha, srv
}

// labEntry is the plug's entry with these of the three optional members ("voltage_entity", ...), and more.
func labEntry(base string, members []string, more map[string]any) map[string]any {
	e := map[string]any{"id": "lab", "type": "homeassistant", "name": "Lab plug", "url": base, "token_env": haTokenEnv, "entity": labPower}
	for _, x := range labExtras {
		if slices.Contains(members, x.member) {
			e[x.member] = x.entity
		}
	}
	for k, v := range more {
		e[k] = v
	}
	return e
}

var allLabMembers = []string{"voltage_entity", "current_entity", "energy_entity"}

func labSource(t *testing.T, base string, members []string, more map[string]any) Partial {
	t.Helper()
	s, err := Build(labEntry(base, members, more), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	p, ok := s.(Partial)
	if !ok {
		t.Fatal("a homeassistant source is not a Partial")
	}
	return p
}

func answerText(code int, body string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, _ *http.Request) {
		if code != http.StatusOK {
			w.WriteHeader(code)
		}
		_, _ = io.WriteString(w, body)
	}
}

func show(p *float64) string {
	if p == nil {
		return "nil"
	}
	return fmt.Sprint(*p)
}

// labValues are the three optional values of a reading by their names.
func labValues(r Reading) map[string]*float64 {
	return map[string]*float64{"voltage": r.Voltage, "current": r.Current, "energy_kwh_total": r.EnergyKWhTotal}
}

var labUsual = map[string]float64{"voltage": labVolts, "current": labAmps, "energy_kwh_total": labKWh}

// What the three members may hold: the id of a sensor by the rule of `entity`, each another sensor than every
// other member of the entry names. A member that is there and empty is an error, not "not set".
func TestHomeAssistantExtrasConfig(t *testing.T) {
	good := []map[string]any{
		{"voltage_entity": labVoltage},
		{"current_entity": labCurrent},
		{"energy_entity": labEnergy},
		{"voltage_entity": labVoltage, "current_entity": labCurrent, "energy_entity": labEnergy},
		{"voltage_entity": "sensor.a", "energy_entity": "sensor.b"},
		{"current_entity": "sensor._", "energy_entity": "sensor.0"},
		{"energy_entity": "sensor.lab_plug_power_2"},                   // another id than entity's
		{"voltage_entity": "sensor.voltage_entity", "max_age_s": 900},  // an id that looks like a member's name
		{"voltage_entity": labCurrent, "current_entity": labVoltage},   // whether a sensor fits its member shows when it is read
		{"energy_entity": labEnergy, "ca_file": nil, "interval": 30.0}, // with the members every entry can have
		{"voltage_entity": "sensor." + strings.Repeat("a", 200)},       // as long as `entity` may be
		{"voltage_entity": labVoltage, "system": "pc", "name": "A plug"},
		{"current_entity": labCurrent, "include_in_total": false},
		{"energy_entity": "sensor.x1", "voltage_entity": "sensor.x2"},
		{"energy_entity": "sensor.e", "url": "https://ha.example.net:8443/"},
	}
	for _, more := range good {
		s, err := Build(labEntry("http://192.0.2.10:8123", nil, more), nil)
		if err != nil {
			t.Errorf("%v: %v", more, err)
			continue
		}
		s.Close()
	}

	const secret = "A-SECRET-IN-THE-ENTRY"
	type bad struct {
		more map[string]any
		want string
	}
	cases := map[string]bad{}
	for _, x := range labExtras {
		word := strings.TrimSuffix(x.member, "_entity")
		must := x.member + " must be the entity id of a sensor, like sensor.desk_plug_" + word + " (only sensor.* is read); leave the member out when the plug has no such sensor"
		// the rule of `entity`: a sensor's id and nothing that is not part of an id
		for name, id := range map[string]any{
			"empty": "", "null": nil, "a switch": "switch.x", "a light": "light.x", "a lock": "lock.front_door", "a binary sensor": "binary_sensor.x",
			"a number entity": "number.x", "capitals": "sensor.X", "capitals in the domain": "Sensor.x", "path traversal": "sensor.a/../b",
			"traversal to a service": "sensor.a/../../services/switch/turn_off", "traversal before the id": "../states/sensor.a",
			"an escaped slash": "sensor.a%2f..%2fb", "a query": "sensor.a?x=1", "a fragment": "sensor.a#x", "only the domain": "sensor.",
			"no domain": "lab_plug_voltage", "no dot": "sensor_lab_plug", "two dots": "sensor.a.b", "a dash": "sensor.lab-plug",
			"a space": "sensor.lab plug", "a space before": " sensor.a", "a line break after": "sensor.a\n", "a line break inside": "sensor.a\nswitch.b",
			"a switch after a sensor": "sensor.a,switch.b", "two sensors": "sensor.a sensor.b", "not ASCII": "sensor.küche", "a NUL": "sensor.a\x00",
			"the whole list": "*", "a secret": secret, "a number": 5, "true": true, "the token": fakeHAToken(),
		} {
			cases[x.member+": "+name] = bad{map[string]any{x.member: id}, must}
		}
		// a value of the wrong kind: the member is named, the value is not shown
		cases[x.member+" as a list"] = bad{map[string]any{x.member: []any{"sensor.a", "switch.b", secret}}, x.member + ": the value is of the wrong kind"}
		cases[x.member+" as a mapping"] = bad{map[string]any{x.member: map[string]any{secret: "sensor.a"}}, x.member + ": the value is of the wrong kind"}
		// the same sensor as `entity`
		cases[x.member+" is the power sensor"] = bad{map[string]any{x.member: labPower}, x.member + " names the same sensor as entity: each value has a sensor of its own"}
	}
	same := " names the same sensor as "
	for name, c := range map[string]bad{
		"voltage and current the same":   {map[string]any{"voltage_entity": "sensor.one", "current_entity": "sensor.one"}, "current_entity" + same + "voltage_entity"},
		"voltage and energy the same":    {map[string]any{"voltage_entity": "sensor.one", "energy_entity": "sensor.one"}, "energy_entity" + same + "voltage_entity"},
		"current and energy the same":    {map[string]any{"current_entity": "sensor.one", "energy_entity": "sensor.one"}, "energy_entity" + same + "current_entity"},
		"all three the same":             {map[string]any{"voltage_entity": "sensor.one", "current_entity": "sensor.one", "energy_entity": "sensor.one"}, "current_entity" + same + "voltage_entity"},
		"all four the same":              {map[string]any{"voltage_entity": labPower, "current_entity": labPower, "energy_entity": labPower}, "voltage_entity" + same + "entity"},
		"the last one is the power's":    {map[string]any{"voltage_entity": labVoltage, "current_entity": labCurrent, "energy_entity": labPower}, "energy_entity" + same + "entity"},
		"the first wrong member is said": {map[string]any{"voltage_entity": "switch.a", "current_entity": "switch.b"}, "voltage_entity must be"},
		// members this type still does not have
		"power_entity":      {map[string]any{"power_entity": labPower}, "field power_entity not found"},
		"frequency_entity":  {map[string]any{"frequency_entity": "sensor.f"}, "field frequency_entity not found"},
		"voltage_entities":  {map[string]any{"voltage_entities": []any{labVoltage}}, "field voltage_entities not found"},
		"switch_entity":     {map[string]any{"switch_entity": "switch.lab_plug"}, "field switch_entity not found"},
		"voltage":           {map[string]any{"voltage": labVoltage}, "field voltage not found"},
		"energy_entity_2":   {map[string]any{"energy_entity_2": labEnergy}, "field energy_entity_2 not found"},
		"Voltage_Entity":    {map[string]any{"Voltage_Entity": labVoltage}, "field Voltage_Entity not found"},
		"entities":          {map[string]any{"entities": map[string]any{"voltage": labVoltage}}, "field entities not found"},
		"a wrong and a new": {map[string]any{"voltage_entity": []any{secret}, "amps_entity": secret}, "field amps_entity not found (a homeassistant entry has no such member); voltage_entity: the value is of the wrong kind"},
	} {
		cases[name] = c
	}
	for name, c := range cases {
		s, err := Build(labEntry("http://192.0.2.10:8123", nil, c.more), nil)
		if err == nil {
			s.Close()
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) || !strings.HasPrefix(err.Error(), "power source lab: ") {
			t.Errorf("%s: %v (want %q, and the entry's id)", name, err, c.want)
		}
		text := err.Error()
		for _, shown := range []string{secret, fakeHAToken(), "sensor.one", "sensor.a", "switch.", labPower, labVoltage, labCurrent, labEnergy, "yaml", "unmarshal", "\n"} {
			if strings.Contains(text, shown) {
				t.Errorf("%s: the error repeats a value of the entry (%q), or is the YAML decoder's own: %v", name, shown, err)
			}
		}
	}
	// an entry without the members is the entry of before: no optional value, one address
	s, err := Build(labEntry("http://192.0.2.10:8123", nil, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ha := s.(*homeAssistant); len(ha.extras) != 0 || ha.addr != "http://192.0.2.10:8123/api/states/"+labPower {
		t.Errorf("%+v", ha)
	}
	// every address asked is put together from the checked parts only
	s, err = Build(labEntry("HTTP://192.0.2.10:8123/", allLabMembers, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	ha := s.(*homeAssistant)
	if len(ha.extras) != 3 || len(ha.extras)+1 > MaxHARequests {
		t.Fatalf("%+v", ha.extras)
	}
	for i, x := range ha.extras {
		want := labExtras[i]
		if x.member != want.member || x.value != want.value || x.entity != want.entity || x.addr != "http://192.0.2.10:8123/api/states/"+want.entity {
			t.Errorf("optional value %d: %+v", i, x)
		}
		if u, err := url.Parse(x.addr); err != nil || u.Path != "/api/states/"+want.entity || u.RawQuery != "" || u.User != nil || u.Fragment != "" {
			t.Errorf("optional value %d: the address asked is %q", i, x.addr)
		}
	}
	if len(haExtras) != MaxHARequests-1 {
		t.Errorf("%d optional values, but at most %d requests for a reading", len(haExtras), MaxHARequests)
	}
}

// One reading is one request for the watts and one for each optional value the entry has, and no other: 1
// without any, 1+n with n, never more than 4. Each is a GET of /api/states/<that sensor> with the token and
// no body. They are made one after the other, in the order watts, voltage, current, energy, on one connection.
func TestHomeAssistantRequestsPerReading(t *testing.T) {
	subsets := [][]string{nil, {"voltage_entity"}, {"current_entity"}, {"energy_entity"}, {"voltage_entity", "current_entity"},
		{"voltage_entity", "energy_entity"}, {"current_entity", "energy_entity"}, allLabMembers}
	for _, members := range subsets {
		slow := func(entity string) func(w http.ResponseWriter, r *http.Request) { // long enough for two at once to meet
			return func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(15 * time.Millisecond)
				body := map[string]string{labPower: labState("95.5", "W", "power", "measurement", time.Now()),
					labVoltage: labState("229.8", "V", "voltage", "measurement", time.Now()),
					labCurrent: labState("0.41", "A", "current", "measurement", time.Now()),
					labEnergy:  labState("12.5", "kWh", "energy", "total_increasing", time.Now())}[entity]
				_, _ = io.WriteString(w, body)
			}
		}
		ha, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labPower: slow(labPower), labVoltage: slow(labVoltage),
			labCurrent: slow(labCurrent), labEnergy: slow(labEnergy)})
		s := labSource(t, srv.URL, members, nil)
		wantURIs := []string{"/api/states/" + labPower}
		for _, x := range labExtras {
			if slices.Contains(members, x.member) {
				wantURIs = append(wantURIs, "/api/states/"+x.entity)
			}
		}
		const readings = 3
		for i := 0; i < readings; i++ {
			var rs []Reading
			var missing map[string]string
			var err error
			if i == 1 { // Read is ReadPartial without the reasons
				rs, err = s.(Source).Read(context.Background(), 5*time.Second)
			} else {
				rs, missing, err = s.ReadPartial(context.Background(), 5*time.Second)
			}
			if err != nil || len(rs) != 1 || missing != nil {
				t.Fatalf("%v, read %d: %+v %v %v", members, i, rs, missing, err)
			}
			r := rs[0]
			if r.Watts == nil || *r.Watts != labWatts || r.SourceID != "lab" || r.Name != "Lab plug" || time.Since(r.Timestamp) > time.Minute {
				t.Errorf("%v, read %d: %s", members, i, mustJSON(r))
			}
			for _, x := range labExtras {
				got := labValues(r)[x.value]
				if slices.Contains(members, x.member) {
					if got == nil || *got != labUsual[x.value] {
						t.Errorf("%v, read %d: %s is %s, want %v", members, i, x.value, show(got), labUsual[x.value])
					}
				} else if got != nil {
					t.Errorf("%v, read %d: %s is %v without %s", members, i, x.value, *got, x.member)
				}
			}
		}
		reqs := ha.seen()
		if len(reqs) != readings*(1+len(members)) || len(reqs) > readings*MaxHARequests {
			t.Errorf("%v: %d requests for %d readings, want %d each", members, len(reqs), readings, 1+len(members))
		}
		for i, q := range reqs {
			if q.method != http.MethodGet || q.uri != wantURIs[i%len(wantURIs)] || q.auth != "Bearer "+fakeHAToken() ||
				q.accept != "application/json" || q.bodyBytes != 0 {
				t.Errorf("%v, request %d: %s %s (want %s), Accept %q, %d bytes of body, token as expected: %v", members, i, q.method, q.uri,
					wantURIs[i%len(wantURIs)], q.accept, q.bodyBytes, q.auth == "Bearer "+fakeHAToken())
			}
		}
		if most := ha.most.Load(); most != 1 {
			t.Errorf("%v: %d requests were with Home Assistant at one moment, want one after the other", members, most)
		}
		if conns := ha.conns.Load(); conns != 1 {
			t.Errorf("%v: %d connections for %d requests, want the one of the first request used again", members, conns, len(reqs))
		}
	}
}

// What the three sensors answer, read through the real request: every unit and its conversion, and a sensor
// that does not fit its member.
func TestHomeAssistantExtraValuesThroughTheRequest(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		member, body string
		want         float64
		reason       string
	}{
		"volts":                   {"voltage_entity", labState("231.4", "V", "voltage", "measurement", now), 231.4, ""},
		"millivolts":              {"voltage_entity", labState("231456.7", "mV", "voltage", "measurement", now), 231.457, ""},
		"volts, no class":         {"voltage_entity", labState("120", "V", "", "", now), 120, ""},
		"no unit, voltage":        {"voltage_entity", `{"state":"230","attributes":{"device_class":"voltage"}}`, 230, ""},
		"amperes":                 {"current_entity", labState("1.25", "A", "current", "measurement", now), 1.25, ""},
		"milliamperes":            {"current_entity", labState("1254.6", "mA", "current", "measurement", now), 1.255, ""},
		"no unit, current":        {"current_entity", `{"state":"3","attributes":{"device_class":"current"}}`, 3, ""},
		"kilowatt hours":          {"energy_entity", labState("1234.567", "kWh", "energy", "total_increasing", now), 1234.567, ""},
		"watt hours":              {"energy_entity", labState("1234567.8", "Wh", "energy", "total_increasing", now), 1234.568, ""},
		"megawatt hours":          {"energy_entity", labState("1.2345678", "MWh", "energy", "total", now), 1234.568, ""},
		"kWh, no state class":     {"energy_entity", labState("7", "kWh", "energy", "", now), 7, ""},
		"zero volts":              {"voltage_entity", labState("-0.0", "V", "voltage", "measurement", now), 0, ""},
		"the power as voltage":    {"voltage_entity", labState("95.5", "W", "power", "measurement", now), 0, "the sensor's unit is not a unit of voltage (V, mV)"},
		"the current as voltage":  {"voltage_entity", labState("0.41", "A", "current", "measurement", now), 0, "the sensor's unit is not a unit of voltage (V, mV)"},
		"the voltage as current":  {"current_entity", labState("229.8", "V", "voltage", "measurement", now), 0, "the sensor's unit is not a unit of current (A, mA)"},
		"the power as energy":     {"energy_entity", labState("95.5", "W", "power", "measurement", now), 0, "the sensor's unit is not a unit of energy (kWh, Wh, MWh)"},
		"kilowatts as energy":     {"energy_entity", labState("0.0955", "kW", "power", "measurement", now), 0, "the sensor's unit is not a unit of energy (kWh, Wh, MWh)"},
		"energy today, a measure": {"energy_entity", labState("1.5", "kWh", "energy", "measurement", now), 0, missTotal},
		"a battery's capacity":    {"energy_entity", labState("10", "kWh", "energy_storage", "", now), 0, "the sensor is not an energy sensor"},
		"energy without a unit":   {"energy_entity", `{"state":"12","attributes":{"device_class":"energy"}}`, 0, "the sensor has no unit (an energy total needs kWh, Wh or MWh)"},
		"1500 V":                  {"voltage_entity", labState("1500", "V", "voltage", "measurement", now), 0, "the sensor's value is not a possible voltage (0 to 1000 V)"},
		"negative current":        {"current_entity", labState("-0.2", "A", "current", "measurement", now), 0, "the sensor's value is not a possible current (0 to 1000 A)"},
		"negative energy":         {"energy_entity", labState("-1", "kWh", "energy", "total", now), 0, "the sensor's value is not a possible energy total (0 to 1e9 kWh)"},
	} {
		var entity, value string
		for _, x := range labExtras {
			if x.member == c.member {
				entity, value = x.entity, x.value
			}
		}
		ha, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){entity: answerText(200, c.body)})
		rs, missing, err := labSource(t, srv.URL, []string{c.member}, nil).ReadPartial(context.Background(), 5*time.Second)
		if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != labWatts {
			t.Errorf("%s: the watts: %s %v", name, mustJSON(rs), err)
			continue
		}
		got := labValues(rs[0])[value]
		if c.reason != "" {
			if got != nil || len(missing) != 1 || missing[value] != c.reason || !fixedMissing(c.reason) {
				t.Errorf("%s: want no %s because %q, got %s %v", name, value, c.reason, show(got), missing)
			}
		} else if got == nil || *got != c.want || missing != nil {
			t.Errorf("%s: want %s %v, got %s %v", name, value, c.want, show(got), missing)
		}
		for other, p := range labValues(rs[0]) {
			if other != value && p != nil {
				t.Errorf("%s: %s is %v, but only %s is asked for", name, other, *p, c.member)
			}
		}
		if n := len(ha.seen()); n != 2 {
			t.Errorf("%s: %d requests, want 2", name, n)
		}
	}
}

// A sensor of an optional value that fails, in whatever way, never takes the watts away: the reading is the
// reading, the value is not in it, its reason is under its name, and the other optional values are read as if
// nothing had happened. No answer is followed anywhere, and every sensor is asked exactly once.
func TestHomeAssistantExtraFailureIsIsolated(t *testing.T) {
	var elsewhereHits atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		elsewhereHits.Add(1)
		_, _ = io.WriteString(w, labState("111", "V", "voltage", "measurement", time.Now()))
	}))
	defer elsewhere.Close()
	now := time.Now()
	good := labState("7", "V", "voltage", "measurement", now) // a body that would be a value if it were read
	head := `{"state":"7","attributes":{"unit_of_measurement":"V",`
	failures := map[string]struct {
		answer func(w http.ResponseWriter, r *http.Request)
		want   string // "": whatever fixed reason the kind gives
	}{
		"unavailable":           {answerText(200, labState("unavailable", "V", "", "", now)), missUnavail},
		"unknown":               {answerText(200, labState("unknown", "V", "", "", now)), missUnknown},
		"not a number":          {answerText(200, labState("on", "V", "", "", now)), missNumber},
		"no state":              {answerText(200, `{}`), "the sensor has no state"},
		"null":                  {answerText(200, `null`), "the sensor has no state"},
		"a unit of nothing":     {answerText(200, labState("7", "°C", "", "", now)), ""},
		"reported an hour ago":  {answerText(200, labState("unavailable", "V", "", "", now.Add(-time.Hour))), missUnavail},
		"404":                   {answerText(404, `{"message":"Entity not found."}`), "entity not found"},
		"400":                   {answerText(400, good), "http 400"},
		"405":                   {answerText(405, good), "http 405"},
		"429":                   {answerText(429, good), "http 429"},
		"500":                   {answerText(500, good), "http 500"},
		"503 while it restarts": {answerText(503, good), "http 503"},
		"302 to another server": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
		}, "http 302"},
		"307 to another server": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusTemporaryRedirect)
		}, "http 307"},
		"302 to a service call": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/services/switch/turn_off", http.StatusFound)
		}, "http 302"},
		"not JSON":                 {answerText(200, `<html>`), "invalid JSON from device"},
		"a list of states":         {answerText(200, `[`+good+`]`), "invalid JSON from device"},
		"300 KiB in one attribute": {answerText(200, head+`"friendly_name":"`+strings.Repeat("a", 300<<10)+`"}}`), "answer from device is too large (over 256 KiB)"},
		"9000 values":              {answerText(200, head+`"x":[`+strings.TrimSuffix(strings.Repeat("0,", 9000), ",")+`]}}`), "answer from device has too many values (over 8192)"},
		"40 levels":                {answerText(200, head+`"x":`+chainOf(`{"":`, "0", "}", 40)+`}}`), "answer from device is nested too deep (over 32 levels)"},
		"connection cut": {func(w http.ResponseWriter, _ *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		}, "connection failed"},
	}
	for _, failing := range labExtras {
		for name, f := range failures {
			name = failing.member + ", " + name
			ha, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){failing.entity: f.answer})
			s := labSource(t, srv.URL, allLabMembers, nil)
			rs, missing, err := s.ReadPartial(context.Background(), 5*time.Second)
			if err != nil || len(rs) != 1 || rs[0].Watts == nil || *rs[0].Watts != labWatts {
				t.Errorf("%s: the watts are gone: %s %v", name, mustJSON(rs), err)
				continue
			}
			if Refused(err) {
				t.Errorf("%s: a refusal", name)
			}
			reason := missing[failing.value]
			if len(missing) != 1 || !fixedMissing(reason) || f.want != "" && reason != f.want {
				t.Errorf("%s: missing is %v, want only %s with %q", name, missing, failing.value, f.want)
			}
			for value, p := range labValues(rs[0]) {
				switch {
				case value == failing.value && p != nil:
					t.Errorf("%s: %s is %v", name, value, *p)
				case value != failing.value && (p == nil || *p != labUsual[value]):
					t.Errorf("%s: %s is %s, want %v: the failure of %s reached it", name, value, show(p), labUsual[value], failing.member)
				}
			}
			// Every sensor is asked once, in order. The one exception is not this source's: a request that got no
			// answer at all because its kept connection was cut is sent once more by Go's HTTP client.
			lines := requestLines(ha.seen())
			if strings.HasSuffix(name, "connection cut") {
				if i := slices.Index(lines, "GET /api/states/"+failing.entity); i >= 0 && i+1 < len(lines) && lines[i+1] == lines[i] {
					lines = slices.Delete(lines, i, i+1)
				}
			}
			if !slices.Equal(lines, []string{"GET /api/states/" + labPower, "GET /api/states/" + labVoltage,
				"GET /api/states/" + labCurrent, "GET /api/states/" + labEnergy}) {
				t.Errorf("%s: the requests were %v", name, requestLines(ha.seen()))
			}
			// the same reading through Read: the reading without the reasons
			if rs, err := s.(Source).Read(context.Background(), 5*time.Second); err != nil || len(rs) != 1 || *rs[0].Watts != labWatts ||
				labValues(rs[0])[failing.value] != nil {
				t.Errorf("%s, through Read: %s %v", name, mustJSON(rs), err)
			}
			srv.CloseClientConnections()
		}
	}
	if n := elsewhereHits.Load(); n != 0 {
		t.Errorf("a redirect was followed: %d requests reached the other server", n)
	}

	// all three fail, each in its own way: three reasons, and the watts
	_, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labVoltage: failures["unavailable"].answer,
		labCurrent: failures["500"].answer, labEnergy: failures["404"].answer})
	rs, missing, err := labSource(t, srv.URL, allLabMembers, nil).ReadPartial(context.Background(), 5*time.Second)
	want := map[string]string{"voltage": missUnavail, "current": "http 500", "energy_kwh_total": "entity not found"}
	if err != nil || len(rs) != 1 || *rs[0].Watts != labWatts || rs[0].Voltage != nil || rs[0].Current != nil || rs[0].EnergyKWhTotal != nil ||
		!maps.Equal(missing, want) {
		t.Errorf("all three fail: %s %v %v", mustJSON(rs), missing, err)
	}
	// a sensor Home Assistant does not have (a typing mistake in the member): 404 of the fake itself
	_, srv = startLab(t, nil)
	rs, missing, err = labSource(t, srv.URL, nil, map[string]any{"current_entity": "sensor.lab_plug_curent"}).ReadPartial(context.Background(), 5*time.Second)
	if err != nil || len(rs) != 1 || *rs[0].Watts != labWatts || !maps.Equal(missing, map[string]string{"current": "entity not found"}) {
		t.Errorf("a sensor that is not there: %s %v %v", mustJSON(rs), missing, err)
	}
}

// A 401 or 403 for an optional value is a refusal of the whole source: no reading, an error that is marked as
// a refusal (so the relay waits long before it asks again) and names the member that was asked for, and
// nothing more is asked for in that reading.
func TestHomeAssistantExtraRefusalIsTheSourcesRefusal(t *testing.T) {
	good := labState("7", "V", "voltage", "measurement", time.Now())
	for i, refusing := range labExtras {
		for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
			name := fmt.Sprintf("%s, %d", refusing.member, code)
			ha, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){refusing.entity: answerText(code, good)})
			s := labSource(t, srv.URL, allLabMembers, nil)
			rs, missing, err := s.ReadPartial(context.Background(), 5*time.Second)
			want := "home assistant refused the token (asked for " + refusing.member + ")"
			if err == nil || !Refused(err) || err.Error() != want || devices.Describe(err) != want || len(rs) != 0 || missing != nil {
				t.Errorf("%s: want the refusal %q, got %s %v %v (a refusal: %v)", name, want, mustJSON(rs), missing, err, Refused(err))
			}
			wantLines := []string{"GET /api/states/" + labPower}
			for _, x := range labExtras[:i+1] {
				wantLines = append(wantLines, "GET /api/states/"+x.entity)
			}
			if lines := requestLines(ha.seen()); !slices.Equal(lines, wantLines) {
				t.Errorf("%s: the requests were %v, want %v and nothing after the refusal", name, lines, wantLines)
			}
			if rs, err := s.(Source).Read(context.Background(), 5*time.Second); err == nil || !Refused(err) || err.Error() != want || len(rs) != 0 {
				t.Errorf("%s, through Read: %s %v", name, mustJSON(rs), err)
			}
		}
	}
	// a token Home Assistant does not know is refused with the watts: one request in the reading, the words of
	// before, and the three other sensors are never sent it
	ha, srv := startLab(t, nil)
	t.Setenv(haTokenEnv, strings.Join([]string{"another", "token"}, "-"))
	rs, missing, err := labSource(t, srv.URL, allLabMembers, nil).ReadPartial(context.Background(), 5*time.Second)
	if err == nil || !Refused(err) || err.Error() != "home assistant refused the token" || len(rs) != 0 || missing != nil {
		t.Errorf("a wrong token: %s %v %v", mustJSON(rs), missing, err)
	}
	if lines := requestLines(ha.seen()); !slices.Equal(lines, []string{"GET /api/states/" + labPower}) {
		t.Errorf("a wrong token was sent %d times in one reading: %v", len(lines), lines)
	}
}

// The watts are the source's reading: when they fail, the source fails with the watts' words, as it did
// before, whatever the other sensors would say. They are not asked: one request.
func TestHomeAssistantWattsFailureIsTheSourcesFailure(t *testing.T) {
	now := time.Now()
	for name, c := range map[string]struct {
		answer  func(w http.ResponseWriter, r *http.Request)
		want    string
		refused bool
	}{
		"unavailable":  {answerText(200, labState("unavailable", "W", "power", "", now)), "home assistant: the sensor is unavailable", false},
		"unknown":      {answerText(200, labState("unknown", "W", "power", "", now)), "home assistant: the sensor's state is unknown", false},
		"a wrong unit": {answerText(200, labState("12", "kWh", "energy", "total", now)), "home assistant: the sensor's unit is not a unit of power (W, mW, kW, MW)", false},
		"too old":      {answerText(200, labState("95.5", "W", "power", "", now.Add(-time.Hour))), "home assistant: the sensor's value is older than max_age_s", false},
		"404":          {answerText(404, ""), "entity not found", false},
		"500":          {answerText(500, ""), "http 500", false},
		"401":          {answerText(401, ""), "home assistant refused the token", true},
		"403":          {answerText(403, ""), "home assistant refused the token", true},
		"not JSON":     {answerText(200, "<html>"), "invalid JSON from device", false},
		"302 elsewhere": {func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/api/states/"+labVoltage, http.StatusFound)
		}, "http 302", false},
	} {
		ha, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labPower: c.answer})
		s := labSource(t, srv.URL, allLabMembers, map[string]any{"max_age_s": 900})
		rs, missing, err := s.ReadPartial(context.Background(), 5*time.Second)
		if err == nil || err.Error() != c.want || devices.Describe(err) != c.want || Refused(err) != c.refused || len(rs) != 0 || missing != nil {
			t.Errorf("%s: want %q, got %s %v %v (a refusal: %v)", name, c.want, mustJSON(rs), missing, err, Refused(err))
		}
		if lines := requestLines(ha.seen()); !slices.Equal(lines, []string{"GET /api/states/" + labPower}) {
			t.Errorf("%s: the requests were %v, want the one for the watts", name, lines)
		}
	}
}

// max_age_s is for each value by itself: every sensor is judged by its own time. A voltage that was last
// written an hour ago is missing next to fresh watts, and fresh values do not make old watts a reading.
func TestHomeAssistantMaxAgeIsForEachValue(t *testing.T) {
	now := time.Now()
	fresh, old := now.Add(-5*time.Minute), now.Add(-20*time.Minute)
	state := map[string]func(at time.Time) string{
		labPower:   func(at time.Time) string { return labState("95.5", "W", "power", "measurement", at) },
		labVoltage: func(at time.Time) string { return labState("229.8", "V", "voltage", "measurement", at) },
		labCurrent: func(at time.Time) string { return labState("0.41", "A", "current", "measurement", at) },
		labEnergy:  func(at time.Time) string { return labState("12.5", "kWh", "energy", "total_increasing", at) },
	}
	for _, c := range []struct {
		name    string
		oldOnes []string
		maxAge  any
		missing map[string]string
		wattsNo bool
	}{
		{"all fresh", nil, 900, nil, false},
		{"an old voltage", []string{labVoltage}, 900, map[string]string{"voltage": missOld}, false},
		{"an old current", []string{labCurrent}, 900, map[string]string{"current": missOld}, false},
		{"an old energy total", []string{labEnergy}, 900, map[string]string{"energy_kwh_total": missOld}, false},
		{"old voltage and energy", []string{labVoltage, labEnergy}, 900, map[string]string{"voltage": missOld, "energy_kwh_total": missOld}, false},
		{"all three old, the watts fresh", []string{labVoltage, labCurrent, labEnergy}, 900,
			map[string]string{"voltage": missOld, "current": missOld, "energy_kwh_total": missOld}, false},
		{"old watts, the others fresh", []string{labPower}, 900, nil, true},
		{"everything old, max_age_s not set", []string{labPower, labVoltage, labCurrent, labEnergy}, nil, nil, false},
		{"everything old, max_age_s 0", []string{labPower, labVoltage, labCurrent, labEnergy}, 0, nil, false},
		{"everything old, a longer max_age_s", []string{labPower, labVoltage, labCurrent, labEnergy}, 3600, nil, false},
	} {
		answers := map[string]func(w http.ResponseWriter, r *http.Request){}
		for entity, body := range state {
			at := fresh
			if slices.Contains(c.oldOnes, entity) {
				at = old
			}
			answers[entity] = answerText(200, body(at))
		}
		_, srv := startLab(t, answers)
		more := map[string]any{}
		if c.maxAge != nil {
			more["max_age_s"] = c.maxAge
		}
		rs, missing, err := labSource(t, srv.URL, allLabMembers, more).ReadPartial(context.Background(), 5*time.Second)
		if c.wattsNo {
			if err == nil || err.Error() != "home assistant: the sensor's value is older than max_age_s" || len(rs) != 0 || missing != nil {
				t.Errorf("%s: %s %v %v", c.name, mustJSON(rs), missing, err)
			}
			continue
		}
		if err != nil || len(rs) != 1 || *rs[0].Watts != labWatts || !maps.Equal(missing, c.missing) {
			t.Errorf("%s: %s, missing %v (want %v), %v", c.name, mustJSON(rs), missing, c.missing, err)
			continue
		}
		for value, p := range labValues(rs[0]) {
			if _, gone := c.missing[value]; gone != (p == nil) {
				t.Errorf("%s: %s is %s", c.name, value, show(p))
			}
		}
	}
	// a sensor without any time, with max_age_s: that value is missing, with its own words
	_, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){
		labEnergy: answerText(200, `{"state":"12.5","attributes":{"unit_of_measurement":"kWh"}}`)})
	rs, missing, err := labSource(t, srv.URL, allLabMembers, map[string]any{"max_age_s": 60}).ReadPartial(context.Background(), 5*time.Second)
	if err != nil || len(rs) != 1 || rs[0].Voltage == nil || rs[0].EnergyKWhTotal != nil || !maps.Equal(missing, map[string]string{"energy_kwh_total": missNoTime}) {
		t.Errorf("an energy sensor without a time: %s %v %v", mustJSON(rs), missing, err)
	}
}

// The timeout is for the whole reading. What the watts leave of it is shared: a sensor that does not answer
// is given up after its part, and the ones after it are still read. With nothing left a value is not asked for.
func TestHomeAssistantExtrasShareTheTimeout(t *testing.T) {
	hang := make(chan struct{})
	defer close(hang)
	silent := func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-hang:
		case <-r.Context().Done():
		}
	}
	read := func(s Partial, timeout time.Duration) ([]Reading, map[string]string, error, time.Duration) {
		// a deadline of the reading's own, far away: a source that does not keep its timeout fails here
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		start := time.Now()
		rs, missing, err := s.ReadPartial(ctx, timeout)
		return rs, missing, err, time.Since(start)
	}

	// the first of three does not answer: it is given up after a third of the time, the other two are read
	const timeout = 1500 * time.Millisecond
	ha, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labVoltage: silent})
	rs, missing, err, took := read(labSource(t, srv.URL, allLabMembers, nil), timeout)
	if err != nil || len(rs) != 1 || *rs[0].Watts != labWatts || rs[0].Voltage != nil || rs[0].Current == nil || *rs[0].Current != labAmps ||
		rs[0].EnergyKWhTotal == nil || *rs[0].EnergyKWhTotal != labKWh || !maps.Equal(missing, map[string]string{"voltage": "timeout"}) {
		t.Errorf("a silent voltage sensor: %s %v %v", mustJSON(rs), missing, err)
	}
	if took < timeout/3-100*time.Millisecond || took > timeout*2/3+200*time.Millisecond {
		t.Errorf("a silent voltage sensor was waited for %v of a reading's %v, want about a third", took.Round(time.Millisecond), timeout)
	}
	if n := len(ha.seen()); n != 4 {
		t.Errorf("a silent voltage sensor: %d requests", n)
	}
	srv.CloseClientConnections()

	// the second of three: it gets half of what is left then
	ha, srv = startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labCurrent: silent})
	rs, missing, err, took = read(labSource(t, srv.URL, allLabMembers, nil), timeout)
	if err != nil || len(rs) != 1 || rs[0].Voltage == nil || rs[0].Current != nil || rs[0].EnergyKWhTotal == nil ||
		!maps.Equal(missing, map[string]string{"current": "timeout"}) {
		t.Errorf("a silent current sensor: %s %v %v", mustJSON(rs), missing, err)
	}
	if took < timeout/2-150*time.Millisecond || took > timeout/2+300*time.Millisecond {
		t.Errorf("a silent current sensor was waited for %v of a reading's %v, want about half", took.Round(time.Millisecond), timeout)
	}
	srv.CloseClientConnections()

	// none of the three answers: three reasons, the watts, and the reading takes its timeout and no longer
	ha, srv = startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labVoltage: silent, labCurrent: silent, labEnergy: silent})
	rs, missing, err, took = read(labSource(t, srv.URL, allLabMembers, nil), 900*time.Millisecond)
	if err != nil || len(rs) != 1 || *rs[0].Watts != labWatts ||
		!maps.Equal(missing, map[string]string{"voltage": "timeout", "current": "timeout", "energy_kwh_total": "timeout"}) {
		t.Errorf("three silent sensors: %s %v %v", mustJSON(rs), missing, err)
	}
	if took < 700*time.Millisecond || took > 900*time.Millisecond+400*time.Millisecond {
		t.Errorf("three silent sensors: the reading with a timeout of 900 ms took %v", took.Round(time.Millisecond))
	}
	if n := len(ha.seen()); n != 4 {
		t.Errorf("three silent sensors: %d requests", n)
	}
	srv.CloseClientConnections()

	// the watts take nearly all of the time (less than haMinShare is left): the reading is the watts, and
	// nothing is asked with the rest. (A machine that is busy enough can make the watts miss the timeout: then
	// the reading is made again.)
	for try := 1; ; try++ {
		ha, srv = startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labPower: func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(time.Second - haMinShare + 20*time.Millisecond)
			_, _ = io.WriteString(w, labState("95.5", "W", "power", "measurement", time.Now()))
		}})
		rs, missing, err, took = read(labSource(t, srv.URL, allLabMembers, nil), time.Second)
		if err != nil && try < 5 {
			continue
		}
		want := map[string]string{"voltage": haNoTimeLeft, "current": haNoTimeLeft, "energy_kwh_total": haNoTimeLeft}
		if err != nil || len(rs) != 1 || *rs[0].Watts != labWatts || !maps.Equal(missing, want) || rs[0].Voltage != nil || rs[0].Current != nil ||
			rs[0].EnergyKWhTotal != nil {
			t.Errorf("slow watts: %s %v %v", mustJSON(rs), missing, err)
		}
		if lines := requestLines(ha.seen()); !slices.Equal(lines, []string{"GET /api/states/" + labPower}) {
			t.Errorf("slow watts: the requests were %v, want only the one for the watts", lines)
		}
		if took > 1500*time.Millisecond {
			t.Errorf("slow watts: the reading with a timeout of 1 s took %v", took.Round(time.Millisecond))
		}
		break
	}
	// the watts time out: the source's failure, one request
	ha, srv = startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){labPower: silent})
	rs, missing, err, took = read(labSource(t, srv.URL, allLabMembers, nil), 200*time.Millisecond)
	if err == nil || devices.Describe(err) != "timeout" || len(rs) != 0 || missing != nil || took > 5*time.Second || len(ha.seen()) != 1 {
		t.Errorf("silent watts: %s %v %v after %v, %d requests", mustJSON(rs), missing, err, took.Round(time.Millisecond), len(ha.seen()))
	}
	srv.CloseClientConnections()
}

// The part of the timeout one optional sensor is asked with: an equal part of what is left for those still to
// ask, never under 50 ms, and nothing at all when less than that is left.
func TestHomeAssistantShareOfTheTimeout(t *testing.T) {
	const ms = time.Millisecond
	if haMinShare != 50*ms {
		t.Fatalf("haMinShare is %v: AGENT.md says 50 ms", haMinShare)
	}
	for _, c := range []struct {
		left  time.Duration
		toAsk int
		share time.Duration
		ask   bool
	}{
		{9 * time.Second, 3, 3 * time.Second, true},
		{9 * time.Second, 2, 4500 * ms, true},
		{9 * time.Second, 1, 9 * time.Second, true},
		{300 * ms, 3, 100 * ms, true},
		{150 * ms, 3, 50 * ms, true},
		{149 * ms, 3, 50 * ms, true}, // a third would be under the least: the least
		{60 * ms, 3, 50 * ms, true},
		{60 * ms, 2, 50 * ms, true},
		{60 * ms, 1, 60 * ms, true},
		{50 * ms, 3, 50 * ms, true},
		{50 * ms, 1, 50 * ms, true},
		{50*ms - 1, 3, 0, false},
		{50*ms - 1, 1, 0, false},
		{ms, 1, 0, false},
		{0, 3, 0, false},
		{-ms, 1, 0, false},
		{-time.Hour, 3, 0, false},
		{time.Second, 0, 0, false}, // nothing to ask
		{time.Second, -1, 0, false},
	} {
		share, ask := haShare(c.left, c.toAsk)
		if share != c.share || ask != c.ask {
			t.Errorf("%v left for %d: %v %v, want %v %v", c.left, c.toAsk, share, ask, c.share, c.ask)
		}
		if ask && (share > c.left || share < haMinShare) {
			t.Errorf("%v left for %d: a part of %v", c.left, c.toAsk, share)
		}
	}
	// three sensors that each use up their part: together never more than was left
	for _, left := range []time.Duration{40 * ms, 50 * ms, 120 * ms, 149 * ms, 151 * ms, time.Second, 10 * time.Second} {
		rest := left
		for toAsk := 3; toAsk >= 1; toAsk-- {
			if share, ask := haShare(rest, toAsk); ask {
				rest -= share
			}
		}
		if rest < 0 {
			t.Errorf("%v left: three parts take %v more than there is", left, -rest)
		}
	}
}

// The token is in no reason of a missing value, in no error, in no log line and not on standard output or
// standard error, whatever the sensors of the optional values answer; and no reason holds anything else of an
// answer. Every reason is one of the fixed list.
func TestHomeAssistantExtrasNeverShowTheToken(t *testing.T) {
	tok := fakeHAToken()
	const marker = "TEXT-FROM-THE-ANSWER"
	leaks := func(text string) bool {
		return strings.Contains(text, tok) || strings.Contains(text, url.QueryEscape(tok)) || strings.Contains(text, "Bearer") ||
			strings.Contains(text, marker) || strings.Contains(text, "sensor.") || strings.Contains(text, "/api/")
	}
	hang := make(chan struct{})
	defer close(hang)
	echo := func(code int, format string) func(w http.ResponseWriter, r *http.Request) { // an answer that repeats the header
		return func(w http.ResponseWriter, r *http.Request) {
			if code != 200 {
				w.WriteHeader(code)
			}
			fmt.Fprintf(w, format, r.Header.Get("Authorization")+" "+marker)
		}
	}
	answers := map[string]func(w http.ResponseWriter, r *http.Request){
		"401 that repeats the header":   echo(401, `{"message":"bad token %s"}`),
		"403 that repeats the header":   echo(403, `{"message":"%s"}`),
		"404 that repeats the header":   echo(404, `{"message":"%s"}`),
		"500 that repeats the header":   echo(500, `%s`),
		"not JSON, with the header":     echo(200, `<html>%s</html>`),
		"the header as the state":       echo(200, `{"state":"%s","attributes":{"unit_of_measurement":"V"}}`),
		"the header as the unit":        echo(200, `{"state":"5","attributes":{"unit_of_measurement":"%s"}}`),
		"the header as the class":       echo(200, `{"state":"5","attributes":{"unit_of_measurement":"V","device_class":"%s"}}`),
		"the header as the only class":  echo(200, `{"state":"5","attributes":{"device_class":"%s"}}`),
		"the header as the state class": echo(200, `{"state":"5","attributes":{"unit_of_measurement":"kWh","state_class":"%s"}}`),
		"the header as the time":        echo(200, `{"state":"5","attributes":{"unit_of_measurement":"V"},"last_reported":"%s"}`),
		"the header as a member's name": echo(200, `{"%s":1}`),
		"the header as the entity id":   echo(200, `{"entity_id":"sensor.%s","state":"unavailable"}`),
		"a redirect with the header in its address": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://192.0.2.1/?t="+url.QueryEscape(r.Header.Get("Authorization")), http.StatusFound)
		},
		"connection cut": func(w http.ResponseWriter, _ *http.Request) {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
		},
		"no answer in time": func(_ http.ResponseWriter, r *http.Request) {
			select {
			case <-hang:
			case <-r.Context().Done():
			}
		},
	}
	const marks = 4
	readings := 0
	out := captured(t, func() {
		fmt.Println("mark-1 standard output")
		fmt.Fprintln(os.Stderr, "mark-2 standard error")
		log.Print("mark-3 the log package")
		slog.Info("mark-4 slog")
		for name, answer := range answers {
			for _, x := range labExtras {
				name := x.member + ", " + name
				_, srv := startLab(t, map[string]func(w http.ResponseWriter, r *http.Request){x.entity: answer})
				s := labSource(t, srv.URL, allLabMembers, map[string]any{"max_age_s": 60})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				rs, missing, err := s.ReadPartial(ctx, 600*time.Millisecond)
				cancel()
				readings++
				refusal := strings.HasPrefix(name, x.member+", 401") || strings.HasPrefix(name, x.member+", 403")
				switch {
				case refusal:
					if err == nil || !Refused(err) || len(rs) != 0 || missing != nil {
						t.Errorf("%s: %s %v %v", name, mustJSON(rs), missing, err)
					}
				case err != nil || len(rs) != 1 || *rs[0].Watts != labWatts || len(missing) != 1 || !fixedMissing(missing[x.value]):
					t.Errorf("%s: %s %v %v", name, mustJSON(rs), missing, err)
				}
				shown := mustJSON(rs) + mustJSON(missing) + fmt.Sprintf(" %+v %#v", missing, missing)
				if err != nil {
					shown += fmt.Sprintf(" %s %+v %#v %s", err.Error(), err, err, devices.Describe(err))
					for e := err; e != nil; e = unwrap(e) {
						if _, ok := e.(*url.Error); ok {
							t.Errorf("%s: a *url.Error is inside the returned error", name)
						}
					}
				}
				if leaks(shown) {
					t.Errorf("%s: the reading, its reasons or its error show the token, the header or a text of the answer: %s", name, shown)
				}
				srv.CloseClientConnections()
			}
		}
	})
	if readings != len(answers)*len(labExtras) {
		t.Fatalf("%d readings", readings)
	}
	if leaks(out) {
		t.Errorf("the token, the header or a text of an answer was printed or logged:\n%s", out)
	}
	if n := strings.Count(out, "\n"); n != marks {
		t.Errorf("reading the optional values wrote %d lines to standard output and standard error, want none:\n%s", n-marks, out)
	}
	// what the source says about itself with the three members: its config and its line for the config check
	t.Setenv(haTokenEnv, tok)
	s := labSource(t, "http://192.0.2.10:8123", allLabMembers, nil)
	about := mustJSON(s.(Source).Info()) + fmt.Sprintf("%+v %#v", s.(Checker).Check(), s)
	if strings.Contains(about, tok) || strings.Contains(about, "Bearer") {
		t.Errorf("the source's own description shows the token: %s", about)
	}
	for reason := range missingWords {
		if len(reason) > 80 || strings.ContainsAny(reason, "\"{}[]%\n") || strings.Contains(reason, "sensor.") {
			t.Errorf("not a short plain text: %q", reason)
		}
	}
}

// All requests of one reading carry the token the variable held when the reading began, and the source keeps
// no copy for the next one. Without a token nothing is sent to any of the sensors.
func TestHomeAssistantExtrasCarryTheReadingsToken(t *testing.T) {
	first, second := fakeHAToken(), strings.Join([]string{"another", "made", "up", "token"}, "-")
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization")+" "+r.URL.Path)
		mu.Unlock()
		body := map[string]string{"/api/states/" + labPower: labState("95.5", "W", "power", "", time.Now()),
			"/api/states/" + labVoltage: labState("229.8", "V", "voltage", "", time.Now()),
			"/api/states/" + labCurrent: labState("0.41", "A", "current", "", time.Now()),
			"/api/states/" + labEnergy:  labState("12.5", "kWh", "energy", "total", time.Now())}[r.URL.Path]
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	tlsSrv := httptest.NewTLSServer(srv.Config.Handler)
	defer tlsSrv.Close()
	ca := filepath.Join(t.TempDir(), "ha.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tlsSrv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(haTokenEnv, first)
	sources := []Partial{labSource(t, srv.URL, allLabMembers, nil), labSource(t, tlsSrv.URL, allLabMembers, map[string]any{"ca_file": ca})}
	var want []string
	for _, tok := range []string{first, second, first} {
		t.Setenv(haTokenEnv, tok)
		for _, s := range sources {
			rs, missing, err := s.ReadPartial(context.Background(), 5*time.Second)
			if err != nil || len(rs) != 1 || missing != nil || rs[0].Voltage == nil || rs[0].Current == nil || rs[0].EnergyKWhTotal == nil {
				t.Fatalf("%s %v %v", mustJSON(rs), missing, err)
			}
			for _, entity := range []string{labPower, labVoltage, labCurrent, labEnergy} {
				want = append(want, "Bearer "+tok+" /api/states/"+entity)
			}
		}
	}
	for _, broken := range []string{"", "two words", first + "\n"} {
		t.Setenv(haTokenEnv, broken)
		for _, s := range sources {
			if rs, missing, err := s.ReadPartial(context.Background(), 5*time.Second); err == nil || len(rs) != 0 || missing != nil ||
				!strings.Contains(err.Error(), haTokenEnv) || strings.Contains(err.Error(), "two words") {
				t.Errorf("a reading without a usable token: %s %v %v", mustJSON(rs), missing, err)
			}
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if !slices.Equal(seen, want) {
		t.Errorf("%d requests, want %d, each with the token of its reading and in the order watts, voltage, current, energy (request by request, as expected: %v)",
			len(seen), len(want), func() (same []bool) {
				for i := range max(len(seen), len(want)) {
					same = append(same, i < len(seen) && i < len(want) && seen[i] == want[i])
				}
				return same
			}())
	}
}

// With an https url every request of a reading is made with the checked certificate: a server that cannot
// show it is sent none of them.
func TestHomeAssistantExtrasHTTPS(t *testing.T) {
	ha := &labPlug{}
	srv := httptest.NewTLSServer(ha)
	defer srv.Close()
	t.Setenv(haTokenEnv, fakeHAToken())
	ca := filepath.Join(t.TempDir(), "ha.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	rs, missing, err := labSource(t, srv.URL, allLabMembers, nil).ReadPartial(context.Background(), 3*time.Second)
	if err == nil || len(rs) != 0 || missing != nil || devices.Describe(err) != "tls verification failed" || len(ha.seen()) != 0 {
		t.Errorf("an unknown certificate: %s %v %v, %d requests", mustJSON(rs), missing, err, len(ha.seen()))
	}
	s := labSource(t, srv.URL, allLabMembers, map[string]any{"ca_file": ca})
	rs, missing, err = s.ReadPartial(context.Background(), 3*time.Second)
	if err != nil || len(rs) != 1 || missing != nil || *rs[0].Watts != labWatts || *rs[0].Voltage != labVolts || *rs[0].Current != labAmps ||
		*rs[0].EnergyKWhTotal != labKWh {
		t.Fatalf("with the ca_file: %s %v %v", mustJSON(rs), missing, err)
	}
	if lines := requestLines(ha.seen()); len(lines) != 4 {
		t.Errorf("%v", lines)
	}
	if s.(*homeAssistant).tr == nil {
		t.Error("an https source has a transport of its own")
	}
}

// The config check's line names the sensors of the optional values after the power sensor, each with its word.
func TestHomeAssistantCheckNamesTheExtraSensors(t *testing.T) {
	t.Setenv(haTokenEnv, fakeHAToken())
	for also, members := range map[string][]string{
		"":                      nil,
		"voltage " + labVoltage: {"voltage_entity"},
		"current " + labCurrent: {"current_entity"},
		"energy " + labEnergy:   {"energy_entity"},
		"voltage " + labVoltage + ", energy " + labEnergy:                             {"energy_entity", "voltage_entity"},
		"voltage " + labVoltage + ", current " + labCurrent + ", energy " + labEnergy: allLabMembers,
	} {
		s := labSource(t, "https://ha.example.net:8443/", members, nil)
		want := Check{ID: "lab", Type: "homeassistant", Scheme: "https", Host: "ha.example.net:8443", Reads: labPower, Also: also,
			SecretEnv: haTokenEnv, SecretSet: true}
		if got := s.(Checker).Check(); got != want {
			t.Errorf("%v: %+v", members, got)
		}
	}
}

// Only homeassistant is a Partial: the reading of every other type is made as it was.
func TestOnlyHomeAssistantIsPartial(t *testing.T) {
	for _, raw := range []map[string]any{{"id": "p", "type": "tasmota", "url": "http://192.0.2.1"}, {"id": "p", "type": "shelly", "url": "http://192.0.2.1"},
		{"id": "p", "type": "redfish", "url": "https://192.0.2.1", "username": "u", "password_env": "X"}} {
		s, err := Build(raw, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := s.(Partial); ok {
			t.Errorf("%v is a Partial", raw["type"])
		}
		s.Close()
	}
}
