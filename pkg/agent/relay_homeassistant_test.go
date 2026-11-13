package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

const haTestEnv = "RELAY_TEST_HA_TOKEN"

// fakeHAToken is a made-up token, put together when the test runs: no text in this file looks like a credential.
func fakeHAToken() string { return strings.Join([]string{"fake", "ha", "token", "for", "tests"}, "-") }

// fakeHA is a Home Assistant on the agent's network with these sensors (entity id -> state object). It answers
// only GET /api/states/<entity> with the right token and records every request line.
type fakeHA struct {
	states map[string]string
	mu     sync.Mutex
	lines  []string
}

func (h *fakeHA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	h.lines = append(h.lines, r.Method+" "+r.URL.RequestURI())
	h.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	body, known := h.states[strings.TrimPrefix(r.URL.Path, "/api/states/")]
	switch {
	case r.Header.Get("Authorization") != "Bearer "+fakeHAToken():
		w.WriteHeader(http.StatusUnauthorized)
	case r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/api/states/"):
		w.WriteHeader(http.StatusMethodNotAllowed)
	case !known:
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Entity not found."}`)
	default:
		_, _ = io.WriteString(w, body)
	}
}

func (h *fakeHA) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.lines...)
}

// A Home Assistant plug in the agent's power_sources is a row of /metrics like every relayed plug: the same
// members, type "homeassistant", the watts in W. A sensor that has no reading is a row with ok false and fixed
// words. The token, its variable and Home Assistant's address are in no row and nowhere else in the answer.
func TestMetricsRelaysHomeAssistantPlugs(t *testing.T) {
	ha := &fakeHA{states: map[string]string{
		"sensor.desk_plug_power":  `{"entity_id":"sensor.desk_plug_power","state":"41.7","attributes":{"unit_of_measurement":"W","device_class":"power","friendly_name":"Desk plug Power"},"last_updated":"2026-01-01T12:00:00+00:00"}`,
		"sensor.rack_plug_power":  `{"state":"0.2345","attributes":{"unit_of_measurement":"kW","device_class":"power"}}`,
		"sensor.attic_plug_power": `{"state":"unavailable","attributes":{"unit_of_measurement":"W","device_class":"power"}}`,
		"sensor.desk_plug_energy": `{"state":"12.5","attributes":{"unit_of_measurement":"kWh","device_class":"energy"}}`,
	}}
	srv := httptest.NewServer(ha)
	defer srv.Close()
	t.Setenv(haTestEnv, fakeHAToken())
	t.Setenv("RELAY_TEST_HA_WRONG", strings.Join([]string{"not", "the", "token"}, "-"))
	shelly := fakePlug(t, `{"apower":95.5,"voltage":229.8,"current":0.41,"aenergy":{"total":12000}}`)

	// through config.yaml, as the owner writes it
	cfg := mustParse(t, `power_sources:
  - {id: desk-plug, type: homeassistant, name: "Desk plug", url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.desk_plug_power, system_hint: self}
  - {id: rack-plug, type: homeassistant, url: "`+srv.URL+`/", token_env: `+haTestEnv+`, entity: sensor.rack_plug_power, max_age_s: 0, interval: 30}
  - {id: attic-plug, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.attic_plug_power}
  - {id: wrong-sensor, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.desk_plug_energy}
  - {id: renamed, type: homeassistant, url: "`+srv.URL+`", token_env: `+haTestEnv+`, entity: sensor.gone_plug_power}
  - {id: refused, type: homeassistant, url: "`+srv.URL+`", token_env: RELAY_TEST_HA_WRONG, entity: sensor.desk_plug_power}
  - {id: no-token, type: homeassistant, url: "`+srv.URL+`", token_env: RELAY_TEST_HA_NOT_SET, entity: sensor.desk_plug_power}
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
	if len(rows) != 8 {
		t.Fatalf("%d rows: %.600s", len(rows), body)
	}
	row := func(i int) map[string]any { r, _ := rows[i].(map[string]any); return r }
	keys := func(r map[string]any) []string {
		var ks []string
		for k := range r {
			ks = append(ks, k)
		}
		slices.Sort(ks)
		return ks
	}
	plain := keys(row(7)) // the Shelly's row: what every relayed plug has
	for i, want := range []struct {
		id, name string
		ok       bool
		watts    any
		hint     any
		errText  any
	}{
		{"desk-plug", "Desk plug", true, 41.7, "self", nil},
		{"rack-plug", "rack-plug", true, 234.5, nil, nil},
		{"attic-plug", "attic-plug", false, nil, nil, "home assistant: the sensor is unavailable"},
		{"wrong-sensor", "wrong-sensor", false, nil, nil, "home assistant: the sensor's unit is not a unit of power (W, mW, kW, MW)"},
		{"renamed", "renamed", false, nil, nil, "entity not found"},
		{"refused", "refused", false, nil, nil, "home assistant refused the token"},
		{"no-token", "no-token", false, nil, nil, "power source no-token: env var RELAY_TEST_HA_NOT_SET is missing or shorter than 1 chars"},
	} {
		r := row(i)
		if r["id"] != want.id || r["name"] != want.name || r["type"] != "homeassistant" || r["ok"] != want.ok || r["watts"] != want.watts ||
			r["system_hint"] != want.hint || r["error"] != want.errText || r["voltage"] != nil || r["current"] != nil || r["energy_kwh_total"] != nil {
			t.Errorf("row %d: %v", i, r)
		}
		if got := keys(r); !slices.Equal(got, plain) {
			t.Errorf("row %d has the members %v, a Shelly's row %v", i, got, plain)
		}
	}
	if r := row(7); r["type"] != "shelly" || r["ok"] != true || r["watts"] != 95.5 {
		t.Errorf("the Shelly next to them: %v", r)
	}
	text := string(body)
	for what, s := range map[string]string{"the token": fakeHAToken(), "the header": "Bearer", "the variable's name": haTestEnv,
		"Home Assistant's address": strings.TrimPrefix(srv.URL, "http://"), "the request's path": "/api/states", "an entity id": "sensor."} {
		if strings.Contains(text, s) {
			t.Errorf("/metrics shows %s", what)
		}
	}
	// what Home Assistant was sent: one GET for each source that has a token, each for its own sensor
	lines := ha.seen()
	slices.Sort(lines)
	want := []string{"GET /api/states/sensor.attic_plug_power", "GET /api/states/sensor.desk_plug_energy", "GET /api/states/sensor.desk_plug_power",
		"GET /api/states/sensor.desk_plug_power", "GET /api/states/sensor.gone_plug_power", "GET /api/states/sensor.rack_plug_power"}
	if !slices.Equal(lines, want) {
		t.Errorf("Home Assistant was sent %v", lines)
	}

	// the config check's facts: the Home Assistant sources only, without a secret
	checks := relay.Checks()
	if len(checks) != 7 || checks[0] != (power.Check{ID: "desk-plug", Type: "homeassistant", Scheme: "http", Host: strings.TrimPrefix(srv.URL, "http://"),
		Reads: "sensor.desk_plug_power", SecretEnv: haTestEnv, SecretSet: true}) || checks[6].SecretSet || checks[6].SecretEnv != "RELAY_TEST_HA_NOT_SET" {
		t.Errorf("%+v", checks)
	}
	if (*Relay)(nil).Checks() != nil {
		t.Error("no relay, but checks")
	}
}

// What the agent refuses to start with: an entry that could ask Home Assistant for anything but a sensor.
func TestRelayRefusesAHomeAssistantEntryThatIsNotASensor(t *testing.T) {
	for y, want := range map[string]string{
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', token_env: HA_TOKEN, entity: switch.desk_plug}":                  "entity must be",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', token_env: HA_TOKEN, entity: light.x}":                           "entity must be",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', token_env: HA_TOKEN, entity: sensor.X}":                          "entity must be",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', token_env: HA_TOKEN, entity: sensor.a/../b}":                     "entity must be",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123/api/services', token_env: HA_TOKEN, entity: sensor.a}":             "url must be",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', entity: sensor.a}":                                               "token_env must be",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', token_env: HA_TOKEN, entity: sensor.a, max_age_s: .nan}":         "max_age_s",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', token_env: HA_TOKEN, entity: sensor.a, service: turn_off}":       "field service not found",
		"{id: p, type: homeassistant, url: 'http://192.0.2.1:8123', token_env: HA_TOKEN, entity: sensor.a, system_hint: self, x: 1}": "field x not found",
	} {
		c, err := Parse([]byte("power_sources: ["+y+"]"), "config.yaml")
		if err != nil {
			t.Fatalf("%q: %v", y, err)
		}
		if _, err := NewRelay(c.PowerSources, c.UPS); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want an error with %q", y, err, want)
		}
	}
}

// The token's variable is a secret of the env file like a plug's password: named by a member that ends in
// "_env", so it counts as in use (an old tuya entry that named the same variable does not get it dropped), it
// is loaded, and it is hidden from the programs the agent starts.
func TestHomeAssistantTokenIsLoadedFromTheEnvFile(t *testing.T) {
	const name = "RELAY_TEST_HA_FROM_FILE"
	if _, set := os.LookupEnv(name); set {
		t.Skip(name + " is set in this environment")
	}
	t.Cleanup(func() { os.Unsetenv(name) })
	dir := t.TempDir()
	env := filepath.Join(dir, "secrets.env")
	if err := os.WriteFile(env, []byte(name+"="+fakeHAToken()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Parse([]byte(`env_file: `+env+`
power_sources:
  - {id: old-plug, type: tuya, device_id: plug1, ip: 192.0.2.60, local_key_env: `+name+`}
  - {id: desk-plug, type: homeassistant, url: "http://192.0.2.10:8123", token_env: `+name+`, entity: sensor.desk_plug_power}
`), filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UnusedSecret(name) {
		t.Fatal("the variable a homeassistant entry names is taken for unused")
	}
	if notes := cfg.Ignored(); len(notes) != 1 || !strings.Contains(notes[0], "leave the line "+name+"=... in the env file: it is still in use") {
		t.Errorf("%v", notes)
	}
	if err := loadSecrets(cfg); err != nil {
		t.Fatal(err)
	}
	if os.Getenv(name) != fakeHAToken() {
		t.Error("the token was not loaded from env_file")
	}
	for _, kv := range collect.MinimalEnv() { // what ipmitool, nvidia-smi, systemctl and PowerShell are started with
		if strings.HasPrefix(kv, name+"=") || strings.Contains(kv, fakeHAToken()) {
			t.Error("a program the agent starts would be handed the token")
		}
	}
	relay, err := NewRelay(cfg.PowerSources, cfg.UPS)
	if err != nil {
		t.Fatal(err)
	}
	if checks := relay.Checks(); len(checks) != 1 || !checks[0].SecretSet || checks[0].SecretEnv != name {
		t.Errorf("%+v", checks)
	}
}
