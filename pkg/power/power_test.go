package power

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

func f(v float64) *float64 { return &v }

// Whatever a source hands over, a Reading can be written as JSON: impossible numbers become unknown (audit 3, M2).
func TestNewReadingDropsImpossibleNumbers(t *testing.T) {
	b := Base{ID: "desk", Name: "Desk", System: "pc"}
	r := NewReading(b, devices.Reading{Watts: f(math.NaN()), Voltage: f(math.Inf(1)), Current: f(1e308), EnergyKWh: f(-1e308)})
	if r.Watts != nil || r.Voltage != nil || r.Current != nil || r.EnergyKWhTotal != nil {
		t.Fatalf("%+v", r)
	}
	if _, err := json.Marshal(r); err != nil {
		t.Fatal(err)
	}
	r = NewReading(b, devices.Reading{Watts: f(95.5), Voltage: f(229.8), Current: f(0.41), EnergyKWh: f(12)})
	if *r.Watts != 95.5 || *r.Voltage != 229.8 || *r.Current != 0.41 || *r.EnergyKWhTotal != 12 || *r.SystemID != "pc" || r.SourceID != "desk" {
		t.Fatalf("%+v", r)
	}
}

// A `type: agent` source passes on what an agent reported: an impossible number is "no reading", not a value.
func TestAgentPowerSourceImpossibleNumber(t *testing.T) {
	for name, v := range map[string]float64{"1e308": 1e308, "NaN": math.NaN(), "Inf": math.Inf(1)} {
		s, err := Build(map[string]any{"id": "gpu", "type": "agent", "agent": "pc", "metric": "gpu_w"},
			func(string, string) *float64 { return &v })
		if err != nil {
			t.Fatal(err)
		}
		rs, err := s.Read(context.Background(), time.Second)
		if err != nil || len(rs) != 1 || rs[0].Watts != nil {
			t.Fatalf("%s: %+v %v", name, rs, err)
		}
		if _, err := json.Marshal(rs); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

// Audit 3, L10: the agent's BMC power source (redfish) followed a redirect to any address and scheme and read
// the JSON it found there as a power reading; to the same host name over http the BMC password went along.
func TestRedfishDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int32
	var auth atomic.Value
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		auth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte(`{"PowerControl":[{"PowerConsumedWatts":31337}]}`))
	}))
	defer elsewhere.Close()
	bmc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, elsewhere.URL+r.URL.Path, http.StatusFound)
	}))
	defer bmc.Close()
	t.Setenv("FAIRY_TEST_BMC_PASSWORD", "bmc-password")
	s, err := Build(map[string]any{"id": "bmc", "type": "redfish", "url": bmc.URL, "password_env": "FAIRY_TEST_BMC_PASSWORD",
		"verify_tls": false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	rs, err := s.Read(context.Background(), 3*time.Second)
	if err == nil || len(rs) != 0 || devices.Describe(err) != "http 302" {
		t.Fatalf("want \"http 302\", got %+v %v", rs, err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect was followed: %d requests, Authorization %q", n, auth.Load())
	}
}

// Audit 3, L35: "below 1 or above 300" is never true for NaN, so `interval: .nan` passed and became the pause
// between two polls of the device.
func TestIntervalAndScaleMustBeNumbers(t *testing.T) {
	for name, iv := range map[string]float64{"NaN": math.NaN(), "+Inf": math.Inf(1), "-Inf": math.Inf(-1), "0.5": 0.5, "301": 301} {
		for _, typ := range []map[string]any{
			{"id": "p", "type": "tasmota", "url": "http://192.0.2.1"},
			{"id": "p", "type": "shelly", "url": "http://192.0.2.1"},
			{"id": "p", "type": "nut", "host": "192.0.2.1"},
			{"id": "p", "type": "redfish", "url": "https://192.0.2.1", "password_env": "X"},
			{"id": "p", "type": "tuya", "device_id": "d", "ip": "192.0.2.1", "local_key_env": "K"},
			{"id": "p", "type": "agent", "agent": "pc"},
		} {
			typ["interval"] = iv
			if _, err := Build(typ, nil); err == nil || !strings.Contains(err.Error(), "interval must be 1-300") {
				t.Errorf("interval %s, type %v: %v", name, typ["type"], err)
			}
		}
	}
	for _, iv := range []float64{1, 2.5, 300} {
		if _, err := Build(map[string]any{"id": "p", "type": "tasmota", "url": "http://192.0.2.1", "interval": iv}, nil); err != nil {
			t.Errorf("interval %v: %v", iv, err)
		}
	}
	tuya := func(scale float64) error {
		_, err := Build(map[string]any{"id": "t", "type": "tuya", "device_id": "d", "ip": "192.0.2.1", "local_key_env": "K",
			"dps": map[string]any{"power": map[string]any{"dp": "19", "scale": scale}}}, nil)
		return err
	}
	for name, sc := range map[string]float64{"NaN": math.NaN(), "+Inf": math.Inf(1), "-Inf": math.Inf(-1)} {
		if err := tuya(sc); err == nil || !strings.Contains(err.Error(), "scale must be a number") {
			t.Errorf("scale %s: %v", name, err)
		}
	}
	for _, sc := range []float64{0, 0.1, 1, -1, 1000} { // 0 means "not set" (1), as before
		if err := tuya(sc); err != nil {
			t.Errorf("scale %v: %v", sc, err)
		}
	}
}
