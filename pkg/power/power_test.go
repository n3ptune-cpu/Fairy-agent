package power

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
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
