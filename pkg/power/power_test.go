package power

import (
	"context"
	"encoding/json"
	"math"
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
