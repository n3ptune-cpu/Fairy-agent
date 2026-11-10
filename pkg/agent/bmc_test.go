package agent

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
)

func bmcTemp(name string, v float64) ipmi.Reading {
	return ipmi.Reading{Sensor: ipmi.Sensor{Name: name, Type: ipmi.TypeTemperature}, Value: v}
}

// Audit 3, L35: a NaN reading in first place stayed "the hottest" (v > NaN is never true), so the watchdog
// compared NaN with the limit and never acted.
func TestMaxCPUTempSkipsNaN(t *testing.T) {
	nan := math.NaN()
	lbl := func(s string) *string { return &s }
	cases := []struct {
		name  string
		bmc   []ipmi.Reading
		local []collect.Temp
		want  float64
		from  string
		ok    bool
	}{
		{"audit: NaN, 95, 20", []ipmi.Reading{bmcTemp("CPU Temp", nan), bmcTemp("CPU2 Temp", 95), bmcTemp("CPU3 Temp", 20)}, nil, 95, "CPU2 Temp", true},
		{"NaN first, unlabelled sensors", []ipmi.Reading{bmcTemp("Zone 1", nan), bmcTemp("Zone 2", 95), bmcTemp("Zone 3", 20)}, nil, 95, "Zone 2", true},
		{"NaN last", []ipmi.Reading{bmcTemp("CPU Temp", 61), bmcTemp("CPU2 Temp", nan)}, nil, 61, "CPU Temp", true},
		{"NaN from the OS, value from the BMC", []ipmi.Reading{bmcTemp("CPU Temp", 88)},
			[]collect.Temp{{Sensor: "coretemp", Label: lbl("Package id 0"), Current: nan}}, 88, "CPU Temp", true},
		{"only NaN: no reading", []ipmi.Reading{bmcTemp("CPU Temp", nan)}, []collect.Temp{{Sensor: "k10temp", Current: nan}}, 0, "", false},
		{"-Inf is no reading", []ipmi.Reading{bmcTemp("CPU Temp", math.Inf(-1))}, nil, 0, "", false},
		{"the CPU's sensor is NaN: not replaced by a cooler board sensor",
			[]ipmi.Reading{bmcTemp("CPU Temp", nan), bmcTemp("System Temp", 35)}, nil, 0, "", false},
		{"+Inf is hotter than everything", []ipmi.Reading{bmcTemp("CPU Temp", 40), bmcTemp("CPU2 Temp", math.Inf(1))}, nil, math.Inf(1), "CPU2 Temp", true},
		{"nothing at all", nil, nil, 0, "", false},
	}
	for _, c := range cases {
		v, name, ok := MaxCPUTemp(c.bmc, c.local)
		if ok != c.ok || name != c.from || (ok && v != c.want) || math.IsNaN(v) {
			t.Errorf("%s: got %v %q %v, want %v %q %v", c.name, v, name, ok, c.want, c.from, c.ok)
		}
	}
}

// The watchdog itself with the audit's readings (NaN, 95, 20) while a manual fan speed is set: the fans go to
// 100 % in the first round. "No usable reading at all" is the case TestWatchdogWithoutTemperature covers.
func TestWatchdogWithNaNReading(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\n")
	r.fan.SetMode(ctx, "full", "test")
	r.fan.SetDuty(ctx, 0, 35, "test")
	if _, d := r.bmc.State(); d[0] != 35 {
		t.Fatalf("manual speed not set: %v", d)
	}
	b := r.a.d.BMC.(*BMC)
	b.mu.Lock()
	b.readings = []ipmi.Reading{bmcTemp("CPU Temp", math.NaN()), bmcTemp("CPU2 Temp", 95), bmcTemp("CPU3 Temp", 20)}
	b.mu.Unlock()
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatalf("fans must be at 100 %%: %v", d)
	}
	_, s := r.do(t, "GET", "/fan/status", readTok, nil)
	ev, _ := s["events"].([]any)
	if len(ev) == 0 {
		t.Fatal("no fan event")
	}
	last, _ := ev[len(ev)-1].(map[string]any)
	if !strings.Contains(last["action"].(string), "watchdog") || !strings.Contains(last["detail"].(string), "CPU2 Temp 95.0") {
		t.Errorf("event %v", last)
	}
}
