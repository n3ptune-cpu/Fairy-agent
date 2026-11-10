package agent

import (
	"context"
	"math"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

const fanYAML = "ipmi: {enabled: true}\nfan_control: {enabled: true}\ncontrol_rate_per_min: 60\n"

// manualRig is a rig in mode "full" with zone 0 at pct, whose only temperatures are the given OS readings
// (the BMC's own readings are gone).
func manualRig(t *testing.T, pct int, temps ...float64) *rig {
	t.Helper()
	r := newRig(t, fanYAML)
	ctx := context.Background()
	if st, b := r.fan.SetMode(ctx, "full", "test"); st != 200 {
		t.Fatal(st, b)
	}
	if st, b := r.fan.SetDuty(ctx, 0, pct, "test"); st != 200 {
		t.Fatal(st, b)
	}
	b := r.a.d.BMC.(*BMC)
	b.mu.Lock()
	b.readings = nil
	b.mu.Unlock()
	r.fan.localTemps = func() []collect.Temp { return cores(temps...) }
	return r
}

// cores are Core Temp style readings ("coretemp Core N"), which count as CPU temperatures.
func cores(v ...float64) []collect.Temp {
	var out []collect.Temp
	for i, x := range v {
		out = append(out, collect.Temp{Sensor: "coretemp", Label: collect.P("Core " + string(rune('0'+i))), Current: x})
	}
	return out
}

// L35: a reading or a limit that is "not a number" must not blind the watchdog.
func TestWatchdogNaN(t *testing.T) {
	ctx := context.Background()
	nan := math.NaN()
	for name, temps := range map[string][]float64{"NaN first": {nan, 95, 20}, "NaN last": {95, 20, nan}, "NaN between": {20, nan, 95}} {
		r := manualRig(t, 35, temps...)
		r.fan.WatchdogOnce(ctx)
		if _, d := r.bmc.State(); d != [2]byte{100, 100} {
			t.Errorf("%s: readings %v left the fans at %v", name, temps, d)
		}
	}
	// nothing but NaN: no usable temperature, so 100 % at the latest after three checks (30 s)
	r := manualRig(t, 35, nan, nan)
	for i := 0; i < 3; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Error("only NaN readings left the fans at", d)
	}
	// a NaN next to a cool reading is ignored: the cool reading counts
	r = manualRig(t, 35, 20, nan)
	for i := 0; i < 4; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if _, d := r.bmc.State(); d[0] != 35 {
		t.Error("a cool reading followed by NaN changed the fans:", d)
	}
	// a limit that is NaN (a config check that let `.nan` through): the watchdog acts instead of never acting
	r = manualRig(t, 35, 20)
	r.fan.cfg.MaxTempC = nan
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Error("max_temp_c NaN left the fans at", d)
	}
}
