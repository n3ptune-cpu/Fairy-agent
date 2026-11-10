package agent

import (
	"context"
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
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

// tempCollector is the fake PC with temperatures the test sets, a count of the samples taken and, when block is
// set, a Sample that does not come back until block is closed.
type tempCollector struct {
	*agenttest.Collector
	mu      sync.Mutex
	temps   []collect.Temp
	samples atomic.Int32
	block   chan struct{}
}

func (c *tempCollector) set(t []collect.Temp) { c.mu.Lock(); c.temps = t; c.mu.Unlock() }

func (c *tempCollector) Sample(ctx context.Context) collect.Sample {
	c.samples.Add(1)
	c.mu.Lock()
	block, temps := c.block, c.temps
	c.mu.Unlock()
	if block != nil {
		<-block
	}
	s := c.Collector.Sample(ctx)
	s.Temps = temps
	return s
}

// staleRig: fans set by hand to 35 %, the BMC's own readings gone, the OS's temperatures cool (45 °C) at the
// panel's last /metrics poll. The clock is the test's.
func staleRig(t *testing.T) (*rig, *tempCollector, *time.Time) {
	t.Helper()
	r := newRig(t, fanYAML)
	c := &tempCollector{Collector: agenttest.NewCollector(), temps: cores(45)}
	r.a.d.Collector = c
	clock := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	r.a.now = func() time.Time { return clock }
	ctx := context.Background()
	r.fan.SetMode(ctx, "full", "test")
	if st, b := r.fan.SetDuty(ctx, 0, 35, "test"); st != 200 {
		t.Fatal(st, b)
	}
	b := r.a.d.BMC.(*BMC)
	b.mu.Lock()
	b.readings = nil
	b.mu.Unlock()
	if st, _ := r.do(t, "GET", "/metrics", readTok, nil); st != 200 { // the panel's last poll
		t.Fatal(st)
	}
	return r, c, &clock
}

// L16: the OS's temperature from the panel's last poll must not count for ever.
func TestWatchdogStaleLocalTemperature(t *testing.T) {
	ctx := context.Background()

	// 1. The panel stops polling and the CPU gets hot: the watchdog takes its own sample and acts on it.
	r, c, clock := staleRig(t)
	c.set(cores(91))
	*clock = clock.Add(29 * time.Second)
	n := c.samples.Load()
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d[0] != 35 || c.samples.Load() != n {
		t.Fatal("a 29 s old sample is still good: no change, no new sample", d, c.samples.Load()-n)
	}
	*clock = clock.Add(2 * time.Second) // 31 s after the last poll
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatal("31 s after the last poll, CPU at 91 °C: fans left at", d)
	}
	if c.samples.Load() != n+1 {
		t.Fatal("expected exactly one fresh sample, got", c.samples.Load()-n)
	}

	// 2. The panel stops polling and the OS has no temperature any more: "no temperature" starts counting
	//    (before, the old 45 °C kept the fail-safe from ever starting).
	r, c, clock = staleRig(t)
	c.set(nil)
	*clock = clock.Add(31 * time.Second)
	for i := 0; i < 2; i++ {
		r.fan.WatchdogOnce(ctx)
		*clock = clock.Add(10 * time.Second)
		if _, d := r.bmc.State(); d[0] != 35 {
			t.Fatal("waits for three checks without a temperature", d)
		}
	}
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatal("no temperature for 30 s: fans left at", d)
	}

	// 3. The panel stops polling and the collector hangs: no reading (never the old value), so 100 % after
	//    three checks; the hung sample is not started a second time.
	r, c, clock = staleRig(t)
	r.a.tempWait = 20 * time.Millisecond
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	c.mu.Lock()
	c.block = block
	c.mu.Unlock()
	*clock = clock.Add(31 * time.Second)
	n = c.samples.Load()
	for i := 0; i < 3; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatal("collector hangs: fans left at", d)
	}
	if c.samples.Load() != n+1 {
		t.Fatal("a hung sample was started again:", c.samples.Load()-n)
	}

	// While the panel polls, the watchdog keeps using the poll's sample.
	r, c, clock = staleRig(t)
	for i := 0; i < 5; i++ {
		*clock = clock.Add(10 * time.Second)
		r.a.cacheAt = time.Time{} // /metrics caches for 250 ms of real time
		r.do(t, "GET", "/metrics", readTok, nil)
		n = c.samples.Load()
		r.fan.WatchdogOnce(ctx)
		if c.samples.Load() != n {
			t.Fatal("a fresh sample although the panel just polled")
		}
	}
	if _, d := r.bmc.State(); d[0] != 35 {
		t.Fatal(d)
	}
	if temps, at := r.a.LastLocalTemps(); len(temps) != 1 || !at.Equal(*clock) {
		t.Fatal(temps, at, *clock)
	}
}
