package agent

import (
	"context"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
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

// L17: after the watchdog's 100 % a request for the minimum was accepted at once, also with the CPU still over
// the limit.
func TestDutyRefusedWhileHot(t *testing.T) {
	r := newRig(t, fanYAML)
	ctx := context.Background()
	start := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	clock := start
	r.fan.now = func() time.Time { return clock }
	bmc := r.a.d.BMC.(*BMC)
	setCPU := func(c byte) {
		t.Helper()
		r.bmc.SetRaw(0x01, c)
		if err := bmc.refresh(ctx); err != nil {
			t.Fatal(err)
		}
	}
	duty := func(pct int) (int, map[string]any) {
		t.Helper()
		return r.do(t, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": pct})
	}
	r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "full"})
	if st, b := duty(40); st != 200 {
		t.Fatal("cool: accepted", st, b)
	}

	// the CPU is at 91 °C and the watchdog has not looked yet: nothing below 100 % is accepted
	setCPU(91)
	for i := 0; i < 8; i++ {
		st, b := duty(30)
		if st != 409 || b["code"] != "fan_too_hot" || !strings.Contains(b["error"].(string), "CPU Temp 91.0") {
			t.Fatal("hot: refused", st, b)
		}
	}
	if _, d := r.bmc.State(); d[0] != 40 {
		t.Fatal("a refused request changed the fans:", d)
	}
	if st, b := duty(100); st != 200 {
		t.Fatal("100 % is always accepted", st, b)
	}
	if st, b := duty(40); st != 409 {
		t.Fatal(st, b)
	}
	// exactly at the limit counts as too hot, one degree below does not
	setCPU(80)
	if st, b := duty(40); st != 409 || b["code"] != "fan_too_hot" {
		t.Fatal("80 °C: refused", st, b)
	}
	setCPU(79)
	if st, b := duty(40); st != 200 {
		t.Fatal("79 °C: accepted", st, b)
	}

	// the watchdog acts at 91 °C; then the CPU cools down at once: still refused for five minutes
	setCPU(91)
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatal(d)
	}
	setCPU(45)
	for _, after := range []time.Duration{0, time.Minute, FanHoldOff - time.Second} {
		clock = start.Add(after)
		st, b := duty(30)
		if st != 409 || b["code"] != "fan_watchdog_hold" {
			t.Fatal("hold-off: refused", after, st, b)
		}
	}
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatal("a refused request changed the fans:", d)
	}
	if st, b := r.do(t, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 1, "percent": 100}); st != 200 {
		t.Fatal("100 % during the hold-off", st, b)
	}
	clock = start.Add(FanHoldOff) // five minutes after the watchdog acted
	if st, b := duty(30); st != 200 {
		t.Fatal("after the hold-off, cool: accepted", st, b)
	}

	// a reading that is not a number is not "below the limit"
	bmc.mu.Lock()
	bmc.readings = nil
	bmc.mu.Unlock()
	r.fan.localTemps = func() []collect.Temp { return cores(math.NaN()) }
	if st, body := duty(35); st != 409 || body["code"] != "fan_too_hot" {
		t.Fatal("NaN: refused", st, body)
	}
	// the OS's reading counts too (no BMC reading)
	r.fan.localTemps = func() []collect.Temp { return cores(60, 93) }
	if st, body := duty(35); st != 409 || !strings.Contains(body["error"].(string), "93.0") {
		t.Fatal("OS reading 93 °C: refused", st, body)
	}
	r.fan.localTemps = func() []collect.Temp { return cores(60, 61) }
	if st, body := duty(35); st != 200 {
		t.Fatal(st, body)
	}
	// no temperature at all: nothing below 100 % is accepted (before, the watchdog undid it 30 s later)
	r.fan.localTemps = func() []collect.Temp { return nil }
	if st, body := duty(35); st != 409 || body["code"] != "fan_no_temperature" {
		t.Fatal("no temperature: refused", st, body)
	}
	if st, body := duty(100); st != 200 {
		t.Fatal("no temperature: 100 % accepted", st, body)
	}
	if st, body := r.do(t, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 1, "percent": 100}); st != 200 {
		t.Fatal(st, body)
	}
	// the watchdog's "no temperature" 100 % starts the hold-off as well (a duty set while there was a reading)
	r.fan.localTemps = func() []collect.Temp { return cores(40) }
	clock = clock.Add(time.Hour)
	if st, body := duty(35); st != 200 {
		t.Fatal(st, body)
	}
	r.fan.localTemps = func() []collect.Temp { return nil }
	for i := 0; i < 3; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatal(d)
	}
	r.fan.localTemps = func() []collect.Temp { return cores(40) }
	if st, body := duty(35); st != 409 || body["code"] != "fan_watchdog_hold" {
		t.Fatal(st, body)
	}
}

// L17 with L35's MaxCPUTemp (which leaves out a reading that is not a number): a CPU sensor that reports NaN or
// -Inf is still not "below the limit", also next to a cool sensor that is not the CPU's (code "fan_too_hot").
// With no sensor at all the request is refused as well, with the code "fan_no_temperature".
func TestDutyRefusedWhenTheCPUReadingIsUnusable(t *testing.T) {
	board := collect.Temp{Sensor: "acpitz", Current: 35}
	for name, tc := range map[string]struct {
		temps []collect.Temp
		want  int
		code  string
	}{
		"NaN only":             {cores(math.NaN()), 409, "fan_too_hot"},
		"-Inf only":            {cores(math.Inf(-1)), 409, "fan_too_hot"},
		"NaN CPU, cool board":  {append(cores(math.NaN()), board), 409, "fan_too_hot"},
		"NaN and a cool core":  {cores(math.NaN(), 40), 200, ""},
		"cool board only":      {[]collect.Temp{board}, 200, ""},
		"no temperature known": {nil, 409, "fan_no_temperature"},
	} {
		r := manualRig(t, 40)
		r.fan.localTemps = func() []collect.Temp { return tc.temps }
		st, body := r.fan.SetDuty(context.Background(), 0, 35, "test")
		if st != tc.want || (st == 409 && body["code"] != tc.code) {
			t.Errorf("%s: %d %v, want %d %s", name, st, body, tc.want, tc.code)
		}
		if _, d := r.bmc.State(); st == 409 && d[0] != 40 {
			t.Errorf("%s: a refused request changed the fans: %v", name, d)
		}
	}
}

// Review N4 (the rest of L16). The OS's temperature counts for 30 s. The BMC's own reading counted for three
// intervals and 30 s: 60 s with the default, 930 s with the longest interval the config accepts. With a BMC
// that stopped answering and no OS temperature (a VM or container that reaches the BMC over the LAN) the
// watchdog kept a manual fan speed on that old, cool value for a quarter of an hour. (The reviewer's proof.)
func TestWatchdogDoesNotRunOnAnOldBMCTemperature(t *testing.T) {
	ctx := context.Background()
	r := newRig(t, "ipmi: {enabled: true, sensor_interval_s: 300}\nfan_control: {enabled: true}\ncontrol_rate_per_min: 60\n")
	r.fan.localTemps = func() []collect.Temp { return nil } // no OS temperature on this machine
	if st, b := r.fan.SetMode(ctx, "full", "test"); st != 200 {
		t.Fatal(st, b)
	}
	if st, b := r.fan.SetDuty(ctx, 0, 30, "test"); st != 200 {
		t.Fatal(st, b)
	}
	b := r.a.d.BMC.(*BMC)
	age := func(d time.Duration) {
		b.mu.Lock()
		b.interval = 300 * time.Second // what Run builds from sensor_interval_s: 300
		b.readAt = time.Now().Add(-d)
		b.mu.Unlock()
	}
	// 50 s old: still good (within one interval a reading cannot be newer than that for long), fans stay
	age(50 * time.Second)
	for i := 0; i < 4; i++ {
		r.fan.WatchdogOnce(ctx)
	}
	if _, d := r.bmc.State(); d[0] != 30 {
		t.Fatal("a 50 s old reading was not used:", d)
	}
	// the BMC stopped answering a quarter of an hour ago: no temperature, 100 % after three checks
	age(15 * time.Minute)
	r.fan.WatchdogOnce(ctx)
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d[0] != 30 {
		t.Fatal("acted before the third check:", d)
	}
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		temp, name, ok := MaxCPUTemp(b.Readings(), nil)
		t.Fatalf("fans left at %v: the watchdog still trusts a BMC reading that is 15 minutes old (%s %.0f °C, shown=%v)", d, name, temp, ok)
	}
	// and a lower speed is not accepted on it either: "no temperature", as with none at all
	r.fan.actedAt = time.Time{} // not the hold-off: the reading's age alone
	if st, body := r.fan.SetDuty(ctx, 0, 30, "test"); st != 409 || body["code"] != "fan_no_temperature" {
		t.Fatal(st, body)
	}
	// /metrics and /fan/status still show that reading for their own, longer time (it is 15 minutes old, and
	// shown up to 15.5): only the watchdog's bound changed
	if len(b.Readings()) == 0 || len(b.FanList()) == 0 {
		t.Fatal("the reading is not shown any more")
	}
	if b.WatchdogReadings() != nil {
		t.Fatal("the watchdog still gets the old reading")
	}
	// a fresh reading: a lower speed is accepted again
	age(0)
	if st, body := r.fan.SetDuty(ctx, 0, 30, "test"); st != 200 {
		t.Fatal(st, body)
	}
}

// The bound follows the polling interval (two intervals and 10 s), is never below the OS's own 30 s and never
// above 60 s.
func TestWatchdogMaxAge(t *testing.T) {
	for interval, want := range map[time.Duration]time.Duration{
		2 * time.Second: 30 * time.Second, 10 * time.Second: 30 * time.Second, 15 * time.Second: 40 * time.Second,
		20 * time.Second: 50 * time.Second, 25 * time.Second: 60 * time.Second, 60 * time.Second: 60 * time.Second,
		300 * time.Second: 60 * time.Second,
	} {
		if got := watchdogMaxAge(interval); got != want {
			t.Errorf("interval %s: %s, want %s", interval, got, want)
		}
		b := NewBMC(nil, interval)
		b.readings = []ipmi.Reading{{Sensor: ipmi.Sensor{Name: "CPU Temp", Type: ipmi.TypeTemperature}, Value: 45}}
		b.readAt = time.Now().Add(-want + 2*time.Second)
		if b.WatchdogReadings() == nil {
			t.Errorf("interval %s: a reading %s old is not used", interval, want-2*time.Second)
		}
		b.readAt = time.Now().Add(-want - time.Second)
		if b.WatchdogReadings() != nil {
			t.Errorf("interval %s: a reading older than %s is used", interval, want)
		}
		b.readAt = time.Now().Add(time.Hour) // a clock that was set back: not "fresh for an hour"
		if b.WatchdogReadings() != nil {
			t.Errorf("interval %s: a reading from the future is used", interval)
		}
	}
	if BMCTempMaxAge != 60*time.Second || LocalTempMaxAge != 30*time.Second {
		t.Fatal(BMCTempMaxAge, LocalTempMaxAge)
	}
	var none *BMC
	if none.WatchdogReadings() != nil {
		t.Fatal("no BMC")
	}
}
