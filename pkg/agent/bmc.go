package agent

import (
	"context"
	"log/slog"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
)

// BMC reads the board's sensors over IPMI in the background: the sensor list (SDR) once, then the readings every
// interval. Its readings feed /metrics (when enabled), the fan status and the fan watchdog.
type BMC struct {
	t        ipmi.Transport
	interval time.Duration

	mu       sync.Mutex
	sensors  []ipmi.Sensor
	sdrOK    bool
	readings []ipmi.Reading
	readAt   time.Time
	lastErr  string
}

// NewBMC returns a BMC reader on this transport.
func NewBMC(t ipmi.Transport, interval time.Duration) *BMC {
	return &BMC{t: t, interval: interval}
}

// Run refreshes the readings until ctx ends.
func (b *BMC) Run(ctx context.Context) {
	for ctx.Err() == nil {
		wait := b.interval
		if err := b.refresh(ctx); err != nil {
			b.mu.Lock()
			first := b.lastErr != err.Error()
			b.lastErr = err.Error()
			b.mu.Unlock()
			if first {
				slog.Warn("BMC sensors unavailable", "error", err.Error())
			}
			wait = max(wait, time.Minute)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (b *BMC) refresh(ctx context.Context) error {
	b.mu.Lock()
	ok := b.sdrOK
	b.mu.Unlock()
	if !ok {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		s, err := ipmi.ReadSDR(cctx, b.t)
		cancel()
		if err != nil {
			return err
		}
		b.mu.Lock()
		b.sensors, b.sdrOK = s, true
		b.mu.Unlock()
		slog.Info("BMC sensor list read", "sensors", len(s))
	}
	b.mu.Lock()
	sensors := b.sensors
	b.mu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, b.interval+30*time.Second)
	r, err := ipmi.ReadSensors(cctx, b.t, sensors)
	cancel()
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.readings, b.readAt, b.lastErr = r, time.Now(), ""
	b.mu.Unlock()
	return nil
}

// Readings returns the latest readings if they are fresh enough to show (three intervals and 30 s: up to
// 930 s with the longest interval the config accepts). The fan watchdog does not use these: see WatchdogReadings.
func (b *BMC) Readings() []ipmi.Reading {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if time.Since(b.readAt) > 3*b.interval+30*time.Second {
		return nil
	}
	return b.readings
}

// BMCTempMaxAge is the oldest BMC reading the fan watchdog ever acts on, whatever the interval.
const BMCTempMaxAge = 60 * time.Second

// watchdogMaxAge is how old the BMC's readings may be for the fan watchdog and for accepting a fan duty.
//
// Run reads, waits one interval and reads again, and a reading is stamped when its read ends: while the BMC
// answers, the latest reading is at most one interval plus the time of one read old. Two intervals and 10 s
// leave room for a read that takes as long as an interval and 10 s more (a BMC reached through PowerShell is
// slow). It is never less than the OS's own temperatures get (LocalTempMaxAge, 30 s: the default interval of
// 10 s gives exactly that) and never more than BMCTempMaxAge. Once the BMC stops answering, Run tries again
// after a minute at the earliest, so the reading runs out before the next try and the watchdog sees "no
// temperature" (review N4: it used Readings' bound and kept a manual fan speed on a temperature up to
// 15.5 minutes old).
//
// With an interval above 25 s the bound is BMCTempMaxAge, and above some 50 s a reading is older than that
// for a part of every interval. A machine with no temperature from the operating system then cannot hold a
// manual fan speed (the watchdog goes to 100 %); that is the safe side, and the cure is a shorter interval.
func watchdogMaxAge(interval time.Duration) time.Duration {
	return min(max(2*interval+10*time.Second, LocalTempMaxAge), BMCTempMaxAge)
}

// WatchdogReadings returns the latest readings if they are fresh enough to keep a manual fan speed on
// (watchdogMaxAge); nil otherwise, which the watchdog treats as "no temperature".
func (b *BMC) WatchdogReadings() []ipmi.Reading {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if age := time.Since(b.readAt); age < 0 || age > watchdogMaxAge(b.interval) {
		return nil
	}
	return b.readings
}

// Metrics converts the readings to the /metrics shapes (sensor "IPMI"; fans and voltages prefixed "IPMI").
// A reading that is not a possible number (the conversion formulas of a broken sensor record can give NaN or
// an infinity) is left out: one of them would make the whole /metrics answer impossible to write.
func (b *BMC) Metrics() ([]collect.Temp, []collect.Fan, []collect.Voltage) {
	var temps []collect.Temp
	var fans []collect.Fan
	var volts []collect.Voltage
	for _, r := range b.Readings() {
		if !devices.Finite(r.Value) {
			continue
		}
		name := r.Sensor.Name
		switch r.Sensor.Type {
		case ipmi.TypeTemperature:
			t := collect.Temp{Sensor: "IPMI", Label: collect.P(name), Current: collect.Round(r.Value, 1)}
			if c := r.Sensor.UpperCritical(); c != nil && *c > 0 && devices.Finite(*c) {
				t.Critical = collect.P(collect.Round(*c, 1))
			}
			temps = append(temps, t)
		case ipmi.TypeFan:
			fans = append(fans, collect.Fan{Name: "IPMI " + name, RPM: r.Value})
		case ipmi.TypeVoltage:
			volts = append(volts, collect.Voltage{Name: "IPMI " + name, Volts: collect.Round(r.Value, 3)})
		}
	}
	return temps, fans, volts
}

// FanList is the fans for /fan/status (names as the BMC calls them: FAN1, FANA ...), without readings that
// are not possible numbers.
func (b *BMC) FanList() []collect.Fan {
	fans := []collect.Fan{}
	for _, r := range b.Readings() {
		if r.Sensor.Type == ipmi.TypeFan && devices.Finite(r.Value) {
			fans = append(fans, collect.Fan{Name: r.Sensor.Name, RPM: r.Value})
		}
	}
	return fans
}

// MaxCPUTemp returns the hottest CPU temperature among the BMC's and the OS's sensors (any temperature when
// none is labelled as the CPU's). ok is false when there is no reading at all.
//
// A reading that is not a number (NaN) is no reading: a comparison with NaN is never true, so a NaN in first
// place used to stay "the hottest" and the fan watchdog never acted. -Inf is skipped as well; +Inf stays what
// it always was, hotter than every limit (the watchdog fails safe on it). When the sensors labelled as the
// CPU's exist but none of them has a usable reading, ok is false (the watchdog then counts it as "no
// temperature" and fails safe after three misses) instead of falling back to some other, cooler sensor.
func MaxCPUTemp(bmc []ipmi.Reading, local []collect.Temp) (float64, string, bool) {
	type cand struct {
		name string
		v    float64
		cpu  bool
	}
	var cs []cand
	isCPU := func(s string) bool {
		s = strings.ToLower(s)
		return strings.Contains(s, "cpu") || strings.Contains(s, "package") || strings.Contains(s, "tctl") ||
			strings.Contains(s, "tdie") || strings.Contains(s, "coretemp") || strings.Contains(s, "k10temp")
	}
	for _, r := range bmc {
		if r.Sensor.Type == ipmi.TypeTemperature {
			cs = append(cs, cand{r.Sensor.Name, r.Value, isCPU(r.Sensor.Name)})
		}
	}
	for _, t := range local {
		label := t.Sensor
		if t.Label != nil {
			label += " " + *t.Label
		}
		cs = append(cs, cand{label, t.Current, isCPU(label)})
	}
	anyCPU := false
	for _, c := range cs {
		anyCPU = anyCPU || c.cpu
	}
	best, name, ok := 0.0, "", false
	for _, c := range cs {
		if anyCPU && !c.cpu {
			continue
		}
		if math.IsNaN(c.v) || math.IsInf(c.v, -1) {
			continue
		}
		if !ok || c.v > best {
			best, name, ok = c.v, c.name, true
		}
	}
	return best, name, ok
}
