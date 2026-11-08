package collect

// Core Temp (Windows, optional): Core Temp by ALCPU reads the CPU's sensors with its own driver and publishes
// them for other programs in a named shared-memory block. fairy-agent only opens that block read-only and copies
// it; it loads no driver and never writes to it.
//
// The layout is the documented one from https://www.alcpu.com/CoreTemp/developers.html (CoreTempSharedDataEx,
// 4-byte member alignment) and the SDK header GetCoreTempInfo.h (CORE_TEMP_SHARED_DATA) in
// https://www.alcpu.com/CoreTemp/main_data/CoreTempSDK.zip:
//
//	unsigned int  uiLoad[256];      //    0
//	unsigned int  uiTjMax[128];     // 1024  per CPU
//	unsigned int  uiCoreCnt;        // 1536  cores per CPU
//	unsigned int  uiCPUCnt;         // 1540
//	float         fTemp[256];       // 1544  index = core + cpu*uiCoreCnt
//	float         fVID;             // 2568
//	float         fCPUSpeed;        // 2572
//	float         fFSBSpeed;        // 2576
//	float         fMultiplier;      // 2580
//	char          sCPUName[100];    // 2584
//	unsigned char ucFahrenheit;     // 2684  temperatures (and, since Core Temp 1.20.1, TjMax) in °F
//	unsigned char ucDeltaToTjMax;   // 2685  fTemp is the distance to TjMax, not the temperature
//	// version 2 ("CoreTempMappingObjectEx") adds:
//	unsigned char ucTdpSupported;   // 2686
//	unsigned char ucPowerSupported; // 2687
//	unsigned int  uiStructVersion;  // 2688  2 today; later versions only append
//	unsigned int  uiTdp[128];       // 2692  per CPU
//	float         fPower[128];      // 3204  per CPU, watts (package power)
//	float         fMultipliers[256];// 3716
//	                                // 4740  end
//
// The block has no package temperature, so none is reported: per-core temperatures only (the panel and the fan
// watchdog use the hottest).

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Core Temp shared-memory layout (see above).
const (
	ctOffTjMax       = 1024
	ctOffCoreCnt     = 1536
	ctOffCPUCnt      = 1540
	ctOffTemp        = 1544
	ctOffName        = 2584
	ctOffFahrenheit  = 2684
	ctOffDelta       = 2685
	ctOffPowerOK     = 2687
	ctOffVersion     = 2688
	ctOffPower       = 3204
	CoreTempBaseSize = 2686 // CORE_TEMP_SHARED_DATA without the padding
	CoreTempExSize   = 4740 // CoreTempSharedDataEx, version 2

	ctMaxCPUs  = 128 // uiTjMax / fPower have 128 entries
	ctMaxCores = 256 // fTemp has 256 entries
)

// CoreTempData is one validated copy of Core Temp's shared memory, already in degrees Celsius.
type CoreTempData struct {
	CPUName    string
	CPUs       int
	CoresPer   int
	TempsC     []float64 // per core, cpu-major; NaN where the value was missing or implausible
	TjMaxC     []float64 // per CPU; NaN when unknown
	PackageW   []float64 // per CPU; nil when Core Temp does not report power (or the block is version 1)
	Version    uint32    // 0 for the original block
	Fahrenheit bool
}

// ParseCoreTemp checks and converts a copy of the shared memory. It never trusts the counts: a block that is too
// short, has no cores or more cores than the arrays hold is an error, and single implausible values (NaN,
// infinities, below -40 °C or above 150 °C, watts outside 0-1000) are dropped.
func ParseCoreTemp(b []byte) (CoreTempData, error) {
	var d CoreTempData
	if len(b) < CoreTempBaseSize {
		return d, fmt.Errorf("core temp shared memory too short (%d bytes)", len(b))
	}
	le := binary.LittleEndian
	u32 := func(off int) uint32 { return le.Uint32(b[off:]) }
	f32 := func(off int) float64 { return float64(math.Float32frombits(le.Uint32(b[off:]))) }
	cores, cpus := u32(ctOffCoreCnt), u32(ctOffCPUCnt)
	if cpus == 0 || cores == 0 {
		return d, errors.New("core temp reports no CPU cores (still starting?)")
	}
	if cpus > ctMaxCPUs || cores > ctMaxCores || uint64(cpus)*uint64(cores) > ctMaxCores {
		return d, fmt.Errorf("core temp reports an impossible core count (%d CPUs x %d cores)", cpus, cores)
	}
	d.CPUs, d.CoresPer = int(cpus), int(cores)
	d.Fahrenheit = b[ctOffFahrenheit] != 0
	delta := b[ctOffDelta] != 0
	name := b[ctOffName : ctOffName+100]
	if i := strings.IndexByte(string(name), 0); i >= 0 {
		name = name[:i]
	}
	d.CPUName = strings.TrimSpace(strings.ToValidUTF8(string(name), ""))

	d.TjMaxC = make([]float64, d.CPUs)
	for i := range d.CPUs {
		d.TjMaxC[i] = math.NaN()
		tj := float64(u32(ctOffTjMax + 4*i))
		if d.Fahrenheit && tj > 130 { // Core Temp before 1.20.1 wrote TjMax in °C even in Fahrenheit mode
			tj = (tj - 32) * 5 / 9
		}
		if tj > 0 && tj <= 150 {
			d.TjMaxC[i] = Round(tj, 1)
		}
	}
	d.TempsC = make([]float64, d.CPUs*d.CoresPer)
	for i := range d.TempsC {
		v := f32(ctOffTemp + 4*i)
		switch {
		case math.IsNaN(v) || math.IsInf(v, 0):
			v = math.NaN()
		case delta: // distance below TjMax, in the display unit
			if d.Fahrenheit {
				v = v * 5 / 9
			}
			if tj := d.TjMaxC[i/d.CoresPer]; !math.IsNaN(tj) && v >= 0 {
				v = tj - v
			} else {
				v = math.NaN()
			}
		case d.Fahrenheit:
			v = (v - 32) * 5 / 9
		}
		if !(v > -40 && v < 150) || v == 0 { // 0 is what Core Temp shows for a core it cannot read
			v = math.NaN()
		}
		if !math.IsNaN(v) {
			v = Round(v, 1)
		}
		d.TempsC[i] = v
	}

	if len(b) >= CoreTempExSize {
		d.Version = u32(ctOffVersion)
		if d.Version >= 2 && b[ctOffPowerOK] != 0 {
			d.PackageW = make([]float64, d.CPUs)
			for i := range d.CPUs {
				w := f32(ctOffPower + 4*i)
				if math.IsNaN(w) || math.IsInf(w, 0) || w < 0 || w > 1000 {
					w = math.NaN()
				} else {
					w = Round(w, 1)
				}
				d.PackageW[i] = w
			}
		}
	}
	return d, nil
}

// Temps returns the per-core temperatures in the shape of Linux's coretemp hwmon readings (sensor "coretemp",
// label "Core 0" ..., critical = TjMax), so the panel and the fan watchdog treat them like Linux CPU temperatures.
// With more than one CPU the label says which: "CPU 1 Core 0".
func (d CoreTempData) Temps() []Temp {
	out := []Temp{}
	for i, v := range d.TempsC {
		if math.IsNaN(v) {
			continue
		}
		cpu, core := i/d.CoresPer, i%d.CoresPer
		label := "Core " + strconv.Itoa(core)
		if d.CPUs > 1 {
			label = "CPU " + strconv.Itoa(cpu) + " " + label
		}
		t := Temp{Sensor: "coretemp", Label: P(label), Current: v}
		if tj := d.TjMaxC[cpu]; !math.IsNaN(tj) {
			t.Critical = P(tj)
		}
		out = append(out, t)
	}
	return out
}

// Power returns the CPU package watts (sum over CPUs) and one sensor per CPU ("coretemp package-0", like Linux's
// "rapl package-0"); nil and none when Core Temp does not report power.
func (d CoreTempData) Power() (*float64, []PowerSensor) {
	var sensors []PowerSensor
	sum, has := 0.0, false
	for i, w := range d.PackageW {
		if math.IsNaN(w) {
			continue
		}
		sensors = append(sensors, PowerSensor{Name: "coretemp package-" + strconv.Itoa(i), Watts: w})
		sum += w
		has = true
	}
	if !has {
		return nil, nil
	}
	return P(Round(sum, 1)), sensors
}

// MergeCoreTemp adds Core Temp's readings to a sample: its temperatures first (the panel lists the first few),
// its package watts as the CPU package power unless the OS already reported one.
func MergeCoreTemp(s *Sample, d CoreTempData) {
	s.Temps = append(d.Temps(), s.Temps...)
	if w, sensors := d.Power(); w != nil && s.Power.CPUPackageW == nil {
		s.Power.CPUPackageW = w
		s.Power.Sensors = append(append([]PowerSensor{}, s.Power.Sensors...), sensors...)
		s.Power.Source = append(append([]string{}, s.Power.Source...), "coretemp")
	}
}

// Errors of the platform's shared-memory reader.
var (
	errCoreTempAbsent = errors.New("core temp shared memory not found")
	errCoreTempDenied = errors.New("access denied to core temp shared memory")
)

// coreTempCollector adds Core Temp's readings to another collector's samples.
type coreTempCollector struct {
	Collector
	read func() ([]byte, string, error) // copy of the shared memory and the name it was found under

	mu     sync.Mutex
	data   *CoreTempData
	at     time.Time
	state  string
	logged string
}

// WithCoreTemp returns c with Core Temp's readings added to every sample (when Core Temp is running; nothing
// otherwise). Only Windows has a reader; elsewhere c is returned unchanged.
func WithCoreTemp(c Collector) Collector {
	if coreTempRead == nil {
		return c
	}
	return &coreTempCollector{Collector: c, read: coreTempRead}
}

// Sample reads the wrapped collector, then adds Core Temp's latest readings.
func (c *coreTempCollector) Sample(ctx context.Context) Sample {
	s := c.Collector.Sample(ctx)
	if d := c.current(time.Now()); d != nil {
		MergeCoreTemp(&s, *d)
	}
	return s
}

// current returns the readings, re-reading the shared memory at most every 2 s (every 10 s while it is absent).
func (c *coreTempCollector) current(now time.Time) *CoreTempData {
	c.mu.Lock()
	defer c.mu.Unlock()
	wait := 2 * time.Second
	if c.data == nil {
		wait = 10 * time.Second
	}
	if !c.at.IsZero() && now.Sub(c.at) < wait {
		return c.data
	}
	c.at = now
	b, name, err := c.read()
	if err == nil {
		var d CoreTempData
		if d, err = ParseCoreTemp(b); err == nil {
			c.data = &d
			c.note("ok", slog.LevelInfo, "Core Temp readings available", "shared_memory", name, "cpu", d.CPUName,
				"cores", d.CPUs*d.CoresPer, "power", d.PackageW != nil)
			return c.data
		}
	}
	c.data = nil
	switch {
	case errors.Is(err, errCoreTempAbsent):
		c.note("absent", slog.LevelInfo, "Core Temp is not running (or its global shared memory is off): no CPU core temperatures or package watts from it")
	case errors.Is(err, errCoreTempDenied):
		c.note("denied", slog.LevelWarn, "Core Temp's shared memory exists but this account may not read it: run the service as LocalSystem (see AGENT.md, Core Temp)", "shared_memory", name)
	default:
		c.note("error", slog.LevelWarn, "Core Temp's shared memory could not be used", "error", err.Error())
	}
	return nil
}

// note logs a state change once (no repeats while the state stays the same).
func (c *coreTempCollector) note(state string, level slog.Level, msg string, args ...any) {
	c.state = state
	if c.logged == state {
		return
	}
	c.logged = state
	slog.Log(context.Background(), level, msg, args...)
}
