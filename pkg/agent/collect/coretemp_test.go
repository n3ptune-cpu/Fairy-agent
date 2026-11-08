package collect

import (
	"context"
	"encoding/binary"
	"errors"
	"math"
	"testing"
	"time"
)

type ctBlock struct {
	cpus, cores    uint32
	tjmax          []uint32
	temps          []float32
	name           string
	fahrenheit     bool
	delta          bool
	ex             bool
	version        uint32
	powerSupported bool
	power          []float32
}

func (c ctBlock) bytes() []byte {
	size := 2688 // sizeof(CORE_TEMP_SHARED_DATA) with padding
	if c.ex {
		size = CoreTempExSize
	}
	b := make([]byte, size)
	le := binary.LittleEndian
	for i, v := range c.tjmax {
		le.PutUint32(b[ctOffTjMax+4*i:], v)
	}
	le.PutUint32(b[ctOffCoreCnt:], c.cores)
	le.PutUint32(b[ctOffCPUCnt:], c.cpus)
	for i, v := range c.temps {
		le.PutUint32(b[ctOffTemp+4*i:], math.Float32bits(v))
	}
	copy(b[ctOffName:ctOffName+99], c.name)
	if c.fahrenheit {
		b[ctOffFahrenheit] = 1
	}
	if c.delta {
		b[ctOffDelta] = 1
	}
	if c.ex {
		if c.powerSupported {
			b[ctOffPowerOK] = 1
		}
		le.PutUint32(b[ctOffVersion:], c.version)
		for i, v := range c.power {
			le.PutUint32(b[ctOffPower+4*i:], math.Float32bits(v))
		}
	}
	return b
}

func TestCoreTempLayout(t *testing.T) {
	// offsets of the documented struct with 4-byte alignment
	if ctOffVersion != 2688 || ctOffPower != 2692+4*128 || CoreTempExSize != ctOffPower+4*128+4*256 {
		t.Fatal("layout constants disagree with the documented struct")
	}
}

func TestParseCoreTempBasic(t *testing.T) {
	d, err := ParseCoreTemp(ctBlock{cpus: 1, cores: 4, tjmax: []uint32{100}, temps: []float32{41.5, 43, 0, 39.96},
		name: "Intel Core i9 9900K (Coffee Lake)"}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if d.CPUName != "Intel Core i9 9900K (Coffee Lake)" || d.Version != 0 || d.PackageW != nil {
		t.Fatalf("%+v", d)
	}
	temps := d.Temps()
	if len(temps) != 3 { // the 0 °C core is dropped
		t.Fatalf("temps %+v", temps)
	}
	if temps[0].Sensor != "coretemp" || *temps[0].Label != "Core 0" || temps[0].Current != 41.5 || *temps[0].Critical != 100 {
		t.Fatalf("%+v", temps[0])
	}
	if *temps[2].Label != "Core 3" || temps[2].Current != 40 {
		t.Fatalf("%+v", temps[2])
	}
	if w, s := d.Power(); w != nil || s != nil {
		t.Fatal("no power in a version 1 block")
	}
}

func TestParseCoreTempExPower(t *testing.T) {
	d, err := ParseCoreTemp(ctBlock{cpus: 1, cores: 2, tjmax: []uint32{100}, temps: []float32{50, 52}, ex: true,
		version: 2, powerSupported: true, power: []float32{35.27}}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	w, s := d.Power()
	if d.Version != 2 || w == nil || *w != 35.3 || len(s) != 1 || s[0].Name != "coretemp package-0" {
		t.Fatalf("%+v %v %+v", d, w, s)
	}
	// power flag off or version 1 in an Ex-sized block: no watts
	for _, blk := range []ctBlock{
		{cpus: 1, cores: 2, tjmax: []uint32{100}, temps: []float32{50, 52}, ex: true, version: 2, power: []float32{35}},
		{cpus: 1, cores: 2, tjmax: []uint32{100}, temps: []float32{50, 52}, ex: true, version: 1, powerSupported: true, power: []float32{35}},
	} {
		d, _ := ParseCoreTemp(blk.bytes())
		if w, _ := d.Power(); w != nil {
			t.Fatalf("unexpected power %v", *w)
		}
	}
	// absurd watts are dropped
	d, _ = ParseCoreTemp(ctBlock{cpus: 2, cores: 1, tjmax: []uint32{100, 100}, temps: []float32{50, 52}, ex: true,
		version: 2, powerSupported: true, power: []float32{float32(math.NaN()), 5000}}.bytes())
	if w, _ := d.Power(); w != nil {
		t.Fatalf("unexpected power %v", *w)
	}
}

func TestParseCoreTempFahrenheit(t *testing.T) {
	d, err := ParseCoreTemp(ctBlock{cpus: 1, cores: 2, tjmax: []uint32{212}, temps: []float32{122, 140}, fahrenheit: true}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	temps := d.Temps()
	if len(temps) != 2 || temps[0].Current != 50 || temps[1].Current != 60 || *temps[0].Critical != 100 {
		t.Fatalf("%+v", temps)
	}
	// old Core Temp: TjMax still in °C in Fahrenheit mode
	d, _ = ParseCoreTemp(ctBlock{cpus: 1, cores: 1, tjmax: []uint32{100}, temps: []float32{122}, fahrenheit: true}.bytes())
	if d.TjMaxC[0] != 100 {
		t.Fatalf("tjmax %v", d.TjMaxC)
	}
}

func TestParseCoreTempDeltaToTjMax(t *testing.T) {
	d, _ := ParseCoreTemp(ctBlock{cpus: 1, cores: 2, tjmax: []uint32{100}, temps: []float32{40, 55}, delta: true}.bytes())
	temps := d.Temps()
	if len(temps) != 2 || temps[0].Current != 60 || temps[1].Current != 45 {
		t.Fatalf("%+v", temps)
	}
	// Fahrenheit distance: 36 °F below a TjMax of 212 °F = 80 °C
	d, _ = ParseCoreTemp(ctBlock{cpus: 1, cores: 1, tjmax: []uint32{212}, temps: []float32{36}, delta: true, fahrenheit: true}.bytes())
	if temps := d.Temps(); len(temps) != 1 || temps[0].Current != 80 {
		t.Fatalf("%+v", temps)
	}
	// unknown TjMax: a distance cannot become a temperature
	d, _ = ParseCoreTemp(ctBlock{cpus: 1, cores: 1, temps: []float32{40}, delta: true}.bytes())
	if temps := d.Temps(); len(temps) != 0 {
		t.Fatalf("%+v", temps)
	}
}

func TestParseCoreTempMultiCPU(t *testing.T) {
	d, _ := ParseCoreTemp(ctBlock{cpus: 2, cores: 2, tjmax: []uint32{90, 95}, temps: []float32{40, 41, 42, 43}}.bytes())
	temps := d.Temps()
	if len(temps) != 4 || *temps[3].Label != "CPU 1 Core 1" || temps[3].Current != 43 || *temps[3].Critical != 95 {
		t.Fatalf("%+v", temps)
	}
}

func TestParseCoreTempRejects(t *testing.T) {
	nan, inf := float32(math.NaN()), float32(math.Inf(1))
	for name, b := range map[string][]byte{
		"short":        make([]byte, 100),
		"just short":   ctBlock{cpus: 1, cores: 1}.bytes()[:CoreTempBaseSize-1],
		"zero cores":   ctBlock{cpus: 1, cores: 0}.bytes(),
		"zero cpus":    ctBlock{cpus: 0, cores: 4}.bytes(),
		"many cores":   ctBlock{cpus: 1, cores: 257}.bytes(),
		"many cpus":    ctBlock{cpus: 129, cores: 1}.bytes(),
		"product":      ctBlock{cpus: 64, cores: 64}.bytes(),
		"huge":         ctBlock{cpus: 0xFFFFFFFF, cores: 0xFFFFFFFF}.bytes(),
		"overflowing":  ctBlock{cpus: 0x10000, cores: 0x10000}.bytes(),
		"empty buffer": nil,
	} {
		if _, err := ParseCoreTemp(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// single bad values are dropped, the rest is kept
	d, err := ParseCoreTemp(ctBlock{cpus: 1, cores: 6, tjmax: []uint32{100}, temps: []float32{nan, inf, -300, 400, 0, 47}}.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if temps := d.Temps(); len(temps) != 1 || temps[0].Current != 47 {
		t.Fatalf("%+v", temps)
	}
	// absurd TjMax: no critical value, and no delta conversion
	d, _ = ParseCoreTemp(ctBlock{cpus: 1, cores: 1, tjmax: []uint32{4000000000}, temps: []float32{50}}.bytes())
	if temps := d.Temps(); len(temps) != 1 || temps[0].Critical != nil {
		t.Fatalf("%+v", temps)
	}
	// a name without a terminating zero is cut at 100 bytes
	blk := ctBlock{cpus: 1, cores: 1, tjmax: []uint32{100}, temps: []float32{50}}.bytes()
	for i := range 100 {
		blk[ctOffName+i] = 'x'
	}
	if d, _ := ParseCoreTemp(blk); len(d.CPUName) != 100 {
		t.Fatalf("name %q", d.CPUName)
	}
}

func TestMergeCoreTemp(t *testing.T) {
	d, _ := ParseCoreTemp(ctBlock{cpus: 1, cores: 2, tjmax: []uint32{100}, temps: []float32{50, 60}, ex: true,
		version: 2, powerSupported: true, power: []float32{40}}.bytes())
	acpi := "ACPI thermal zone TZ00"
	s := Sample{Temps: []Temp{{Sensor: "acpi", Label: &acpi, Current: 27.8}},
		Power: Power{Sensors: []PowerSensor{}, Source: []string{"battery"}}}
	MergeCoreTemp(&s, d)
	if len(s.Temps) != 3 || s.Temps[0].Sensor != "coretemp" || s.Temps[2].Sensor != "acpi" {
		t.Fatalf("%+v", s.Temps)
	}
	if s.Power.CPUPackageW == nil || *s.Power.CPUPackageW != 40 || len(s.Power.Sensors) != 1 ||
		len(s.Power.Source) != 2 || s.Power.Source[1] != "coretemp" {
		t.Fatalf("%+v", s.Power)
	}
	// an OS reading (RAPL) wins
	s = Sample{Power: Power{CPUPackageW: P(12.0)}}
	MergeCoreTemp(&s, d)
	if *s.Power.CPUPackageW != 12 || len(s.Power.Sensors) != 0 {
		t.Fatalf("%+v", s.Power)
	}
}

type fixedCollector struct{ s Sample }

func (f fixedCollector) Static() Static                { return Static{} }
func (f fixedCollector) Sample(context.Context) Sample { return f.s }
func (f fixedCollector) Processes(context.Context, ProcOptions) ([]Process, int, error) {
	return nil, 0, nil
}

func TestCoreTempCollector(t *testing.T) {
	block := ctBlock{cpus: 1, cores: 1, tjmax: []uint32{100}, temps: []float32{55}}.bytes()
	var err error
	calls := 0
	c := &coreTempCollector{Collector: fixedCollector{}, read: func() ([]byte, string, error) {
		calls++
		if err != nil {
			return nil, "", err
		}
		return block, `Global\CoreTempMappingObjectEx`, nil
	}}
	now := time.Now()
	if d := c.current(now); d == nil || d.TempsC[0] != 55 {
		t.Fatal("no reading")
	}
	c.current(now.Add(time.Second)) // cached
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	err = errCoreTempAbsent
	if d := c.current(now.Add(3 * time.Second)); d != nil || c.state != "absent" {
		t.Fatal("reading while absent")
	}
	c.current(now.Add(5 * time.Second)) // absent: retried only every 10 s
	if calls != 2 {
		t.Fatalf("calls %d", calls)
	}
	err = errCoreTempDenied
	if c.current(now.Add(14 * time.Second)); c.state != "denied" {
		t.Fatal(c.state)
	}
	err = errors.New("boom")
	if c.current(now.Add(25 * time.Second)); c.state != "error" {
		t.Fatal(c.state)
	}
	err = nil
	block = make([]byte, 10) // malformed
	if d := c.current(now.Add(36 * time.Second)); d != nil || c.state != "error" {
		t.Fatal("malformed block accepted")
	}
}
