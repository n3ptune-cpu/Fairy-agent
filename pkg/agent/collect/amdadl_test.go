package collect

import (
	"errors"
	"testing"
)

// fakeADL stands in for atiadlxx.dll (CI has no AMD GPU).
type fakeADL struct {
	adapters []ADLAdapter
	version  map[int]int
	pmlog    map[int][]ADLSensor
	odn, od6 map[int]int
	od6p     map[int]int
	fail     bool
	reads    int
}

func (f *fakeADL) Adapters() ([]ADLAdapter, error) {
	if f.fail {
		return nil, errors.New("ADL error -1")
	}
	return f.adapters, nil
}
func (f *fakeADL) OverdriveVersion(i int) (int, error) {
	if v, ok := f.version[i]; ok {
		return v, nil
	}
	return 0, errors.New("Overdrive not supported")
}
func (f *fakeADL) PMLog(i int) ([]ADLSensor, error) {
	f.reads++
	if s, ok := f.pmlog[i]; ok {
		return s, nil
	}
	return nil, errors.New("ADL error -8")
}
func get(m map[int]int, i int) (int, error) {
	if v, ok := m[i]; ok {
		return v, nil
	}
	return 0, errors.New("ADL error -8")
}
func (f *fakeADL) ODNTemperature(i int) (int, error) { return get(f.odn, i) }
func (f *fakeADL) OD6Temperature(i int) (int, error) { return get(f.od6, i) }
func (f *fakeADL) OD6Power(i int) (int, error)       { return get(f.od6p, i) }
func (f *fakeADL) OD5Temperature(int) (int, error)   { return 0, errors.New("ADL error -8") }

func sensors(kv map[int]int32) []ADLSensor {
	s := make([]ADLSensor, 256)
	for k, v := range kv {
		s[k] = ADLSensor{Supported: true, Value: v}
	}
	return s
}

func TestAMDSensorsAttachToTheDedupedCard(t *testing.T) {
	// ADL: the RX 5600 XT at 0b:00.0 three times (one per output; the first has no Overdrive), a second card
	// (Polaris, OverdriveN) at 0c:00.0, and an NVIDIA entry that is ignored.
	f := &fakeADL{
		adapters: []ADLAdapter{
			{Index: 0, Bus: 0x0b, VendorID: 0x1002, Name: "AMD Radeon RX 5600 XT"},
			{Index: 1, Bus: 0x0b, VendorID: 0x1002, Name: "AMD Radeon RX 5600 XT"},
			{Index: 2, Bus: 0x0b, VendorID: 0x1002, Name: "AMD Radeon RX 5600 XT"},
			{Index: 3, Bus: 0x0c, VendorID: 0x1002, Name: "Radeon RX 580"},
			{Index: 4, Bus: 0x0d, VendorID: 0x10de, Name: "nope"},
		},
		version: map[int]int{1: 8, 2: 8, 3: 7, 4: 8},
		pmlog:   map[int][]ADLSensor{1: sensors(map[int]int32{pmlogTempEdge: 54, pmlogTempHotspot: 61, pmlogASICPower: 87})},
		odn:     map[int]int{3: 48000},
		od6p:    map[int]int{3: 120 * 256},
	}
	s := NewAMDSensors(f)
	if s == nil || len(s.cards) != 2 || s.cards[0].index != 1 {
		t.Fatalf("%+v", s)
	}
	if c := s.Cards(); c[0] != "AMD Radeon RX 5600 XT (0b:00.0, Overdrive 8)" {
		t.Fatal(c)
	}
	// the three DXGI entries of the RX 5600 XT were deduped (wingpu.go) to the one with counters
	gpus := []GPU{
		{Name: "AMD Radeon RX 5600 XT", Vendor: "amd", Source: "windows", loc: &PCILoc{Bus: 0x0b}},
		{Name: "Radeon RX 580", Vendor: "amd", Source: "windows", loc: &PCILoc{Bus: 0x0c}},
		{Name: "Intel(R) UHD Graphics 770", Vendor: "intel", Source: "windows"},
	}
	s.Attach(gpus)
	if g := gpus[0]; g.TempC == nil || *g.TempC != 54 || *g.PowerW != 87 || g.Source != "amd" {
		t.Fatalf("RX 5600 XT %+v", g)
	}
	if g := gpus[1]; *g.TempC != 48 || *g.PowerW != 120 || g.Source != "amd" {
		t.Fatalf("RX 580 %+v", g)
	}
	if g := gpus[2]; g.TempC != nil || g.Source != "windows" {
		t.Fatalf("Intel %+v", g)
	}
	// newer drivers: board power wins over ASIC power; no edge sensor -> hotspot
	f.pmlog[1] = sensors(map[int]int32{pmlogTempHotspot: 70, pmlogASICPower: 87, pmlogBoardPower: 140})
	gpus = []GPU{{Vendor: "amd", Source: "windows", loc: &PCILoc{Bus: 0x0b}}}
	s.Attach(gpus)
	if *gpus[0].TempC != 70 || *gpus[0].PowerW != 140 {
		t.Fatalf("%+v", gpus[0])
	}
	// a failing read keeps load / VRAM only (and logs once)
	delete(f.pmlog, 1)
	gpus = []GPU{{Vendor: "amd", Source: "windows", loc: &PCILoc{Bus: 0x0b}}}
	s.Attach(gpus)
	s.Attach(gpus)
	if gpus[0].TempC != nil || gpus[0].PowerW != nil || gpus[0].Source != "windows" || !s.cards[0].warned {
		t.Fatalf("%+v", gpus[0])
	}
	// implausible values are dropped
	f.pmlog[1] = sensors(map[int]int32{pmlogTempEdge: 0, pmlogASICPower: 65535})
	gpus = []GPU{{Vendor: "amd", Source: "windows", loc: &PCILoc{Bus: 0x0b}}}
	s.Attach(gpus)
	if gpus[0].TempC != nil || gpus[0].PowerW != nil {
		t.Fatalf("%+v", gpus[0])
	}
}

func TestAMDSensorsWithoutLocationOrADL(t *testing.T) {
	if NewAMDSensors(&fakeADL{fail: true}) != nil || NewAMDSensors(nil) != nil {
		t.Fatal("no ADL: nil")
	}
	if NewAMDSensors(&fakeADL{adapters: []ADLAdapter{{Index: 0, VendorID: 0x1002}}}) != nil {
		t.Fatal("no Overdrive: nil")
	}
	f := &fakeADL{adapters: []ADLAdapter{{Index: 0, Bus: 3, VendorID: 0x1002}}, version: map[int]int{0: 8},
		pmlog: map[int][]ADLSensor{0: sensors(map[int]int32{pmlogTempEdge: 40})}}
	s := NewAMDSensors(f)
	// one AMD GPU without a known location, one ADL card: matched
	gpus := []GPU{{Vendor: "amd", Source: "windows"}}
	s.Attach(gpus)
	if gpus[0].TempC == nil || *gpus[0].TempC != 40 || gpus[0].PowerW != nil {
		t.Fatalf("%+v", gpus[0])
	}
	// two AMD GPUs without locations: no guessing
	gpus = []GPU{{Vendor: "amd", Source: "windows"}, {Vendor: "amd", Source: "windows"}}
	s.Attach(gpus)
	if gpus[0].TempC != nil || gpus[1].TempC != nil {
		t.Fatal("guessed")
	}
	var nilS *AMDSensors
	nilS.Attach(gpus) // safe
}
