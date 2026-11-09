package collect

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
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
	if c := s.Cards(); c[0] != "AMD Radeon RX 5600 XT (0b:00.0, Overdrive 8, temperature via PMLog)" || c[1] != "Radeon RX 580 (0c:00.0, Overdrive 7, temperature via OverdriveN)" {
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

// The start-up line says what ADL answered: the DLL, the adapter count, per adapter its location and the
// Overdrive answer (the error code when ADL refuses), and how many cards are read.
func TestAMDSensorsLogsWhatADLAnswered(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	defer slog.SetDefault(old)
	f := &fakeADL{adapters: []ADLAdapter{
		{Index: 0, Bus: 0x2d, VendorID: 0x1002, Present: true, Exist: true},
		{Index: 1, Bus: 0x2d, VendorID: 0x1002},
	}}
	if s := NewAMDSensors(f); s != nil {
		t.Fatal(s)
	}
	line := buf.String()
	for _, want := range []string{`msg="AMD GPU sensors (ADL)"`, "adapters=2", "cards=0", "#0 2d:00.0 vendor=1002 present=true exist=true overdrive=Overdrive not supported"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %s", want, line)
		}
	}
	buf.Reset()
	if s := NewAMDSensors(&fakeADL{fail: true}); s != nil {
		t.Fatal(s)
	}
	if !strings.Contains(buf.String(), `adapters_error="ADL error -1"`) || strings.Count(buf.String(), "\n") != 1 {
		t.Fatal(buf.String())
	}
}

// captureLog sends slog to a buffer for the test.
func captureLog(t *testing.T) *bytes.Buffer {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// varesaADL is what ADL answered on STWS-VARESA (one RX 5600 XT, agent as NT SERVICE\fairy-agent in session 0)
// on 0.5.2: "#0 2d:00.0 vendor=03ea present=false exist=true skipped #1 2d:00.0 vendor=03ea present=false
// exist=true skipped". 03ea is 1002 decimal: ADL's way of writing AMD's vendor id.
func varesaADL() *fakeADL {
	rx := ADLAdapter{Bus: 0x2d, VendorID: 1002, Name: "AMD Radeon RX 5600 XT", Present: false, Exist: true}
	a0, a1 := rx, rx
	a1.Index = 1
	return &fakeADL{adapters: []ADLAdapter{a0, a1}, version: map[int]int{0: 8, 1: 8},
		pmlog: map[int][]ADLSensor{0: sensors(map[int]int32{pmlogTempEdge: 52, pmlogTempHotspot: 60, pmlogBoardPower: 98}),
			1: sensors(map[int]int32{pmlogTempEdge: 52})}}
}

func TestADLVaresaSession0(t *testing.T) {
	buf := captureLog(t)
	f := varesaADL()
	s := NewAMDSensors(f)
	if s == nil || len(s.cards) != 1 || s.cards[0].index != 0 || s.cards[0].api != apiPMLog {
		t.Fatalf("one card, ADL index 0, read through PMLog: %+v", s)
	}
	line := buf.String()
	for _, want := range []string{"adapters=2", "cards=1", `temp_api="[2d:00.0 PMLog]"`,
		"#0 2d:00.0 vendor=1002 present=false exist=true overdrive=8 temp=PMLog 52.0C power=98.0W",
		"#1 2d:00.0 vendor=1002 present=false exist=true same card"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %s", want, line)
		}
	}
	if strings.Contains(line, "skipped") {
		t.Fatal(line)
	}
	// DXGI on VARESA (TestBuild12VaresaTwoLeftoverLUIDs): two leftover LUIDs without a location and the live one
	// at 2d:00.0 (D3DKMT); after DropGhosts / GroupAdapters one GPU, matched by its location
	none := &PCILoc{Bus: 0xFFFFFFFF, Device: 0xFFFF, Function: 0xFFFF}
	rx := func(luid string, loc *PCILoc) WinAdapter {
		return WinAdapter{Name: "AMD Radeon RX 5600 XT", VendorID: 0x1002, DeviceID: 0x731f, SubSysID: 0xe4161da2, Revision: 0xca,
			VRAMTotal: 6 << 30, LUID: luid, Loc: loc}
	}
	all := []WinAdapter{rx("0x00000000_0x0001AACF", none), rx("0x00000000_0x000188B4", none), rx("0x00000000_0x00011AE4", &PCILoc{Bus: 0x2d})}
	gpus := WinGPUs(GroupAdapters(DropGhosts(ShownAdapters(all, true), nil), nil), EngineLoad{}, nil)
	if len(gpus) != 1 || gpus[0].Vendor != "amd" || gpus[0].loc.String() != "2d:00.0" {
		t.Fatalf("precondition: %+v", gpus)
	}
	s.Attach(gpus)
	if g := gpus[0]; g.TempC == nil || *g.TempC != 52 || g.PowerW == nil || *g.PowerW != 98 || g.Source != "amd" {
		t.Fatalf("%+v", g)
	}
	if c := s.Cards(); len(c) != 1 || c[0] != "AMD Radeon RX 5600 XT (2d:00.0, Overdrive 8, temperature via PMLog)" {
		t.Fatal(c)
	}
}

func TestADLTemperatureFallbacks(t *testing.T) {
	// PMLog refused (older driver, or session 0): OverdriveN answers, remembered and tried first afterwards
	buf := captureLog(t)
	f := varesaADL()
	f.pmlog = nil
	f.odn = map[int]int{0: 47000}
	s := NewAMDSensors(f)
	if s == nil || len(s.cards) != 1 || s.cards[0].api != apiODN {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(buf.String(), "#0 2d:00.0 vendor=1002 present=false exist=true overdrive=8 temp=OverdriveN 47.0C") ||
		!strings.Contains(buf.String(), `temp_api="[2d:00.0 OverdriveN]"`) {
		t.Fatal(buf.String())
	}
	reads := f.reads
	gpus := []GPU{{Vendor: "amd", Source: "windows", loc: &PCILoc{Bus: 0x2d}}}
	s.Attach(gpus)
	if gpus[0].TempC == nil || *gpus[0].TempC != 47 || f.reads != reads {
		t.Fatalf("%+v, PMLog calls %d -> %d", gpus[0], reads, f.reads)
	}

	// ADL2_Overdrive_Caps refused for both entries: every call is tried; PMLog answers, the card is kept
	buf.Reset()
	f = varesaADL()
	f.version = nil
	s = NewAMDSensors(f)
	if s == nil || len(s.cards) != 1 || s.cards[0].version != 0 || s.cards[0].api != apiPMLog {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(buf.String(), "#0 2d:00.0 vendor=1002 present=false exist=true overdrive=Overdrive not supported temp=PMLog 52.0C") {
		t.Fatal(buf.String())
	}
	if c := s.Cards(); c[0] != "AMD Radeon RX 5600 XT (2d:00.0, Overdrive unknown, temperature via PMLog)" {
		t.Fatal(c)
	}

	// the first entry gives no temperature, the second entry of the same card does: the second is used
	buf.Reset()
	f = varesaADL()
	delete(f.pmlog, 0)
	s = NewAMDSensors(f)
	if s == nil || len(s.cards) != 1 || s.cards[0].index != 1 || s.cards[0].api != apiPMLog {
		t.Fatalf("%+v", s)
	}
	if !strings.Contains(buf.String(), "#1 2d:00.0 vendor=1002 present=false exist=true overdrive=8 temp=PMLog 52.0C (used instead of #0)") {
		t.Fatal(buf.String())
	}

	// no call answers: an Overdrive 8 card is kept (tried again each time) and logged temp=none with the errors
	buf.Reset()
	f = varesaADL()
	f.pmlog = nil
	s = NewAMDSensors(f)
	if s == nil || len(s.cards) != 1 || s.cards[0].index != 0 || s.cards[0].api != "" {
		t.Fatalf("%+v", s)
	}
	for _, want := range []string{"temp=none (PMLog: ADL error -8; OverdriveN: ADL error -8; Overdrive6: ADL error -8)",
		`temp_api="[2d:00.0 none]"`, "#1 2d:00.0 vendor=1002 present=false exist=true overdrive=8 temp=none"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("missing %q in %s", want, buf.String())
		}
	}
	f.pmlog = map[int][]ADLSensor{0: sensors(map[int]int32{pmlogTempEdge: 61})} // the driver answers later
	gpus = []GPU{{Vendor: "amd", Source: "windows", loc: &PCILoc{Bus: 0x2d}}}
	s.Attach(gpus)
	if gpus[0].TempC == nil || *gpus[0].TempC != 61 || s.cards[0].api != apiPMLog {
		t.Fatalf("%+v", gpus[0])
	}

	// neither Overdrive caps nor any call: no card
	buf.Reset()
	f = varesaADL()
	f.version, f.pmlog = nil, nil
	if s := NewAMDSensors(f); s != nil {
		t.Fatal(s)
	}
}

func TestADLCandidates(t *testing.T) {
	ads := []ADLAdapter{
		{Index: 0, VendorID: 1002},                // neither exists nor present: last
		{Index: 1, VendorID: 0x1002, Exist: true}, // the PCI form of the id counts too
		{Index: 2, VendorID: 0x10de, Exist: true}, // not AMD
		{Index: -1, VendorID: 1002, Exist: true},  // no index
		{Index: 4, VendorID: 1002, Present: true},
		{Index: 5, VendorID: 1002, Present: false, Exist: true},
	}
	order, reasons := adlCandidates(ads)
	if !slices.Equal(order, []int{1, 4, 5, 0}) {
		t.Fatal(order)
	}
	if reasons[2] != "skipped (not AMD)" || reasons[3] != "skipped (no index)" || reasons[0] != "" || reasons[5] != "" {
		t.Fatal(reasons)
	}
}

func TestMatchADLCards(t *testing.T) {
	rx := &adlCard{index: 0, loc: PCILoc{Bus: 0x2d}}
	apu := &adlCard{index: 3, loc: PCILoc{Bus: 0x0e}}
	unknown := &PCILoc{Bus: 0xFFFFFFFF, Device: 0xFFFF, Function: 0xFFFF}
	nv := GPU{Vendor: "nvidia", loc: &PCILoc{Bus: 0x2d}}
	for _, tc := range []struct {
		name  string
		gpus  []GPU
		cards []*adlCard
		want  []*adlCard
	}{
		{"by location, two AMD GPUs", []GPU{{Vendor: "amd", loc: &PCILoc{Bus: 0x0e}}, nv, {Vendor: "amd", loc: &PCILoc{Bus: 0x2d}}},
			[]*adlCard{rx, apu}, []*adlCard{apu, nil, rx}},
		{"location not in ADL: nothing", []GPU{{Vendor: "amd", loc: &PCILoc{Bus: 0x30}}}, []*adlCard{rx}, []*adlCard{nil}},
		{"unknown location: the card no located GPU took", []GPU{{Vendor: "amd", loc: &PCILoc{Bus: 0x0e}}, {Vendor: "amd", loc: unknown}},
			[]*adlCard{rx, apu}, []*adlCard{apu, rx}},
		{"no location at all, one card", []GPU{{Vendor: "amd"}}, []*adlCard{rx}, []*adlCard{rx}},
		{"two GPUs without location: no guessing", []GPU{{Vendor: "amd"}, {Vendor: "amd", loc: unknown}}, []*adlCard{rx},
			[]*adlCard{nil, nil}},
		{"one unlocated GPU, two cards left: no guessing", []GPU{{Vendor: "amd"}}, []*adlCard{rx, apu}, []*adlCard{nil}},
		{"not AMD: never", []GPU{nv}, []*adlCard{rx}, []*adlCard{nil}},
	} {
		if got := matchADLCards(tc.gpus, tc.cards); !slices.Equal(got, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}
