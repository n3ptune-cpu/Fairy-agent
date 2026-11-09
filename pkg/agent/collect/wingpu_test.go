package collect

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Counter instances as Windows names them (an AMD RX 5600 XT, an NVIDIA card, the Basic Render Driver).
const (
	amdLUID = "0x00000000_0x0000C1A3"
	nvLUID  = "0x00000000_0x0000D2B4"
)

func TestEngineUtilIsTheBusiestEngine(t *testing.T) {
	names := []string{
		"pid_1200_luid_0x00000000_0x0000c1a3_phys_0_eng_0_engtype_3D", // two processes on the 3D engine: 30 + 25
		"pid_4400_luid_0x00000000_0x0000C1A3_phys_0_eng_0_engtype_3D",
		"pid_1200_luid_0x00000000_0x0000C1A3_phys_0_eng_3_engtype_VideoDecode",
		"pid_1200_luid_0x00000000_0x0000C1A3_phys_0_eng_5_engtype_Copy",
		"pid_9_luid_0x00000000_0x0000D2B4_phys_0_eng_0_engtype_3D",
		"pid_9_luid_0x00000000_0x0000D2B4_phys_0_eng_1_engtype_Compute_0", // 70 + 60 on one engine: capped at 100
		"pid_10_luid_0x00000000_0x0000D2B4_phys_0_eng_1_engtype_Compute_0",
		"not a gpu engine",
		"pid_1_luid_0x00000000_0x0000C1A3_phys_0_eng_7_engtype_3D", // a broken negative reading
	}
	values := []float64{30, 25, 40, 5, 10, 70, 60, 99, -1}
	u := EngineUtil(names, values)
	if u[amdLUID] != 55 || u[nvLUID] != 100 || len(u) != 2 {
		t.Fatal(u)
	}
}

func TestAdapterMemorySumsPhysicalParts(t *testing.T) {
	m := AdapterMemory([]string{"luid_0x00000000_0x0000C1A3_phys_0", "luid_0x00000000_0x0000c1a3_phys_1", "luid_0x00000000_0x0000D2B4_phys_0", "total"},
		[]float64{2 << 30, 1 << 20, 512 << 20, 5})
	if m[amdLUID] != 2<<30+1<<20 || m[nvLUID] != 512<<20 || len(m) != 2 {
		t.Fatal(m)
	}
}

func TestShownAdaptersSkipsBasicRenderAndNVIDIAWithNvidiaSMI(t *testing.T) {
	all := []WinAdapter{
		{Name: "AMD Radeon RX 5600 XT", VendorID: 0x1002, VRAMTotal: 6 << 30, LUID: amdLUID},
		{Name: "NVIDIA GeForce RTX 3080", VendorID: 0x10de, VRAMTotal: 10 << 30, LUID: nvLUID},
		{Name: "Microsoft Basic Render Driver", VendorID: 0x1414, LUID: "0x00000000_0x0000E5F6", Software: true},
		{Name: "AMD Radeon RX 5600 XT", VendorID: 0x1002, LUID: amdLUID}, // the same adapter twice
	}
	if s := ShownAdapters(all, true); len(s) != 1 || s[0].LUID != amdLUID {
		t.Fatal("with nvidia-smi", s)
	}
	if s := ShownAdapters(all, false); len(s) != 2 || s[1].LUID != nvLUID {
		t.Fatal("without nvidia-smi", s)
	}
	if s := ShownAdapters(all[2:3], false); len(s) != 0 {
		t.Fatal("Basic Render Driver only", s)
	}
}

func TestWinGPUs(t *testing.T) {
	ad := []WinAdapter{{Name: " AMD Radeon RX 5600 XT ", VendorID: 0x1002, VRAMTotal: 6 << 30, LUID: amdLUID},
		{Name: "Intel(R) UHD Graphics 770", VendorID: 0x8086, LUID: "0x00000000_0x00001111"}}
	g := WinGPUs(ad, nil, nil) // first poll: rate counters have no value yet
	if len(g) != 2 || g[0].UtilPercent != nil || g[0].VRAMUsed != nil || *g[0].VRAMTotal != 6<<30 || g[1].VRAMTotal != nil {
		t.Fatalf("%+v", g)
	}
	g = WinGPUs(ad, EngineLoad{amdLUID: {"0/0/3d": 42.26}}, map[string]int64{amdLUID: 1 << 30})
	a, i := g[0], g[1]
	if a.Name != "AMD Radeon RX 5600 XT" || a.Vendor != "amd" || a.Source != "windows" || *a.UtilPercent != 42.3 || *a.VRAMUsed != 1<<30 ||
		a.TempC != nil || a.PowerW != nil {
		t.Fatalf("%+v", a)
	}
	if i.Vendor != "intel" || *i.UtilPercent != 0 || i.VRAMUsed != nil || i.Index != 1 {
		t.Fatalf("idle iGPU %+v", i)
	}
	if LUIDKey(0, 0xc1a3) != amdLUID || LUIDKey(-1, 1) != "0xFFFFFFFF_0x00000001" {
		t.Fatal(LUIDKey(0, 0xc1a3))
	}
}

// STWS-VARESA (Windows 10 IoT LTSC 21H2, one RX 5600 XT): DXGI lists the card three times with three LUIDs, the
// GPU counters know only one of them. The card is shown once, with the live readings.
func TestPhysicalAdaptersOneCardThreeDXGIEntries(t *testing.T) {
	rx := func(luid string, loc *PCILoc) WinAdapter {
		return WinAdapter{Name: "AMD Radeon RX 5600 XT", VendorID: 0x1002, DeviceID: 0x731f, SubSysID: 0x04e41da2, Revision: 0xca,
			VRAMTotal: 6 << 30, LUID: luid, Loc: loc}
	}
	live := "0x00000000_0x0001A2B3"
	pdhNames := []string{"pid_1200_luid_0x00000000_0x0001a2b3_phys_0_eng_0_engtype_3D", "luid_0x00000000_0x0001A2B3_phys_0"}
	present := CounterLUIDs(pdhNames)
	at := &PCILoc{Bus: 0x0b}
	for _, tc := range []struct {
		name string
		all  []WinAdapter
	}{
		{"same PCI location", []WinAdapter{rx("0x00000000_0x0000C001", at), rx("0x00000000_0x0000C002", at), rx(live, at)}},
		{"leftover LUIDs Windows cannot open (no location)", []WinAdapter{rx("0x00000000_0x0000C001", nil), rx("0x00000000_0x0000C002", nil), rx(live, at)}},
		{"no location at all", []WinAdapter{rx("0x00000000_0x0000C001", nil), rx("0x00000000_0x0000C002", nil), rx(live, nil)}},
	} {
		got := PhysicalAdapters(tc.all, present)
		if len(got) != 1 || got[0].LUID != live {
			t.Fatalf("%s: %+v", tc.name, got)
		}
		g := WinGPUs(got, EngineLoads(pdhNames, []float64{43, 0}), AdapterMemory(pdhNames, []float64{0, 1.7 * (1 << 30)}))
		if len(g) != 1 || *g[0].UtilPercent != 43 || g[0].VRAMUsed == nil || g[0].Index != 0 {
			t.Fatalf("%s: %+v", tc.name, g)
		}
	}
	// before the counters are read: one entry per PCI location
	if got := PhysicalAdapters([]WinAdapter{rx("0x00000000_0x0000C001", at), rx(live, at)}, nil); len(got) != 1 {
		t.Fatal("not read yet", got)
	}
	// two identical cards in two slots stay two, and so do two that both have counters
	other := &PCILoc{Bus: 0x0c}
	second := "0x00000000_0x0002B3C4"
	both := map[string]bool{live: true, second: true}
	if got := PhysicalAdapters([]WinAdapter{rx(live, at), rx(second, other)}, both); len(got) != 2 {
		t.Fatal("two cards", got)
	}
	if got := PhysicalAdapters([]WinAdapter{rx(live, nil), rx(second, nil), rx("0x00000000_0x0000C001", nil)}, both); len(got) != 2 {
		t.Fatal("two live cards without locations", got)
	}
	// different cards are never merged
	intel := WinAdapter{Name: "Intel(R) UHD Graphics 770", VendorID: 0x8086, DeviceID: 0x4680, LUID: "0x00000000_0x00001111"}
	if got := PhysicalAdapters([]WinAdapter{rx(live, at), intel}, present); len(got) != 2 {
		t.Fatal("AMD + Intel", got)
	}
}

// A one-GPU PC with a leftover DXGI entry for the same RX 5600 XT: dwm.exe and the game have GPU Engine instances
// on both LUIDs (so both looked "live"), only the real one has a GPU Adapter Memory instance. Before: two RX
// 5600 XT and no Radeon temperature (ADL is matched to the only AMD GPU). Now: one card, with temperature.
func TestDropGhostsOneRadeonTwoLiveLUIDs(t *testing.T) {
	live, ghost := "0x00000000_0x0001A2B3", "0x00000000_0x0000C001"
	rx := func(luid string, sub uint32) WinAdapter {
		return WinAdapter{Name: "AMD Radeon RX 5600 XT", VendorID: 0x1002, DeviceID: 0x731f, SubSysID: sub, VRAMTotal: 6 << 30, LUID: luid}
	}
	all := []WinAdapter{rx(ghost, 0), rx(live, 0x04e41da2)} // the leftover even reports other subsystem ids
	eng := []string{
		"pid_812_luid_0x00000000_0x0000C001_phys_0_eng_0_engtype_3D", // dwm.exe on the leftover LUID
		"pid_812_luid_0x00000000_0x0001A2B3_phys_0_eng_0_engtype_3D",
		"pid_4400_luid_0x00000000_0x0001A2B3_phys_0_eng_0_engtype_3D",
	}
	memNames := []string{"luid_0x00000000_0x0001A2B3_phys_0"}
	present := CounterLUIDs(eng, memNames)
	if got := PhysicalAdapters(all, present); len(got) != 2 {
		t.Fatalf("precondition: engine instances alone keep the ghost: %+v", got)
	}
	shown := PhysicalAdapters(DropGhosts(all, MemoryLUIDs(memNames)), present)
	if len(shown) != 1 || shown[0].LUID != live {
		t.Fatalf("%+v", shown)
	}
	gpus := WinGPUs(shown, EngineLoads(eng, []float64{1, 20, 30}), AdapterMemory(memNames, []float64{1 << 30}))
	f := &fakeADL{adapters: []ADLAdapter{{Index: 0, Bus: 0x0b, VendorID: 0x1002, Name: "AMD Radeon RX 5600 XT"}},
		version: map[int]int{0: 8}, pmlog: map[int][]ADLSensor{0: sensors(map[int]int32{pmlogTempEdge: 57, pmlogBoardPower: 120})}}
	NewAMDSensors(f).Attach(gpus) // the leftover had no PCI location: matched as the only AMD GPU
	if len(gpus) != 1 || gpus[0].TempC == nil || *gpus[0].TempC != 57 || gpus[0].Source != "amd" || *gpus[0].UtilPercent != 50 {
		t.Fatalf("%+v", gpus)
	}
	// counter not read (or not available): nothing is dropped
	if got := DropGhosts(all, nil); len(got) != 2 {
		t.Fatal(got)
	}
}

func TestDropGhostsIntelUHDAndTwins(t *testing.T) {
	uhd := func(luid string) WinAdapter {
		return WinAdapter{Name: "Intel(R) UHD Graphics 770", VendorID: 0x8086, DeviceID: 0x4680, VRAMTotal: 128 << 20, LUID: luid}
	}
	a, b := "0x00000000_0x00001111", "0x00000000_0x00002222"
	if got := DropGhosts([]WinAdapter{uhd(a), uhd(b)}, MemoryLUIDs([]string{"luid_0x00000000_0x00002222_phys_0"})); len(got) != 1 || got[0].LUID != b {
		t.Fatal("2x Intel UHD", got)
	}
	// two real identical cards: both have memory instances, both stay (also through PhysicalAdapters)
	twin := func(luid string, bus uint32) WinAdapter {
		return WinAdapter{Name: "AMD Radeon RX 7900 XTX", VendorID: 0x1002, DeviceID: 0x744c, VRAMTotal: 24 << 30, LUID: luid, Loc: &PCILoc{Bus: bus}}
	}
	mem := []string{"luid_0x00000000_0x00001111_phys_0", "luid_0x00000000_0x00002222_phys_0"}
	twins := []WinAdapter{twin(a, 3), twin(b, 4)}
	if got := PhysicalAdapters(DropGhosts(twins, MemoryLUIDs(mem)), CounterLUIDs(mem)); len(got) != 2 {
		t.Fatal("twins", got)
	}
	// a different card without a memory instance is not a ghost of another model
	other := WinAdapter{Name: "Intel(R) UHD Graphics 770", VendorID: 0x8086, DeviceID: 0x4680, VRAMTotal: 128 << 20, LUID: "0x00000000_0x00003333"}
	if got := DropGhosts([]WinAdapter{twin(a, 3), other}, MemoryLUIDs(mem[:1])); len(got) != 2 {
		t.Fatal("different model", got)
	}
}

// NSX-FURINA (Windows 11 laptop, i7-12650H's Intel UHD + RTX 3050 Laptop): PDH has three LUIDs, ALL with
// `GPU Adapter Memory` and `GPU Engine` instances (0x...FA66 the NVIDIA card: 624 engine instances, 0x...FEAA
// and 0x...FE16 the Intel UHD: 182 and 170). DXGI lists the Intel UHD twice. Windows' kernel puts both Intel
// LUIDs at the same PCI location 00:02.0, so they are one card, with the counters of both.
const (
	furinaNV    = "0x00000000_0x0000FA66"
	furinaUHD1  = "0x00000000_0x0000FEAA"
	furinaUHD2  = "0x00000000_0x0000FE16"
	furinaNVBus = 0x01
)

// furinaCounters builds the counter instances: per LUID n engine instances (processes x engines, the engine
// types an Intel / NVIDIA driver names), and one memory instance each.
func furinaCounters(t *testing.T) (eng []string, engVals []float64, mem []string, memVals []float64) {
	t.Helper()
	types := []string{"3D", "VideoDecode", "VideoProcessing", "Copy", "Compute_0", "VideoEncode", "Security"}
	add := func(luid string, n int, busy func(pid, eng int) float64) {
		lo := strings.ToLower(luid) // PDH writes the hex digits in either case
		for i := range n {
			pid, e := 1000+i/len(types), i%len(types)
			eng = append(eng, fmt.Sprintf("pid_%d_luid_%s_phys_0_eng_%d_engtype_%s", pid, lo, e, types[e]))
			engVals = append(engVals, busy(pid, e))
		}
	}
	add(furinaNV, 624, func(pid, e int) float64 { return 0 })
	// the browser (pid 1000) renders through the first Intel LUID, dwm.exe (pid 1001) through the second
	add(furinaUHD1, 182, func(pid, e int) float64 {
		if pid == 1000 && e == 0 {
			return 12
		}
		return 0
	})
	add(furinaUHD2, 170, func(pid, e int) float64 {
		if pid == 1001 && e == 0 {
			return 7
		}
		if pid == 1001 && e == 1 {
			return 3
		}
		return 0
	})
	if len(eng) != 624+182+170 {
		t.Fatal(len(eng))
	}
	for _, l := range []string{furinaNV, furinaUHD1, furinaUHD2} {
		mem = append(mem, "luid_"+l+"_phys_0")
	}
	memVals = []float64{1288 << 20, 40 << 20, 8 << 20}
	return
}

func furinaAdapters(loc bool) []WinAdapter {
	at := func(bus, dev uint32) *PCILoc {
		if !loc {
			return nil
		}
		return &PCILoc{Bus: bus, Device: dev}
	}
	return []WinAdapter{
		// DXGI's order on a laptop: the iGPU that drives the panel first, then the NVIDIA card, then the second
		// Intel entry, which reports other subsystem / revision ids (as the RX 5600 XT's leftover did)
		{Name: "Intel(R) UHD Graphics", VendorID: 0x8086, DeviceID: 0x46a3, SubSysID: 0x3f9a17aa, Revision: 0x0c,
			VRAMTotal: 128 << 20, LUID: furinaUHD2, Loc: at(0, 2)},
		{Name: "NVIDIA GeForce RTX 3050 Laptop GPU", VendorID: 0x10de, DeviceID: 0x25a2, SubSysID: 0x3f9a17aa, Revision: 0xa1,
			VRAMTotal: 4 << 30, LUID: furinaNV, Loc: at(furinaNVBus, 0)},
		{Name: "Intel(R) UHD Graphics", VendorID: 0x8086, DeviceID: 0x46a3, VRAMTotal: 128 << 20, LUID: furinaUHD1, Loc: at(0, 2)},
		{Name: "Microsoft Basic Render Driver", VendorID: 0x1414, DeviceID: 0x8c, Software: true, LUID: "0x00000000_0x0000F00D"},
	}
}

func TestFurinaOneIntelUHD(t *testing.T) {
	eng, engVals, mem, memVals := furinaCounters(t)
	memLUIDs := MemoryLUIDs(mem)
	for _, nvidiaSMI := range []bool{true, false} {
		shown := ShownAdapters(furinaAdapters(true), nvidiaSMI)
		if got := DropGhosts(shown, memLUIDs); len(got) != len(shown) {
			t.Fatalf("precondition: every LUID has a memory instance, DropGhosts keeps all: %+v", got)
		}
		grouped := GroupAdapters(DropGhosts(shown, memLUIDs), CounterActivity(eng, mem))
		want := 1
		if !nvidiaSMI {
			want = 2
		}
		if len(grouped) != want {
			t.Fatalf("nvidia-smi %v: %d entries: %+v", nvidiaSMI, len(grouped), grouped)
		}
		uhd := grouped[0]
		// the busier LUID (182 engine instances) represents the card, the other one is merged into it
		if uhd.LUID != furinaUHD1 || len(uhd.Also) != 1 || uhd.Also[0] != furinaUHD2 {
			t.Fatalf("Intel entry %+v", uhd)
		}
		gpus := WinGPUs(grouped, EngineLoads(eng, engVals), AdapterMemory(mem, memVals))
		g := gpus[0]
		// 3D: 12 % (browser via FEAA) + 7 % (dwm via FE16) on the same engine; memory: both LUIDs' allocations
		if g.UtilPercent == nil || *g.UtilPercent != 19 || g.VRAMUsed == nil || *g.VRAMUsed != 48<<20 || *g.VRAMTotal != 128<<20 ||
			g.Vendor != "intel" || g.Index != 0 {
			t.Fatalf("Intel GPU %+v util %v used %v", g, g.UtilPercent, g.VRAMUsed)
		}
		if !nvidiaSMI {
			if n := gpus[1]; n.Vendor != "nvidia" || n.UtilPercent == nil || *n.UtilPercent != 0 || *n.VRAMUsed != 1288<<20 {
				t.Fatalf("NVIDIA GPU %+v", n)
			}
		}
		// per-process GPU memory on either Intel LUID goes to that one card
		idx := GPULUIDIndex(gpus, nil)
		if idx[furinaUHD1] != 0 || idx[furinaUHD2] != 0 {
			t.Fatalf("LUID index %v", idx)
		}
	}
}

// The same with the DXGI order reversed: still one card, represented by the busier LUID.
func TestFurinaOrderDoesNotMatter(t *testing.T) {
	eng, _, mem, _ := furinaCounters(t)
	ad := furinaAdapters(true)
	ad[0], ad[2] = ad[2], ad[0]
	got := GroupAdapters(ShownAdapters(ad, true), CounterActivity(eng, mem))
	if len(got) != 1 || got[0].LUID != furinaUHD1 || !slices.Equal(got[0].Also, []string{furinaUHD2}) {
		t.Fatalf("%+v", got)
	}
	// before the counters are read: grouped by location alone, the first DXGI entry represents it
	got = GroupAdapters(ShownAdapters(furinaAdapters(true), true), nil)
	if len(got) != 1 || got[0].LUID != furinaUHD2 || !slices.Equal(got[0].Also, []string{furinaUHD1}) {
		t.Fatalf("not read yet: %+v", got)
	}
}

// D3DKMT could not give locations: the rule before applies (DXGI's ids differ, both have counters: two
// entries). Documented fallback; no merging on guesses.
func TestFurinaWithoutLocations(t *testing.T) {
	eng, _, mem, _ := furinaCounters(t)
	if got := GroupAdapters(ShownAdapters(furinaAdapters(false), true), CounterActivity(eng, mem)); len(got) != 2 {
		t.Fatalf("%+v", got)
	}
}

// Different device ids at one location are never merged (a bogus location from a virtual adapter).
func TestSameLocationDifferentDevice(t *testing.T) {
	at := &PCILoc{}
	a := WinAdapter{Name: "Virtual Display", VendorID: 0x1234, DeviceID: 1, LUID: "0x00000000_0x00000001", Loc: at}
	b := WinAdapter{Name: "Other Virtual", VendorID: 0x1234, DeviceID: 2, LUID: "0x00000000_0x00000002", Loc: at}
	c := WinAdapter{Name: "Other Vendor", VendorID: 0x4321, DeviceID: 1, LUID: "0x00000000_0x00000003", Loc: at}
	if got := GroupAdapters([]WinAdapter{a, b, c}, nil); len(got) != 3 {
		t.Fatalf("%+v", got)
	}
}

// Intel's engine instance names (engtype with digits and underscores) parse; engines of one type stay apart
// within a LUID (two Copy engines are two engines), the same engine is added across LUIDs.
func TestEngineLoadsIntelNames(t *testing.T) {
	names := []string{
		"pid_5_luid_0x00000000_0x0000FEAA_phys_0_eng_3_engtype_Copy",
		"pid_5_luid_0x00000000_0x0000FEAA_phys_0_eng_4_engtype_Copy",
		"pid_5_luid_0x00000000_0x0000fe16_phys_0_eng_3_engtype_Copy",
		"pid_6_luid_0x00000000_0x0000FEAA_phys_0_eng_7_engtype_Compute_1",
		"pid_7_luid_0x00000000_0x0000FEAA_phys_0_eng_9", // no engtype at all
	}
	l := EngineLoads(names, []float64{30, 30, 25, 40, 45})
	if got := l.Util(furinaUHD1); got != 45 {
		t.Fatalf("one LUID: %v (%v)", got, l)
	}
	if got := l.Util(furinaUHD1, furinaUHD2); got != 55 { // eng 3 Copy: 30 + 25
		t.Fatalf("both LUIDs: %v", got)
	}
	if got := l.Util("0x00000000_0x00009999"); got != 0 {
		t.Fatal(got)
	}
	if u := EngineUtil(names, []float64{30, 30, 25, 40, 45}); u[furinaUHD2] != 25 || u[furinaUHD1] != 45 {
		t.Fatal(u)
	}
}
