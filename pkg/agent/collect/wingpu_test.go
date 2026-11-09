package collect

import "testing"

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
	g = WinGPUs(ad, map[string]float64{amdLUID: 42.26}, map[string]int64{amdLUID: 1 << 30})
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
		g := WinGPUs(got, EngineUtil(pdhNames, []float64{43, 0}), AdapterMemory(pdhNames, []float64{0, 1.7 * (1 << 30)}))
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
