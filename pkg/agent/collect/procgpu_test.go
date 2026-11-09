package collect

import (
	"reflect"
	"testing"
)

func TestProcessGPUMemoryParsing(t *testing.T) {
	names := []string{
		"pid_4400_luid_0x00000000_0x0000C1A3_phys_0",
		"pid_4400_luid_0x00000000_0x0000c1a3_phys_1", // a second physical part of the same adapter: summed
		"pid_4400_luid_0x00000000_0x0000D2B4_phys_0",
		"pid_812_luid_0x00000000_0x0000D2B4_phys_0",
		"pid_9_luid_0x00000000_0x0000D2B4_phys_0",  // zero: left out
		"pid_10_luid_0x00000000_0x0000D2B4_phys_0", // a broken negative reading
		"luid_0x00000000_0x0000D2B4_phys_0",        // an adapter (not a process) instance
		"pid_0_luid_0x00000000_0x0000D2B4_phys_0",
		"pid_x_luid_0x00000000_0x0000D2B4_phys_0",
		"pid_77_luid_0x00000000_0x0000D2B4_phys_0", // no value
	}
	got := ProcessGPUMemory(names, []float64{2 << 30, 1 << 20, 300 << 20, 64 << 20, 0, -5, 1 << 30, 1, 1})
	want := map[int]map[string]int64{
		4400: {amdLUID: 2<<30 + 1<<20, nvLUID: 300 << 20},
		812:  {nvLUID: 64 << 20},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestNvidiaBusID(t *testing.T) {
	g, ok := ParseNvidiaGPULine("0, GPU-1234, NVIDIA GeForce RTX 3080, 37, 1024, 10240, 61, 220.5, 00000000:0B:00.0")
	if !ok || g.loc == nil || *g.loc != (PCILoc{Bus: 0x0b}) {
		t.Fatalf("%+v %v", g, g.loc)
	}
	for in, want := range map[string]*PCILoc{"0000:65:00.1": {Bus: 0x65, Function: 1}, "01:00.0": {Bus: 1}, "[N/A]": nil, "": nil, "zz:00.0": nil} {
		if got := pciBusID(in); !reflect.DeepEqual(got, want) {
			t.Fatal(in, got)
		}
	}
	// an older line without the bus id still parses
	if g, ok := ParseNvidiaGPULine("0, GPU-1, Tesla P4, 3, 0, 7680, 40, 20"); !ok || g.loc != nil {
		t.Fatal(g, ok)
	}
}

// A gaming PC: an RTX 3080 read by nvidia-smi (index 0) and the CPU's Intel UHD read through Windows (index 1),
// plus a leftover DXGI entry of the RTX and the Basic Render Driver.
func TestGPULUIDIndexAndMerge(t *testing.T) {
	const (
		rtxLUID   = "0x00000000_0x0000AAAA"
		ghostLUID = "0x00000000_0x0000BBBB"
		uhdLUID   = "0x00000000_0x0000CCCC"
		swLUID    = "0x00000000_0x0000DDDD"
	)
	at := &PCILoc{Bus: 1}
	adapters := []WinAdapter{
		{Name: "NVIDIA GeForce RTX 3080", VendorID: 0x10de, DeviceID: 0x2206, LUID: rtxLUID, Loc: at},
		{Name: "NVIDIA GeForce RTX 3080", VendorID: 0x10de, DeviceID: 0x2206, LUID: ghostLUID},
		{Name: "Intel(R) UHD Graphics 770", VendorID: 0x8086, DeviceID: 0x4680, LUID: uhdLUID, Loc: &PCILoc{Device: 2}},
		{Name: "Microsoft Basic Render Driver", VendorID: 0x1414, LUID: swLUID, Software: true},
	}
	nv, _ := ParseNvidiaGPULine("0, GPU-1, NVIDIA GeForce RTX 3080, 37, 1024, 10240, 61, 220.5, 00000000:01:00.0")
	gpus := append([]GPU{nv}, WinGPUs(adapters[2:3], nil, nil)...)
	idx := GPULUIDIndex(gpus, adapters)
	if idx[rtxLUID] != 0 || idx[uhdLUID] != 1 || len(idx) != 2 {
		t.Fatalf("by location / own LUID: %v", idx)
	}
	// nvidia-smi without the bus id (or Windows without the location): the only NVIDIA card gets every NVIDIA LUID
	nv.loc = nil
	gpus[0] = nv
	if idx = GPULUIDIndex(gpus, adapters); idx[rtxLUID] != 0 || idx[ghostLUID] != 0 || idx[uhdLUID] != 1 || len(idx) != 3 {
		t.Fatalf("fallback: %v", idx)
	}
	// two NVIDIA cards without locations: no guessing
	two := []GPU{nv, nv}
	if idx := GPULUIDIndex(two, adapters); len(idx) != 0 {
		t.Fatalf("two unknown cards: %v", idx)
	}

	perPID := ProcessGPUMemory([]string{
		"pid_4400_luid_0x00000000_0x0000AAAA_phys_0", // the game on the RTX
		"pid_4400_luid_0x00000000_0x0000CCCC_phys_0", // and a little on the iGPU
		"pid_812_luid_0x00000000_0x0000CCCC_phys_0",  // dwm.exe on the iGPU
		"pid_99_luid_0x00000000_0x0000DDDD_phys_0",   // only on the Basic Render Driver: not a reported GPU
	}, []float64{6 << 30, 50 << 20, 120 << 20, 1 << 20})
	byIdx := ProcGPUByIndex(perPID, GPULUIDIndex(gpus, adapters), len(gpus))
	want := map[int][]int64{4400: {6 << 30, 50 << 20}, 812: {0, 120 << 20}}
	if !reflect.DeepEqual(byIdx, want) {
		t.Fatalf("%v", byIdx)
	}

	// nvidia-smi on Windows (WDDM): every used_memory is [N/A], so its map is empty (not nil). Before, that empty
	// map won and every process showed "–". Merging takes the larger value per GPU.
	smi := ParseComputeApps([]byte("4400, GPU-1, [N/A]\n812, GPU-1, [N/A]\n"), map[string]int{"GPU-1": 0}, 1)
	if smi == nil || len(smi) != 0 {
		t.Fatal(smi)
	}
	if got := MergeComputeApps(smi, byIdx); !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	// Linux / TCC: nvidia-smi has numbers, Windows none; and when both have one, the larger counts (not the sum)
	got := MergeComputeApps(map[int][]int64{7: {1 << 30}}, map[int][]int64{7: {2 << 30, 5}, 8: {0, 9}})
	if !reflect.DeepEqual(got, map[int][]int64{7: {2 << 30, 5}, 8: {0, 9}}) {
		t.Fatalf("%v", got)
	}
	if MergeComputeApps(nil, map[int][]int64{}) != nil {
		t.Fatal("nothing from anyone must stay nil (unknown)")
	}
}
