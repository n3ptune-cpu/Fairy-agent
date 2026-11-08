package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// amdgpuFixture builds a fake /sys with three amdgpu cards and one Intel card. It is made at test time (not kept
// in testdata) because sysfs names contain ':', which Go module zips and Windows checkouts do not allow.
func amdgpuFixture(t *testing.T) string {
	t.Helper()
	sys := t.TempDir()
	const pci = "devices/pci0000:00/"
	files := map[string]string{
		"class/drm/card1-eDP-1/status":        "connected",
		pci + "0000:00:02.0/gpu_busy_percent": "50",
		// discrete GPU, busy, average power
		pci + "0000:03:00.0/device":                      "0x73bf",
		pci + "0000:03:00.0/gpu_busy_percent":            "99",
		pci + "0000:03:00.0/hwmon/hwmon4/power1_average": "250123456",
		pci + "0000:03:00.0/hwmon/hwmon4/temp1_input":    "71000",
		pci + "0000:03:00.0/mem_info_vram_total":         "17163091968",
		pci + "0000:03:00.0/mem_info_vram_used":          "4294967296",
		pci + "0000:03:00.0/power/runtime_status":        "active",
		pci + "0000:03:00.0/product_name":                "AMD Radeon RX 6800 XT",
		// integrated GPU (APU)
		pci + "0000:04:00.0/device":                    "0x15bf",
		pci + "0000:04:00.0/gpu_busy_percent":          "7",
		pci + "0000:04:00.0/hwmon/hwmon3/freq1_input":  "800000000",
		pci + "0000:04:00.0/hwmon/hwmon3/power1_input": "8123000",
		pci + "0000:04:00.0/hwmon/hwmon3/temp1_input":  "45000",
		pci + "0000:04:00.0/mem_info_gtt_total":        "8589934592",
		pci + "0000:04:00.0/mem_info_gtt_used":         "1073741824",
		pci + "0000:04:00.0/mem_info_vram_total":       "536870912",
		pci + "0000:04:00.0/mem_info_vram_used":        "268435456",
		pci + "0000:04:00.0/power/runtime_status":      "active",
		// runtime-suspended GPU
		pci + "0000:05:00.0/device":               "0x7340",
		pci + "0000:05:00.0/gpu_busy_percent":     "0",
		pci + "0000:05:00.0/power/runtime_status": "suspended",
	}
	links := map[string]string{
		"class/drm/card0/device":    "../../../" + pci + "0000:00:02.0",
		"class/drm/card1/device":    "../../../" + pci + "0000:04:00.0",
		"class/drm/card2/device":    "../../../" + pci + "0000:03:00.0",
		"class/drm/card3/device":    "../../../" + pci + "0000:05:00.0",
		pci + "0000:00:02.0/driver": "../../bus/pci/drivers/i915",
		pci + "0000:03:00.0/driver": "../../bus/pci/drivers/amdgpu",
		pci + "0000:04:00.0/driver": "../../bus/pci/drivers/amdgpu",
		pci + "0000:05:00.0/driver": "../../bus/pci/drivers/amdgpu",
	}
	for name, v := range files {
		p := filepath.Join(sys, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := writeFile(p, v); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range links {
		p := filepath.Join(sys, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	return sys
}

func TestAMDGPUFixture(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture uses symlinks")
	}
	sys := amdgpuFixture(t)
	cards := AMDCards(sys)
	if len(cards) != 3 { // card0 is Intel (i915); card1-eDP-1 is a connector
		t.Fatalf("cards %v", cards)
	}
	a := NewAMDGPU(sys, time.Second)
	gpus := a.GPUs()
	if len(gpus) != 3 {
		t.Fatalf("%+v", gpus)
	}
	igpu, dgpu, asleep := gpus[0], gpus[1], gpus[2]
	// integrated: no product_name, power1_input, VRAM = the carve-out (GTT not added)
	if igpu.Name != "AMD Radeon (amdgpu 1002:15bf)" || igpu.Vendor != "amd" || *igpu.UtilPercent != 7 ||
		*igpu.VRAMUsed != 256<<20 || *igpu.VRAMTotal != 512<<20 || *igpu.TempC != 45 || *igpu.PowerW != 8.1 {
		t.Fatalf("igpu %+v", igpu)
	}
	if dgpu.Name != "AMD Radeon RX 6800 XT" || *dgpu.UtilPercent != 99 || *dgpu.VRAMTotal != 17163091968 ||
		*dgpu.TempC != 71 || *dgpu.PowerW != 250.1 {
		t.Fatalf("dgpu %+v", dgpu)
	}
	// runtime-suspended: not woken up, reported idle with nothing else
	if asleep.Name != "AMD Radeon (amdgpu 1002:7340)" || *asleep.UtilPercent != 0 || asleep.VRAMTotal != nil ||
		asleep.TempC != nil || asleep.PowerW != nil {
		t.Fatalf("asleep %+v", asleep)
	}
	if a.ComputeApps(t.Context()) != nil {
		t.Fatal("no per-process VRAM from sysfs")
	}
}

func TestAMDGPUNone(t *testing.T) {
	if NewAMDGPU(t.TempDir(), time.Second) != nil {
		t.Fatal("no cards = no reader")
	}
}

func TestReadAMDGPUBadValues(t *testing.T) {
	dir := t.TempDir()
	write := func(name, v string) {
		t.Helper()
		if err := writeFile(dir+"/"+name, v); err != nil {
			t.Fatal(err)
		}
	}
	write("gpu_busy_percent", "250")
	write("mem_info_vram_used", "900")
	write("mem_info_vram_total", "100") // used > total
	write("product_name", "bad\x01name")
	write("device", "zz")
	g := ReadAMDGPU(dir, 0)
	if g.UtilPercent != nil || g.VRAMUsed != nil || g.Name != "AMD Radeon (amdgpu)" {
		t.Fatalf("%+v", g)
	}
}

func writeFile(path, s string) error { return os.WriteFile(path, []byte(s+"\n"), 0o644) }
