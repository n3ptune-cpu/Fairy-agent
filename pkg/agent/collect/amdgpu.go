package collect

// AMD GPUs on Linux through the amdgpu kernel driver's own sysfs files (no extra software, nothing loaded):
//
//	/sys/class/drm/cardN/device/driver            -> .../amdgpu
//	/sys/class/drm/cardN/device/gpu_busy_percent  0-100
//	/sys/class/drm/cardN/device/mem_info_vram_used, mem_info_vram_total   bytes
//	/sys/class/drm/cardN/device/product_name      (many cards; often missing on integrated GPUs)
//	/sys/class/drm/cardN/device/hwmon/hwmonM/temp1_input        milli-°C ("edge")
//	/sys/class/drm/cardN/device/hwmon/hwmonM/power1_average or power1_input   µW
//
// VRAM on an integrated Radeon is the small carve-out the firmware reserves; what the GPU borrows from system RAM
// on top (GTT) is already part of the machine's memory figure, so it is not added here.
//
// A discrete GPU that the kernel has put to sleep (runtime power management, typical for the second GPU of a
// laptop) is not woken: reading these files would power it up, so it is reported idle with no other values.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var drmCardRe = regexp.MustCompile(`^card([0-9]+)$`)

// AMDCards returns the device directories of the amdgpu-driven cards under sysRoot (/sys), ordered by card number.
func AMDCards(sysRoot string) []string {
	ents, _ := os.ReadDir(filepath.Join(sysRoot, "class", "drm"))
	type card struct {
		n   int
		dir string
	}
	var cards []card
	for _, e := range ents {
		m := drmCardRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		dev := filepath.Join(sysRoot, "class", "drm", e.Name(), "device")
		drv, err := os.Readlink(filepath.Join(dev, "driver"))
		if err != nil || filepath.Base(drv) != "amdgpu" {
			continue
		}
		n, _ := strconv.Atoi(m[1])
		cards = append(cards, card{n, dev})
	}
	sort.Slice(cards, func(i, j int) bool { return cards[i].n < cards[j].n })
	out := make([]string, len(cards))
	for i, c := range cards {
		out[i] = c.dir
	}
	return out
}

// ReadAMDGPU reads one amdgpu card's device directory.
func ReadAMDGPU(dev string, index int) GPU {
	g := GPU{Index: index, Vendor: "amd", Name: amdName(dev)}
	if s, _ := readTrim(filepath.Join(dev, "power", "runtime_status")); s == "suspended" {
		g.UtilPercent = P(0.0)
		return g
	}
	if v, ok := readNum(filepath.Join(dev, "gpu_busy_percent")); ok && v >= 0 && v <= 100 {
		g.UtilPercent = P(v)
	}
	used, okU := readNum(filepath.Join(dev, "mem_info_vram_used"))
	total, okT := readNum(filepath.Join(dev, "mem_info_vram_total"))
	if okU && okT && total > 0 && used >= 0 && used <= total {
		g.VRAMUsed, g.VRAMTotal = P(int64(used)), P(int64(total))
	}
	hw, _ := filepath.Glob(filepath.Join(dev, "hwmon", "hwmon*"))
	sort.Strings(hw)
	for _, h := range hw {
		if g.TempC == nil {
			if v, ok := readNum(filepath.Join(h, "temp1_input")); ok && v > -40000 && v < 150000 {
				g.TempC = P(Round(v/1000, 1))
			}
		}
		if g.PowerW == nil {
			for _, f := range []string{"power1_average", "power1_input"} {
				if v, ok := readNum(filepath.Join(h, f)); ok && v >= 0 && v < 1e9 {
					g.PowerW = P(Round(v/1e6, 1))
					break
				}
			}
		}
	}
	return g
}

// amdName is the card's product name, else "AMD Radeon (amdgpu 1002:xxxx)" from the PCI ids.
func amdName(dev string) string {
	if s, ok := readTrim(filepath.Join(dev, "product_name")); ok && s != "" && isPrintable(s) {
		return s
	}
	id, _ := readTrim(filepath.Join(dev, "device"))
	id = strings.TrimPrefix(strings.ToLower(id), "0x")
	if len(id) == 4 && isHex(id) {
		return "AMD Radeon (amdgpu 1002:" + id + ")"
	}
	return "AMD Radeon (amdgpu)"
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return len(s) <= 128
}

func isHex(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

// AMDGPU reports the amdgpu cards (re-read at most every interval; sysfs reads are cheap).
type AMDGPU struct {
	sys      string
	interval time.Duration

	mu    sync.Mutex
	cards []string
	gpus  []GPU
	at    time.Time
}

// NewAMDGPU returns a reader for the amdgpu cards under sysRoot, or nil when there are none.
func NewAMDGPU(sysRoot string, interval time.Duration) *AMDGPU {
	cards := AMDCards(sysRoot)
	if len(cards) == 0 {
		return nil
	}
	return &AMDGPU{sys: sysRoot, interval: interval, cards: cards}
}

// Cards is the number of amdgpu cards found at start.
func (a *AMDGPU) Cards() int { return len(a.cards) }

// GPUs returns the latest readings.
func (a *AMDGPU) GPUs() []GPU {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.gpus != nil && time.Since(a.at) < a.interval {
		return a.gpus
	}
	gpus := make([]GPU, 0, len(a.cards))
	for i, dev := range a.cards {
		gpus = append(gpus, ReadAMDGPU(dev, i))
	}
	a.gpus, a.at = gpus, time.Now()
	return gpus
}

// ComputeApps is nil: amdgpu has no per-process VRAM list in sysfs.
func (a *AMDGPU) ComputeApps(context.Context) map[int][]int64 { return nil }
