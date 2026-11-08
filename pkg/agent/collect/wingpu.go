package collect

// GPUs on Windows from what Windows itself reports, for cards without a vendor tool the agent uses (AMD,
// Intel, integrated): the adapters from DXGI (name, vendor, dedicated VRAM, LUID) and two PDH counter sets
// that Task Manager uses too:
//
//	\GPU Engine(*)\Utilization Percentage   instances  pid_<pid>_luid_0x<hi>_0x<lo>_phys_<n>_eng_<n>_engtype_<type>
//	\GPU Adapter Memory(*)\Dedicated Usage  instances  luid_0x<hi>_0x<lo>_phys_<n>
//
// Utilization is Task Manager's: each engine's percentage summed over the processes using it, and the
// adapter's value is its busiest engine. No temperature or watts (those need the vendor's library). This file
// holds the platform-independent part (parsing, sums) so it is tested everywhere.

import (
	"fmt"
	"regexp"
	"strings"
)

// WinAdapter is one display adapter as DXGI describes it.
type WinAdapter struct {
	Name      string
	VendorID  uint32
	VRAMTotal int64  // dedicated video memory, bytes (0: none / shared only)
	LUID      string // "0x<hi>_0x<lo>", upper-case hex, as in PDH instance names
	Software  bool   // Microsoft Basic Render Driver and other software adapters
}

// normLUID writes a LUID from a counter name like LUIDKey does (hex digits upper-case, "0x" prefixes).
func normLUID(s string) string { return strings.ReplaceAll(strings.ToUpper(s), "0X", "0x") }

// LUIDKey formats an adapter LUID the way PDH instance names do.
func LUIDKey(high int32, low uint32) string { return fmt.Sprintf("0x%08X_0x%08X", uint32(high), low) }

// PCIVendor names a PCI vendor id.
func PCIVendor(id uint32) string {
	switch id {
	case 0x10de:
		return "nvidia"
	case 0x1002, 0x1022:
		return "amd"
	case 0x8086:
		return "intel"
	}
	return "other"
}

var (
	engineRe = regexp.MustCompile(`(?i)luid_(0x[0-9a-f]{8}_0x[0-9a-f]{8})_phys_(\d+)_eng_(\d+)`)
	memRe    = regexp.MustCompile(`(?i)^luid_(0x[0-9a-f]{8}_0x[0-9a-f]{8})_phys_\d+$`)
)

// EngineUtil turns `\GPU Engine(*)\Utilization Percentage` values into each adapter's utilization (LUID ->
// percent): per engine the sum over processes, per adapter the busiest engine, at most 100.
func EngineUtil(names []string, values []float64) map[string]float64 {
	engines := map[string]float64{} // luid/phys/eng -> sum
	for i, n := range names {
		m := engineRe.FindStringSubmatch(n)
		if m == nil || values[i] < 0 {
			continue
		}
		engines[normLUID(m[1])+"/"+m[2]+"/"+m[3]] += values[i]
	}
	out := map[string]float64{}
	for k, v := range engines {
		luid := k[:strings.IndexByte(k, '/')]
		if v > out[luid] {
			out[luid] = v
		}
	}
	for k, v := range out {
		if v > 100 {
			out[k] = 100
		}
	}
	return out
}

// AdapterMemory turns `\GPU Adapter Memory(*)\Dedicated Usage` values into bytes per adapter LUID.
func AdapterMemory(names []string, values []float64) map[string]int64 {
	out := map[string]int64{}
	for i, n := range names {
		m := memRe.FindStringSubmatch(n)
		if m == nil || values[i] < 0 {
			continue
		}
		out[normLUID(m[1])] += int64(values[i])
	}
	return out
}

// ShownAdapters is the adapters to report: no software adapters (Microsoft Basic Render Driver), and no NVIDIA
// cards when nvidia-smi reports them already (they would be listed twice). The same LUID is listed once.
func ShownAdapters(all []WinAdapter, nvidiaSMI bool) []WinAdapter {
	var out []WinAdapter
	seen := map[string]bool{}
	for _, a := range all {
		if a.Software || a.VendorID == 0x1414 || strings.Contains(strings.ToLower(a.Name), "basic render") || seen[a.LUID] {
			continue
		}
		if nvidiaSMI && a.VendorID == 0x10de {
			continue
		}
		seen[a.LUID] = true
		out = append(out, a)
	}
	return out
}

// WinGPUs builds the GPU list from the adapters and the latest counter values (nil maps: not read yet).
func WinGPUs(adapters []WinAdapter, util map[string]float64, mem map[string]int64) []GPU {
	gpus := make([]GPU, 0, len(adapters))
	for i, a := range adapters {
		g := GPU{Index: i, Name: strings.TrimSpace(a.Name), Vendor: PCIVendor(a.VendorID), Source: "windows"}
		if g.Name == "" {
			g.Name = "GPU"
		}
		if util != nil {
			v := Round(util[a.LUID], 1) // an adapter without busy engines has no instances: 0 %
			g.UtilPercent = &v
		}
		if b, ok := mem[a.LUID]; ok {
			g.VRAMUsed = P(b)
		}
		if a.VRAMTotal > 0 {
			g.VRAMTotal = P(a.VRAMTotal)
		}
		gpus = append(gpus, g)
	}
	return gpus
}
