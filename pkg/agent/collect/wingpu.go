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
	Name                         string
	VendorID                     uint32
	DeviceID, SubSysID, Revision uint32
	VRAMTotal                    int64  // dedicated video memory, bytes (0: none / shared only)
	LUID                         string // "0x<hi>_0x<lo>", upper-case hex, as in PDH instance names
	Software                     bool   // Microsoft Basic Render Driver and other software adapters
	Loc                          *PCILoc
}

// PCILoc is where a card sits on the PCI bus (from the adapter's LUID; nil when Windows would not say).
type PCILoc struct{ Bus, Device, Function uint32 }

func (l *PCILoc) String() string {
	if l == nil {
		return ""
	}
	return fmt.Sprintf("%02x:%02x.%x", l.Bus, l.Device, l.Function)
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

// CounterLUIDs is the set of adapter LUIDs that have instances in the GPU counters (engine or adapter memory):
// what Windows really drives. An adapter DXGI lists without any is a leftover entry (seen on Windows 10 LTSC with
// an RX 5600 XT: three DXGI entries, one card, counters for one LUID only).
func CounterLUIDs(names ...[]string) map[string]bool {
	out := map[string]bool{}
	for _, list := range names {
		for _, n := range list {
			if m := engineRe.FindStringSubmatch(n); m != nil {
				out[normLUID(m[1])] = true
			} else if m := memRe.FindStringSubmatch(n); m != nil {
				out[normLUID(m[1])] = true
			}
		}
	}
	return out
}

// DropGhosts removes DXGI entries that Windows does not really drive: an adapter without a
// `\GPU Adapter Memory` instance, when another adapter with the same vendor, device and dedicated VRAM has one.
// `\GPU Engine` instances do not tell: every process with a Direct3D device (dwm.exe, browsers, games) gets
// engine instances on every adapter DXGI lists, leftover ones included, so a leftover entry looked "live" and
// showed up as a second card (2x RX 5600 XT on a one-GPU PC, 2x Intel UHD). Two identical cards that both have
// memory instances are both kept. memLUIDs nil (the memory counter not read or not available): nothing is dropped.
func DropGhosts(all []WinAdapter, memLUIDs map[string]bool) []WinAdapter {
	if memLUIDs == nil {
		return all
	}
	key := func(a WinAdapter) string { return fmt.Sprintf("%04x:%04x:%d", a.VendorID, a.DeviceID, a.VRAMTotal) }
	live := map[string]bool{}
	for _, a := range all {
		if memLUIDs[a.LUID] {
			live[key(a)] = true
		}
	}
	out := make([]WinAdapter, 0, len(all))
	for _, a := range all {
		if !memLUIDs[a.LUID] && live[key(a)] {
			continue
		}
		out = append(out, a)
	}
	return out
}

// MemoryLUIDs is the set of adapter LUIDs that have a `\GPU Adapter Memory` instance.
func MemoryLUIDs(names []string) map[string]bool {
	out := map[string]bool{}
	for _, n := range names {
		if m := memRe.FindStringSubmatch(n); m != nil {
			out[normLUID(m[1])] = true
		}
	}
	return out
}

// PhysicalAdapters lists each physical card once. Entries with the same PCI ids (vendor, device, subsystem,
// revision) are the same card when they sit at the same PCI location, or when the location of either is unknown;
// of these the one with GPU counters (present; nil: not read yet) is kept, else the first. Two identical cards at
// different PCI locations both stay, and so does any entry that has counters of its own.
func PhysicalAdapters(all []WinAdapter, present map[string]bool) []WinAdapter {
	type group struct {
		ids  string
		loc  string // "" unknown
		pick int    // index in out
	}
	var out []WinAdapter
	var groups []group
	has := func(a WinAdapter) bool { return present != nil && present[a.LUID] }
	for _, a := range all {
		ids := fmt.Sprintf("%04x:%04x:%08x:%02x", a.VendorID, a.DeviceID, a.SubSysID, a.Revision)
		loc := a.Loc.String()
		matched := -1
		for gi, g := range groups {
			if g.ids != ids || (loc != "" && g.loc != "" && g.loc != loc) {
				continue
			}
			kept := out[g.pick]
			if has(a) && has(kept) && kept.LUID != a.LUID && (loc == "" || g.loc == "") {
				continue // both really driven by Windows: two cards whose location is unknown
			}
			matched = gi
			break
		}
		if matched < 0 {
			groups = append(groups, group{ids: ids, loc: loc, pick: len(out)})
			out = append(out, a)
			continue
		}
		g := &groups[matched]
		if has(a) && !has(out[g.pick]) { // the entry Windows really drives replaces a leftover
			out[g.pick] = a
		}
		if g.loc == "" && loc != "" && out[g.pick].LUID == a.LUID {
			g.loc = loc
		}
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
		g.loc = a.Loc
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
