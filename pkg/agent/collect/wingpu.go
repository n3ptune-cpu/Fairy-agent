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
	"slices"
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
	// Also: further LUIDs of the same physical card (GroupAdapters), whose counters are added to this one's.
	Also []string
}

// LUIDs are the adapter's LUID and those merged into it.
func (a WinAdapter) LUIDs() []string { return append([]string{a.LUID}, a.Also...) }

// PCILoc is where a card sits on the PCI bus (from the adapter's LUID; nil when Windows would not say).
type PCILoc struct{ Bus, Device, Function uint32 }

// Known reports whether l is a real PCI location. For a leftover LUID (left by a driver reset) and for software
// adapters D3DKMT answers, but with bus 0xFFFFFFFF, device 0xFFFF and function 0xFFFF ("ffffffff:ffff.ffff"
// in the log): that is "unknown", not a location. A PCI device number is below 32, a function below 8.
func (l *PCILoc) Known() bool {
	return l != nil && l.Bus != 0xFFFFFFFF && l.Device < 32 && l.Function < 8
}

// String is "bus:device.function", "" when the location is unknown (Known).
func (l *PCILoc) String() string {
	if !l.Known() {
		return ""
	}
	return fmt.Sprintf("%02x:%02x.%x", l.Bus, l.Device, l.Function)
}

// pciIDs are the PCI ids DXGI reports for an adapter: vendor, device, subsystem, revision.
func (a WinAdapter) pciIDs() string {
	return fmt.Sprintf("%04x:%04x:%08x:%02x", a.VendorID, a.DeviceID, a.SubSysID, a.Revision)
}

// software reports a software adapter (Microsoft Basic Render Driver): never a GPU of this PC.
func (a WinAdapter) software() bool {
	return a.Software || a.VendorID == 0x1414 || strings.Contains(strings.ToLower(a.Name), "basic render")
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
	engineRe = regexp.MustCompile(`(?i)luid_(0x[0-9a-f]{8}_0x[0-9a-f]{8})_phys_(\d+)_eng_(\d+)(?:_engtype_([0-9a-z_ ]*))?`)
	memRe    = regexp.MustCompile(`(?i)^luid_(0x[0-9a-f]{8}_0x[0-9a-f]{8})_phys_\d+$`)
)

// EngineLoad is `\GPU Engine(*)\Utilization Percentage` per adapter and engine: LUID -> "<phys>/<eng>/<engtype>"
// -> percent, summed over the processes using that engine (Task Manager's way).
type EngineLoad map[string]map[string]float64

// EngineLoads reads the counter's instances. Negative (broken) readings are skipped.
func EngineLoads(names []string, values []float64) EngineLoad {
	out := EngineLoad{}
	for i, n := range names {
		m := engineRe.FindStringSubmatch(n)
		if m == nil || i >= len(values) || values[i] < 0 {
			continue
		}
		luid := normLUID(m[1])
		if out[luid] == nil {
			out[luid] = map[string]float64{}
		}
		out[luid][m[2]+"/"+m[3]+"/"+strings.ToLower(m[4])] += values[i]
	}
	return out
}

// Util is the utilization of one physical card seen through luids (usually one): per engine the sum over those
// LUIDs (work submitted through either reaches the same engine), then the busiest engine, at most 100.
func (l EngineLoad) Util(luids ...string) float64 {
	engines := map[string]float64{}
	for _, luid := range luids {
		for k, v := range l[luid] {
			engines[k] += v
		}
	}
	busiest := 0.0
	for _, v := range engines {
		busiest = max(busiest, v)
	}
	return min(busiest, 100)
}

// EngineUtil is each LUID's utilization on its own (EngineLoads, then Util per LUID).
func EngineUtil(names []string, values []float64) map[string]float64 {
	l := EngineLoads(names, values)
	out := make(map[string]float64, len(l))
	for luid := range l {
		out[luid] = l.Util(luid)
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
		if a.software() || seen[a.LUID] {
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

// DropGhosts removes DXGI entries that Windows does not really drive, and software adapters (Microsoft Basic
// Render Driver) whatever ShownAdapters let through:
//
//   - an adapter whose PCI location Windows' kernel could not give (D3DKMT failed or answered
//     ffffffff:ffff.ffff), when another adapter with the same PCI ids (vendor, device, subsystem, revision) has
//     a location: the leftover LUID of a card after a driver reset (one laptop: two "Intel(R) UHD Graphics",
//     one at 00:02.0, one without a location and without any GPU counter). This needs no counter, so it also
//     works when the agent cannot read them. It is kept if it has a `\GPU Adapter Memory` instance (Windows
//     drives it; GroupAdapters decides);
//   - an adapter without a `\GPU Adapter Memory` instance, when another adapter with the same vendor, device and
//     dedicated VRAM has one. `\GPU Engine` instances do not tell: every process with a Direct3D device
//     (dwm.exe, browsers, games) gets engine instances on every adapter DXGI lists, leftover ones included, so a
//     leftover entry looked "live" and showed up as a second card (2x RX 5600 XT on a one-GPU PC, 2x Intel
//     UHD). memLUIDs nil (the memory counter not read or not available): this rule drops nothing.
//
// Two identical cards that both have a location, or both have memory instances, are both kept.
func DropGhosts(all []WinAdapter, memLUIDs map[string]bool) []WinAdapter {
	located := map[string]bool{} // PCI ids of the adapters with a location
	for _, a := range all {
		if !a.software() && a.Loc.Known() {
			located[a.pciIDs()] = true
		}
	}
	key := func(a WinAdapter) string { return fmt.Sprintf("%04x:%04x:%d", a.VendorID, a.DeviceID, a.VRAMTotal) }
	live := map[string]bool{}
	for _, a := range all {
		if memLUIDs[a.LUID] && !a.software() {
			live[key(a)] = true
		}
	}
	out := make([]WinAdapter, 0, len(all))
	for _, a := range all {
		switch {
		case a.software():
			continue
		case !a.Loc.Known() && located[a.pciIDs()] && !memLUIDs[a.LUID]:
			continue
		case memLUIDs != nil && !memLUIDs[a.LUID] && live[key(a)]:
			continue
		}
		out = append(out, a)
	}
	return out
}

// CounterActivity says how much Windows really drives each LUID: 1000 for a `\GPU Adapter Memory` instance, plus
// one per `\GPU Engine` instance (process x engine). GroupAdapters keeps the busiest entry of a card.
func CounterActivity(engNames, memNames []string) map[string]int {
	out := map[string]int{}
	for _, n := range engNames {
		if m := engineRe.FindStringSubmatch(n); m != nil {
			out[normLUID(m[1])]++
		}
	}
	for _, n := range memNames {
		if m := memRe.FindStringSubmatch(n); m != nil {
			out[normLUID(m[1])] += 1000
		}
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

// PhysicalAdapters is GroupAdapters with present (LUIDs that have GPU counters; nil: not read yet) as the
// activity.
func PhysicalAdapters(all []WinAdapter, present map[string]bool) []WinAdapter {
	var act map[string]int
	if present != nil {
		act = map[string]int{}
		for k, v := range present {
			if v {
				act[k] = 1
			}
		}
	}
	return GroupAdapters(all, act)
}

// GroupAdapters lists each physical card once; the LUIDs merged into an entry are in its Also, so their
// counters are added to it (WinGPUs). Two entries are the same card when
//
//   - Windows' kernel (D3DKMT) puts both at the same PCI bus / device / function and DXGI gives both the same
//     vendor and device id: one PCI function is one card, whatever else DXGI says about the entries (a second
//     LUID of a laptop's Intel UHD had GPU counters of its own and showed up as a second card), or
//   - DXGI gives the same PCI ids (vendor, device, subsystem, revision) and the location of either is unknown,
//     unless both have GPU counters (two cards whose location Windows did not give).
//
// Of a card's entries the one with the most activity (CounterActivity; nil: not read yet) represents it (its
// name and total VRAM), on a tie the first DXGI lists. Two identical cards at different PCI locations both stay.
// Without locations (D3DKMT failed) only the second rule applies, as before.
func GroupAdapters(all []WinAdapter, activity map[string]int) []WinAdapter {
	type group struct {
		ids  string
		loc  string // "" unknown
		pick int    // index in out
	}
	var out []WinAdapter
	var groups []group
	has := func(a WinAdapter) bool { return activity != nil && activity[a.LUID] > 0 }
	act := func(a WinAdapter) int { return activity[a.LUID] }
	for _, a := range all {
		ids := a.pciIDs()
		loc := a.Loc.String()
		matched := -1
		for gi, g := range groups {
			kept := out[g.pick]
			if loc != "" && g.loc != "" {
				if loc == g.loc && kept.VendorID == a.VendorID && kept.DeviceID == a.DeviceID {
					matched = gi
					break
				}
				continue
			}
			if g.ids != ids {
				continue
			}
			if has(a) && has(kept) && kept.LUID != a.LUID {
				continue // both really driven by Windows: two cards whose location is unknown
			}
			matched = gi
			break
		}
		if matched < 0 {
			groups = append(groups, group{ids: ids, loc: loc, pick: len(out)})
			a.Also = slices.Clone(a.Also)
			out = append(out, a)
			continue
		}
		g := &groups[matched]
		kept := out[g.pick]
		if a.LUID == kept.LUID || slices.Contains(kept.Also, a.LUID) {
			continue
		}
		if act(a) > act(kept) { // the entry Windows really drives (or drives more) represents the card
			a.Also = append(append(slices.Clone(a.Also), kept.LUID), kept.Also...)
			out[g.pick] = a
		} else {
			out[g.pick].Also = append(append(kept.Also, a.LUID), a.Also...)
		}
		if g.loc == "" && loc != "" {
			g.loc = loc
		}
	}
	return out
}

// WinGPUs builds the GPU list from the adapters and the latest counter values (nil: not read yet). The counters
// of every LUID of an adapter (its own and Also) are added up: engine load per engine (EngineLoad.Util),
// dedicated memory in use as the sum (each LUID's allocations are its own, on the same card's memory).
func WinGPUs(adapters []WinAdapter, util EngineLoad, mem map[string]int64) []GPU {
	gpus := make([]GPU, 0, len(adapters))
	for i, a := range adapters {
		g := GPU{Index: i, Name: strings.TrimSpace(a.Name), Vendor: PCIVendor(a.VendorID), Source: "windows"}
		if g.Name == "" {
			g.Name = "GPU"
		}
		luids := a.LUIDs()
		if util != nil {
			v := Round(util.Util(luids...), 1) // an adapter without busy engines has no instances: 0 %
			g.UtilPercent = &v
		}
		g.loc, g.luid, g.also = a.Loc, a.LUID, slices.Clone(a.Also)
		var used int64
		found := false
		for _, l := range luids {
			if b, ok := mem[l]; ok {
				used, found = used+b, true
			}
		}
		if found {
			g.VRAMUsed = P(used)
		}
		if a.VRAMTotal > 0 {
			g.VRAMTotal = P(a.VRAMTotal)
		}
		gpus = append(gpus, g)
	}
	return gpus
}
