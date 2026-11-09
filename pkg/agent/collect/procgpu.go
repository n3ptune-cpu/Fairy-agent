package collect

// Per-process GPU memory on Windows from the counter Task Manager's "Dedicated GPU memory" column uses:
//
//	\GPU Process Memory(*)\Dedicated Usage   instances  pid_<pid>_luid_0x<hi>_0x<lo>_phys_<n>
//
// The process id is part of the counter's instance name, so no process is opened (no OpenProcess, nothing read
// from another program). nvidia-smi --query-compute-apps reports used_memory as [N/A] for every process on
// Windows (WDDM), so before this the Processes tab showed "–" on every Windows PC. This file holds the
// platform-independent part (parsing, matching adapters to the reported GPUs, merging); procgpu_windows.go reads
// the counter.

import (
	"regexp"
	"strconv"
)

var procMemRe = regexp.MustCompile(`(?i)^pid_(\d+)_luid_(0x[0-9a-f]{8}_0x[0-9a-f]{8})_phys_\d+$`)

// ProcessGPUMemory turns `\GPU Process Memory(*)\Dedicated Usage` values into pid -> adapter LUID -> bytes
// (physical parts of one adapter summed; zero and negative readings left out).
func ProcessGPUMemory(names []string, values []float64) map[int]map[string]int64 {
	out := map[int]map[string]int64{}
	for i, n := range names {
		if i >= len(values) || values[i] < 1 {
			continue
		}
		m := procMemRe.FindStringSubmatch(n)
		if m == nil {
			continue
		}
		pid, err := strconv.Atoi(m[1])
		if err != nil || pid <= 0 {
			continue
		}
		if out[pid] == nil {
			out[pid] = map[string]int64{}
		}
		out[pid][normLUID(m[2])] += int64(values[i])
	}
	return out
}

// GPULUIDIndex maps adapter LUIDs to positions in gpus (the /metrics `gpus` list, whose order gpu_mem_by_gpu
// follows):
//   - a GPU read through Windows' counters carries its own LUID;
//   - a GPU from a vendor tool (nvidia-smi) is matched to the DXGI adapters at its PCI location (pci.bus_id);
//   - otherwise, when a vendor has exactly one such GPU and all of that vendor's remaining adapters are one model,
//     they are that GPU (one NVIDIA card whose location Windows or nvidia-smi did not give).
//
// Adapters that match nothing are left out (their memory is not shown rather than shown on the wrong card).
func GPULUIDIndex(gpus []GPU, adapters []WinAdapter) map[string]int {
	idx := map[string]int{}
	var pending []int // GPUs without a LUID or location match
	for i, g := range gpus {
		if g.luid != "" {
			idx[g.luid] = i
			continue
		}
		matched := false
		if g.loc != nil {
			for _, a := range adapters {
				if a.Loc != nil && *a.Loc == *g.loc && PCIVendor(a.VendorID) == g.Vendor {
					idx[a.LUID] = i
					matched = true
				}
			}
		}
		if !matched {
			pending = append(pending, i)
		}
	}
	byVendor := map[string][]int{}
	for _, i := range pending {
		byVendor[gpus[i].Vendor] = append(byVendor[gpus[i].Vendor], i)
	}
	for vendor, list := range byVendor {
		if len(list) != 1 {
			continue
		}
		var cands []WinAdapter
		for _, a := range adapters {
			if _, done := idx[a.LUID]; !done && !a.Software && PCIVendor(a.VendorID) == vendor {
				cands = append(cands, a)
			}
		}
		if len(cands) == 0 {
			continue
		}
		same := true
		for _, a := range cands[1:] {
			if a.DeviceID != cands[0].DeviceID {
				same = false
			}
		}
		if !same {
			continue
		}
		for _, a := range cands {
			idx[a.LUID] = list[0]
		}
	}
	return idx
}

// ProcGPUByIndex turns pid -> LUID -> bytes into pid -> bytes per GPU position (n long). Processes left with
// nothing on any reported GPU are left out.
func ProcGPUByIndex(perPID map[int]map[string]int64, luidIndex map[string]int, n int) map[int][]int64 {
	out := map[int][]int64{}
	for pid, byLUID := range perPID {
		var v []int64
		for luid, b := range byLUID {
			i, ok := luidIndex[luid]
			if !ok || i < 0 || i >= n || b <= 0 {
				continue
			}
			if v == nil {
				v = make([]int64, n)
			}
			v[i] += b
		}
		if v != nil {
			out[pid] = v
		}
	}
	return out
}

// MergeComputeApps merges per-process GPU memory from several readers (nvidia-smi, Windows' counters): per
// process and GPU the larger value, so a card reported by two readers is not counted twice. nil when no reader
// had anything.
func MergeComputeApps(maps ...map[int][]int64) map[int][]int64 {
	var out map[int][]int64
	for _, m := range maps {
		for pid, v := range m {
			if out == nil {
				out = map[int][]int64{}
			}
			cur := out[pid]
			if len(cur) < len(v) {
				cur = append(cur, make([]int64, len(v)-len(cur))...)
			}
			for i, b := range v {
				cur[i] = max(cur[i], b)
			}
			out[pid] = cur
		}
	}
	return out
}

// pciBusID parses nvidia-smi's pci.bus_id ("00000000:01:00.0": domain:bus:device.function); nil if malformed.
func pciBusID(s string) *PCILoc {
	m := busIDRe.FindStringSubmatch(s)
	if m == nil {
		return nil
	}
	bus, _ := strconv.ParseUint(m[1], 16, 32)
	dev, _ := strconv.ParseUint(m[2], 16, 32)
	fn, _ := strconv.ParseUint(m[3], 16, 32)
	return &PCILoc{Bus: uint32(bus), Device: uint32(dev), Function: uint32(fn)}
}

var busIDRe = regexp.MustCompile(`^\s*(?:[0-9A-Fa-f]{4,8}:)?([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2})\.([0-7])\s*$`)
