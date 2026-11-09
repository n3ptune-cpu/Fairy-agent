//go:build windows

package collect

import (
	"sync"
	"time"
)

// ProcGPU reads per-process dedicated GPU memory from `\GPU Process Memory(*)\Dedicated Usage` (see procgpu.go)
// for every adapter, NVIDIA included. Only PDH is used: no process is opened.
type ProcGPU struct {
	mu       sync.Mutex
	q        *pdhQuery
	adapters []WinAdapter
	listedAt time.Time
	last     map[int]map[string]int64
	at       time.Time
}

// NewProcGPU returns the reader, or nil when Windows has no such counter (older Windows 10, no WDDM 2 driver).
func NewProcGPU() *ProcGPU {
	q, err := newPDHQuery(`\GPU Process Memory(*)\Dedicated Usage`)
	if err != nil {
		NoteCounterAccess(err)
		return nil
	}
	return &ProcGPU{q: q}
}

// ComputeAppsFor returns pid -> dedicated GPU memory per position in gpus (the reported GPU list); nil when
// nothing could be read. The counter is read at most every two seconds.
func (p *ProcGPU) ComputeAppsFor(gpus []GPU) map[int][]int64 {
	if p == nil || len(gpus) == 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.adapters == nil || time.Since(p.listedAt) > 5*time.Minute { // LUIDs change when a driver restarts
		if all, err := DXGIAdapters(); err == nil {
			p.adapters = all
		}
		p.listedAt = time.Now()
	}
	if p.last == nil || time.Since(p.at) >= 2*time.Second {
		vals, err := p.q.values()
		if err != nil {
			p.last = map[int]map[string]int64{} // no instances: no process holds GPU memory
		} else {
			names, values := split(vals)
			p.last = ProcessGPUMemory(names, values)
		}
		p.at = time.Now()
	}
	if len(p.last) == 0 {
		return nil
	}
	return ProcGPUByIndex(p.last, GPULUIDIndex(gpus, p.adapters), len(gpus))
}
