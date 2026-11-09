//go:build windows

package collect

// The Windows side of wingpu.go: adapters from DXGI (the documented user-mode graphics API: only adapter
// descriptions are read, no device is created) and the GPU counters from PDH. Nothing is loaded into other
// processes and no driver is involved.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	dxgi                   = windows.NewLazySystemDLL("dxgi.dll")
	procCreateDXGIFactory1 = dxgi.NewProc("CreateDXGIFactory1")
	iidIDXGIFactory1       = windows.GUID{Data1: 0x770aae78, Data2: 0xf26f, Data3: 0x4dba, Data4: [8]byte{0xa8, 0x29, 0x25, 0x3c, 0x83, 0xd1, 0xb3, 0x87}}

	// D3DKMT (gdi32, documented in d3dkmthk.h): only to read an adapter's PCI location from its LUID.
	gdi32                         = windows.NewLazySystemDLL("gdi32.dll")
	procD3DKMTOpenAdapterFromLuid = gdi32.NewProc("D3DKMTOpenAdapterFromLuid")
	procD3DKMTQueryAdapterInfo    = gdi32.NewProc("D3DKMTQueryAdapterInfo")
	procD3DKMTCloseAdapter        = gdi32.NewProc("D3DKMTCloseAdapter")
)

const (
	kmtqaiAdapterAddress       = 6  // KMTQAITYPE_ADAPTERADDRESS -> D3DKMT_ADAPTERADDRESS
	kmtqaiAdapterAddressRender = 53 // KMTQAITYPE_ADAPTERADDRESS_RENDER: the render adapter of a display-only one
)

type d3dkmtOpenAdapterFromLUID struct {
	LUIDLow  uint32
	LUIDHigh int32
	Adapter  uint32
}

type d3dkmtQueryAdapterInfo struct {
	Adapter  uint32
	Type     uint32
	Data     uintptr
	DataSize uint32
	_        uint32
}

type d3dkmtAdapterAddress struct{ Bus, Device, Function uint32 }

// adapterLocation is the PCI bus / device / function of the adapter with this LUID (nil when Windows cannot
// open it, e.g. a leftover LUID).
func adapterLocation(high int32, low uint32) *PCILoc {
	if procD3DKMTOpenAdapterFromLuid.Find() != nil || procD3DKMTQueryAdapterInfo.Find() != nil || procD3DKMTCloseAdapter.Find() != nil {
		return nil
	}
	o := d3dkmtOpenAdapterFromLUID{LUIDLow: low, LUIDHigh: high}
	if r, _, _ := procD3DKMTOpenAdapterFromLuid.Call(uintptr(unsafe.Pointer(&o))); r != 0 {
		return nil
	}
	defer procD3DKMTCloseAdapter.Call(uintptr(unsafe.Pointer(&o.Adapter)))
	for _, typ := range []uint32{kmtqaiAdapterAddress, kmtqaiAdapterAddressRender} {
		var addr d3dkmtAdapterAddress
		q := d3dkmtQueryAdapterInfo{Adapter: o.Adapter, Type: typ, Data: uintptr(unsafe.Pointer(&addr)), DataSize: uint32(unsafe.Sizeof(addr))}
		if r, _, _ := procD3DKMTQueryAdapterInfo.Call(uintptr(unsafe.Pointer(&q))); r == 0 {
			return &PCILoc{Bus: addr.Bus, Device: addr.Device, Function: addr.Function}
		}
	}
	return nil
}

const (
	dxgiErrorNotFound       = 0x887A0002
	dxgiAdapterFlagSoftware = 2
	// vtable slots: IUnknown 0-2, IDXGIObject 3-6, IDXGIFactory 7-11, IDXGIFactory1 12-13; IDXGIAdapter 7-9,
	// IDXGIAdapter1 10.
	slotRelease       = 2
	slotEnumAdapters1 = 12
	slotGetDesc1      = 10
)

// comObject is a COM interface pointer: the object starts with its vtable pointer.
type comObject struct{ vtbl *[16]uintptr }

func (o *comObject) call(slot int, args ...uintptr) uintptr {
	r, _, _ := syscall.SyscallN(o.vtbl[slot], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return r
}

// dxgiAdapterDesc1 is DXGI_ADAPTER_DESC1.
type dxgiAdapterDesc1 struct {
	Description                                                     [128]uint16
	VendorID, DeviceID, SubSysID, Revision                          uint32
	DedicatedVideoMemory, DedicatedSystemMemory, SharedSystemMemory uintptr
	LUIDLow                                                         uint32
	LUIDHigh                                                        int32
	Flags                                                           uint32
}

// DXGIAdapters lists the display adapters.
func DXGIAdapters() ([]WinAdapter, error) {
	if err := procCreateDXGIFactory1.Find(); err != nil {
		return nil, err
	}
	var f *comObject
	if r, _, _ := procCreateDXGIFactory1.Call(uintptr(unsafe.Pointer(&iidIDXGIFactory1)), uintptr(unsafe.Pointer(&f))); r != 0 || f == nil {
		return nil, errors.New("CreateDXGIFactory1 failed")
	}
	defer f.call(slotRelease)
	var out []WinAdapter
	for i := uintptr(0); i < 16; i++ {
		var a *comObject
		r := f.call(slotEnumAdapters1, i, uintptr(unsafe.Pointer(&a)))
		if uint32(r) == dxgiErrorNotFound || a == nil {
			break
		}
		if r != 0 {
			continue
		}
		var d dxgiAdapterDesc1
		ok := a.call(slotGetDesc1, uintptr(unsafe.Pointer(&d))) == 0
		a.call(slotRelease)
		if !ok {
			continue
		}
		out = append(out, WinAdapter{Name: windows.UTF16ToString(d.Description[:]), VendorID: d.VendorID,
			DeviceID: d.DeviceID, SubSysID: d.SubSysID, Revision: d.Revision,
			VRAMTotal: int64(d.DedicatedVideoMemory), LUID: LUIDKey(d.LUIDHigh, d.LUIDLow), Software: d.Flags&dxgiAdapterFlagSoftware != 0,
			Loc: adapterLocation(d.LUIDHigh, d.LUIDLow)})
	}
	return out, nil
}

// WinGPU reports the adapters DXGI lists, with utilization and dedicated VRAM in use from PDH.
type WinGPU struct {
	interval  time.Duration
	nvidiaSMI bool

	mu       sync.Mutex
	adapters []WinAdapter
	listedAt time.Time
	eng, mem *pdhQuery
	triedAt  time.Time // when the counter queries were last set up (again)
	logged   map[string]bool
	gpus     []GPU
	at       time.Time
	amd      *AMDSensors // Radeon temperature / watts through ADL (nil: off, not installed or no Overdrive)
}

// NewWinGPU returns the reader, or nil when there is no adapter to report (none, only the Basic Render Driver,
// or only NVIDIA cards that nvidia-smi reports). amdADL adds Radeon temperature / watts from AMD's ADL.
func NewWinGPU(interval time.Duration, nvidiaSMI, amdADL bool) *WinGPU {
	all, err := DXGIAdapters()
	if err != nil {
		slog.Info("GPUs via Windows: adapters not readable", "error", err)
		return nil
	}
	for _, a := range all { // once at start: what DXGI and the kernel say, to tell a card's several entries apart
		loc := a.Loc.String()
		if loc == "" {
			loc = "unknown"
		}
		slog.Info("GPUs via Windows: DXGI adapter", "name", a.Name, "luid", a.LUID, "ids",
			fmt.Sprintf("%04x:%04x:%08x:%02x", a.VendorID, a.DeviceID, a.SubSysID, a.Revision), "pci", loc, "software", a.Software)
	}
	shown := ShownAdapters(all, nvidiaSMI)
	if len(shown) == 0 {
		return nil
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	w := &WinGPU{interval: interval, nvidiaSMI: nvidiaSMI, adapters: shown, listedAt: time.Now(), logged: map[string]bool{}}
	w.setupQueries()
	if amdADL && slices.ContainsFunc(shown, func(a WinAdapter) bool { return a.VendorID == 0x1002 }) {
		if lib, err := OpenADL(); err != nil {
			slog.Debug("AMD GPU sensors (ADL): not available; showing load and VRAM only", "error", err)
		} else {
			w.amd = NewAMDSensors(lib)
		}
	}
	return w
}

const (
	engCounter = `\GPU Engine(*)\Utilization Percentage`
	memCounter = `\GPU Adapter Memory(*)\Dedicated Usage`
)

// setupQueries opens the counter queries that are missing. They can be missing at start (the GPU counters'
// provider is not ready yet right after boot); without them utilization and VRAM in use are unknown ("-" in
// the panel) and the ghost entries of a card cannot be told apart. So they are tried again once a minute, and
// each failure is logged once. Caller holds w.mu (or owns w).
func (w *WinGPU) setupQueries() {
	w.triedAt = time.Now()
	for _, c := range []struct {
		q    **pdhQuery
		path string
	}{{&w.eng, engCounter}, {&w.mem, memCounter}} {
		if *c.q != nil {
			continue
		}
		q, err := newPDHQuery(c.path)
		if err != nil {
			if !w.logged[c.path] {
				w.logged[c.path] = true
				slog.Info("GPUs via Windows: counter not readable yet; trying again every minute", "counter", c.path, "error", err)
			}
			continue
		}
		if w.logged[c.path] {
			slog.Info("GPUs via Windows: counter readable now", "counter", c.path)
		}
		*c.q = q
	}
}

func (w *WinGPU) readFailed(path string, err error) {
	if key := "read " + path; !w.logged[key] {
		w.logged[key] = true
		slog.Info("GPUs via Windows: reading a counter failed (logged once)", "counter", path, "error", err)
	}
}

// AMDCards lists the Radeon cards read through ADL (for the start-up log).
func (w *WinGPU) AMDCards() []string {
	if w.amd == nil {
		return nil
	}
	return w.amd.Cards()
}

// Names lists the reported adapters (for the start-up log): what GPUs reports, leftover DXGI entries dropped.
func (w *WinGPU) Names() []string {
	var n []string
	for _, g := range w.GPUs() {
		n = append(n, g.Name)
	}
	return n
}

func split(vals []pdhValue) ([]string, []float64) {
	names, values := make([]string, len(vals)), make([]float64, len(vals))
	for i, v := range vals {
		names[i], values[i] = v.name, v.value
	}
	return names, values
}

// GPUs returns the latest readings (read at most once per interval).
func (w *WinGPU) GPUs() []GPU {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.gpus != nil && time.Since(w.at) < w.interval {
		return w.gpus
	}
	if time.Since(w.listedAt) > 5*time.Minute { // LUIDs change when a driver restarts
		if all, err := DXGIAdapters(); err == nil {
			if shown := ShownAdapters(all, w.nvidiaSMI); len(shown) > 0 {
				w.adapters = shown
			}
		}
		w.listedAt = time.Now()
	}
	if (w.eng == nil || w.mem == nil) && time.Since(w.triedAt) > time.Minute {
		w.setupQueries()
	}
	var util EngineLoad
	var mem map[string]int64
	var memLUIDs map[string]bool
	var engNames, memNames []string
	read := false
	if w.eng != nil {
		if v, err := w.eng.values(); err == nil {
			names, values := split(v)
			util, engNames, read = EngineLoads(names, values), names, true
		} else {
			w.readFailed(engCounter, err)
			if w.gpus != nil {
				util = EngineLoad{} // collected before, no busy engine now
			}
		}
	}
	if w.mem != nil {
		if v, err := w.mem.values(); err == nil {
			names, values := split(v)
			mem, memLUIDs, memNames, read = AdapterMemory(names, values), MemoryLUIDs(names), names, true
		} else {
			w.readFailed(memCounter, err)
		}
	}
	var activity map[string]int
	if read {
		activity = CounterActivity(engNames, memNames)
	}
	w.gpus, w.at = WinGPUs(GroupAdapters(DropGhosts(w.adapters, memLUIDs), activity), util, mem), time.Now()
	if w.amd != nil {
		w.amd.Attach(w.gpus)
	}
	return w.gpus
}

// ComputeApps is not available from these counters.
func (w *WinGPU) ComputeApps(context.Context) map[int][]int64 { return nil }
