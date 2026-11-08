//go:build windows

package collect

// The Windows side of wingpu.go: adapters from DXGI (the documented user-mode graphics API: only adapter
// descriptions are read, no device is created) and the GPU counters from PDH. Nothing is loaded into other
// processes and no driver is involved.

import (
	"context"
	"errors"
	"log/slog"
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
)

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
			VRAMTotal: int64(d.DedicatedVideoMemory), LUID: LUIDKey(d.LUIDHigh, d.LUIDLow), Software: d.Flags&dxgiAdapterFlagSoftware != 0})
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
	gpus     []GPU
	at       time.Time
}

// NewWinGPU returns the reader, or nil when there is no adapter to report (none, only the Basic Render Driver,
// or only NVIDIA cards that nvidia-smi reports).
func NewWinGPU(interval time.Duration, nvidiaSMI bool) *WinGPU {
	all, err := DXGIAdapters()
	if err != nil {
		slog.Info("GPUs via Windows: adapters not readable", "error", err)
		return nil
	}
	shown := ShownAdapters(all, nvidiaSMI)
	if len(shown) == 0 {
		return nil
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	w := &WinGPU{interval: interval, nvidiaSMI: nvidiaSMI, adapters: shown, listedAt: time.Now()}
	w.eng, _ = newPDHQuery(`\GPU Engine(*)\Utilization Percentage`)
	w.mem, _ = newPDHQuery(`\GPU Adapter Memory(*)\Dedicated Usage`)
	return w
}

// Names lists the reported adapters (for the start-up log).
func (w *WinGPU) Names() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var n []string
	for _, a := range w.adapters {
		n = append(n, a.Name)
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
	var util map[string]float64
	var mem map[string]int64
	if w.eng != nil {
		if v, err := w.eng.values(); err == nil {
			util = EngineUtil(split(v))
		} else if w.gpus != nil {
			util = map[string]float64{} // collected before, no busy engine now
		}
	}
	if w.mem != nil {
		if v, err := w.mem.values(); err == nil {
			mem = AdapterMemory(split(v))
		}
	}
	w.gpus, w.at = WinGPUs(w.adapters, util, mem), time.Now()
	return w.gpus
}

// ComputeApps is not available from these counters.
func (w *WinGPU) ComputeApps(context.Context) map[int][]int64 { return nil }
