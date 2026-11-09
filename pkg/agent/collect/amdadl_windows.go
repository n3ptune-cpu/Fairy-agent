//go:build windows

package collect

// The ADL DLL behind ADLLib (see amdadl.go): plain C calls through syscall, no cgo. Only ...Get / Caps / Query
// functions are looked up at all, so no write can happen by mistake.

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const adlMaxPath = 256

// adlAdapterInfo is AdapterInfo (Windows layout, 1572 bytes).
type adlAdapterInfo struct {
	Size, AdapterIndex                      int32
	UDID                                    [adlMaxPath]byte
	BusNumber, DeviceNumber, FunctionNumber int32
	VendorID                                int32
	AdapterName, DisplayName                [adlMaxPath]byte
	Present, Exist                          int32
	DriverPath, DriverPathExt, PNPString    [adlMaxPath]byte
	OSDisplayIndex                          int32
}

// adlPMLogDataOutput is ADLPMLogDataOutput.
type adlPMLogDataOutput struct {
	Size    int32
	Sensors [256]struct{ Supported, Value int32 }
}

type adlTemperature struct{ Size, Temperature int32 }

type adlDLL struct {
	ctx   uintptr
	procs map[string]*windows.LazyProc
}

var (
	adlAllocOnce sync.Once
	adlAllocCB   uintptr // ADL_MAIN_MALLOC_CALLBACK: memory from LocalAlloc (never Go memory)
)

func adlAlloc() uintptr {
	adlAllocOnce.Do(func() {
		adlAllocCB = syscall.NewCallback(func(size uintptr) uintptr {
			n := uint32(int32(size)) // an int in C: only the low 32 bits are meaningful
			if int32(n) <= 0 {
				return 0
			}
			p, err := windows.LocalAlloc(windows.LPTR, n)
			if err != nil {
				return 0
			}
			return p
		})
	})
	return adlAllocCB
}

// OpenADL loads atiadlxx.dll (atiadlxy.dll as a fallback) from System32 and creates an ADL2 context.
func OpenADL() (ADLLib, error) {
	names := []string{"ADL2_Main_Control_Create", "ADL2_Adapter_NumberOfAdapters_Get", "ADL2_Adapter_AdapterInfo_Get",
		"ADL2_Overdrive_Caps", "ADL2_New_QueryPMLogData_Get", "ADL2_OverdriveN_Temperature_Get",
		"ADL2_Overdrive6_Temperature_Get", "ADL2_Overdrive6_CurrentPower_Get", "ADL2_Overdrive5_Temperature_Get"}
	var lastErr error
	for _, file := range []string{"atiadlxx.dll", "atiadlxy.dll"} {
		dll := windows.NewLazySystemDLL(file)
		if err := dll.Load(); err != nil {
			lastErr = err
			continue
		}
		d := &adlDLL{procs: map[string]*windows.LazyProc{}}
		for _, n := range names {
			if p := dll.NewProc(n); p.Find() == nil {
				d.procs[n] = p
			}
		}
		create := d.procs["ADL2_Main_Control_Create"]
		if create == nil || d.procs["ADL2_Adapter_AdapterInfo_Get"] == nil || d.procs["ADL2_Overdrive_Caps"] == nil {
			lastErr = fmt.Errorf("%s: ADL2 functions missing", file)
			continue
		}
		if r, _, _ := create.Call(adlAlloc(), 1, uintptr(unsafe.Pointer(&d.ctx))); int32(r) != 0 || d.ctx == 0 {
			lastErr = fmt.Errorf("%s: ADL2_Main_Control_Create: %d", file, int32(r))
			continue
		}
		slog.Debug("AMD GPU sensors (ADL): loaded", "dll", file)
		return d, nil
	}
	return nil, lastErr
}

// call runs an ADL2 function with the context first; ADL_OK (0) and ADL_OK_WARNING (1) count as success.
func (d *adlDLL) call(name string, args ...uintptr) error {
	p := d.procs[name]
	if p == nil {
		return errors.New(name + " not in this ADL")
	}
	r, _, _ := p.Call(append([]uintptr{d.ctx}, args...)...)
	if c := int32(r); c != 0 && c != 1 {
		return fmt.Errorf("%s: ADL error %d", name, c)
	}
	return nil
}

func (d *adlDLL) Adapters() ([]ADLAdapter, error) {
	var n int32
	if err := d.call("ADL2_Adapter_NumberOfAdapters_Get", uintptr(unsafe.Pointer(&n))); err != nil {
		return nil, err
	}
	if n <= 0 || n > 64 {
		return nil, fmt.Errorf("ADL: %d adapters", n)
	}
	infos := make([]adlAdapterInfo, n)
	size := int32(unsafe.Sizeof(infos[0])) * n
	for i := range infos {
		infos[i].Size = int32(unsafe.Sizeof(infos[0]))
	}
	if err := d.call("ADL2_Adapter_AdapterInfo_Get", uintptr(unsafe.Pointer(&infos[0])), uintptr(size)); err != nil {
		return nil, err
	}
	out := make([]ADLAdapter, 0, n)
	for _, a := range infos {
		out = append(out, ADLAdapter{Index: int(a.AdapterIndex), Bus: int(a.BusNumber), Device: int(a.DeviceNumber),
			Function: int(a.FunctionNumber), VendorID: int(a.VendorID), Name: cString(a.AdapterName[:]),
			Present: a.Present != 0, Exist: a.Exist != 0})
	}
	return out, nil
}

func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func (d *adlDLL) OverdriveVersion(index int) (int, error) {
	var supported, enabled, version int32
	if err := d.call("ADL2_Overdrive_Caps", uintptr(index), uintptr(unsafe.Pointer(&supported)),
		uintptr(unsafe.Pointer(&enabled)), uintptr(unsafe.Pointer(&version))); err != nil {
		return 0, err
	}
	if supported == 0 {
		return 0, errors.New("overdrive not supported")
	}
	return int(version), nil
}

func (d *adlDLL) PMLog(index int) ([]ADLSensor, error) {
	var out adlPMLogDataOutput
	if err := d.call("ADL2_New_QueryPMLogData_Get", uintptr(index), uintptr(unsafe.Pointer(&out))); err != nil {
		return nil, err
	}
	s := make([]ADLSensor, len(out.Sensors))
	for i, x := range out.Sensors {
		s[i] = ADLSensor{Supported: x.Supported != 0, Value: x.Value}
	}
	return s, nil
}

func (d *adlDLL) ODNTemperature(index int) (int, error) {
	var t int32
	err := d.call("ADL2_OverdriveN_Temperature_Get", uintptr(index), 1, uintptr(unsafe.Pointer(&t))) // 1: edge
	return int(t), err
}

func (d *adlDLL) OD6Temperature(index int) (int, error) {
	var t int32
	err := d.call("ADL2_Overdrive6_Temperature_Get", uintptr(index), uintptr(unsafe.Pointer(&t)))
	return int(t), err
}

func (d *adlDLL) OD6Power(index int) (int, error) {
	var p int32
	err := d.call("ADL2_Overdrive6_CurrentPower_Get", uintptr(index), 0, uintptr(unsafe.Pointer(&p))) // 0: total
	return int(p), err
}

func (d *adlDLL) OD5Temperature(index int) (int, error) {
	t := adlTemperature{Size: int32(unsafe.Sizeof(adlTemperature{}))}
	err := d.call("ADL2_Overdrive5_Temperature_Get", uintptr(index), 0, uintptr(unsafe.Pointer(&t)))
	return int(t.Temperature), err
}
