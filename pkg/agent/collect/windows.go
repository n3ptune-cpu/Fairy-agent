//go:build windows

package collect

// Windows collector. Only documented user-mode APIs, nothing that needs a driver:
//
//   - CPU: GetSystemTimes; memory: GlobalMemoryStatusEx; uptime: GetTickCount64
//   - disks: GetLogicalDriveStrings / GetDriveType / GetDiskFreeSpaceEx / GetVolumeInformation (fixed drives)
//   - network: GetIfTable2Ex (hardware interfaces only, so VPN / Hyper-V / filter interfaces are not counted twice)
//   - OS name and SMBIOS strings: the registry (HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion and
//     HKLM\HARDWARE\DESCRIPTION\System), which Windows fills at boot
//   - temperatures: the "Thermal Zone Information" performance counters (PDH), i.e. the ACPI thermal zones
//   - optionally (sensors.coretemp) CPU core temperatures and package watts from Core Temp's shared memory,
//     read-only (coretemp_windows.go); Core Temp's own driver does the reading, the agent loads none
//   - battery: GetSystemPowerStatus (state only; watts would need the battery driver's IOCTL, left out)
//   - processes: a Toolhelp32 snapshot (names and ids, no handles), then, per process, OpenProcess with
//     PROCESS_QUERY_LIMITED_INFORMATION only, for GetProcessTimes, GetProcessMemoryInfo,
//     QueryFullProcessImageName and the owner from the process token. Never PROCESS_VM_READ, never memory
//     reads, never anything with write or thread access. Access denied = the process is listed by name only.

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	kernel32                 = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemTimes       = kernel32.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")
	procGetSystemPowerStatus = kernel32.NewProc("GetSystemPowerStatus")
	procK32GetProcessMemInfo = kernel32.NewProc("K32GetProcessMemoryInfo")
	procGetTickCount64       = kernel32.NewProc("GetTickCount64")
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

type processMemoryCounters struct {
	CB                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func ft64(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }

type winProcSample struct {
	cpu    uint64 // kernel + user, 100 ns
	create uint64
}

// Windows is the collector for Windows.
type Windows struct {
	static Static

	mu                        sync.Mutex
	prevIdle, prevKern, prevU uint64
	prevAt                    time.Time
	lastPct                   *float64
	diskCache                 []Disk
	diskAt                    time.Time
	temps                     []Temp
	tempsAt                   time.Time
	thermal                   *pdhQuery
	thermalOff                bool
	procPrev                  map[uint32]winProcSample
	procPrevAt                time.Time
	accounts                  map[string]string
}

// NewSystem returns the collector for this machine.
func NewSystem() Collector {
	windows.SetErrorMode(windows.SEM_FAILCRITICALERRORS) // never a "no disk in drive" dialog
	w := &Windows{accounts: map[string]string{}}
	w.static = readWinStatic()
	w.prevIdle, w.prevKern, w.prevU, _ = systemTimes()
	w.prevAt = time.Now()
	return w
}

func regString(k registry.Key, name string) *string {
	v, _, err := k.GetStringValue(name)
	v = strings.TrimSpace(v)
	if err != nil || v == "" {
		return nil
	}
	return &v
}

func readWinStatic() Static {
	s := Static{Platform: Platform{System: "Windows", Pretty: "Windows"}, Logical: int(windows.GetActiveProcessorCount(windows.ALL_PROCESSOR_GROUPS))}
	if s.Logical <= 0 {
		s.Logical = numCPU()
	}
	s.Hostname, _ = os.Hostname()
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		product, _, _ := k.GetStringValue("ProductName")
		display, _, _ := k.GetStringValue("DisplayVersion")
		if display == "" {
			display, _, _ = k.GetStringValue("ReleaseId")
		}
		buildStr, _, _ := k.GetStringValue("CurrentBuildNumber")
		build := 0
		for _, c := range buildStr {
			if c < '0' || c > '9' {
				break
			}
			build = build*10 + int(c-'0')
		}
		s.Platform.Pretty = WindowsPretty(product, display, build)
		k.Close()
	}
	hw := &Hardware{}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE); err == nil {
		hw.SystemVendor, hw.SystemModel = regString(k, "SystemManufacturer"), regString(k, "SystemProductName")
		hw.BoardVendor, hw.BoardModel = regString(k, "BaseBoardManufacturer"), regString(k, "BaseBoardProduct")
		hw.BIOSVersion = regString(k, "BIOSVersion")
		k.Close()
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, registry.QUERY_VALUE); err == nil {
		hw.CPUModel = regString(k, "ProcessorNameString")
		k.Close()
	}
	if *hw != (Hardware{}) {
		s.Hardware = hw
	}
	return s
}

// Static returns what was read at start.
func (w *Windows) Static() Static { return w.static }

func systemTimes() (idle, kernel, user uint64, ok bool) {
	var i, k, u windows.Filetime
	r, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&i)), uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(&u)))
	return ft64(i), ft64(k), ft64(u), r != 0
}

// Sample reads the changing values.
func (w *Windows) Sample(context.Context) Sample {
	now := time.Now()
	var s Sample
	if i, k, u, ok := systemTimes(); ok {
		w.mu.Lock()
		if now.Sub(w.prevAt) >= 500*time.Millisecond || w.lastPct == nil {
			if p := CPUDelta(w.prevIdle, w.prevKern, w.prevU, i, k, u); p != nil {
				w.lastPct = p
			}
			w.prevIdle, w.prevKern, w.prevU, w.prevAt = i, k, u, now
		}
		s.CPUPercent = w.lastPct
		w.mu.Unlock()
	}
	ms := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	if r, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&ms))); r != 0 {
		s.Memory = Memory{Total: int64(ms.TotalPhys), Used: int64(ms.TotalPhys - ms.AvailPhys)}
	}
	s.Disks = w.disks(now)
	s.Net = netCounters()
	if ms, _, _ := procGetTickCount64.Call(); ms != 0 {
		up := int64(ms / 1000)
		s.UptimeS = &up
	}
	s.Temps, s.Fans, s.Voltages = w.thermalZones(now), []Fan{}, []Voltage{}
	s.Power = Power{Sensors: []PowerSensor{}, Source: []string{}}
	var ps systemPowerStatus
	ok, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&ps)))
	if ok != 0 {
		s.Battery = WindowsBattery(ps.ACLineStatus, ps.BatteryFlag, ps.BatteryLifePercent, ps.BatteryLifeTime)
	}
	if ok != 0 && ps.BatteryFlag != 128 && ps.BatteryFlag != 255 {
		state := "discharging"
		switch {
		case ps.BatteryFlag&8 != 0:
			state = "charging"
		case ps.ACLineStatus == 1 && ps.BatteryLifePercent >= 100:
			state = "full"
		case ps.ACLineStatus == 1:
			state = "not charging"
		}
		s.Power.BatteryState = &state
		s.Power.Source = append(s.Power.Source, "battery")
	}
	return s
}

func (w *Windows) disks(now time.Time) []Disk {
	w.mu.Lock()
	if w.diskCache != nil && now.Sub(w.diskAt) < 10*time.Second {
		d := w.diskCache
		w.mu.Unlock()
		return d
	}
	w.mu.Unlock()
	disks := []Disk{}
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err == nil && int(n) <= len(buf) {
		start := 0
		for i := 0; i < int(n); i++ {
			if buf[i] != 0 {
				continue
			}
			if i > start {
				if d, ok := driveInfo(buf[start : i+1]); ok {
					disks = append(disks, d)
				}
			}
			start = i + 1
		}
	}
	w.mu.Lock()
	w.diskCache, w.diskAt = disks, now
	w.mu.Unlock()
	return disks
}

func driveInfo(root []uint16) (Disk, bool) {
	p := &root[0]
	if windows.GetDriveType(p) != windows.DRIVE_FIXED {
		return Disk{}, false
	}
	var free, total, totalFree uint64
	if windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree) != nil || total == 0 {
		return Disk{}, false
	}
	fs := make([]uint16, 64)
	fsType := ""
	if windows.GetVolumeInformation(p, nil, 0, nil, nil, nil, &fs[0], uint32(len(fs))) == nil {
		fsType = windows.UTF16ToString(fs)
	}
	return Disk{Mount: windows.UTF16ToString(root), FSType: fsType, Total: int64(total), Used: int64(total - totalFree)}, true
}

// netCounters sums the hardware interfaces (not filter, loopback, VPN or virtual switch interfaces).
func netCounters() Net {
	var t *windows.MibIfTable2
	if windows.GetIfTable2Ex(windows.MibIfTableNormal, &t) != nil || t == nil {
		return Net{}
	}
	defer windows.FreeMibTable(unsafe.Pointer(t))
	rows := unsafe.Slice(&t.Table[0], t.NumEntries)
	var hw, all Net
	for i := range rows {
		r := &rows[i]
		if r.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK || r.InterfaceAndOperStatusFlags&0x02 != 0 { // FilterInterface
			continue
		}
		all.BytesRecv += int64(r.InOctets)
		all.BytesSent += int64(r.OutOctets)
		if r.InterfaceAndOperStatusFlags&0x01 != 0 { // HardwareInterface
			hw.BytesRecv += int64(r.InOctets)
			hw.BytesSent += int64(r.OutOctets)
		}
	}
	if hw == (Net{}) {
		return all
	}
	return hw
}

func (w *Windows) thermalZones(now time.Time) []Temp {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.temps != nil && now.Sub(w.tempsAt) < 5*time.Second {
		return w.temps
	}
	w.tempsAt = now
	w.temps = []Temp{}
	if w.thermalOff {
		return w.temps
	}
	if w.thermal == nil {
		q, err := newPDHQuery(`\Thermal Zone Information(*)\Temperature`)
		if err != nil {
			w.thermalOff = true // no thermal zones on this machine
			return w.temps
		}
		w.thermal = q
	}
	vals, err := w.thermal.values()
	if err != nil {
		return w.temps
	}
	for _, v := range vals {
		if c, ok := KelvinToC(v.value); ok {
			label := "ACPI thermal zone " + strings.TrimPrefix(v.name, `\_TZ.`)
			w.temps = append(w.temps, Temp{Sensor: "acpi", Label: &label, Current: c})
		}
	}
	return w.temps
}

func (w *Windows) account(tok windows.Token) *string {
	tu, err := tok.GetTokenUser()
	if err != nil {
		return nil
	}
	sid := tu.User.Sid.String()
	w.mu.Lock()
	name, ok := w.accounts[sid]
	w.mu.Unlock()
	if !ok {
		acct, dom, _, err := tu.User.Sid.LookupAccount("")
		if err != nil {
			name = sid
		} else if dom != "" {
			name = dom + `\` + acct
		} else {
			name = acct
		}
		w.mu.Lock()
		w.accounts[sid] = name
		w.mu.Unlock()
	}
	return &name
}

type winRow struct {
	p   Process
	cpu *winProcSample
}

func (w *Windows) scan(o ProcOptions) ([]winRow, int) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, 0
	}
	defer windows.CloseHandle(snap)
	var rows []winRow
	total := 0
	e := windows.ProcessEntry32{Size: uint32(unsafe.Sizeof(windows.ProcessEntry32{}))}
	for err = windows.Process32First(snap, &e); err == nil; err = windows.Process32Next(snap, &e) {
		pid := e.ProcessID
		total++
		if pid == 0 { // System Idle Process
			continue
		}
		name := windows.UTF16ToString(e.ExeFile[:])
		row := winRow{p: Process{PID: int(pid), Name: P(name), Status: P("running")}}
		if !o.NeverOpen[strings.ToLower(name)] {
			w.details(pid, &row, o)
		}
		rows = append(rows, row)
	}
	return rows, total
}

// details fills in what a PROCESS_QUERY_LIMITED_INFORMATION handle allows; on any error the row keeps just its
// name (access denied is normal for protected and other users' processes).
func (w *Windows) details(pid uint32, row *winRow, o ProcOptions) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	var c, x, k, u windows.Filetime
	if windows.GetProcessTimes(h, &c, &x, &k, &u) == nil {
		row.cpu = &winProcSample{cpu: ft64(k) + ft64(u), create: ft64(c)}
		if ct := FiletimeToUnix(ft64(c)); ct > 0 {
			row.p.CreateTime = P(Round(ct, 2))
		}
	}
	pmc := processMemoryCounters{CB: uint32(unsafe.Sizeof(processMemoryCounters{}))}
	if r, _, _ := procK32GetProcessMemInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&pmc)), uintptr(pmc.CB)); r != 0 {
		rss := int64(pmc.WorkingSetSize)
		row.p.RSS = &rss
		if o.MemTotal > 0 {
			row.p.MemPercent = P(Round(float64(rss)/float64(o.MemTotal)*100, 2))
		}
	}
	if o.Cmdline {
		buf := make([]uint16, 1024)
		n := uint32(len(buf))
		if windows.QueryFullProcessImageName(h, 0, &buf[0], &n) == nil {
			s := windows.UTF16ToString(buf[:n])
			row.p.Cmdline = &s
		}
	}
	var tok windows.Token
	if windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok) == nil {
		row.p.Username = w.account(tok)
		tok.Close()
	}
}

// Processes lists every process with CPU use since the previous listing (or over o.Interval).
func (w *Windows) Processes(ctx context.Context, o ProcOptions) ([]Process, int, error) {
	w.mu.Lock()
	prev, prevAt := w.procPrev, w.procPrevAt
	w.mu.Unlock()
	if prev == nil || time.Since(prevAt) > 30*time.Second {
		rows, _ := w.scan(ProcOptions{NeverOpen: o.NeverOpen})
		prev, prevAt = map[uint32]winProcSample{}, time.Now()
		for _, r := range rows {
			if r.cpu != nil {
				prev[uint32(r.p.PID)] = *r.cpu
			}
		}
		select {
		case <-ctx.Done():
			return nil, 0, ctx.Err()
		case <-time.After(o.Interval):
		}
	}
	now := time.Now()
	rows, total := w.scan(o)
	dt := now.Sub(prevAt)
	cur := map[uint32]winProcSample{}
	out := make([]Process, 0, len(rows))
	for _, r := range rows {
		if r.cpu != nil {
			pid := uint32(r.p.PID)
			cur[pid] = *r.cpu
			if pr, ok := prev[pid]; ok && pr.create == r.cpu.create && r.cpu.cpu >= pr.cpu {
				r.p.CPUPercent = P(ProcCPUPercent(r.cpu.cpu-pr.cpu, dt))
			} else {
				r.p.CPUPercent = P(0.0)
			}
		}
		out = append(out, r.p)
	}
	w.mu.Lock()
	w.procPrev, w.procPrevAt = cur, now
	w.mu.Unlock()
	return out, total, nil
}
