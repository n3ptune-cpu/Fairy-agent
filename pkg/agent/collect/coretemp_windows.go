//go:build windows

package collect

// Reading Core Temp's shared memory (see coretemp.go for the layout and the source of the specification).
//
// Core Temp always creates "CoreTempMappingObjectEx" (and the older "CoreTempMappingObject") in the namespace of
// the session it runs in (Local\, e.g. \Sessions\1\BaseNamedObjects). A service runs in session 0 and cannot
// see those names. With Core Temp's setting "Enable global shared memory (SNMP)" (Options > Settings >
// Advanced; CoreTemp.ini [Advanced] SnmpSharedMemory=1) it also creates "Global\CoreTempMappingObjectEx" and
// "Global\CoreTempMappingObject", which a service can open. Core Temp creates them with the default security
// of its own (elevated) token, which lets SYSTEM and administrators read them; other accounts such as
// LocalService are usually refused.
//
// Names tried, first usable one wins (coretemp_source.go): the Global\ names; the plain names (when the agent
// itself runs in the signed-in user's session, e.g. "fairy-agent run" in a console); and the console session's
// names through the system's Session\<id>\ link (lets a LocalSystem service read Core Temp without the global
// setting). A name outside Global\ can be created by any program of the signed-in user, so it is used only when
// the object belongs to Administrators or SYSTEM (Core Temp runs elevated); anything else under that name is
// never mapped. A Global\ name can be created by any service in session 0: its owner is read too, and an object
// of a service's account is never mapped (coretemp_source.go has the whole rule).
//
// Only OpenFileMappingW(FILE_MAP_READ plus READ_CONTROL, to read the object's owner from the same handle) +
// MapViewOfFile(FILE_MAP_READ): the view is read-only, copied at once and unmapped. No synchronisation object
// of Core Temp's is opened; a reading taken while Core Temp updates the block can mix old and new values of
// single cores, which is harmless. The copy is at most the size of the block, only of committed readable
// memory, and a fault while copying (a view of a file that shrank) is an error, not a crash: the helper holds
// the fans and must keep running.

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procOpenFileMappingW = kernel32.NewProc("OpenFileMappingW")

var coreTempRead = readCoreTempWindows

// coreTempNoted: what coreTempOwnerProblem had to say about an object that is used all the same, said once.
var coreTempNoted sync.Map

func coreTempNames() []coreTempName {
	var own uint32
	known := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &own) == nil
	return coreTempCandidates(own, windows.WTSGetActiveConsoleSessionId(), known)
}

func readCoreTempWindows() ([]byte, string, error) {
	denied := ""
	var untrusted error
	for _, c := range coreTempNames() {
		b, err := readMapping(c)
		if err == nil {
			return b, c.Name, nil
		}
		if errors.Is(err, ErrCoreTempUntrusted) && untrusted == nil {
			untrusted = err
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && denied == "" {
			denied = c.Name
		}
	}
	if untrusted != nil { // say so, instead of "Core Temp is not running"
		return nil, "", untrusted
	}
	if denied != "" {
		return nil, denied, errCoreTempDenied
	}
	return nil, "", errCoreTempAbsent
}

// mappingOwner is the owner SID of an open file mapping (the handle needs READ_CONTROL).
func mappingOwner(h windows.Handle) (string, error) {
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return "", err
	}
	if owner == nil {
		return "", errors.New("no owner")
	}
	return owner.String(), nil
}

// readMapping copies up to CoreTempExSize bytes of the named file mapping (read-only).
func readMapping(c coreTempName) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(c.Name)
	if err != nil {
		return nil, err
	}
	// READ_CONTROL: to read the object's owner before anything of it is mapped, from the handle that is mapped
	access := uintptr(windows.FILE_MAP_READ | windows.READ_CONTROL)
	r, _, callErr := procOpenFileMappingW.Call(access, 0, uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return nil, callErr
	}
	h := windows.Handle(r)
	defer windows.CloseHandle(h)
	owner, oerr := mappingOwner(h)
	note, problem := coreTempOwnerProblem(c, owner, oerr)
	if problem != nil {
		return nil, problem
	}
	if note != "" {
		if _, said := coreTempNoted.LoadOrStore(note, true); !said {
			slog.Warn(note)
		}
	}
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	defer windows.UnmapViewOfFile(addr)
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		return nil, err
	}
	if mbi.State != windows.MEM_COMMIT || mbi.Protect&(windows.PAGE_NOACCESS|windows.PAGE_GUARD) != 0 {
		return nil, fmt.Errorf("core temp shared memory %q is not readable memory (state %#x, protection %#x)", c.Name, mbi.State, mbi.Protect)
	}
	n, err := coreTempCopyLen(uint64(mbi.RegionSize))
	if err != nil {
		return nil, err
	}
	return copyView(addr, n)
}

// copyView copies n bytes of a mapped view. Reading a view can fault (a mapping of a file that was cut short
// after it was mapped); that must not take the process down, so the fault becomes an error.
func copyView(addr uintptr, n int) (b []byte, err error) {
	defer debug.SetPanicOnFault(debug.SetPanicOnFault(true))
	defer func() {
		if r := recover(); r != nil {
			b, err = nil, fmt.Errorf("core temp shared memory could not be read: %v", r)
		}
	}()
	view := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), n)
	return append([]byte(nil), view...), nil
}
