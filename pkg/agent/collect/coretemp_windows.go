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
// Names tried, first found wins: the Global\ names; the plain names (when the agent itself runs in the
// signed-in user's session, e.g. "fairy-agent run" in a console); and the console session's names through the
// system's Session\<id>\ link (lets a LocalSystem service read Core Temp without the global setting).
//
// Only OpenFileMappingW(FILE_MAP_READ) + MapViewOfFile(FILE_MAP_READ): the view is read-only, copied at once
// and unmapped. No synchronisation object of Core Temp's is opened; a reading taken while Core Temp updates the
// block can mix old and new values of single cores, which is harmless.

import (
	"errors"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procOpenFileMappingW = kernel32.NewProc("OpenFileMappingW")

var coreTempRead = readCoreTempWindows

func coreTempNames() []string {
	names := []string{`Global\CoreTempMappingObjectEx`, `Global\CoreTempMappingObject`,
		"CoreTempMappingObjectEx", "CoreTempMappingObject"}
	var own uint32
	console := windows.WTSGetActiveConsoleSessionId()
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &own) == nil && console != 0xFFFFFFFF && console != own {
		s := `Session\` + strconv.FormatUint(uint64(console), 10) + `\`
		names = append(names, s+"CoreTempMappingObjectEx", s+"CoreTempMappingObject")
	}
	return names
}

func readCoreTempWindows() ([]byte, string, error) {
	denied := ""
	for _, name := range coreTempNames() {
		b, err := readMapping(name)
		if err == nil {
			return b, name, nil
		}
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) && denied == "" {
			denied = name
		}
	}
	if denied != "" {
		return nil, denied, errCoreTempDenied
	}
	return nil, "", errCoreTempAbsent
}

// readMapping copies up to CoreTempExSize bytes of the named file mapping (read-only).
func readMapping(name string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	r, _, callErr := procOpenFileMappingW.Call(windows.FILE_MAP_READ, 0, uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return nil, callErr
	}
	h := windows.Handle(r)
	defer windows.CloseHandle(h)
	addr, err := windows.MapViewOfFile(h, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	defer windows.UnmapViewOfFile(addr)
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
		return nil, err
	}
	n := min(int(mbi.RegionSize), CoreTempExSize)
	view := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), n)
	return append([]byte(nil), view...), nil
}
