//go:build windows

package agent

import (
	"time"

	"golang.org/x/sys/windows"
)

// systemPower uses InitiateSystemShutdownEx: Windows itself counts down (and shows its "you are about to be
// signed out" warning to whoever is logged in) and AbortSystemShutdown cancels. Like `shutdown /s /t N`, running
// programs are closed after the countdown. Needs SeShutdownPrivilege, which LocalService and LocalSystem have.
type systemPower struct{}

// SystemPower returns the Windows implementation.
func SystemPower() PowerExec { return systemPower{} }

var procAbortSystemShutdown = windows.NewLazySystemDLL("advapi32.dll").NewProc("AbortSystemShutdownW")

func enableShutdownPrivilege() error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	name, _ := windows.UTF16PtrFromString("SeShutdownPrivilege")
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

func (systemPower) Schedule(action string, delay time.Duration, message string) error {
	if err := enableShutdownPrivilege(); err != nil {
		return err
	}
	msg, _ := windows.UTF16PtrFromString(message)
	reason := uint32(windows.SHTDN_REASON_MAJOR_OTHER | windows.SHTDN_REASON_MINOR_OTHER | windows.SHTDN_REASON_FLAG_PLANNED)
	return windows.InitiateSystemShutdownEx(nil, msg, uint32(delay/time.Second), true, action == "reboot", reason)
}

func (systemPower) Cancel() error {
	if err := enableShutdownPrivilege(); err != nil {
		return err
	}
	if r, _, err := procAbortSystemShutdown.Call(0); r == 0 {
		return err
	}
	return nil
}
