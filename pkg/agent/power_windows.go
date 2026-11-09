//go:build windows

package agent

import (
	"log/slog"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemPower uses InitiateSystemShutdownEx for shutdown and reboot: Windows itself counts down (and shows its
// "you are about to be signed out" warning to whoever is logged in) and AbortSystemShutdown cancels. Like
// `shutdown /s /t N`, running programs are closed after the countdown. Sleep has no Windows countdown: the agent
// waits and then calls SetSuspendState (sleep, not hibernate). All need SeShutdownPrivilege, which LocalService
// and LocalSystem have.
type systemPower struct {
	mu    sync.Mutex
	sleep *time.Timer
}

// SystemPower returns the Windows implementation.
func SystemPower() PowerExec { return &systemPower{} }

var (
	procAbortSystemShutdown = windows.NewLazySystemDLL("advapi32.dll").NewProc("AbortSystemShutdownW")
	powrprof                = windows.NewLazySystemDLL("powrprof.dll")
	procSetSuspendState     = powrprof.NewProc("SetSuspendState")
	procGetPwrCapabilities  = powrprof.NewProc("GetPwrCapabilities")
)

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

func (s *systemPower) Schedule(action string, delay time.Duration, message string) error {
	if err := enableShutdownPrivilege(); err != nil {
		return err
	}
	if action == "sleep" {
		if err := procSetSuspendState.Find(); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.sleep != nil {
			s.sleep.Stop()
		}
		s.sleep = time.AfterFunc(delay, func() {
			slog.Warn("power: going to sleep (SetSuspendState)")
			if err := enableShutdownPrivilege(); err != nil {
				slog.Error("power: sleep failed", "error", err.Error())
				return
			}
			// bHibernate FALSE (sleep), bForce FALSE, bWakeupEventsDisabled FALSE (Wake-on-LAN and timers may wake it)
			if r, _, err := procSetSuspendState.Call(0, 0, 0); r == 0 {
				slog.Error("power: sleep failed", "error", err.Error())
			}
		})
		return nil
	}
	msg, _ := windows.UTF16PtrFromString(message)
	reason := uint32(windows.SHTDN_REASON_MAJOR_OTHER | windows.SHTDN_REASON_MINOR_OTHER | windows.SHTDN_REASON_FLAG_PLANNED)
	return windows.InitiateSystemShutdownEx(nil, msg, uint32(delay/time.Second), true, action == "reboot", reason)
}

func (s *systemPower) Cancel() error {
	s.mu.Lock()
	if s.sleep != nil {
		s.sleep.Stop()
		s.sleep = nil
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	if err := enableShutdownPrivilege(); err != nil {
		return err
	}
	if r, _, err := procAbortSystemShutdown.Call(0); r == 0 {
		return err
	}
	return nil
}

// CanSleep reads GetPwrCapabilities (SYSTEM_POWER_CAPABILITIES): sleep means S1-S3. A machine with only Modern
// Standby (S0 low power idle, AoAc) cannot be sent to sleep by SetSuspendState.
func (s *systemPower) CanSleep() (bool, string) {
	if err := procGetPwrCapabilities.Find(); err != nil {
		return false, "powrprof.dll: " + err.Error()
	}
	var caps [128]byte // SYSTEM_POWER_CAPABILITIES is 76 bytes
	if r, _, err := procGetPwrCapabilities.Call(uintptr(unsafe.Pointer(&caps[0]))); r == 0 {
		return false, "GetPwrCapabilities: " + err.Error()
	}
	return sleepFromCaps(caps[:])
}
