//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

const serviceName = "fairy-agent"

func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// isAdmin reports whether this process may change config.yaml: an elevated (UAC) token, or one that holds the
// Administrators group (SYSTEM, e.g. a remote-support shell).
func isAdmin() bool {
	if windows.GetCurrentProcessToken().IsElevated() {
		return true
	}
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	ok, err := windows.Token(0).IsMember(sid)
	return err == nil && ok
}

// lowerPriority runs the agent below normal priority so it never competes with games.
func lowerPriority() {
	_ = windows.SetPriorityClass(windows.CurrentProcess(), windows.BELOW_NORMAL_PRIORITY_CLASS)
}

type handler struct{ cfgPath string }

func (h handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- serve(ctx, h.cfgPath, false) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-errc:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		case err := <-errc:
			if err != nil {
				if el, e := eventlog.Open(serviceName); e == nil {
					_ = el.Error(1, "fairy-agent stopped: "+err.Error())
					el.Close()
				}
				return false, 1 // non-zero: the service manager restarts it (recovery actions)
			}
			return false, 0
		}
	}
}

func configArg() string {
	for i, a := range os.Args {
		if a == "--config" && i+1 < len(os.Args) {
			return os.Args[i+1]
		}
		if v, ok := strings.CutPrefix(a, "--config="); ok {
			return v
		}
	}
	return agent.DefaultConfigPath()
}

func runService() int {
	if err := svc.Run(serviceName, handler{cfgPath: configArg()}); err != nil {
		return 1
	}
	return 0
}

// applyACL replaces a folder's permissions (inherited by everything inside) with the given SDDL DACL.
func applyACL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

const starterConfig = `# fairy-agent configuration (see AGENT.md). Restart the service after a change:
#   Restart-Service fairy-agent
#
# listen: empty = this PC's Tailscale address on port 9101 (the agent never listens on every network).
# listen: 100.64.0.10:9101

# The panel's token for this PC is in the file "token" next to this one; fan, power and Wake-on-LAN (all
# off below) use the separate "control-token".

processes:
  enabled: true          # the panel's Processes tab; false = the agent never looks at other programs at all
  cmdline: true          # show program paths
  never_open: []         # e.g. [VALORANT-Win64-Shipping.exe]: listed by name only, never opened

gpu:
  nvidia_smi: auto       # auto | off | full path to nvidia-smi.exe

ipmi:
  enabled: false         # Supermicro BMC sensors (needs: fairy-agent install --account LocalSystem)

fan_control:
  enabled: false         # needs ipmi.enabled; fans never below 30 %, back to 100 % at 80 °C

power_control:
  enabled: false         # remote shutdown / reboot from the panel

wol:
  enabled: false         # send Wake-on-LAN packets for the panel

self_update:
  enabled: false         # let the panel's Update button install the latest signed release (see AGENT.md)
`

func writeIfMissing(path string, data []byte) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	_, err = f.Write(data)
	return true, err
}

func install(cfgPath, account string) error {
	var startName string
	switch strings.ToLower(account) {
	case "localservice":
		startName = `NT AUTHORITY\LocalService`
	case "localsystem":
		startName = "" // LocalSystem
	default:
		return errors.New("--account must be LocalService or LocalSystem")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = os.Getenv("ProgramFiles")
	}
	if pf != "" && !strings.HasPrefix(strings.ToLower(exe), strings.ToLower(pf)+`\`) {
		fmt.Println("warning: the service will run", exe, "- keep the program under", pf,
			"so only administrators can replace it")
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run PowerShell as Administrator): %w", err)
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return errors.New("the service is already installed (fairy-agent uninstall first to reinstall)")
	}
	s, err := m.CreateService(serviceName, exe, mgr.Config{DisplayName: "Fairy agent",
		Description: "Reports this PC's metrics to the Fairy homelab panel (read-only unless enabled in config.yaml).",
		StartType:   mgr.StartAutomatic, DelayedAutoStart: true, ServiceStartName: startName,
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED, ErrorControl: mgr.ErrorNormal},
		"run", "--config", cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)

	// Folder: administrators and SYSTEM full control, the service itself read-only; logs\ writable by it.
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return fmt.Errorf("service installed, but its account was not found for the folder permissions: %w", err)
	}
	dir := filepath.Dir(cfgPath)
	logs := filepath.Join(dir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		return err
	}
	if err := applyACL(dir, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+sid.String()+")"); err != nil {
		return fmt.Errorf("folder permissions: %w", err)
	}
	if err := applyACL(logs, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+sid.String()+")"); err != nil {
		return fmt.Errorf("log folder permissions: %w", err)
	}
	if err := setupSelfUpdate(cfgPath); err != nil {
		return fmt.Errorf("self-update permissions: %w", err)
	}
	if created, err := writeIfMissing(cfgPath, []byte(strings.ReplaceAll(starterConfig, "\n", "\r\n"))); err != nil {
		return err
	} else if created {
		fmt.Println("wrote a starter", cfgPath)
	}
	for _, name := range []string{"token", "control-token"} {
		tok, err := newToken()
		if err != nil {
			return err
		}
		p := filepath.Join(dir, name)
		if created, err := writeIfMissing(p, []byte(tok+"\r\n")); err != nil {
			return err
		} else if created {
			fmt.Println("created", p)
		}
	}
	fmt.Println(`installed the "fairy-agent" service (account: ` + account + `, starts automatically).
Next: check config.yaml, add the firewall rule from AGENT.md, then: Start-Service fairy-agent`)
	return nil
}

// grantACE adds (or widens) one allow entry for sid to an object's DACL, keeping everything else (inherited
// entries included). Running it again changes nothing.
func grantACE(name string, typ windows.SE_OBJECT_TYPE, handle windows.Handle, sid *windows.SID, mask windows.ACCESS_MASK, inherit uint32) error {
	var sd *windows.SECURITY_DESCRIPTOR
	var err error
	if handle != 0 {
		sd, err = windows.GetSecurityInfo(handle, typ, windows.DACL_SECURITY_INFORMATION)
	} else {
		sd, err = windows.GetNamedSecurityInfo(name, typ, windows.DACL_SECURITY_INFORMATION)
	}
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{AccessPermissions: mask, AccessMode: windows.GRANT_ACCESS,
		Inheritance: inherit, Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID,
			TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP, TrusteeValue: windows.TrusteeValueFromSID(sid)}}}, old)
	if err != nil {
		return err
	}
	if handle != 0 {
		return windows.SetSecurityInfo(handle, typ, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	}
	return windows.SetNamedSecurityInfo(name, typ, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// setupSelfUpdate gives the service's own SID (NT SERVICE\fairy-agent; no other account or service) what the
// self-update needs, idempotently:
//   - modify on the program folder (C:\Program Files\Fairy), to rename the exe to .old and put the new one in;
//   - an update folder under ProgramData it may write (stage + result), like logs\;
//   - start / stop / query on its own service, so the installer it starts can restart it.
//
// The agent still installs only releases signed with the key built into it, and only when self_update is
// enabled in config.yaml.
func setupSelfUpdate(cfgPath string) error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return fmt.Errorf("the service account was not found (is the service installed?): %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	const modify = 0x1301bf // read, write, execute, delete
	if err := grantACE(filepath.Dir(exe), windows.SE_FILE_OBJECT, 0, sid, modify, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT); err != nil {
		return fmt.Errorf("program folder %s: %w", filepath.Dir(exe), err)
	}
	upd := filepath.Join(filepath.Dir(cfgPath), "update")
	if err := os.MkdirAll(upd, 0o700); err != nil {
		return err
	}
	if err := applyACL(upd, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+sid.String()+")"); err != nil {
		return fmt.Errorf("update folder %s: %w", upd, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run PowerShell as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the %s service is not installed: %w", serviceName, err)
	}
	defer s.Close()
	const svcRights = windows.SERVICE_START | windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS | windows.SERVICE_INTERROGATE
	if err := grantACE("", windows.SE_SERVICE, s.Handle, sid, svcRights, windows.NO_INHERITANCE); err != nil {
		return fmt.Errorf("service permissions: %w", err)
	}
	fmt.Println("self-update permissions set (service account " + `NT SERVICE\` + serviceName + ")")
	return nil
}

func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run PowerShell as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return errors.New("the service is not installed")
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		for i := 0; i < 40; i++ {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(serviceName)
	fmt.Println(`removed the "fairy-agent" service. Its folder (config, tokens, logs) is kept: delete`,
		filepath.Dir(agent.DefaultConfigPath()), "yourself if you no longer need it.")
	return nil
}
