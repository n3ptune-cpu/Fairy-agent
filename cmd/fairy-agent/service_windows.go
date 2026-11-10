//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
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
	if len(os.Args) > 1 && os.Args[1] == "apply-update" { // the fairy-agent-update service (LocalSystem)
		if err := svc.Run(agent.UpdaterServiceName, updaterHandler{cfgPath: configArg()}); err != nil {
			return 1
		}
		return 0
	}
	if len(os.Args) > 1 && os.Args[1] == "helper" { // the fairy-agent-helper service (LocalSystem)
		if err := svc.Run(proto.ServiceName, helperHandler{cfgPath: configArg()}); err != nil {
			return 1
		}
		return 0
	}
	if err := svc.Run(serviceName, handler{cfgPath: configArg()}); err != nil {
		return 1
	}
	return 0
}

// updaterExitUntrusted is the updater service's exit code when it refused to run because the data folder
// cannot be trusted (the reason is in the Event Log, source fairy-agent).
const updaterExitUntrusted = 3

// updaterHandler is the fairy-agent-update service: it installs what the agent staged (applyUpdateCtx) and
// stops. The agent's own account may only start it; start parameters are ignored.
type updaterHandler struct{ cfgPath string }

func (h updaterHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	// This service is LocalSystem and is started by the agent's low-rights account. Before it reads config.yaml
	// (which names the token file it would read and the address it would send the token to) or opens its log
	// in update\, the data folder must be one only administrators and SYSTEM can change. If it is not, nothing
	// is opened or written there: the reason goes to the Windows Event Log and the service stops.
	if err := updateDirTrusted(h.cfgPath); err != nil {
		if el, e := eventlog.Open(serviceName); e == nil {
			_ = el.Error(1, "fairy-agent-update did nothing: "+err.Error())
			el.Close()
		}
		status <- svc.Status{State: svc.StopPending}
		return true, updaterExitUntrusted
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan int, 1)
	go func() { done <- applyUpdateCtx(ctx, h.cfgPath) }()
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
				case <-done:
				case <-time.After(20 * time.Second):
				}
				return false, 0
			}
		case code := <-done:
			status <- svc.Status{State: svc.StopPending}
			if code != 0 {
				return true, uint32(code) // service-specific exit code; the result file has the reason
			}
			return false, 0
		}
	}
}

const windowsStarter = `# fairy-agent configuration (see AGENT.md). Restart the service after a change:
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
  enabled: false         # Supermicro BMC sensors (through the fairy-agent-helper service, see AGENT.md)

fan_control:
  enabled: false         # needs ipmi.enabled; fans never below 30 %, back to 100 % at 80 °C

power_control:
  enabled: false         # remote shutdown / reboot from the panel

wol:
  enabled: false         # send Wake-on-LAN packets for the panel

self_update:
  enabled: false         # let the panel's Update button install the latest signed release (see AGENT.md)
`

func starterConfig() string { return strings.ReplaceAll(windowsStarter, "\n", "\r\n") }

// agentAccount is the agent's virtual service account: no password, cannot sign in, only its own rights.
const agentAccount = `NT SERVICE\` + serviceName

func install(cfgPath, account string, withHelper bool) error {
	switch strings.ToLower(account) {
	case "":
	case "localsystem":
		fmt.Println(`note: --account LocalSystem is deprecated: the agent now always runs as ` + agentAccount +
			` and the elevated fairy-agent-helper service is installed instead (same as --helper)`)
		withHelper = true
	case "localservice":
		fmt.Println(`note: --account is deprecated: the agent runs as ` + agentAccount)
	default:
		return errors.New("--account is deprecated (the agent runs as " + agentAccount + "); use --helper for Core Temp, IPMI, fans or power control")
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
		StartType:   mgr.StartAutomatic, DelayedAutoStart: true, ServiceStartName: agentAccount,
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED, ErrorControl: mgr.ErrorNormal},
		"run", "--config", cfgPath)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := hardenAgentService(s); err != nil {
		return fmt.Errorf("service installed, but: %w", err)
	}
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	// The data folder: created with its final permissions, or, when something is already there, checked file
	// by file and repaired (setupFolders). A starter config.yaml and the tokens are written when missing;
	// existing ones are kept unless they could not be trusted.
	if err := setupFolders(cfgPath); err != nil {
		return err
	}
	if err := setup(cfgPath, withHelper, false); err != nil {
		fmt.Println("warning:", err)
	}
	fmt.Println(`installed the "fairy-agent" service (account: ` + agentAccount + `, starts automatically).
Next: check config.yaml, add the firewall rule from AGENT.md, then: Start-Service fairy-agent`)
	return nil
}

// Rights of the services. The agent's token keeps only SeChangeNotifyPrivilege (every process needs it to walk
// folders): no shutdown, no impersonation, nothing else, whatever the account would get by default. The
// helper is LocalSystem but keeps only what it uses: SeShutdownPrivilege (shutdown, reboot, sleep),
// SeImpersonatePrivilege (to identify pipe clients) and SeChangeNotifyPrivilege; without SeDebugPrivilege,
// SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege ... it can neither open other programs'
// memory, nor load a driver, nor take files over.
var (
	agentPrivileges  = []string{"SeChangeNotifyPrivilege"}
	helperPrivileges = []string{"SeChangeNotifyPrivilege", "SeImpersonatePrivilege", "SeShutdownPrivilege"}
)

// serviceSidInfo is SERVICE_SID_INFO; requiredPrivilegesInfo is SERVICE_REQUIRED_PRIVILEGES_INFO.
type serviceSidInfo struct{ ServiceSidType uint32 }
type requiredPrivilegesInfo struct{ RequiredPrivileges *uint16 }

func setRequiredPrivileges(h windows.Handle, privs []string) error {
	var block []uint16 // REG_MULTI_SZ: each name NUL-terminated, then one more NUL
	for _, p := range privs {
		u, err := windows.UTF16FromString(p)
		if err != nil {
			return err
		}
		block = append(block, u...)
	}
	block = append(block, 0)
	info := requiredPrivilegesInfo{RequiredPrivileges: &block[0]}
	return windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, (*byte)(unsafe.Pointer(&info)))
}

func setSidType(h windows.Handle, t uint32) error {
	info := serviceSidInfo{ServiceSidType: t}
	return windows.ChangeServiceConfig2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&info)))
}

func setRecovery(s *mgr.Service) {
	_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second}, {Type: mgr.ServiceRestart, Delay: 60 * time.Second}}, 86400)
	_ = s.SetRecoveryActionsOnNonCrashFailures(true)
}

// hardenAgentService makes the agent's service run as its virtual account with an unrestricted service SID
// (the folder permissions name that SID) and only SeChangeNotifyPrivilege. It reports whether the account
// changed (the change takes effect when the service next starts).
func hardenAgentService(s *mgr.Service) error {
	_, err := migrateAgentAccount(s)
	return err
}

func migrateAgentAccount(s *mgr.Service) (bool, error) {
	c, err := s.Config()
	if err != nil {
		return false, err
	}
	changed := !strings.EqualFold(c.ServiceStartName, agentAccount)
	if changed {
		acc, _ := windows.UTF16PtrFromString(agentAccount)
		// a virtual account has no password: lpPassword must be NULL
		if err := windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE,
			windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, acc, nil, nil); err != nil {
			return false, fmt.Errorf("switching the service to %s: %w", agentAccount, err)
		}
	}
	if err := setSidType(s.Handle, windows.SERVICE_SID_TYPE_UNRESTRICTED); err != nil {
		return changed, fmt.Errorf("service SID type: %w", err)
	}
	if err := setRequiredPrivileges(s.Handle, agentPrivileges); err != nil {
		return changed, fmt.Errorf("service privileges: %w", err)
	}
	setRecovery(s)
	return changed, nil
}

// setupFolders makes C:\ProgramData\fairy-agent safe to use and complete (as Administrator: install and
// setup-self-update; safe to run again). See repairDataDir and fillDataDir in datadir.go:
//   - the folder (config.yaml, token, control-token): administrators and SYSTEM full control, the agent's
//     account read-only, owner Administrators; logs\, state\ and update\stage\: the agent may write; helper\
//     and update\: the agent may only read. A folder that is missing is created with these permissions in the
//     same call.
//   - what already exists is not taken on trust: every file and folder must be a plain one owned by
//     Administrators or SYSTEM that nobody else can change. What is not is moved aside (never used), links
//     are removed, and what was done is printed.
//   - a starter config.yaml and the two tokens are written when they are missing. Existing ones are kept, so
//     a healthy PC stays paired; only when another account could have read or changed them are new tokens
//     written (and the PC must be paired again).
func setupFolders(cfgPath string) error {
	return repairDataFolder(cfgPath, os.Stdout)
}

// applyACL replaces the permissions of one file or folder with the given SDDL DACL (and its owner, when the
// SDDL names one), on the object opened itself: a link is refused, never followed.
func applyACL(path, sddl string) error { return winFS{}.Secure(path, sddl) }

// withObject opens path itself (never what a link points to) with access, refuses a link, and runs f on the
// handle: security is read and set on what was opened, not by name.
func withObject(path string, access uint32, f func(h windows.Handle) error) error {
	h, info, err := openObject(path, access)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if isLink(info) {
		return fmt.Errorf("%s is a link (a junction or symbolic link): remove it", path)
	}
	return f(h)
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

// revokeSID removes every explicit allow entry for sid from the DACL of an open file or folder (inherited
// entries of objects inside follow when Windows propagates the change).
func revokeSID(h windows.Handle, sid *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if old == nil {
		return nil // no permission list at all: nothing of sid's to remove (and never write a NULL list back)
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{AccessMode: windows.REVOKE_ACCESS,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid)}}}, old)
	if err != nil {
		return err
	}
	if acl == nil {
		return errors.New("no permission list to set")
	}
	return windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}

// secureProgramFolder takes back the write access to the program folder (and the files in it) that fairy-agent
// 0.4.2 and older gave the service's own account for self-update, and makes Administrators the owner of
// anything that service created there (an exe the old in-service installer put in place is owned by the
// service's account, and an owner can always change the permissions).
func secureProgramFolder(dir string, sid *windows.SID) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	_ = enablePrivilege("SeTakeOwnershipPrivilege") // administrators and SYSTEM hold it, disabled
	_ = enablePrivilege("SeRestorePrivilege")
	paths := []string{dir}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range ents {
		paths = append(paths, filepath.Join(dir, e.Name()))
	}
	for _, p := range paths {
		// each object is opened itself and changed through that handle: a link put there (by the service's
		// account, while it could still write here) is refused, and nothing it points to is touched
		err := withObject(p, windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER, func(h windows.Handle) error {
			if err := revokeSID(h, sid); err != nil {
				return err
			}
			sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
			if err != nil {
				return err
			}
			if owner, _, err := sd.Owner(); err == nil && owner != nil && collect.TrustedOwner(owner.String()) {
				return nil
			}
			if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
				return fmt.Errorf("making Administrators the owner: %w", err)
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
	}
	return nil
}

// enablePrivilege switches on one privilege this process's token holds.
func enablePrivilege(name string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var luid windows.LUID
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
	return windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
}

// checkProgramFolder runs when the agent starts: if the program (or its folder) can be changed by anyone but
// administrators / SYSTEM - typically the service's own Modify entry from fairy-agent 0.4.2 after an update
// through the panel - it removes the service's entry when it may (running as LocalSystem), else it says how to.
func checkProgramFolder() {
	checkDataFolder()
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, _ = filepath.Abs(exe)
	if collect.TrustedExecutable(exe) == nil {
		return
	}
	if sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName); err == nil {
		if secureProgramFolder(filepath.Dir(exe), sid) == nil && collect.TrustedExecutable(exe) == nil {
			slog.Warn("removed the service's write access to the program folder (left by fairy-agent 0.4.2 or older)", "folder", filepath.Dir(exe))
			return
		}
	}
	err = collect.TrustedExecutable(exe)
	slog.Warn("the fairy-agent program can be changed by others than administrators; fix it "+agent.UpdaterSetupHint, "problem", err.Error())
}

// checkDataFolder runs when the agent starts: it only looks (the agent's account can read the folder's owner
// and permissions) and warns when config.yaml or its folder could be changed by someone other than
// administrators and SYSTEM. The agent goes on running with what it has; the updater and the helper, which
// are LocalSystem, refuse such a folder until an administrator has repaired it.
func checkDataFolder() {
	err := trustedDataDir(configArg())
	switch {
	case err == nil:
	case errors.Is(err, os.ErrPermission):
		// this account may not read some owner or permission list: that says nothing about the folder
		slog.Info("the data folder's permissions could not be looked at with the agent's own rights", "detail", err.Error())
	default:
		slog.Warn("the agent's data folder is not safe: self-update and the helper will not work until it is repaired", "problem", err.Error())
	}
}

// setupSelfUpdate sets up self-update, idempotently (as Administrator: install and install-fairy-agent.ps1 run it):
//   - removes the program-folder write access fairy-agent 0.4.2 and older gave the service's account
//     (NT SERVICE\fairy-agent); the program folder stays administrators-only;
//   - update\ under ProgramData: administrators / SYSTEM full control, the service read-only (the installer's
//     result and log); update\stage\: the service may write (it downloads the release there);
//   - the fairy-agent-update service: LocalSystem, started on demand, runs this (installed) program's
//     apply-update; the agent's account may only start and query it;
//   - takes back the start / stop right on its own service that older versions gave the agent.
//
// The installer only installs releases signed with the key built into the installed program, and only when
// self_update is enabled in config.yaml (the agent will not stage anything otherwise).
func setupSelfUpdate(cfgPath string) error {
	sid, _, _, err := windows.LookupSID("", agentAccount)
	if err != nil {
		return fmt.Errorf("the service account was not found (is the service installed?): %w", err)
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	if err := secureProgramFolder(filepath.Dir(exe), sid); err != nil {
		return err
	}
	upd := filepath.Join(filepath.Dir(cfgPath), "update")
	stage := filepath.Join(upd, "stage")
	// update\ (the agent reads), update\stage\ and state\ (the agent writes; state\ holds the pairing): made
	// with their permissions when missing; an existing one is opened itself, must be a plain folder, and gets
	// owner Administrators and its permissions on that handle
	if err := ensureFolders(cfgPath, "update", "update/stage", "state"); err != nil {
		return fmt.Errorf("update and state folders: %w", err)
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
	if err := revokeServiceSID(s.Handle, sid); err != nil {
		return fmt.Errorf("service permissions: %w", err)
	}
	if err := collect.TrustedExecutable(exe); err != nil {
		return fmt.Errorf("the updater would run this program as LocalSystem, so only administrators may be able to change it (install it in C:\\Program Files\\Fairy): %w", err)
	}
	u, err := m.OpenService(agent.UpdaterServiceName)
	cfg := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, DisplayName: "Fairy agent updater",
		Description: "Installs a signed fairy-agent release that the Fairy agent downloaded (the panel's Update button), then stops.",
		StartType:   mgr.StartManual, ServiceStartName: "LocalSystem", ErrorControl: mgr.ErrorNormal,
		BinaryPathName: syscall.EscapeArg(exe) + " apply-update --config " + syscall.EscapeArg(cfgPath)}
	if err == nil {
		old, qerr := u.Config()
		if qerr == nil {
			cfg.Dependencies, cfg.LoadOrderGroup = old.Dependencies, old.LoadOrderGroup
		}
		if err := u.UpdateConfig(cfg); err != nil {
			u.Close()
			return fmt.Errorf("updating the %s service: %w", agent.UpdaterServiceName, err)
		}
	} else {
		u, err = m.CreateService(agent.UpdaterServiceName, exe, cfg, "apply-update", "--config", cfgPath)
		if err != nil {
			return fmt.Errorf("creating the %s service: %w", agent.UpdaterServiceName, err)
		}
	}
	defer u.Close()
	if err := grantACE("", windows.SE_SERVICE, u.Handle, sid, windows.SERVICE_START|windows.SERVICE_QUERY_STATUS, windows.NO_INHERITANCE); err != nil {
		return fmt.Errorf("%s service permissions: %w", agent.UpdaterServiceName, err)
	}
	fmt.Println("self-update set up: the " + agent.UpdaterServiceName + " service (LocalSystem) installs signed releases; " +
		`NT SERVICE\` + serviceName + " may start it, write " + stage + " and nothing in " + filepath.Dir(exe))
	return nil
}

// revokeServiceSID removes every allow entry for sid from a service's DACL.
func revokeServiceSID(h windows.Handle, sid *windows.SID) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	old, _, err := sd.DACL()
	if err != nil {
		return err
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{AccessMode: windows.REVOKE_ACCESS,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sid)}}}, old)
	if err != nil {
		return err
	}
	return windows.SetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
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
	stopAndWait(s, 20*time.Second)
	// while the service exists (its account exists only with it)
	if err := agent.RemoveCounterAccess(); err != nil {
		fmt.Println("warning:", err)
	}
	if err := s.Delete(); err != nil {
		return err
	}
	deleteHelper(m)
	if u, err := m.OpenService(agent.UpdaterServiceName); err == nil {
		if err := u.Delete(); err != nil {
			fmt.Println("warning: could not remove the", agent.UpdaterServiceName, "service:", err)
		}
		u.Close()
	}
	_ = eventlog.Remove(serviceName)
	fmt.Println(`removed the "fairy-agent" services. Their folder (config, tokens, logs) is kept: delete`,
		filepath.Dir(agent.DefaultConfigPath()), "yourself if you no longer need it.")
	return nil
}
