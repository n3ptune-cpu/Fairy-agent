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

// updaterHandler is the fairy-agent-update service: it installs what the agent staged (applyUpdateCtx) and
// stops. The agent's own account may only start it; start parameters are ignored.
type updaterHandler struct{ cfgPath string }

func (h updaterHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
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
	dir := filepath.Dir(cfgPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := setupFolders(cfgPath); err != nil {
		return err
	}
	if created, err := writeIfMissing(cfgPath, []byte(starterConfig())); err != nil {
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

// setupFolders sets the permissions of C:\ProgramData\fairy-agent (idempotent): the folder (config.yaml,
// token, control-token): administrators and SYSTEM full control, the agent's account read-only; logs\: the agent
// may write; helper\ (the helper's audit log): the agent may only read.
func setupFolders(cfgPath string) error {
	sid, _, _, err := windows.LookupSID("", agentAccount)
	if err != nil {
		return fmt.Errorf("the service account %s was not found (is the service installed?): %w", agentAccount, err)
	}
	dir := filepath.Dir(cfgPath)
	logs := filepath.Join(dir, "logs")
	hdir := filepath.Join(dir, "helper")
	for _, d := range []string{logs, hdir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	for _, d := range []string{dir, logs, hdir} {
		if st, err := os.Lstat(d); err != nil || !st.IsDir() || isReparse(st) {
			return fmt.Errorf("%s is not a plain folder: remove it and run this again", d)
		}
	}
	read := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + sid.String() + ")"
	if err := applyACL(dir, read); err != nil {
		return fmt.Errorf("folder permissions: %w", err)
	}
	if err := applyACL(logs, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+sid.String()+")"); err != nil {
		return fmt.Errorf("log folder permissions: %w", err)
	}
	if err := applyACL(hdir, read); err != nil {
		return fmt.Errorf("helper folder permissions: %w", err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	// the helper (LocalSystem) writes in hdir only if an administrator owns it (collect.TrustedFolder)
	if err := windows.SetNamedSecurityInfo(hdir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return fmt.Errorf("helper folder owner: %w", err)
	}
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

// revokeSID removes every explicit allow entry for sid from a file system object's DACL (inherited entries of
// objects inside follow when Windows propagates the change).
func revokeSID(path string, sid *windows.SID) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
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
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
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
		if err := revokeSID(p, sid); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		if owner, _, err := sd.Owner(); err == nil && owner != nil && collect.TrustedOwner(owner.String()) {
			continue
		}
		if err := windows.SetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
			return fmt.Errorf("%s: making Administrators the owner: %w", p, err)
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
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return err
	}
	for _, d := range []string{upd, stage} {
		if st, err := os.Lstat(d); err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 || isReparse(st) {
			return fmt.Errorf("%s is not a plain folder: remove it and run this again", d)
		}
	}
	if err := applyACL(upd, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+sid.String()+")"); err != nil {
		return fmt.Errorf("update folder %s: %w", upd, err)
	}
	if err := applyACL(stage, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+sid.String()+")"); err != nil {
		return fmt.Errorf("stage folder %s: %w", stage, err)
	}
	if err := prepareStateDir(filepath.Join(filepath.Dir(cfgPath), "state")); err != nil { // pairing (Add host)
		return fmt.Errorf("state folder: %w", err)
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

func isReparse(st os.FileInfo) bool {
	d, ok := st.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
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
