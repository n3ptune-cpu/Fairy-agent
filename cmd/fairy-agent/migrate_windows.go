//go:build windows

package main

// The Windows side of pkg/agent/migrate: an agent still running as LocalSystem moves its own service to
// NT SERVICE\fairy-agent (the same end state as setup-self-update), and the fairy-agent-update service
// (LocalSystem) restarts it under the new account and checks it. See AGENT.md, "Moving to the new account by
// itself".

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/migrate"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

func migrationLogf(f string, a ...any) { slog.Warn(fmt.Sprintf(f, a...)) }

// installedExe is where the program must be for the agent to move itself: %ProgramFiles%\Fairy\fairy-agent.exe.
func installedExe() string {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || pf == "" {
		pf = `C:\Program Files`
	}
	return filepath.Join(pf, "Fairy", "fairy-agent.exe")
}

func migrationCommand() string {
	return `& "` + installedExe() + `" setup-self-update`
}

// migrationStore is C:\ProgramData\fairy-agent\migration\state.json: written only by LocalSystem (the agent
// before the switch, the updater service), read by anyone with the agent's rights; refused unless the folder
// is administrators-only.
func migrationStore(cfgPath string) *migrate.FileStore {
	return &migrate.FileStore{Path: filepath.Join(filepath.Dir(cfgPath), "migration", "state.json"),
		Prepare: secureMigrationDir, Check: collect.TrustedFolder}
}

// secureMigrationDir: administrators and SYSTEM full control, the agent's account read-only, owner
// Administrators, nothing inherited from above.
func secureMigrationDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || isReparse(st) {
		return fmt.Errorf("%s is not a plain folder", dir)
	}
	sddl := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if sid, _, _, err := windows.LookupSID("", agentAccount); err == nil {
		sddl += "(A;OICI;0x1200a9;;;" + sid.String() + ")"
	}
	if err := applyACL(dir, sddl); err != nil {
		return err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return err
	}
	return collect.TrustedFolder(dir)
}

func isLocalSystemName(n string) bool {
	switch strings.ToLower(n) {
	case "", "localsystem", `.\localsystem`, `nt authority\system`:
		return true
	}
	return false
}

// serviceExe is the program the service manager starts for a service (the first word of its command line).
func serviceExe(name string) (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return "", err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return "", err
	}
	args, err := windows.DecomposeCommandLine(c.BinaryPathName)
	if err != nil || len(args) == 0 {
		return "", fmt.Errorf("cannot read the service's command line %q", c.BinaryPathName)
	}
	return args[0], nil
}

// migrationFacts: which account this process runs as, and whether it may move itself. Only the signed release
// installed as %ProgramFiles%\Fairy\fairy-agent.exe (only administrators can change it), started as the
// fairy-agent service, does anything.
func migrationFacts() migrate.Facts {
	f := migrate.Facts{Kind: migrate.KindNotService, Command: migrationCommand()}
	if !isService() {
		return f
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		f.Kind, f.Account = migrate.KindOther, "unknown"
		return f
	}
	sid := u.User.Sid
	if own, _, _, err := windows.LookupSID("", agentAccount); err == nil && windows.EqualSid(sid, own) {
		f.Kind, f.Account = migrate.KindNew, agentAccount
		return f
	}
	switch sid.String() {
	case "S-1-5-18":
		f.Kind, f.Account = migrate.KindLocalSystem, "LocalSystem"
	case "S-1-5-19":
		f.Kind, f.Account = migrate.KindOther, "LocalService"
		return f
	case "S-1-5-20":
		f.Kind, f.Account = migrate.KindOther, "NetworkService"
		return f
	default:
		f.Kind, f.Account = migrate.KindOther, sid.String()
		if acc, dom, _, err := sid.LookupAccount(""); err == nil {
			f.Account = dom + `\` + acc
		}
		return f
	}
	exe, err := os.Executable()
	if err == nil {
		exe, err = filepath.Abs(exe)
	}
	want := installedExe()
	switch {
	case err != nil:
		f.Ineligible = "cannot find this program's path: " + err.Error()
	case releaseKey == "":
		f.Ineligible = "this program is a local build without the release key: only signed releases move themselves"
	case !strings.EqualFold(filepath.Clean(exe), want):
		f.Ineligible = "the program runs from " + exe + ", not " + want
		f.Command = `install-fairy-agent.ps1 (as Administrator, from the release files): it puts the program in ` + filepath.Dir(want)
	default:
		if err := collect.TrustedExecutable(exe); err != nil {
			f.Ineligible = "others than administrators can change the program: " + err.Error()
		} else if img, err := serviceExe(serviceName); err != nil {
			f.Ineligible = "cannot read the service's settings: " + err.Error()
		} else if !strings.EqualFold(filepath.Clean(img), want) {
			f.Ineligible = "the service starts " + img + ", not " + want
		}
	}
	return f
}

// winMigrator is agent.Migrator on Windows.
type winMigrator struct {
	r   *migrate.Runner
	ops *winMigrationOps
}

func (w *winMigrator) Status() api.MigrationStatus { return w.r.Status() }
func (w *winMigrator) Busy() bool                  { return w.r.Busy() }
func (w *winMigrator) Run(ctx context.Context, h agent.MigrationHooks) {
	w.ops.fans, w.ops.busy = h.FansAuto, h.Busy
	w.r.Loop(ctx)
}

// newMigrator is built before agent.Run (which clears the update stage): it notes the update that just
// installed this version, so the move waits until that installer has finished checking it.
func newMigrator(cfgPath string, cfg *agent.Config) agent.Migrator {
	facts := migrationFacts()
	stage, result := agent.UpdatePaths(cfg)
	ops := &winMigrationOps{cfgPath: cfgPath, start: time.Now(), result: result, inflight: stagedID(stage)}
	r := &migrate.Runner{Facts: facts, Ready: ops.ready,
		Kick:    func() error { return agent.StartUpdaterService(context.Background()) },
		Machine: &migrate.Machine{Store: migrationStore(cfgPath), Ops: ops, Version: version, Logf: migrationLogf}}
	switch {
	case facts.Kind == migrate.KindLocalSystem && facts.Ineligible == "":
		slog.Warn("the fairy-agent service runs as LocalSystem; it moves itself to its own low-rights account " + agentAccount +
			" in about two minutes (the panel shows it as \"migration\")")
	case facts.Kind == migrate.KindLocalSystem:
		slog.Warn("the fairy-agent service runs as LocalSystem and cannot move itself to "+agentAccount, "reason", facts.Ineligible,
			"fix", facts.Command)
	case facts.Kind == migrate.KindOther:
		slog.Warn("the fairy-agent service runs as "+facts.Account+"; an administrator moves it to its own low-rights account "+
			agentAccount+" once (and installs the helper where needed)", "command", facts.Command)
	}
	return &winMigrator{r: r, ops: ops}
}

// stagedID is the id of the release the agent staged last ("" if none).
func stagedID(stage string) string {
	b, err := release.ReadStaged(filepath.Join(stage, "request.json"), 4<<10)
	if err != nil {
		return ""
	}
	var r struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(b, &r) != nil {
		return ""
	}
	return r.ID
}

// winMigrationOps does the steps, as LocalSystem, with the same functions as setup-self-update.
type winMigrationOps struct {
	cfgPath  string
	start    time.Time
	result   string // the installer's result file
	inflight string // the id of the update that installed this version, if any
	fans     func(ctx context.Context) error
	busy     func() string
}

// ready: what the first attempt waits for.
func (o *winMigrationOps) ready() string {
	if o.inflight != "" && time.Since(o.start) < 5*time.Minute {
		var r struct {
			ID string `json:"id"`
		}
		b, err := release.ReadStaged(o.result, 16<<10)
		if err != nil || json.Unmarshal(b, &r) != nil || r.ID != o.inflight {
			return "the installer that put this version in place has not finished checking it"
		}
	}
	if st, err := updaterState(); err == nil && st != svc.Stopped {
		return "the " + agent.UpdaterServiceName + " service is running"
	}
	if o.busy != nil {
		return o.busy()
	}
	return ""
}

// updaterState is the updater service's state (Stopped when it does not exist).
func updaterState() (svc.State, error) {
	m, err := mgr.Connect()
	if err != nil {
		return 0, err
	}
	defer m.Disconnect()
	u, err := m.OpenService(agent.UpdaterServiceName)
	if err != nil {
		return svc.Stopped, nil
	}
	defer u.Close()
	st, err := u.Query()
	return st.State, err
}

func exeAbs() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Abs(exe)
}

func (o *winMigrationOps) Step(ctx context.Context, step string) error {
	switch step {
	case migrate.StepProgramFolder:
		exe, err := exeAbs()
		if err != nil {
			return err
		}
		sid, _, _, err := windows.LookupSID("", agentAccount)
		if err != nil {
			return err
		}
		if err := secureProgramFolder(filepath.Dir(exe), sid); err != nil {
			return err
		}
		return collect.TrustedExecutable(exe)
	case migrate.StepFolders:
		return setupFolders(o.cfgPath)
	case migrate.StepUpdater:
		return setupSelfUpdate(o.cfgPath)
	case migrate.StepFans:
		if o.fans == nil {
			return nil
		}
		if err := o.fans(ctx); err != nil {
			return fmt.Errorf("handing the fans to the BMC: %w", err)
		}
		return nil
	case migrate.StepHelper:
		cfg, err := agent.Load(o.cfgPath)
		if err != nil {
			return err
		}
		m, err := mgr.Connect()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		if !agent.NeedsHelper(cfg) && !helperInstalled(m) {
			slog.Info("migration: no helper needed (no Core Temp, IPMI through Windows or power control in config.yaml)")
			return nil
		}
		return setupHelper(m, o.cfgPath)
	case migrate.StepFirewall:
		m, err := mgr.Connect()
		if err != nil {
			return err
		}
		installed := helperInstalled(m)
		m.Disconnect()
		if !installed {
			return nil
		}
		return helperFirewall()
	case migrate.StepCounters:
		// not fatal: without it only GPU load, VRAM in use and ACPI temperatures are missing, and the agent
		// asks the updater service again under its new account (counterAccessKick)
		if added, err := agent.EnsureCounterAccess(); err != nil {
			slog.Warn("migration: the new account will not read performance counters", "error", err.Error(), "fix", collect.CounterAccessFix)
		} else if added {
			slog.Info(`migration: NT SERVICE\` + serviceName + " added to Performance Monitor Users (" + agent.PerfMonitorUsersSID + ")")
		}
		return nil
	case migrate.StepSwitch:
		m, err := mgr.Connect()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		if _, err := migrateAgentAccount(s); err != nil {
			return err
		}
		// after the account: if Windows restarts before the check, the updater service starts with it and
		// finishes (or rolls back) the switch
		return setUpdaterStart(m, windows.SERVICE_AUTO_START)
	case migrate.StepRestart:
		m, err := mgr.Connect()
		if err != nil {
			return err
		}
		defer m.Disconnect()
		u, err := m.OpenService(agent.UpdaterServiceName)
		if err != nil {
			return err
		}
		defer u.Close()
		return u.Start() // it stops this service and starts it as the new account
	}
	return fmt.Errorf("unknown step %s", step)
}

func helperInstalled(m *mgr.Mgr) bool {
	h, err := m.OpenService(proto.ServiceName)
	if err != nil {
		return false
	}
	h.Close()
	return true
}

func (o *winMigrationOps) Capture(context.Context) (migrate.Original, error) {
	m, err := mgr.Connect()
	if err != nil {
		return migrate.Original{}, err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return migrate.Original{}, err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return migrate.Original{}, err
	}
	orig := migrate.Original{Account: migrate.LocalSystem, SidType: c.SidType}
	switch {
	case isLocalSystemName(c.ServiceStartName):
		if orig.Privileges, err = requiredPrivileges(s.Handle); err != nil {
			return orig, fmt.Errorf("the service's privileges: %w", err)
		}
	case strings.EqualFold(c.ServiceStartName, agentAccount): // set already, not restarted since: LocalSystem is what runs
		orig.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	default:
		return orig, fmt.Errorf("the service is set to run as %s, not LocalSystem", c.ServiceStartName)
	}
	if len(orig.Privileges) == 0 { // none set: the service had every privilege of LocalSystem; keep exactly those
		if orig.Privileges, err = tokenPrivileges(); err != nil {
			return orig, fmt.Errorf("this process's privileges: %w", err)
		}
	}
	return orig, nil
}

func (o *winMigrationOps) Rollback(_ context.Context, orig migrate.Original) error {
	return rollbackService(orig)
}

// rollbackService puts the agent's service back on LocalSystem (the only account it restores, whatever the
// state file says) with its old SID type and privileges, and the updater on manual start.
func rollbackService(orig migrate.Original) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()
	acc, _ := windows.UTF16PtrFromString(migrate.LocalSystem)
	empty, _ := windows.UTF16PtrFromString("")
	var errs []error
	if err := windows.ChangeServiceConfig(s.Handle, windows.SERVICE_NO_CHANGE, windows.SERVICE_NO_CHANGE,
		windows.SERVICE_NO_CHANGE, nil, nil, nil, nil, acc, empty, nil); err != nil {
		errs = append(errs, fmt.Errorf("account: %w", err))
	}
	if err := setSidType(s.Handle, orig.SidType); err != nil {
		errs = append(errs, fmt.Errorf("SID type: %w", err))
	}
	if len(orig.Privileges) > 0 {
		if err := setRequiredPrivileges(s.Handle, orig.Privileges); err != nil {
			errs = append(errs, fmt.Errorf("privileges: %w", err))
		}
	}
	if err := setUpdaterStart(m, windows.SERVICE_DEMAND_START); err != nil {
		errs = append(errs, fmt.Errorf("updater start type: %w", err))
	}
	return errors.Join(errs...)
}

func setUpdaterStart(m *mgr.Mgr, start uint32) error {
	u, err := m.OpenService(agent.UpdaterServiceName)
	if err != nil {
		return err
	}
	defer u.Close()
	return windows.ChangeServiceConfig(u.Handle, windows.SERVICE_NO_CHANGE, start, windows.SERVICE_NO_CHANGE,
		nil, nil, nil, nil, nil, nil, nil)
}

// requiredPrivileges is a service's RequiredPrivileges list (empty: none set).
func requiredPrivileges(h windows.Handle) ([]string, error) {
	n := uint32(1024)
	for {
		buf := make([]byte, n)
		err := windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &buf[0], n, &n)
		if errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) && n <= 64<<10 {
			continue
		}
		if err != nil {
			return nil, err
		}
		p := (*requiredPrivilegesInfo)(unsafe.Pointer(&buf[0])).RequiredPrivileges
		if p == nil {
			return nil, nil
		}
		// the list points into buf: a REG_MULTI_SZ (names, each NUL-terminated, then one more NUL)
		off := uintptr(unsafe.Pointer(p)) - uintptr(unsafe.Pointer(&buf[0]))
		if off >= uintptr(n) || off%2 != 0 {
			return nil, errors.New("malformed privilege list")
		}
		u := unsafe.Slice((*uint16)(unsafe.Pointer(p)), (uintptr(n)-off)/2)
		return splitMultiSZ(u), nil
	}
}

var procLookupPrivilegeNameW = windows.NewLazySystemDLL("advapi32.dll").NewProc("LookupPrivilegeNameW")

// tokenPrivileges are the names of every privilege this process's token holds (enabled or not).
func tokenPrivileges() ([]string, error) {
	tok := windows.GetCurrentProcessToken()
	var n uint32
	_ = windows.GetTokenInformation(tok, windows.TokenPrivileges, nil, 0, &n)
	if n == 0 || n > 64<<10 {
		return nil, errors.New("no privilege list")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenPrivileges, &buf[0], n, &n); err != nil {
		return nil, err
	}
	count := *(*uint32)(unsafe.Pointer(&buf[0]))
	const entry = unsafe.Sizeof(windows.LUIDAndAttributes{})
	if uintptr(count)*entry+4 > uintptr(len(buf)) {
		return nil, errors.New("malformed privilege list")
	}
	var out []string
	for i := uintptr(0); i < uintptr(count); i++ {
		la := (*windows.LUIDAndAttributes)(unsafe.Pointer(&buf[4+i*entry]))
		name := make([]uint16, 128)
		size := uint32(len(name))
		r, _, err := procLookupPrivilegeNameW.Call(0, uintptr(unsafe.Pointer(&la.Luid)), uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size)))
		if r == 0 {
			return nil, err
		}
		out = append(out, windows.UTF16ToString(name[:size]))
	}
	return out, nil
}

// helperFirewallRule is the display name of the two block rules (also install-fairy-agent.ps1's).
const helperFirewallRule = "Fairy agent helper (no network)"

// netsh runs System32\netsh.exe with a fixed command line.
func netsh(args string) ([]byte, error) {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	exe := filepath.Join(sys, "netsh.exe")
	cmd := exec.Command(exe)
	cmd.Env = collect.MinimalEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CmdLine: `"` + exe + `" ` + args}
	return cmd.CombinedOutput()
}

// helperFirewall (re)creates the rules that block all network traffic of the helper's service SID, in and out
// (idempotent: the old rules of that name are removed first, whoever made them).
func helperFirewall() error {
	removeHelperFirewall()
	for _, dir := range []string{"in", "out"} {
		out, err := netsh(`advfirewall firewall add rule name="` + helperFirewallRule + `" dir=` + dir +
			` action=block service=` + proto.ServiceName + ` profile=any`)
		if err != nil {
			return fmt.Errorf("firewall rule %q (%s): %v: %s", helperFirewallRule, dir, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func removeHelperFirewall() {
	_, _ = netsh(`advfirewall firewall delete rule name="` + helperFirewallRule + `"`) // fails when there is none
}

// ---- the Supervisor, in the fairy-agent-update service

type winSupervisor struct {
	cfg *agent.Config
}

func openAgent() (*mgr.Mgr, *mgr.Service, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, nil, err
	}
	s, err := m.OpenService(serviceName)
	if err != nil {
		m.Disconnect()
		return nil, nil, err
	}
	return m, s, nil
}

func (w winSupervisor) Agent(context.Context) (migrate.AgentInfo, error) {
	m, s, err := openAgent()
	if err != nil {
		return migrate.AgentInfo{}, err
	}
	defer m.Disconnect()
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return migrate.AgentInfo{}, err
	}
	info := migrate.AgentInfo{Running: st.State == svc.Running, PID: st.ProcessId}
	if info.Running && info.PID != 0 {
		info.NewAccount = processRunsAs(info.PID, agentAccount)
	}
	return info, nil
}

// processRunsAs reports whether process pid's token user is account.
func processRunsAs(pid uint32, account string) bool {
	want, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return false
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return false
	}
	defer tok.Close()
	u, err := tok.GetTokenUser()
	return err == nil && windows.EqualSid(u.User.Sid, want)
}

func (w winSupervisor) StopAgent(context.Context) error {
	m, s, err := openAgent()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	stopAndWait(s, 30*time.Second)
	if st, err := s.Query(); err != nil || st.State != svc.Stopped {
		return fmt.Errorf("the %s service did not stop (state %d)", serviceName, st.State)
	}
	return nil
}

func (w winSupervisor) StartAgent(context.Context) error {
	m, s, err := openAgent()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	return startAndWait(s, 30*time.Second)
}

func (w winSupervisor) Healthy(ctx context.Context) error {
	return agent.CheckRunning(ctx, w.cfg, version)
}

func (w winSupervisor) Rollback(_ context.Context, o migrate.Original) error {
	return rollbackService(o)
}

func (w winSupervisor) Finish(context.Context) error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	return setUpdaterStart(m, windows.SERVICE_DEMAND_START)
}

// superviseMigration runs first in apply-update (the fairy-agent-update service): when the state file says
// the agent's service was switched and not yet checked, it restarts and checks the agent (or rolls back) and
// installs nothing. handled false: no migration to finish, go on with the update.
func superviseMigration(ctx context.Context, cfg *agent.Config, cfgPath string) (bool, int) {
	sup := &migrate.Supervisor{Store: migrationStore(cfgPath), Ops: winSupervisor{cfg: cfg}, Logf: migrationLogf}
	handled, err := sup.Run(ctx)
	if !handled {
		if err != nil {
			slog.Error("migration: cannot read the state; not acting on it", "error", err.Error())
		}
		return false, 0
	}
	if err != nil {
		return true, 1
	}
	return true, 0
}
