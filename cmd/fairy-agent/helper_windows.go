//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/winpipe"
)

// helperHandler is the fairy-agent-helper service (pkg/helper): the pipe, the fan watchdog, and on stop or
// shutdown the fans handed back to the BMC's automatic mode before it reports "stopped".
type helperHandler struct{ cfgPath string }

func helperEventLog(msg string) {
	if el, e := eventlog.Open(proto.ServiceName); e == nil {
		_ = el.Error(1, msg)
		el.Close()
	}
}

func (h helperHandler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	// small like the agent, but at normal priority: the fan watchdog must not wait behind a game
	runtime.GOMAXPROCS(min(2, runtime.NumCPU()))
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(24 << 20)
	// LocalSystem reads nothing in a folder someone else controls: the folder is checked before config.yaml
	// is opened (loadTrustedConfig)
	cfg, err := loadTrustedConfig(h.cfgPath, func(p string) error { return trustedDataDir(p) })
	if err != nil {
		helperEventLog("fairy-agent-helper cannot start: " + err.Error())
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- helper.Run(ctx, cfg, version, helperEventLog) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending, WaitHint: 30000}
				cancel() // helper.Run hands the fans back to the BMC (at most 20 s), then returns
				select {
				case <-errc:
				case <-time.After(28 * time.Second):
				}
				return false, 0
			}
		case err := <-errc:
			if err != nil {
				helperEventLog("fairy-agent-helper stopped: " + err.Error())
				return false, 1 // the service manager restarts it (recovery actions)
			}
			return false, 0
		}
	}
}

// stopAndWait stops a service and waits (up to d) until it has stopped.
func stopAndWait(s *mgr.Service, d time.Duration) {
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		for deadline := time.Now().Add(d); time.Now().Before(deadline); {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				return
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// startAndWait starts a service and waits (up to d) until it runs.
func startAndWait(s *mgr.Service, d time.Duration) error {
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	for deadline := time.Now().Add(d); ; {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == svc.Running {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("still not running after %s (state %d)", d, st.State)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// setup is `fairy-agent setup-self-update` and the end of `install` (as Administrator, idempotent):
//   - moves the agent's service to its virtual account NT SERVICE\fairy-agent (from LocalService or
//     LocalSystem), with only SeChangeNotifyPrivilege; restarts it when it was running and restart is set;
//   - NT SERVICE\fairy-agent into the built-in group Performance Monitor Users (S-1-5-32-558): read access to
//     performance counters (GPU load, VRAM in use, ACPI temperatures), nothing else; when it was not a member,
//     a running agent is restarted (when restart is set) so its token carries the group;
//   - the ProgramData folder permissions (setupFolders); config and tokens are kept;
//   - self-update (setupSelfUpdate);
//   - the fairy-agent-helper service when forceHelper is set or config.yaml needs it (Core Temp, IPMI through
//     Windows, fans, power control), and updates an existing one; it is never removed here (remove-helper).
func setup(cfgPath string, forceHelper, restart bool) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run PowerShell as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("the %s service is not installed (fairy-agent install): %w", serviceName, err)
	}
	defer s.Close()
	old, _ := s.Config()
	changed, err := migrateAgentAccount(s)
	if err != nil {
		return err
	}
	if changed {
		fmt.Printf("the %s service now runs as %s (was %s)\n", serviceName, agentAccount, orLocalSystem(old.ServiceStartName))
	}
	var problems []string
	added, err := agent.EnsureCounterAccess()
	if err != nil {
		problems = append(problems, "GPU load, VRAM in use and ACPI temperatures will be unknown: "+err.Error())
	} else if added {
		fmt.Println(agentAccount + ` added to the group "Performance Monitor Users" (` + agent.PerfMonitorUsersSID + `): read access to performance counters`)
	}
	if err := setupFolders(cfgPath); err != nil {
		return err
	}
	if err := setupSelfUpdate(cfgPath); err != nil {
		problems = append(problems, "self-update (the panel's Update button) is not set up: "+err.Error())
	}
	cfg, cerr := agent.Load(cfgPath)
	need := forceHelper || (cerr == nil && agent.NeedsHelper(cfg))
	if h, err := m.OpenService(proto.ServiceName); err == nil {
		h.Close()
		need = true // keep an installed helper up to date
	}
	if need {
		if err := setupHelper(m, cfgPath); err != nil {
			problems = append(problems, "the helper is not set up: "+err.Error())
		}
		if helperInstalled(m) {
			if err := helperFirewall(); err != nil {
				problems = append(problems, err.Error())
			} else {
				fmt.Println(`firewall: all network traffic of the helper's service blocked (rules "` + helperFirewallRule + `", in and out)`)
			}
		}
	} else {
		fmt.Println("no helper needed (no Core Temp, IPMI, fan or power control in config.yaml): only the low-rights agent runs")
	}
	if (changed || added) && restart {
		if st, err := s.Query(); err == nil && st.State != svc.Stopped {
			if changed {
				fmt.Println("restarting", serviceName, "under its new account")
			} else {
				fmt.Println("restarting", serviceName, "so it can read performance counters")
			}
			stopAndWait(s, 20*time.Second)
			if err := startAndWait(s, 30*time.Second); err != nil {
				problems = append(problems, "restarting "+serviceName+": "+err.Error())
			}
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func orLocalSystem(n string) string {
	if n == "" {
		return "LocalSystem"
	}
	return n
}

// setupHelper creates or updates the fairy-agent-helper service and (re)starts it: LocalSystem, starts with
// Windows, runs this installed program's "helper", only the privileges in helperPrivileges, restarted on
// failure. The agent's account may query, start and stop it (the panel's Stop / Start), nothing else.
func setupHelper(m *mgr.Mgr, cfgPath string) error {
	sid, _, _, err := windows.LookupSID("", agentAccount)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, _ = filepath.Abs(exe)
	if err := collect.TrustedExecutable(exe); err != nil {
		return fmt.Errorf("the helper would run this program as LocalSystem, so only administrators may be able to change it (install it in C:\\Program Files\\Fairy): %w", err)
	}
	cfg := mgr.Config{ServiceType: windows.SERVICE_WIN32_OWN_PROCESS, StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal,
		DisplayName:      "Fairy agent helper",
		Description:      "Does the few things the Fairy agent may not (Core Temp, the BMC's sensors and fans, shutdown / sleep) for it; no network, local pipe only.",
		ServiceStartName: "LocalSystem", SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
		BinaryPathName: syscall.EscapeArg(exe) + " helper --config " + syscall.EscapeArg(cfgPath)}
	h, err := m.OpenService(proto.ServiceName)
	if err == nil {
		stopAndWait(h, 35*time.Second) // hands the fans back to the BMC first
		if err := h.UpdateConfig(cfg); err != nil {
			h.Close()
			return fmt.Errorf("updating the %s service: %w", proto.ServiceName, err)
		}
	} else {
		h, err = m.CreateService(proto.ServiceName, exe, cfg, "helper", "--config", cfgPath)
		if err != nil {
			return fmt.Errorf("creating the %s service: %w", proto.ServiceName, err)
		}
	}
	defer h.Close()
	if err := setRequiredPrivileges(h.Handle, helperPrivileges); err != nil {
		return fmt.Errorf("helper privileges: %w", err)
	}
	setRecovery(h)
	if err := revokeServiceSID(h.Handle, sid); err != nil {
		return fmt.Errorf("helper service permissions: %w", err)
	}
	if err := grantACE("", windows.SE_SERVICE, h.Handle, sid, windows.SERVICE_START|windows.SERVICE_STOP|windows.SERVICE_QUERY_STATUS, windows.NO_INHERITANCE); err != nil {
		return fmt.Errorf("helper service permissions: %w", err)
	}
	_ = eventlog.InstallAsEventCreate(proto.ServiceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err := startAndWait(h, 30*time.Second); err != nil {
		return fmt.Errorf("starting %s: %w (see Event Viewer > Windows Logs > Application, and %s)", proto.ServiceName, err,
			filepath.Join(filepath.Dir(cfgPath), "helper", "helper.log"))
	}
	fmt.Println("helper set up: the " + proto.ServiceName + " service (LocalSystem, no network, privileges " +
		strings.Join(helperPrivileges, ", ") + ") runs; " + agentAccount + " may only query, start and stop it")
	return nil
}

// removeHelper is `fairy-agent remove-helper`: stops the helper (the fans go back to the BMC first) and
// removes its service.
func removeHelper() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run PowerShell as Administrator): %w", err)
	}
	defer m.Disconnect()
	h, err := m.OpenService(proto.ServiceName)
	if err != nil {
		fmt.Println("the helper is not installed")
		return nil
	}
	defer h.Close()
	stopAndWait(h, 35*time.Second)
	if err := h.Delete(); err != nil {
		return err
	}
	_ = eventlog.Remove(proto.ServiceName)
	removeHelperFirewall()
	fmt.Println("removed the " + proto.ServiceName + " service; restart the agent: Restart-Service fairy-agent")
	return nil
}

// deleteHelper stops and deletes the helper service if it exists (uninstall).
func deleteHelper(m *mgr.Mgr) {
	h, err := m.OpenService(proto.ServiceName)
	if err != nil {
		return
	}
	defer h.Close()
	stopAndWait(h, 35*time.Second) // fans back to the BMC first
	if err := h.Delete(); err != nil {
		fmt.Println("warning: could not remove the", proto.ServiceName, "service:", err)
	}
	_ = eventlog.Remove(proto.ServiceName)
	removeHelperFirewall()
}

// helperStatus is `fairy-agent helper-status` (Administrator): asks the helper over its pipe (administrators
// may open it too) and prints its state. Exit code 0 running, 3 not running or not installed, 1 error.
func helperStatus() int {
	m, err := mgr.Connect()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot reach the service manager:", err)
		return 1
	}
	defer m.Disconnect()
	if a, err := m.OpenService(serviceName); err == nil {
		ac, _ := a.Config()
		fmt.Printf("agent service:  %s, account %s\n", serviceName, orLocalSystem(ac.ServiceStartName))
		a.Close()
	}
	h, err := m.OpenService(proto.ServiceName)
	if err != nil {
		fmt.Println("helper: not installed")
		return 3
	}
	defer h.Close()
	c, _ := h.Config()
	fmt.Printf("helper service: %s, account %s\n", proto.ServiceName, orLocalSystem(c.ServiceStartName))
	st, err := h.Query()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot query the helper:", err)
		return 1
	}
	if st.State != svc.Running {
		fmt.Println("helper: stopped (service state", st.State, ")")
		return 3
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// the pipe's owner is looked at and printed (never refused here: this command is for looking)
	owner := &winpipe.OwnerCheck{Warn: func(msg string) { fmt.Println("note:", msg) }}
	conn, err := winpipe.Dial(ctx, proto.PipeName, func() (uint32, error) {
		q, err := h.Query()
		return q.ProcessId, err
	}, owner)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: running, but its pipe:", err)
		return 1
	}
	fmt.Println("helper pipe owner:", owner.Owner(), "(expected: S-1-5-32-544, Administrators, or S-1-5-18, SYSTEM)")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	b, _ := proto.EncodeRequest(proto.Request{Verb: proto.VerbStatus})
	if err := proto.WriteFrame(conn, b, proto.MaxRequest); err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		return 1
	}
	f, err := proto.ReadFrame(conn, proto.MaxResponse)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		return 1
	}
	r, err := proto.DecodeResponse(f)
	if err != nil || r.Status != 200 {
		fmt.Fprintln(os.Stderr, "helper answered:", r.Status, r.Error, err)
		return 1
	}
	fmt.Println("helper: running, answers on", proto.PipeName)
	fmt.Println(string(r.Data))
	for _, l := range helperApprovalLines(r.Data) {
		fmt.Println(l)
	}
	return 0
}
