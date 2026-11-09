//go:build windows

package main

// Performance counters for NT SERVICE\fairy-agent: the account must be a member of Performance Monitor Users
// (agent.EnsureCounterAccess). install, setup-self-update, the move off LocalSystem and the updater service
// before it starts an updated agent add it. An agent moved by 0.5.1 and then updated by 0.5.1's updater
// (which does not know the group) runs without it: such an agent asks the updater service once, with nothing
// staged, and the updater (LocalSystem, the installed program) adds the group and restarts the agent.

import (
	"context"
	"log/slog"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// runsAsAgentAccount reports whether this process runs as NT SERVICE\fairy-agent.
func runsAsAgentAccount() bool {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false
	}
	own, _, _, err := windows.LookupSID("", agentAccount)
	return err == nil && windows.EqualSid(u.User.Sid, own)
}

// counterAccessKick runs in the agent's service: as NT SERVICE\fairy-agent without Performance Monitor Users
// in its token, it starts the updater service once, when that is stopped (it may still be checking the update
// that installed this version), at the earliest a minute after start. The updater changes nothing but the
// group and restarts the agent only when it really added it, so this cannot loop.
func counterAccessKick(ctx context.Context) {
	if !isService() || !runsAsAgentAccount() {
		return
	}
	if ok, err := agent.HasCounterAccess(); err != nil || ok {
		return
	}
	slog.Warn("this account is not a member of Performance Monitor Users: asking the " + agent.UpdaterServiceName +
		" service to add it (it restarts the agent once)")
	wait := time.Minute
	for range 60 { // up to about half an hour
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		wait = 30 * time.Second
		stopped, err := agent.UpdaterStopped()
		if err != nil {
			slog.Warn("cannot ask the updater service to add this account to Performance Monitor Users", "error", err.Error(), "fix", collect.CounterAccessFix)
			return
		}
		if !stopped {
			continue
		}
		if err := agent.StartUpdaterService(ctx); err != nil {
			slog.Warn("cannot start the updater service to add this account to Performance Monitor Users", "error", err.Error(), "fix", collect.CounterAccessFix)
		}
		return
	}
	slog.Warn("the updater service kept running; not asking it to add this account to Performance Monitor Users", "fix", collect.CounterAccessFix)
}

// counterAccessRun runs first in apply-update (the fairy-agent-update service, LocalSystem), after a
// migration check: with nothing staged it is the agent's request above. It adds NT SERVICE\fairy-agent to
// Performance Monitor Users and, only when it was not a member, restarts the agent if it runs as that account
// (the group counts from a new token). handled false: an update is staged, go on with it (its installer adds
// the group before it starts the agent).
func counterAccessRun(_ context.Context, cfg *agent.Config) (bool, int) {
	if agent.Staged(cfg) {
		return false, 0
	}
	added, err := agent.EnsureCounterAccess()
	if err != nil {
		slog.Error("apply-update: nothing staged; could not add the agent's account to Performance Monitor Users", "error", err.Error())
		return true, 1
	}
	if !added {
		slog.Info("apply-update: nothing staged; the agent's account is in Performance Monitor Users already: nothing to do")
		return true, 0
	}
	slog.Warn(`apply-update: added NT SERVICE\` + serviceName + " to Performance Monitor Users (" + agent.PerfMonitorUsersSID + "): read access to performance counters")
	m, s, err := openAgent()
	if err != nil {
		slog.Error("apply-update: cannot open the agent's service to restart it", "error", err.Error())
		return true, 1
	}
	defer m.Disconnect()
	defer s.Close()
	st, err := s.Query()
	if err != nil || st.State != svc.Running || !processRunsAs(st.ProcessId, agentAccount) {
		return true, 0 // not running as that account now: it gets the group when it next starts
	}
	slog.Warn("apply-update: restarting " + serviceName + " so it can read performance counters")
	stopAndWait(s, 30*time.Second)
	if err := startAndWait(s, 30*time.Second); err != nil {
		slog.Error("apply-update: starting "+serviceName+" again failed", "error", err.Error())
		return true, 1
	}
	return true, 0
}
