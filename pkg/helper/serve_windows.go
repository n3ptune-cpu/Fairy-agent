//go:build windows

package helper

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/winpipe"
)

// AgentAccount is the agent's virtual service account: the only non-administrator the pipe admits.
const AgentAccount = `NT SERVICE\fairy-agent`

// LogDir is the helper's own folder under C:\ProgramData\fairy-agent: Administrators and SYSTEM may change it,
// the agent's account may only read it. The helper never writes where the agent's account can create files
// (logs\): a LocalSystem process writing in such a folder could be pointed at another file by a planted link.
func LogDir(cfg *agent.Config) string { return filepath.Join(cfg.Dir(), "helper") }

// LogPath is the audit log.
func LogPath(cfg *agent.Config) string { return filepath.Join(LogDir(cfg), "helper.log") }

// OpenAudit opens the audit log (5 MB, one old copy) after checking its folder; it falls back to discarding
// (the reason is returned) when the folder is not safe to write as LocalSystem.
func OpenAudit(cfg *agent.Config) (*slog.Logger, io.Closer, error) {
	dir := LogDir(cfg)
	if err := collect.TrustedFolder(dir); err != nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil)), nil,
			fmt.Errorf("not writing the helper log: %w (fairy-agent setup-self-update recreates the folder)", err)
	}
	f, err := agent.OpenLog(LogPath(cfg), 5<<20)
	if err != nil {
		return slog.New(slog.NewTextHandler(io.Discard, nil)), nil, err
	}
	h := agent.RateLimitLog(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelInfo}), 60)
	return slog.New(h), f, nil
}

// TrustedConfig, when set (cmd/fairy-agent sets it), must accept config.yaml's path before the helper serves
// anything that file switches on: the helper is LocalSystem, and config.yaml decides whether it shuts the PC
// down, drives the fans or starts the updater for the agent. It returns an error when config.yaml or its
// folder could have been written by someone other than administrators and SYSTEM.
var TrustedConfig func(cfgPath string) error

// Run is the helper service: it serves the pipe until ctx ends, then hands the fans back to the BMC (within
// 20 s) and returns. logErr reports problems the service manager should see (the Event Log).
func Run(ctx context.Context, cfg *agent.Config, version string, logErr func(string)) error {
	if TrustedConfig != nil {
		if err := TrustedConfig(cfg.Path()); err != nil {
			// nothing was opened or written yet; the caller reports the error to the Event Log
			return fmt.Errorf("not serving anything: %w", err)
		}
	}
	audit, closer, err := OpenAudit(cfg)
	if err != nil {
		logErr(err.Error())
	}
	if closer != nil {
		defer closer.Close()
	}
	slog.SetDefault(audit) // the BMC reader and the fan controller log through slog
	parts, closeParts, err := FromConfig(cfg, version, audit)
	if err != nil {
		audit.Error("helper cannot start", "error", err.Error())
		return err
	}
	defer closeParts()
	srv := New(parts)
	sctx, stop := context.WithCancel(context.Background()) // the BMC and the watchdog outlive ctx until Shutdown
	defer stop()
	srv.Start(sctx)

	agentSID, _, _, err := windows.LookupSID("", AgentAccount)
	if err != nil {
		audit.Error("the agent's service account was not found", "account", AgentAccount, "error", err.Error())
		srv.Shutdown(context.Background())
		return fmt.Errorf("%s not found (is the fairy-agent service installed?): %w", AgentAccount, err)
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	serveErr := winpipe.Serve(ctx, proto.PipeName, winpipe.SDDL(agentSID.String()), 4,
		winpipe.MemberOf(agentSID, system, admins),
		func(ctx context.Context, c *winpipe.Conn, who winpipe.Client) { srv.ServeConn(ctx, c, who.String()) },
		func(who winpipe.Client, why string) {
			audit.Warn("refused client", "client", who.String(), "reason", why)
		},
		pipeHeld(audit, logErr))
	if serveErr != nil {
		audit.Error("pipe", "error", serveErr.Error())
		logErr("fairy-agent-helper: " + serveErr.Error())
	}
	sdctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv.Shutdown(sdctx)
	stop()
	return serveErr
}

// pipeHeld reports that another process holds the helper's pipe name (winpipe.Serve keeps trying): every try
// goes to the audit log, the first one and the recovery also to the Event Log. The fan watchdog and the BMC
// reader run meanwhile; only the agent cannot reach the helper (it refuses to talk to the other process).
func pipeHeld(audit *slog.Logger, logErr func(string)) func(holder string, err error, retryIn time.Duration) {
	reported := false
	return func(holder string, err error, retryIn time.Duration) {
		if err == nil {
			audit.Warn("pipe: the name is free again, serving", "pipe", proto.PipeName)
			logErr("fairy-agent-helper: the pipe " + proto.PipeName + " is free again; the helper serves the agent")
			reported = false
			return
		}
		audit.Error("pipe: another process holds the name; trying again", "pipe", proto.PipeName, "held_by", holder,
			"error", err.Error(), "retry_in", retryIn.String())
		if !reported {
			reported = true
			logErr("fairy-agent-helper: another process holds the pipe " + proto.PipeName + " (" + holder +
				"); the helper keeps trying and the fan watchdog keeps running, but the agent cannot reach the helper until that process ends")
		}
	}
}

// ErrNotService is returned when the helper is started outside the service manager.
var ErrNotService = fmt.Errorf("the helper runs only as the %s service (Start-Service %s)", proto.ServiceName, proto.ServiceName)
