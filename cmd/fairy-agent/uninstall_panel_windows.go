//go:build windows

package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// agentFirewallRule is the display name of the rule install-fairy-agent.ps1 makes for the panel's port.
const agentFirewallRule = "Fairy agent (Tailscale only)"

// uninstallAnswerGrace lets the agent's 202 reach the panel before the agent is stopped.
const uninstallAnswerGrace = 3 * time.Second

// uninstallFromPanel runs first in apply-update, that is in the fairy-agent-update service (LocalSystem). It
// acts on one thing only: the one-time request the helper leaves in its own folder after it has verified the
// uninstall's passkey approval (agent.UninstallMarker). That folder and the file must pass the checks of the
// trust file's folder (owner and permission list: administrators and SYSTEM only), the request is taken away
// before anything is done, and only a fresh one is acted on. Nothing in the stage folder, which the agent's
// account may write, is ever looked at for this; nothing is changed about the start type of any service.
//
// What it removes: the agent's, the helper's and this updater's services (the fans go back to the BMC when the
// helper stops), the helper's and the agent's firewall rules, the counter access, and, at the next reboot, the
// program folder (this program runs from it now). What stays: C:\ProgramData\fairy-agent (config, tokens,
// logs), as with `fairy-agent uninstall`.
//
// handled is false when there is no request (the updater was started for something else). A request that
// does not pass is not acted on, and neither is anything else in this run: an administrator looks at the log.
func uninstallFromPanel(ctx context.Context, cfg *agent.Config) (handled bool, code int) {
	by, err := agent.WindowsUninstallMarker(cfg).Take(time.Now())
	if errors.Is(err, agent.ErrNoUninstallMarker) {
		return false, 0
	}
	if err != nil {
		slog.Error("uninstall from the panel: the request is not acted on, and nothing else is done in this run", "error", err.Error())
		return true, 1
	}
	slog.Warn("uninstall from the panel: approved with a passkey, checked by the helper; removing the services", "requested_by", by)
	select {
	case <-time.After(uninstallAnswerGrace):
	case <-ctx.Done():
	}
	if err := removeServices(func(msg string) { slog.Warn("uninstall from the panel: " + msg) }); err != nil {
		slog.Error("uninstall from the panel: the services could not be removed", "error", err.Error())
		return true, 1
	}
	if out, err := netsh(`advfirewall firewall delete rule name="` + agentFirewallRule + `"`); err != nil {
		slog.Warn("uninstall from the panel: the agent's firewall rule was not removed (there may be none)", "output", strings.TrimSpace(string(out)))
	}
	scheduleProgramRemoval()
	slog.Warn("uninstall from the panel: done. The services are gone; " + filepath.Dir(agent.DefaultConfigPath()) +
		" (config, tokens, logs) is kept: delete it when you are sure; the program folder goes at the next reboot")
	return true, 0
}

// scheduleProgramRemoval asks Windows to delete the program folder's files and the folder at the next reboot
// (MOVEFILE_DELAY_UNTIL_REBOOT): this program runs from there and cannot delete itself now. Only the folder the
// installer uses (Program Files\Fairy), only files directly in it; anything else is left and said.
func scheduleProgramRemoval() {
	exe, err := os.Executable()
	if err != nil {
		slog.Warn("uninstall from the panel: the program folder stays", "error", err.Error())
		return
	}
	dir := filepath.Dir(exe)
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || !strings.EqualFold(filepath.Clean(dir), filepath.Join(pf, "Fairy")) {
		slog.Warn("uninstall from the panel: the program is not in Program Files\\Fairy, its folder stays", "folder", dir)
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("uninstall from the panel: the program folder stays", "error", err.Error())
		return
	}
	for _, e := range entries {
		if e.IsDir() || e.Type()&os.ModeSymlink != 0 {
			slog.Warn("uninstall from the panel: left in the program folder", "name", e.Name())
			continue
		}
		if err := delayDelete(filepath.Join(dir, e.Name())); err != nil {
			slog.Warn("uninstall from the panel: not removed at the next reboot", "name", e.Name(), "error", err.Error())
		}
	}
	if err := delayDelete(dir); err != nil {
		slog.Warn("uninstall from the panel: the program folder is not removed at the next reboot", "error", err.Error())
	}
}

func delayDelete(path string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(p, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
}
