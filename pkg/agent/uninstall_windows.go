//go:build windows

package agent

import (
	"context"
	"path/filepath"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// WindowsUninstallMarker is the one-time uninstall request in the helper's folder, with the checks of that
// folder that the trust file has too (owner and permission list: administrators and SYSTEM only).
func WindowsUninstallMarker(cfg *Config) UninstallMarker {
	return UninstallMarker{Path: filepath.Join(cfg.Dir(), "helper", UninstallMarkerName),
		CheckDir: collect.TrustedFolder, CheckFile: collect.TrustedFile}
}

// StartUninstallViaUpdater is what the helper does once it has accepted an uninstall's approval: it leaves the
// one-time request (the updater acts on nothing else) and starts the updater service, which removes the
// services. If the updater cannot be started, the request is taken away again, so that no later start of the
// updater (an update, a migration) acts on it.
func StartUninstallViaUpdater(ctx context.Context, cfg *Config, by string) error {
	if UpdaterRunning() {
		return ErrUpdaterBusy
	}
	m := WindowsUninstallMarker(cfg)
	if err := m.Write(by, time.Now()); err != nil {
		return err
	}
	if err := StartUpdaterService(ctx); err != nil {
		_ = m.Remove()
		return err
	}
	return nil
}

// SystemUninstaller is what POST /uninstall hands the request to on this system: the helper. Without a helper
// client (never on Windows) there is none.
func SystemUninstaller(h *HelperClient) Uninstaller {
	if h == nil {
		return nil
	}
	return HelperUninstaller(h)
}
