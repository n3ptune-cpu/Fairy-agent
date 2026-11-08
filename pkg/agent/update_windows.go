//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// Windows: the service stages into C:\ProgramData\fairy-agent\update\stage and starts a detached
// `fairy-agent.exe apply-update` (same account). The installer stops the service, renames the exe to
// fairy-agent.exe.old (a running exe can be renamed, not replaced), moves the new one in, starts the service and
// checks it; on failure it puts the old exe back. `fairy-agent setup-self-update` (run by install and by
// install-fairy-agent.ps1) gives the service's own SID (NT SERVICE\fairy-agent, nobody else) the rights this
// needs: modify on C:\Program Files\Fairy and start/stop/query on its own service.

// ServiceName is the Windows service.
const ServiceName = "fairy-agent"

const stageHint = " (run install-fairy-agent.ps1 again as Administrator: it creates the update folder and its permissions)"

// UpdatePaths are the stage folder and the installer's result file.
func UpdatePaths(cfg *Config) (stage, result string) {
	dir := filepath.Join(cfg.Dir(), "update")
	return filepath.Join(dir, "stage"), filepath.Join(dir, "result.json")
}

func startInstaller(_ context.Context, cfgPath string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	start := func(flags uint32) error {
		cmd := exec.Command(exe, "apply-update", "--config", cfgPath)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: flags}
		if err := cmd.Start(); err != nil {
			return err
		}
		return cmd.Process.Release()
	}
	base := uint32(windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP)
	if err := start(base | windows.CREATE_BREAKAWAY_FROM_JOB); err != nil {
		return start(base) // not in a job that allows breaking away
	}
	return nil
}

func openOwnService(access uint32) (windows.Handle, func(), error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, nil, err
	}
	name, _ := windows.UTF16PtrFromString(ServiceName)
	s, err := windows.OpenService(m, name, access)
	if err != nil {
		windows.CloseServiceHandle(m)
		return 0, nil, fmt.Errorf("opening the %s service: %w (run install-fairy-agent.ps1 again: it grants the service the right to restart itself)", ServiceName, err)
	}
	return s, func() { windows.CloseServiceHandle(s); windows.CloseServiceHandle(m) }, nil
}

func serviceState(s windows.Handle) (uint32, error) {
	var st windows.SERVICE_STATUS
	if err := windows.QueryServiceStatus(s, &st); err != nil {
		return 0, err
	}
	return st.CurrentState, nil
}

func waitState(ctx context.Context, s windows.Handle, want uint32, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		st, err := serviceState(s)
		if err != nil {
			return err
		}
		if st == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("service state %d, waited %s for %d", st, d, want)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func stopService(ctx context.Context) error {
	s, done, err := openOwnService(windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	if st, err := serviceState(s); err == nil && st == windows.SERVICE_STOPPED {
		return nil
	}
	var st windows.SERVICE_STATUS
	if err := windows.ControlService(s, windows.SERVICE_CONTROL_STOP, &st); err != nil &&
		!errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return waitState(ctx, s, windows.SERVICE_STOPPED, 30*time.Second)
}

func startService(ctx context.Context) error {
	s, done, err := openOwnService(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	if err := windows.StartService(s, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return waitState(ctx, s, windows.SERVICE_RUNNING, 30*time.Second)
}

func installerFor(exe string) *release.Installer {
	return &release.Installer{Target: exe, RenameSwap: true, HealthTimeout: 60 * time.Second, HealthPasses: 2,
		Stop: stopService, Start: startService}
}

func serviceRunning(context.Context) error {
	s, done, err := openOwnService(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	st, err := serviceState(s)
	if err != nil {
		return err
	}
	if st != windows.SERVICE_RUNNING {
		return fmt.Errorf("the %s service is not running (state %d)", ServiceName, st)
	}
	return nil
}
