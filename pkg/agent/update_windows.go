//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// Windows: the agent's service (LocalService or LocalSystem, SID NT SERVICE\fairy-agent) downloads and stages
// the release into C:\ProgramData\fairy-agent\update\stage, the only update folder it may write, and starts the
// installer service "fairy-agent-update": LocalSystem, started on demand, running the INSTALLED
// C:\Program Files\Fairy\fairy-agent.exe apply-update. The agent's account may only start and query that
// service; it can change neither the service nor the program folder (only administrators, SYSTEM and
// TrustedInstaller can), so a compromised agent cannot plant a program that an administrator or SYSTEM later
// runs. The installer verifies the stage with its own built-in key, copies the binary into the program folder
// (hashing what it writes), stops the agent's service, renames the exe to fairy-agent.exe.old (a running exe can
// be renamed, not replaced), moves the new one in, starts the service and checks it; on failure it puts the old
// exe back. Its result goes to C:\ProgramData\fairy-agent\update\result.json, which the agent may only read.
// `fairy-agent setup-self-update` (run by install and by install-fairy-agent.ps1, as Administrator) sets all
// this up and removes the write access to the program folder that fairy-agent 0.4.2 and older granted.

// ServiceName is the Windows service.
const ServiceName = "fairy-agent"

// UpdaterServiceName is the LocalSystem service that installs a staged update.
const UpdaterServiceName = "fairy-agent-update"

// UpdaterSetupHint is how to (re)create the updater service and the permissions.
const UpdaterSetupHint = `in an Administrator PowerShell: & "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update ` +
	`(or update by hand there: & "C:\Program Files\Fairy\fairy-agent.exe" update)`

const stageHint = " (" + UpdaterSetupHint + ")"

// UpdatePaths are the stage folder and the installer's result file.
func UpdatePaths(cfg *Config) (stage, result string) {
	dir := filepath.Join(cfg.Dir(), "update")
	return filepath.Join(dir, "stage"), filepath.Join(dir, "result.json")
}

func isReparsePoint(st os.FileInfo) bool {
	d, ok := st.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// InstallerLogPath is the installer's log, in the update folder only administrators and SYSTEM may write: the
// installer runs as LocalSystem and must not open files in folders the agent's account can change (logs\).
func InstallerLogPath(cfg *Config) string { return filepath.Join(cfg.Dir(), "update", "installer.log") }

// lockDir opens dir without following a junction and without sharing write or delete access, so that while the
// installer reads the stage the agent's account can neither remove the folder nor turn it into a junction.
func lockDir(dir string) (func(), error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return nil, err
	}
	var h windows.Handle
	for i := 0; ; i++ {
		h, err = windows.CreateFile(p, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err == nil || !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || i >= 20 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%s is not a plain folder", dir)
	}
	return func() { windows.CloseHandle(h) }, nil
}

func openUpdater(access uint32) (windows.Handle, func(), error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, nil, err
	}
	name, _ := windows.UTF16PtrFromString(UpdaterServiceName)
	s, err := windows.OpenService(m, name, access)
	if err != nil {
		windows.CloseServiceHandle(m)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return 0, nil, fmt.Errorf("the panel's Update button needs the %s service, which is not installed: %s", UpdaterServiceName, UpdaterSetupHint)
		}
		return 0, nil, fmt.Errorf("this agent may not start the %s service (%v): %s", UpdaterServiceName, err, UpdaterSetupHint)
	}
	return s, func() { windows.CloseServiceHandle(s); windows.CloseServiceHandle(m) }, nil
}

// installerReady checks that the updater service exists and that this process may start it (opening it with
// the start right checks the right without starting anything).
func installerReady() error {
	_, done, err := openUpdater(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	done()
	return nil
}

// startInstaller starts the updater service; it stops and restarts this service.
func startInstaller(context.Context, string) error {
	s, done, err := openUpdater(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	if err := windows.StartService(s, 0, nil); err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return errors.New("the installer is already running")
		}
		return err
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
		return 0, nil, fmt.Errorf("opening the %s service: %w (the installer runs as LocalSystem; by hand: run as Administrator)", ServiceName, err)
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
