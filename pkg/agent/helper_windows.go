//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/winpipe"
)

// systemHelper is the client for fairy-agent-helper (also when it is not installed: /metrics then says so).
func systemHelper(cfg *Config) *HelperClient {
	svc := scmHelper{}
	// who owns the pipe: reported in the log once when it is not SYSTEM or Administrators; refused only with
	// require_helper_pipe_owner: true (winpipe.OwnerCheck says why this release only reports)
	owner := &winpipe.OwnerCheck{Enforce: cfg.RequireHelperPipeOwner, Warn: func(msg string) { slog.Warn(msg) }}
	dial := func(ctx context.Context) (io.ReadWriteCloser, error) {
		return winpipe.Dial(ctx, proto.PipeName, svc.pid, owner)
	}
	return NewHelperClient(dial, svc, NeedsHelper(cfg))
}

func isAccessDenied(err error) bool { return errors.Is(err, windows.ERROR_ACCESS_DENIED) }

// scmHelper asks the service manager about fairy-agent-helper. The agent's account may query, start and stop
// it (setup-self-update grants exactly SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP).
type scmHelper struct{}

func (scmHelper) open(access uint32) (windows.Handle, func(), error) {
	m, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return 0, nil, err
	}
	name, _ := windows.UTF16PtrFromString(proto.ServiceName)
	s, err := windows.OpenService(m, name, access)
	if err != nil {
		windows.CloseServiceHandle(m)
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return 0, nil, api.ErrHelperNotInstalled
		}
		return 0, nil, err
	}
	return s, func() { windows.CloseServiceHandle(s); windows.CloseServiceHandle(m) }, nil
}

func (h scmHelper) status() (windows.SERVICE_STATUS_PROCESS, error) {
	var st windows.SERVICE_STATUS_PROCESS
	s, done, err := h.open(windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return st, err
	}
	defer done()
	var need uint32
	err = windows.QueryServiceStatusEx(s, windows.SC_STATUS_PROCESS_INFO, (*byte)(unsafe.Pointer(&st)), uint32(unsafe.Sizeof(st)), &need)
	return st, err
}

func (h scmHelper) State() (string, error) {
	st, err := h.status()
	if errors.Is(err, api.ErrHelperNotInstalled) {
		return api.HelperNotInstalled, nil
	}
	if err != nil {
		return "", err
	}
	switch st.CurrentState {
	case windows.SERVICE_RUNNING:
		return api.HelperRunning, nil
	case windows.SERVICE_START_PENDING, windows.SERVICE_CONTINUE_PENDING:
		return api.HelperStarting, nil
	}
	return api.HelperStopped, nil
}

// pid is the helper service's process id (0 when it is not running).
func (h scmHelper) pid() (uint32, error) {
	st, err := h.status()
	if err != nil {
		return 0, err
	}
	if st.CurrentState != windows.SERVICE_RUNNING {
		return 0, errors.New("the helper is not running")
	}
	return st.ProcessId, nil
}

func (h scmHelper) wait(ctx context.Context, s windows.Handle, want uint32, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		var st windows.SERVICE_STATUS
		if err := windows.QueryServiceStatus(s, &st); err != nil {
			return err
		}
		if st.CurrentState == want {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the helper service is in state %d after %s", st.CurrentState, d)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func (h scmHelper) Stop(ctx context.Context) error {
	s, done, err := h.open(windows.SERVICE_STOP | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	var st windows.SERVICE_STATUS
	if err := windows.ControlService(s, windows.SERVICE_CONTROL_STOP, &st); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return err
	}
	return h.wait(ctx, s, windows.SERVICE_STOPPED, 40*time.Second) // the helper hands the fans back first
}

func (h scmHelper) Start(ctx context.Context) error {
	s, done, err := h.open(windows.SERVICE_START | windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return err
	}
	defer done()
	if err := windows.StartService(s, 0, nil); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return err
	}
	return h.wait(ctx, s, windows.SERVICE_RUNNING, 30*time.Second)
}
