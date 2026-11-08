//go:build windows

package ipmi

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// WMI sends raw IPMI requests through Windows' built-in IPMI driver, using the documented Microsoft_IPMI WMI
// class from one long-lived powershell.exe (started on first use, stopped after IdleStop without requests).
// It needs the service to run as LocalSystem (the class is restricted to administrators).
type WMI struct {
	IdleStop time.Duration

	mu    sync.Mutex
	cmd   *exec.Cmd
	stdin io.WriteCloser
	lines chan string
	idle  *time.Timer
}

// NewWMI returns the transport (powershell is not started until the first request).
func NewWMI(idleStop time.Duration) (Transport, error) {
	if idleStop <= 0 {
		idleStop = 5 * time.Minute
	}
	return &WMI{IdleStop: idleStop}, nil
}

func (w *WMI) start() error {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	ps := filepath.Join(sys, "WindowsPowerShell", "v1.0", "powershell.exe")
	cmd := exec.Command(ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", EncodedWMIScript())
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.BELOW_NORMAL_PRIORITY_CLASS}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return errors.New("cannot start powershell for IPMI")
	}
	lines := make(chan string, 4)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	w.cmd, w.stdin, w.lines = cmd, stdin, lines
	select {
	case l, ok := <-lines:
		if ok && l == "READY" {
			return nil
		}
		w.stopLocked()
		if strings.HasPrefix(l, "FATAL ") {
			return errors.New("IPMI via WMI unavailable: " + truncate(l[6:], 160))
		}
		return errors.New("IPMI via WMI unavailable")
	case <-time.After(30 * time.Second):
		w.stopLocked()
		return errors.New("IPMI via WMI: powershell did not start in time")
	}
}

func (w *WMI) stopLocked() {
	if w.cmd == nil {
		return
	}
	_ = w.stdin.Close()
	_ = w.cmd.Process.Kill()
	_ = w.cmd.Wait()
	w.cmd, w.stdin, w.lines = nil, nil, nil
}

// Raw sends one request and waits for its answer (a timeout kills the helper; the next request restarts it).
func (w *WMI) Raw(ctx context.Context, netfn, cmd byte, data []byte) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cmd == nil {
		if err := w.start(); err != nil {
			return nil, err
		}
	}
	if w.idle != nil {
		w.idle.Stop()
	}
	w.idle = time.AfterFunc(w.IdleStop, func() { w.mu.Lock(); w.stopLocked(); w.mu.Unlock() })
	if _, err := io.WriteString(w.stdin, FormatWMIRequest(netfn, cmd, data)); err != nil {
		w.stopLocked()
		return nil, errors.New("IPMI helper stopped")
	}
	select {
	case l, ok := <-w.lines:
		if !ok {
			w.stopLocked()
			return nil, errors.New("IPMI helper stopped")
		}
		return ParseWMIResponse(l)
	case <-ctx.Done():
		w.stopLocked()
		return nil, ctx.Err()
	}
}

// Close stops the helper.
func (w *WMI) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.idle != nil {
		w.idle.Stop()
	}
	w.stopLocked()
}
