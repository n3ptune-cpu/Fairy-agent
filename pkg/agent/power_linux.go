//go:build linux

package agent

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"
)

// systemPower waits in the agent and then asks systemd to power off or reboot (`systemctl poweroff|reboot`).
// The agent's user needs permission for that: a polkit rule (deploy/fairy-agent.polkit.rules), see AGENT.md.
// If the agent stops before the time comes, the action is dropped (the safe direction).
type systemPower struct {
	mu    sync.Mutex
	timer *time.Timer
}

// SystemPower returns the Linux implementation.
func SystemPower() PowerExec { return &systemPower{} }

func systemctl() (string, error) {
	for _, p := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New("systemctl not found")
}

func (s *systemPower) Schedule(action string, delay time.Duration, _ string) error {
	path, err := systemctl()
	if err != nil {
		return err
	}
	verb := "poweroff"
	if action == "reboot" {
		verb = "reboot"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	s.timer = time.AfterFunc(delay, func() {
		slog.Warn("power: running systemctl " + verb)
		if out, err := exec.Command(path, verb).CombinedOutput(); err != nil {
			slog.Error("power: systemctl failed (polkit rule missing?)", "verb", verb, "error", err.Error(), "output", string(out))
		}
	})
	return nil
}

func (s *systemPower) Cancel() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	return nil
}
