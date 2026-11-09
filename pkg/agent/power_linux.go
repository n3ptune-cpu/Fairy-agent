//go:build linux

package agent

import (
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// systemPower waits in the agent and then asks systemd to power off, reboot or suspend (`systemctl
// poweroff|reboot|suspend`). The agent's user needs permission for that: a polkit rule
// (deploy/fairy-agent.polkit.rules), see AGENT.md. If the agent stops before the time comes, the action is
// dropped (the safe direction).
type systemPower struct {
	mu    sync.Mutex
	timer *time.Timer
}

// SystemPower returns the Linux implementation.
func SystemPower() PowerExec { return &systemPower{} }

func systemctl() (string, error) {
	return firstExisting("systemctl", "/usr/bin/systemctl", "/bin/systemctl")
}

func firstExisting(name string, paths ...string) (string, error) {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", errors.New(name + " not found")
}

var linuxVerb = map[string]string{"shutdown": "poweroff", "reboot": "reboot", "sleep": "suspend"}

func (s *systemPower) Schedule(action string, delay time.Duration, _ string) error {
	path, err := systemctl()
	if err != nil {
		return err
	}
	verb, ok := linuxVerb[action]
	if !ok {
		return errors.New("unknown action " + action)
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

// CanSleep asks systemd-logind (CanSuspend, through busctl) when it can, else whether the kernel offers suspend
// to RAM at all (/sys/power/state lists "mem").
func (s *systemPower) CanSleep() (bool, string) {
	state, _ := os.ReadFile("/sys/power/state")
	busctl, err := firstExisting("busctl", "/usr/bin/busctl", "/bin/busctl")
	if err != nil {
		return sleepFromKernel(string(state))
	}
	out, err := exec.Command(busctl, "call", "--system", "org.freedesktop.login1", "/org/freedesktop/login1",
		"org.freedesktop.login1.Manager", "CanSuspend").Output()
	if err != nil {
		return sleepFromKernel(string(state))
	}
	return sleepFromLogind(string(out))
}

// sleepFromLogind reads busctl's answer to CanSuspend (`s "yes"`).
func sleepFromLogind(out string) (bool, string) {
	v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "s")), `" `)
	switch v {
	case "yes":
		return true, ""
	case "challenge", "no":
		return false, "systemd-logind does not allow the agent to suspend (CanSuspend: " + v + "): install deploy/fairy-agent.polkit.rules"
	case "na":
		return false, "this machine does not support suspend (CanSuspend: na)"
	}
	return false, "systemd-logind answered CanSuspend with " + strings.TrimSpace(out)
}

func sleepFromKernel(state string) (bool, string) {
	if strings.Contains(state, "mem") {
		return true, ""
	}
	return false, "the kernel offers no suspend to RAM (/sys/power/state has no \"mem\")"
}
