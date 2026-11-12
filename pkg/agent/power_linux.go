//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// systemPower waits in the agent and then asks systemd to power off, reboot or suspend (`systemctl
// poweroff|reboot|suspend`). The agent's user needs permission for that: a polkit rule
// (deploy/fairy-agent-power.polkit.rules), see AGENT.md. If the agent stops before the time comes, the action is
// dropped (the safe direction).
type systemPower struct {
	mu    sync.Mutex
	timer *time.Timer
	// ran is the systemctl verb the timer has run since the last Schedule ("": none). From then on there is
	// nothing left to stop, and Cancel says so (errTooLate).
	ran string
	// run runs `systemctl <verb>`; nil: the real one. Tests put their own in.
	run func(path, verb string)
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

func runPowerVerb(path, verb string) {
	if out, err := collect.Command(context.Background(), path, verb).CombinedOutput(); err != nil {
		slog.Error("power: systemctl failed (polkit rule missing?)", "verb", verb, "error", err.Error(), "output", string(out))
	}
}

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
	s.ran = ""
	var t *time.Timer
	t = time.AfterFunc(delay, func() {
		// Either Cancel stopped this timer or it runs systemctl, never both: a Cancel that came in the moment
		// the timer fired (Stop is too late then) has taken the timer away, and nothing is run; otherwise it is
		// written down that the action was carried out, before it is, so no later Cancel says "cancelled".
		s.mu.Lock()
		if s.timer != t {
			s.mu.Unlock()
			return
		}
		s.ran = verb
		run := s.run
		s.mu.Unlock()
		slog.Warn("power: running systemctl " + verb)
		if run == nil {
			run = runPowerVerb
		}
		run(path, verb)
	})
	s.timer = t
	return nil
}

// Cancel stops the timer. Once the timer has run systemctl there is nothing to stop: errTooLate (audit 6,
// r4-a1-03: such a cancel answered "cancelled" while the machine was already being switched off).
func (s *systemPower) Cancel() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ran != "" {
		return fmt.Errorf("%w: systemctl %s was already run", errTooLate, s.ran)
	}
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
	out, err := collect.Command(context.Background(), busctl, "call", "--system", "org.freedesktop.login1", "/org/freedesktop/login1",
		"org.freedesktop.login1.Manager", "CanSuspend").Output()
	if err != nil {
		return sleepFromKernel(string(state))
	}
	return sleepFromLogind(string(out))
}

// powerPolkitHint names the rule file that lets the agent's user power off, reboot and suspend, as the release
// ships it and where install.sh puts it.
const powerPolkitHint = "deploy/fairy-agent-power.polkit.rules as /etc/polkit-1/rules.d/49-fairy-agent-power.rules " +
	"(the panel's Add host or Re-pair command does that when shutdown / reboot is switched on)"

// sleepFromLogind reads busctl's answer to CanSuspend (`s "yes"`).
func sleepFromLogind(out string) (bool, string) {
	v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out), "s")), `" `)
	switch v {
	case "yes":
		return true, ""
	case "challenge", "no":
		return false, "systemd-logind does not allow the agent to suspend (CanSuspend: " + v + "): install " + powerPolkitHint
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

// systemPowerAt: the agent itself waits for the time, so a pending action ends with the agent and there is
// nothing to remember (see RememberedPower for Windows).
func systemPowerAt(string) PowerExec { return SystemPower() }
