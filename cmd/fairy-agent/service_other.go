//go:build !windows

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

func isService() bool  { return false }
func runService() int  { return 1 }
func lowerPriority()   {} // the systemd unit sets Nice= and the I/O class
func isAdmin() bool    { return os.Geteuid() == 0 }
func uninstall() error { return errors.New("on Linux, remove the systemd unit instead (see AGENT.md)") }

// checkProgramFolder warns when the running binary could be replaced by someone other than root (or the agent's
// own user): the update installer and administrators run it with more rights.
func checkProgramFolder() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if err := collect.TrustedExecutable(exe); err != nil {
		slog.Warn("the fairy-agent program can be changed by others; install it in /usr/local/bin owned by root", "problem", err.Error())
	}
}

func setupSelfUpdate(string) error {
	fmt.Println(`On Linux self-update needs (AGENT.md, "Updates"):
  deploy/fairy-agent.service (StateDirectory=fairy-agent), deploy/fairy-agent-update.service,
  deploy/fairy-agent-update.polkit.rules as /etc/polkit-1/rules.d/49-fairy-agent-update.rules,
  then: systemctl daemon-reload && systemctl restart fairy-agent`)
	return nil
}

func setup(cfgPath string, _, _ bool) error { return setupSelfUpdate(cfgPath) }

func removeHelper() error { return errors.New("the helper exists only on Windows") }

// helperForTrust: there is no helper on this system; the agent checks approvals itself (trust_cmd.go).
func helperForTrust() (string, []byte, error) { return trustNoHelperHere, nil, nil }

func helperStatus() int {
	fmt.Println("helper: Windows only (on Linux the agent needs no elevated helper)")
	return 3
}

func install(string, string, bool) error {
	fmt.Println(`On Linux fairy-agent runs as a systemd service:
  1. copy the binary to /usr/local/bin/fairy-agent
  2. create /etc/fairy-agent/config.yaml (deploy/fairy-agent.config.example.yaml) and the token file
  3. install deploy/fairy-agent.service and run: systemctl enable --now fairy-agent
AGENT.md has the exact commands.`)
	return nil
}

const linuxStarter = `# fairy-agent configuration: /etc/fairy-agent/config.yaml (see AGENT.md). Everything that can change the
# machine is off unless switched on here. After a change: systemctl restart fairy-agent
# Change one setting without an editor: fairy-agent config set <setting> <value>   (e.g. power_control.enabled true)
#
# listen: empty = this machine's Tailscale address on port 9101 (never every network).
# The panel's tokens are the files "token" and "control-token" next to this one.

processes:
  enabled: true          # the panel's Processes tab; false = the agent never looks at other programs
  cmdline: false         # true = also send command lines (a filter blanks the secrets it recognises; best effort)

gpu:
  nvidia_smi: auto       # auto | off | full path to nvidia-smi
  amdgpu: auto           # AMD GPUs via the amdgpu driver's /sys files | off

ipmi:
  enabled: false         # BMC sensors (ipmitool, see AGENT.md)

fan_control:
  enabled: false         # needs ipmi.enabled; fans never below 30 %, back to 100 % at 80 °C

power_control:
  enabled: false         # remote shutdown / reboot from the panel

wol:
  enabled: false         # send Wake-on-LAN packets for the panel

self_update:
  enabled: false         # let the panel's Update button install the latest signed release

ups: []                  # UPSes this agent reads and passes on, e.g. [{id: local-ups, type: nut, host: 127.0.0.1}]
`

func starterConfig() string { return linuxStarter }
