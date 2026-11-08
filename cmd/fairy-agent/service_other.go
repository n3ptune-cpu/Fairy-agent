//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
)

func isService() bool  { return false }
func runService() int  { return 1 }
func lowerPriority()   {} // the systemd unit sets Nice= and the I/O class
func isAdmin() bool    { return os.Geteuid() == 0 }
func uninstall() error { return errors.New("on Linux, remove the systemd unit instead (see AGENT.md)") }

func setupSelfUpdate(string) error {
	fmt.Println(`On Linux self-update needs (AGENT.md, "Updates"):
  deploy/fairy-agent.service (StateDirectory=fairy-agent), deploy/fairy-agent-update.service,
  deploy/fairy-agent.polkit.rules as /etc/polkit-1/rules.d/49-fairy-agent.rules,
  then: systemctl daemon-reload && systemctl restart fairy-agent`)
	return nil
}

func install(string, string) error {
	fmt.Println(`On Linux fairy-agent runs as a systemd service:
  1. copy the binary to /usr/local/bin/fairy-agent
  2. create /etc/fairy-agent/config.yaml (deploy/fairy-agent.config.example.yaml) and the token file
  3. install deploy/fairy-agent.service and run: systemctl enable --now fairy-agent
AGENT.md has the exact commands.`)
	return nil
}
