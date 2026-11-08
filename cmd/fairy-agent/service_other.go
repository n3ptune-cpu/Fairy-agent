//go:build !windows

package main

import (
	"errors"
	"fmt"
)

func isService() bool  { return false }
func runService() int  { return 1 }
func lowerPriority()   {} // the systemd unit sets Nice= and the I/O class
func uninstall() error { return errors.New("on Linux, remove the systemd unit instead (see AGENT.md)") }

func install(string, string) error {
	fmt.Println(`On Linux fairy-agent runs as a systemd service:
  1. copy the binary to /usr/local/bin/fairy-agent
  2. create /etc/fairy-agent/config.yaml (deploy/fairy-agent.config.example.yaml) and the token file
  3. install deploy/fairy-agent.service and run: systemctl enable --now fairy-agent
AGENT.md has the exact commands.`)
	return nil
}
