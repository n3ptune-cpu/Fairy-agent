//go:build !windows

package main

import (
	"context"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// uninstallFromPanel: Linux removes the agent with its own root unit (fairy-agent-uninstall.service), never
// from apply-update.
func uninstallFromPanel(context.Context, *agent.Config) (bool, int) { return false, 0 }
