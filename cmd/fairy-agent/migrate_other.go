//go:build !windows

package main

import (
	"context"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
)

// newMigrator: only Windows agents move to another account (Linux runs as its own user from the start).
func newMigrator(string, *agent.Config) agent.Migrator { return nil }

func superviseMigration(context.Context, *agent.Config, string) (bool, int) { return false, 0 }
