//go:build !linux && !windows

package agent

import (
	"context"
	"errors"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

var errNoSelfUpdate = errors.New("self-update is only available on Linux and Windows")

const stageHint = ""

// UpdatePaths are the stage folder and the installer's result file.
func UpdatePaths(*Config) (stage, result string) { return "", "" }

func startInstaller(context.Context, string) error { return errNoSelfUpdate }

func installerFor(exe string) *release.Installer {
	return &release.Installer{Target: exe, Start: func(context.Context) error { return errNoSelfUpdate }}
}

func serviceRunning(context.Context) error { return errNoSelfUpdate }
