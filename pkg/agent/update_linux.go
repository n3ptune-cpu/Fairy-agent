//go:build linux

package agent

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
)

// Linux: the agent (user fairy-agent, read-only system) stages into its StateDirectory; the root oneshot unit
// fairy-agent-update.service runs `fairy-agent apply-update` and writes its result into its own StateDirectory.
const (
	linuxStageDir   = "/var/lib/fairy-agent/update"
	linuxResultPath = "/var/lib/fairy-agent-update/result.json"
	updateUnit      = "fairy-agent-update.service"
	agentUnit       = "fairy-agent.service"
)

const stageHint = " (install the new deploy/fairy-agent.service, which has StateDirectory=fairy-agent, then " +
	"systemctl daemon-reload && systemctl restart fairy-agent)"

func isReparsePoint(os.FileInfo) bool { return false }

func lockDir(string) (func(), error) { return func() {}, nil }

// InstallerLogPath: the installer unit logs to the journal.
func InstallerLogPath(*Config) string { return "" }

// installerReady: the polkit rule and the unit are checked when the agent starts the unit.
func installerReady() error { return nil }

// UpdatePaths are the stage folder and the installer's result file.
func UpdatePaths(*Config) (stage, result string) { return linuxStageDir, linuxResultPath }

func runSystemctl(ctx context.Context, args ...string) error {
	path, err := systemctl()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	out, err := collect.Command(ctx, path, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("systemctl %s: %v %s", strings.Join(args, " "), err, msg)
	}
	return nil
}

// startInstaller asks systemd to start the root installer unit; the polkit rule allows exactly this to the
// fairy-agent user. --no-block: the unit restarts this agent, so do not wait for it.
func startInstaller(ctx context.Context, _ string) error {
	if err := runSystemctl(ctx, "start", "--no-block", updateUnit); err != nil {
		return fmt.Errorf("%w (are deploy/fairy-agent-update.service and deploy/fairy-agent-update.polkit.rules installed?)", err)
	}
	return nil
}

func installerFor(exe string) *release.Installer {
	return &release.Installer{Target: exe, HealthTimeout: 40 * time.Second, HealthPasses: 2,
		Start:   func(ctx context.Context) error { return runSystemctl(ctx, "restart", agentUnit) },
		Relabel: restorecon}
}

// restorecon gives the new binary its normal SELinux label (Fedora); a no-op without SELinux tools.
func restorecon(path string) {
	for _, p := range []string{"/usr/sbin/restorecon", "/sbin/restorecon"} {
		if _, err := os.Stat(p); err == nil {
			_ = exec.Command(p, path).Run()
			return
		}
	}
}

func serviceRunning(ctx context.Context) error {
	if err := runSystemctl(ctx, "is-active", "--quiet", agentUnit); err != nil {
		return fmt.Errorf("%s is not active", agentUnit)
	}
	return nil
}
