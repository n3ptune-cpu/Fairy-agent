//go:build linux

package agent

import (
	"context"
	"errors"
	"fmt"
)

// uninstallUnit is the fixed root oneshot that removes this agent (deploy/fairy-agent-uninstall.service). It
// runs /usr/local/lib/fairy-agent/uninstall-fairy-agent.sh --yes --keep-data; the polkit rule
// 49-fairy-agent-uninstall.rules lets the fairy-agent user start exactly this unit, nothing else. install.sh
// installs both only while uninstall.enabled is on.
const uninstallUnit = "fairy-agent-uninstall.service"

type unitUninstaller struct {
	run func(ctx context.Context, args ...string) error // runSystemctl; tests put their own in
}

// SystemUninstaller is what POST /uninstall starts on this system.
func SystemUninstaller(*HelperClient) Uninstaller { return unitUninstaller{run: runSystemctl} }

// Start asks systemd to start the root unit and does not wait (--no-block): the unit stops this agent.
func (u unitUninstaller) Start(ctx context.Context) error {
	if err := u.run(ctx, "start", "--no-block", uninstallUnit); err != nil {
		return fmt.Errorf("%w (are deploy/fairy-agent-uninstall.service and deploy/fairy-agent-uninstall.polkit.rules installed? "+
			"install.sh puts them in place while uninstall.enabled is on)", err)
	}
	return nil
}

func (unitUninstaller) ThroughHelper() bool { return false }

// StartUninstallViaUpdater is the Windows helper's; there is no helper here.
func StartUninstallViaUpdater(context.Context, *Config, string) error {
	return errors.New("uninstall through the updater service is Windows only")
}
