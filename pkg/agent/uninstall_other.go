//go:build !linux && !windows

package agent

import (
	"context"
	"errors"
)

// SystemUninstaller: nothing on this system can remove the agent from the panel. nil keeps POST /uninstall
// closed (404 uninstall_disabled).
func SystemUninstaller(*HelperClient) Uninstaller { return nil }

// StartUninstallViaUpdater is the Windows helper's; there is no helper here.
func StartUninstallViaUpdater(context.Context, *Config, string) error {
	return errors.New("uninstall through the updater service is Windows only")
}
