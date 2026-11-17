//go:build !linux

package agent

// SystemUninstaller: nothing on this system can remove the agent from the panel yet (Windows: through the
// helper and the updater service, next). nil keeps POST /uninstall closed (404 uninstall_disabled).
func SystemUninstaller() Uninstaller { return nil }
