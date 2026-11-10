//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lineEnd() string { return "\r\n" }

// secureNew: new files inherit the folder's permissions (administrators, SYSTEM, the service read-only).
func secureNew(string) error { return nil }

// prepareStateDir makes the state folder the service may write (pairing state), like logs\ and update\stage\:
// created with its permissions when it is missing; an existing one is opened itself (never what a link points
// to), must be a plain folder that nobody but administrators and the agent's account controls, and gets owner
// Administrators and its permissions on that handle.
func prepareStateDir(dir string) error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return fmt.Errorf("the service account was not found (is the service installed?): %w", err)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil { // the folder above: normally the data folder
		return err
	}
	return winFolders().ensure(dir, folderSpec{sid.String(), true})
}

// agentIDs: there is no owner to set, the pairing state inherits the state folder's permissions.
func agentIDs() (int, int, bool) { return 0, 0, false }
