//go:build windows

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func lineEnd() string { return "\r\n" }

// secureNew: new files inherit the folder's permissions (administrators, SYSTEM, the service read-only).
func secureNew(string) error { return nil }

// prepareStateDir makes the state folder the service may write (pairing state), like logs\ and update\.
func prepareStateDir(dir string) error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return fmt.Errorf("the service account was not found (is the service installed?): %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return applyACL(dir, "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+sid.String()+")")
}

// handOver: the file inherits the state folder's permissions.
func handOver(string) error { return nil }
