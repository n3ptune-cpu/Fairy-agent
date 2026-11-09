//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func isTerminal(f *os.File) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(f.Fd()), &mode) == nil
}

// readHidden reads one line with the console's echo off.
func readHidden(f *os.File) (string, error) {
	h := windows.Handle(f.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return "", err
	}
	if err := windows.SetConsoleMode(h, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", err
	}
	defer func() { _ = windows.SetConsoleMode(h, mode) }()
	line, err := bufio.NewReader(f).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// secureSecretFile: SYSTEM and Administrators full control, the agent's service account read-only, nobody else
// (the service must read the password to use it).
func secureSecretFile(path string) error {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+serviceName)
	if err != nil {
		return fmt.Errorf("the service account was not found (is the service installed?): %w", err)
	}
	return applyACL(path, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;"+sid.String()+")")
}
