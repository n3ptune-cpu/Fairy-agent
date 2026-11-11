//go:build windows

package main

// trustBecomeOwner: on Windows the trust file is in the helper's folder, which Administrators and SYSTEM
// change; an elevated administrator works there as himself.
func trustBecomeOwner(string) (string, error) { return "", nil }
