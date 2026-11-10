package main

import (
	"os"
	"runtime"
	"testing"
)

// inTestFolders lets join and the typed commands run in temporary folders on Windows. There, two steps look
// at the real machine and would stop every such test before it reaches what it tests:
//
//   - the data folder check (dataDirTrusted) refuses a temporary folder, rightly: the test's user owns it.
//     The check has its own tests (datadir_test.go against real permission lists, datadir_windows_test.go
//     against this machine);
//   - the state folder gets the permissions of the installed service's account (makeStateDir), and the PC the
//     tests run on has no such service and must not get one.
//
// Both are answered here as on a healthy, installed PC. Everything else is the real code: what join writes,
// where, and how (the pairing state through the opened folder, datadir_state.go). Elsewhere than Windows
// nothing is replaced.
func inTestFolders(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "windows" {
		return
	}
	trusted, mk := dataDirTrusted, makeStateDir
	t.Cleanup(func() { dataDirTrusted, makeStateDir = trusted, mk })
	dataDirTrusted = func(string) error { return nil }
	makeStateDir = func(dir string) error { return os.MkdirAll(dir, 0o700) }
}
