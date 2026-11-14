//go:build !windows

package approval

import "os"

// openShared opens a file for reading. Elsewhere than on Windows an open file never keeps another one from
// taking its name (open_windows.go).
func openShared(path string) (*os.File, error) { return os.Open(path) }

// renameBusy: a rename does not fail because the file is open (open_windows.go).
func renameBusy(error) bool { return false }
