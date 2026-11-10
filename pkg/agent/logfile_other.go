//go:build !windows

package agent

import "os"

// openLogFile opens the log for appending, creating it when missing.
func openLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
}
