//go:build windows

package release

import "os"

// On Windows the stager and the installer run as the same account (the service's), so there is no privilege
// boundary to defend here; openStaged still refuses anything but a regular file.
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }
