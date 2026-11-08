//go:build !linux && !windows

package configedit

import "os"

func copyXattrs(*os.File, string) error { return nil }
