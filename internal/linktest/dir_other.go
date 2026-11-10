//go:build !windows

package linktest

import "os"

func dirLink(target, link string) (string, error) { return Symlink, os.Symlink(target, link) }
