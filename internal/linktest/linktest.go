// Package linktest makes links for the tests, on every system they run on.
//
// The tests play someone who puts a link where a plain file or folder belongs. On Linux that is a symbolic
// link. On Windows an ordinary user may not create symbolic links (it needs a privilege that only an elevated
// window or Developer Mode gives), but anyone may create a junction: a folder that leads to another folder.
// A junction is what an attacker without rights would use there, so it is what the tests use.
package linktest

import (
	"fmt"
	"os"
	"path/filepath"
)

// Kinds of link, as Dir reports them.
const (
	Symlink  = "symbolic link"
	Junction = "junction"
)

// IsLink reports whether fi (from os.Lstat) is a link of either kind. Go shows a symbolic link as
// os.ModeSymlink; a Windows junction, and every other reparse point that is not a plain file, as
// os.ModeIrregular (since Go 1.23).
func IsLink(fi os.FileInfo) bool {
	return fi != nil && fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
}

// Dir makes link a link to the existing folder target and reports its kind: a symbolic link, or on Windows a
// junction (no privilege needed). The result is looked at: an error is returned when the system said yes and
// made no link.
func Dir(target, link string) (kind string, err error) {
	target, err = filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if kind, err = dirLink(target, link); err != nil {
		return "", err
	}
	return kind, made(link)
}

// File makes link a symbolic link to the file target. On Windows this fails for an ordinary user ("A required
// privilege is not held by the client"): the caller then leaves out what needs a link to a file.
func File(target, link string) error {
	if err := os.Symlink(target, link); err != nil {
		return err
	}
	return made(link)
}

func made(link string) error {
	fi, err := os.Lstat(link)
	if err != nil {
		return fmt.Errorf("the link was not made: %w", err)
	}
	if !IsLink(fi) {
		return fmt.Errorf("%s was made, but it is not a link (mode %v)", link, fi.Mode())
	}
	return nil
}
