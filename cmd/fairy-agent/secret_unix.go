//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func isTerminal(f *os.File) bool {
	_, err := unix.IoctlGetTermios(int(f.Fd()), ioctlGetTermios)
	return err == nil
}

// readHidden reads one line with the terminal's echo off.
func readHidden(f *os.File) (string, error) {
	fd := int(f.Fd())
	old, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return "", err
	}
	quiet := *old
	quiet.Lflag &^= unix.ECHO
	quiet.Lflag |= unix.ICANON | unix.ISIG
	if err := unix.IoctlSetTermios(fd, ioctlSetTermios, &quiet); err != nil {
		return "", err
	}
	defer func() { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, old) }()
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := f.Read(b)
		if n == 0 || err != nil || b[0] == '\n' {
			return string(buf), nil
		}
		buf = append(buf, b[0])
	}
}

// secureSecretFile: 0640, owner root, the config folder's group (the agent's user reads it through its group).
func secureSecretFile(path string) error {
	if err := os.Chmod(path, 0o640); err != nil {
		return err
	}
	st, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok && os.Geteuid() == 0 {
		return os.Chown(path, 0, int(s.Gid))
	}
	return nil
}
