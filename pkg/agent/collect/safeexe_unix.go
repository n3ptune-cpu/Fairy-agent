//go:build !windows

package collect

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// TrustedExecutable checks that path is an absolute path to a regular file that only root (or the agent's own
// user) can change, through every folder above it (symlinks resolved first). See safeexe.go.
func TrustedExecutable(path string) error {
	if p := ExecPathProblem(path, false); p != "" {
		return fmt.Errorf("%s %s", path, p)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	st, err := os.Stat(real)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", real)
	}
	euid := uint32(os.Geteuid())
	kind := ObjFile
	for p := real; ; {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot read its owner", p)
		}
		mode := uint32(st.Mode().Perm())
		if st.Mode()&os.ModeSticky != 0 {
			mode |= 0o1000
		}
		if err := CheckUnixMode(p, kind, UnixFile{UID: uint32(sys.Uid), GID: uint32(sys.Gid), Mode: mode}, euid); err != nil {
			return err
		}
		parent := filepath.Dir(p)
		if parent == p {
			return nil
		}
		p = parent
		if kind == ObjFile {
			kind = ObjParent
		} else {
			kind = ObjAncestor
		}
	}
}

// FindIpmitool returns the first trusted ipmitool in /usr/bin, /usr/sbin, /usr/local/bin or PATH.
func FindIpmitool() (string, error) {
	var firstErr error
	try := func(p string) bool {
		st, err := os.Stat(p)
		if err != nil || st.IsDir() {
			return false
		}
		if err := TrustedExecutable(p); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return false
		}
		return true
	}
	for _, p := range []string{"/usr/bin/ipmitool", "/usr/sbin/ipmitool", "/usr/local/bin/ipmitool"} {
		if try(p) {
			return p, nil
		}
	}
	if p, err := exec.LookPath("ipmitool"); err == nil && filepath.IsAbs(p) && try(p) {
		return p, nil
	}
	if firstErr != nil {
		return "", fmt.Errorf("ipmitool found but not used: %w", firstErr)
	}
	return "", errors.New("ipmitool not found: install it (apt install ipmitool) or set its path")
}
