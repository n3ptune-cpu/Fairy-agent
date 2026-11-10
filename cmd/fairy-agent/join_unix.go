//go:build !windows

package main

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
)

const agentUser = "fairy-agent"

func lineEnd() string { return "\n" }

// secureNew gives a new config or token file the folder's group (root:fairy-agent on Linux) and 0640.
func secureNew(path string) error {
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

// agentIDs is the fairy-agent user's uid and gid (ok=false when it does not exist, e.g. in tests).
var agentIDs = func() (int, int, bool) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return 0, 0, false
	}
	u, err := user.Lookup(agentUser)
	if err != nil {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	return uid, gid, err1 == nil && err2 == nil
}

// prepareStateDir makes the agent's state folder (systemd's StateDirectory, 0700 fairy-agent) if needed. The
// folder is opened without following a link and its owner is set on that descriptor, never by name.
func prepareStateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	d, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.EMLINK) {
			return errors.New("not a folder (a link is not accepted)")
		}
		return err
	}
	defer d.Close()
	st, err := d.Stat()
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return errors.New("not a folder")
	}
	if uid, gid, ok := agentIDs(); ok {
		return d.Chown(uid, gid)
	}
	return nil
}
