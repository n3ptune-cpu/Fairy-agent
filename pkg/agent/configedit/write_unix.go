//go:build !windows

package configedit

import (
	"os"
	"syscall"
)

func copyAttrs(tmp *os.File, path string, st os.FileInfo) error {
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		return err
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		if err := tmp.Chown(int(s.Uid), int(s.Gid)); err != nil {
			return err
		}
	}
	return copyXattrs(tmp, path)
}

func sameSecurity(string, string) bool { return true } // copyAttrs made them equal

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
}
