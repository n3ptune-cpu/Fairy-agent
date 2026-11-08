package configedit

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// copyXattrs gives the new file the old one's SELinux label and POSIX ACL, when it has them.
func copyXattrs(tmp *os.File, path string) error {
	for _, name := range []string{"security.selinux", "system.posix_acl_access"} {
		buf := make([]byte, 4096)
		n, err := unix.Getxattr(path, name, buf)
		if err != nil {
			continue // not set, or not supported by the file system
		}
		if err := unix.Fsetxattr(int(tmp.Fd()), name, buf[:n], 0); err != nil && !errors.Is(err, unix.ENOTSUP) {
			return err
		}
	}
	return nil
}
