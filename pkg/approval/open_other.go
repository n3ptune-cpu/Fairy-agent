//go:build !windows

package approval

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// openShared opens a file for reading. Elsewhere than on Windows an open file never keeps another one from
// taking its name (open_windows.go).
func openShared(path string) (*os.File, error) { return os.Open(path) }

// renameBusy: a rename does not fail because the file is open (open_windows.go).
func renameBusy(error) bool { return false }

// lockFile takes the lock that the two writers of the run record hold while they write (runLock): the file
// at path, exclusively (flock), tried again until wait is over while somebody else holds it. The lock ends
// with unlock, and at the latest with the process. Any other failure is said at once.
//
// The file holds nothing and is never removed (a lock on a file that lost its name excludes nobody). It is
// opened for reading only, never through a link, and made 0600 when it is missing. The administrator's
// command (admin), which runs as root while the service may not, hands a file it made to the group of the
// folder, mode 0640, as it does with the record it writes (UnixAdminPrepare): the service's user can then
// open it. That is done on the open file, not by its name, and only when the command is root; the service
// itself never changes an owner (UnixCanKeep says why it must not even try).
//
// check, when set, must accept the file after it was opened and before it is locked (Files.CheckLock).
func lockFile(path string, wait time.Duration, admin bool, check func(path string) error) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	made := err == nil
	if errors.Is(err, os.ErrExist) {
		// O_NONBLOCK: something that is not a file under this name (a pipe) must not keep the open waiting
		f, err = os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	}
	if err != nil {
		return nil, err
	}
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a plain file", path)
	}
	if admin && os.Geteuid() == 0 {
		// also for a file that was there: one that an earlier call made and could not hand on
		if err := lockHandOn(f, filepath.Dir(path)); err != nil && made {
			_ = f.Close()
			return nil, err
		}
	}
	if check != nil {
		if err := check(path); err != nil {
			_ = f.Close()
			return nil, fmt.Errorf("the lock file is not used: %w", err)
		}
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) || !time.Now().Before(deadline) {
			_ = f.Close()
			return nil, &os.PathError{Op: "lock", Path: path, Err: err}
		}
		time.Sleep(lockStep)
	}
}

// lockHandOn gives the open lock file to root and the group of the folder dir, mode 0640.
func lockHandOn(f *os.File, dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its group", dir)
	}
	is, err := f.Stat()
	if err != nil {
		return err
	}
	if now, ok := is.Sys().(*syscall.Stat_t); !ok || now.Uid != 0 || now.Gid != sys.Gid {
		if err := f.Chown(0, int(sys.Gid)); err != nil {
			return err
		}
	}
	return f.Chmod(0o640)
}
