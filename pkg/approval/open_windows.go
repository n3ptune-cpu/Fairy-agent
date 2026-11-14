//go:build windows

package approval

import (
	"errors"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

// openShared opens a file for reading and lets everybody else read it, write it, and rename or delete it in
// the meantime (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE). os.Open shares for reading and
// writing only: while the agent, the helper or `fairy-agent helper-run show` had the run record open that
// way, the helper's new record could not take the record's name (the rename failed with a sharing violation),
// and neither could the administrator's cancel.
func openShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// renameBusy reports whether a rename failed because somebody has the file open at this moment (another
// program that opened it without sharing, a virus scanner): worth trying again shortly.
func renameBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// lockFile takes the lock that the two writers of the run record hold while they write (runLock): the first
// byte of the file at path, exclusively (LockFileEx), tried again until wait is over while somebody else
// holds it. The lock ends with unlock, and at the latest with the process. Any other failure is said at once.
//
// The file holds nothing and is never removed. It is made when it is missing and has the owner and the access
// list its folder hands on (the helper's folder: SYSTEM and Administrators), which is what both writers are;
// admin changes nothing here. It is opened so that nobody is kept from opening it too.
func lockFile(path string, wait time.Duration, admin bool) (unlock func(), err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	deadline := time.Now().Add(wait)
	for {
		var ol windows.Overlapped
		err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
		if err == nil {
			return func() {
				var ol windows.Overlapped
				_ = windows.UnlockFileEx(h, 0, 1, 0, &ol)
				_ = windows.CloseHandle(h)
			}, nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) || !time.Now().Before(deadline) {
			_ = windows.CloseHandle(h)
			return nil, &os.PathError{Op: "lock", Path: path, Err: err}
		}
		time.Sleep(lockStep)
	}
}
