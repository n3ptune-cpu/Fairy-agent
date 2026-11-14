//go:build windows

package approval

import (
	"errors"
	"os"

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
