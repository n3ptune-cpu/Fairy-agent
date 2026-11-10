//go:build windows

package agent

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// errLogLink: the log's name is a link or has a second name; nothing is written through it.
var errLogLink = errors.New("is a link (a symbolic link, a junction or a second name of another file), not a plain log file")

// openLogFile opens the log for appending, creating it when missing, without ever following a link: the name
// is opened itself (FILE_FLAG_OPEN_REPARSE_POINT) and what was opened must be a plain file with one name.
// The handle has the same rights os.OpenFile asks for with O_WRONLY|O_APPEND (append only, so every write goes
// to the end of the file).
//
// If that open fails for a reason of its own, the log is opened the usual way, unless the name is a link:
// logging must not stop working over the stricter call.
func openLogFile(path string) (*os.File, error) {
	f, err := openLogNoFollow(path)
	if err == nil || errors.Is(err, errLogLink) {
		return f, err
	}
	if st, lerr := os.Lstat(path); lerr == nil && (!st.Mode().IsRegular() || isReparsePoint(st)) {
		return nil, fmt.Errorf("%s %w", path, errLogLink)
	}
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
}

func openLogNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const access = windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA |
		windows.STANDARD_RIGHTS_WRITE | windows.SYNCHRONIZE
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || info.NumberOfLinks > 1 {
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%s %w", path, errLogLink)
	}
	return os.NewFile(uintptr(h), path), nil
}
