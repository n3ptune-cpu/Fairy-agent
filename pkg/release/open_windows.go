//go:build windows

package release

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// openNoFollow opens a staged file without following a symlink, junction or other reparse point, and refuses
// files with more than one name (hard links): the installer runs as LocalSystem, the stage belongs to the
// agent's service account.
func openNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	switch {
	case info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0:
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%s is a link or a folder, not a regular file", path)
	case info.NumberOfLinks > 1:
		windows.CloseHandle(h)
		return nil, fmt.Errorf("%s has more than one name (hard link)", path)
	}
	return os.NewFile(uintptr(h), path), nil
}
