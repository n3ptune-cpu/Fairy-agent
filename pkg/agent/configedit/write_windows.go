package configedit

import (
	"os"

	"golang.org/x/sys/windows"
)

// copyAttrs does nothing on Windows: the new file inherits the folder's permissions (sameSecurity checks).
func copyAttrs(*os.File, string, os.FileInfo) error { return nil }

// sameSecurity reports whether the new file's owner and access list equal the old file's.
func sameSecurity(tmp, path string) bool {
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION)
	a, err := windows.GetNamedSecurityInfo(tmp, windows.SE_FILE_OBJECT, info)
	if err != nil {
		return false
	}
	b, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info)
	if err != nil {
		return false
	}
	return a.String() == b.String()
}

func syncDir(string) {}
