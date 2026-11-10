//go:build windows

package collect

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TrustedExecutable checks that path is a local, absolute path to a plain file (no link or junction) that only
// Administrators, SYSTEM or TrustedInstaller can change, through every folder above it. See safeexe.go.
func TrustedExecutable(path string) error {
	if p := ExecPathProblem(path, true); p != "" {
		return fmt.Errorf("%s %s", path, p)
	}
	path = filepath.Clean(path)
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || isReparse(st) {
		return fmt.Errorf("%s is not a plain file (a link or a folder?)", path)
	}
	kind := ObjFile
	for p := path; ; {
		parent := filepath.Dir(p)
		if parent == p && kind == ObjAncestor {
			kind = ObjRoot // C:\ (the program's own folder keeps the stricter ObjParent check even if it is C:\)
		}
		if err := checkACL(p, kind); err != nil {
			return err
		}
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

func isReparse(st os.FileInfo) bool {
	d, ok := st.Sys().(*syscall.Win32FileAttributeData)
	return ok && d.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func checkACL(p string, kind int) error {
	sd, err := windows.GetNamedSecurityInfo(p, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
	}
	owner, null, aces, err := ownerAndACL(p, sd)
	if err != nil {
		return err
	}
	if kind == objOwnFolder {
		return CheckOwnFolderACL(p, owner, null, aces)
	}
	return CheckWindowsACL(p, kind, owner, null, aces)
}

// objOwnFolder: a folder of Fairy's own that LocalSystem writes files in (CheckOwnFolderACL).
const objOwnFolder = -1

// ownerAndACL reads the owner and the entries out of a security descriptor (null: it has no DACL at all).
func ownerAndACL(p string, sd *windows.SECURITY_DESCRIPTOR) (owner string, null bool, aces []ACE, err error) {
	o, _, err := sd.Owner()
	if err != nil || o == nil {
		return "", false, nil, fmt.Errorf("%s: cannot read its owner", p)
	}
	dacl, _, err := sd.DACL()
	null = errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil)
	if err != nil && !null {
		return "", false, nil, fmt.Errorf("%s: cannot read its permissions: %w", p, err)
	}
	if !null {
		// the DACL as stored (ACL header, then the entries), read by the pure ParseDACL
		size := *(*uint16)(unsafe.Add(unsafe.Pointer(dacl), 2))
		if aces, err = ParseDACL(unsafe.Slice((*byte)(unsafe.Pointer(dacl)), size)); err != nil {
			return "", false, nil, fmt.Errorf("%s: cannot read its permissions: %w", p, err)
		}
	}
	return o.String(), null, aces, nil
}

// FindIpmitool returns ipmitool from C:\Program Files\ipmitool\ (ipmitool.exe or bin\ipmitool.exe) if it is
// trusted. PATH and other folders are never searched: any user may create C:\ipmitool, and the agent may run as
// LocalSystem.
func FindIpmitool() (string, error) {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil || pf == "" {
		pf = `C:\Program Files`
	}
	for _, p := range []string{filepath.Join(pf, "ipmitool", "ipmitool.exe"), filepath.Join(pf, "ipmitool", "bin", "ipmitool.exe")} {
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			continue
		}
		if err := TrustedExecutable(p); err != nil {
			return "", fmt.Errorf("ipmitool found but not used: %w", err)
		}
		return p, nil
	}
	return "", fmt.Errorf("ipmitool not found in %s: install it there or set its full path", filepath.Join(pf, "ipmitool"))
}

// TrustedFolder checks that dir is a plain local folder (no junction) that only Administrators, SYSTEM or
// TrustedInstaller can change, with every folder above it: a folder a LocalSystem process may write files in
// (the helper's log) without another account planting a link there first. For dir itself an entry that only
// passes rights on to what is created inside counts too (CheckOwnFolderACL): the files written there must not
// become another account's.
func TrustedFolder(dir string) error {
	if p := ExecPathProblem(dir, true); p != "" {
		return fmt.Errorf("%s %s", dir, p)
	}
	dir = filepath.Clean(dir)
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() || isReparse(st) {
		return fmt.Errorf("%s is not a plain folder", dir)
	}
	kind := objOwnFolder
	for p := dir; ; {
		parent := filepath.Dir(p)
		if parent == p && kind == ObjAncestor {
			kind = ObjRoot
		}
		if err := checkACL(p, kind); err != nil {
			return err
		}
		if parent == p {
			return nil
		}
		p, kind = parent, ObjAncestor
	}
}
