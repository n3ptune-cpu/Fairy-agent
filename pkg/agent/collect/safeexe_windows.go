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

const accessAllowedCallbackACEType = 9

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
		if err := checkACL(p, kind); err != nil {
			return err
		}
		parent := filepath.Dir(p)
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
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%s: cannot read its owner", p)
	}
	dacl, _, err := sd.DACL()
	null := errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil)
	if err != nil && !null {
		return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
	}
	var aces []ACE
	if !null {
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE && ace.Header.AceType != accessAllowedCallbackACEType {
				continue // deny entries only take rights away
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			aces = append(aces, ACE{SID: sid.String(), Mask: uint32(ace.Mask), InheritOnly: ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0})
		}
	}
	return CheckWindowsACL(p, kind, owner.String(), null, aces)
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
