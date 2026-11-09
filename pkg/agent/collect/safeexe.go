package collect

// Helper programs the agent starts (nvidia-smi, ipmitool) run with the agent's rights: on Windows often
// LocalSystem. A program file that an ordinary user can replace (C:\ipmitool\ipmitool.exe: any signed-in user may
// create folders in C:\) would let that user run code as SYSTEM. TrustedExecutable refuses such files: the path
// must be absolute and local, and neither the file nor any folder above it may be changeable by anyone but
// administrators / SYSTEM / TrustedInstaller (Windows) or root / the agent's own user (Linux). PATH is never
// searched on Windows.

import (
	"fmt"
	"path/filepath"
	"strings"
)

// ExecPathProblem is what is wrong with a configured helper program path ("" = fine as far as the text goes):
// it must be absolute, and on Windows a local drive path (not \\server\share or \\?\...).
func ExecPathProblem(p string, windows bool) string {
	if windows {
		if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, "//") {
			return "must be a path on a local drive (C:\\...), not a network or device path"
		}
		if len(p) < 3 || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
			return "must be an absolute path like C:\\Program Files\\...\\program.exe"
		}
		return ""
	}
	if !filepath.IsAbs(p) {
		return "must be an absolute path"
	}
	return ""
}

// ACE is one access-allowed entry of a Windows DACL, as far as the check needs it.
type ACE struct {
	SID         string // string form, e.g. S-1-5-32-544
	Mask        uint32
	InheritOnly bool // applies only to objects created inside, not to this one
}

// Well-known SIDs that may change program files.
const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

func trustedSID(s string) bool {
	return s == sidSystem || s == sidAdministrators || s == sidTrustedInstaller
}

// Access rights that let someone replace a program or what it loads.
const (
	fileWriteData      = 0x2 // folder: add a file (e.g. a DLL next to the program)
	fileAppendData     = 0x4
	fileDeleteChild    = 0x40
	accessDelete       = 0x10000
	accessWriteDAC     = 0x40000
	accessWriteOwner   = 0x80000
	accessGenericAll   = 0x10000000
	accessGenericWrite = 0x40000000
	accessMaxAllowed   = 0x02000000
)

// Which object of the path is being checked.
const (
	ObjFile     = iota // the program itself
	ObjParent          // the folder holding it (DLLs are loaded from there)
	ObjAncestor        // folders further up
)

func dangerousMask(kind int) uint32 {
	m := uint32(accessDelete | accessWriteDAC | accessWriteOwner | accessGenericAll | accessGenericWrite | accessMaxAllowed)
	switch kind {
	case ObjFile:
		m |= fileWriteData | fileAppendData
	case ObjParent:
		m |= fileWriteData | fileDeleteChild
	default:
		m |= fileDeleteChild
	}
	return m
}

// CheckWindowsACL decides whether one object of a program's path is safe: owned by SYSTEM, Administrators or
// TrustedInstaller, and no allow entry for anyone else with a right that could replace the program. nullDACL is a
// security descriptor without a DACL (everyone has full access).
func CheckWindowsACL(path string, kind int, owner string, nullDACL bool, aces []ACE) error {
	if nullDACL {
		return fmt.Errorf("%s has no permissions set (everyone may change it)", path)
	}
	if !trustedSID(owner) {
		return fmt.Errorf("%s is owned by %s, not by Administrators / SYSTEM (its owner can change it; as administrator: icacls \"%s\" /setowner Administrators)", path, owner, path)
	}
	bad := dangerousMask(kind)
	for _, a := range aces {
		if a.InheritOnly || trustedSID(a.SID) || a.Mask&bad == 0 {
			continue
		}
		return fmt.Errorf("%s may be changed by %s (access 0x%x); install the program under C:\\Program Files instead", path, a.SID, a.Mask)
	}
	return nil
}

// UnixFile is what CheckUnixMode needs of one path component.
type UnixFile struct {
	UID, GID uint32
	Mode     uint32 // permission bits incl. sticky (0o1000)
}

// CheckUnixMode decides whether one component of a program's path is safe: owned by root (or the agent's own
// user, euid), not writable by group (unless group root) or others (folders: unless sticky, like /tmp).
func CheckUnixMode(path string, kind int, f UnixFile, euid uint32) error {
	if f.UID != 0 && f.UID != euid {
		return fmt.Errorf("%s is owned by uid %d (only root may own the programs fairy-agent runs)", path, f.UID)
	}
	if f.Mode&0o020 != 0 && f.GID != 0 {
		return fmt.Errorf("%s is writable by group %d", path, f.GID)
	}
	if f.Mode&0o002 != 0 && (kind == ObjFile || f.Mode&0o1000 == 0) {
		return fmt.Errorf("%s is writable by everyone", path)
	}
	return nil
}
