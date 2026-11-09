package collect

// Helper programs the agent starts (nvidia-smi, ipmitool) run with the agent's rights: on Windows often
// LocalSystem. A program file that an ordinary user can replace (C:\ipmitool\ipmitool.exe: any signed-in user may
// create folders in C:\) would let that user run code as SYSTEM. TrustedExecutable refuses such files: the path
// must be absolute and local, and nobody but administrators / SYSTEM / TrustedInstaller (Windows) or root / the
// agent's own user (Linux) may change the file, put files next to it, or replace any folder above it (on Windows
// see dangerousMask for exactly which rights count where). PATH is never searched on Windows.

import (
	"encoding/binary"
	"errors"
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

// ACE is one entry of a Windows DACL, as far as the check needs it (ParseDACL reads them from the binary DACL).
type ACE struct {
	Kind  int    // ACEAllow, ACEDeny or ACEOther
	Flags uint8  // AceFlags: OBJECT_INHERIT 0x1, CONTAINER_INHERIT 0x2, NO_PROPAGATE 0x4, INHERIT_ONLY 0x8, INHERITED 0x10
	SID   string // string form, e.g. S-1-5-32-544; "" if it could not be read (never trusted)
	Mask  uint32 // as stored: may hold generic rights (GENERIC_ALL ...), mapped by fileRights
}

// ACE kinds.
const (
	ACEAllow = iota // ACCESS_ALLOWED (also callback, object and compound allow entries)
	ACEDeny         // ACCESS_DENIED (and its callback / object forms)
	ACEOther        // an entry type the check does not know: treated like an allow entry of an unknown principal
)

// aceInheritOnly marks an entry that only passes to objects created inside, without applying to this one.
const aceInheritOnly = 0x8

// Well-known SIDs that may change program files.
const (
	sidSystem           = "S-1-5-18"
	sidAdministrators   = "S-1-5-32-544"
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// trustedSID: SYSTEM, Administrators, TrustedInstaller. Nobody else, CREATOR OWNER included: it only ever
// appears in inherit-only entries (skipped anyway), and one that applies is not taken on trust.
func trustedSID(s string) bool {
	return s == sidSystem || s == sidAdministrators || s == sidTrustedInstaller
}

// TrustedOwner reports whether a Windows owner SID is SYSTEM, Administrators or TrustedInstaller.
func TrustedOwner(sid string) bool { return trustedSID(sid) }

// File access rights (folder meaning in the comment where it differs).
const (
	fileWriteData    = 0x2  // folder: FILE_ADD_FILE
	fileAppendData   = 0x4  // folder: FILE_ADD_SUBDIRECTORY
	fileDeleteChild  = 0x40 // folder: delete or rename anything inside, whatever its own permissions
	accessDelete     = 0x10000
	accessWriteDAC   = 0x40000
	accessWriteOwner = 0x80000

	accessMaxAllowed   = 0x02000000
	accessGenericAll   = 0x10000000
	accessGenericExec  = 0x20000000
	accessGenericWrite = 0x40000000
	accessGenericRead  = 0x80000000

	fileAllAccess    = 0x1f01ff // FILE_ALL_ACCESS
	fileGenericRead  = 0x120089
	fileGenericWrite = 0x120116
	fileGenericExec  = 0x1200a0
)

// fileRights maps the generic rights in an entry's mask to what they mean for files and folders (as Windows
// does when it checks access). MAXIMUM_ALLOWED has no meaning in an entry; it is counted as everything.
func fileRights(m uint32) uint32 {
	if m&(accessGenericAll|accessMaxAllowed) != 0 {
		m |= fileAllAccess
	}
	if m&accessGenericRead != 0 {
		m |= fileGenericRead
	}
	if m&accessGenericWrite != 0 {
		m |= fileGenericWrite
	}
	if m&accessGenericExec != 0 {
		m |= fileGenericExec
	}
	return m &^ (accessGenericAll | accessGenericExec | accessGenericWrite | accessGenericRead | accessMaxAllowed)
}

// Which object of the path is being checked.
const (
	ObjFile     = iota // the program itself
	ObjParent          // the folder holding it (DLLs, a .local folder or a manifest next to it are loaded from there)
	ObjAncestor        // folders further up
	ObjRoot            // the drive's root folder (C:\), when it is further up than the program's folder
)

// dangerousMask is which rights, held by anyone but administrators / SYSTEM / TrustedInstaller, would let them
// replace the program or what it loads:
//   - the program: change it (write, append), delete or rename it, change its permissions or owner;
//   - its folder: also put files or folders next to it (DLL planting, program.exe.local redirection) and delete or
//     rename what is inside (FILE_DELETE_CHILD);
//   - a folder further up: only what replaces the path below it: deleting / renaming the folder itself (DELETE),
//     deleting / renaming the folder inside it that the path goes through (FILE_DELETE_CHILD), or taking over
//     its permissions (WRITE_DAC, WRITE_OWNER). Creating new files or folders next to the path (Windows lets
//     every signed-in user create folders in C:\) cannot replace an existing one, so it does not count;
//   - the drive's root: the same, minus DELETE: a drive's root folder cannot be deleted or renamed.
func dangerousMask(kind int) uint32 {
	switch kind {
	case ObjFile:
		return fileWriteData | fileAppendData | accessDelete | accessWriteDAC | accessWriteOwner
	case ObjParent:
		return fileWriteData | fileAppendData | fileDeleteChild | accessDelete | accessWriteDAC | accessWriteOwner
	case ObjRoot:
		return fileDeleteChild | accessWriteDAC | accessWriteOwner
	default:
		return fileDeleteChild | accessDelete | accessWriteDAC | accessWriteOwner
	}
}

// CheckWindowsACL decides whether one object of a program's path is safe: owned by SYSTEM, Administrators or
// TrustedInstaller (an owner may always change the permissions), and no entry that applies to it gives anyone
// else a right that could replace the program (see dangerousMask). nullDACL is a security descriptor without a
// DACL (everyone has full access).
//
// Inherit-only entries are skipped: they do not apply to this object (C:\ gives Authenticated Users Modify
// that way, for the folders they create). Deny entries are ignored: they can only take rights away, so ignoring
// them can make the check refuse something that is in fact safe, never accept something that is not (and an
// entry kind it does not know counts as an allow entry of an unknown principal).
func CheckWindowsACL(path string, kind int, owner string, nullDACL bool, aces []ACE) error {
	if nullDACL {
		return fmt.Errorf("%s has no permissions set (everyone may change it)", path)
	}
	if !trustedSID(owner) {
		return fmt.Errorf("%s is owned by %s, not by Administrators / SYSTEM (its owner can change it; as administrator: icacls \"%s\" /setowner Administrators)", path, owner, path)
	}
	bad := dangerousMask(kind)
	for _, a := range aces {
		if a.Kind == ACEDeny || a.Flags&aceInheritOnly != 0 {
			continue
		}
		if a.Kind == ACEAllow && trustedSID(a.SID) {
			continue
		}
		if m := fileRights(a.Mask) & bad; m != 0 {
			who := a.SID
			if who == "" {
				who = "an entry it cannot read"
			}
			return fmt.Errorf("%s may be changed by %s (access 0x%x, of which 0x%x could replace the program); install the program under C:\\Program Files instead", path, who, a.Mask, m)
		}
	}
	return nil
}

// ParseDACL reads the entries of a binary ACL (the ACL header and the ACEs after it, as Windows stores a DACL).
func ParseDACL(b []byte) ([]ACE, error) {
	if len(b) < 8 {
		return nil, errors.New("ACL too short")
	}
	size, count := int(binary.LittleEndian.Uint16(b[2:4])), int(binary.LittleEndian.Uint16(b[4:6]))
	if size < 8 || size > len(b) {
		return nil, fmt.Errorf("ACL size %d out of range", size)
	}
	b = b[:size]
	aces := make([]ACE, 0, count)
	for i, off := 0, 8; i < count; i++ {
		if off+8 > len(b) {
			return nil, fmt.Errorf("ACE %d past the end of the ACL", i)
		}
		typ, flags, n := b[off], b[off+1], int(binary.LittleEndian.Uint16(b[off+2:off+4]))
		if n < 8 || off+n > len(b) {
			return nil, fmt.Errorf("ACE %d: size %d out of range", i, n)
		}
		ace, body := b[off:off+n], 8 // body: where the SID starts
		a := ACE{Flags: flags, Mask: binary.LittleEndian.Uint32(ace[4:8])}
		switch typ {
		case 0x0, 0x9: // ACCESS_ALLOWED, ACCESS_ALLOWED_CALLBACK
			a.Kind = ACEAllow
		case 0x1, 0x6, 0xa, 0xc: // ACCESS_DENIED (plain, object, callback, callback object)
			a.Kind = ACEDeny
		case 0x5, 0xb: // ACCESS_ALLOWED_OBJECT (and callback): Flags, then the GUIDs those flags announce
			a.Kind = ACEAllow
			if len(ace) < 12 {
				break
			}
			body = 12
			of := binary.LittleEndian.Uint32(ace[8:12])
			if of&1 != 0 {
				body += 16
			}
			if of&2 != 0 {
				body += 16
			}
		default: // compound, audit, label, anything newer: counts as an unknown principal's allow entry
			a.Kind = ACEOther
			body = -1
		}
		if body > 0 && body < len(ace) {
			a.SID = sidString(ace[body:])
		}
		aces = append(aces, a)
		off += n
	}
	return aces, nil
}

// sidString formats a binary SID (S-1-5-32-544); "" if b does not hold one.
func sidString(b []byte) string {
	if len(b) < 8 || b[0] != 1 {
		return ""
	}
	n := int(b[1])
	if n > 15 || len(b) < 8+4*n {
		return ""
	}
	var auth uint64
	for _, c := range b[2:8] {
		auth = auth<<8 | uint64(c)
	}
	var sb strings.Builder
	if auth < 1<<32 {
		fmt.Fprintf(&sb, "S-1-%d", auth)
	} else {
		fmt.Fprintf(&sb, "S-1-0x%012x", auth)
	}
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return sb.String()
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
