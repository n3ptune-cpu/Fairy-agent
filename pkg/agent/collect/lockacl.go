package collect

import "fmt"

// CheckLockACL decides whether a file can be the lock of the run record's two writers (approval.RunLockName,
// Windows). The lock is taken with LockFileEx, and for that a handle that can read is enough: whoever can
// open the file at all can hold the lock, and while he holds it the helper writes nothing (nothing is armed,
// a cancel is answered with an error). So this file is stricter than every other file of the helper's, which
// the agent's account may read: its owner is SYSTEM or Administrators, it has a permission list, and every
// entry that applies to it allows something to SYSTEM or to Administrators and to nobody else, whatever the
// rights (also none, and also TrustedInstaller: nobody else has any business with it). Deny entries are
// ignored (they only take away), entries that only pass on do not apply to a file, and an entry of a kind
// this does not know is somebody else's.
func CheckLockACL(path, owner string, nullDACL bool, aces []ACE) error {
	if nullDACL {
		return fmt.Errorf("%s has no permissions set (everyone may open it)", path)
	}
	if owner != sidSystem && owner != sidAdministrators {
		return fmt.Errorf("%s is owned by %s, not by Administrators or SYSTEM", path, owner)
	}
	for _, a := range aces {
		if a.Kind == ACEDeny || a.Flags&aceInheritOnly != 0 {
			continue
		}
		if a.Kind == ACEAllow && (a.SID == sidSystem || a.SID == sidAdministrators) {
			continue
		}
		who := a.SID
		if who == "" {
			who = "an entry it cannot read"
		}
		return fmt.Errorf("%s has an entry for %s (access 0x%x): only SYSTEM and Administrators may open this file, because whoever can open it can hold the lock", path, who, a.Mask)
	}
	return nil
}

// LockFileProblem says why the file at path cannot be used as that lock ("" = it can): it must be a plain file
// with one name that passes CheckLockACL.
func LockFileProblem(path string, dir, link bool, names uint32, owner string, nullDACL bool, aces []ACE) string {
	switch {
	case link:
		return path + " is a link (a junction or symbolic link), not a plain file"
	case dir:
		return path + " is a folder where a file belongs"
	case names > 1:
		return path + " has more than one name (a hard link)"
	}
	if err := CheckLockACL(path, owner, nullDACL, aces); err != nil {
		return err.Error()
	}
	return ""
}
