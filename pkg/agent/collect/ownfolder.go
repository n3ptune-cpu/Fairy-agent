package collect

import "fmt"

// Folders of Fairy's own that a LocalSystem program writes files in (the helper's folder with its log and its
// record of a pending shutdown, the migration's state). The rules for a program's path (CheckWindowsACL) are
// made for Windows' own folders and leave out something that matters here; the decision is in this file so it
// is tested on every platform, the Windows calls are in safeexe_windows.go.

// CREATOR OWNER and CREATOR GROUP stand, in an entry that passes on, for whoever creates the new object.
const (
	sidCreatorOwner = "S-1-3-0"
	sidCreatorGroup = "S-1-3-1"
)

// CheckOwnFolderACL is CheckWindowsACL(path, ObjParent, ...) for one of Fairy's own folders, plus this: an
// entry that only passes on to what is created inside (inherit-only) counts too. CheckWindowsACL skips those,
// rightly for C:\ and C:\ProgramData, which give users rights that way on what they create there themselves.
// In a folder where LocalSystem writes files, such an entry for another account makes every file written from
// now on that account's to change: the folder passes the check today and the file written tomorrow is not
// safe. CREATOR OWNER / CREATOR GROUP entries are the exception (they give the creator rights on what it
// created, and who may create is decided by the other entries).
func CheckOwnFolderACL(path, owner string, nullDACL bool, aces []ACE) error {
	if err := CheckWindowsACL(path, ObjParent, owner, nullDACL, aces); err != nil {
		return err
	}
	bad := dangerousMask(ObjParent)
	for _, a := range aces {
		if a.Kind == ACEDeny || a.Flags&aceInheritOnly == 0 {
			continue
		}
		if (a.Kind == ACEAllow && trustedSID(a.SID)) || a.SID == sidCreatorOwner || a.SID == sidCreatorGroup {
			continue
		}
		if m := fileRights(a.Mask) & bad; m != 0 {
			who := a.SID
			if who == "" {
				who = "an entry it cannot read"
			}
			return fmt.Errorf("%s lets %s change everything that is created in it (an entry that only passes on, access 0x%x)", path, who, a.Mask)
		}
	}
	return nil
}
