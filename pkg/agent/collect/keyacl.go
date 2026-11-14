package collect

import "fmt"

// Rights on a registry key with which whoever holds them could change what the key says, replace it, or
// take it over: set a value, make a subkey or a link, delete the key, change its permissions or its owner
// (and the generic rights that contain those).
const (
	keySetValue     = 0x2
	keyCreateSubKey = 0x4
	keyCreateLink   = 0x20
	genericAll      = 0x10000000
	genericWrite    = 0x40000000
	maximumAllowed  = 0x02000000
	keyChange       = keySetValue | keyCreateSubKey | keyCreateLink | accessDelete | accessWriteDAC | accessWriteOwner | genericAll | genericWrite | maximumAllowed
)

// CheckKeyACL decides whether a registry key can be believed that only SYSTEM or an administrator may have
// written: the key in which the Windows helper keeps the id of this boot (agent.SystemBootID). It is the
// check of the trust file (CheckWindowsACL), for a key: the owner is SYSTEM or Administrators (an owner can
// always change the permissions; TrustedInstaller owns Windows' own keys and never this one), there is a
// permission list, and no entry that applies to the key gives anybody else a right to change it. Reading is
// everybody's: the id is no secret, and the agent's own account must read it. Deny entries are ignored (they
// only take away), inherit-only entries do not apply to the key, and an entry of a kind this does not know
// counts as an allow entry of somebody unknown.
func CheckKeyACL(name, owner string, nullDACL bool, aces []ACE) error {
	if nullDACL {
		return fmt.Errorf("%s has no permissions set (everyone may change it)", name)
	}
	if owner != sidSystem && owner != sidAdministrators {
		return fmt.Errorf("%s is owned by %s, not by Administrators or SYSTEM", name, owner)
	}
	for _, a := range aces {
		if a.Kind == ACEDeny || a.Flags&aceInheritOnly != 0 {
			continue
		}
		if a.Kind == ACEAllow && (a.SID == sidSystem || a.SID == sidAdministrators) {
			continue
		}
		if m := a.Mask & keyChange; m != 0 || a.Kind != ACEAllow {
			who := a.SID
			if who == "" {
				who = "an entry it cannot read"
			}
			return fmt.Errorf("%s may be changed by %s (access 0x%x)", name, who, a.Mask)
		}
	}
	return nil
}
