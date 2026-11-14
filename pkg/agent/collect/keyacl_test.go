package collect

import "testing"

func TestCheckKeyACL(t *testing.T) {
	const (
		system, admins, users, authed, owner = "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545", "S-1-5-11", "S-1-3-0"
		service                              = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-555555555"
		keyAll, keyRead                      = 0xF003F, 0x20019
	)
	good := []ACE{{Kind: ACEAllow, SID: system, Mask: keyAll}, {Kind: ACEAllow, SID: admins, Mask: keyAll}, {Kind: ACEAllow, SID: authed, Mask: keyRead}}
	with := func(a ACE) []ACE { return append(append([]ACE{}, good...), a) }
	for _, c := range []struct {
		name  string
		owner string
		null  bool
		aces  []ACE
		ok    bool
	}{
		{"as the helper makes it", admins, false, good, true},
		{"made by SYSTEM with SYSTEM as the owner", system, false, good, true},
		{"only SYSTEM and Administrators, nobody reads", system, false, good[:2], true},
		{"no entries at all (nobody but the owner)", admins, false, nil, true},
		{"no permission list", admins, true, nil, false},
		{"owned by a user", "S-1-5-21-1-2-3-1001", false, good, false},
		{"owned by the agent's service account", service, false, good, false},
		{"owned by TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", false, good, false},
		{"owned by nobody it can read", "", false, good, false},
		{"Users may set a value", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: keyRead | 0x2}), false},
		{"Users may make a subkey", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: 0x4}), false},
		{"Users may make a link", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: 0x20}), false},
		{"Users may delete it", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: 0x10000}), false},
		{"Users may change its permissions", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: 0x40000}), false},
		{"Users may take it over", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: 0x80000}), false},
		{"the agent's account has everything", admins, false, with(ACE{Kind: ACEAllow, SID: service, Mask: keyAll}), false},
		{"Everyone, GENERIC_ALL", admins, false, with(ACE{Kind: ACEAllow, SID: "S-1-1-0", Mask: 0x10000000}), false},
		{"Everyone, GENERIC_WRITE", admins, false, with(ACE{Kind: ACEAllow, SID: "S-1-1-0", Mask: 0x40000000}), false},
		{"Everyone, MAXIMUM_ALLOWED", admins, false, with(ACE{Kind: ACEAllow, SID: "S-1-1-0", Mask: 0x02000000}), false},
		{"CREATOR OWNER applies to the key", admins, false, with(ACE{Kind: ACEAllow, SID: owner, Mask: keyAll}), false},
		{"CREATOR OWNER, inherit-only", admins, false, with(ACE{Kind: ACEAllow, SID: owner, Mask: keyAll, Flags: aceInheritOnly}), true},
		{"an entry whose account cannot be read, with a write right", admins, false, with(ACE{Kind: ACEAllow, SID: "", Mask: 0x2}), false},
		{"an entry of an unknown kind", admins, false, with(ACE{Kind: ACEOther, SID: users, Mask: 0}), false},
		{"a deny entry for Users", admins, false, with(ACE{Kind: ACEDeny, SID: users, Mask: keyAll}), true},
		{"Users read", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: keyRead}), true},
	} {
		if err := CheckKeyACL(`HKLM\SOFTWARE\x`, c.owner, c.null, c.aces); (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok %v", c.name, err, c.ok)
		}
	}
}
