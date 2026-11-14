package collect

import "testing"

// The lock of the run record's two writers (approval.RunLockName) is taken with LockFileEx, which needs
// nothing but a handle that can read. So the file must be one that nobody can open at all but the two
// writers: SYSTEM (the helper) and Administrators (fairy-agent helper-run). The helper's folder hands on a
// read entry for the agent's account, which is right for the trust file and the record and wrong for this
// file: with it the agent's low-privilege account could hold the lock for ever (second review of the runs, U3).
func TestCheckLockACL(t *testing.T) {
	const (
		system, admins, users, authed, owner = "S-1-5-18", "S-1-5-32-544", "S-1-5-32-545", "S-1-5-11", "S-1-3-0"
		service                              = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-555555555"
		fileAll, fileRead                    = 0x1F01FF, 0x1200A9
	)
	good := []ACE{{Kind: ACEAllow, SID: system, Mask: fileAll}, {Kind: ACEAllow, SID: admins, Mask: fileAll}}
	with := func(a ACE) []ACE { return append(append([]ACE{}, good...), a) }
	for _, c := range []struct {
		name  string
		owner string
		null  bool
		aces  []ACE
		ok    bool
	}{
		{"as it is made (D:P, SYSTEM and Administrators everything)", admins, false, good, true},
		{"made by SYSTEM with SYSTEM as the owner", system, false, good, true},
		{"the two entries marked as handed on by a folder that has only those", admins, false,
			[]ACE{{Kind: ACEAllow, SID: system, Mask: fileAll, Flags: 0x10}, {Kind: ACEAllow, SID: admins, Mask: fileAll, Flags: 0x10}}, true},
		{"no entries at all (nobody but the owner)", admins, false, nil, true},
		{"no permission list", admins, true, nil, false},
		{"owned by a user", "S-1-5-21-1-2-3-1001", false, good, false},
		{"owned by the agent's service account", service, false, good, false},
		{"owned by TrustedInstaller", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", false, good, false},
		{"owned by nobody it can read", "", false, good, false},
		{"as the helper's folder hands it on: the agent's account reads", admins, false, with(ACE{Kind: ACEAllow, SID: service, Mask: fileRead, Flags: 0x10}), false},
		{"the agent's account reads, set on the file itself", admins, false, with(ACE{Kind: ACEAllow, SID: service, Mask: fileRead}), false},
		{"Users read", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: fileRead}), false},
		{"signed-in accounts read the data only", admins, false, with(ACE{Kind: ACEAllow, SID: authed, Mask: 0x1}), false},
		{"Users may only read the attributes", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: 0x80}), false},
		{"Everyone, GENERIC_READ", admins, false, with(ACE{Kind: ACEAllow, SID: "S-1-1-0", Mask: 0x80000000}), false},
		{"Everyone, MAXIMUM_ALLOWED", admins, false, with(ACE{Kind: ACEAllow, SID: "S-1-1-0", Mask: 0x02000000}), false},
		{"Everyone, with no right at all", admins, false, with(ACE{Kind: ACEAllow, SID: "S-1-1-0", Mask: 0}), false},
		{"TrustedInstaller has everything", admins, false, with(ACE{Kind: ACEAllow, SID: "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", Mask: fileAll}), false},
		{"CREATOR OWNER applies to the file", admins, false, with(ACE{Kind: ACEAllow, SID: owner, Mask: fileAll}), false},
		{"an entry that only passes on (it does not apply to a file)", admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: fileAll, Flags: aceInheritOnly}), true},
		{"an entry whose account cannot be read", admins, false, with(ACE{Kind: ACEAllow, SID: "", Mask: fileRead}), false},
		{"an entry of an unknown kind", admins, false, with(ACE{Kind: ACEOther, SID: users, Mask: 0}), false},
		{"an entry of an unknown kind for SYSTEM", admins, false, with(ACE{Kind: ACEOther, SID: system, Mask: fileAll}), false},
		{"a deny entry for Users", admins, false, with(ACE{Kind: ACEDeny, SID: users, Mask: fileAll}), true},
	} {
		err := CheckLockACL(`C:\ProgramData\fairy-agent\helper\approval-run.lock`, c.owner, c.null, c.aces)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want ok=%v", c.name, err, c.ok)
		}
	}
	// and the file itself: a plain file with one name
	const p = `C:\ProgramData\fairy-agent\helper\approval-run.lock`
	if why := LockFileProblem(p, false, false, 1, admins, false, good); why != "" {
		t.Errorf("the lock file as it is made: %s", why)
	}
	for name, why := range map[string]string{
		"a folder":            LockFileProblem(p, true, false, 1, admins, false, good),
		"a link":              LockFileProblem(p, false, true, 1, admins, false, good),
		"a file of two names": LockFileProblem(p, false, false, 2, admins, false, good),
		"readable by Users":   LockFileProblem(p, false, false, 1, admins, false, with(ACE{Kind: ACEAllow, SID: users, Mask: fileRead})),
	} {
		if why == "" {
			t.Errorf("%s is taken for the lock file", name)
		}
	}
}
