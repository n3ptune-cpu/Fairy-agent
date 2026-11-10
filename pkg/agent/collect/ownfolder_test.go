package collect

import (
	"strings"
	"testing"
)

// parsedSDDL is an SDDL string as the checks get it from Windows: owner, "no DACL", entries.
func parsedSDDL(t *testing.T, sddl string) (string, bool, []ACE) {
	t.Helper()
	owner, null, aces := parseSDDL(t, sddl)
	parsed, err := ParseDACL(binaryACL(t, aces, false))
	if err != nil {
		t.Fatal(err)
	}
	return owner, null, parsed
}

// N8 (review of the Windows side): a folder of Fairy's own that Administrators own and whose only entry for
// someone else is one that only passes on to what is created inside. Such a folder passed TrustedFolder, and
// the next file LocalSystem wrote into it (the helper's log, its record of a pending shutdown) was that
// account's to change.
func TestCheckOwnFolderACL(t *testing.T) {
	const (
		svc    = "(A;OICI;0x1200a9;;;" + sidFairySvc + ")"
		helper = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" + svc // helper\ as install makes it
	)
	check := func(sddl string) error {
		owner, null, aces := parsedSDDL(t, sddl)
		return CheckOwnFolderACL(`C:\ProgramData\fairy-agent\helper`, owner, null, aces)
	}
	for name, sddl := range map[string]string{
		"as install makes it":                  helper,
		"owner SYSTEM":                         strings.Replace(helper, "O:BA", "O:SY", 1),
		"read passed on to Users":              helper + "(A;OICIIO;GXGR;;;BU)", // they can read what is written; not change it
		"CREATOR OWNER passed on":              helper + "(A;OICIIO;GA;;;CO)",   // whoever creates there: administrators and SYSTEM
		"CREATOR GROUP passed on":              helper + "(A;OICIIO;GA;;;CG)",
		"a deny entry that passes on":          helper + "(D;OICIIO;GA;;;BU)",
		"full control passed on to SYSTEM":     helper + "(A;OICIIO;GA;;;SY)",
		"inherited, as under a healthy folder": "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;" + sidFairySvc + ")",
	} {
		if err := check(sddl); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, c := range map[string]struct{ sddl, want string }{
		"full control passed on to Users":         {helper + "(A;OICIIO;FA;;;BU)", "S-1-5-32-545"},
		"GENERIC_ALL passed on to Authenticated":  {"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;AU)", "S-1-5-11"},
		"Modify passed on to files only":          {helper + "(A;OIIO;0x1301bf;;;BU)", "only passes on"},
		"write passed on to the agent's account":  {helper + "(A;OICIIO;GW;;;" + sidFairySvc + ")", sidFairySvc},
		"delete passed on to a user":              {helper + "(A;CIIO;SD;;;" + sidSomeUser + ")", sidSomeUser},
		"change permissions passed on":            {helper + "(A;OICIIO;WD;;;BU)", "S-1-5-32-545"},
		"what CheckWindowsACL refuses anyway":     {helper + "(A;OICI;0x1301bf;;;BU)", "S-1-5-32-545"},
		"someone else's folder":                   {strings.Replace(helper, "O:BA", "O:"+sidSomeUser, 1), "owned by"},
		"no permissions at all":                   {"O:BAD:NO_ACCESS_CONTROL", "no permissions"},
		"the stock C:\\ would not do as helper\\": {sddlDriveRoot, "S-1-5-11"},
	} {
		err := check(c.sddl)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// the folders above keep the old rule: C:\ and C:\ProgramData have such entries by design
	for _, s := range []string{sddlDriveRoot, sddlDriveRootMapped} {
		if err := sddlCheck(t, `C:\`, ObjRoot, s); err != nil {
			t.Error(err)
		}
	}
	// and so does a program's folder (C:\Program Files hands CREATOR OWNER and SYSTEM full control down)
	if err := sddlCheck(t, `C:\Program Files\Fairy`, ObjParent, sddlFairyDir); err != nil {
		t.Error(err)
	}
}
