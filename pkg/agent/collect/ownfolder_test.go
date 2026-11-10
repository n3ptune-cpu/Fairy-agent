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

// N9 (review of the Windows side): a file in a folder of Fairy's own is looked at itself before a LocalSystem
// program believes what is in it.
func TestOwnFileProblem(t *testing.T) {
	const (
		path = `C:\ProgramData\fairy-agent\helper\power-pending.json`
		// as the helper (LocalSystem) writes it: owner Administrators, everything inherited from helper\
		written = "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;" + sidFairySvc + ")"
	)
	problem := func(sddl string, dir, link bool, names uint32) string {
		owner, null, aces := parsedSDDL(t, sddl)
		return OwnFileProblem(path, dir, link, names, owner, null, aces)
	}
	for name, sddl := range map[string]string{
		"as the helper writes it":    written,
		"owner SYSTEM":               strings.Replace(written, "O:BA", "O:SY", 1),
		"someone else may read it":   written + "(A;ID;0x1200a9;;;BU)", // reading a pending shutdown's time steers nothing
		"a deny entry":               written + "(D;;FA;;;BU)",
		"its own protected list":     "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)",
		"CREATOR OWNER, not applied": written + "(A;OICIIO;GA;;;CO)",
	} {
		if why := problem(sddl, false, false, 1); why != "" {
			t.Errorf("%s: refused: %s", name, why)
		}
	}
	for name, c := range map[string]struct{ sddl, want string }{
		"planted before the folder was locked: the planter owns it": {strings.Replace(written, "O:BA", "O:"+sidSomeUser, 1), "owned by " + sidSomeUser},
		"the planter may still write it":                            {written + "(A;;0x1301bf;;;" + sidSomeUser + ")", sidSomeUser},
		"Users may write":                                           {written + "(A;;FW;;;BU)", "S-1-5-32-545"},
		"Users may delete it":                                       {written + "(A;;SD;;;BU)", "S-1-5-32-545"},
		"the agent's own account may write it":                      {"O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;" + sidFairySvc + ")", sidFairySvc},
		"owned by the agent's account":                              {strings.Replace(written, "O:BA", "O:"+sidFairySvc, 1), "owned by"},
		"no permissions at all":                                     {"O:BAD:NO_ACCESS_CONTROL", "no permissions"},
	} {
		if why := problem(c.sddl, false, false, 1); !strings.Contains(why, c.want) || why == "" {
			t.Errorf("%s: %q", name, why)
		}
	}
	// not a plain file with one name, whatever its permissions
	if why := problem(written, false, true, 1); !strings.Contains(why, "is a link") {
		t.Error("a link:", why)
	}
	if why := problem(written, true, false, 1); !strings.Contains(why, "folder where a file belongs") {
		t.Error("a folder:", why)
	}
	if why := problem(written, false, false, 2); !strings.Contains(why, "more than one name") {
		t.Error("a hard link:", why)
	}
	if why := problem(written, false, false, 0); why != "" { // the number of names is not known: not a reason
		t.Error(why)
	}
}
