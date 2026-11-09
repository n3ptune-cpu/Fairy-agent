package collect

import (
	"strings"
	"testing"
)

const (
	sidUsers     = "S-1-5-32-545"
	sidAuthUsers = "S-1-5-11"
	sidFairySvc  = "S-1-5-80-1111111111-2222222222-3333333333-4044444444-1555555555" // NT SERVICE\fairy-agent
	sidSomeUser  = "S-1-5-21-1-2-3-1001"
	ti           = sidTrustedInstaller
)

// Permissions as (Get-Acl <path>).Sddl prints them on stock Windows 10 / 11 (owner and DACL; group and SACL left
// out). icacls shows the same entries: e.g. C:\'s "(A;OICIIO;SDGXGWGR;;;AU)" is "Authenticated Users:(OI)(CI)(IO)(M)"
// and "(A;;LC;;;AU)" is "Authenticated Users:(AD)".
const (
	// C:\ on Windows 10 / 11
	sddlDriveRoot = "O:" + ti + "G:" + ti + "D:PAI(A;OICIIO;SDGXGWGR;;;AU)(A;;LC;;;AU)(A;OICI;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	// C:\ the way some installs show it: the same with mapped rights instead of generic ones
	sddlDriveRootMapped = "O:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;0x1301bf;;;AU)(A;;0x4;;;AU)"
	// C:\ with Authenticated Users' Modify applying to C:\ itself (not inherit-only): seen on a real PC; Modify
	// holds DELETE (harmless on a drive's root) but neither FILE_DELETE_CHILD nor WRITE_DAC / WRITE_OWNER
	sddlDriveRootModify = "O:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1301bf;;;AU)(A;;0x4;;;AU)"
	// C:\Program Files (C:\Windows and C:\Windows\System32 have the same entries)
	sddlProgramFiles = "O:" + ti + "G:" + ti + "D:PAI(A;;FA;;;" + ti + ")(A;CIIO;GA;;;" + ti + ")(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)" +
		"(A;;0x1301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;CO)" +
		"(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)(A;;0x1200a9;;;S-1-15-2-2)(A;OICIIO;GXGR;;;S-1-15-2-2)"
	sddlWindows  = sddlProgramFiles
	sddlSystem32 = sddlProgramFiles
	// a folder made in C:\Program Files by an administrator (install-fairy-agent.ps1's C:\Program Files\Fairy,
	// C:\Program Files\ipmitool): owned by Administrators, everything inherited, CREATOR OWNER become Administrators
	sddlFairyDir = "O:BAG:S-1-5-21-1-2-3-513D:AI(A;ID;FA;;;" + ti + ")(A;CIIOID;GA;;;" + ti + ")(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)" +
		"(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)" +
		"(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)"
	// a program copied into such a folder
	sddlFairyExe = "O:BAG:S-1-5-21-1-2-3-513D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)"
	// C:\Program Files\NVIDIA Corporation (and NVSMI inside): made by the driver installer as SYSTEM
	sddlNvidiaDir = "O:SYG:SYD:AI(A;ID;FA;;;" + ti + ")(A;CIIOID;GA;;;" + ti + ")(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)" +
		"(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)" +
		"(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)"
	sddlNvidiaExe = "O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)"
	// C:\Windows\System32\nvidia-smi.exe: copied there by the driver (inherited entries), or a protected
	// TrustedInstaller file like Windows' own programs
	sddlSys32Exe   = sddlNvidiaExe
	sddlSys32ExeTI = "O:" + ti + "G:" + ti + "D:PAI(A;;FA;;;" + ti + ")(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)(A;;0x1200a9;;;AC)(A;;0x1200a9;;;S-1-15-2-2)"

	// bad: C:\ipmitool made by a signed-in user: owned by them, Authenticated Users' Modify inherited from C:\
	sddlUserDir = "O:" + sidSomeUser + "G:S-1-5-21-1-2-3-513D:AI(A;ID;0x1301bf;;;AU)(A;OICIIOID;SDGXGWGR;;;AU)(A;OICIID;FA;;;SY)" +
		"(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;OICIID;0x1200a9;;;BU)"
	sddlUserDirExe = "O:" + sidSomeUser + "G:S-1-5-21-1-2-3-513D:AI(A;ID;0x1301bf;;;AU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"
	// bad: the program folder with Users Modify added
	sddlFairyDirUsers = "O:BAD:AI(A;OICI;0x1301bf;;;BU)(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"
	// bad: the program folder as fairy-agent 0.4.2's setup-self-update left it (the service may replace the exe)
	sddlFairyDirLegacy = "O:BAD:AI(A;OICI;0x1301bf;;;" + sidFairySvc + ")(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"
	// bad: a program owned by a user (0.4.2's in-service updater left one owned by the service account)
	sddlUserOwnedExe = "O:" + sidSomeUser + "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)"
)

func TestCheckWindowsACLStock(t *testing.T) {
	// the whole path of each program, file first, as TrustedExecutable walks it
	type step struct {
		path string
		kind int
		sddl string
	}
	ok := map[string][]step{
		`C:\Program Files\Fairy\fairy-agent.exe`: {
			{`C:\Program Files\Fairy\fairy-agent.exe`, ObjFile, sddlFairyExe},
			{`C:\Program Files\Fairy`, ObjParent, sddlFairyDir},
			{`C:\Program Files`, ObjAncestor, sddlProgramFiles},
			{`C:\`, ObjRoot, sddlDriveRoot},
		},
		`C:\Windows\System32\nvidia-smi.exe`: {
			{`C:\Windows\System32\nvidia-smi.exe`, ObjFile, sddlSys32Exe},
			{`C:\Windows\System32`, ObjParent, sddlSystem32},
			{`C:\Windows`, ObjAncestor, sddlWindows},
			{`C:\`, ObjRoot, sddlDriveRoot},
		},
		`C:\Windows\System32\nvidia-smi.exe (TrustedInstaller file)`: {
			{`C:\Windows\System32\nvidia-smi.exe`, ObjFile, sddlSys32ExeTI},
		},
		`C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe`: {
			{`C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe`, ObjFile, sddlNvidiaExe},
			{`C:\Program Files\NVIDIA Corporation\NVSMI`, ObjParent, sddlNvidiaDir},
			{`C:\Program Files\NVIDIA Corporation`, ObjAncestor, sddlNvidiaDir},
			{`C:\Program Files`, ObjAncestor, sddlProgramFiles},
			{`C:\`, ObjRoot, sddlDriveRootMapped},
		},
		`C:\Program Files\ipmitool\ipmitool.exe`: {
			{`C:\Program Files\ipmitool\ipmitool.exe`, ObjFile, sddlFairyExe},
			{`C:\Program Files\ipmitool`, ObjParent, sddlFairyDir},
			{`C:\Program Files`, ObjAncestor, sddlProgramFiles},
			{`C:\`, ObjRoot, sddlDriveRootModify}, // the PC whose C:\ gives Authenticated Users Modify
		},
	}
	for name, steps := range ok {
		for _, s := range steps {
			if err := sddlCheck(t, s.path, s.kind, s.sddl); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
	// also stock C:\ variants as a folder further up (not a root): the inherit-only Modify is skipped
	for _, s := range []string{sddlDriveRoot, sddlDriveRootMapped} {
		if err := sddlCheck(t, `D:\x`, ObjAncestor, s); err != nil {
			t.Error(err)
		}
	}
}

func TestCheckWindowsACLRefuses(t *testing.T) {
	for _, c := range []struct {
		name, path string
		kind       int
		sddl, want string
	}{
		{"user's C:\\ipmitool", `C:\ipmitool`, ObjParent, sddlUserDir, "owned by " + sidSomeUser},
		{"user's C:\\ipmitool given to Administrators", `C:\ipmitool`, ObjParent, strings.Replace(sddlUserDir, "O:"+sidSomeUser, "O:BA", 1), sidAuthUsers},
		{"user's C:\\ipmitool\\ipmitool.exe", `C:\ipmitool\ipmitool.exe`, ObjFile, strings.Replace(sddlUserDirExe, "O:"+sidSomeUser, "O:BA", 1), sidAuthUsers},
		{"user's C:\\ipmitool further up", `C:\ipmitool`, ObjAncestor, strings.Replace(sddlUserDir, "O:"+sidSomeUser, "O:BA", 1), sidAuthUsers}, // Modify holds DELETE
		{"Users-writable program folder", `C:\Program Files\Fairy`, ObjParent, sddlFairyDirUsers, sidUsers},
		{"0.4.2's service-writable program folder", `C:\Program Files\Fairy`, ObjParent, sddlFairyDirLegacy, sidFairySvc},
		{"user-owned program", `C:\Program Files\Fairy\fairy-agent.exe`, ObjFile, sddlUserOwnedExe, "owned by"},
		{"Modify on C:\\ itself, as the program's folder", `C:\`, ObjParent, sddlDriveRootModify, sidAuthUsers},
		{"stock C:\\ as the program's folder (anyone may add a folder: x.exe.local)", `C:\`, ObjParent, sddlDriveRoot, sidAuthUsers},
		{"Modify on a folder further up (not the root)", `C:\Tools`, ObjAncestor, sddlDriveRootModify, sidAuthUsers},
		{"delete-child on the root", `C:\`, ObjRoot, "O:SYD:(A;;FA;;;SY)(A;;DT;;;AU)", sidAuthUsers},
		{"write-DAC on the root", `C:\`, ObjRoot, "O:SYD:(A;;FA;;;SY)(A;;WD;;;BU)", sidUsers},
		{"take-ownership on a folder further up", `C:\Program Files`, ObjAncestor, "O:SYD:(A;;FA;;;SY)(A;;WO;;;BU)", sidUsers},
		{"GENERIC_ALL on a folder further up", `C:\Program Files`, ObjAncestor, "O:SYD:(A;;FA;;;SY)(A;;GA;;;WD)", "S-1-1-0"},
		{"GENERIC_WRITE on the program's folder", `C:\Program Files\Fairy`, ObjParent, "O:BAD:(A;;FA;;;SY)(A;;GW;;;BU)", sidUsers},
		{"GENERIC_WRITE on the program", `C:\x.exe`, ObjFile, "O:BAD:(A;;FA;;;SY)(A;;GWGR;;;BU)", sidUsers},
		{"a deny entry does not make Users' Modify safe", `C:\Program Files\Fairy`, ObjParent, "O:BAD:(D;;0x1301bf;;;BU)(A;;FA;;;SY)(A;;0x1301bf;;;BU)", sidUsers},
		{"a deny entry for Everyone does not hide an allow", `C:\x.exe`, ObjFile, "O:BAD:(D;;FA;;;WD)(A;;FW;;;BU)", sidUsers},
		{"CREATOR OWNER that applies", `C:\Program Files\X`, ObjAncestor, "O:BAD:(A;;FA;;;SY)(A;;GA;;;CO)", "S-1-3-0"},
		{"OWNER RIGHTS", `C:\Program Files\X`, ObjParent, "O:BAD:(A;;FA;;;SY)(A;;0x1301bf;;;OW)", "S-1-3-4"},
		{"object allow entry", `C:\x.exe`, ObjFile, "O:BAD:(A;;FA;;;SY)(OA;;FA;;;BU)", sidUsers},
		{"callback allow entry", `C:\x.exe`, ObjFile, "O:BAD:(A;;FA;;;SY)(XA;;FA;;;BU)", sidUsers},
		{"no DACL", `C:\x.exe`, ObjFile, "O:SYD:NO_ACCESS_CONTROL", "no permissions"},
	} {
		err := sddlCheck(t, c.path, c.kind, c.sddl)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want an error with %q", c.name, err, c.want)
		}
	}
}

func TestCheckWindowsACLRights(t *testing.T) {
	// which single right, held by Users, refuses which object
	for _, c := range []struct {
		mask                  uint32
		file, parent, up, top bool // refused as the program / its folder / a folder further up / the drive's root
	}{
		{0x1200a9, false, false, false, false},                  // read & execute
		{fileWriteData, true, true, false, false},               // write / add file
		{fileAppendData, true, true, false, false},              // append / add subfolder
		{fileDeleteChild, false, true, true, true},              // delete child
		{accessDelete, true, true, true, false},                 // delete / rename
		{accessWriteDAC, true, true, true, true},                // change permissions
		{accessWriteOwner, true, true, true, true},              // take ownership
		{0x100 | 0x10 | 0x20 | 0x8, false, false, false, false}, // attributes and extended attributes
		{accessGenericAll, true, true, true, true},
		{accessGenericWrite, true, true, false, false},
		{accessGenericRead | accessGenericExec, false, false, false, false},
		{accessMaxAllowed, true, true, true, true},
	} {
		for kind, want := range []bool{c.file, c.parent, c.up, c.top} {
			err := CheckWindowsACL("p", kind, sidAdministrators, false, []ACE{{Kind: ACEAllow, SID: sidUsers, Mask: c.mask}})
			if (err != nil) != want {
				t.Errorf("mask 0x%x kind %d: %v, want refused=%v", c.mask, kind, err, want)
			}
			// the same entry inherit-only, or for SYSTEM / Administrators / TrustedInstaller, never counts
			for _, a := range []ACE{{Kind: ACEAllow, SID: sidUsers, Mask: c.mask, Flags: 0xb}, {Kind: ACEAllow, SID: sidSystem, Mask: c.mask},
				{Kind: ACEAllow, SID: sidAdministrators, Mask: c.mask}, {Kind: ACEAllow, SID: sidTrustedInstaller, Mask: c.mask}} {
				if err := CheckWindowsACL("p", kind, sidTrustedInstaller, false, []ACE{a}); err != nil {
					t.Errorf("%+v kind %d: %v", a, kind, err)
				}
			}
		}
	}
	for _, owner := range []string{sidUsers, sidSomeUser, "S-1-3-0", "S-1-1-0", ""} {
		if err := CheckWindowsACL("p", ObjRoot, owner, false, nil); err == nil {
			t.Errorf("owner %q accepted", owner)
		}
	}
	if err := CheckWindowsACL("p", ObjFile, sidSystem, false, nil); err != nil { // empty DACL: only the owner
		t.Fatal(err)
	}
}

func TestExecPathProblem(t *testing.T) {
	for p, bad := range map[string]bool{`C:\Program Files\ipmitool\ipmitool.exe`: false, `c:/tools/x.exe`: false,
		`\\nas\share\ipmitool.exe`: true, `//nas/share/x.exe`: true, `\\?\C:\x.exe`: true, `ipmitool.exe`: true, `\ipmitool.exe`: true, `C:ipmitool.exe`: true} {
		if got := ExecPathProblem(p, true) != ""; got != bad {
			t.Errorf("windows %q: problem=%v", p, got)
		}
	}
	if ExecPathProblem("/usr/bin/ipmitool", false) != "" || ExecPathProblem("ipmitool", false) == "" {
		t.Fatal("unix")
	}
}

func TestCheckUnixMode(t *testing.T) {
	for _, c := range []struct {
		kind int
		f    UnixFile
		ok   bool
	}{
		{ObjFile, UnixFile{0, 0, 0o755}, true},
		{ObjFile, UnixFile{0, 0, 0o775}, true}, // group root
		{ObjFile, UnixFile{0, 50, 0o775}, false},
		{ObjFile, UnixFile{0, 0, 0o757}, false},
		{ObjFile, UnixFile{1000, 0, 0o755}, false},
		{ObjFile, UnixFile{999, 999, 0o755}, true},  // the agent's own user (euid 999)
		{ObjAncestor, UnixFile{0, 0, 0o1777}, true}, // /tmp: sticky
		{ObjParent, UnixFile{0, 0, 0o777}, false},
	} {
		if err := CheckUnixMode("p", c.kind, c.f, 999); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c, err)
		}
	}
}
