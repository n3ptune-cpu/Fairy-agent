package collect

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const (
	sidUsers     = "S-1-5-32-545"
	sidAuthUsers = "S-1-5-11"
	sidCreatorOw = "S-1-3-0"
	sidFairySvc  = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-5555555555" // NT SERVICE\fairy-agent
	sidSomeUser  = "S-1-5-21-1-2-3-1001"
)

// Windows' default permissions, as icacls shows them on Windows 10 / 11.
func TestCheckWindowsACL(t *testing.T) {
	driveRoot := []ACE{ // C:\
		{SID: sidAdministrators, Mask: 0x1f01ff}, {SID: sidSystem, Mask: 0x1f01ff}, {SID: sidUsers, Mask: 0x1200a9},
		{SID: sidAuthUsers, Mask: 0x1301bf, InheritOnly: true}, // (OI)(CI)(IO)(M): for what users create inside
		{SID: sidAuthUsers, Mask: 0x4},                         // (AD): any user may create a folder in C:\
	}
	programFiles := []ACE{
		{SID: sidTrustedInstaller, Mask: 0x1f01ff}, {SID: sidSystem, Mask: 0x1301bf}, {SID: sidAdministrators, Mask: 0x1301bf},
		{SID: sidUsers, Mask: 0x1200a9}, {SID: sidCreatorOw, Mask: 0x10000000, InheritOnly: true},
	}
	ok := []struct {
		kind  int
		owner string
		aces  []ACE
	}{
		{ObjAncestor, sidTrustedInstaller, driveRoot},
		{ObjAncestor, sidTrustedInstaller, programFiles},
		{ObjParent, sidAdministrators, programFiles}, // C:\Program Files\ipmitool made by an administrator
		{ObjFile, sidAdministrators, programFiles[:4]},
	}
	for i, c := range ok {
		if err := CheckWindowsACL("x", c.kind, c.owner, false, c.aces); err != nil {
			t.Errorf("%d: %v", i, err)
		}
	}
	// C:\ipmitool made by a signed-in user: owned by them, and they have Modify through CREATOR OWNER / AU
	userDir := []ACE{{SID: sidAdministrators, Mask: 0x1f01ff}, {SID: sidSystem, Mask: 0x1f01ff}, {SID: sidAuthUsers, Mask: 0x1301bf}}
	if err := CheckWindowsACL(`C:\ipmitool`, ObjParent, sidSomeUser, false, userDir); err == nil || !strings.Contains(err.Error(), "owned by") {
		t.Fatal(err)
	}
	if err := CheckWindowsACL(`C:\ipmitool`, ObjParent, sidAdministrators, false, userDir); err == nil || !strings.Contains(err.Error(), sidAuthUsers) {
		t.Fatal(err)
	}
	// the program folder as fairy-agent 0.4.2's setup-self-update left it: the service may replace the exe
	legacy := append(programFiles[:4:4], ACE{SID: sidFairySvc, Mask: 0x1301bf})
	if err := CheckWindowsACL(`C:\Program Files\Fairy`, ObjParent, sidAdministrators, false, legacy); err == nil {
		t.Fatal("service-writable program folder accepted")
	}
	// adding files to the program's folder (a DLL next to it) is enough to refuse; on folders further up not
	if err := CheckWindowsACL("d", ObjParent, sidAdministrators, false, []ACE{{SID: sidUsers, Mask: 0x2}}); err == nil {
		t.Fatal("add-file on the program's folder")
	}
	if err := CheckWindowsACL("d", ObjAncestor, sidAdministrators, false, []ACE{{SID: sidUsers, Mask: 0x2}}); err != nil {
		t.Fatal(err)
	}
	for _, mask := range []uint32{0x2, 0x4, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000} {
		if err := CheckWindowsACL("f", ObjFile, sidAdministrators, false, []ACE{{SID: sidUsers, Mask: mask}}); err == nil {
			t.Errorf("file mask 0x%x accepted", mask)
		}
	}
	if err := CheckWindowsACL("f", ObjFile, sidSystem, true, nil); err == nil {
		t.Fatal("null DACL accepted")
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

func TestTrustedExecutableUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix permissions")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "ipmitool")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := TrustedExecutable(bin); err != nil && os.Geteuid() == 0 {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil { // a folder anyone may write into (no sticky bit)
		t.Fatal(err)
	}
	if err := TrustedExecutable(bin); err == nil || !strings.Contains(err.Error(), "everyone") {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o755)
	if err := TrustedExecutable("ipmitool"); err == nil {
		t.Fatal("relative path accepted")
	}
	if err := TrustedExecutable(dir); err == nil {
		t.Fatal("a folder accepted")
	}
	if os.Geteuid() == 0 {
		if err := os.Chown(bin, 1234, 0); err != nil {
			t.Fatal(err)
		}
		if err := TrustedExecutable(bin); err == nil || !strings.Contains(err.Error(), "uid 1234") {
			t.Fatal(err)
		}
	}
}
