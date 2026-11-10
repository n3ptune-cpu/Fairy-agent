package collect

// Two real PCs as fixtures: the security descriptors of the program's path and of the folders above the data
// folder, read with (Get-Acl path).Sddl from two PCs that run fairy-agent 0.5.3, healthy and paired. The
// checks of this package (TrustedExecutable for C:\Program Files\Fairy\fairy-agent.exe, TrustedFolder for
// helper\ and migration\, TrustedFile for the files the helper keeps) have to accept them as they are. They
// run through the same walk the Windows code uses (walkUp) and the same decisions (checkObject,
// OwnFileProblem); the Windows calls that read a descriptor from the disk are not part of the test.
//
// Only the machine's own identifier (the S-1-5-21-... part of the primary group) is replaced by a made-up one
// of the same shape. The rest of the data folder is in cmd/fairy-agent/datadir_realpc_test.go.

import (
	"strings"
	"testing"
)

// realSvc is NT SERVICE\fairy-agent, as Windows derives it from the service's name.
const realSvc = "S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563"

// Path, two spaces, SDDL, as read. C:\Program Files itself was not read on either PC: the line marked "stock"
// is what Windows sets up there, and it is what the inherited entries of C:\Program Files\Fairy mirror.
const realProgramPC1 = `
C:\  O:SYG:SYD:(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1301bf;;;AU)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)
C:\Program Files  stock
C:\Program Files\Fairy  O:BAG:SYD:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)
C:\Program Files\Fairy\fairy-agent.exe  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)
C:\ProgramData  O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)
C:\ProgramData\fairy-agent  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\helper  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
`

const realProgramPC2 = `
C:\  O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)
C:\Program Files  stock
C:\Program Files\Fairy  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:AI(A;ID;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;CIIOID;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;ID;FA;;;SY)(A;OICIIOID;GA;;;SY)(A;ID;FA;;;BA)(A;OICIIOID;GA;;;BA)(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)(A;OICIIOID;GA;;;CO)(A;ID;0x1200a9;;;AC)(A;OICIIOID;GXGR;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)(A;OICIIOID;GXGR;;;S-1-15-2-2)
C:\Program Files\Fairy\fairy-agent.exe  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)(A;ID;0x1200a9;;;AC)(A;ID;0x1200a9;;;S-1-15-2-2)
C:\ProgramData  O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)
C:\ProgramData\fairy-agent  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\helper  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
`

// Not read from the PCs (see cmd/fairy-agent/datadir_realpc_test.go): migration\ as 0.5.3 sets it, and files
// with what they take from their folder. helper.log belongs to SYSTEM on these PCs.
const realProgramAssumed = `
C:\ProgramData\fairy-agent\migration  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\helper\helper.log  O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\helper\power-pending.json  O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\migration\state.json  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
`

// winParent is filepath.Dir for a Windows path, which this test cannot call on another platform: C:\ is its
// own parent.
func winParent(p string) string {
	i := strings.LastIndex(p, `\`)
	if i <= 2 {
		return p[:3]
	}
	return p[:i]
}

// realDisk reads a fixture into path -> SDDL.
func realDisk(t *testing.T, fixture string) map[string]string {
	t.Helper()
	disk := map[string]string{}
	for _, line := range strings.Split(fixture+realProgramAssumed, "\n") {
		if line == "" {
			continue
		}
		p, sddl, ok := strings.Cut(line, "  ")
		if !ok {
			t.Fatalf("fixture line %q", line)
		}
		if sddl == "stock" {
			sddl = sddlProgramFiles
		}
		if strings.Contains(sddl, "S-1-5-21-") && !strings.Contains(sddl, "S-1-5-21-100000000") {
			t.Fatalf("a real machine identifier is in the fixture: %s", p)
		}
		disk[p] = sddl
	}
	return disk
}

// walk runs the walk of TrustedExecutable (first: ObjFile) or TrustedFolder (first: objOwnFolder) over a disk
// of descriptors, and returns the kinds each path was checked as.
func walk(t *testing.T, disk map[string]string, path string, first int) (map[string]int, error) {
	t.Helper()
	kinds := map[string]int{}
	err := walkUp(path, first, winParent, func(p string, kind int) error {
		sddl, ok := disk[p]
		if !ok {
			t.Fatalf("the walk asks for %s, which is not in the fixture", p)
		}
		kinds[p] = kind
		owner, null, aces := parsedSDDL(t, sddl)
		return checkObject(p, kind, owner, null, aces)
	})
	return kinds, err
}

var realProgramPCs = map[string]string{"PC 1 (drive root: SYSTEM, Authenticated Users Modify)": realProgramPC1,
	"PC 2 (stock drive root: TrustedInstaller)": realProgramPC2}

const (
	realExe    = `C:\Program Files\Fairy\fairy-agent.exe`
	realHelper = `C:\ProgramData\fairy-agent\helper`
)

func TestRealPCsProgramAndFoldersAreTrusted(t *testing.T) {
	for name, fixture := range realProgramPCs {
		disk := realDisk(t, fixture)

		// the program: what the agent checks at start, the helper before it starts the updater, the updater and
		// the self-migration before they run or install it
		kinds, err := walk(t, disk, realExe, ObjFile)
		if err != nil {
			t.Errorf("%s: the program is not trusted: %v", name, err)
		}
		want := map[string]int{realExe: ObjFile, `C:\Program Files\Fairy`: ObjParent, `C:\Program Files`: ObjAncestor, `C:\`: ObjRoot}
		if len(kinds) != len(want) {
			t.Errorf("%s: walked %v", name, kinds)
		}
		for p, k := range want {
			if kinds[p] != k {
				t.Errorf("%s: %s was checked as %d, want %d", name, p, kinds[p], k)
			}
		}

		// helper\ (the helper's log, the record of a pending shutdown) and migration\ (the self-migration's
		// state): folders LocalSystem writes in
		for _, dir := range []string{realHelper, `C:\ProgramData\fairy-agent\migration`} {
			kinds, err := walk(t, disk, dir, objOwnFolder)
			if err != nil {
				t.Errorf("%s: %s is not trusted: %v", name, dir, err)
			}
			if kinds[dir] != objOwnFolder || kinds[`C:\ProgramData\fairy-agent`] != ObjAncestor || kinds[`C:\ProgramData`] != ObjAncestor ||
				kinds[`C:\`] != ObjRoot || len(kinds) != 4 {
				t.Errorf("%s: %s walked as %v", name, dir, kinds)
			}
		}
		// the files in them
		for _, f := range []string{realHelper + `\helper.log`, realHelper + `\power-pending.json`, `C:\ProgramData\fairy-agent\migration\state.json`} {
			owner, null, aces := parsedSDDL(t, disk[f])
			if why := OwnFileProblem(f, false, false, 1, owner, null, aces); why != "" {
				t.Errorf("%s: %s", name, why)
			}
		}
	}
}

// The other direction: the same PCs with one entry added for ordinary users are refused.
func TestRealPCsWithOneEntryForOthersAreNotTrusted(t *testing.T) {
	for name, fixture := range realProgramPCs {
		for _, c := range []struct {
			what, path, entry, start string
			first                    int
		}{
			{"the program: Authenticated Users full control", realExe, "(A;;FA;;;AU)", realExe, ObjFile},
			{"the program: Users may modify", realExe, "(A;OICI;0x1301bf;;;BU)", realExe, ObjFile},
			{"the program's folder: Users may modify", `C:\Program Files\Fairy`, "(A;OICI;0x1301bf;;;BU)", realExe, ObjFile},
			{"the program's folder: Authenticated Users full control", `C:\Program Files\Fairy`, "(A;;FA;;;AU)", realExe, ObjFile},
			{"C:\\Program Files: Users may delete what is in it", `C:\Program Files`, "(A;;0x1301ff;;;BU)", realExe, ObjFile},
			{"the drive root: Users may delete what is in it", `C:\`, "(A;;0x1301ff;;;BU)", realExe, ObjFile},
			{"helper\\: Users may modify", realHelper, "(A;OICI;0x1301bf;;;BU)", realHelper, objOwnFolder},
			{"helper\\: Authenticated Users full control", realHelper, "(A;;FA;;;AU)", realHelper, objOwnFolder},
			{"helper\\: Users may modify what is created from now on", realHelper, "(A;OICIIO;0x1301bf;;;BU)", realHelper, objOwnFolder},
			{"the data folder: Users may modify", `C:\ProgramData\fairy-agent`, "(A;OICI;0x1301bf;;;BU)", realHelper, objOwnFolder},
			{"the data folder: Authenticated Users full control", `C:\ProgramData\fairy-agent`, "(A;;FA;;;AU)", realHelper, objOwnFolder},
		} {
			disk := realDisk(t, fixture)
			disk[c.path] += c.entry
			_, err := walk(t, disk, c.start, c.first)
			if err == nil || (!strings.Contains(err.Error(), sidUsers) && !strings.Contains(err.Error(), sidAuthUsers)) {
				t.Errorf("%s, %s: %v", name, c.what, err)
			}
		}
		// helper\ with the agent's own account allowed to write (what its own folders logs\ and state\ have): not a
		// folder LocalSystem may write in
		disk := realDisk(t, fixture)
		disk[realHelper] = strings.Replace(disk[realHelper], "0x1200a9;;;"+realSvc, "0x1301bf;;;"+realSvc, 1)
		if _, err := walk(t, disk, realHelper, objOwnFolder); err == nil || !strings.Contains(err.Error(), realSvc) {
			t.Errorf("%s: helper\\ writable by the agent's account: %v", name, err)
		}
		// a file of the helper's that Users may write, or that a user owns
		disk = realDisk(t, fixture)
		f := realHelper + `\power-pending.json`
		for _, sddl := range []string{disk[f] + "(A;;0x1301bf;;;BU)", disk[f] + "(A;;FA;;;AU)", strings.Replace(disk[f], "O:SY", "O:"+sidSomeUser, 1)} {
			owner, null, aces := parsedSDDL(t, sddl)
			if why := OwnFileProblem(f, false, false, 1, owner, null, aces); why == "" {
				t.Errorf("%s: %s is trusted", name, sddl)
			}
		}
	}
}

// What walkUp gives each object of a path, also where the program or the folder sits directly on the drive.
func TestWalkUpKinds(t *testing.T) {
	for _, c := range []struct {
		path  string
		first int
		want  string
	}{
		{`C:\Program Files\Fairy\fairy-agent.exe`, ObjFile, `C:\Program Files\Fairy\fairy-agent.exe=file C:\Program Files\Fairy=parent C:\Program Files=ancestor C:\=root`},
		{`C:\tools\x.exe`, ObjFile, `C:\tools\x.exe=file C:\tools=parent C:\=root`},
		{`C:\x.exe`, ObjFile, `C:\x.exe=file C:\=parent`}, // the stricter check stays for a program directly in C:\
		{`C:\ProgramData\fairy-agent\helper`, objOwnFolder, `C:\ProgramData\fairy-agent\helper=own C:\ProgramData\fairy-agent=ancestor C:\ProgramData=ancestor C:\=root`},
		{`C:\helper`, objOwnFolder, `C:\helper=own C:\=root`},
		{`C:\`, objOwnFolder, `C:\=own`},
	} {
		names := map[int]string{ObjFile: "file", ObjParent: "parent", ObjAncestor: "ancestor", ObjRoot: "root", objOwnFolder: "own"}
		var got []string
		if err := walkUp(c.path, c.first, winParent, func(p string, kind int) error {
			got = append(got, p+"="+names[kind])
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.path, strings.Join(got, " "), c.want)
		}
	}
}
