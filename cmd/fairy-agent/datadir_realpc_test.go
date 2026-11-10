package main

// Two real PCs as fixtures. The security descriptors below were read with (Get-Acl path).Sddl from two PCs
// that run fairy-agent 0.5.3, installed and updated the ordinary way, healthy and paired. Every check this
// program makes on an existing install has to accept them as they are, and the installer's repair has to find
// nothing to do on them: no call that changes anything, nothing moved aside, no line printed. An earlier
// release refused one of these PCs because of its drive root.
//
// Only the machine's own identifier (the S-1-5-21-... part of the primary group) is replaced by a made-up one
// of the same shape. The service SIDs (S-1-5-80-...) are derived from the service names and are the same on
// every PC; S-1-15-3-65536-... is a capability SID that Windows 11 puts on every drive root.
//
// The program's own path (C:\Program Files\Fairy) is in pkg/agent/collect/realpc_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// realSvc is NT SERVICE\fairy-agent, as Windows derives it from the service's name.
const realSvc = "S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563"

// What was read from each PC: path, two spaces, SDDL.
//
// PC 1: the drive root belongs to SYSTEM and gives Authenticated Users Modify on the root itself (0x1301bf,
// not inherit-only); state\ has the local "None" group (-513) as its primary group; update\stage belongs to
// SYSTEM (the agent made it itself while it still ran as LocalSystem).
const realPC1 = `
C:\  O:SYG:SYD:(A;OICIIO;SDGXGWGR;;;AU)(A;;0x1301bf;;;AU)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)
C:\ProgramData  O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)
C:\ProgramData\fairy-agent  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\config.yaml  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\token  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\control-token  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\helper  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\logs  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\state  O:BAG:S-1-5-21-1000000001-2000000002-3000000003-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\update  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\update\stage  O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
`

// PC 2: a stock Windows install. The drive root belongs to TrustedInstaller (owner and group); the local
// "None" group is the primary group of almost every one of Fairy's paths; update\stage belongs to SYSTEM.
const realPC2 = `
C:\  O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:PAI(A;;LC;;;AU)(A;OICIIO;SDGXGWGR;;;AU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;;0x1000a1;;;S-1-15-3-65536-1888954469-739942743-1668119174-2468466756-4239452838-1296943325-355587736-700089176)
C:\ProgramData  O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)
C:\ProgramData\fairy-agent  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\config.yaml  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\token  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\control-token  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\helper  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\logs  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\state  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\update  O:BAG:S-1-5-21-1000000004-2000000005-3000000006-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\update\stage  O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
`

// What is on these PCs but whose entries were NOT read from them: the migration\ folder and the files inside
// the folders. Their owners are as seen on PC 1 (helper.log and agent.log belong to SYSTEM, the others to
// Administrators); their entries are what 0.5.3 itself sets (migration\) and what a file takes from its
// folder (everything inherited). If a real file there has entries of its own, this test does not know it.
const realPCAssumed = `
C:\ProgramData\fairy-agent\migration  O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\migration\state.json  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\helper\helper.log  O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\update\installer.log  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\update\result.json  O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\logs\agent.log  O:SYG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
C:\ProgramData\fairy-agent\state\pairing.json  O:S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563G:S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;S-1-5-80-2776773523-1070830605-2554773251-1415194215-791193563)
`

// driveFS shows a fakeFS's temporary folder as a drive: "/" is C:\ itself, so the folder that stands for the
// drive root is the last one of every walk upwards and is judged as a drive root, as on the PC.
type driveFS struct {
	fs   *fakeFS
	root string
}

func (d driveFS) real(p string) string            { return filepath.Join(d.root, p) }
func (d driveFS) Stat(p string) (secObj, error)   { return d.fs.Stat(d.real(p)) }
func (d driveFS) List(p string) ([]string, error) { return d.fs.List(d.real(p)) }
func (d driveFS) Mkdir(p, sddl string) error      { return d.fs.Mkdir(d.real(p), sddl) }
func (d driveFS) Secure(p, sddl string) error     { return d.fs.Secure(d.real(p), sddl) }
func (d driveFS) SetOwner(p string) error         { return d.fs.SetOwner(d.real(p)) }
func (d driveFS) Move(from, to string) error      { return d.fs.Move(d.real(from), d.real(to)) }
func (d driveFS) Stamp() string                   { return d.fs.Stamp() }
func (d driveFS) Remove(p string) error           { return d.fs.Remove(d.real(p)) }
func (d driveFS) Rewrite(p string) error          { return d.fs.Rewrite(d.real(p)) }
func (d driveFS) Elevate() func()                 { return d.fs.Elevate() }
func (d driveFS) put(path, sddl string)           { d.fs.sddl[d.real(path)] = sddl }
func (d driveFS) with(path, entry string) (old string) {
	old = d.fs.sddl[d.real(path)]
	d.fs.sddl[d.real(path)] = old + entry
	return old
}

const realCfg = "/ProgramData/fairy-agent/config.yaml"

// realPC builds one of the PCs: every path of the fixture exists (a folder unless it has a file's name), with
// exactly the security that was read.
func realPC(t *testing.T, fixture string) driveFS {
	t.Helper()
	d := driveFS{fs: newFakeFS(t), root: t.TempDir()}
	d.fs.dataDir = d.real("/ProgramData/fairy-agent")
	files := map[string]bool{"config.yaml": true, "token": true, "control-token": true}
	n := 0
	for _, line := range strings.Split(fixture+realPCAssumed, "\n") {
		if line == "" {
			continue
		}
		win, sddl, ok := strings.Cut(line, "  ")
		if !ok || !strings.HasPrefix(win, `C:\`) {
			t.Fatalf("fixture line %q", line)
		}
		if strings.Contains(sddl, "S-1-5-21-") && !strings.Contains(sddl, "S-1-5-21-100000000") {
			t.Fatalf("a real machine identifier is in the fixture: %s", win)
		}
		p := "/" + strings.ReplaceAll(strings.TrimPrefix(win, `C:\`), `\`, "/")
		base := filepath.Base(p)
		if files[base] || strings.Contains(base, ".") {
			if err := os.WriteFile(d.real(p), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		} else if err := os.MkdirAll(d.real(p), 0o755); err != nil {
			t.Fatal(err)
		}
		parseSDDL(t, sddl) // every entry is one the reader knows
		d.put(p, sddl)
		n++
	}
	if n != 11+7 {
		t.Fatalf("%d fixture lines", n)
	}
	// nothing takes a made-up default: every object below the drive root is in the table
	_ = filepath.WalkDir(d.root, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := d.fs.sddl[p]; !ok {
			t.Fatalf("%s has no security in the fixture", p)
		}
		return nil
	})
	return d
}

var realPCs = map[string]string{"PC 1 (drive root: SYSTEM, Authenticated Users Modify)": realPC1, "PC 2 (stock drive root: TrustedInstaller)": realPC2}

// Every check on an existing install accepts both PCs, and the repair changes nothing on them.
func TestRealPCsAreAcceptedAsTheyAre(t *testing.T) {
	for name, fixture := range realPCs {
		d := realPC(t, fixture)

		// the read-only check, as each caller makes it: join, the typed commands, the helper before it reads
		// config.yaml (no folder named); the updater service and apply-update (update\); and both with helper\
		for _, also := range [][]string{nil, {"update"}, {"update", "helper"}, {"logs", "state", "update/stage", "migration"}} {
			if err := checkDataDir(d, realCfg, realSvc, also...); err != nil {
				t.Errorf("%s: checkDataDir%v refuses a healthy PC: %v", name, also, err)
			}
		}
		// the folders above, each on its own: the drive root is judged as a drive root
		if err := checkAncestors(d, "/ProgramData/fairy-agent"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		// every single object: nothing about it is held against it, not even "someone else may read it"
		for p, sddl := range d.fs.sddl {
			rel := relOf(d.fs.dataDir, p)
			if strings.HasPrefix(rel, "..") {
				continue // the drive root and C:\ProgramData: Windows' own, judged by checkAncestors
			}
			if rel == "." {
				rel = ""
			}
			o, err := d.fs.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			agentZone, zoneRoot := zoneOf(rel)
			if lv, why := judge(o, o.Dir, agentZone, zoneRoot, realSvc); lv != lvOK {
				t.Errorf("%s: %s %s (%s)", name, rel, why, sddl)
			}
			// Fairy's own folders have exactly the security the installer would give them
			if spec, known := knownFolder(rel, realSvc); o.Dir && (known || rel == "") {
				if rel == "" {
					spec = folderSpec{realSvc, false}
				}
				if !spec.matches(o) {
					t.Errorf("%s: %s is not taken as it is (%s)", name, rel, sddl)
				}
			}
		}

		// the installer's repair (install, setup-self-update): twice, and nothing is done either time
		for run := 1; run <= 2; run++ {
			rep, err := repairDataDir(d, realCfg, realSvc)
			if err != nil {
				t.Fatalf("%s: repair run %d: %v", name, run, err)
			}
			if len(d.fs.calls) != 0 || len(rep.Notes) != 0 || rep.Created || rep.Replaced != "" || rep.ConfigAside || rep.RootLeak ||
				len(rep.Leaked) != 0 || len(rep.Aside) != 0 || len(rep.Zones) != 0 {
				t.Errorf("%s: repair run %d changed a healthy PC: calls %v, report %+v", name, run, d.fs.calls, rep)
			}
		}
		// the single folders other commands make sure of (join: state\; setup-self-update: update\,
		// update\stage, state\; the self-migration: the data folder, logs\, helper\, migration\)
		fo := folders{fs: d, hint: repairHint}
		for _, rel := range []string{"", "logs", "helper", "update", "update/stage", "state", "migration"} {
			spec := folderSpec{realSvc, false}
			if rel != "" {
				spec, _ = knownFolder(rel, realSvc)
			}
			if err := fo.ensure(filepath.Join("/ProgramData/fairy-agent", filepath.FromSlash(rel)), spec); err != nil {
				t.Errorf("%s: ensure %q: %v", name, rel, err)
			}
		}
		if len(d.fs.calls) != 0 {
			t.Errorf("%s: making sure of the folders changed something: %v", name, d.fs.calls)
		}
	}
}

// The other direction: the same PCs with one entry added that lets ordinary users in. The check refuses, for
// every caller, and the repair does not keep what it cannot trust.
func TestRealPCsWithOneEntryForOthersAreRefused(t *testing.T) {
	const dir = "/ProgramData/fairy-agent"
	entries := map[string]string{
		"Users may modify (passed on to everything inside)": "(A;OICI;0x1301bf;;;BU)",
		"Authenticated Users have full control":             "(A;;FA;;;AU)",
		"Users may modify what is created from now on":      "(A;OICIIO;0x1301bf;;;BU)",
	}
	for name, fixture := range realPCs {
		for what, entry := range entries {
			for _, target := range []string{dir, realCfg, dir + "/token"} {
				if target != dir && strings.Contains(entry, "IO") {
					continue // an entry that only passes on means nothing on a file
				}
				d := realPC(t, fixture)
				d.with(target, entry)
				for _, also := range [][]string{nil, {"update"}, {"update", "helper"}} {
					err := checkDataDir(d, realCfg, realSvc, also...)
					if err == nil {
						t.Errorf("%s, %s on %s: checkDataDir%v accepts it", name, what, target, also)
					} else if !strings.Contains(err.Error(), "S-1-5-32-545") && !strings.Contains(err.Error(), "S-1-5-11") {
						t.Errorf("%s, %s on %s: refused without naming the account: %v", name, what, target, err)
					}
				}
				rep, err := repairDataDir(d, realCfg, realSvc)
				if err != nil {
					t.Fatalf("%s, %s on %s: %v", name, what, target, err)
				}
				switch {
				case target == dir && rep.Replaced == "":
					t.Errorf("%s, %s: the data folder was kept: %+v", name, what, rep)
				case target == realCfg && !rep.ConfigAside:
					t.Errorf("%s, %s: config.yaml was kept: %+v", name, what, rep)
				case target != dir && len(rep.Aside) != 1:
					t.Errorf("%s, %s on %s: moved aside: %v", name, what, target, rep.Aside)
				}
				if err := checkDataDir(d, realCfg, realSvc); err != nil {
					t.Errorf("%s, %s on %s: not safe after the repair: %v", name, what, target, err)
				}
			}
		}
		// the same in one of the agent's own folders and in helper\: the folder is not taken as it is
		for _, rel := range []string{"helper", "update", "state", "logs", "update/stage"} {
			d := realPC(t, fixture)
			d.with(dir+"/"+rel, "(A;OICI;0x1301bf;;;BU)")
			if err := checkDataDir(d, realCfg, realSvc, rel); err == nil {
				t.Errorf("%s: %s with an entry for Users passes", name, rel)
			}
			if rep, err := repairDataDir(d, realCfg, realSvc); err != nil || len(d.fs.calls) == 0 {
				t.Errorf("%s: %s with an entry for Users: the repair did nothing (%v, %+v)", name, rel, err, rep)
			}
		}
		// and a folder above: Users may delete or rename what is in C:\ProgramData
		d := realPC(t, fixture)
		d.with("/ProgramData", "(A;;0x1301ff;;;BU)")
		if err := checkDataDir(d, realCfg, realSvc); err == nil {
			t.Errorf("%s: C:\\ProgramData with delete-child for Users passes", name)
		}
		if _, err := repairDataDir(d, realCfg, realSvc); err == nil || len(d.fs.calls) != 0 {
			t.Errorf("%s: the repair built on a C:\\ProgramData others can change: %v %v", name, err, d.fs.calls)
		}
	}
}
