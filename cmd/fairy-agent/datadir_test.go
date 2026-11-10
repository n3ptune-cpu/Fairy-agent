package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// The decision for one object, against real permission lists.
func TestJudge(t *testing.T) {
	type zone struct{ agent, root bool }
	admin, agentRoot, inAgent := zone{}, zone{true, true}, zone{true, false}
	cases := []struct {
		name    string
		sddl    string
		dir     bool // what the object is
		wantDir bool
		z       zone
		want    level
		why     string
	}{
		// what a healthy installation looks like: all of it is trusted
		{"the data folder as install makes it", sddlDataDir, true, true, admin, lvOK, ""},
		{"config.yaml / token, everything inherited", sddlDataFile, false, false, admin, lvOK, ""},
		{"logs\\", sddlAgentDir, true, true, agentRoot, lvOK, ""},
		{"agent.log, made by the agent's account", sddlAgentFile, false, false, inAgent, lvOK, ""},
		{"a log from before 0.5 (LocalService)", sddlLocalServiceFile, false, false, inAgent, lvOK, ""},
		{"owner SYSTEM (made by the updater or the helper)", strings.Replace(sddlDataFile, "O:BA", "O:SY", 1), false, false, admin, lvOK, ""},
		{"owner TrustedInstaller", strings.Replace(sddlDataDir, "O:BA", "O:"+tTI, 1), true, true, admin, lvOK, ""},
		{"the secrets file (secret set): its own protected list", "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;" + tSvc + ")", false, false, admin, lvOK, ""},
		{"a deny entry takes rights away only", "O:BAD:PAI(D;OICI;FA;;;BU)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", true, true, admin, lvOK, ""},

		// H1: prepared by another account before the installation
		{"a folder an ordinary user made under C:\\ProgramData", sddlUserMadeDir, true, true, admin, lvForeign, "owned by " + tUser},
		{"the same after the old installer reset its permissions", sddlUserOwnedReset, true, true, admin, lvForeign, "owned by " + tUser},
		{"a planted file with its own permissions", sddlPlantedFile, false, false, admin, lvForeign, tUser},
		{"a planted file that only inherits", sddlPlantedInherits, false, false, admin, lvForeign, "owned by " + tUser},
		{"planted pairing state in state\\", sddlPlantedInherits, false, false, inAgent, lvForeign, "owned by " + tUser},
		// H1b: the folder as plain mkdir leaves it under C:\ProgramData (Users may add files)
		{"an administrator's mkdir, permissions inherited", sddlAdminMkdir, true, true, admin, lvForeign, "S-1-5-32-545"},
		{"C:\\ProgramData itself would not do as the data folder", sddlProgramData, true, true, admin, lvForeign, "S-1-5-32-545"},
		// Windows' own folders, for comparison: nobody but administrators changes them, Users read them
		{"C:\\Program Files as a data folder: readable by Users", sddlProgramFiles, true, true, admin, lvLeak, "S-1-5-32-545"},
		{"System32 the same", sddlSystem32, true, true, admin, lvLeak, "read by"},
		{"C:\\ as a data folder: Authenticated Users may add folders", sddlCRoot, true, true, admin, lvForeign, "S-1-5-11"},

		// the agent's own account where it should only read (L2: a compromised agent)
		{"update\\ as 0.3 - 0.4.2 made it (the service may write)", sddlAgentDir, true, true, admin, lvAgent, "agent's own account"},
		{"a file the agent's account owns outside its folders", sddlAgentFile, false, false, admin, lvAgent, "owned by the agent's own account"},
		{"a LocalService file outside the agent's folders", sddlLocalServiceFile, false, false, admin, lvAgent, "S-1-5-19"},
		{"one of the agent's folders, owned by the agent's account", strings.Replace(sddlAgentDir, "O:BA", "O:"+tSvc, 1), true, true, agentRoot, lvAgent, "owned by the agent's own account"},

		// someone else may read (does not let them steer anything, but tokens would be known)
		{"read access given by hand", sddlHandRead, false, false, admin, lvLeak, "read by " + tUser},
		{"Users may read", "O:BAD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)", false, false, admin, lvLeak, "S-1-5-32-545"},
		{"read access for others in the agent's folder", "O:" + tSvc + "D:AI(A;;FR;;;BU)(A;ID;FA;;;SY)(A;ID;0x1301bf;;;" + tSvc + ")", false, false, inAgent, lvLeak, "S-1-5-32-545"},

		// single rights that change the object, each for someone else
		{"write data", "O:BAD:(A;;FA;;;SY)(A;;DC;;;BU)", false, false, admin, lvForeign, "S-1-5-32-545"},
		{"append", "O:BAD:(A;;FA;;;SY)(A;;LC;;;BU)", false, false, admin, lvForeign, ""},
		{"delete", "O:BAD:(A;;FA;;;SY)(A;;SD;;;BU)", false, false, admin, lvForeign, ""},
		{"delete what is inside", "O:BAD:(A;;FA;;;SY)(A;;DT;;;BU)", true, true, admin, lvForeign, ""},
		{"change permissions", "O:BAD:(A;;FA;;;SY)(A;;WD;;;BU)", false, false, admin, lvForeign, ""},
		{"take ownership", "O:BAD:(A;;FA;;;SY)(A;;WO;;;BU)", false, false, admin, lvForeign, ""},
		{"GENERIC_WRITE", "O:BAD:(A;;FA;;;SY)(A;;GW;;;BU)", false, false, admin, lvForeign, ""},
		{"GENERIC_ALL for Everyone", "O:BAD:(A;;FA;;;SY)(A;;GA;;;WD)", true, true, admin, lvForeign, "S-1-1-0"},
		{"a deny entry does not make an allow entry safe", "O:BAD:(D;;FA;;;BU)(A;;FA;;;SY)(A;;0x1301bf;;;BU)", false, false, admin, lvForeign, ""},
		{"OWNER RIGHTS", "O:BAD:(A;;FA;;;SY)(A;;0x1301bf;;;OW)", false, false, admin, lvForeign, "S-1-3-4"},
		{"CREATOR OWNER that applies to the object", "O:BAD:(A;;FA;;;SY)(A;;GA;;;CO)", true, true, admin, lvForeign, "S-1-3-0"},
		{"an object entry", "O:BAD:(A;;FA;;;SY)(OA;;FA;;;BU)", false, false, admin, lvForeign, ""},
		{"an entry kind the check does not know", "O:BAD:(A;;FA;;;SY)(AU;;FA;;;BU)", false, false, admin, lvForeign, "cannot be read"},
		{"no permissions at all", "O:BAD:NO_ACCESS_CONTROL", false, false, admin, lvForeign, "everyone"},
		{"no owner", "D:(A;;FA;;;SY)", false, false, admin, lvForeign, "owned by"},
		{"the agent's entry of another PC's service", "O:BAD:(A;;FA;;;SY)(A;;0x1301bf;;;S-1-5-80-1-2-3-4-5)", false, false, inAgent, lvForeign, "S-1-5-80-1-2-3-4-5"},

		// N8: an entry that only passes on to what is created in the folder (inherit-only) counts for Fairy's
		// own folders: the files written there from now on would be that account's
		{"full control passed on to Users", sddlDataDir + "(A;OICIIO;FA;;;BU)", true, true, admin, lvForeign, "change everything that is created in it"},
		{"GENERIC_ALL passed on to Authenticated Users", "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;AU)", true, true, admin, lvForeign, "S-1-5-11"},
		{"read passed on to Users", sddlDataDir + "(A;OICIIO;GXGR;;;BU)", true, true, admin, lvLeak, "read everything that is created in it"},
		{"write passed on to the agent's account, outside its folders", sddlDataDir + "(A;OICIIO;GW;;;" + tSvc + ")", true, true, admin, lvAgent, "agent's own account"},
		{"the same in one of its folders", sddlAgentDir + "(A;OICIIO;GA;;;" + tSvc + ")", true, true, agentRoot, lvOK, ""},
		{"passed on to Users in one of the agent's folders", sddlAgentDir + "(A;OICIIO;FA;;;BU)", true, true, agentRoot, lvForeign, "S-1-5-32-545"},
		{"CREATOR OWNER passed on: the creator's own", sddlDataDir + "(A;OICIIO;GA;;;CO)", true, true, admin, lvOK, ""},
		{"passed on to SYSTEM", sddlDataDir + "(A;OICIIO;GA;;;SY)", true, true, admin, lvOK, ""},
		{"a deny entry that passes on", sddlDataDir + "(D;OICIIO;GA;;;BU)", true, true, admin, lvOK, ""},

		// the wrong kind of thing
		{"a folder named config.yaml", sddlDataDir, true, false, admin, lvForeign, "folder where a file belongs"},
		{"a file named logs", sddlDataFile, false, true, agentRoot, lvForeign, "file where a folder belongs"},
	}
	for _, c := range cases {
		o := parseSDDL(t, c.sddl)
		o.Dir, o.Links = c.dir, 1
		lv, why := judge(o, c.wantDir, c.z.agent, c.z.root, tSvc)
		if lv != c.want || !strings.Contains(why, c.why) {
			t.Errorf("%s: level %d (%s), want level %d with %q", c.name, lv, why, c.want, c.why)
		}
	}
	// links and second names are never trusted, whoever owns them
	link := fileObj(t, sddlDataFile)
	link.Reparse = true
	if lv, why := judge(link, false, false, false, tSvc); lv != lvForeign || !strings.Contains(why, "link") {
		t.Error("a link:", lv, why)
	}
	junction := dirObj(t, sddlAgentDir)
	junction.Reparse = true
	if lv, _ := judge(junction, true, true, true, tSvc); lv != lvForeign {
		t.Error("a junction as logs\\:", lv)
	}
	two := fileObj(t, sddlDataFile)
	two.Links = 2
	if lv, why := judge(two, false, false, false, tSvc); lv != lvForeign || !strings.Contains(why, "more than one name") {
		t.Error("a hard link:", lv, why)
	}
	// without the service (its SID is unknown) its entries are a stranger's
	if lv, _ := judge(dirObj(t, sddlAgentDir), true, true, true, ""); lv != lvForeign {
		t.Error("the agent's entry trusted although the service does not exist")
	}
	if lv, _ := judge(dirObj(t, sddlDataDir), true, false, false, ""); lv != lvLeak { // its read-only entry: a stranger who can read
		t.Error("read entry of an unknown service:", lv)
	}
}

func TestZoneOf(t *testing.T) {
	for rel, want := range map[string][2]bool{
		"": {false, false}, "config.yaml": {false, false}, "helper": {false, false}, "update": {false, false},
		"update/result.json": {false, false}, "migration/state.json": {false, false}, "logsx": {false, false},
		"logs": {true, true}, "Logs": {true, true}, "STATE": {true, true}, "update/stage": {true, true}, "Update/Stage": {true, true},
		"logs/agent.log": {true, false}, "state/pairing.json": {true, false}, "update/stage/x/y": {true, false},
	} {
		if a, r := zoneOf(rel); a != want[0] || r != want[1] {
			t.Errorf("%q: %v %v", rel, a, r)
		}
	}
}

// The security Fairy sets on its folders: the SDDL handed to Windows and the list it is compared with are the
// same thing, and they are exactly what the installer has set since 0.1 (so a healthy PC is not written to).
func TestFolderSpec(t *testing.T) {
	read, write := folderSpec{tSvc, false}, folderSpec{tSvc, true}
	if got := read.sddl(); got != "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+tSvc+")" {
		t.Fatal(got)
	}
	if got := write.sddl(); got != "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;"+tSvc+")" {
		t.Fatal(got)
	}
	for _, s := range []folderSpec{read, write, {"", false}} {
		o := dirObj(t, s.sddl())
		if len(o.ACEs) != len(s.aces()) || !s.matches(o) || !o.Protected || o.Owner != sidAdmins {
			t.Errorf("%+v: sddl() and aces() differ: %+v", s, o)
		}
		if lv, why := judge(o, true, s.write, true, s.agentSID); lv != lvOK {
			t.Errorf("%+v does not pass its own check: %s", s, why)
		}
	}
	if !read.matches(dirObj(t, sddlDataDir)) || !write.matches(dirObj(t, sddlAgentDir)) {
		t.Fatal("the folders of an installed PC do not match: they would be rewritten on every run")
	}
	for name, s := range map[string]string{
		"the other mask":       sddlAgentDir,
		"inherits from above":  strings.Replace(sddlDataDir, "D:PAI", "D:AI", 1),
		"owner SYSTEM":         strings.Replace(sddlDataDir, "O:BA", "O:SY", 1),
		"owner a user":         sddlUserOwnedReset,
		"one entry more":       sddlDataDir + "(A;;FR;;;BU)",
		"one entry less":       "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		"not passed on":        strings.Replace(sddlDataDir, "(A;OICI;0x1200a9", "(A;;0x1200a9", 1),
		"another service":      strings.Replace(sddlDataDir, tSvc, "S-1-5-80-1-2-3-4-5", 1),
		"the same entry twice": "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;" + tSvc + ")",
		"no permissions":       "O:BAD:NO_ACCESS_CONTROL",
	} {
		if read.matches(dirObj(t, s)) {
			t.Errorf("%s: matches", name)
		}
	}
	if read.matches(fileObj(t, sddlDataDir)) {
		t.Error("a file matches a folder's spec")
	}
}

// The folders above the data folder are Windows' own. Only rights that could replace the path count; a drive's
// root cannot be deleted or renamed. Real lists, among them the PC an earlier release refused by mistake.
func TestCheckAncestors(t *testing.T) {
	const dir = "/ProgramData/fairy-agent"
	ok := map[string]string{
		"stock C:\\":            sddlCRoot,
		"C:\\ after an upgrade": sddlCRootMapped,
		"C:\\ with Modify for Authenticated Users": sddlCRootModify,
	}
	for name, root := range ok {
		fs := memFS{"/": dirObj(t, root), "/ProgramData": dirObj(t, sddlProgramData)}
		if err := checkAncestors(fs, dir); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	// a data folder under C:\Program Files (another --config): the same rules
	fs := memFS{"/": dirObj(t, sddlCRoot), "/Program Files": dirObj(t, sddlProgramFiles), "/Program Files/Fairy": dirObj(t, sddlDataDir)}
	if err := checkAncestors(fs, "/Program Files/Fairy/data"); err != nil {
		t.Error(err)
	}
	bad := []struct {
		name, root, pd, want string
	}{
		{"C:\\ProgramData owned by a user", sddlCRoot, strings.Replace(sddlProgramData, "O:SY", "O:"+tUser, 1), "owned by " + tUser},
		{"Users may delete what is in C:\\ProgramData", sddlCRoot, sddlProgramData + "(A;;DT;;;BU)", "S-1-5-32-545"},
		{"Users may delete or rename C:\\ProgramData", sddlCRoot, sddlProgramData + "(A;;SD;;;BU)", "S-1-5-32-545"},
		{"Modify on C:\\ProgramData for Authenticated Users", sddlCRoot, sddlCRootModify, "S-1-5-11"},
		{"Everyone full control on C:\\", "O:SYD:PAI(A;OICI;FA;;;WD)", sddlProgramData, "S-1-1-0"},
		{"Users may change the permissions of C:\\", sddlCRootMapped + "(A;;WD;;;BU)", sddlProgramData, "S-1-5-32-545"},
		{"C:\\ProgramData without permissions", sddlCRoot, "O:SYD:NO_ACCESS_CONTROL", "no permissions"},
	}
	for _, c := range bad {
		fs := memFS{"/": dirObj(t, c.root), "/ProgramData": dirObj(t, c.pd)}
		if err := checkAncestors(fs, dir); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := checkAncestors(memFS{"/": dirObj(t, sddlCRoot)}, dir); err == nil { // cannot be read
		t.Error("a folder above that cannot be read was accepted")
	}
	if err := checkAncestors(memFS{"/": dirObj(t, sddlCRoot), "/ProgramData": fileObj(t, sddlDataFile)}, dir); err == nil {
		t.Error("a file as C:\\ProgramData was accepted")
	}
}

// run is what `fairy-agent install` and `setup-self-update` do with the data folder.
func (p *pc) run(t *testing.T) (dirReport, string, error) {
	t.Helper()
	rep, err := repairDataDir(p.fs, p.cfgPath, tSvc)
	if err != nil {
		return rep, "", err
	}
	if p.fs.elevations != 0 {
		t.Error("the extra privileges were left switched on")
	}
	var out bytes.Buffer
	if err := fillDataDir(p.cfgPath, rep, &out); err != nil {
		t.Fatal(err)
	}
	return rep, out.String(), nil
}

// usable: after install the folder passes the check the updater, the helper and join make, and holds a config
// and two different tokens.
func (p *pc) usable(t *testing.T) (token, control string) {
	t.Helper()
	if err := checkDataDir(p.fs, p.cfgPath, tSvc, "update", "helper"); err != nil {
		t.Fatalf("the repaired folder does not pass the check: %v", err)
	}
	for _, f := range dataFolders {
		path := filepath.Join(p.dir, filepath.FromSlash(f.rel))
		o, err := p.fs.Stat(path)
		if err != nil || !(folderSpec{tSvc, f.write}).matches(o) {
			t.Fatalf("%s: %+v %v", f.rel, o, err)
		}
	}
	if o, _ := p.fs.Stat(p.dir); !(folderSpec{tSvc, false}).matches(o) {
		t.Fatalf("the data folder: %+v", o)
	}
	cfg, err := agent.Load(p.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := cfg.LoadTokens()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(p.read(t, "token")), strings.TrimSpace(p.read(t, "control-token")) + tok.Control
}

// H1b: on a clean PC every folder is created with its final permissions in the create call; nothing is set
// afterwards, so there is no moment with the permissions C:\ProgramData would hand down.
func TestInstallOnACleanPC(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	p := newPC(t)
	rep, out, err := p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Created || rep.Replaced != "" || len(rep.Aside) != 0 || len(rep.Notes) != 0 {
		t.Fatalf("%+v", rep)
	}
	if got := p.fs.did("mkdir"); len(got) != 6 || got[0] != p.dir {
		t.Fatalf("created: %v", got)
	}
	if n := len(p.fs.did("secure")) + len(p.fs.did("setowner")) + len(p.fs.did("move")) + len(p.fs.did("remove")) + len(p.fs.did("rewrite")); n != 0 {
		t.Fatalf("something was changed after it was created: %v", p.fs.calls)
	}
	tok, _ := p.usable(t)
	if len(tok) < agent.MinTokenLen || !strings.Contains(out, "wrote a starter") || strings.Count(out, "created") != 2 ||
		strings.Contains(out, "IMPORTANT") || strings.Contains(out, tok) {
		t.Fatalf("output:\n%s", out)
	}
	if cfg, _ := agent.Load(p.cfgPath); cfg.ControlEnabled() {
		t.Fatal("the starter config switches something on")
	}

	// a second run (install ends with setup-self-update, which checks again): nothing at all is touched
	p.fs.calls = nil
	before := p.read(t, "token")
	rep, out, err = p.run(t)
	if err != nil || len(p.fs.calls) != 0 || rep.Created || out != "" || p.read(t, "token") != before {
		t.Fatalf("second run: %v %v %q", err, p.fs.calls, out)
	}

	// if the create call does not apply the security it is given, the folder still ends up right
	p2 := newPC(t)
	p2.fs.mkdirIgnoresSecurity = true
	if _, _, err := p2.run(t); err != nil {
		t.Fatal(err)
	}
	p2.usable(t)
	if len(p2.fs.did("secure")) != 6 {
		t.Fatalf("%v", p2.fs.calls)
	}
}

// Compatibility: a healthy, paired PC (as 0.5.3 left it) is not changed by a re-install or by
// setup-self-update. Config, tokens, logs and the pairing state stay byte for byte; nothing is written.
func TestReinstallOnAHealthyPCChangesNothing(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	if err := checkDataDir(p.fs, p.cfgPath, tSvc, "update", "helper"); err != nil { // the new binary alone
		t.Fatalf("a healthy PC fails the check the new updater and helper make: %v", err)
	}
	before := map[string]string{}
	for _, f := range []string{"config.yaml", "token", "control-token", "logs/agent.log", "state/pairing.json", "update/result.json", "migration/state.json"} {
		before[f] = p.read(t, f)
	}
	for i := 0; i < 2; i++ {
		rep, out, err := p.run(t)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.fs.calls) != 0 || len(rep.Notes) != 0 || rep.Created || out != "" {
			t.Fatalf("run %d changed a healthy PC: %v %v %q", i, p.fs.calls, rep.Notes, out)
		}
	}
	for f, want := range before {
		if got := p.read(t, f); got != want {
			t.Errorf("%s changed", f)
		}
	}
	// what earlier versions and other accounts of Fairy's own left behind does not unpair the PC either
	p.put(t, "logs/agent.log.1", sddlLocalServiceFile, "from 0.4\n")                              // kept
	p.put(t, "update/result.json", sddlLocalServiceFile, "{}")                                    // the old in-service updater's: moved aside
	p.fs.sddl[filepath.Join(p.dir, "state")] = strings.Replace(sddlAgentDir, "O:BA", "O:SY", 1)   // made by a LocalSystem agent
	p.fs.sddl[filepath.Join(p.dir, "logs")] = strings.Replace(sddlAgentDir, "O:BA", "O:"+tSvc, 1) // owned by the agent's account
	rep, out, err := p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "IMPORTANT") || strings.Contains(out, "token") || rep.ConfigAside || rep.Replaced != "" {
		t.Fatalf("leftovers of Fairy's own unpaired the PC:\n%s", out)
	}
	if got := p.fs.did("move"); len(got) != 1 || !strings.HasSuffix(got[0], "result.json") {
		t.Fatalf("moved aside: %v", got)
	}
	// the two folders of the agent's own got Administrators as their owner, on the folder itself: nothing in
	// them was touched, and no permissions were set (Windows would pass those on into them)
	if got := p.fs.did("setowner"); len(got) != 2 || len(p.fs.did("secure")) != 0 {
		t.Fatalf("owner set on %v, permissions on %v", got, p.fs.did("secure"))
	}
	if p.read(t, "state/pairing.json") != before["state/pairing.json"] || p.read(t, "logs/agent.log") != before["logs/agent.log"] {
		t.Fatal("the content of the agent's folders was not kept")
	}
	if p.read(t, "logs/agent.log.1") != "from 0.4\n" || p.read(t, "token") != before["token"] || p.read(t, "config.yaml") != before["config.yaml"] {
		t.Fatal("something of the healthy PC was lost")
	}
	p.usable(t)
}

// H1, the audit's reproduction: another account prepared C:\ProgramData\fairy-agent before the first install,
// with a config.yaml that names token files elsewhere and switches power control on. Up to 0.5.3 install kept
// all of it. Now the folder is not used at all: it is moved aside as a whole, a new one is made, the config is
// a starter and the tokens are new.
func TestPreparedFolderIsReplaced(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	for name, rootSDDL := range map[string]string{"as the user made it": sddlUserMadeDir, "after the old installer's reset": sddlUserOwnedReset} {
		p := newPC(t)
		elsewhere := filepath.Join(p.root, "Users", "mallory", "got-the-token")
		if err := os.MkdirAll(filepath.Dir(elsewhere), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.WriteFile(elsewhere, []byte("untouched"), 0o644)
		p.put(t, "", rootSDDL, "")
		planted := "token_file: " + elsewhere + "\npower_control:\n  enabled: true\n  min_delay_s: 10\n"
		p.put(t, "config.yaml", sddlPlantedInherits, planted)
		p.put(t, "token", sddlPlantedFile, "a-token-the-planter-knows-0123456789\r\n")
		p.put(t, "control-token", sddlPlantedFile, "a-control-token-the-planter-knows-01\r\n")
		p.put(t, "state/", sddlUserMadeDir, "")
		p.put(t, "state/pairing.json", sddlPlantedFile, `{"panel":"127.0.0.1"}`)

		if err := checkDataDir(p.fs, p.cfgPath, tSvc); err == nil || !strings.Contains(err.Error(), "owned by "+tUser) {
			t.Fatalf("%s: the check passes a prepared folder: %v", name, err)
		}
		rep, out, err := p.run(t)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if rep.Replaced == "" || !strings.Contains(filepath.Base(rep.Replaced), "fairy-agent"+asideMark) || !strings.Contains(out, "IMPORTANT") ||
			!strings.Contains(out, "owned by "+tUser) || !strings.Contains(out, "wrote a starter") {
			t.Fatalf("%s: %+v\n%s", name, rep, out)
		}
		// nothing of the prepared folder is in use
		tok, ctl := p.usable(t)
		if strings.Contains(tok+ctl, "planter-knows") || p.read(t, "config.yaml") == planted {
			t.Fatalf("%s: planted content is in use", name)
		}
		cfg, _ := agent.Load(p.cfgPath)
		if cfg.ControlEnabled() || cfg.TokenFile != filepath.Join(p.dir, "token") {
			t.Fatalf("%s: the planted config is in effect: %+v", name, cfg.PowerControl)
		}
		if _, err := os.Stat(filepath.Join(p.dir, "state", "pairing.json")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: the planted pairing state is in use", name)
		}
		// it is all still there to look at, moved aside, and the file it pointed at was not written
		if b, _ := os.ReadFile(filepath.Join(rep.Replaced, "config.yaml")); string(b) != planted {
			t.Fatalf("%s: the old folder was not kept aside", name)
		}
		if b, _ := os.ReadFile(elsewhere); string(b) != "untouched" {
			t.Fatalf("%s: the file the planted config named was written: %q", name, b)
		}
		// the folder moved aside is not given new permissions (nothing is passed on into what was prepared)
		for _, s := range p.fs.did("secure") {
			if strings.Contains(s, asideMark) {
				t.Fatalf("%s: permissions set on %s", name, s)
			}
		}
		// the next run finds a healthy folder: tokens stay (no re-pairing on every install)
		p.fs.calls = nil
		tokBefore := p.read(t, "token")
		if _, out, err := p.run(t); err != nil || out != "" || len(p.fs.calls) != 0 || p.read(t, "token") != tokBefore {
			t.Fatalf("%s: second run: %v %q %v", name, err, out, p.fs.calls)
		}
	}
}

// H1 / H1b: the folder itself is fine, but things were put into it by someone else (in the gap of an older
// install, or by hand). Each is dealt with on its own; what was not touched by anyone else stays.
func TestPlantedThingsInAKeptFolder(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	p := newPC(t)
	p.installed(t)
	outside := filepath.Join(p.root, "Windows", "System32")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(outside, "keep.dll"), []byte("system"), 0o644)
	p.fs.sddl[outside] = sddlSystem32

	p.put(t, "control-token", sddlPlantedFile, "a-control-token-the-planter-knows-01\r\n") // replaced by the planter
	p.put(t, "state/pairing.json", sddlPlantedInherits, `{"panel":"127.0.0.1"}`)
	p.put(t, "secrets.env", sddlPlantedFile, "FAIRY_AGENT_TOKEN=chosen-by-the-planter\n")
	p.put(t, "helper/", sddlUserMadeDir, "") // the helper's folder belongs to the user
	p.put(t, "helper/helper.log", sddlPlantedFile, "x")
	p.put(t, "update/stage/fairy-agent-windows-amd64.exe", sddlPlantedFile, "MZ")
	p.put(t, "extra/", sddlUserMadeDir, "") // a folder Fairy does not know
	for _, l := range []string{"logs/link", "update/installer.log", "state/deep-link"} {
		lp := filepath.Join(p.dir, filepath.FromSlash(l))
		_ = os.Remove(lp)
		if err := os.Symlink(outside, lp); err != nil {
			t.Skip("no symbolic links here:", err)
		}
	}
	hard := p.put(t, "migration/state.json", sddlDataFile, `{"phase":"switched"}`) // a second name of some file
	p.fs.links[hard] = 2

	if err := checkDataDir(p.fs, p.cfgPath, tSvc); err == nil || !strings.Contains(err.Error(), "control-token") {
		t.Fatalf("the check passes a planted token file: %v", err)
	}
	tokBefore, cfgBefore := p.read(t, "token"), p.read(t, "config.yaml")
	rep, out, err := p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	gone := []string{"state/pairing.json", "secrets.env", "helper/helper.log", "update/stage/fairy-agent-windows-amd64.exe", "extra",
		"logs/link", "update/installer.log", "state/deep-link", "migration/state.json"}
	for _, g := range gone {
		if _, err := os.Lstat(filepath.Join(p.dir, filepath.FromSlash(g))); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s is still in place", g)
		}
	}
	// Where only administrators can change things, each planted thing is dealt with on its own: the link
	// update\installer.log is removed; control-token, secrets.env, helper\, extra\ and migration\state.json are
	// moved aside. The agent's own folders are never gone through like that: logs\, state\ and update\stage\
	// each hold something that does not belong there, so each is moved aside as a whole and made anew.
	if len(p.fs.did("remove")) != 1 || len(p.fs.did("move")) != 8 || len(rep.Zones) != 3 {
		t.Fatalf("removed %v\nmoved aside %v\nreplaced %v", p.fs.did("remove"), p.fs.did("move"), rep.Zones)
	}
	// everything moved aside is in one folder of this run, which only administrators can open
	asideAt := filepath.Join(p.dir, asideDir+p.fs.Stamp())
	if o, err := p.fs.Stat(asideAt); err != nil || !(folderSpec{}).matches(o) {
		t.Fatalf("%s: %+v %v", asideAt, o, err)
	}
	for _, to := range rep.Aside {
		if filepath.Dir(to) != asideAt {
			t.Errorf("moved aside to %s, not into %s", to, asideAt)
		}
	}
	// ... with what was in it, untouched: the old logs can still be read there
	if b, _ := os.ReadFile(filepath.Join(asideAt, "logs", "agent.log")); string(b) != "log\n" {
		t.Errorf("the old log is not in the folder moved aside: %q", b)
	}
	for _, z := range []string{"logs", "state", "update/stage"} {
		if ents, err := os.ReadDir(filepath.Join(p.dir, filepath.FromSlash(z))); err != nil || len(ents) != 0 {
			t.Errorf("%s was not made anew, empty: %v %v", z, ents, err)
		}
	}
	// links were removed, not followed: what they pointed to is as it was, with its permissions
	if b, _ := os.ReadFile(filepath.Join(outside, "keep.dll")); string(b) != "system" || p.fs.sddl[outside] != sddlSystem32 {
		t.Fatal("something a link pointed to was touched")
	}
	for _, s := range p.fs.did("secure") {
		if !strings.HasPrefix(s, p.dir+string(filepath.Separator)) && s != p.dir {
			t.Fatalf("permissions set outside the data folder: %s", s)
		}
	}
	// the token nobody else touched stays; only the planted one is new, and the administrator is told
	_, ctl := p.usable(t)
	if p.read(t, "token") != tokBefore || p.read(t, "config.yaml") != cfgBefore {
		t.Fatal("the read token or the config, which nobody else had touched, was changed")
	}
	if strings.Contains(ctl, "planter-knows") || !strings.Contains(out, "created "+filepath.Join(p.dir, "control-token")) ||
		!strings.Contains(out, "IMPORTANT: the tokens are new") || rep.ConfigAside || rep.Replaced != "" {
		t.Fatalf("%+v\n%s", rep, out)
	}
	if !strings.Contains(out, "was a link") || !strings.Contains(out, "more than one name") || !strings.Contains(out, "owned by "+tUser) {
		t.Fatalf("the administrator is not told what was found:\n%s", out)
	}
	// ... and what is gone with each of the agent's folders
	for _, want := range []string{"the old log files are in the moved folder", "Re-pair command is run on this PC again", "press Update in the panel again"} {
		if !strings.Contains(out, want) {
			t.Errorf("the output does not say %q:\n%s", want, out)
		}
	}
	// the next run finds nothing to do, and does not look into what was moved aside
	p.fs.calls = nil
	if _, out, err := p.run(t); err != nil || out != "" || len(p.fs.calls) != 0 {
		t.Fatalf("second run: %v %q %v", err, out, p.fs.calls)
	}
}

// A planted config.yaml in a folder that is otherwise fine is moved aside and replaced by a starter; the
// tokens next to it, which nobody else could touch, stay.
func TestPlantedConfigInAKeptFolder(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	planted := "power_control:\n  enabled: true\n  min_delay_s: 10\n"
	p.put(t, "config.yaml", sddlPlantedInherits, planted)
	tokBefore := p.read(t, "token")
	rep, out, err := p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.ConfigAside || !strings.Contains(out, "wrote a starter") || !strings.Contains(out, "IMPORTANT: config.yaml could not be trusted") {
		t.Fatalf("%+v\n%s", rep, out)
	}
	if cfg, _ := agent.Load(p.cfgPath); cfg == nil || cfg.ControlEnabled() {
		t.Fatal("the planted config is in effect")
	}
	if p.read(t, "token") != tokBefore {
		t.Fatal("the token was changed although only the config was planted")
	}
	p.usable(t)
}

// Someone else could read (not change) the folder or a token: the content is the administrator's and stays,
// the permissions are corrected, and exactly the tokens that could have been read are replaced.
func TestReadableByOthers(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	// one token file
	p := newPC(t)
	p.installed(t)
	p.put(t, "control-token", sddlHandRead, "control-token-of-the-paired-panel-012345\r\n")
	p.put(t, "config.yaml", sddlHandRead, "self_update:\n  enabled: true\n")
	if err := checkDataDir(p.fs, p.cfgPath, tSvc, "update"); err != nil { // reading does not steer anything: the updater goes on
		t.Fatalf("the check refuses a folder someone else can only read: %v", err)
	}
	tokBefore := p.read(t, "token")
	rep, out, err := p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.fs.did("rewrite"); len(got) != 2 || len(p.fs.did("move")) != 0 {
		t.Fatalf("%v", p.fs.calls)
	}
	if p.read(t, "config.yaml") != "self_update:\n  enabled: true\n" || rep.ConfigAside {
		t.Fatal("the config's content was lost")
	}
	if p.read(t, "token") != tokBefore || strings.Contains(p.read(t, "control-token"), "of-the-paired-panel") {
		t.Fatal("exactly the readable token must be new")
	}
	if !strings.Contains(out, "new token in "+filepath.Join(p.dir, "control-token")) || !strings.Contains(out, "IMPORTANT: the tokens are new") {
		t.Fatalf("output:\n%s", out)
	}
	p.usable(t)

	// the whole folder
	p = newPC(t)
	p.installed(t)
	p.fs.sddl[p.dir] = sddlDataDir + "(A;OICI;0x1200a9;;;BU)"
	rep, out, err = p.run(t)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.RootLeak || rep.Replaced != "" || strings.Count(out, "new token in") != 2 || p.read(t, "config.yaml") == "" ||
		strings.Contains(p.read(t, "token"), "of-the-paired-panel") {
		t.Fatalf("%+v\n%s", rep, out)
	}
	p.usable(t)
	// The data folder's permissions were set, and Windows passes them on to everything below. The agent's own
	// folders were not below it in that moment: each was moved out next to the data folder and put back, with
	// what is in it (the test file system fails the test if anything the agent's account can write is below).
	if got := p.fs.did("secure"); len(got) != 1 || got[0] != p.dir {
		t.Fatalf("permissions set on %v", got)
	}
	if len(p.fs.moves) != 6 || len(rep.Zones) != 0 || len(rep.Aside) != 0 {
		t.Fatalf("moves %v, replaced %v", p.fs.moves, rep.Zones)
	}
	for i, z := range []string{"logs", "state", "update/stage"} {
		away, back := p.fs.moves[i], p.fs.moves[len(p.fs.moves)-1-i]
		at := filepath.Join(p.dir, filepath.FromSlash(z))
		if away[0] != at || filepath.Dir(away[1]) != p.pd || !strings.Contains(away[1], parkMark) || back != [2]string{away[1], away[0]} {
			t.Errorf("%s: moved %v, back %v", z, away, back)
		}
	}
	if p.read(t, "logs/agent.log") != "log\n" || p.read(t, "state/pairing.json") != `{"closed":"paired"}` || p.read(t, "update/stage/request.json") != "{}" {
		t.Fatal("the agent's folders did not come back as they were")
	}
	if ents, _ := os.ReadDir(p.pd); len(ents) != 1 {
		t.Fatalf("something was left next to the data folder: %v", ents)
	}
}

// Only the standard folder is repaired by moving things. With another --config folder (say, someone's
// documents) the installer says what is wrong and moves nothing.
func TestOtherConfigFolderIsNotRepaired(t *testing.T) {
	p := newPC(t)
	other := filepath.Join(p.root, "Users", "me", "Documents")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	p.fs.sddl[other] = sddlUserMadeDir
	p.fs.sddl[filepath.Dir(other)] = sddlDataDir
	p.fs.sddl[filepath.Dir(filepath.Dir(other))] = sddlDataDir
	_ = os.WriteFile(filepath.Join(other, "thesis.docx"), []byte("x"), 0o644)
	_, err := repairDataDir(p.fs, filepath.Join(other, "config.yaml"), tSvc)
	if err == nil || !strings.Contains(err.Error(), "not the standard data folder") || len(p.fs.calls) != 0 {
		t.Fatalf("%v %v", err, p.fs.calls)
	}
	// a folder of another name that is fine in itself, with one foreign file and one link inside
	p.fs.sddl[other] = sddlDataDir
	p.fs.sddl[filepath.Join(other, "thesis.docx")] = sddlPlantedFile
	_, err = repairDataDir(p.fs, filepath.Join(other, "config.yaml"), tSvc)
	if err == nil || !strings.Contains(err.Error(), "thesis.docx") || len(p.fs.did("move")) != 0 {
		t.Fatalf("%v %v", err, p.fs.calls)
	}
	if b, _ := os.ReadFile(filepath.Join(other, "thesis.docx")); string(b) != "x" {
		t.Fatal("a file in another folder was moved")
	}
}

func TestRepairStopsWithAClearMessage(t *testing.T) {
	// the prepared folder cannot be moved (something keeps it open)
	p := newPC(t)
	p.put(t, "", sddlUserMadeDir, "")
	p.put(t, "config.yaml", sddlPlantedFile, "x: 1\n")
	p.fs.moveErr = errors.New("Access is denied.")
	_, err := repairDataDir(p.fs, p.cfgPath, tSvc)
	if err == nil || !strings.Contains(err.Error(), "Stop-Service") || !strings.Contains(err.Error(), "owned by "+tUser) {
		t.Fatal(err)
	}
	if len(p.fs.calls) != 0 || p.read(t, "config.yaml") != "x: 1\n" {
		t.Fatalf("something was changed although the folder could not be replaced: %v", p.fs.calls)
	}
	// the folders above are not safe: nothing is built there
	p = newPC(t)
	p.fs.sddl[p.pd] = strings.Replace(sddlProgramData, "O:SY", "O:"+tUser, 1)
	if _, err := repairDataDir(p.fs, p.cfgPath, tSvc); err == nil || !strings.Contains(err.Error(), "not safe to build on") || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
	// a link where the data folder should be
	p = newPC(t)
	target := t.TempDir()
	if err := os.Symlink(target, p.dir); err != nil {
		t.Skip(err)
	}
	p.fs.sddl[p.dir] = sddlDataDir
	rep, err := repairDataDir(p.fs, p.cfgPath, tSvc)
	if err != nil || rep.Replaced == "" {
		t.Fatal(rep, err)
	}
	if ents, _ := os.ReadDir(target); len(ents) != 0 {
		t.Fatalf("the installer wrote into what the link pointed to: %v", ents)
	}
	if st, _ := os.Lstat(p.dir); st == nil || !st.IsDir() {
		t.Fatal("no real data folder was made")
	}
}

// checkDataDir: what the updater, the helper, join and the agent's start-up warning rely on. It only looks.
func TestCheckDataDir(t *testing.T) {
	healthy := func() *pc { p := newPC(t); p.installed(t); return p }
	p := healthy()
	if err := checkDataDir(p.fs, p.cfgPath, tSvc, "update", "helper"); err != nil || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
	// nothing installed yet in a healthy folder (join right after install with a missing token) is fine too
	_ = os.Remove(filepath.Join(p.dir, "control-token"))
	if err := checkDataDir(p.fs, p.cfgPath, tSvc); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		make func(p *pc)
		also []string
		want string
	}{
		{"the folder belongs to a user", func(p *pc) { p.fs.sddl[p.dir] = sddlUserOwnedReset }, nil, "owned by " + tUser},
		{"a user may add files to the folder", func(p *pc) { p.fs.sddl[p.dir] = sddlAdminMkdir }, nil, "S-1-5-32-545"},
		{"the agent's account may write the folder", func(p *pc) { p.fs.sddl[p.dir] = sddlAgentDir }, nil, "agent's own account"},
		{"config.yaml belongs to a user", func(p *pc) { p.fs.sddl[p.cfgPath] = sddlPlantedInherits }, nil, "config.yaml is owned by " + tUser},
		{"config.yaml has a second name", func(p *pc) { p.fs.links[p.cfgPath] = 2 }, nil, "more than one name"},
		{"config.yaml is a link", func(p *pc) {
			_ = os.Remove(p.cfgPath)
			_ = os.Symlink(filepath.Join(p.root, "elsewhere.yaml"), p.cfgPath)
		}, nil, "is a link"},
		{"config.yaml is a folder", func(p *pc) { _ = os.Remove(p.cfgPath); _ = os.Mkdir(p.cfgPath, 0o755) }, nil, "folder where a file belongs"},
		{"the token can be changed by a user", func(p *pc) { p.fs.sddl[filepath.Join(p.dir, "token")] = sddlPlantedFile }, nil, "token"},
		{"the control token belongs to the agent's account", func(p *pc) { p.fs.sddl[filepath.Join(p.dir, "control-token")] = sddlAgentFile }, nil, "control-token"},
		{"update\\ is missing", func(p *pc) { _ = os.RemoveAll(filepath.Join(p.dir, "update")) }, []string{"update"}, "update"},
		{"update\\ is writable by the agent's account (0.4.2)", func(p *pc) { p.fs.sddl[filepath.Join(p.dir, "update")] = sddlAgentDir }, []string{"update"}, "agent's own account"},
		{"update\\ is a link", func(p *pc) {
			_ = os.RemoveAll(filepath.Join(p.dir, "update"))
			_ = os.Symlink(p.root, filepath.Join(p.dir, "update"))
		}, []string{"update"}, "is a link"},
		{"helper\\ belongs to a user", func(p *pc) { p.fs.sddl[filepath.Join(p.dir, "helper")] = sddlUserMadeDir }, []string{"helper"}, "owned by " + tUser},
		{"C:\\ProgramData can be replaced", func(p *pc) { p.fs.sddl[p.pd] = sddlProgramData + "(A;;SD;;;BU)" }, nil, "ProgramData"},
	}
	for _, c := range cases {
		p := healthy()
		c.make(p)
		err := checkDataDir(p.fs, p.cfgPath, tSvc, c.also...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.name, err)
		}
		if len(p.fs.calls) != 0 {
			t.Errorf("%s: the check changed something: %v", c.name, p.fs.calls)
		}
	}
	// not reasons to refuse: someone can read; things in the agent's own folders; a folder that is not asked for
	for name, mk := range map[string]func(p *pc){
		"a token someone else can read":      func(p *pc) { p.fs.sddl[filepath.Join(p.dir, "token")] = sddlHandRead },
		"the folder readable by Users":       func(p *pc) { p.fs.sddl[p.dir] = sddlDataDir + "(A;OICI;0x1200a9;;;BU)" },
		"a planted file in logs\\":           func(p *pc) { p.put(t, "logs/x", sddlPlantedFile, "x") },
		"update\\ in a bad state, not asked": func(p *pc) { p.fs.sddl[filepath.Join(p.dir, "update")] = sddlUserMadeDir },
		"token files named elsewhere by a config only administrators can change": func(p *pc) {
			out := filepath.Join(p.root, "secrets")
			_ = os.Mkdir(out, 0o755)
			_ = os.WriteFile(filepath.Join(out, "t"), []byte("x"), 0o644)
			p.fs.sddl[filepath.Join(out, "t")] = sddlPlantedFile
			p.put(t, "config.yaml", sddlDataFile, "token_file: "+filepath.Join(out, "t")+"\n")
		},
	} {
		p := healthy()
		mk(p)
		if err := checkDataDir(p.fs, p.cfgPath, tSvc); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// One of Fairy's folders (the migration's, the state folder for join, update\ and its stage): made with its
// permissions when missing, corrected on the opened folder as far as that is safe, refused when it is not
// Fairy's own.
func TestEnsureFolder(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	f := folders{fs: p.fs, hint: repairHint}
	state := filepath.Join(p.dir, "state")
	write, read := folderSpec{tSvc, true}, folderSpec{tSvc, false}

	if err := f.ensure(state, write); err != nil || len(p.fs.calls) != 0 { // as it should be: nothing written
		t.Fatal(err, p.fs.calls)
	}
	pairing := p.read(t, "state/pairing.json")
	_ = os.RemoveAll(state)
	delete(p.fs.sddl, state)
	if err := f.ensure(state, write); err != nil || len(p.fs.did("mkdir")) != 1 || len(p.fs.did("secure")) != 0 {
		t.Fatal(err, p.fs.calls)
	}
	if o, _ := p.fs.Stat(state); !write.matches(o) {
		t.Fatalf("%+v", o)
	}
	p.put(t, "state/pairing.json", sddlAgentFile, pairing)
	// Fairy's own with the right permissions, only the owner is another: Administrators become the owner on
	// the folder itself. No permissions are set (Windows would pass them on to what is inside), and nothing
	// inside is touched.
	for name, s := range map[string]string{
		"owned by the agent's account":         strings.Replace(sddlAgentDir, "O:BA", "O:"+tSvc, 1),
		"owned by LocalService (before 0.5)":   strings.Replace(sddlAgentDir, "O:BA", "O:LS", 1),
		"owner SYSTEM (made by the old agent)": strings.Replace(sddlAgentDir, "O:BA", "O:SY", 1),
	} {
		p.fs.calls, p.fs.sddl[state] = nil, s
		if err := f.ensure(state, write); err != nil || strings.Join(p.fs.calls, ",") != "setowner "+state {
			t.Errorf("%s: %v %v", name, err, p.fs.calls)
		}
		if o, _ := p.fs.Stat(state); !write.matches(o) {
			t.Errorf("%s: not corrected: %+v", name, o)
		}
	}
	// One of the agent's own folders whose permissions differ: they are not set in place (rule 1). install /
	// setup-self-update replace such a folder as a whole; everyone else is told to run that.
	for name, s := range map[string]string{
		"inherits from the data folder":             "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;" + tSvc + ")",
		"readable by Users":                         sddlAgentDir + "(A;OICI;0x1200a9;;;BU)",
		"owned by the agent, and readable by Users": strings.Replace(sddlAgentDir, "O:BA", "O:"+tSvc, 1) + "(A;OICI;0x1200a9;;;BU)",
	} {
		p.fs.calls, p.fs.sddl[state] = nil, s
		if err := f.ensure(state, write); err == nil || !strings.Contains(err.Error(), "setup-self-update") || len(p.fs.calls) != 0 {
			t.Errorf("%s: %v %v", name, err, p.fs.calls)
		}
	}
	p.fs.sddl[state] = sddlAgentDir
	// helper\ (only administrators change it, and so everything in it): permissions set on the folder
	helper := filepath.Join(p.dir, "helper")
	p.fs.calls, p.fs.sddl[helper] = nil, sddlDataDir+"(A;OICI;0x1200a9;;;BU)"
	if err := f.ensure(helper, read); err != nil || strings.Join(p.fs.calls, ",") != "secure "+helper {
		t.Fatal(err, p.fs.calls)
	}
	// ... but not while something below it could be changed by someone else, or is a link: Windows passes the
	// new permissions on to everything below (rule 2). Nothing is set then.
	p.fs.sddl[helper] = sddlDataDir + "(A;OICI;0x1200a9;;;BU)"
	planted := p.put(t, "helper/sub/x", sddlPlantedFile, "x")
	p.fs.calls = nil
	if err := f.ensure(helper, read); err == nil || !strings.Contains(err.Error(), planted) || !strings.Contains(err.Error(), "setup-self-update") || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
	_ = os.Remove(planted)
	if err := os.Symlink(p.root, planted); err != nil {
		t.Skip(err)
	}
	if err := f.ensure(helper, read); err == nil || !strings.Contains(err.Error(), "is a link") || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
	_ = os.RemoveAll(filepath.Dir(planted))
	p.fs.sddl[helper] = sddlDataDir
	// update\ that the agent's account may still write (0.4.2), with the agent's stage folder below it. Typed
	// by an administrator this is refused: the agent's account is someone else, and install /
	// setup-self-update move such an update\ aside as a whole (TestUpdateFolderOf042IsReplaced).
	upd := filepath.Join(p.dir, "update")
	p.fs.calls, p.fs.sddl[upd] = nil, sddlAgentDir
	if err := f.ensure(upd, read); err == nil || !strings.Contains(err.Error(), "setup-self-update") || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
	// Inside the agent itself, moving its own service to the low-rights account (it still is LocalSystem, and
	// the agent's account is nobody else), it is corrected in place as before.
	self := folders{fs: p.fs, hint: repairHint, agentIsSelf: true}
	p.fs.agentIsSelf = true
	if err := self.ensure(upd, read); err != nil || strings.Join(p.fs.calls, ",") != "secure "+upd {
		t.Fatal(err, p.fs.calls)
	}
	p.fs.agentIsSelf = false
	// someone else's: refused, with the way out, and nothing written
	for name, s := range map[string]string{
		"owned by a user":        sddlUserMadeDir,
		"owned by a user, reset": strings.Replace(sddlAgentDir, "O:BA", "O:"+tUser, 1),
		"a user may add files":   sddlAgentDir + "(A;OICI;0x1301bf;;;BU)",
		"no permissions":         "O:BAD:NO_ACCESS_CONTROL",
	} {
		p.fs.calls, p.fs.sddl[state] = nil, s
		if err := f.ensure(state, write); err == nil || !strings.Contains(err.Error(), "setup-self-update") || len(p.fs.calls) != 0 {
			t.Errorf("%s: %v %v", name, err, p.fs.calls)
		}
	}
	// a link or a file under the folder's name: refused, and what the link points to is not touched (L2)
	target := filepath.Join(p.root, "Program Files", "Fairy")
	_ = os.MkdirAll(target, 0o755)
	p.fs.sddl[target] = sddlProgramFiles
	_ = os.RemoveAll(state)
	if err := os.Symlink(target, state); err != nil {
		t.Skip(err)
	}
	p.fs.calls, p.fs.sddl[state] = nil, sddlAgentDir // the link itself looks like the agent's folder
	if err := f.ensure(state, write); err == nil || !strings.Contains(err.Error(), "is a link") || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
	if p.fs.sddl[target] != sddlProgramFiles {
		t.Fatal("the program folder's permissions were changed through a link")
	}
	_ = os.Remove(state)
	_ = os.WriteFile(state, []byte("x"), 0o644)
	if err := f.ensure(state, write); err == nil || !strings.Contains(err.Error(), "file where a folder belongs") {
		t.Fatal(err)
	}
}

// The create call races with someone else making the folder: what appears is judged like any folder found.
func TestMakeFolderRace(t *testing.T) {
	p := newPC(t)
	p.installed(t)
	d := filepath.Join(p.dir, "state2")
	_ = os.Mkdir(d, 0o755) // "appeared" between the look and the create call
	p.fs.sddl[d] = sddlUserMadeDir
	err := folders{fs: p.fs}.make(d, folderSpec{tSvc, true})
	if err == nil || !strings.Contains(err.Error(), "appeared while this was running") || len(p.fs.calls) != 0 {
		t.Fatal(err, p.fs.calls)
	}
}

func TestTokenPathProblem(t *testing.T) {
	const dir = `C:\ProgramData\fairy-agent`
	for _, p := range []string{`C:\ProgramData\fairy-agent\token`, `c:\programdata\FAIRY-AGENT\control-token`,
		`C:/ProgramData/fairy-agent/token`, `C:\ProgramData\fairy-agent\my token.txt`} {
		if why := tokenPathProblem(dir, p, true); why != "" {
			t.Errorf("%s: %s", p, why)
		}
	}
	for _, p := range []string{
		`C:\Users\mallory\got-the-token`, `C:\ProgramData\fairy-agent\..\..\Windows\System32\drivers\etc\hosts`,
		`C:\ProgramData\fairy-agent\logs\token`, `C:\ProgramData\fairy-agent2\token`, `C:\ProgramData\token`,
		`C:\ProgramData\fairy-agent\.\token`, `\\server\share\token`, `\\?\C:\ProgramData\fairy-agent\token`,
		`\\.\pipe\x`, `C:\ProgramData\fairy-agent\token:stream`, `C:\ProgramData\fairy-agent\token.`, `C:\ProgramData\fairy-agent\token `,
		`C:\PROGRA~3\fairy-agent\token`, `token`, `fairy-agent\token`, `C:\ProgramData\fairy-agent\`, `C:\ProgramData\fairy-agent`,
		`C:\ProgramData\fairy-agent\..`, `C:\ProgramData\fairy-agent\a*`, ``,
	} {
		if why := tokenPathProblem(dir, p, true); why == "" {
			t.Errorf("%q accepted", p)
		}
	}
	// a trailing separator on the folder makes no difference
	if tokenPathProblem(dir+`\`, dir+`\token`, true) != "" {
		t.Error("trailing separator")
	}
	// elsewhere (the tests of join run with these)
	d := t.TempDir()
	if tokenPathProblem(d, filepath.Join(d, "token"), false) != "" {
		t.Error("a file in the folder refused")
	}
	for _, p := range []string{filepath.Join(d, "sub", "token"), filepath.Join(filepath.Dir(d), "token"), filepath.Join(d, "..", "x"), "token", d} {
		if tokenPathProblem(d, p, false) == "" {
			t.Errorf("%q accepted", p)
		}
	}
}

// The audit's other two reproductions of H1: join followed a planted config.yaml and wrote the new tokens where
// it said, replacing whatever file was there. Now join looks first and writes token files only in the config
// folder.
func TestJoinRefusesAnUntrustedOrOutwardConfig(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	dir, state := t.TempDir(), t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	victim := filepath.Join(t.TempDir(), "important-file")
	_ = os.WriteFile(victim, []byte("do not replace me"), 0o600)
	planted := "token_file: " + victim + "\ncontrol_token_file: " + filepath.Join(filepath.Dir(victim), "ctl") + "\npower_control:\n  enabled: true\n"
	_ = os.WriteFile(cfgPath, []byte(planted), 0o640)
	o := joinOpts{code: "MFRG-GZDF-MZTW-Q2LK-NNWG-23TP-OBYX-E43U", panel: "100.88.109.47", cfgPath: cfgPath, stateDir: state, powerControl: true}
	untouched := func(what string) {
		t.Helper()
		if b, _ := os.ReadFile(victim); string(b) != "do not replace me" {
			t.Fatalf("%s: join replaced the file the config named: %q", what, b)
		}
		if b, _ := os.ReadFile(cfgPath); string(b) != planted {
			t.Fatalf("%s: join rewrote the config", what)
		}
		for _, f := range []string{filepath.Join(dir, "token"), filepath.Join(dir, "control-token"), filepath.Join(filepath.Dir(victim), "ctl"), filepath.Join(state, "pairing.json")} {
			if _, err := os.Lstat(f); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("%s: join wrote %s", what, f)
			}
		}
	}

	// 1. the folder check fails (Windows: the folder or config.yaml is someone else's): nothing is written
	defer func(f func(string) error, in bool) { dataDirTrusted, tokensInConfigDir = f, in }(dataDirTrusted, tokensInConfigDir)
	asked := ""
	dataDirTrusted = func(p string) error {
		asked = p
		return errors.New("the data folder cannot be trusted: " + cfgPath + " is owned by " + tUser)
	}
	var out bytes.Buffer
	if err := join(o, &out); err == nil || !strings.Contains(err.Error(), "cannot be trusted") || asked != cfgPath {
		t.Fatal(err, asked)
	}
	untouched("untrusted folder")

	// 2. the folder passes, but config.yaml names token files outside it: refused before anything is written
	dataDirTrusted, tokensInConfigDir = func(string) error { return nil }, true
	err := join(o, &out)
	if err == nil || !strings.Contains(err.Error(), victim) || !strings.Contains(err.Error(), "token_file") {
		t.Fatal(err)
	}
	untouched("token file outside the folder")

	// 3. token files in the folder (the default, or named there): join works as before
	o.powerControl = false // switching a feature on is `config set`, which needs root; not what is tested here
	_ = os.WriteFile(cfgPath, []byte("token_file: "+filepath.Join(dir, "panel-token")+"\n"), 0o640)
	if err := join(o, &out); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{filepath.Join(dir, "panel-token"), filepath.Join(dir, "control-token"), filepath.Join(state, "pairing.json")} {
		if _, err := os.Stat(f); err != nil {
			t.Fatal(err)
		}
	}

	// elsewhere than Windows nothing changes: a config root made may name token files anywhere
	tokensInConfigDir = false
	other := filepath.Join(t.TempDir(), "tok")
	_ = os.WriteFile(cfgPath, []byte("token_file: "+other+"\n"), 0o640)
	if err := join(o, &out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal(err)
	}
}

func TestRewriteFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(p, []byte("a: 1\n"), 0o640)
	before, _ := os.Stat(p)
	if err := rewriteFile(p); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	if b, _ := os.ReadFile(p); string(b) != "a: 1\n" || os.SameFile(before, after) {
		t.Fatal("not a new file with the same content")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatal("temporary file left behind")
	}
	if err := rewriteFile(dir); err == nil {
		t.Fatal("a folder was rewritten")
	}
	big := filepath.Join(dir, "big")
	_ = os.WriteFile(big, make([]byte, rewriteMax+1), 0o640)
	if err := rewriteFile(big); err == nil {
		t.Fatal("no size limit")
	}
	if err := os.Symlink(p, filepath.Join(dir, "link")); err == nil {
		if err := rewriteFile(filepath.Join(dir, "link")); err == nil {
			t.Fatal("a link was rewritten")
		}
	}
}

// The walk is bounded. Where only administrators can change things, folders nested without end stop the
// installer with a message. In one of the agent's own folders they cannot do that (the agent's account could
// make every installer run fail): the folder is replaced as a whole.
func TestRepairLimits(t *testing.T) {
	deep := func(top string) string {
		for i := 0; i < repairMaxDepth+2; i++ {
			top += "/d"
		}
		return top + "/"
	}
	p := newPC(t)
	p.installed(t)
	p.put(t, deep("helper"), sddlDataDir, "")
	if _, err := repairDataDir(p.fs, p.cfgPath, tSvc); err == nil || !strings.Contains(err.Error(), "nested too deep") {
		t.Fatal(err)
	}
	p = newPC(t)
	p.installed(t)
	p.put(t, deep("logs"), "", "")
	rep, err := repairDataDir(p.fs, p.cfgPath, tSvc)
	if err != nil || len(rep.Zones) != 1 || rep.Zones[0] != "logs" || !strings.Contains(strings.Join(rep.Notes, "\n"), "nested more than") {
		t.Fatal(err, rep.Zones, rep.Notes)
	}
	if collect.TrustedOwner(tUser) { // the fixtures' user is an ordinary one
		t.Fatal("fixture")
	}
}

// N8, the review's proof as it was written (it failed before the fix): a data folder that Administrators own,
// whose only foreign entry is inherit-only (it gives ordinary users full control of everything created inside
// from now on), passed the read-only check. join then wrote config.yaml and the new tokens into it, and those
// files inherit the entry: the user reads the tokens.
func TestInheritOnlyEntryIsNotTrusted(t *testing.T) {
	p := newPC(t)
	p.put(t, "", "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;"+tSvc+")(A;OICIIO;FA;;;BU)", "")
	if err := checkDataDir(p.fs, p.cfgPath, tSvc); err == nil {
		t.Errorf("checkDataDir accepted %s although every file created in it will be changeable by BUILTIN\\Users (inherit-only entry)", p.dir)
	}
	// the same one level down: helper\ (TrustedFolder on Windows skips inherit-only entries the same way)
	o := dirObj(t, "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;AU)")
	if lv, _ := judge(o, true, false, false, tSvc); lv == lvOK {
		t.Errorf("judge: a folder whose new files Authenticated Users will fully control is lvOK")
	}
	// what the installer does with such a folder: it is not adopted (someone else decides what its new files
	// are), so it is moved aside as a whole and the tokens are new
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	p.put(t, "token", sddlDataFile+"(A;ID;FA;;;BU)", "a-token-users-could-read-and-change-01\r\n")
	rep, out, err := p.run(t)
	if err != nil || rep.Replaced == "" || !strings.Contains(out, "IMPORTANT") || strings.Contains(p.read(t, "token"), "users-could-read") {
		t.Fatalf("%v %+v\n%s", err, rep, out)
	}
	p.usable(t)
	// one that only lets others read what is created: kept, permissions reset, tokens new
	p = newPC(t)
	p.installed(t)
	p.fs.sddl[p.dir] = sddlDataDir + "(A;OICIIO;GXGR;;;BU)"
	if err := checkDataDir(p.fs, p.cfgPath, tSvc); err != nil {
		t.Fatalf("reading does not steer anything, the check must pass: %v", err)
	}
	rep, out, err = p.run(t)
	if err != nil || !rep.RootLeak || rep.Replaced != "" || strings.Count(out, "new token in") != 2 {
		t.Fatalf("%v %+v\n%s", err, rep, out)
	}
	p.usable(t)
}
