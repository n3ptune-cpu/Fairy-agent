package main

// Test doubles for datadir.go: a reader for SDDL (the form in which Windows prints permissions, e.g.
// (Get-Acl path).Sddl), so the fixtures are real permission lists copied from Windows, and a dataFS over a
// temporary folder whose owners and permissions are kept in a table. There is no Windows here; the Win32 side
// (datadir_windows.go) is only compiled and vetted.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

const (
	tSvc  = "S-1-5-80-3141592653-589793238-462643383-279502884-197169399" // NT SERVICE\fairy-agent
	tUser = "S-1-5-21-1111111111-2222222222-3333333333-1001"              // an ordinary local user
	tTI   = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	tSys  = "S-1-5-18"
)

var sddlSIDs = map[string]string{
	"SY": tSys, "BA": sidAdmins, "BU": "S-1-5-32-545", "AU": "S-1-5-11", "WD": "S-1-1-0", "CO": "S-1-3-0",
	"OW": "S-1-3-4", "IU": "S-1-5-4", "LS": "S-1-5-19", "NS": "S-1-5-20", "AC": "S-1-15-2-1",
}

var sddlRights = map[string]uint32{
	"GA": rtGenericAll, "GR": rtGenericRead, "GW": rtGenericWrite, "GX": rtGenericExec,
	"RC": 0x20000, "SD": rtDelete, "WD": rtWriteDAC, "WO": rtWriteOwner,
	"CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "RP": 0x10, "WP": 0x20, "DT": 0x40, "LO": 0x80, "CR": 0x100,
	"FA": rtFileAll, "FR": rtFileGenericRead, "FW": rtFileGenericWrite, "FX": rtFileGenericExec,
}

var sddlFlags = map[string]uint8{"OI": 0x1, "CI": 0x2, "NP": 0x4, "IO": 0x8, "ID": 0x10}

func sddlSID(t testing.TB, s string) string {
	t.Helper()
	if strings.HasPrefix(s, "S-1-") {
		return s
	}
	if v, ok := sddlSIDs[s]; ok {
		return v
	}
	t.Fatalf("SDDL: unknown SID %q", s)
	return ""
}

// parseSDDL reads the owner and the DACL of an SDDL string into a secObj (kind and links are the caller's).
func parseSDDL(t testing.TB, s string) secObj {
	t.Helper()
	var o secObj
	parts := map[byte]string{}
	for len(s) >= 2 && s[1] == ':' {
		tag, depth, end := s[0], 0, len(s)
		for j := 2; j < len(s); j++ {
			switch s[j] {
			case '(':
				depth++
			case ')':
				depth--
			}
			if depth == 0 && j+1 < len(s) && s[j+1] == ':' && strings.IndexByte("OGDS", s[j]) >= 0 {
				end = j
				break
			}
		}
		parts[tag], s = s[2:end], s[end:]
	}
	if s != "" {
		t.Fatalf("SDDL: unexpected %q", s)
	}
	if ow, ok := parts['O']; ok {
		o.Owner = sddlSID(t, ow)
	}
	d, ok := parts['D']
	if !ok || strings.HasPrefix(d, "NO_ACCESS_CONTROL") {
		o.NullDACL = true
		return o
	}
	flags := d
	if i := strings.Index(d, "("); i >= 0 {
		flags = d[:i]
	}
	o.Protected = strings.Contains(flags, "P")
	if !strings.Contains(d, "(") {
		return o
	}
	for _, e := range strings.Split(strings.TrimSuffix(d[strings.Index(d, "(")+1:], ")"), ")(") {
		f := strings.Split(e, ";")
		if len(f) < 6 {
			t.Fatalf("SDDL: bad entry %q", e)
		}
		var a collect.ACE
		switch f[0] {
		case "A", "OA", "XA":
			a.Kind = collect.ACEAllow
		case "D", "OD", "XD":
			a.Kind = collect.ACEDeny
		default:
			a.Kind = collect.ACEOther
		}
		for fl := f[1]; fl != ""; fl = fl[2:] {
			v, ok := sddlFlags[fl[:2]]
			if !ok {
				t.Fatalf("SDDL: unknown flag in %q", e)
			}
			a.Flags |= v
		}
		if strings.HasPrefix(f[2], "0x") {
			v, err := strconv.ParseUint(f[2][2:], 16, 32)
			if err != nil {
				t.Fatal(err)
			}
			a.Mask = uint32(v)
		} else {
			for r := f[2]; r != ""; r = r[2:] {
				v, ok := sddlRights[r[:2]]
				if !ok {
					t.Fatalf("SDDL: unknown right in %q", e)
				}
				a.Mask |= v
			}
		}
		if a.Kind != collect.ACEOther {
			a.SID = sddlSID(t, f[5])
		}
		o.ACEs = append(o.ACEs, a)
	}
	return o
}

// Real permission lists, as Windows 10 / 11 print them ((Get-Acl path).Sddl), with the test SIDs filled in.
const (
	// C:\ as Windows sets it up: owner TrustedInstaller; Authenticated Users may create folders (and get
	// Modify on what they create, an inherit-only entry)
	sddlCRoot = "O:" + tTI + "G:" + tTI + "D:PAI(A;OICIIO;SDGXGWGR;;;AU)(A;;LC;;;AU)(A;OICI;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	// the same after an upgrade (generic rights mapped, owner SYSTEM)
	sddlCRootMapped = "O:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;0x1301bf;;;AU)(A;;0x4;;;AU)"
	// a real PC whose drive root gives Authenticated Users Modify on the root itself (an earlier release
	// refused such a PC by mistake: a drive's root cannot be deleted or renamed)
	sddlCRootModify = "O:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICI;0x1301bf;;;AU)(A;;0x4;;;AU)"
	// C:\ProgramData: Users may add files and folders (and own what they add)
	sddlProgramData = "O:SYG:SYD:PAI(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;CI;DCLCRPCR;;;BU)"
	// C:\Program Files and C:\Windows\System32
	sddlProgramFiles = "O:" + tTI + "G:" + tTI + "D:PAI(A;;FA;;;" + tTI + ")(A;CIIO;GA;;;" + tTI + ")(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;SY)" +
		"(A;;0x1301bf;;;BA)(A;OICIIO;GA;;;BA)(A;;0x1200a9;;;BU)(A;OICIIO;GXGR;;;BU)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;AC)(A;OICIIO;GXGR;;;AC)"
	sddlSystem32 = sddlProgramFiles

	// C:\ProgramData\fairy-agent as `fairy-agent install` has made it since 0.1 (the owner is whoever ran the
	// installer elevated: Administrators)
	sddlDataDir = "O:BAG:S-1-5-21-1111111111-2222222222-3333333333-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + tSvc + ")"
	// a file in it (config.yaml, token): everything inherited
	sddlDataFile = "O:BAG:S-1-5-21-1111111111-2222222222-3333333333-513D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;" + tSvc + ")"
	// logs\, state\, update\stage\
	sddlAgentDir = "O:BAG:S-1-5-21-1111111111-2222222222-3333333333-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + tSvc + ")"
	// a file the agent's account made there (agent.log, pairing.json)
	sddlAgentFile = "O:" + tSvc + "G:" + tSvc + "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;" + tSvc + ")"
	// a log file from before 0.5, when the agent ran as LocalService
	sddlLocalServiceFile = "O:LSG:LSD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1301bf;;;" + tSvc + ")"

	// a folder an ordinary user created under C:\ProgramData before Fairy was installed: the user owns it and
	// has full control (the CREATOR OWNER entry of C:\ProgramData, made concrete)
	sddlUserMadeDir = "O:" + tUser + "G:S-1-5-21-1111111111-2222222222-3333333333-513D:AI(A;ID;FA;;;" + tUser + ")(A;OICIIOID;GA;;;CO)" +
		"(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"
	// the same folder after the installer up to 0.5.3 had reset its permissions: the permissions look right,
	// the owner is still the user (H1)
	sddlUserOwnedReset = "O:" + tUser + "G:S-1-5-21-1111111111-2222222222-3333333333-513D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;" + tSvc + ")"
	// a file the user planted, with its own protected permissions (they survive a reset of the folder)
	sddlPlantedFile = "O:" + tUser + "D:P(A;;FA;;;" + tUser + ")(A;;FA;;;SY)(A;;FA;;;BA)"
	// a file the user planted that only inherits: after the folder's reset its permissions look right, the
	// owner is still the user
	sddlPlantedInherits = "O:" + tUser + "D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;" + tSvc + ")"
	// a folder made by an administrator with plain mkdir under C:\ProgramData (what the installer's first step
	// produced before it set permissions): Users may add files to it (H1b)
	sddlAdminMkdir = "O:BAG:S-1-5-21-1111111111-2222222222-3333333333-513D:AI(A;OICIIOID;GA;;;CO)(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)" +
		"(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)"
	// an administrator gave their own (non-elevated) account read access by hand
	sddlHandRead = "O:BAD:AI(A;;0x1200a9;;;" + tUser + ")(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;" + tSvc + ")"
)

// fakeFS is a dataFS over a real temporary folder. What exists, listing, renaming and removing are the real
// file system's; owner and permissions come from the table sddl (path -> SDDL), with the "everything
// inherited from a healthy data folder" lists for paths that are not in it. A symbolic link stands for any
// link (junction, symbolic link).
type fakeFS struct {
	t     testing.TB
	sddl  map[string]string
	links map[string]uint32 // names a file has, when not one
	// mkdirIgnoresSecurity: the create call does not apply the security it is given; the new folder gets what
	// it would inherit under C:\ProgramData (the case makeFolder must cope with)
	mkdirIgnoresSecurity bool
	asideErr             error
	calls                []string // every call that changes something
	elevations           int
}

func newFakeFS(t testing.TB) *fakeFS {
	return &fakeFS{t: t, sddl: map[string]string{}, links: map[string]uint32{}}
}

func (f *fakeFS) log(op, path string) { f.calls = append(f.calls, op+" "+path) }

// did lists the changing calls whose operation is op.
func (f *fakeFS) did(op string) []string {
	var out []string
	for _, c := range f.calls {
		if strings.HasPrefix(c, op+" ") {
			out = append(out, strings.TrimPrefix(c, op+" "))
		}
	}
	return out
}

func (f *fakeFS) Stat(path string) (secObj, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return secObj{}, err
	}
	s, ok := f.sddl[path]
	if !ok {
		s = sddlDataFile
		if st.IsDir() {
			s = "O:BAD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;" + tSvc + ")"
		}
	}
	o := parseSDDL(f.t, s)
	o.Dir, o.Reparse, o.Links = st.IsDir(), st.Mode()&os.ModeSymlink != 0, 1
	if n, ok := f.links[path]; ok {
		o.Links = n
	}
	return o, nil
}

func (f *fakeFS) List(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names, nil
}

func (f *fakeFS) Mkdir(path, sddl string) error {
	if err := os.Mkdir(path, 0o700); err != nil {
		return err
	}
	f.log("mkdir", path)
	f.sddl[path] = sddl
	if f.mkdirIgnoresSecurity {
		f.sddl[path] = sddlAdminMkdir
	}
	return nil
}

func (f *fakeFS) Secure(path, sddl string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a link", path)
	}
	if !strings.HasPrefix(sddl, "O:") { // only the permissions: the owner stays
		o, _ := f.Stat(path)
		sddl = "O:" + o.Owner + sddl
	}
	f.log("secure", path)
	f.sddl[path] = sddl
	return nil
}

func (f *fakeFS) Aside(path string) (string, error) {
	if f.asideErr != nil {
		return "", f.asideErr
	}
	to := path + asideMark + "20270101-000000"
	for i := 2; ; i++ {
		if _, err := os.Lstat(to); errors.Is(err, os.ErrNotExist) {
			break
		}
		to = fmt.Sprintf("%s%s20270101-000000-%d", path, asideMark, i)
	}
	if err := os.Rename(path, to); err != nil {
		return "", err
	}
	f.log("aside", path)
	for p, s := range f.sddl { // owners and permissions move with the objects
		if p == path || strings.HasPrefix(p, path+string(filepath.Separator)) {
			delete(f.sddl, p)
			f.sddl[to+strings.TrimPrefix(p, path)] = s
		}
	}
	return to, nil
}

func (f *fakeFS) Remove(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("%s is not a link", path)
	}
	f.log("remove", path)
	return os.Remove(path)
}

func (f *fakeFS) Rewrite(path string) error {
	if err := rewriteFile(path); err != nil {
		return err
	}
	f.log("rewrite", path)
	delete(f.sddl, path) // a new file: everything inherited, owner Administrators
	return nil
}

func (f *fakeFS) Elevate() func() {
	f.elevations++
	return func() { f.elevations-- }
}

// pc is a "PC": a drive root, C:\ProgramData and (not yet) the data folder, as paths in a temporary folder.
type pc struct {
	fs      *fakeFS
	root    string // stands for C:\
	pd      string // C:\ProgramData
	dir     string // C:\ProgramData\fairy-agent
	cfgPath string
}

func newPC(t testing.TB) *pc {
	t.Helper()
	root := t.TempDir()
	p := &pc{fs: newFakeFS(t), root: root, pd: filepath.Join(root, "ProgramData")}
	p.dir = filepath.Join(p.pd, "fairy-agent")
	p.cfgPath = filepath.Join(p.dir, "config.yaml")
	if err := os.Mkdir(p.pd, 0o755); err != nil {
		t.Fatal(err)
	}
	// the folders above the temporary folder count as Windows' own; the temporary folder is the drive
	p.fs.sddl[root] = sddlCRoot
	p.fs.sddl[p.pd] = sddlProgramData
	for d := filepath.Dir(root); ; d = filepath.Dir(d) {
		p.fs.sddl[d] = sddlProgramFiles
		if d == filepath.Dir(d) {
			break
		}
	}
	return p
}

// put creates a file or (name ending in /) a folder below the data folder with the given security.
func (p *pc) put(t testing.TB, rel, sddl, content string) string {
	t.Helper()
	path := filepath.Join(p.dir, filepath.FromSlash(strings.TrimSuffix(rel, "/")))
	if rel == "" {
		path = p.dir
	}
	if rel == "" || strings.HasSuffix(rel, "/") {
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(path)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if sddl != "" {
		p.fs.sddl[path] = sddl
	}
	return path
}

// installed makes the data folder as fairy-agent 0.5.3's install and setup-self-update left it on a healthy,
// paired PC that has been running for a while.
func (p *pc) installed(t testing.TB) {
	t.Helper()
	p.put(t, "", sddlDataDir, "")
	p.put(t, "config.yaml", sddlDataFile, "power_control:\n  enabled: true\nself_update:\n  enabled: true\n")
	p.put(t, "token", sddlDataFile, "read-token-of-the-paired-panel-0123456789\r\n")
	p.put(t, "control-token", sddlDataFile, "control-token-of-the-paired-panel-012345\r\n")
	p.put(t, "logs/", sddlAgentDir, "")
	p.put(t, "logs/agent.log", sddlAgentFile, "log\n")
	p.put(t, "logs/agent.log.1", sddlAgentFile, "older log\n")
	p.put(t, "helper/", sddlDataDir, "")
	p.put(t, "helper/helper.log", sddlDataFile, "helper log\n")
	p.put(t, "update/", sddlDataDir, "")
	p.put(t, "update/result.json", sddlDataFile, "{}")
	p.put(t, "update/installer.log", sddlDataFile, "installer log\n")
	p.put(t, "update/stage/", sddlAgentDir, "")
	p.put(t, "update/stage/request.json", sddlAgentFile, "{}")
	p.put(t, "state/", sddlAgentDir, "")
	p.put(t, "state/pairing.json", sddlAgentFile, `{"closed":"paired"}`)
	p.put(t, "migration/", sddlDataDir, "")
	p.put(t, "migration/state.json", sddlDataFile, `{"phase":"done"}`)
}

func (p *pc) read(t testing.TB, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(p.dir, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// memFS is a read-only dataFS of nothing but a table (path -> object), for the checks that only look. Paths
// are written the Unix way; "/" stands for the drive (C:\).
type memFS map[string]secObj

func (m memFS) Stat(path string) (secObj, error) {
	o, ok := m[path]
	if !ok {
		return secObj{}, &os.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
	}
	return o, nil
}
func (memFS) List(string) ([]string, error) { panic("read-only") }
func (memFS) Mkdir(string, string) error    { panic("read-only") }
func (memFS) Secure(string, string) error   { panic("read-only") }
func (memFS) Aside(string) (string, error)  { panic("read-only") }
func (memFS) Remove(string) error           { panic("read-only") }
func (memFS) Rewrite(string) error          { panic("read-only") }
func (memFS) Elevate() func()               { panic("read-only") }

func dirObj(t testing.TB, sddl string) secObj {
	o := parseSDDL(t, sddl)
	o.Dir, o.Links = true, 1
	return o
}

func fileObj(t testing.TB, sddl string) secObj {
	o := parseSDDL(t, sddl)
	o.Links = 1
	return o
}
