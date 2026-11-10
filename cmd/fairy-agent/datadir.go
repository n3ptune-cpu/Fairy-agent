package main

// The Windows data folder, C:\ProgramData\fairy-agent: who may change what in it, and how that is checked.
//
//	fairy-agent\                 config.yaml, token, control-token, secrets: administrators and SYSTEM change,
//	                             the agent's account (NT SERVICE\fairy-agent) only reads
//	  helper\  update\  migration\   the same (the LocalSystem helper and updater write here)
//	  logs\  state\  update\stage\   the agent's account writes ("the agent's folders")
//
// Windows lets ordinary users create folders and files under C:\ProgramData, and whoever creates something
// owns it and can always give themselves access again. So nothing that already exists here is taken on trust:
// every folder and file must be a plain one (no junction, no symbolic link, one name), owned by Administrators
// or SYSTEM, with no entry that lets anyone else change it. Inside the agent's folders the agent's account is
// allowed as well.
//
// This file holds the decisions, written against a small file-system interface (dataFS) so they are tested on
// every platform with real Windows permission lists as fixtures; datadir_windows.go is the Win32 side, which
// opens every object itself (FILE_FLAG_OPEN_REPARSE_POINT), never what a link points to, and sets security
// on that open handle.
//
//   - checkDataDir: read-only. join, the updater, the helper and the migration state use it before they act
//     on config.yaml; they refuse when it fails.
//   - folders.ensure: one of Fairy's own folders exists as a plain folder with its permissions.
//   - repairDataDir: `install` and `setup-self-update` (an administrator). What cannot be trusted is never
//     adopted: it is moved aside (name.untrusted-<time>) and made anew; links are removed.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

const (
	sidAdmins       = "S-1-5-32-544"
	sidLocalService = "S-1-5-19" // the agent's account before 0.5: files it made in the agent's folders remain

	dataFolderName = "fairy-agent"
	asideMark      = ".untrusted-"
)

// secObj is what the checks need of one file or folder, read from the object itself (never through a link).
type secObj struct {
	Dir       bool
	Reparse   bool   // a junction, symbolic link or other reparse point
	Links     uint32 // names the file has (hard links); 0 = not known
	Owner     string // SID
	NullDACL  bool   // no permissions at all: everyone has full access
	Protected bool   // takes no entries from the folder above
	ACEs      []collect.ACE
}

// Access rights (winnt.h), as far as the checks need them. For a folder, write data is "add a file" and append
// data is "add a folder".
const (
	rtReadData    = 0x1
	rtWriteData   = 0x2
	rtAppendData  = 0x4
	rtDeleteChild = 0x40
	rtDelete      = 0x10000
	rtWriteDAC    = 0x40000
	rtWriteOwner  = 0x80000

	rtMaxAllowed   = 0x02000000
	rtGenericAll   = 0x10000000
	rtGenericExec  = 0x20000000
	rtGenericWrite = 0x40000000
	rtGenericRead  = 0x80000000

	rtFileAll          = 0x1f01ff
	rtFileGenericRead  = 0x120089
	rtFileGenericWrite = 0x120116
	rtFileGenericExec  = 0x1200a0

	rtReadExecute = 0x1200a9 // what the agent's account gets on the folder
	rtModify      = 0x1301bf // and on its own folders

	// rtChange: the rights that change an object or what is in it, or hand it to someone else.
	rtChange = rtWriteData | rtAppendData | rtDeleteChild | rtDelete | rtWriteDAC | rtWriteOwner
)

// plainRights maps the generic rights of an entry to the file rights they stand for, as Windows does.
func plainRights(m uint32) uint32 {
	if m&(rtGenericAll|rtMaxAllowed) != 0 {
		m |= rtFileAll
	}
	if m&rtGenericRead != 0 {
		m |= rtFileGenericRead
	}
	if m&rtGenericWrite != 0 {
		m |= rtFileGenericWrite
	}
	if m&rtGenericExec != 0 {
		m |= rtFileGenericExec
	}
	return m &^ (rtGenericAll | rtGenericExec | rtGenericWrite | rtGenericRead | rtMaxAllowed)
}

// level is how far an object can be trusted, worst last.
type level int

const (
	lvOK      level = iota
	lvLeak          // someone else may read it; nobody else can change it
	lvAgent         // the agent's own account can change it (or owns it) where it should only read
	lvForeign       // someone else can change it, owns it, or it is not a plain file / folder
)

const aceInheritOnly = 0x8

func sidName(sid string) string {
	if sid == "" {
		return "an entry that cannot be read"
	}
	return sid
}

// judge decides how far one object of the data folder can be trusted. wantDir says what it must be. agentZone:
// it is in one of the agent's folders; zoneRoot: it is such a folder itself. agentSID is the service's SID
// ("" when the service does not exist).
//
// Owner: Administrators, SYSTEM or TrustedInstaller. Inside the agent's folders also the agent's account (and
// LocalService, which the agent ran as before 0.5); the agent's folders themselves belong to Administrators.
// Entries: deny entries and entries that only pass on to new objects are skipped (as in
// collect.CheckWindowsACL); for anyone but administrators, SYSTEM and (in its folders) the agent, a right that
// changes the object is lvForeign and read access is lvLeak. An entry kind the check does not know counts as
// an unknown account's.
func judge(o secObj, wantDir, agentZone, zoneRoot bool, agentSID string) (level, string) {
	switch {
	case o.Reparse:
		return lvForeign, "is a link (a junction or symbolic link), not a plain file or folder"
	case o.Dir && !wantDir:
		return lvForeign, "is a folder where a file belongs"
	case !o.Dir && wantDir:
		return lvForeign, "is a file where a folder belongs"
	case !o.Dir && o.Links > 1:
		return lvForeign, "has more than one name (a hard link)"
	case o.NullDACL:
		return lvForeign, "has no permissions set (everyone may change it)"
	}
	lv, why := lvOK, ""
	worse := func(l level, f string, a ...any) {
		if l > lv {
			lv, why = l, fmt.Sprintf(f, a...)
		}
	}
	agentish := func(sid string) bool { return sid != "" && (sid == agentSID || sid == sidLocalService) }
	switch {
	case collect.TrustedOwner(o.Owner):
	case agentish(o.Owner) && agentZone && !zoneRoot:
	case agentish(o.Owner):
		worse(lvAgent, "is owned by the agent's own account (%s), not by Administrators (an owner can always change the permissions)", o.Owner)
	default:
		worse(lvForeign, "is owned by %s, not by Administrators or SYSTEM (an owner can always give themselves access)", sidName(o.Owner))
	}
	for _, a := range o.ACEs {
		if a.Kind == collect.ACEDeny || a.Flags&aceInheritOnly != 0 {
			continue
		}
		m := plainRights(a.Mask)
		switch {
		case a.Kind == collect.ACEAllow && collect.TrustedOwner(a.SID):
		case a.Kind == collect.ACEAllow && a.SID != "" && a.SID == agentSID:
			if !agentZone && m&rtChange != 0 {
				worse(lvAgent, "can be changed by the agent's own account (access 0x%x), which should only read it", a.Mask)
			}
		case m&rtChange != 0:
			worse(lvForeign, "can be changed by %s (access 0x%x)", sidName(a.SID), a.Mask)
		case m&rtReadData != 0:
			worse(lvLeak, "can be read by %s (access 0x%x)", sidName(a.SID), a.Mask)
		}
	}
	return lv, why
}

// agentZones are the folders the agent's account writes, relative to the data folder.
var agentZones = []string{"logs", "state", "update/stage"}

// zoneOf: rel is a path below the data folder with forward slashes ("" is the folder itself).
func zoneOf(rel string) (agentZone, zoneRoot bool) {
	r := strings.ToLower(rel)
	for _, z := range agentZones {
		if r == z {
			return true, true
		}
		if strings.HasPrefix(r, z+"/") {
			return true, false
		}
	}
	return false, false
}

// folderSpec is the security of one of Fairy's own folders: owner Administrators; administrators and SYSTEM
// full control; the agent's account read (or, in its own folders, modify); nothing taken from the folder
// above; passed on to everything inside.
type folderSpec struct {
	agentSID string
	write    bool
}

func (s folderSpec) agentMask() uint32 {
	if s.write {
		return rtModify
	}
	return rtReadExecute
}

// sddl is the spec as Windows reads it (SDDL).
func (s folderSpec) sddl() string {
	d := "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	if s.agentSID != "" {
		d += fmt.Sprintf("(A;OICI;0x%x;;;%s)", s.agentMask(), s.agentSID)
	}
	return d
}

// aces is the same list as sddl's, for comparing with what a folder has.
func (s folderSpec) aces() []collect.ACE {
	const oici = 0x3
	l := []collect.ACE{{Kind: collect.ACEAllow, Flags: oici, SID: "S-1-5-18", Mask: rtFileAll},
		{Kind: collect.ACEAllow, Flags: oici, SID: sidAdmins, Mask: rtFileAll}}
	if s.agentSID != "" {
		l = append(l, collect.ACE{Kind: collect.ACEAllow, Flags: oici, SID: s.agentSID, Mask: s.agentMask()})
	}
	return l
}

// matches reports whether a folder already has exactly this security (then nothing is written).
func (s folderSpec) matches(o secObj) bool {
	want := s.aces()
	if !o.Dir || o.Reparse || o.NullDACL || !o.Protected || o.Owner != sidAdmins || len(o.ACEs) != len(want) {
		return false
	}
	used := make([]bool, len(o.ACEs))
next:
	for _, w := range want {
		for i, a := range o.ACEs {
			if !used[i] && a.Kind == w.Kind && a.Flags == w.Flags && a.SID == w.SID && a.Mask == w.Mask {
				used[i] = true
				continue next
			}
		}
		return false
	}
	return true
}

// dataFolders are Fairy's own folders in the data folder, in the order they are made.
var dataFolders = []struct {
	rel   string
	write bool // the agent's account writes there
}{{"logs", true}, {"helper", false}, {"update", false}, {"update/stage", true}, {"state", true}}

// knownFolder returns the spec of one of Fairy's folders (migration\ is made when it is needed).
func knownFolder(rel, agentSID string) (folderSpec, bool) {
	r := strings.ToLower(rel)
	for _, f := range dataFolders {
		if r == f.rel {
			return folderSpec{agentSID, f.write}, true
		}
	}
	if r == "migration" {
		return folderSpec{agentSID, false}, true
	}
	return folderSpec{}, false
}

// dataFS is the file system as the checks use it. Every call acts on the named object itself, never on what a
// link points to.
type dataFS interface {
	// Stat reads an object's kind, owner and permissions (os.ErrNotExist when there is none).
	Stat(path string) (secObj, error)
	// List returns the names in a folder.
	List(dir string) ([]string, error)
	// Mkdir creates one folder with its final security in the same call (os.ErrExist when it exists).
	Mkdir(path, sddl string) error
	// Secure sets owner and permissions on the opened object; it refuses a link.
	Secure(path, sddl string) error
	// Aside renames an object to <name>.untrusted-<time> next to it and returns the new path.
	Aside(path string) (string, error)
	// Remove deletes a link (the link, not what it points to).
	Remove(path string) error
	// Rewrite replaces a file by a new one with the same content, which takes its permissions from the folder.
	Rewrite(path string) error
	// Elevate switches on what an administrator needs to take over objects that shut administrators out; the
	// returned function switches it off again.
	Elevate() func()
}

// checkAncestors checks the folders above dir, up to the drive: none may be replaceable by anyone but
// administrators, SYSTEM and TrustedInstaller. These are Windows' own folders (C:\ProgramData, C:\), so only
// the rights that could replace the path count, exactly as for a program's folders (collect.CheckWindowsACL:
// every signed-in user may create folders in C:\ and in C:\ProgramData, which replaces nothing).
func checkAncestors(fs dataFS, dir string) error {
	for p := filepath.Dir(dir); ; {
		parent := filepath.Dir(p)
		kind := collect.ObjAncestor
		if parent == p {
			kind = collect.ObjRoot
		}
		o, err := fs.Stat(p)
		if err != nil {
			return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
		}
		if !o.Dir {
			return fmt.Errorf("%s is not a folder", p)
		}
		if err := collect.CheckWindowsACL(p, kind, o.Owner, o.NullDACL, o.ACEs); err != nil {
			return err
		}
		if parent == p {
			return nil
		}
		p = parent
	}
}

// relOf is path below dir with forward slashes.
func relOf(dir, path string) string {
	r, err := filepath.Rel(dir, path)
	if err != nil {
		return ""
	}
	return filepath.ToSlash(r)
}

// tokenPathProblem says why p is not a token file directly in the config folder dir ("" = it is). windows
// selects Windows path rules (both separators, names compared without case); the folder's short (8.3) name,
// a device or network path, an alternate data stream and ".." are all refused.
func tokenPathProblem(dir, p string, windows bool) string {
	if !windows {
		if filepath.Dir(filepath.Clean(p)) != filepath.Clean(dir) || !filepath.IsAbs(p) {
			return "is not a file in " + dir
		}
		return ""
	}
	norm := func(s string) string { return strings.TrimRight(strings.ReplaceAll(s, "/", `\`), `\`) }
	d, f := norm(dir), strings.ReplaceAll(p, "/", `\`)
	if strings.HasPrefix(f, `\\`) {
		return "is a network or device path"
	}
	i := strings.LastIndex(f, `\`)
	if i < 0 {
		return "is not a full path"
	}
	parent, base := f[:i], f[i+1:]
	for _, seg := range strings.Split(parent, `\`) {
		if seg == "." || seg == ".." {
			return `contains "." or ".."`
		}
	}
	if !strings.EqualFold(parent, d) {
		return "is not a file in " + dir
	}
	if base == "" || base == "." || base == ".." || strings.ContainsAny(base, `:*?"<>|`) ||
		strings.HasSuffix(base, ".") || strings.HasSuffix(base, " ") {
		return "is not a plain file name"
	}
	return ""
}

// configTokenFiles are the token files config.yaml names, as far as they are in its folder; the defaults when
// config.yaml is missing or cannot be read.
func configTokenFiles(cfgPath string) []string {
	dir := filepath.Dir(cfgPath)
	files := []string{filepath.Join(dir, "token"), filepath.Join(dir, "control-token")}
	if c, err := agent.Load(cfgPath); err == nil {
		files = files[:0]
		for _, p := range []string{c.TokenFile, c.ControlTokenFile} {
			if tokenPathProblem(dir, p, runtime.GOOS == "windows") == "" {
				files = append(files, p)
			}
		}
	}
	return files
}

const repairHint = `; as Administrator run: & "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update   (it repairs the folder; what it cannot trust is moved aside)`

// checkDataDir is the read-only check a privileged program makes before it acts on config.yaml: the folders
// above, the folder itself, config.yaml and the token files it names in that folder, and alsoDirs (folders
// below the data folder the caller is about to write, which must exist). Nothing is changed. Someone else
// being able to read is not a reason to refuse here (it does not let them steer the program); `install` and
// `setup-self-update` correct that.
func checkDataDir(fs dataFS, cfgPath, agentSID string, alsoDirs ...string) error {
	dir := filepath.Dir(cfgPath)
	if err := checkAncestors(fs, dir); err != nil {
		return err
	}
	check := func(p string, wantDir, must bool) error {
		o, err := fs.Stat(p)
		if errors.Is(err, os.ErrNotExist) && !must {
			return nil
		}
		if err != nil {
			return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
		}
		agentZone, zoneRoot := zoneOf(relOf(dir, p))
		if lv, why := judge(o, wantDir, agentZone, zoneRoot, agentSID); lv >= lvAgent {
			return fmt.Errorf("%s %s", p, why)
		}
		return nil
	}
	if err := check(dir, true, true); err != nil {
		return err
	}
	for _, d := range alsoDirs {
		if err := check(filepath.Join(dir, filepath.FromSlash(d)), true, true); err != nil {
			return err
		}
	}
	if err := check(cfgPath, false, false); err != nil {
		return err
	}
	for _, p := range configTokenFiles(cfgPath) { // read only after config.yaml itself passed
		if err := check(p, false, false); err != nil {
			return err
		}
	}
	return nil
}

// folders does the folder work of this file on one file system.
type folders struct {
	fs dataFS
	// keepLinks: a link found inside a folder whose permissions are about to be set is an error instead of
	// being removed (a --config folder that is not Fairy's own).
	keepLinks bool
	// note is told what was changed besides permissions (may be nil).
	note func(format string, a ...any)
}

func (f folders) say(format string, a ...any) {
	if f.note != nil {
		f.note(format, a...)
	}
}

// ensure makes sure one of Fairy's folders exists as a plain folder with its security. A folder that is
// missing is created with it in the same call; an existing one must not be a link, a file, or controlled by
// someone other than administrators and the agent's account (then it is refused: only install /
// setup-self-update replace such a folder), and gets owner and permissions set on the opened folder when
// they differ. The folder above must exist.
func (f folders) ensure(path string, spec folderSpec) error {
	o, err := f.fs.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return f.make(path, spec)
	}
	if err != nil {
		return fmt.Errorf("%s: cannot read its permissions: %w", path, err)
	}
	if lv, why := judge(o, true, spec.write, true, spec.agentSID); lv == lvForeign {
		return fmt.Errorf("%s %s%s", path, why, repairHint)
	}
	if spec.matches(o) {
		return nil
	}
	return f.secure(path, spec)
}

// make creates a folder with its final security, then looks at the result: whatever the create call did with
// the security it was given, the folder is only used when it ends up as it should.
func (f folders) make(path string, spec folderSpec) error {
	err := f.fs.Mkdir(path, spec.sddl())
	made := err == nil
	if err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("creating %s: %w", path, err)
	}
	o, err := f.fs.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: cannot read its permissions: %w", path, err)
	}
	if !made { // someone else made it in the same moment: it is judged like any folder found there
		if lv, why := judge(o, true, spec.write, true, spec.agentSID); lv == lvForeign {
			return fmt.Errorf("%s appeared while this was running and %s: run this again", path, why)
		}
	}
	if spec.matches(o) {
		return nil
	}
	return f.secure(path, spec)
}

// secure sets the spec on the opened folder and checks the result. Before that, every link (junction,
// symbolic link) below the folder is removed, without ever entering one: Windows passes a folder's new
// permissions on to what is inside, and nothing a link points to may be reached that way.
func (f folders) secure(path string, spec folderSpec) error {
	var seen int
	if err := f.unlink(path, 0, &seen); err != nil {
		return err
	}
	if err := f.fs.Secure(path, spec.sddl()); err != nil {
		return fmt.Errorf("setting the permissions of %s: %w", path, err)
	}
	o, err := f.fs.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: cannot read its permissions: %w", path, err)
	}
	if lv, why := judge(o, true, spec.write, true, spec.agentSID); lv != lvOK {
		return fmt.Errorf("%s still %s after its permissions were set", path, why)
	}
	return nil
}

// unlink removes every link below folder d (see secure).
func (f folders) unlink(d string, depth int, seen *int) error {
	if depth > repairMaxDepth {
		return fmt.Errorf("%s: folders nested too deep; delete what does not belong there and run this again", d)
	}
	names, err := f.fs.List(d)
	if err != nil {
		return fmt.Errorf("%s: cannot list it: %w", d, err)
	}
	for _, name := range names {
		if *seen++; *seen > repairMaxEntries {
			return fmt.Errorf("%s holds more than %d files: delete what does not belong there and run this again", d, repairMaxEntries)
		}
		p := filepath.Join(d, name)
		o, err := f.fs.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
		}
		switch {
		case o.Reparse:
			if err := f.removeLink(p); err != nil {
				return err
			}
		case o.Dir:
			if err := f.unlink(p, depth+1, seen); err != nil {
				return err
			}
		}
	}
	return nil
}

// removeLink removes one link (the link itself, never what it points to).
func (f folders) removeLink(p string) error {
	if f.keepLinks {
		return fmt.Errorf("%s is a link (a junction or symbolic link); this is not fairy-agent's standard data folder, so nothing in it is removed: "+
			"remove the link yourself, or leave out --config", p)
	}
	if err := f.fs.Remove(p); err != nil {
		return fmt.Errorf("%s is a link (a junction or symbolic link) and could not be removed: %w", p, err)
	}
	f.say("%s was a link (a junction or symbolic link): the link was removed, what it pointed to was not touched.", p)
	return nil
}

// dirReport is what repairDataDir found and did.
type dirReport struct {
	Created     bool            // the data folder did not exist
	Replaced    string          // the old data folder was moved here: it could not be trusted as a whole
	ConfigAside bool            // config.yaml was moved aside
	RootLeak    bool            // someone else could read the data folder (and with it the token files)
	Leaked      map[string]bool // files someone else could read
	Aside       []string        // what was moved aside
	Notes       []string        // what was found and done, one sentence each, for the administrator
}

func (r *dirReport) note(f string, a ...any) { r.Notes = append(r.Notes, fmt.Sprintf(f, a...)) }

// Limits of the walk through the data folder (it holds a handful of files).
const (
	repairMaxEntries = 20000
	repairMaxDepth   = 8
)

type dirRepair struct {
	folders
	dir      string
	cfgPath  string
	agentSID string
	ours     bool // the folder is named fairy-agent: things in it may be moved aside
	rep      *dirReport
	seen     int
}

// repairDataDir makes the data folder safe to use (as an administrator: install, setup-self-update).
//
//   - The folders above must not be replaceable by others; otherwise it stops.
//   - A data folder that does not exist is created with its final permissions in the same call.
//   - A data folder that someone else owns or can change is not adopted: it is moved aside as a whole
//     (fairy-agent.untrusted-<time>) and a new one is made. Whoever prepared it may still hold it open, and
//     an open handle keeps its rights whatever is set afterwards; a new folder has no such history.
//   - Inside a folder that is kept, every file and folder is looked at: links are removed, what someone else
//     (or, outside its own folders, the agent's account) owns or can change is moved aside, what someone else
//     could only read is rewritten as a new file (folders: permissions reset).
//   - Fairy's own folders are created with their final permissions where they are missing.
//
// Only a folder named fairy-agent is repaired this way; with another --config folder it reports what is wrong
// and changes nothing inside.
func repairDataDir(fs dataFS, cfgPath, agentSID string) (dirReport, error) {
	dir := filepath.Dir(cfgPath)
	rep := dirReport{Leaked: map[string]bool{}}
	ours := strings.EqualFold(filepath.Base(dir), dataFolderName)
	w := &dirRepair{folders: folders{fs: fs, keepLinks: !ours, note: rep.note}, dir: dir, cfgPath: cfgPath,
		agentSID: agentSID, rep: &rep, ours: ours}
	if err := checkAncestors(fs, dir); err != nil {
		return rep, fmt.Errorf("the folders above %s are not safe to build on: %w", dir, err)
	}
	defer fs.Elevate()()
	root := folderSpec{agentSID, false}
	o, err := fs.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := w.make(dir, root); err != nil {
			return rep, err
		}
		rep.Created = true
	case err != nil:
		return rep, fmt.Errorf("%s: cannot read its permissions: %w", dir, err)
	default:
		lv, why := judge(o, true, false, false, agentSID)
		switch {
		case lv >= lvAgent:
			if !w.ours {
				return rep, fmt.Errorf("%s %s. It is not the standard data folder (...\\%s), so it is not replaced: "+
					"make it a folder only administrators can change, or leave out --config", dir, why, dataFolderName)
			}
			to, err := fs.Aside(dir)
			if err != nil {
				return rep, fmt.Errorf("%s %s, and it could not be moved out of the way (%w). Something keeps it open: "+
					"stop the fairy-agent services (Stop-Service fairy-agent, fairy-agent-helper) or restart Windows, "+
					"then run this again; or delete the folder yourself", dir, why, err)
			}
			rep.Replaced = to
			rep.Aside = append(rep.Aside, to)
			rep.note("%s %s. It was not used: it is now %s (look at it, then delete it), and a new %s was made.", dir, why, to, dir)
			if err := w.make(dir, root); err != nil {
				return rep, err
			}
		case lv == lvLeak:
			if err := w.secure(dir, root); err != nil {
				return rep, err
			}
			rep.RootLeak = true
			rep.note("%s %s: its permissions were reset.", dir, why)
		case !root.matches(o):
			if err := w.secure(dir, root); err != nil {
				return rep, err
			}
		}
	}
	// what is inside, also in a folder made a moment ago (something may have been put there meanwhile)
	if err := w.walk(dir, "", 0); err != nil {
		return rep, err
	}
	for _, f := range dataFolders {
		p := filepath.Join(dir, filepath.FromSlash(f.rel))
		if err := w.ensure(p, folderSpec{agentSID, f.write}); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

func (w *dirRepair) refuseElsewhere(p, why string) error {
	return fmt.Errorf("%s %s. %s is not the standard data folder (...\\%s), so nothing in it was moved: fix it by hand, or leave out --config",
		p, why, w.dir, dataFolderName)
}

// aside moves an object out of the way.
func (w *dirRepair) aside(p, why string) error {
	if !w.ours {
		return w.refuseElsewhere(p, why)
	}
	to, err := w.fs.Aside(p)
	if err != nil {
		return fmt.Errorf("%s %s, and it could not be moved aside (%w): stop the fairy-agent services "+
			"(Stop-Service fairy-agent, fairy-agent-helper) or restart Windows, then run this again", p, why, err)
	}
	w.rep.Aside = append(w.rep.Aside, to)
	if strings.EqualFold(p, w.cfgPath) {
		w.rep.ConfigAside = true
	}
	w.rep.note("%s %s. It was not used: it is now %s.", p, why, to)
	return nil
}

func (w *dirRepair) walk(d, rel string, depth int) error {
	if depth > repairMaxDepth {
		return fmt.Errorf("%s: folders nested too deep; delete what does not belong there and run this again", d)
	}
	names, err := w.fs.List(d)
	if err != nil {
		return fmt.Errorf("%s: cannot list it: %w", d, err)
	}
	sort.Strings(names)
	type entry struct {
		path, rel string
		o         secObj
	}
	var entries []entry
	// first the links: they are removed before anything else is touched in this folder
	for _, name := range names {
		if strings.Contains(strings.ToLower(name), asideMark) {
			continue // set aside earlier; nothing reads these
		}
		if w.seen++; w.seen > repairMaxEntries {
			return fmt.Errorf("%s holds more than %d files: delete what does not belong there and run this again", w.dir, repairMaxEntries)
		}
		p := filepath.Join(d, name)
		o, err := w.fs.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
		}
		if o.Reparse {
			if err := w.removeLink(p); err != nil {
				return err
			}
			continue
		}
		crel := name
		if rel != "" {
			crel = rel + "/" + name
		}
		entries = append(entries, entry{p, crel, o})
	}
	for _, e := range entries {
		agentZone, zoneRoot := zoneOf(e.rel)
		spec, known := knownFolder(e.rel, w.agentSID)
		wantDir := e.o.Dir
		switch {
		case known:
			wantDir = true
		case strings.EqualFold(e.path, w.cfgPath), w.isTokenName(e.rel):
			wantDir = false
		}
		lv, why := judge(e.o, wantDir, agentZone, zoneRoot, w.agentSID)
		if !e.o.Dir || !wantDir {
			if err := w.file(e.path, agentZone, lv, why); err != nil {
				return err
			}
			continue
		}
		// a folder. One of the agent's folders that the agent's account owns is taken over in place; anything
		// else that is not trusted is moved aside (Fairy's own folders are made anew afterwards).
		if lv == lvForeign || (lv == lvAgent && !(agentZone && zoneRoot)) {
			if err := w.aside(e.path, why); err != nil {
				return err
			}
			continue
		}
		if !known {
			spec = folderSpec{w.agentSID, agentZone}
		}
		if lv != lvOK || (known && !spec.matches(e.o)) {
			if err := w.secure(e.path, spec); err != nil {
				return err
			}
			if lv != lvOK {
				w.rep.note("%s %s: owner and permissions were reset.", e.path, why)
			}
		}
		if err := w.walk(e.path, e.rel, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// isTokenName: the default token files, which must be files.
func (w *dirRepair) isTokenName(rel string) bool {
	r := strings.ToLower(rel)
	return r == "token" || r == "control-token"
}

// file handles one file (or something that sits where a file belongs).
func (w *dirRepair) file(p string, agentZone bool, lv level, why string) error {
	switch {
	case lv == lvOK:
		return nil
	case agentZone || lv >= lvAgent:
		// in the agent's folders nothing is worth keeping that someone else had a hand in (logs, a download,
		// the pairing state); elsewhere what someone else could change is not believed
		return w.aside(p, why)
	}
	// only readable by someone else: the content is the administrator's, the file is made anew
	if !w.ours {
		return w.refuseElsewhere(p, why)
	}
	if err := w.fs.Rewrite(p); err != nil {
		return w.aside(p, why+" (and could not be rewritten: "+err.Error()+")")
	}
	w.rep.Leaked[p] = true
	w.rep.note("%s %s: it was written anew with the folder's permissions.", p, why)
	return nil
}

// fillDataDir puts what belongs into a data folder that repairDataDir prepared: a starter config.yaml when
// there is none, and the two token files. Existing tokens are kept (the PC stays paired with the panel) unless
// someone else could have read them, or they were moved aside with a folder or file that could not be trusted:
// then new ones are written and the PC must be paired again.
func fillDataDir(cfgPath string, rep dirReport, out io.Writer) error {
	for _, n := range rep.Notes {
		fmt.Fprintln(out, "repaired:", n)
	}
	created, err := writeNew(cfgPath, []byte(starterConfig()))
	if err != nil {
		return err
	}
	if created {
		fmt.Fprintln(out, "wrote a starter", cfgPath)
	}
	repair := false
	for _, p := range configTokenFiles(cfgPath) {
		_, statErr := os.Lstat(p)
		missing := errors.Is(statErr, os.ErrNotExist)
		exposed := rep.RootLeak || rep.Leaked[p]
		if !missing && !exposed {
			continue
		}
		tok, err := newToken()
		if err != nil {
			return err
		}
		if _, err := replaceToken(p, []byte(tok+lineEnd())); err != nil {
			return err
		}
		if missing {
			fmt.Fprintln(out, "created", p)
			repair = repair || rep.Replaced != "" || len(rep.Aside) > 0
		} else {
			fmt.Fprintln(out, "new token in", p, "(another account could read the old one; it stops working when the agent restarts)")
			repair = true
		}
	}
	switch {
	case rep.Replaced != "" || rep.ConfigAside:
		fmt.Fprintln(out, "IMPORTANT: config.yaml could not be trusted and was replaced by a starter (everything that can change this PC is off), "+
			"and the tokens are new. Pair this PC with the panel again (Re-pair), and switch the features on again there or in config.yaml.")
	case repair:
		fmt.Fprintln(out, "IMPORTANT: the tokens are new. Pair this PC with the panel again (Re-pair in the panel).")
	}
	return nil
}

// rewriteMax is the largest file rewriteFile copies (config.yaml and the secrets file are a few KB).
const rewriteMax = 4 << 20

// rewriteFile replaces a file by a new one with the same content: the new file is created next to it (so it
// takes the folder's permissions and belongs to whoever runs this) and renamed over the old one.
func rewriteFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() > rewriteMax {
		return fmt.Errorf("%s is not a regular file of at most %d bytes", path, rewriteMax)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".new-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
