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
//     on config.yaml; they refuse when it fails. So do the commands an administrator types that act on
//     config.yaml (adminDataDirTrusted).
//   - folders.ensure: one of Fairy's own folders exists as a plain folder with its permissions.
//   - repairDataDir: `install` and `setup-self-update` (an administrator). What cannot be trusted is never
//     adopted: it is moved aside and made anew; links are removed.
//
// Two rules hold for everything here that changes something (they are what closes the audit's L2 for good):
//
//  1. Nothing is ever changed inside a folder the agent's own account can write (logs\, state\,
//     update\stage\). A path through such a folder is not a fixed thing: the agent's account can turn a folder
//     there into a junction between the moment a name is looked at and the moment it is used, and an
//     administrator's change would then land somewhere else on the disk. Such a folder is only looked at. When
//     something in it is not as it should be, the whole folder is moved away by its name in the folder above
//     (which only administrators can change) and a new, empty one is made in its place.
//  2. Windows passes a folder's new permissions on to everything below it. So a folder's permissions are set
//     only while nothing below it can be changed by anyone but administrators: the agent's folders below are
//     moved out for that moment and put back afterwards, and what was moved aside does not stay below either.
//
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
	sidSystem       = "S-1-5-18"
	sidLocalService = "S-1-5-19" // the agent's account before 0.5: files it made in the agent's folders remain

	dataFolderName = "fairy-agent"
	// asideMark is in the name of everything moved aside. A data folder that cannot be trusted as a whole
	// becomes fairy-agent.untrusted-<UTC time> next to itself; single things inside a data folder that is kept
	// go into <data folder>\untrusted-<UTC time>\ (asideDir + the time).
	asideMark = ".untrusted-"
	asideDir  = "untrusted-"
	// parkMark is in the name the agent's folders have, next to the data folder, for the moment the
	// permissions of the folder above them are set.
	parkMark = ".parked-"
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

// CREATOR OWNER and CREATOR GROUP: placeholders in an entry that passes on, replaced by the creator of each
// new object.
const (
	sidCreatorOwner = "S-1-3-0"
	sidCreatorGroup = "S-1-3-1"
)

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
// Entries: deny entries are skipped (they only take rights away); for anyone but administrators, SYSTEM and
// (in its folders) the agent, a right that changes the object is lvForeign and read access is lvLeak. An entry
// kind the check does not know counts as an unknown account's.
//
// An entry that only passes on to what is created in a folder (inherit-only) counts like one that applies to
// the folder: it does not let its account change the folder today, but every file written there from now on
// (the tokens join writes, the helper's record of a pending shutdown) would be that account's to read or
// change. That differs from the folders above the data folder (collect.CheckWindowsACL skips such entries:
// C:\ and C:\ProgramData have them by design, for what users create there themselves). The one exception is
// CREATOR OWNER / CREATOR GROUP: such an entry gives whoever creates something rights on what they created,
// and who may create here is decided by the other entries.
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
		if a.Kind == collect.ACEDeny {
			continue
		}
		passesOn := a.Flags&aceInheritOnly != 0
		if passesOn && (a.SID == sidCreatorOwner || a.SID == sidCreatorGroup) {
			continue
		}
		m := plainRights(a.Mask)
		switch {
		case a.Kind == collect.ACEAllow && collect.TrustedOwner(a.SID):
		case a.Kind == collect.ACEAllow && a.SID != "" && a.SID == agentSID:
			if !agentZone && m&rtChange != 0 && passesOn {
				worse(lvAgent, "lets the agent's own account, which should only read here, change everything that is created in it (an entry that only passes on, access 0x%x)", a.Mask)
			} else if !agentZone && m&rtChange != 0 {
				worse(lvAgent, "can be changed by the agent's own account (access 0x%x), which should only read it", a.Mask)
			}
		case m&rtChange != 0 && passesOn:
			worse(lvForeign, "lets %s change everything that is created in it (an entry that only passes on, access 0x%x)", sidName(a.SID), a.Mask)
		case m&rtChange != 0:
			worse(lvForeign, "can be changed by %s (access 0x%x)", sidName(a.SID), a.Mask)
		case m&rtReadData != 0 && passesOn:
			worse(lvLeak, "lets %s read everything that is created in it (an entry that only passes on, access 0x%x)", sidName(a.SID), a.Mask)
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
//
// A folder that SYSTEM owns is taken as it is too (specOwner). Real PCs have one: update\stage was made by
// the agent itself while it still ran as LocalSystem, so it belongs to SYSTEM and not to Administrators.
// Nothing is gained by changing that: SYSTEM is the account the helper and the updater run as, the folder's
// own entries give it full control, and all an owner can do beyond its entries is change the permissions,
// which that full control includes. Setting the owner there was a write (and a "repaired:" line) on every
// such PC for no gain in safety. A folder owned by anyone else is still corrected or replaced.
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
	l := []collect.ACE{{Kind: collect.ACEAllow, Flags: oici, SID: sidSystem, Mask: rtFileAll},
		{Kind: collect.ACEAllow, Flags: oici, SID: sidAdmins, Mask: rtFileAll}}
	if s.agentSID != "" {
		l = append(l, collect.ACE{Kind: collect.ACEAllow, Flags: oici, SID: s.agentSID, Mask: s.agentMask()})
	}
	return l
}

// specOwner: the owners with which one of Fairy's own folders is left as it is (see folderSpec).
func specOwner(sid string) bool { return sid == sidAdmins || sid == sidSystem }

// matches reports whether a folder already has this security (then nothing is written): exactly these
// entries, nothing taken from the folder above, and Administrators or SYSTEM as its owner.
func (s folderSpec) matches(o secObj) bool {
	want := s.aces()
	if !o.Dir || o.Reparse || o.NullDACL || !o.Protected || !specOwner(o.Owner) || len(o.ACEs) != len(want) {
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

// ownerOnly reports whether a folder differs from the spec in its owner alone.
func (s folderSpec) ownerOnly(o secObj) bool {
	if specOwner(o.Owner) {
		return false
	}
	o.Owner = sidAdmins
	return s.matches(o)
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
	// Secure sets owner and permissions on the opened object; it refuses a link. For a folder Windows passes
	// the permissions on to everything below it, so the caller first makes sure that nothing below can be
	// changed by anyone but administrators (folders.secure does).
	Secure(path, sddl string) error
	// SetOwner makes Administrators the owner of the opened object and changes nothing else: nothing is passed
	// on to what is inside. It refuses a link.
	SetOwner(path string) error
	// Move renames an object as it is (a link as the link, a folder with everything in it) to a name that
	// does not exist yet, on the same drive. Both names are in folders only administrators can change.
	Move(from, to string) error
	// Stamp is the time that goes into the names of things moved aside (UTC, yyyymmdd-hhmmss).
	Stamp() string
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

// adminDataDirTrusted is the data folder check (dataDirTrusted) for the commands an administrator types on the
// machine and that act on what config.yaml says: `update` (the repository that is asked, the token file read
// for the health check, the result written into update\), `config set`, `secret set` (the secrets file
// config.yaml names is written), `bmc-relay add` and `fans-auto` (the BMC address and the secrets file).
// A config.yaml someone else prepared must not steer an administrator's command: it is refused with the same
// message join gives, before config.yaml is read. Like dataDirTrusted itself this does nothing off Windows.
//
// Someone who is not an administrator is not checked: with ordinary rights the folder's owner and permissions
// cannot be read (that would say nothing about the folder), such a run has no rights a prepared config.yaml
// could borrow, and the commands that write refuse it themselves ("run it in an Administrator PowerShell")
// before they read anything.
func adminDataDirTrusted(cfgPath string) error {
	if !isAdmin() {
		return nil
	}
	return dataDirTrusted(cfgPath)
}

// adminUpdateDirTrusted is adminDataDirTrusted for `apply-update` typed by an administrator: the same check the
// updater service makes before it opens anything (updateDirTrusted: the data folder, config.yaml, the token
// files and update\, where the installer writes its log and result). Before this, the typed command read
// config.yaml and opened update\installer.log first and was refused afterwards.
func adminUpdateDirTrusted(cfgPath string) error {
	if !isAdmin() {
		return nil
	}
	return updateDirTrusted(cfgPath)
}

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
	// keepLinks: a link found in a folder is an error instead of being removed (a --config folder that is not
	// Fairy's own).
	keepLinks bool
	// agentIsSelf: this process is the agent itself, still running as LocalSystem and moving its own service
	// to the low-rights account (the self-migration from 0.4). The agent's account is then nobody else: what
	// only it can change below a folder does not keep that folder's permissions from being set.
	agentIsSelf bool
	// hint is added to a refusal: what to run to have the folder repaired ("" inside the repair itself).
	hint string
	// note is told what was changed besides permissions (may be nil).
	note func(format string, a ...any)
}

func (f folders) say(format string, a ...any) {
	if f.note != nil {
		f.note(format, a...)
	}
}

// ensure makes sure one of Fairy's folders exists as a plain folder with its security. A folder that is
// missing is created with it in the same call. An existing one must not be a link, a file, or controlled by
// someone other than administrators and the agent's account (then it is refused: only install /
// setup-self-update replace such a folder). What differs is corrected on the opened folder, as far as the two
// rules at the top of this file allow (settle). The folder above must exist.
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
	return f.settle(path, spec, o, false)
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
	return f.settle(path, spec, o, made)
}

// settle brings an existing folder of Fairy's own (o is what it looks like; it is not someone else's) to its
// spec. fresh: this call created it a moment ago.
//
//   - Only the owner differs: Administrators become the owner on the opened folder. Nothing is passed on.
//   - The permissions differ, and it is one of the agent's own folders: refused. Windows would pass the new
//     permissions on to everything inside, where the agent's account can put a link at any moment (rule 1).
//     install / setup-self-update replace such a folder as a whole. A folder made a moment ago is still empty
//     and gets them.
//   - The permissions differ on a folder only administrators change: set on the opened folder, after a look
//     that nothing below it could be changed by someone else (secure, rule 2).
func (f folders) settle(path string, spec folderSpec, o secObj, fresh bool) error {
	switch {
	case spec.matches(o):
		return nil
	case spec.ownerOnly(o):
		return f.own(path, spec)
	case spec.write && !fresh:
		return fmt.Errorf("%s does not have the permissions of one of fairy-agent's own folders, and they are not set in place "+
			"(Windows would pass them on to everything inside, where the agent's own account can put links)%s", path, repairHint)
	}
	return f.secure(path, spec)
}

// own makes Administrators the owner of a folder whose permissions already are as they should be. Only the
// owner is set, on the opened folder: nothing is passed on to what is inside.
func (f folders) own(path string, spec folderSpec) error {
	if err := f.fs.SetOwner(path); err != nil {
		return fmt.Errorf("making Administrators the owner of %s: %w", path, err)
	}
	o, err := f.fs.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: cannot read its permissions: %w", path, err)
	}
	if !spec.matches(o) {
		return fmt.Errorf("%s is still not as it should be after Administrators were made its owner%s", path, f.hint)
	}
	return nil
}

// secure sets the spec on the opened folder and checks the result. Windows passes a folder's permissions on to
// everything below it, and nothing a link points to, and nothing someone else could swap for a link, may be
// reached that way. So first comes a look at everything below (it changes nothing): a link, or anything
// someone other than administrators owns or may change, and nothing is set. The repair moves such things out
// of the way before it comes here; everyone else gets the refusal with the way out.
func (f folders) secure(path string, spec folderSpec) error {
	var seen int
	if why := f.below(path, spec.agentSID, 0, &seen); why != "" {
		return fmt.Errorf("%s needs its permissions set, which Windows passes on to everything inside, and %s. Nothing was changed%s", path, why, f.hint)
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

// below looks for anything under folder d that is a link, or that someone other than administrators owns or
// may change: "" when there is nothing of the kind. It only reads. With agentIsSelf the agent's own account is
// not "someone other".
func (f folders) below(d, agentSID string, depth int, seen *int) string {
	if depth > repairMaxDepth {
		return fmt.Sprintf("%s holds folders nested more than %d deep", d, repairMaxDepth)
	}
	names, err := f.fs.List(d)
	if err != nil {
		return fmt.Sprintf("%s cannot be listed (%v)", d, err)
	}
	sort.Strings(names)
	for _, name := range names {
		if *seen++; *seen > repairMaxEntries {
			return fmt.Sprintf("%s holds more than %d files", d, repairMaxEntries)
		}
		p := filepath.Join(d, name)
		o, err := f.fs.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("%s cannot be looked at (%v)", p, err)
		}
		if lv, why := judge(o, o.Dir, false, false, agentSID); lv == lvForeign || (lv == lvAgent && !f.agentIsSelf) {
			return p + " " + why
		}
		if o.Dir {
			if why := f.below(p, agentSID, depth+1, seen); why != "" {
				return why
			}
		}
	}
	return ""
}

// removeLink removes one link (the link itself, never what it points to). The folder it is in is one only
// administrators can change, so the name stands for the same thing from the look to the removal.
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
	Aside       []string        // what was moved aside (where it is now)
	Zones       []string        // the agent's own folders that were replaced by new, empty ones ("logs", "state", "update/stage")
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
	stamp    string // the time in the names of what this run moves
	asideAt  string // <dir>\untrusted-<stamp>, once this run has made it
}

const stopServices = "stop the fairy-agent services (Stop-Service fairy-agent, fairy-agent-helper) or restart Windows, then run this again"

// repairDataDir makes the data folder safe to use (as an administrator: install, setup-self-update).
//
//   - The folders above must not be replaceable by others; otherwise it stops.
//   - A data folder that does not exist is created with its final permissions in the same call.
//   - A data folder that someone else owns or can change is not adopted: it is moved aside as a whole
//     (fairy-agent.untrusted-<time>) and a new one is made. Whoever prepared it may still hold it open, and
//     an open handle keeps its rights whatever is set afterwards; a new folder has no such history.
//   - Inside a folder that is kept, everything that only administrators can change is gone through by name
//     (closed): links are removed, what someone else (or, there, the agent's account) owns or can change is
//     moved aside into <data folder>\untrusted-<time>\, what someone else could only read is rewritten as a
//     new file, and a folder's permissions are reset where they differ.
//   - The agent's own folders (logs\, state\, update\stage\) are not gone through that way: each is looked at
//     and, when anything about it is not as it should be, moved aside as a whole and made anew (zone).
//   - Fairy's own folders are created with their final permissions where they are missing.
//
// Only a folder named fairy-agent is repaired this way; with another --config folder it reports what is wrong
// and moves nothing.
func repairDataDir(fs dataFS, cfgPath, agentSID string) (dirReport, error) {
	dir := filepath.Dir(cfgPath)
	rep := dirReport{Leaked: map[string]bool{}}
	ours := strings.EqualFold(filepath.Base(dir), dataFolderName)
	w := &dirRepair{folders: folders{fs: fs, keepLinks: !ours, note: rep.note}, dir: dir, cfgPath: cfgPath,
		agentSID: agentSID, rep: &rep, ours: ours, stamp: fs.Stamp()}
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
		if lv, why := judge(o, true, false, false, agentSID); lv >= lvAgent {
			if !w.ours {
				return rep, fmt.Errorf("%s %s. It is not the standard data folder (...\\%s), so it is not replaced: "+
					"make it a folder only administrators can change, or leave out --config", dir, why, dataFolderName)
			}
			to, err := w.free(dir + asideMark + w.stamp)
			if err == nil {
				err = fs.Move(dir, to)
			}
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
		}
	}
	// What is inside, also in a folder made a moment ago (something may have been put there meanwhile). First
	// everything only administrators can change, each folder's own permissions after what is below it and the
	// data folder's last; then the agent's own folders, each as a whole.
	if o, err = fs.Stat(dir); err != nil {
		return rep, fmt.Errorf("%s: cannot read its permissions: %w", dir, err)
	}
	if err := w.closed(dir, "", 0, o); err != nil {
		return rep, err
	}
	for _, z := range agentZones {
		if err := w.zone(z); err != nil {
			return rep, err
		}
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

// free returns base, or base-2, base-3 ..., whichever name does not exist yet.
func (w *dirRepair) free(base string) (string, error) {
	to := base
	for i := 2; ; i++ {
		if _, err := w.fs.Stat(to); errors.Is(err, os.ErrNotExist) {
			return to, nil
		}
		if i > 50 {
			return "", fmt.Errorf("no free name like %s", base)
		}
		to = fmt.Sprintf("%s-%d", base, i)
	}
}

// moveAside moves one thing below the data folder (rel) into <data folder>\untrusted-<time>\, which this run
// makes when it first needs it: a folder of its own that only administrators and SYSTEM can open. The thing is
// renamed as it is, a link as the link and a folder with everything in it; nothing in it is opened.
func (w *dirRepair) moveAside(p, rel string) (string, error) {
	if w.asideAt == "" {
		only := folderSpec{} // administrators and SYSTEM, nobody else
		base := filepath.Join(w.dir, asideDir+w.stamp)
		for i := 1; ; i++ {
			name := base
			if i > 1 {
				name = fmt.Sprintf("%s-%d", base, i)
			}
			err := w.fs.Mkdir(name, only.sddl())
			if errors.Is(err, os.ErrExist) && i < 50 {
				continue
			}
			if err != nil {
				return "", fmt.Errorf("creating %s: %w", name, err)
			}
			o, err := w.fs.Stat(name)
			if err != nil {
				return "", fmt.Errorf("%s: cannot read its permissions: %w", name, err)
			}
			if err := w.settle(name, only, o, true); err != nil {
				return "", err
			}
			w.asideAt = name
			break
		}
	}
	to, err := w.free(filepath.Join(w.asideAt, strings.ReplaceAll(rel, "/", "-")))
	if err != nil {
		return "", err
	}
	if err := w.fs.Move(p, to); err != nil {
		return "", err
	}
	return to, nil
}

// aside moves one thing in a folder only administrators can change out of the way.
func (w *dirRepair) aside(p, rel, why string) error {
	if !w.ours {
		return w.refuseElsewhere(p, why)
	}
	to, err := w.moveAside(p, rel)
	if err != nil {
		return fmt.Errorf("%s %s, and it could not be moved aside (%w): %s", p, why, err, stopServices)
	}
	w.rep.Aside = append(w.rep.Aside, to)
	if strings.EqualFold(p, w.cfgPath) {
		w.rep.ConfigAside = true
	}
	w.rep.note("%s %s. It was not used: it is now %s.", p, why, to)
	return nil
}

// isAsideDir: a folder an earlier run (or this one) moved things into, directly in the data folder. It is
// never looked into again.
func isAsideDir(rel string) bool {
	return !strings.Contains(rel, "/") && strings.HasPrefix(strings.ToLower(rel), asideDir)
}

// closed deals with one folder that only administrators can change (o is what it looks like) and with
// everything below it of the same kind. The agent's own folders are not entered here (zone deals with each as
// a whole), and neither is what was moved aside. Things in the folder are dealt with by name; that is sound
// exactly because nobody but administrators can change what a name in this folder stands for.
func (w *dirRepair) closed(d, rel string, depth int, o secObj) error {
	if depth > repairMaxDepth {
		return fmt.Errorf("%s: folders nested too deep; delete what does not belong there and run this again", d)
	}
	names, err := w.fs.List(d)
	if err != nil {
		return fmt.Errorf("%s: cannot list it: %w", d, err)
	}
	sort.Strings(names)
	type entry struct {
		path, rel, why string
		o              secObj
	}
	var subs, leaks []entry
	for _, name := range names {
		crel := name
		if rel != "" {
			crel = rel + "/" + name
		}
		if _, zoneRoot := zoneOf(crel); zoneRoot || isAsideDir(crel) {
			continue
		}
		if w.seen++; w.seen > repairMaxEntries {
			return fmt.Errorf("%s holds more than %d files: delete what does not belong there and run this again", w.dir, repairMaxEntries)
		}
		p := filepath.Join(d, name)
		co, err := w.fs.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
		}
		if co.Reparse {
			if err := w.removeLink(p); err != nil {
				return err
			}
			continue
		}
		wantDir := co.Dir
		if _, known := knownFolder(crel, w.agentSID); known {
			wantDir = true
		} else if strings.EqualFold(p, w.cfgPath) || w.isTokenName(crel) {
			wantDir = false
		}
		lv, why := judge(co, wantDir, false, false, w.agentSID)
		switch {
		case lv >= lvAgent:
			// someone else, or the agent's account (which only reads here), owns it or may change it, or it is
			// not the kind of thing that belongs under this name: not believed, moved aside as it is
			if err := w.aside(p, crel, why); err != nil {
				return err
			}
		case co.Dir:
			subs = append(subs, entry{p, crel, why, co})
		case lv == lvLeak:
			leaks = append(leaks, entry{p, crel, why, co})
		}
	}
	for _, s := range subs {
		if err := w.closed(s.path, s.rel, depth+1, s.o); err != nil {
			return err
		}
	}
	// the folder's own permissions, now that nothing below it is left that someone else could change
	if err := w.settleClosed(d, rel, o); err != nil {
		return err
	}
	// files someone else could only read: the content is the administrator's, the file is made anew (after the
	// folder has its permissions, which the new file takes)
	for _, l := range leaks {
		if !w.ours {
			return w.refuseElsewhere(l.path, l.why)
		}
		if err := w.fs.Rewrite(l.path); err != nil {
			if err := w.aside(l.path, l.rel, l.why+" (and could not be rewritten: "+err.Error()+")"); err != nil {
				return err
			}
			continue
		}
		w.rep.Leaked[l.path] = true
		w.rep.note("%s %s: it was written anew with the folder's permissions.", l.path, l.why)
	}
	return nil
}

// settleClosed gives a folder that only administrators can change its owner and permissions where they differ
// (o is what it looked like; nobody else can change it, at most read it). Windows passes the permissions on to
// everything below, so the agent's own folders below it, and what was moved aside, are moved out of the data
// folder for that moment (park) and put back afterwards: nothing the agent's account can write is below the
// folder while its permissions are set (rule 2 at the top of this file).
func (w *dirRepair) settleClosed(d, rel string, o secObj) error {
	spec, known := knownFolder(rel, w.agentSID)
	if rel == "" {
		spec, known = folderSpec{w.agentSID, false}, true
	}
	if !known {
		spec = folderSpec{w.agentSID, false}
	}
	lv, why := judge(o, true, false, false, w.agentSID)
	switch {
	case lv == lvOK && (!known || spec.matches(o)):
		return nil
	case lv == lvOK && spec.ownerOnly(o):
		return w.own(d, spec)
	}
	parked, err := w.park(d, rel)
	if err != nil {
		return err
	}
	err = w.secure(d, spec)
	if uerr := w.unpark(parked); uerr != nil {
		if err != nil {
			return fmt.Errorf("%w; and %w", err, uerr)
		}
		return uerr
	}
	if err != nil {
		return err
	}
	if lv != lvOK {
		if rel == "" {
			w.rep.RootLeak = true
			w.rep.note("%s %s: its permissions were reset.", d, why)
		} else {
			w.rep.note("%s %s: owner and permissions were reset.", d, why)
		}
	}
	return nil
}

type parkedDir struct{ from, to string }

// park moves everything below folder d that the agent's account (or whoever owned what was moved aside) can
// write out of the data folder, to names next to it: the agent's own folders below d and, for the data folder
// itself, the untrusted-<time> folders. They are renamed as they are; nothing in them is opened.
func (w *dirRepair) park(d, rel string) ([]parkedDir, error) {
	var from []string
	for _, z := range agentZones {
		if rel == "" || strings.HasPrefix(z, strings.ToLower(rel)+"/") {
			from = append(from, z)
		}
	}
	if rel == "" {
		names, err := w.fs.List(d)
		if err != nil {
			return nil, fmt.Errorf("%s: cannot list it: %w", d, err)
		}
		sort.Strings(names)
		for _, name := range names {
			if isAsideDir(name) {
				from = append(from, name)
			}
		}
	}
	var out []parkedDir
	for _, r := range from {
		p := filepath.Join(w.dir, filepath.FromSlash(r))
		if _, err := w.fs.Stat(p); errors.Is(err, os.ErrNotExist) {
			continue
		}
		to, err := w.free(w.dir + parkMark + w.stamp + "-" + strings.ReplaceAll(r, "/", "-"))
		if err == nil {
			err = w.fs.Move(p, to)
		}
		if err != nil {
			err = fmt.Errorf("the permissions of %s have to be set, which Windows passes on to everything inside; %s is moved out for that "+
				"moment, and that failed (%w): %s", d, p, err, stopServices)
			if uerr := w.unpark(out); uerr != nil {
				err = fmt.Errorf("%w; and %w", err, uerr)
			}
			return nil, err
		}
		out = append(out, parkedDir{p, to})
	}
	return out, nil
}

// unpark puts back what park moved.
func (w *dirRepair) unpark(parked []parkedDir) error {
	var failed []string
	for i := len(parked) - 1; i >= 0; i-- {
		if err := w.fs.Move(parked[i].to, parked[i].from); err != nil {
			failed = append(failed, fmt.Sprintf("%s could not be put back as %s (%v): move it back yourself (Move-Item), then run this again",
				parked[i].to, parked[i].from, err))
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "; "))
	}
	return nil
}

// zone deals with one of the agent's own folders (logs\, state\, update\stage\) as a whole. Nothing inside it
// is changed, by name or by what Windows passes on (rule 1 at the top of this file): the agent's account can
// turn any folder in there into a junction between the look at a name and its use. The folder is looked at
// (inside), and when it or anything in it is not as it should be, it is moved aside as it is, by its name in
// the folder above, and a new, empty one is made with its permissions in the create call.
//
// The look itself can be led astray the same way; it only reads. The worst that follows from a wrong look is
// that the folder is replaced although it was fine, or that it stays with a link in it, which nothing with
// more rights than the agent's own account ever follows.
func (w *dirRepair) zone(rel string) error {
	p := filepath.Join(w.dir, filepath.FromSlash(rel))
	spec := folderSpec{w.agentSID, true}
	o, err := w.fs.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil // repairDataDir makes it, with its permissions
	}
	if err != nil {
		return fmt.Errorf("%s: cannot read its permissions: %w", p, err)
	}
	why := ""
	if lv, y := judge(o, true, true, true, w.agentSID); lv == lvForeign {
		why = y
	} else if !spec.matches(o) && !spec.ownerOnly(o) {
		why = "does not have the permissions of the agent's own folders"
		if lv != lvOK {
			why += " (it " + y + ")"
		}
	} else {
		var seen int
		why = w.inside(p, 0, &seen)
	}
	if why == "" {
		if spec.matches(o) {
			return nil
		}
		// only the owner differs (the folder was made by the agent itself, or by an agent that ran as LocalSystem):
		// set on the opened folder, nothing is passed on to what is inside
		err := w.own(p, spec)
		if err == nil {
			w.rep.note("%s was owned by %s: Administrators were made its owner.", p, sidName(o.Owner))
			return nil
		}
		why = "could not be given Administrators as its owner (" + err.Error() + ")"
	}
	if !w.ours {
		return w.refuseElsewhere(p, why)
	}
	to, err := w.moveAside(p, rel)
	if err != nil {
		return fmt.Errorf("%s %s. Nothing inside one of the agent's own folders is changed in place; the folder is moved aside as a whole, "+
			"and that failed (%w): %s", p, why, err, stopServices)
	}
	w.rep.Aside = append(w.rep.Aside, to)
	w.rep.Zones = append(w.rep.Zones, rel)
	w.rep.note("%s %s. Nothing inside one of the agent's own folders is changed in place, so the whole folder was moved: it is now %s "+
		"(look at it, then delete it), and a new, empty %s was made. %s", p, why, to, p, zoneLoss(rel))
	return w.make(p, spec)
}

// zoneLoss says what the owner is without after one of the agent's folders was replaced by an empty one.
func zoneLoss(rel string) string {
	switch strings.ToLower(rel) {
	case "logs":
		return "The agent starts a new log; the old log files are in the moved folder."
	case "state":
		return "The pairing state went with it: a join code that was waiting no longer works, and the agent does not know the panel's " +
			"address until the panel's Add host / Re-pair command is run on this PC again (with only_from_panel on, it refuses the panel until then). " +
			"The tokens are not affected."
	case "update/stage":
		return "A downloaded update that was waiting to be installed went with it: press Update in the panel again."
	}
	return ""
}

// inside looks through one of the agent's own folders: "" when everything in it is something the agent's
// account (or an administrator) made and nobody else can change or read. It only reads.
func (w *dirRepair) inside(d string, depth int, seen *int) string {
	if depth > repairMaxDepth {
		return fmt.Sprintf("holds folders nested more than %d deep (%s)", repairMaxDepth, d)
	}
	names, err := w.fs.List(d)
	if err != nil {
		return fmt.Sprintf("cannot be looked through (%s: %v)", d, err)
	}
	sort.Strings(names)
	for _, name := range names {
		if *seen++; *seen > repairMaxEntries {
			return fmt.Sprintf("holds more than %d files", repairMaxEntries)
		}
		p := filepath.Join(d, name)
		o, err := w.fs.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Sprintf("holds %s, which cannot be looked at (%v)", p, err)
		}
		if lv, why := judge(o, o.Dir, true, false, w.agentSID); lv != lvOK {
			return fmt.Sprintf("holds %s, which %s", p, why)
		}
		if o.Dir {
			if why := w.inside(p, depth+1, seen); why != "" {
				return why
			}
		}
	}
	return ""
}

// isTokenName: the default token files, which must be files.
func (w *dirRepair) isTokenName(rel string) bool {
	r := strings.ToLower(rel)
	return r == "token" || r == "control-token"
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

// loadTrustedConfig reads config.yaml for a service that runs as LocalSystem (the helper): only after check
// has accepted the file and its folder. Before, the helper read and parsed config.yaml first and its folder was
// checked afterwards (in helper.Run): a file someone else had prepared was read whole into a LocalSystem
// process, and when it did not parse, the error, with words of the file in it, went to the Application event
// log. helper.Run still makes the check again before it serves anything.
func loadTrustedConfig(cfgPath string, check func(cfgPath string) error) (*agent.Config, error) {
	if err := check(cfgPath); err != nil {
		return nil, fmt.Errorf("not serving anything: %w", err)
	}
	return agent.Load(cfgPath)
}

// repairOrRemoveService is the data folder step of a first `install`. The service has to exist before the
// folder is repaired (the folder's permissions name the service's account, which Windows creates with the
// service), and it starts with Windows. So when the repair fails, the service is removed again: left
// installed, it would start at the next boot on a data folder that could not be made safe, with whatever
// config.yaml and tokens are in it. Whoever prepared the folder can make the repair fail (a file held open
// keeps the folder from being moved aside).
func repairOrRemoveService(service string, repair, removeService func() error) error {
	err := repair()
	if err == nil {
		return nil
	}
	if rerr := removeService(); rerr != nil {
		return fmt.Errorf("%w. The %s service was created before that and could NOT be removed again (%v): it starts with Windows, "+
			"on a data folder that is not safe. Remove it: & \"C:\\Program Files\\Fairy\\fairy-agent.exe\" uninstall", err, service, rerr)
	}
	return fmt.Errorf("%w. The %s service, created a moment ago, was removed again (it would have started with Windows on a data folder "+
		"that is not safe). Run the installer once more when this is solved", err, service)
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
