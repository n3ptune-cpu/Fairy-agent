//go:build windows

package main

// The Win32 side of datadir.go. Every object is opened itself (FILE_FLAG_OPEN_REPARSE_POINT: a junction or
// symbolic link is opened as the link, never followed), its kind is read from that handle, and security is read
// and set on that handle (GetSecurityInfo / SetSecurityInfo), never by name: what was checked is what is
// changed, and nothing a link points to is ever given new permissions.
//
// What that does not cover, and datadir.go therefore rules out (its two rules): a full path is resolved name
// by name, so opening "the object itself" only holds for the last name; a folder in the middle that the
// agent's account can turn into a junction leads the whole path elsewhere. And SetSecurityInfo on a folder
// does more than set that folder: "the system automatically propagates any inheritable access control entries
// (ACEs) to existing child objects" (Microsoft, SetSecurityInfo). Whether that walk stops at a junction is
// not documented, so it is never started on a folder with anything below that someone else can change.

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
)

// dataDirTrusted is checked by join before it writes anything, and by the commands an administrator types that
// act on config.yaml (adminDataDirTrusted).
var dataDirTrusted = func(cfgPath string) error { return trustedDataDir(cfgPath) }

// updateDirTrusted is the check before apply-update reads or opens anything: the data folder and update\.
var updateDirTrusted = func(cfgPath string) error { return trustedDataDir(cfgPath, "update") }

// tokensInConfigDir: join writes token files only into the config folder.
var tokensInConfigDir = true

func init() {
	// the helper (LocalSystem) checks config.yaml and its folder before it serves what that file switches on
	// (its own folder helper\ is checked where it is used: the log and the record of a pending shutdown)
	helper.TrustedConfig = func(cfgPath string) error { return trustedDataDir(cfgPath) }
	// join writes the pairing state relative to the opened state folder (datadir_state.go)
	writeStateIn = writePairingState
	folderItself = openFolderItself
}

// openFolderItself opens dir itself (FILE_FLAG_OPEN_REPARSE_POINT: a junction is opened as the junction, not
// followed), refuses a link, and returns the folder's identity (volume and file id) as read from that handle.
// The handle stays open until done: while it is, no other folder can get that file id.
func openFolderItself(dir string) (os.FileInfo, func(), error) {
	h, info, err := openObject(dir, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(h), dir) // owns the handle from here
	if f == nil {
		windows.CloseHandle(h)
		return nil, nil, fmt.Errorf("%s: cannot use the opened folder", dir)
	}
	if isLink(info) || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		f.Close()
		return nil, nil, fmt.Errorf("%s is not a plain folder (a link, or a file): nothing was written%s", dir, repairHint)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, &os.PathError{Op: "stat", Path: dir, Err: err}
	}
	return fi, func() { f.Close() }, nil
}

// agentSIDString is the agent's service SID ("" while the service does not exist).
func agentSIDString() string {
	sid, _, _, err := windows.LookupSID("", agentAccount)
	if err != nil {
		return ""
	}
	return sid.String()
}

// trustedDataDir is checkDataDir on this machine: nil when config.yaml, its folder and alsoDirs can only be
// changed by administrators and SYSTEM. Read-only; any account that may read the folder can run it.
func trustedDataDir(cfgPath string, alsoDirs ...string) error {
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	if p := collect.ExecPathProblem(abs, true); p != "" {
		return fmt.Errorf("%s %s", abs, p)
	}
	if err := checkDataDir(winFS{}, abs, agentSIDString(), alsoDirs...); err != nil {
		return fmt.Errorf("the data folder cannot be trusted: %w%s", err, repairHint)
	}
	return nil
}

type winFS struct{}

// openObject opens path itself, without following a link, and reads what kind of object it is.
func openObject(path string, access uint32) (windows.Handle, windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, info, err
	}
	h, err := windows.CreateFile(p, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, info, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return 0, info, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	return h, info, nil
}

func isLink(info windows.ByHandleFileInformation) bool {
	return info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// handleSecurity reads owner and permissions from an open handle.
func handleSecurity(h windows.Handle, o *secObj) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return errors.New("cannot read its owner")
	}
	o.Owner = owner.String()
	if ctrl, _, err := sd.Control(); err == nil {
		o.Protected = ctrl&windows.SE_DACL_PROTECTED != 0
	}
	dacl, _, err := sd.DACL()
	o.NullDACL = errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) || (err == nil && dacl == nil)
	if err != nil && !o.NullDACL {
		return err
	}
	if !o.NullDACL {
		// the DACL as stored (ACL header, then the entries), read by the pure collect.ParseDACL
		size := *(*uint16)(unsafe.Add(unsafe.Pointer(dacl), 2))
		if o.ACEs, err = collect.ParseDACL(unsafe.Slice((*byte)(unsafe.Pointer(dacl)), size)); err != nil {
			return err
		}
	}
	return nil
}

func (winFS) Stat(path string) (secObj, error) {
	h, info, err := openObject(path, windows.READ_CONTROL)
	if err != nil {
		return secObj{}, err
	}
	defer windows.CloseHandle(h)
	o := secObj{Dir: info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, Reparse: isLink(info), Links: info.NumberOfLinks}
	if err := handleSecurity(h, &o); err != nil {
		return o, &os.PathError{Op: "read the permissions of", Path: path, Err: err}
	}
	return o, nil
}

func (winFS) List(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(ents))
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names, nil
}

// Mkdir creates one folder with sddl as its security descriptor in the create call itself, so there is no
// moment in which the folder has the permissions it would inherit (C:\ProgramData lets ordinary users add
// files to a new folder).
func (winFS) Mkdir(path, sddl string) error {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	mk := func(sddl string) error {
		sd, err := windows.SecurityDescriptorFromString(sddl)
		if err != nil {
			return err
		}
		sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
		return windows.CreateDirectory(p, sa)
	}
	err = mk(sddl)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) { // this account may not name Administrators as owner here: the caller sets it afterwards
		if rest, ok := cutOwner(sddl); ok {
			err = mk(rest)
		}
	}
	if err != nil {
		return &os.PathError{Op: "mkdir", Path: path, Err: err}
	}
	return nil
}

// cutOwner removes the owner part ("O:BA") from the start of an SDDL string.
func cutOwner(sddl string) (string, bool) {
	const o = "O:BA"
	if len(sddl) > len(o) && sddl[:len(o)] == o {
		return sddl[len(o):], true
	}
	return sddl, false
}

// Secure sets the owner (when sddl names one) and the protected DACL of sddl on the opened object. It refuses
// a link. For a folder Windows passes the inheritable entries on to everything below it (the handle may list
// the folder for that): the caller has made sure that nothing below can be changed by anyone but
// administrators (folders.secure).
//
// When this account may not make Administrators the owner (the object does not allow it, or Windows does not
// accept that owner from this account), the permissions are set all the same and the owner stays; the caller
// looks at the result.
func (winFS) Secure(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if dacl == nil {
		return errors.New("no permission list to set") // never a NULL DACL (everyone full access)
	}
	owner, _, _ := sd.Owner()
	const base = windows.READ_CONTROL | windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY
	const daclInfo = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	set := func(withOwner bool) error {
		access, info, o := uint32(base), windows.SECURITY_INFORMATION(daclInfo), (*windows.SID)(nil)
		if withOwner {
			access |= windows.WRITE_OWNER
			info |= windows.OWNER_SECURITY_INFORMATION
			o = owner
		}
		h, fi, err := openObject(path, access)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)
		if isLink(fi) {
			return fmt.Errorf("%s is a link (a junction or symbolic link): its permissions are not changed%w", path, errIsLink)
		}
		if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, info, o, nil, dacl, nil); err != nil {
			return &os.PathError{Op: "set the permissions of", Path: path, Err: err}
		}
		return nil
	}
	if owner == nil {
		return set(false)
	}
	err = set(true)
	if err != nil && !errors.Is(err, errIsLink) && !errors.Is(err, os.ErrNotExist) {
		if err2 := set(false); err2 == nil {
			return nil
		}
	}
	return err
}

// errIsLink marks Secure's refusal of a link (it adds nothing to the message).
var errIsLink = linkError{}

type linkError struct{}

func (linkError) Error() string { return "" }

// SetOwner makes Administrators the owner of the opened object, which must not be a link. Only the owner is
// set: SetSecurityInfo passes entries on to what is inside a folder when the DACL or SACL is set, and neither
// is touched here.
func (winFS) SetOwner(path string) error {
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	h, fi, err := openObject(path, windows.READ_CONTROL|windows.WRITE_OWNER)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	if isLink(fi) {
		return fmt.Errorf("%s is a link (a junction or symbolic link): its owner is not changed", path)
	}
	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return &os.PathError{Op: "set the owner of", Path: path, Err: err}
	}
	return nil
}

// Move renames from to to, which must not exist (MoveFileEx without MOVEFILE_REPLACE_EXISTING: an existing
// name is an error, whatever it is). The last name of from is what is renamed: a junction or symbolic link is
// moved as the link, a folder with everything in it, and nothing in it is opened. Windows refuses to rename a
// folder while a file in it is open; the caller says what to stop.
func (winFS) Move(from, to string) error {
	f, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return err
	}
	t, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(f, t, 0); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}

// Stamp is the time in the names of what is moved aside.
func (winFS) Stamp() string { return time.Now().UTC().Format("20060102-150405") }

// Remove deletes a link: os.Remove takes away the junction or symbolic link itself, never what it points to.
// The look and the removal are two calls by name; the caller only removes links in folders that nobody but
// administrators can change, where the name stands for the same thing in both.
func (winFS) Remove(path string) error {
	h, info, err := openObject(path, windows.READ_CONTROL)
	if err != nil {
		return err
	}
	windows.CloseHandle(h)
	if !isLink(info) {
		return fmt.Errorf("%s is not a link", path)
	}
	return os.Remove(path)
}

// Rewrite replaces a file by a new one with the same content: the new file is created in the folder (whose
// permissions it takes) and renamed over the old one.
func (winFS) Rewrite(path string) error { return rewriteFile(path) }

// Elevate switches on the privileges an administrator holds (disabled) for taking over objects whose
// permissions shut administrators out, and returns a function that switches off those it switched on.
func (winFS) Elevate() func() {
	var on []string
	for _, name := range []string{"SeBackupPrivilege", "SeRestorePrivilege", "SeTakeOwnershipPrivilege"} {
		if changed, err := setPrivilege(name, true); err == nil && changed {
			on = append(on, name)
		}
	}
	return func() {
		for _, name := range on {
			_, _ = setPrivilege(name, false)
		}
	}
}

// setPrivilege switches one privilege of this process's token on or off. changed reports whether that changed
// anything (false when the token does not hold the privilege, or it already was in that state).
func setPrivilege(name string, on bool) (changed bool, err error) {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		return false, err
	}
	defer tok.Close()
	var luid windows.LUID
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return false, err
	}
	if err := windows.LookupPrivilegeValue(nil, n, &luid); err != nil {
		return false, err
	}
	tp := windows.Tokenprivileges{PrivilegeCount: 1}
	tp.Privileges[0].Luid = luid
	if on {
		tp.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	}
	// the previous state lists the privileges this call changed: one entry, or none
	var old windows.Tokenprivileges
	var size uint32
	if err := windows.AdjustTokenPrivileges(tok, false, &tp, uint32(unsafe.Sizeof(old)), &old, &size); err != nil {
		return false, err
	}
	return old.PrivilegeCount == 1, nil
}

// repairDataFolder is repairDataDir + fillDataDir on this machine (install, setup-self-update).
func repairDataFolder(cfgPath string, out io.Writer) error {
	sid, _, _, err := windows.LookupSID("", agentAccount)
	if err != nil {
		return fmt.Errorf("the service account %s was not found (is the service installed?): %w", agentAccount, err)
	}
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	if p := collect.ExecPathProblem(abs, true); p != "" {
		return fmt.Errorf("--config %s %s", abs, p)
	}
	// the folders above the data folder (C:\ProgramData exists; only another --config folder may lack them)
	if err := os.MkdirAll(filepath.Dir(filepath.Dir(abs)), 0o700); err != nil {
		return err
	}
	rep, err := repairDataDir(winFS{}, abs, sid.String())
	if err != nil {
		return err
	}
	return fillDataDir(abs, rep, out)
}

// ensureFolders makes sure Fairy's own folders named by rels ("" is the data folder itself; "logs",
// "update/stage" ...) exist as plain folders with their permissions (folders.ensure: nothing is moved or
// replaced; a folder someone else controls is refused).
func ensureFolders(cfgPath string, rels ...string) error {
	sid, _, _, err := windows.LookupSID("", agentAccount)
	if err != nil {
		return fmt.Errorf("the service account %s was not found (is the service installed?): %w", agentAccount, err)
	}
	abs, err := filepath.Abs(cfgPath)
	if err != nil {
		return err
	}
	dir := filepath.Dir(abs)
	for _, rel := range rels {
		p, spec := dir, folderSpec{sid.String(), false}
		if rel != "" {
			var ok bool
			if spec, ok = knownFolder(rel, sid.String()); !ok {
				return fmt.Errorf("%s is not one of fairy-agent's folders", rel)
			}
			p = filepath.Join(dir, filepath.FromSlash(rel))
		}
		if err := winFolders().ensure(p, spec); err != nil {
			return err
		}
	}
	return nil
}

// agentIsSelf is set by the agent while it moves its own service from LocalSystem to the low-rights account
// (migrate_windows.go): see folders.agentIsSelf. It is never set in a program an administrator runs.
var agentIsSelf bool

// winFolders is the folder work on this machine; a removed link is reported on standard output and in the log.
func winFolders() folders {
	return folders{fs: winFS{}, hint: repairHint, agentIsSelf: agentIsSelf, note: func(format string, a ...any) {
		msg := fmt.Sprintf(format, a...)
		fmt.Println("repaired:", msg)
		slog.Warn("data folder: " + msg)
	}}
}

// trustedFile checks one file that only administrators and SYSTEM may change (nil when it does not exist).
func trustedFile(path string) error {
	o, err := winFS{}.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if lv, why := judge(o, false, false, false, agentSIDString()); lv >= lvAgent {
		return fmt.Errorf("%s %s", path, why)
	}
	return nil
}
