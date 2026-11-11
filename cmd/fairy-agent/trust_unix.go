//go:build !windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Who owns the approval trust on systems other than Windows, and as whom `fairy-agent helper-trust` works.
//
// The trust file is in the agent's state folder (Linux: /var/lib/fairy-agent). That folder belongs to the
// user the agent runs as (a standard install: fairy-agent, mode 0700; an agent that runs as root: root), and
// the agent itself writes the file there at the first-time set from the panel. So the file is, by its place,
// the service user's: whoever owns a folder can replace any file in it, whatever the file's own owner is. A
// root-owned file there would only look more protected than it is, and on these systems the agent process is
// the checker anyway. The rule the agent checks (approval.UnixCheckDir, UnixCheckFile) is: the folder and the
// file belong to root or to the agent's own user and nobody else can write them.
//
// The command is root's (set and clear refuse everybody else). In a folder that belongs to another user, root
// does not do file work as root: it becomes that user first, for good, and then reads, writes and removes
// exactly as the agent would. Two things follow. `show` reports what the running agent sees, with the agent's
// own checks. And nothing in a folder that the service user controls (a link planted there, a file swapped
// between a check and a write) can make a root process touch a file outside it: by then the process has no
// more rights than the user who could have planted it. A file written this way belongs to the service user,
// mode 0600, like the one the agent writes itself. In a folder that belongs to root, root works as root and
// the file is root's, readable by the folder's group (approval.UnixAdminPrepare).
//
// A local user who is neither root nor the service user cannot read or change anything: the folder is 0700.

// trustActAs decides as whom the file work in the trust folder is done: drop says "give up root and become the
// folder's owner"; err says that this user cannot do it at all. euid is who runs the command; found, isDir,
// owner say what the folder is.
func trustActAs(euid int, found, isDir bool, owner uint32) (drop bool, err error) {
	switch {
	case !found || !isDir:
		return false, nil // nothing to work in: the checks say what is wrong (no folder is "off", a link is refused)
	case euid == 0:
		return owner != 0, nil
	case uint32(euid) == owner:
		return false, nil // the service user itself (show; set and clear ask for root before this)
	}
	return false, fmt.Errorf("only root and the agent's own user (uid %d) can read the approval trust of this machine; run this as root", owner)
}

// trustBecomeOwner prepares this process for the file work in the folder of the trust file path (see above).
// It returns a line for `show` that says as whom the file is looked at ("" when that is simply this user).
func trustBecomeOwner(path string) (string, error) {
	dir := filepath.Dir(path)
	st, err := os.Lstat(dir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	var owner, group uint32
	if err == nil {
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return "", fmt.Errorf("%s: cannot read its owner", dir)
		}
		owner, group = sys.Uid, sys.Gid
	}
	drop, aerr := trustActAs(os.Geteuid(), err == nil, err == nil && st.IsDir(), owner)
	if aerr != nil {
		return "", aerr
	}
	if !drop {
		return "", nil
	}
	if err := dropPrivileges(owner, group); err != nil {
		return "", fmt.Errorf("could not become the owner of %s (uid %d) for the file work: %w", dir, owner, err)
	}
	return fmt.Sprintf("checked as:      uid %d, the owner of %s (what the running agent sees)", owner, dir), nil
}

// dropPrivileges makes this process, all of it and for good, the user uid with the group gid and no other
// groups, and makes sure root cannot be had back.
func dropPrivileges(uid, gid uint32) error {
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(int(gid)); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(int(uid)); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if os.Getuid() != int(uid) || os.Geteuid() != int(uid) || os.Getgid() != int(gid) || os.Getegid() != int(gid) {
		return errors.New("the user did not change")
	}
	if syscall.Setuid(0) == nil || os.Geteuid() == 0 {
		return errors.New("root could be had back")
	}
	return nil
}
