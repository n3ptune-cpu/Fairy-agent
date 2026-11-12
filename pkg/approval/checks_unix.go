//go:build !windows

package approval

import (
	"fmt"
	"os"
	"syscall"
)

// On systems other than Windows the agent itself checks approvals, and it also writes the trust file at the
// first-time set, so the file is the agent's own user's or root's (after `fairy-agent helper-trust set` as
// root). What these checks keep out is everybody else: a folder or file that another user or a group can write.

func ownerOK(st os.FileInfo) (uint32, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return sys.Uid, sys.Uid == 0 || sys.Uid == uint32(os.Geteuid())
}

// UnixCheckDir accepts a real folder (not a link) that belongs to root or to this process's user and that
// neither its group nor others can write.
func UnixCheckDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("%s is not a folder", dir)
	}
	if uid, ok := ownerOK(st); !ok {
		return fmt.Errorf("%s belongs to user %d, not to root or the agent's user", dir, uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by its group or by others (mode %04o)", dir, st.Mode().Perm())
	}
	return nil
}

// UnixCheckFile accepts a plain file with one name that belongs to root or to this process's user and that
// neither its group nor others can write.
func UnixCheckFile(path string) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a plain file", path)
	}
	uid, ok := ownerOK(st)
	if !ok {
		return fmt.Errorf("%s belongs to user %d, not to root or the agent's user", path, uid)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s can be written by its group or by others (mode %04o)", path, st.Mode().Perm())
	}
	if sys := st.Sys().(*syscall.Stat_t); sys.Nlink != 1 {
		return fmt.Errorf("%s has %d names", path, sys.Nlink)
	}
	return nil
}

// UnixAdminPrepare is Files.Prepare for the administrator's command: run as root, it gives the new file to
// root and to the group of the folder (the agent's), mode 0640, so the agent can read it and not change it.
// Run as another user (the agent's own, in a test) it only sets the mode to 0600.
func UnixAdminPrepare(dir string) func(tmp string) error {
	return func(tmp string) error {
		if os.Geteuid() != 0 {
			return os.Chmod(tmp, 0o600)
		}
		st, err := os.Lstat(dir)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot read its group", dir)
		}
		if err := os.Chown(tmp, 0, int(sys.Gid)); err != nil {
			return err
		}
		return os.Chmod(tmp, 0o640)
	}
}

// Who this process is, and the one call that changes a file's owner. Variables so that a test can stand in
// for them and count: nothing else in this package may change an owner on the service's path.
var (
	keepEuid   = os.Geteuid
	keepEgid   = os.Getegid
	keepLchown = os.Lchown
)

// errNotOurs is why a process that is not root cannot write a file that stays (uid, gid)'s: a file it makes is
// (mine, group)'s, and only root can change that. The words are part of the "broken" reason the owner reads.
func errNotOurs(uid, gid, mine, group uint32) error {
	return fmt.Errorf("the trust file belongs to user %d, group %d, but this service is user %d, group %d: only root can keep the owner",
		uid, gid, mine, group)
}

// UnixCanKeep is Files.CanKeep: it says, before anything is written, whether a file this process makes in dir
// can be given the owner and group of the trust file as it is now (old). Root can always. Any other user can
// only when a new file is that user's and that group's anyway: its own file (the agent wrote it at the
// first-time set). For root's file under an agent that runs as another user (after `helper-trust set` as
// root) it fails with the reason, and nothing is written and no owner is touched.
//
// A process that is not root never asks the system to change an owner here, not even to learn that it may
// not: under the shipped unit (deploy/fairy-agent.service: SystemCallFilter=~@privileged, which holds the
// chown family, and no SystemCallErrorNumber) the answer to that call is not an error, the process is killed.
func UnixCanKeep(dir string, old os.FileInfo) error {
	was, ok := old.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", old.Name())
	}
	uid := uint32(keepEuid())
	if uid == 0 {
		return nil
	}
	// a new file's group: the process's, or the folder's when the folder hands its group on (setgid)
	gid := uint32(keepEgid())
	if st, err := os.Lstat(dir); err != nil {
		return err
	} else if sys, ok := st.Sys().(*syscall.Stat_t); ok && st.Mode()&os.ModeSetgid != 0 {
		gid = sys.Gid
	}
	if was.Uid != uid || was.Gid != gid {
		return errNotOurs(was.Uid, was.Gid, uid, gid)
	}
	return nil
}

// UnixKeep is Files.Keep: it gives the temporary file tmp the owner, the group and the mode of the file it is
// about to replace (old), and fails when it cannot. So a trust file that gets its machine id added (Files.
// AddMachineID) is afterwards whose it was, with the rights it had: root's file stays root's.
//
// The owner is compared first. It is changed only when it really differs and this process is root; a process
// that is not root fails here without the call (UnixCanKeep has refused that case before the temporary file
// was made; this is the same rule for a file that came out otherwise than foreseen).
func UnixKeep(tmp string, old os.FileInfo) error {
	was, ok := old.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", old.Name())
	}
	st, err := os.Lstat(tmp)
	if err != nil {
		return err
	}
	is, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot read its owner", tmp)
	}
	if is.Uid != was.Uid || is.Gid != was.Gid {
		if keepEuid() != 0 {
			return errNotOurs(was.Uid, was.Gid, is.Uid, is.Gid)
		}
		if err := keepLchown(tmp, int(was.Uid), int(was.Gid)); err != nil {
			return fmt.Errorf("the trust file belongs to user %d, group %d, and the file that would replace it cannot be given to them: %w", was.Uid, was.Gid, err)
		}
	}
	return os.Chmod(tmp, old.Mode().Perm()) // after the owner: a change of owner can clear mode bits
}

// UnixFiles is the trust file at path with the checks above.
func UnixFiles(path string) Files {
	return Files{Path: path, CheckDir: UnixCheckDir, CheckFile: UnixCheckFile, CanKeep: UnixCanKeep, Keep: UnixKeep}
}
