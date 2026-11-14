//go:build windows

package approval

import (
	"errors"
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// openShared opens a file for reading and lets everybody else read it, write it, and rename or delete it in
// the meantime (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE). os.Open shares for reading and
// writing only: while the agent, the helper or `fairy-agent helper-run show` had the run record open that
// way, the helper's new record could not take the record's name (the rename failed with a sharing violation),
// and neither could the administrator's cancel.
func openShared(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// renameBusy reports whether a rename failed because somebody has the file open at this moment (another
// program that opened it without sharing, a virus scanner): worth trying again shortly.
func renameBusy(err error) bool {
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)
}

// lockSDDL is the security descriptor the lock file is made with: owned by Administrators, a permission list
// of its own that takes nothing from the folder (D:P, SE_DACL_PROTECTED), and in it everything (FA,
// FILE_GENERIC_ALL) for SYSTEM (SY) and Administrators (BA) and nothing for anybody else. The strings are
// those of "Security Descriptor String Format", "ACE Strings" and "SID Strings" on learn.microsoft.com.
const lockSDDL = "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"

// lockFile takes the lock that the two writers of the run record hold while they write (runLock): the first
// byte of the file at path, exclusively (LockFileEx), tried again until wait is over. The lock ends with
// unlock, and at the latest with the process ("If a process terminates with a portion of a file locked or
// closes a file that has outstanding locks, the locks are unlocked by the operating system").
//
// LockFileEx asks nothing of its caller but a handle "created with either the GENERIC_READ or GENERIC_WRITE
// access right". The helper's folder hands on a read entry for the agent's account to every file made in it,
// so a lock file made the plain way could be held for ever by that low-privilege account, and by nobody's
// intent the helper would then write nothing: no ticket taken, every cancel an error (second review of the
// runs, U3). So the file is made with its own protected permission list (lockSDDL) in the create call itself
// (CREATE_NEW: "CreateFile ignores the lpSecurityDescriptor member when opening an existing file"), a file
// that is there already is opened as it is, and in both cases check (Files.CheckLock: owner and permission
// list, read from the file) must accept it before it is locked. A lock file that somebody else could open is
// not used: the helper then keeps no runs and says why, and an administrator deletes the file while the helper
// is stopped (TEST-ON-WINDOWS.md). The file holds nothing and is never removed by this program.
//
// The documentation names no error for a lock that is held when LOCKFILE_FAIL_IMMEDIATELY is given (it is
// ERROR_LOCK_VIOLATION as far as known), so every failure of LockFileEx is tried again until wait is over,
// and the last error is the one that is said. admin changes nothing here.
func lockFile(path string, wait time.Duration, admin bool, check func(path string) error) (unlock func(), err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	const access, share = windows.GENERIC_READ | windows.GENERIC_WRITE, windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	h, err := lockCreate(p, access, share, lockSDDL)
	if errors.Is(err, windows.ERROR_INVALID_OWNER) { // this account may not name Administrators as the owner: without one (check looks at the result)
		h, err = lockCreate(p, access, share, lockSDDL[len("O:BA"):])
	}
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		h, err = windows.CreateFile(p, access, share, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if check != nil {
		if err := check(path); err != nil {
			_ = windows.CloseHandle(h)
			return nil, fmt.Errorf("the lock file is not used: %w", err)
		}
	}
	deadline := time.Now().Add(wait)
	for {
		var ol windows.Overlapped // the offset of the range: 0
		err = windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &ol)
		if err == nil {
			return func() {
				var ol windows.Overlapped
				_ = windows.UnlockFileEx(h, 0, 1, 0, &ol)
				_ = windows.CloseHandle(h)
			}, nil
		}
		if !time.Now().Before(deadline) {
			_ = windows.CloseHandle(h)
			return nil, &os.PathError{Op: "lock", Path: path, Err: err}
		}
		time.Sleep(lockStep)
	}
}

// lockCreate makes the lock file, which must not exist, with sddl as its security descriptor.
func lockCreate(p *uint16, access, share uint32, sddl string) (windows.Handle, error) {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return windows.InvalidHandle, err
	}
	sa := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	return windows.CreateFile(p, access, share, sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
}
