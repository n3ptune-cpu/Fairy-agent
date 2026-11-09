//go:build windows

package agent

// The agent's virtual account NT SERVICE\fairy-agent reads the GPU counters (and the ACPI thermal zones) through
// PDH. PDH first reads the counters' names from the Perflib registry key, which only Administrators, SYSTEM,
// INTERACTIVE, Performance Monitor Users and Performance Log Users may read; a service's virtual account is
// none of these, so every counter failed with PDH_CANNOT_READ_NAME_STRINGS (0xC0000BC8). The fix is the
// built-in group Performance Monitor Users (S-1-5-32-558): it grants read access to performance counter data and
// nothing else (no administrator rights, no right to change anything). Membership is added by everything that
// ends with the agent on that account (install, setup-self-update, the move off LocalSystem, the updater
// service) and removed by uninstall. A group in a token is fixed when the token is made: the service must start
// again to get it.

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PerfMonitorUsersSID is the built-in local group "Performance Monitor Users" (its name is localized; its SID
// is not).
const PerfMonitorUsersSID = "S-1-5-32-558"

var (
	netapi32                    = windows.NewLazySystemDLL("netapi32.dll")
	procNetLocalGroupAddMembers = netapi32.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMembers = netapi32.NewProc("NetLocalGroupDelMembers")
)

const nerrGroupNotFound = 2220 // NERR_GroupNotFound

// localGroupMembersInfo0 is LOCALGROUP_MEMBERS_INFO_0.
type localGroupMembersInfo0 struct{ SID *windows.SID }

// perfMonitorUsersName is the group's name on this Windows (NetLocalGroup* take a name, not a SID).
func perfMonitorUsersName() (*uint16, error) {
	sid, err := windows.StringToSid(PerfMonitorUsersSID)
	if err != nil {
		return nil, err
	}
	name, _, _, err := sid.LookupAccount("")
	if err != nil {
		return nil, fmt.Errorf("the group %s (Performance Monitor Users) was not found: %w", PerfMonitorUsersSID, err)
	}
	return windows.UTF16PtrFromString(name)
}

func agentSID() (*windows.SID, error) {
	sid, _, _, err := windows.LookupSID("", `NT SERVICE\`+ServiceName)
	if err != nil {
		return nil, fmt.Errorf(`the service account NT SERVICE\%s was not found (is the service installed?): %w`, ServiceName, err)
	}
	return sid, nil
}

func localGroupMembers(proc *windows.LazyProc, member *windows.SID) (uint32, error) {
	if err := proc.Find(); err != nil {
		return 0, err
	}
	group, err := perfMonitorUsersName()
	if err != nil {
		return 0, err
	}
	info := localGroupMembersInfo0{SID: member}
	r, _, _ := proc.Call(0, uintptr(unsafe.Pointer(group)), 0, uintptr(unsafe.Pointer(&info)), 1)
	return uint32(r), nil
}

// EnsureCounterAccess makes NT SERVICE\fairy-agent a member of Performance Monitor Users (as Administrator or
// SYSTEM; idempotent). added is false when it was a member already. The agent's service gets the group when it
// next starts.
func EnsureCounterAccess() (added bool, err error) {
	sid, err := agentSID()
	if err != nil {
		return false, err
	}
	st, err := localGroupMembers(procNetLocalGroupAddMembers, sid)
	if err != nil {
		return false, err
	}
	switch st {
	case 0:
		return true, nil
	case uint32(windows.ERROR_MEMBER_IN_ALIAS):
		return false, nil
	}
	return false, fmt.Errorf(`adding NT SERVICE\%s to Performance Monitor Users (%s): %w`, ServiceName, PerfMonitorUsersSID, netStatus(st))
}

// RemoveCounterAccess takes NT SERVICE\fairy-agent out of Performance Monitor Users (uninstall; not a member,
// or no such account: nothing to do). Call it before the service is deleted: the account exists only with it.
func RemoveCounterAccess() error {
	sid, err := agentSID()
	if err != nil {
		return nil
	}
	st, err := localGroupMembers(procNetLocalGroupDelMembers, sid)
	if err != nil {
		return err
	}
	switch st {
	case 0, uint32(windows.ERROR_MEMBER_NOT_IN_ALIAS), nerrGroupNotFound:
		return nil
	}
	return fmt.Errorf(`removing NT SERVICE\%s from Performance Monitor Users: %w`, ServiceName, netStatus(st))
}

func netStatus(st uint32) error {
	if st == nerrGroupNotFound {
		return errors.New("the group does not exist (NERR_GroupNotFound)")
	}
	return syscall.Errno(st)
}

// HasCounterAccess reports whether this process's token holds Performance Monitor Users.
func HasCounterAccess() (bool, error) {
	sid, err := windows.StringToSid(PerfMonitorUsersSID)
	if err != nil {
		return false, err
	}
	return windows.Token(0).IsMember(sid)
}
