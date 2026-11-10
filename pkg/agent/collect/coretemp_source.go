package collect

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Which shared memory is Core Temp's? (The Windows calls are in coretemp_windows.go; the decisions are here so
// they are tested on every platform.)
//
// Whoever creates the shared memory first supplies the "temperatures": high values put the fans to 100 % and
// raise alarms, low values hide a hot processor from the fan watchdog.
//
// A name in a session's own namespace (the plain name, or Session\<id>\ as seen from a service) can be
// created by anyone signed in to that session. So a session name is used only when the object's owner is
// Administrators or SYSTEM: Core Temp needs administrator rights to run at all (it loads its own driver), so
// what it creates belongs to Administrators, and an object made by an ordinary user's program belongs to that
// user.
//
// A name in Global\ needs SeCreateGlobalPrivilege from a session other than session 0, which an ordinary
// signed-in user does not hold. But the services' own session 0 needs no privilege for it ("applies only to
// file-mapping objects created from a session other than session zero", Microsoft, Kernel object namespaces):
// any service that is not an administrator (LocalService, NetworkService, another program's own service
// account) can take Core Temp's Global\ name first. So the owner of a Global\ name is read too, and an object
// that belongs to such a service identity, or whose owner cannot be read, is never used. An object that
// belongs to Administrators or SYSTEM is used as before. Anything else (a person's account) is still used in
// this release, with a note in the log: Core Temp is started by a person, the rule above says its objects
// belong to Administrators, and that rule has not been confirmed on a real PC yet for these names; refusing
// here on a wrong guess would take the processor temperatures away from every PC with Core Temp's global
// setting. The note says which account it is, so the rule can be made strict.

// coreTempName is one name the shared memory may have.
type coreTempName struct {
	Name   string
	Global bool // in Global\: an ordinary signed-in user cannot create it (a service in session 0 can)
}

// coreTempCandidates lists the names in the order they are tried: the Global\ names; the plain names (the
// process's own session); and, for a process outside the console session (a service), the console session's
// names through Session\<id>\. sessionsKnown is false when the session ids could not be read.
func coreTempCandidates(own, console uint32, sessionsKnown bool) []coreTempName {
	names := []coreTempName{
		{`Global\CoreTempMappingObjectEx`, true}, {`Global\CoreTempMappingObject`, true},
		{"CoreTempMappingObjectEx", false}, {"CoreTempMappingObject", false},
	}
	if sessionsKnown && console != 0xFFFFFFFF && console != own {
		s := `Session\` + strconv.FormatUint(uint64(console), 10) + `\`
		names = append(names, coreTempName{s + "CoreTempMappingObjectEx", false}, coreTempName{s + "CoreTempMappingObject", false})
	}
	return names
}

// ErrCoreTempUntrusted: a shared memory with Core Temp's name exists, but not one an administrator's Core Temp
// made (see above). It is never read.
var ErrCoreTempUntrusted = errors.New("core temp shared memory not made by an administrator's program")

// serviceIdentity reports whether a SID is an account a service runs as and no person signs in with:
// LocalService, NetworkService, a service's own SID (NT SERVICE\name; TrustedInstaller is one of those and is
// trusted before this is asked), an IIS application pool, a virtual machine, and the window manager / font
// driver accounts. None of them is Core Temp, which a person starts.
func serviceIdentity(sid string) bool {
	if sid == "S-1-5-19" || sid == "S-1-5-20" {
		return true
	}
	for _, prefix := range []string{"S-1-5-80-", "S-1-5-82-", "S-1-5-83-", "S-1-5-90-", "S-1-5-96-", "S-1-5-99-"} {
		if strings.HasPrefix(sid, prefix) {
			return true
		}
	}
	return false
}

// coreTempOwnerProblem decides whether the object found under c may be used. owner is its owner SID; ownerErr
// is set when the owner could not be read. No error = use it; note, when not empty, goes to the log once
// (the object is used, but its owner is not the one expected).
func coreTempOwnerProblem(c coreTempName, owner string, ownerErr error) (note string, problem error) {
	fix := `; not used. Switch on Core Temp's "Enable global shared memory (SNMP)" (Options > Settings > Advanced) so it publishes the Global\ name`
	if c.Global {
		fix = "; not used. Another program holds Core Temp's name: close Core Temp, find and stop that program, then start Core Temp again"
	}
	if ownerErr != nil {
		return "", fmt.Errorf("%w: who made %q cannot be read (%v)%s", ErrCoreTempUntrusted, c.Name, ownerErr, fix)
	}
	switch {
	case trustedSID(owner):
		return "", nil
	case !c.Global:
		return "", fmt.Errorf("%w: %q belongs to %s, not to Administrators or SYSTEM%s", ErrCoreTempUntrusted, c.Name, owner, fix)
	case owner == "" || serviceIdentity(owner):
		return "", fmt.Errorf("%w: %q belongs to %s (a service's account, not a person's), not to Administrators or SYSTEM%s",
			ErrCoreTempUntrusted, c.Name, sidOrNone(owner), fix)
	}
	return fmt.Sprintf("Core Temp's shared memory %s belongs to %s, not to Administrators or SYSTEM as expected of a program an administrator started. "+
		"It is used all the same in this release. Please report this line: a later release will refuse such an object", c.Name, owner), nil
}

func sidOrNone(sid string) string {
	if sid == "" {
		return "nobody (no owner)"
	}
	return sid
}

// coreTempCopyLen is how many bytes of a mapped view of regionSize bytes are copied: at most the size of the
// largest known block, and an error when the view cannot hold even the original block.
func coreTempCopyLen(regionSize uint64) (int, error) {
	if regionSize < CoreTempBaseSize {
		return 0, fmt.Errorf("core temp shared memory too small (%d bytes mapped, the block has %d)", regionSize, CoreTempBaseSize)
	}
	return int(min(regionSize, CoreTempExSize)), nil
}
