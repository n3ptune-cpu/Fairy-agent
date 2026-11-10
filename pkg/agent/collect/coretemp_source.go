package collect

import (
	"errors"
	"fmt"
	"strconv"
)

// Which shared memory is Core Temp's? (The Windows calls are in coretemp_windows.go; the decisions are here so
// they are tested on every platform.)
//
// A name in Global\ can only be created with SeCreateGlobalPrivilege, which administrators and services hold
// and an ordinary signed-in user does not: such a name is accepted as it is. A name in a session's own
// namespace (the plain name, or Session\<id>\ as seen from a service) can be created by anyone signed in to
// that session. Whoever creates it first supplies the "temperatures": high values put the fans to 100 % and
// raise alarms, low values hide a hot processor from the fan watchdog. So a session name is used only when the
// object's owner is Administrators or SYSTEM: Core Temp needs administrator rights to run at all (it loads its
// own driver), so what it creates belongs to Administrators, and an object made by an ordinary user's program
// belongs to that user.

// coreTempName is one name the shared memory may have.
type coreTempName struct {
	Name   string
	Global bool // in Global\: an ordinary signed-in user cannot create it
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

// coreTempOwnerProblem decides whether the object found under c may be used. owner is its owner SID; ownerErr
// is set when the owner could not be read. nil = use it.
func coreTempOwnerProblem(c coreTempName, owner string, ownerErr error) error {
	if c.Global {
		return nil
	}
	const fix = `; not used. Switch on Core Temp's "Enable global shared memory (SNMP)" (Options > Settings > Advanced) so it publishes the Global\ name`
	if ownerErr != nil {
		return fmt.Errorf("%w: who made %q cannot be read (%v)%s", ErrCoreTempUntrusted, c.Name, ownerErr, fix)
	}
	if !trustedSID(owner) {
		return fmt.Errorf("%w: %q belongs to %s, not to Administrators or SYSTEM%s", ErrCoreTempUntrusted, c.Name, owner, fix)
	}
	return nil
}

// coreTempCopyLen is how many bytes of a mapped view of regionSize bytes are copied: at most the size of the
// largest known block, and an error when the view cannot hold even the original block.
func coreTempCopyLen(regionSize uint64) (int, error) {
	if regionSize < CoreTempBaseSize {
		return 0, fmt.Errorf("core temp shared memory too small (%d bytes mapped, the block has %d)", regionSize, CoreTempBaseSize)
	}
	return int(min(regionSize, CoreTempExSize)), nil
}
