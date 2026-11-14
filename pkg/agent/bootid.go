package agent

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// The id of this boot on Windows.
//
// Linux has one (/proc/sys/kernel/random/boot_id). Windows has nothing of the kind that a service can read,
// so the helper keeps its own: 16 random bytes in a registry key that is VOLATILE. Such a key is held in
// memory and never written to the hive's file; Microsoft's description of REG_OPTION_VOLATILE (RegCreateKeyEx)
// is: "the information is stored in memory and is not preserved when the corresponding registry hive is
// unloaded. For HKEY_LOCAL_MACHINE, this occurs only when the system initiates a full shutdown." So:
//
//   - a restart of Windows, and a shutdown that is a full one, end the key: the next start has no key, the
//     helper makes a new one with a new value, and everything that was written with the old value is "another
//     boot" (a live run ends; the mark that closes a boot for tickets opens);
//   - a restart of the helper, of the agent, or an update of both does not touch it: same boot;
//   - sleep and hibernation keep it: the system did not start anew, and its uptime (GetTickCount64) goes on
//     counting through them as well;
//   - a shutdown with Fast Startup (Windows' default on most PCs) is, by Microsoft's own words, not a full
//     shutdown: the kernel's session, with the registry in memory, is hibernated and comes back. By the
//     sentence above the key is still there when the PC is switched on again, and so is the uptime: for Windows,
//     and for Fairy, that is the same boot going on. Such a PC has been "up" for as long as it has been since
//     its last real start, so no ticket arms it (not_fresh: it stays on, as the design says for PCs whose
//     uptime does not reset), and a run that was armed before the "shutdown" finds its wait long over and ends
//     with the machine on (approval.RunWatch.Tick). Nothing here makes a Fast Startup wake count as a new boot:
//     what Windows offers for that (the kernel's boot time, a session id) does not change with it either, as
//     far as its documentation says, and this code does not guess. What a real PC does is in TEST-ON-WINDOWS.md
//     (section 14, the boot id steps); wherever it differs from the documentation the result is the safe one:
//     the id is another one, so a live run ends and the machine stays on.
//
// Who may write the key decides whether the id can be believed, as with the trust file: it is made with a
// permission list of its own (SYSTEM and Administrators change it, everybody reads it; nothing is inherited),
// directly under HKLM\SOFTWARE, where only SYSTEM and administrators can make keys; and every time it is read
// its owner and its permission list are checked (collect.CheckKeyACL). A key that somebody else could have
// made or changed counts as no id, and without an id the helper keeps no runs.

// BootKey is that key as the logic below needs it: the Windows registry in the service, a fake in the tests.
type BootKey interface {
	// Name is how the key is called in a message.
	Name() string
	// Read returns the key's value, its owner and its permission list. os.ErrNotExist: there is no such key.
	// A key without the value returns id "".
	Read() (id string, owner string, nullDACL bool, aces []collect.ACE, err error)
	// Create makes the key, volatile and with its own permission list, and stores id in it. os.ErrExist: the
	// key is there already (somebody made it in this moment); nothing was changed then.
	Create(id string) error
	// Set stores id in the key that is there (one that was made and never got its value).
	Set(id string) error
	// Volatile reports whether the key lives in memory only. Only whoever may write the key can find out.
	Volatile() (bool, error)
}

// errNoBootKey: the key is not there, and this process is not the one that makes it (the agent: the helper
// does, when it starts).
var errNoBootKey = errors.New("the helper has not made its registry key for the id of this boot yet")

func bootIDValid(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// bootIDFrom reads the id of this boot from k. owner: this process may make the key when it is not there, and
// give it its value (the helper, which runs as SYSTEM, and the administrator's command); the agent only reads.
// The value is believed only from a key that passes collect.CheckKeyACL, and the owner also makes sure the key
// is a volatile one: a key that would outlive a restart is no id of a boot.
//
// Nothing is kept in memory between two calls: when two processes made the key in the same moment, each reads
// what is there in the end, and that is one value.
func bootIDFrom(k BootKey, rnd io.Reader, owner bool) (string, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	fresh := func() (string, error) {
		var b [16]byte
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return "", errors.New("no random numbers for the id of this boot")
		}
		return hex.EncodeToString(b[:]), nil
	}
	id, own, null, aces, err := k.Read()
	if errors.Is(err, os.ErrNotExist) {
		if !owner {
			return "", errNoBootKey
		}
		nid, ferr := fresh()
		if ferr != nil {
			return "", ferr
		}
		if cerr := k.Create(nid); cerr != nil && !errors.Is(cerr, os.ErrExist) {
			return "", fmt.Errorf("%s could not be made: %w", k.Name(), cerr)
		}
		id, own, null, aces, err = k.Read()
	}
	if err != nil {
		return "", fmt.Errorf("%s cannot be read: %w", k.Name(), err)
	}
	if err := collect.CheckKeyACL(k.Name(), own, null, aces); err != nil {
		return "", err // never believed, and never written into
	}
	if owner {
		v, err := k.Volatile()
		if err != nil {
			return "", fmt.Errorf("%s: cannot tell whether it is a volatile key: %w", k.Name(), err)
		}
		if !v {
			return "", fmt.Errorf("%s is not a volatile key: it would still be there after a restart (as administrator: reg delete \"%s\" /f, then restart the fairy-agent-helper service)", k.Name(), k.Name())
		}
	}
	if !bootIDValid(id) {
		if !owner {
			return "", fmt.Errorf("%s holds no id", k.Name())
		}
		// the key was made and never got its value (the process ended in between), or holds something else
		nid, err := fresh()
		if err != nil {
			return "", err
		}
		if err := k.Set(nid); err != nil {
			return "", fmt.Errorf("%s: the id could not be stored: %w", k.Name(), err)
		}
		if id, own, null, aces, err = k.Read(); err != nil {
			return "", fmt.Errorf("%s cannot be read: %w", k.Name(), err)
		}
		if err := collect.CheckKeyACL(k.Name(), own, null, aces); err != nil {
			return "", err
		}
		if !bootIDValid(id) {
			return "", fmt.Errorf("%s holds no id", k.Name())
		}
	}
	return id, nil
}
