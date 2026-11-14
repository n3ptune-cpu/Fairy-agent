package agent

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// fakeBootKey is the registry key of the boot id, as Windows keeps one: gone after a restart, kept through
// everything else.
type fakeBootKey struct {
	exists      bool
	id          string
	owner       string
	null        bool
	aces        []collect.ACE
	persistent  bool // somebody made it as an ordinary key
	creates     int
	sets        int
	createErr   error
	raceID      string // somebody else makes the key in the moment this process tries to
	volatileErr error
	readErr     error
}

const (
	sidSYSTEM = "S-1-5-18"
	sidAdmins = "S-1-5-32-544"
	sidUsers  = "S-1-5-32-545"
	sidAuthed = "S-1-5-11"
)

func helperACL() []collect.ACE {
	return []collect.ACE{{Kind: collect.ACEAllow, SID: sidSYSTEM, Mask: 0xF003F}, {Kind: collect.ACEAllow, SID: sidAdmins, Mask: 0xF003F},
		{Kind: collect.ACEAllow, SID: sidAuthed, Mask: 0x20019}}
}

func (k *fakeBootKey) Name() string { return `HKLM\SOFTWARE\FairyAgentBoot` }
func (k *fakeBootKey) Read() (string, string, bool, []collect.ACE, error) {
	if k.readErr != nil {
		return "", "", false, nil, k.readErr
	}
	if !k.exists {
		return "", "", false, nil, os.ErrNotExist
	}
	return k.id, k.owner, k.null, k.aces, nil
}
func (k *fakeBootKey) Create(id string) error {
	k.creates++
	if k.createErr != nil {
		return k.createErr
	}
	if k.raceID != "" {
		k.exists, k.id, k.owner, k.aces = true, k.raceID, sidAdmins, helperACL()
		return os.ErrExist
	}
	if k.exists {
		return os.ErrExist
	}
	k.exists, k.id, k.owner, k.aces = true, id, sidAdmins, helperACL()
	return nil
}
func (k *fakeBootKey) Set(id string) error { k.sets++; k.id = id; return nil }
func (k *fakeBootKey) Volatile() (bool, error) {
	return !k.persistent, k.volatileErr
}

// restartWindows is what a restart (or a full shutdown) does to a volatile key.
func (k *fakeBootKey) restartWindows() {
	if !k.persistent {
		k.exists, k.id = false, ""
	}
}

func TestBootIDOnWindows(t *testing.T) {
	k := &fakeBootKey{}
	// the agent, before the helper has started in this boot: no id, and it makes nothing
	if id, err := bootIDFrom(k, nil, false); id != "" || !errors.Is(err, errNoBootKey) || k.creates != 0 {
		t.Fatalf("the agent without a key: %q %v, %d creates", id, err, k.creates)
	}
	// the helper makes it, once; a restart of the helper, the agent, and every later look read the same value
	first, err := bootIDFrom(k, nil, true)
	if err != nil || !bootIDValid(first) || k.creates != 1 {
		t.Fatalf("the helper's first look: %q %v, %d creates", first, err, k.creates)
	}
	for i := 0; i < 3; i++ {
		for _, owner := range []bool{true, false} {
			if id, err := bootIDFrom(k, nil, owner); id != first || err != nil {
				t.Fatalf("a later look (owner %v): %q %v, want %q", owner, id, err, first)
			}
		}
	}
	if k.creates != 1 || k.sets != 0 {
		t.Fatalf("%d creates, %d sets", k.creates, k.sets)
	}
	// Windows restarts: the key is gone, the helper makes a new one with another value
	k.restartWindows()
	if id, err := bootIDFrom(k, nil, false); id != "" || err == nil {
		t.Fatalf("the agent after a restart of Windows, before the helper: %q %v", id, err)
	}
	second, err := bootIDFrom(k, nil, true)
	if err != nil || !bootIDValid(second) || second == first {
		t.Fatalf("after a restart of Windows: %q %v (before: %q)", second, err, first)
	}
	// sleep, hibernation and a shutdown with Fast Startup do nothing to the key (it is in memory, and memory
	// comes back): the same boot goes on
	if id, _ := bootIDFrom(k, nil, true); id != second {
		t.Fatalf("after a sleep: %q, want %q", id, second)
	}
}

func TestBootIDIsNotBelievedFromAKeyOthersCanChange(t *testing.T) {
	good := func() *fakeBootKey {
		return &fakeBootKey{exists: true, id: "00112233445566778899aabbccddeeff", owner: sidAdmins, aces: helperACL()}
	}
	for name, spoil := range map[string]func(k *fakeBootKey){
		"owned by a user":    func(k *fakeBootKey) { k.owner = "S-1-5-21-1-2-3-1001" },
		"no permission list": func(k *fakeBootKey) { k.null = true },
		"Users may set a value": func(k *fakeBootKey) {
			k.aces = append(k.aces, collect.ACE{Kind: collect.ACEAllow, SID: sidUsers, Mask: 0x2})
		},
		"Users may delete it": func(k *fakeBootKey) {
			k.aces = append(k.aces, collect.ACE{Kind: collect.ACEAllow, SID: sidUsers, Mask: 0x10000})
		},
		"Everyone has full control": func(k *fakeBootKey) {
			k.aces = append(k.aces, collect.ACE{Kind: collect.ACEAllow, SID: "S-1-1-0", Mask: 0xF003F})
		},
	} {
		for _, owner := range []bool{true, false} {
			k := good()
			spoil(k)
			id, err := bootIDFrom(k, nil, owner)
			if id != "" || err == nil {
				t.Errorf("%s (owner %v): believed %q", name, owner, id)
			}
			if k.creates != 0 || k.sets != 0 {
				t.Errorf("%s (owner %v): wrote into a key that is not safe (%d creates, %d sets)", name, owner, k.creates, k.sets)
			}
		}
	}
	// a value that is not an id: the agent believes nothing; the helper stores a new one (the key is its own)
	for _, bad := range []string{"", "zz112233445566778899aabbccddeeff", "00112233445566778899AABBCCDDEEFF", "0011", strings.Repeat("0", 33)} {
		k := good()
		k.id = bad
		if id, err := bootIDFrom(k, nil, false); id != "" || err == nil {
			t.Errorf("the agent believed %q", bad)
		}
		id, err := bootIDFrom(k, nil, true)
		if err != nil || !bootIDValid(id) || id == bad || k.sets != 1 {
			t.Errorf("the helper with the value %q in its key: %q %v, %d sets", bad, id, err, k.sets)
		}
	}
	// a key that is not volatile would be the same after a restart: no id for the helper, and nothing written
	k := good()
	k.persistent = true
	if id, err := bootIDFrom(k, nil, true); id != "" || err == nil || !strings.Contains(err.Error(), "not a volatile key") || k.sets != 0 {
		t.Errorf("a key that is not volatile: %q %v", id, err)
	}
	k = good()
	k.volatileErr = errors.New("access denied")
	if id, err := bootIDFrom(k, nil, true); id != "" || err == nil {
		t.Errorf("a key whose kind cannot be told: %q %v", id, err)
	}
}

func TestBootIDFailures(t *testing.T) {
	// the key cannot be made
	k := &fakeBootKey{createErr: errors.New("access denied")}
	if id, err := bootIDFrom(k, nil, true); id != "" || err == nil {
		t.Errorf("%q %v", id, err)
	}
	// it cannot be read
	k = &fakeBootKey{readErr: errors.New("registry: handle is invalid")}
	for _, owner := range []bool{true, false} {
		if id, err := bootIDFrom(k, nil, owner); id != "" || err == nil || k.creates != 0 {
			t.Errorf("owner %v: %q %v, %d creates", owner, id, err, k.creates)
		}
	}
	// no random numbers
	k = &fakeBootKey{}
	if id, err := bootIDFrom(k, bytes.NewReader(nil), true); id != "" || err == nil || k.exists {
		t.Errorf("without random numbers: %q %v, key made %v", id, err, k.exists)
	}
	// the helper and the administrator's command make the key in the same moment: both read the one that is there
	k = &fakeBootKey{raceID: "ffeeddccbbaa99887766554433221100"}
	if id, err := bootIDFrom(k, nil, true); id != k.raceID || err != nil {
		t.Errorf("two makers: %q %v", id, err)
	}
}
