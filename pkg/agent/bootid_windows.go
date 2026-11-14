//go:build windows

package agent

import (
	"errors"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// The registry calls behind BootKey (bootid.go says what the key is and why it can be believed). Nothing in
// this file decides anything: it opens, reads, makes and probes one key.
const (
	// bootKeyPath is the key, under HKEY_LOCAL_MACHINE. Directly under SOFTWARE: only SYSTEM and administrators
	// can make a key there, and a volatile key leaves nothing behind when the service is removed.
	bootKeyPath  = `SOFTWARE\FairyAgentBoot`
	bootKeyValue = "id"
	// bootKeySDDL is the key's own permission list: SYSTEM and Administrators everything, signed-in accounts
	// (the agent's service account is one) read; protected, so nothing is inherited from SOFTWARE. The owner is
	// whoever makes it: for a service that runs as SYSTEM and for an elevated administrator that is the
	// Administrators group.
	bootKeySDDL = "D:P(A;;KA;;;SY)(A;;KA;;;BA)(A;;KR;;;AU)"

	regOptionVolatile = 0x1 // REG_OPTION_VOLATILE
	regCreatedNewKey  = 0x1 // REG_CREATED_NEW_KEY
)

var (
	procRegCreateKeyExW = windows.NewLazySystemDLL("advapi32.dll").NewProc("RegCreateKeyExW")
	// bootKeyIsVolatile: this process has made sure once that the key is a volatile one. A key cannot change
	// its kind; only an administrator could put another key in its place.
	bootKeyIsVolatile atomic.Bool
)

type winBootKey struct{}

func (winBootKey) Name() string { return `HKLM\` + bootKeyPath }

func (k winBootKey) Read() (id, owner string, nullDACL bool, aces []collect.ACE, err error) {
	h, err := registry.OpenKey(registry.LOCAL_MACHINE, bootKeyPath, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return "", "", false, nil, err // registry.ErrNotExist is os.ErrNotExist
	}
	defer h.Close()
	owner, nullDACL, aces, err = collect.KeySecurity(k.Name(), windows.Handle(h))
	if err != nil {
		return "", "", false, nil, err
	}
	id, _, verr := h.GetStringValue(bootKeyValue)
	if verr != nil {
		id = "" // no value, or one of another type: no id
	}
	return id, owner, nullDACL, aces, nil
}

func (winBootKey) Create(id string) error {
	sd, err := windows.SecurityDescriptorFromString(bootKeySDDL)
	if err != nil {
		return err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	path, err := windows.UTF16PtrFromString(bootKeyPath)
	if err != nil {
		return err
	}
	var h windows.Handle
	var disposition uint32
	r, _, _ := procRegCreateKeyExW.Call(uintptr(windows.HKEY_LOCAL_MACHINE), uintptr(unsafe.Pointer(path)), 0, 0, regOptionVolatile,
		uintptr(registry.SET_VALUE|registry.QUERY_VALUE|registry.WOW64_64KEY), uintptr(unsafe.Pointer(&sa)),
		uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(&disposition)))
	runtime.KeepAlive(sd)
	runtime.KeepAlive(path)
	if r != 0 {
		return syscall.Errno(r)
	}
	defer windows.RegCloseKey(h)
	if disposition != regCreatedNewKey {
		return os.ErrExist // it was there: its permissions are whatever they were, and nothing is written here
	}
	return registry.Key(h).SetStringValue(bootKeyValue, id)
}

func (winBootKey) Set(id string) error {
	h, err := registry.OpenKey(registry.LOCAL_MACHINE, bootKeyPath, registry.SET_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer h.Close()
	return h.SetStringValue(bootKeyValue, id)
}

// Volatile probes the key: Windows refuses to make an ordinary (stored) key under a volatile one
// (ERROR_CHILD_MUST_BE_VOLATILE). If the probe key can be made, the key is an ordinary one; the probe is
// removed again.
func (winBootKey) Volatile() (bool, error) {
	if bootKeyIsVolatile.Load() {
		return true, nil
	}
	h, err := registry.OpenKey(registry.LOCAL_MACHINE, bootKeyPath, registry.CREATE_SUB_KEY|registry.WOW64_64KEY)
	if err != nil {
		return false, err
	}
	defer h.Close()
	const probe = "probe"
	sub, _, err := registry.CreateKey(h, probe, registry.QUERY_VALUE)
	if errors.Is(err, windows.ERROR_CHILD_MUST_BE_VOLATILE) {
		bootKeyIsVolatile.Store(true)
		return true, nil
	}
	if err != nil {
		return false, err
	}
	sub.Close()
	_ = registry.DeleteKey(h, probe)
	return false, nil
}
