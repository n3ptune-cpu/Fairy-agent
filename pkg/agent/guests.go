package agent

import (
	"os"
	"path/filepath"
	"strings"
)

// GuestsRunning reports whether a guest runs on this machine: a virtual machine (a process named kvm, qemu-kvm
// or qemu-system-..., which is what QEMU / KVM and with it Proxmox VE start one as) or a container of LXC (a
// process named lxc-start, its monitor; Proxmox VE's containers). The run watch asks it when the wait of a run
// is over: a machine with a guest never switches itself off. An error (the process list cannot be read) counts
// there as "one runs". It looks at the names in /proc and at nothing else of any process; where there is no
// /proc with such names (not Linux) there is no guest of these kinds to find.
func GuestsRunning() (bool, error) { return guestsIn("/proc") }

func guestsIn(proc string) (bool, error) {
	ents, err := os.ReadDir(proc)
	if err != nil {
		return false, err
	}
	for _, e := range ents {
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := os.ReadFile(filepath.Join(proc, name, "comm"))
		if err != nil {
			continue // the process ended in this moment
		}
		if guestProcess(strings.TrimSpace(string(b))) {
			return true, nil
		}
	}
	return false, nil
}

// guestProcess: is comm (the kernel's name of a process, at most 15 characters) the process of a guest?
func guestProcess(comm string) bool {
	return comm == "kvm" || comm == "qemu-kvm" || strings.HasPrefix(comm, "qemu-system-") || comm == "lxc-start"
}
