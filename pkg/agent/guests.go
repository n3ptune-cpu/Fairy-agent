package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// GuestsRunning reports whether a guest runs on this machine: a virtual machine (a process named kvm, qemu-kvm
// or qemu-system-..., which is what QEMU / KVM and with it Proxmox VE start one as) or a container of LXC (a
// process named lxc-start, its monitor; Proxmox VE's containers). The run watch asks it when the wait of a run
// is over: a machine with a guest never switches itself off. An error counts there as "one runs". It looks at
// the names in /proc and at nothing else of any process; where there is no /proc with such names (not Linux)
// there is no guest of these kinds to find.
//
// "No guest" is said only when every process could be looked at. The error is: the process list cannot be
// read; the name of a process cannot be read for another reason than that the process ended in this moment
// (/proc mounted with hidepid=1: other users' processes are listed and closed); or process 1 is not in the
// list (hidepid=2, which hides other users' processes altogether, and with them every guest of root's).
func GuestsRunning() (bool, error) { return guestsIn("/proc") }

func guestsIn(proc string) (bool, error) {
	ents, err := os.ReadDir(proc)
	if err != nil {
		return false, err
	}
	init := false
	for _, e := range ents {
		name := e.Name()
		if name == "" || name[0] < '0' || name[0] > '9' {
			continue
		}
		b, err := os.ReadFile(filepath.Join(proc, name, "comm"))
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			continue // the process ended in this moment
		}
		if err != nil {
			return false, fmt.Errorf("the name of process %s cannot be read, so nobody can say that no guest runs: %w", name, err)
		}
		if name == "1" {
			init = true
		}
		if guestProcess(strings.TrimSpace(string(b))) {
			return true, nil
		}
	}
	if !init {
		return false, errors.New("process 1 is not in the process list: the processes of other users are hidden from this agent, so nobody can say that no guest runs")
	}
	return false, nil
}

// guestProcess: is comm (the kernel's name of a process, at most 15 characters) the process of a guest?
func guestProcess(comm string) bool {
	return comm == "kvm" || comm == "qemu-kvm" || strings.HasPrefix(comm, "qemu-system-") || comm == "lxc-start"
}
