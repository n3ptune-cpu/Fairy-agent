package agent

import (
	"os"
	"path/filepath"
	"testing"
)

// A guest is a process named as QEMU / KVM and LXC name theirs; nothing else is, and a process list that
// cannot be read is an error (which the run watch takes as "a guest runs").
func TestGuestsIn(t *testing.T) {
	proc := t.TempDir()
	add := func(pid, comm string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, pid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	add("1", "systemd")
	add("812", "pvedaemon")
	add("self", "kvm") // not a process id
	if err := os.MkdirAll(filepath.Join(proc, "900"), 0o755); err != nil {
		t.Fatal(err) // a process that ended: no comm
	}
	if on, err := guestsIn(proc); on || err != nil {
		t.Fatalf("no guest: %v, %v", on, err)
	}
	for _, comm := range []string{"kvm", "qemu-kvm", "qemu-system-x86", "lxc-start"} {
		add("4242", comm)
		if on, err := guestsIn(proc); !on || err != nil {
			t.Errorf("%s: %v, %v", comm, on, err)
		}
	}
	for _, comm := range []string{"kvm-irqfd-clean", "lxcfs", "qemu-ga", "kvmd", "my-kvm"} {
		add("4242", comm)
		if on, _ := guestsIn(proc); on {
			t.Errorf("%s counts as a guest", comm)
		}
	}
	if _, err := guestsIn(filepath.Join(proc, "missing")); err == nil {
		t.Error("a process list that is not there is no error")
	}
}
