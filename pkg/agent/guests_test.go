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

// A process whose name cannot be read is not "no guest": with /proc mounted hidepid=1 the folders of other
// users' processes are listed and nothing in them can be read (EACCES), so every kvm of root was invisible to
// the agent's user and the veto failed open (review of fd6d3be, T5). Only a process that ended in this moment
// is passed over; every other failure is "cannot tell", which the run watch takes as "a guest runs".
func TestGuestsCannotTellWhenANameCannotBeRead(t *testing.T) {
	newProc := func() string {
		proc := t.TempDir()
		for pid, comm := range map[string]string{"1": "systemd", "77": "sshd"} {
			if err := os.MkdirAll(filepath.Join(proc, pid), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(proc, pid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return proc
	}
	// a name that cannot be read (a folder in its place: every read error but "it is gone")
	proc := newProc()
	if err := os.MkdirAll(filepath.Join(proc, "4242", "comm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if on, err := guestsIn(proc); !on && err == nil {
		t.Errorf("a process whose name cannot be read counts as \"no guest\": on=%v err=%v", on, err)
	}
	// the same with the real thing where the test can make it: a comm file nobody may read
	if os.Getuid() != 0 {
		proc = newProc()
		if err := os.MkdirAll(filepath.Join(proc, "4243"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(proc, "4243", "comm"), []byte("kvm\n"), 0o000); err != nil {
			t.Fatal(err)
		}
		if on, err := guestsIn(proc); !on && err == nil {
			t.Errorf("a name that may not be read (EACCES) counts as \"no guest\"")
		}
	}
	// a process that ended between the listing and the read is passed over, as before
	proc = newProc()
	if err := os.MkdirAll(filepath.Join(proc, "900"), 0o755); err != nil {
		t.Fatal(err)
	}
	if on, err := guestsIn(proc); on || err != nil {
		t.Errorf("a process that ended: %v, %v", on, err)
	}
	// hidepid=2 hides the processes of other users altogether: then not even process 1 is there, and nobody
	// can say that no guest runs
	proc = t.TempDir()
	if err := os.MkdirAll(filepath.Join(proc, "5000"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "5000", "comm"), []byte("fairy-agent\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if on, err := guestsIn(proc); !on && err == nil {
		t.Errorf("a process list without process 1 (other users' processes are hidden) counts as \"no guest\"")
	}
}
