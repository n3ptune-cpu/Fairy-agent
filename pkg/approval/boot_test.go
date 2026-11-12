package approval_test

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// bootRig is a machine with trust and boot_shutdown_s 600 that has been up for 100 s.
func bootRig(t *testing.T) *rig {
	t.Helper()
	r := newRig(t, true)
	r.setLocal(func(tr *approval.Trust) { tr.BootShutdownS = 600 })
	r.mu.Lock()
	r.uptime = 100 * time.Second
	r.mu.Unlock()
	return r
}

// reboot: the machine is off for a while and starts again; it has now been up for up.
func (r *rig) reboot(off, up time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(off + up)
	r.uptime = up
	r.mu.Unlock()
}

// TestBootShutdownIsShortAndOncePerBoot (review L2): the one shutdown without approval shortly after boot takes
// a delay of at most BootShutdownMaxDelayS, and "one" is one per boot: a restarted service (which a panel can
// cause on Windows with /helper/stop and /helper/start) gets no second one, the next boot does.
func TestBootShutdownIsShortAndOncePerBoot(t *testing.T) {
	r := bootRig(t)
	g := r.gate()
	// a shutdown 24 hours away is not "shortly after boot", and neither is one 601 s away
	for _, delay := range []int{86400, approval.BootShutdownMaxDelayS + 1} {
		refused(t, "long delay", g.Check(power("shutdown", delay), nil), api.CodeApprovalRequired, "")
		if c, ref := g.Challenge(power("shutdown", delay)); ref != nil || !c.Needed {
			t.Errorf("challenge for a delay of %d s: %+v, %v", delay, c, ref)
		}
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(r.files.Path), approval.BootMarkName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused request was recorded as the one shutdown")
	}
	if c, ref := g.Challenge(power("shutdown", approval.BootShutdownMaxDelayS)); ref != nil || c.Needed || c.Reason != "boot_shutdown" {
		t.Errorf("challenge for the longest delay allowed: %+v, %v", c, ref)
	}
	accepted(t, "the one shutdown, longest delay allowed", g.Check(power("shutdown", approval.BootShutdownMaxDelayS), nil))
	refused(t, "a second one, same process", g.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	// the service restarted in the same boot: a new gate on the same folder
	r.wait(30 * time.Second)
	restarted := r.gate()
	refused(t, "after a restart of the service", restarted.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	if c, ref := restarted.Challenge(power("shutdown", 60)); ref != nil || !c.Needed {
		t.Errorf("challenge after a restart: %+v, %v", c, ref)
	}
	// an approved shutdown still works, of course
	accepted(t, "approved", restarted.Check(power("shutdown", 60), r.iss.Approve(r.Now(), r.entryFrom(restarted, power("shutdown", 60)))))

	// the next boot, an hour later, up for 50 s: one again, and again only one
	r.reboot(time.Hour, 50*time.Second)
	next := r.gate()
	accepted(t, "the next boot", next.Check(power("shutdown", 60), nil))
	refused(t, "the next boot, a second one", r.gate().Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	// a boot later in the day than the last one was used in its own boot (uptime 400 s against 50 s then)
	r.reboot(3*time.Hour, 400*time.Second)
	accepted(t, "a third boot, later after its start", r.gate().Check(power("shutdown", 60), nil))
	// past the window nothing is given, record or not
	r.reboot(time.Hour, 600*time.Second)
	refused(t, "at 600 s", r.gate().Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
}

// TestBootShutdownWithBootID: where the system names its boots (Linux), that name decides, whatever the clock
// says: the same id is the same boot even when the clock was set forward by a day in between, another id is
// another boot even when the clock stood still.
func TestBootShutdownWithBootID(t *testing.T) {
	r := bootRig(t)
	id := "boot-1"
	gate := func() *approval.Gate {
		return approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Now: r.Now,
			Uptime: func() (time.Duration, error) { r.mu.Lock(); defer r.mu.Unlock(); return r.uptime, nil },
			BootID: func() (string, error) { return id, nil }, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	}
	accepted(t, "the one shutdown", gate().Check(power("shutdown", 60), nil))
	// the clock is set a day forward (a PC whose clock battery is empty gets the time from the network): by the
	// clock the record is from "before this boot"; by the boot id it is this boot
	r.mu.Lock()
	r.now = r.now.Add(24 * time.Hour)
	r.mu.Unlock()
	refused(t, "same boot id, clock a day later", gate().Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	id = "boot-2"
	accepted(t, "another boot id", gate().Check(power("shutdown", 60), nil))
	refused(t, "and once only", gate().Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
}

// TestBootShutdownFailsClosed: a record that cannot be read or written means no unapproved shutdown.
func TestBootShutdownFailsClosed(t *testing.T) {
	r := bootRig(t)
	mark := filepath.Join(filepath.Dir(r.files.Path), approval.BootMarkName)
	must(t, os.WriteFile(mark, []byte("not a record"), 0o600))
	refused(t, "unreadable record", r.gate().Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	if !strings.Contains(r.log.String(), "the record of the shutdown after boot cannot be read") {
		t.Errorf("log:\n%s", r.log.String())
	}
	must(t, os.Remove(mark))
	// the folder cannot be written (its check refuses): the shutdown cannot be recorded, so it is not accepted
	ro := r.files
	calls := 0
	ro.CheckDir = func(string) error {
		if calls++; calls > 1 { // the first call is the trust file's own load
			return errors.New("read-only folder")
		}
		return nil
	}
	g := approval.NewGate(approval.Options{Files: ro, EnforcedBy: api.EnforcedByAgent, Now: r.Now,
		Uptime: func() (time.Duration, error) { return 100 * time.Second, nil }, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	refused(t, "record cannot be written", g.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	if !strings.Contains(r.log.String(), "it could not be recorded") {
		t.Errorf("log:\n%s", r.log.String())
	}
	if _, err := os.Lstat(mark); !errors.Is(err, os.ErrNotExist) {
		t.Error("a record was written")
	}
}

// TestAuthTimeAllowance (review L3) pins down what the check of auth_time is: the user's last authentication at
// Pocket ID must not be more than ClockAllowance (60 s) older than the moment this machine gave the challenge.
// The allowance is there because the two times come from two clocks. It is not a proof that the passkey was
// touched FOR this request: that rests on "Requires Re-Authentication" of the Pocket ID client, which the
// machine cannot see (protocol, section 9).
func TestAuthTimeAllowance(t *testing.T) {
	if approval.ClockAllowance != 60*time.Second {
		t.Fatalf("ClockAllowance is %s: the protocol document and the guide say 60 s", approval.ClockAllowance)
	}
	for _, c := range []struct {
		before time.Duration
		reason string
	}{{59 * time.Second, ""}, {60 * time.Second, ""}, {61 * time.Second, approval.ReasonAuthTime}, {10 * time.Minute, approval.ReasonAuthTime}} {
		r := newRig(t, true)
		req := power("shutdown", 60)
		e := r.entry(req)
		nonce, _ := api.ApprovalNonce([]api.MachineEntry{e})
		cl := r.iss.Claims(nonce, r.Now())
		cl["auth_time"] = r.Now().Add(-c.before).Unix()
		ref := r.g.Check(req, &api.Approval{Token: r.iss.Token(cl), Entries: []api.MachineEntry{e}})
		if c.reason == "" {
			accepted(t, "authenticated "+c.before.String()+" before the challenge", ref)
		} else {
			refused(t, "authenticated "+c.before.String()+" before the challenge", ref, api.CodeApprovalRefused, c.reason)
		}
	}
}
