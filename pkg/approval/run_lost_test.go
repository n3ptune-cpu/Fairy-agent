package approval_test

import (
	"os"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// The mark of the record (the boot of the last ticket or cancel, the ids of sixteen runs) only refuses. When
// the record was removed, or `helper-run cancel` removed one that could not be read, and the service started
// again, the mark was gone with the file, and the SAME ticket armed the machine again after a cancel in that
// boot (review of fd6d3be, T6; only an administrator can remove the file).
//
// Now nothing removes the record: a record that is missing or was unreadable is made anew, and a record that
// is made anew closes its boot for tickets and takes no ticket that was signed before it was made.
func TestSameTicketDoesNotArmAgainAfterTheRecordWasLost(t *testing.T) {
	for _, lost := range []string{"unreadable, then helper-run cancel", "deleted", "deleted while the service is stopped"} {
		t.Run(lost, func(t *testing.T) {
			r := newRunRig(t)
			tk := r.ticket(runA, r.up()+100*time.Second)
			if _, ref := r.w.Arm(tk); ref != nil {
				t.Fatal(ref)
			}
			if _, err := r.w.Cancel("x"); err != nil {
				t.Fatal(err)
			}
			switch lost {
			case "unreadable, then helper-run cancel":
				if err := os.WriteFile(r.files.RunPath(), []byte("{broken"), 0o600); err != nil {
					t.Fatal(err)
				}
				if _, ref := r.w.Arm(tk); ref == nil {
					t.Fatal("armed with a broken record")
				}
				was, changed, err := r.files.RunCancel(r.stamp()) // the documented remedy
				if err != nil || !changed || was.Err == nil {
					t.Fatalf("helper-run cancel: %+v %v %v", was, changed, err)
				}
				if exists, err := r.files.RunRecordCheck(); !exists || err != nil {
					t.Fatalf("helper-run cancel left no usable record: %v %v", exists, err)
				}
			case "deleted":
				if err := os.Remove(r.files.RunPath()); err != nil {
					t.Fatal(err)
				}
			case "deleted while the service is stopped":
				if err := os.Remove(r.files.RunPath()); err != nil {
					t.Fatal(err)
				}
				r.restart()
			}
			if _, ref := r.w.Arm(tk); ref == nil {
				t.Errorf("same process: the cancelled run's ticket armed again after the record was lost")
			}
			r.restart()
			ans, ref := r.w.Arm(tk)
			if ref == nil {
				t.Fatalf("record lost + service restart: the SAME ticket armed again after a cancel in the same boot: %+v", ans)
			}
			// another ticket, signed after the loss: not in this boot either
			r.wait(5 * time.Second)
			if _, ref = r.w.Arm(r.ticket(runB, time.Second)); ref == nil {
				t.Fatal("a new ticket armed the machine in the boot in which the record was made anew")
			}
			// the next boot, two minutes later: the old ticket is still within its valid_s, its run id is not
			// on record any more, and it is not taken, because it was signed before the record was made
			r.reboot(90*time.Second, 20*time.Second)
			_, ref = r.w.Arm(tk)
			runRefused(t, "the old ticket in the next boot", ref, 409, api.CodeRunRefused, api.RunReasonBeforeRecord)
			// a ticket signed after the record was made arms the machine in that boot as ever
			if _, ref := r.w.Arm(r.ticket(runC, time.Second)); ref != nil {
				t.Fatalf("a new ticket in the next boot: %v", ref)
			}
		})
	}
}

// A machine gets its record when the service first looks with trust set: made anew, so that boot is closed.
// The machine a run wakes has its record from the boot before.
func TestFirstRecordClosesItsBoot(t *testing.T) {
	r := newRunRig(t)
	if err := os.Remove(r.files.RunPath()); err != nil { // as on a machine whose service has never looked
		t.Fatal(err)
	}
	r.mu.Lock()
	r.uptime = 20 * time.Second // the service starts with the machine
	r.mu.Unlock()
	r.restart()
	r.w.Tick()
	if exists, err := r.files.RunRecordCheck(); !exists || err != nil {
		t.Fatalf("no record after the first look: %v %v", exists, err)
	}
	r.wait(5 * time.Second)
	_, ref := r.w.Arm(r.ticket(runA, time.Second)) // signed after the record was made, on a machine that has just started
	runRefused(t, "a ticket in the boot in which the record was first made", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
	// a confirmation needs no ticket and is a challenge of this machine: it is taken
	if _, ref := r.confirm(goReq(runB, "-", 30, 300)); ref != nil {
		t.Fatalf("a confirmation in that boot: %v", ref)
	}
	r.reboot(time.Hour, 30*time.Second)
	if _, ref := r.w.Arm(r.ticket(runA, time.Second)); ref != nil {
		t.Fatalf("a ticket after the next start: %v", ref)
	}
}

// R40 of the review: "one ticket per boot" does not rest on the record alone. A record put back as it was
// before the ticket (an older copy of the file, valid in every value) does not open the boot again for the
// service that took the ticket.
func TestOneTicketPerBootDoesNotRestOnTheRecordAlone(t *testing.T) {
	r := newRunRig(t)
	before, err := os.ReadFile(r.files.RunPath())
	if err != nil {
		t.Fatal(err)
	}
	r.armed(runA)
	if _, err := r.w.Cancel("x"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.files.RunPath(), before, 0o600); err != nil {
		t.Fatal(err)
	}
	_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
	runRefused(t, "a second ticket after the record was put back", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
}

// helper-run cancel closes the boot itself (R15 of the review): also with the service stopped, and also for
// a run that was confirmed without a ticket.
func TestCancelOnTheMachineClosesTheBootWithoutTheService(t *testing.T) {
	for _, state := range []string{api.RunArmed, api.RunConfirmed} {
		r := newRunRig(t)
		if state == api.RunArmed {
			r.armed(runA)
		} else if _, ref := r.confirm(goReq(runA, "-", 30, 300)); ref != nil {
			t.Fatal(ref)
		}
		// the service is not running when the administrator cancels
		was, changed, err := r.files.RunCancel(r.stamp())
		if err != nil || !changed || was.State != state {
			t.Fatalf("%s: helper-run cancel: %+v %v %v", state, was, changed, err)
		}
		r.restart()
		_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
		runRefused(t, state+": a ticket after helper-run cancel and a start of the service", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
		r.reboot(time.Hour, 30*time.Second)
		if _, ref := r.w.Arm(r.ticket(runB, time.Second)); ref != nil {
			t.Fatalf("%s: a ticket after the next start: %v", state, ref)
		}
	}
}

// A record that is there is never made anew over: a service that looked while there was none (and has not
// made one yet) finds the one that was written in the meantime, at its next look, and keeps it.
func TestRecordThatAppearedIsNotMadeAnewOver(t *testing.T) {
	r := newRunRig(t)
	rec := r.record(t)
	if err := os.Remove(r.files.RunPath()); err != nil {
		t.Fatal(err)
	}
	r.restart()
	r.g.Status() // the first look of this service: no record (the status makes none)
	if err := os.WriteFile(r.files.RunPath(), rec, 0o600); err != nil {
		t.Fatal(err)
	}
	r.ticks(3 * time.Second)
	if v := r.files.RunShow(); v.Born >= r.Now().Unix()-10 {
		t.Fatalf("the record that was there was made anew: born %d, now %d", v.Born, r.Now().Unix())
	}
	if _, ref := r.w.Arm(r.ticket(runA, r.up()+100*time.Second)); ref != nil {
		t.Fatalf("a ticket on a machine whose record is from a boot before: %v", ref)
	}
}
