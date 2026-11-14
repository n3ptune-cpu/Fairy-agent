package approval_test

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// TestRandomRunSequences plays random sequences of everything that can happen to a machine in a run (tickets
// good and bad, confirmations, the run's update and shutdown, cancels, restarts of the service, new boots,
// the clock being set, time passing) and holds every single thing the machine does against what it was
// allowed to do, kept by the test itself from the answers it saw:
//
//  1. a ticket is taken only on a machine up for less than 600 s that started not before the ticket was
//     signed (60 s allowance), at most once per boot, and never twice for one run;
//  2. the machine switches itself off only in a boot in which a ticket was taken, not before that ticket's
//     wait is over by the uptime, at most once, never after a confirmation or a cancel in that boot, never
//     over another pending action, never with a guest running;
//  3. an update or a shutdown that names a run is let through only after a confirmation of that run was
//     taken in the same boot, within its within_s by the uptime, at most once each, the update only when the
//     confirmation named a version, the shutdown only with its delay, and never after a cancel;
//  4. after a cancel nothing arms the machine again in that boot;
//  5. no token is in the log, the status or the record.
//
// FAIRY_RANDOM_RUNS sets the number of sequences (default 150), FAIRY_RANDOM_FROM the first seed.
func TestRandomRunSequences(t *testing.T) {
	runs, from := 150, int64(1)
	if v, err := strconv.Atoi(os.Getenv("FAIRY_RANDOM_RUNS")); err == nil && v > 0 {
		runs = v
	}
	if v, err := strconv.ParseInt(os.Getenv("FAIRY_RANDOM_FROM"), 10, 64); err == nil {
		from = v
	}
	if testing.Short() {
		runs = min(runs, 20)
	}
	for seed := from; seed < from+int64(runs); seed++ {
		if !randomRunSequence(t, seed) {
			t.Fatalf("seed %d (FAIRY_RANDOM_FROM=%d FAIRY_RANDOM_RUNS=1)", seed, seed)
		}
	}
}

type goSeen struct {
	boot             int
	up               time.Duration
	within, delay    int
	to               string
	updates, shutoff int
}

func randomRunSequence(t *testing.T, seed int64) bool {
	rnd := rand.New(rand.NewSource(seed))
	r := newRunRig(t)
	withBootID := rnd.Intn(2) == 0
	if !withBootID {
		r.bootID = ""
	}
	r.mu.Lock()
	r.uptime = time.Duration(5+rnd.Intn(120)) * time.Second
	r.mu.Unlock()
	r.restart()

	// what the test saw
	boot, drift := 0, time.Duration(0)
	type armSeen struct {
		boot int
		id   string
		up   time.Duration
		wait int
	}
	armsInBoot := map[int]*armSeen{}
	everArmed := map[string]bool{}
	gos := map[string]*goSeen{}       // by run id, the confirmation taken last
	cancelled := map[int]bool{}       // boots with a cancel
	cancelledRun := map[string]bool{} // runs that were live at a cancel
	confirmedInBoot := map[int]bool{} // boots with a confirmation of the armed run
	offs := map[int]int{}             // self-offs per boot
	seenOff := 0
	ids := []string{runA, runB, runC, "00000000000000dd"}
	fail := func(f string, a ...any) bool {
		t.Errorf("seed %d, boot %d, uptime %s: %s", seed, boot, r.up(), fmt.Sprintf(f, a...))
		return false
	}
	liveID := func() string {
		if run := r.run(); run != nil && run.State != api.RunCancelled && run.State != api.RunDone {
			return run.ID
		}
		return ""
	}
	checkOffs := func() bool {
		for ; seenOff < len(r.scheduled); seenOff++ {
			s := r.scheduled[seenOff]
			a := armsInBoot[boot]
			offs[boot]++
			switch {
			case a == nil:
				return fail("switched itself off in a boot without a ticket")
			case s.up < a.up+time.Duration(a.wait)*time.Second:
				return fail("switched itself off at %s, the wait ends at %s", s.up, a.up+time.Duration(a.wait)*time.Second)
			case offs[boot] > 1:
				return fail("switched itself off twice in one boot")
			case cancelled[boot]:
				return fail("switched itself off after a cancel in this boot")
			case confirmedInBoot[boot]:
				return fail("switched itself off after the confirmation")
			case r.guests:
				return fail("switched itself off with a guest running")
			case s.who != "run "+a.id:
				return fail("the self-off is on record for %q", s.who)
			}
		}
		return true
	}
	for step := 0; step < 70; step++ {
		switch op := rnd.Intn(20); op {
		case 0, 1, 2: // a ticket: mostly good, sometimes old, from the future or for another machine
			id := ids[rnd.Intn(len(ids))]
			age := r.up() + time.Duration(rnd.Intn(300)-100)*time.Second // signed around the moment the machine started
			machine := approvaltest.MachineID
			if rnd.Intn(8) == 0 {
				machine = "another-machine-BBBBBBBBBB"
			}
			wait, notice := 120+rnd.Intn(900), 30+rnd.Intn(120)
			signedAt := r.Now().Add(-age)
			up, pending := r.up(), r.pending
			_, ref := r.w.Arm(r.signed(signedAt, ticketEntry(machine, id, 420, wait, notice)))
			if ref != nil {
				break
			}
			started := r.Now().Add(-up)
			switch {
			case machine != approvaltest.MachineID:
				return fail("took a ticket for another machine")
			case up >= 600*time.Second:
				return fail("took a ticket after %s of uptime", up)
			case started.Before(signedAt.Add(-60 * time.Second)):
				return fail("took a ticket signed %s after it started", signedAt.Sub(started))
			case r.Now().Sub(signedAt) > 480*time.Second || signedAt.Sub(r.Now()) > 60*time.Second:
				return fail("took a ticket signed %s ago", r.Now().Sub(signedAt))
			case armsInBoot[boot] != nil:
				return fail("took a second ticket in one boot")
			case everArmed[id]:
				return fail("took a ticket of run %s a second time", id)
			case cancelled[boot]:
				return fail("took a ticket after a cancel in this boot")
			case pending:
				return fail("took a ticket while a power action was pending")
			}
			armsInBoot[boot], everArmed[id] = &armSeen{boot, id, up, wait}, true
		case 3, 4: // a confirmation
			id := ids[rnd.Intn(len(ids))]
			if l := liveID(); l != "" && rnd.Intn(3) > 0 {
				id = l
			}
			to := []string{"19-abc", "-"}[rnd.Intn(2)]
			delay, within := 10+rnd.Intn(100), 300+rnd.Intn(600)
			up := r.up()
			if _, ref := r.confirm(goReq(id, to, delay, within)); ref != nil {
				break
			}
			if a := armsInBoot[boot]; a != nil && a.id == id {
				if up >= a.up+time.Duration(a.wait)*time.Second {
					return fail("took a confirmation after the wait was over")
				}
				confirmedInBoot[boot] = true
			}
			if cancelledRun[id] {
				return fail("took a confirmation of a run that was cancelled here")
			}
			gos[id] = &goSeen{boot: boot, up: up, within: within, delay: delay, to: to}
		case 5, 6, 7: // the update or the shutdown of a run
			id := ids[rnd.Intn(len(ids))]
			if l := liveID(); l != "" && rnd.Intn(4) > 0 {
				id = l
			}
			g := gos[id]
			req := update
			if rnd.Intn(2) == 0 {
				d := 10 + rnd.Intn(100)
				if g != nil && rnd.Intn(3) > 0 {
					d = g.delay
				}
				req = power([]string{"shutdown", "shutdown", "shutdown", "reboot"}[rnd.Intn(4)], d)
			}
			up := r.up()
			if _, ref := r.g.AdmitRun(req, id); ref != nil {
				break
			}
			switch {
			case g == nil || g.boot != boot:
				return fail("let %s of run %s through without a confirmation in this boot", req.Verb, id)
			case up >= g.up+time.Duration(g.within)*time.Second:
				return fail("let %s through %s after the confirmation (within_s %d)", req.Verb, up-g.up, g.within)
			case cancelledRun[id]:
				return fail("let %s of a cancelled run through", req.Verb)
			case g.shutoff > 0:
				return fail("let %s through after the run's shutdown", req.Verb)
			}
			if req.Verb == api.ApproveApplyUpdate {
				if g.updates++; g.updates > 1 || g.to == "-" {
					return fail("let update %d through (to %s)", g.updates, g.to)
				}
			} else {
				if *req.Action != "shutdown" || *req.DelayS != g.delay {
					return fail("let %s with delay_s %d through, the confirmation named a shutdown with %d", *req.Action, *req.DelayS, g.delay)
				}
				g.shutoff++
			}
		case 8: // the cancel route
			l := liveID()
			was, err := r.w.Cancel("random")
			if err != nil {
				return fail("cancel: %v", err)
			}
			if was != "" {
				cancelled[boot], cancelledRun[l] = true, true
				if was == api.RunOffPending {
					r.pending = false // the route stops the countdown next
				}
				if st := r.state(); st != api.RunCancelled {
					return fail("after a cancel the run is %q", st)
				}
			}
		case 9: // helper-run cancel on the machine
			l := liveID()
			if _, changed, err := r.files.RunCancel(); err != nil {
				return fail("helper-run cancel: %v", err)
			} else if changed && l != "" {
				cancelled[boot], cancelledRun[l] = true, true
				r.w.Tick()
			}
		case 10: // the service restarts
			r.restart()
		case 11: // a new boot
			off := time.Duration(1+rnd.Intn(3000)) * time.Second
			if !withBootID {
				off += 3 * time.Minute // without a boot id, two boots within two minutes cannot be told apart for the mark
			}
			r.reboot(off, time.Duration(5+rnd.Intn(700))*time.Second)
			boot++
			drift = 0
			seenOff = len(r.scheduled)
		case 12: // the clock is set
			j := time.Duration(rnd.Intn(4000)-2000) * time.Second
			if !withBootID {
				j = time.Duration(rnd.Intn(100)-50) * time.Second
				if drift+j > 100*time.Second || drift+j < -100*time.Second {
					break // without a boot id a clock set by more than two minutes ends a live run at the next restart
				}
			}
			drift += j
			r.jump(j)
		case 13:
			if liveID() == "" || r.state() != api.RunOffPending { // not while the self-off itself is the pending action
				r.pending = rnd.Intn(4) == 0
			}
		case 14:
			r.guests = rnd.Intn(3) == 0
		case 15:
			r.updating = rnd.Intn(3) == 0
		default: // time passes
			r.ticks(time.Duration(1+rnd.Intn(400)) * time.Second)
		}
		r.w.Tick()
		if !checkOffs() {
			return false
		}
		// what the machine says of itself fits what the test saw
		if run := r.run(); run != nil {
			switch {
			case run.State == api.RunArmed && (armsInBoot[boot] == nil || armsInBoot[boot].id != run.ID):
				return fail("says it is armed for %s, and no such ticket was taken in this boot", run.ID)
			case run.State == api.RunConfirmed && (gos[run.ID] == nil || gos[run.ID].boot != boot):
				return fail("says run %s is confirmed, and no confirmation was taken in this boot", run.ID)
			case run.State == api.RunOffPending && offs[boot] != 1:
				return fail("says it is counting down, and %d self-offs were scheduled in this boot", offs[boot])
			}
		}
	}
	before := t.Failed()
	r.noTokenAnywhere(t)
	return !t.Failed() || before
}
