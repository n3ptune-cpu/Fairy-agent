package approval_test

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// TestRandomRunSequences plays random sequences of everything that can happen to a machine in a run (tickets
// good, bad, old and presented again, confirmations, the run's update and shutdown, cancels through the
// service and on the machine, the record removed, restarts of the service, new boots however soon after the
// last, the clock set by any amount, time passing) and holds every single thing the machine does against what
// it was allowed to do, kept by the test itself from the answers it saw.
//
// The test has a clock of its own that the machine does not own (the issuer's: a ticket is signed by it), so
// the rules that read the machine's clock are held against what really happened:
//
//  1. a ticket is taken only on a machine up for less than 600 s; not older than its valid_s + 60 s, and on a
//     machine that started not more than 60 s before it was signed, both by the real clock but for what the
//     machine's own clock is off at that moment; never while the machine's clock is more than two minutes
//     behind the latest time on its record; never one signed before the record was made anew; at most once
//     per boot; never twice the same ticket, whatever happened in between; never after a cancel in that boot,
//     or after the record was lost in it; never while a power action is pending;
//  2. the clock on record never goes back while the machine can still be armed in that boot;
//  3. the machine switches itself off only in a boot in which a ticket was taken, not before that ticket's
//     wait is over by the uptime and not a minute or more after it (but for a self-off that waited for an
//     update, and then not more than 15 minutes), at most once, never after a confirmation or a cancel in
//     that boot, never over another pending action, never with a guest running, never while an update is
//     being installed unless it waited the 15 minutes out; with the ticket's notice, the notice's text, and
//     under the run's name;
//  4. an update or a shutdown that names a run is let through only after a confirmation of that run was
//     taken in the same boot, within its within_s by the uptime, at most once each, the update only when the
//     confirmation named a version (which is the one handed back), the shutdown only with its delay, never
//     another action, and never after a cancel;
//  5. what the machine says of itself (the "run" of its status) fits: armed only for the ticket of this
//     boot, with off_at at the end of the wait; confirmed only within within_s; counting down only after its
//     one self-off;
//  6. a machine that cannot say which boot this is takes nothing of a run at all;
//  7. no token is in the log, the status or the record.
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

// offSeen is one self-off, with what was true on the machine at the moment it was scheduled.
type offSeen struct {
	sched
	pending, updating, guests bool
}

type ticketSeen struct {
	ap     *api.Approval
	signed time.Time // by the real clock
	id     string
	valid  int
	wait   int
	notice int
	mine   bool
	taken  bool
}

func randomRunSequence(t *testing.T, seed int64) bool {
	rnd := rand.New(rand.NewSource(seed))
	r := newRunRig(t)
	kind := rnd.Intn(12) // 0: a system without a boot id; even: the kernel's id (Linux); odd: the helper's (Windows)
	switch {
	case kind == 0:
		r.bootID = ""
	case kind%2 == 1:
		r.bootID = winBoot
	}
	r.mu.Lock()
	r.uptime = time.Duration(5+rnd.Intn(120)) * time.Second
	r.mu.Unlock()
	var offsSeen []offSeen
	watch := func() { // the service's watch, with a look at the machine at the moment of every self-off
		r.w = approval.NewRunWatch(r.g, approval.RunHooks{
			Pending: func() bool { return r.pending },
			Shutdown: func(d time.Duration, msg, who string) error {
				offsSeen = append(offsSeen, offSeen{sched{d, msg, who, r.up()}, r.pending, r.updating, r.guests})
				r.pending = true
				return nil
			},
			Cancel:   func() error { r.cancels++; r.pending = false; return nil },
			Updating: func() bool { return r.updating },
			Guests:   func() (bool, error) { return r.guests, r.guestsErr },
		})
	}
	restart := func() { r.restart(); watch() }
	restart()

	// what the test saw
	realNow := r.Now() // the clock the machine does not own
	boot := 0
	type armSeen struct {
		id           string
		up           time.Duration
		wait, notice int
		lost         bool // the record was lost after it: the machine knows nothing of this run any more
	}
	armsInBoot := map[int]*armSeen{}
	everArmed := map[string]bool{}    // run ids, as far as the machine can know them (its record)
	gos := map[string]*goSeen{}       // by run id, the confirmation taken last
	closed := map[int]bool{}          // boots with a cancel, or in which the record was lost
	cancelledRun := map[string]bool{} // runs that were live at a cancel
	confirmedInBoot := map[int]bool{} // boots with a confirmation of the armed run
	waited := map[int]bool{}          // boots in which an update was being installed when the wait ended
	offs := map[int]int{}             // self-offs per boot
	var tickets []*ticketSeen
	seenOff := 0
	lastClock, lastClockBoot := int64(0), -1
	ids := []string{runA, runB, runC, "00000000000000dd"}
	fail := func(f string, a ...any) bool {
		t.Errorf("seed %d, boot %d (id %q), uptime %s, clock off by %s: %s", seed, boot, r.bootID, r.up(), r.Now().Sub(realNow), fmt.Sprintf(f, a...))
		return false
	}
	liveID := func() string {
		if run := r.run(); run != nil && run.State != api.RunCancelled && run.State != api.RunDone {
			return run.ID
		}
		return ""
	}
	pass := func(d time.Duration) { // time passes, a second at a time, the watch looking
		for ; d > 0; d -= time.Second {
			r.wait(time.Second)
			realNow = realNow.Add(time.Second)
			if a := armsInBoot[boot]; a != nil && r.updating {
				if late := r.up() - a.up - time.Duration(a.wait)*time.Second; late >= 0 && late < approval.RunOffGrace {
					waited[boot] = true
				}
			}
			r.w.Tick()
		}
	}
	present := func(tk *ticketSeen) bool {
		up, pending, nowM := r.up(), r.pending, r.Now()
		clockSeen := r.files.RunClockSeen()
		born := r.files.RunShow().Born
		_, ref := r.w.Arm(tk.ap)
		if ref != nil {
			return true
		}
		off := nowM.Sub(realNow) // how far the machine's clock is ahead of the real one
		started := realNow.Add(-up)
		switch {
		case r.bootID == "":
			return fail("took a ticket and cannot say which boot this is")
		case !tk.mine:
			return fail("took a ticket for another machine")
		case tk.taken:
			return fail("took the same ticket a second time")
		case up >= 600*time.Second:
			return fail("took a ticket after %s of uptime", up)
		case realNow.Sub(tk.signed) > time.Duration(tk.valid+60)*time.Second-off:
			return fail("took a ticket signed %s ago (valid_s %d)", realNow.Sub(tk.signed), tk.valid)
		case tk.signed.Sub(realNow) > 60*time.Second+off:
			return fail("took a ticket signed %s in its future", tk.signed.Sub(realNow))
		case started.Before(tk.signed.Add(-60*time.Second - off)):
			return fail("took a ticket signed %s after the machine started", tk.signed.Sub(started))
		case clockSeen != 0 && nowM.Unix() < clockSeen-int64(approval.RunClockBack/time.Second):
			return fail("took a ticket with its clock %d s behind the latest time on record", clockSeen-nowM.Unix())
		case born != 0 && tk.signed.Unix() < born:
			return fail("took a ticket signed %d s before the record was made anew", born-tk.signed.Unix())
		case armsInBoot[boot] != nil:
			return fail("took a second ticket in one boot")
		case everArmed[tk.id]:
			return fail("took a ticket of run %s a second time", tk.id)
		case closed[boot]:
			return fail("took a ticket after a cancel in this boot, or after the record was lost in it")
		case pending:
			return fail("took a ticket while a power action was pending")
		}
		tk.taken = true
		armsInBoot[boot], everArmed[tk.id] = &armSeen{id: tk.id, up: up, wait: tk.wait, notice: tk.notice}, true
		if st := r.run(); st == nil || st.State != api.RunArmed || st.ID != tk.id || st.OffAt != nowM.Add(time.Duration(tk.wait)*time.Second).Unix() {
			return fail("the status of a machine that was just armed: %+v, want off_at %d", st, nowM.Add(time.Duration(tk.wait)*time.Second).Unix())
		}
		return true
	}
	checkOffs := func() bool {
		for ; seenOff < len(offsSeen); seenOff++ {
			s := offsSeen[seenOff]
			a := armsInBoot[boot]
			offs[boot]++
			if a == nil {
				return fail("switched itself off in a boot without a ticket")
			}
			deadline := a.up + time.Duration(a.wait)*time.Second
			switch {
			case s.up < deadline:
				return fail("switched itself off at %s, the wait ends at %s", s.up, deadline)
			case s.up >= deadline+approval.RunUpdateWait+approval.RunOffGrace:
				return fail("switched itself off %s after the wait was over", s.up-deadline)
			case s.up >= deadline+approval.RunOffGrace && !waited[boot]:
				return fail("switched itself off %s after the wait was over, and no update was being installed at that time", s.up-deadline)
			case offs[boot] > 1:
				return fail("switched itself off twice in one boot")
			case closed[boot]:
				return fail("switched itself off after a cancel in this boot")
			case confirmedInBoot[boot]:
				return fail("switched itself off after the confirmation")
			case s.guests:
				return fail("switched itself off with a guest running")
			case s.pending:
				return fail("scheduled its self-off over another pending power action")
			case s.updating && s.up < deadline+approval.RunUpdateWait:
				return fail("switched itself off while an update was being installed, %s after the wait was over", s.up-deadline)
			case s.delay != time.Duration(a.notice)*time.Second:
				return fail("the self-off has a notice of %s, the ticket says %d s", s.delay, a.notice)
			case s.message != approval.RunNotice("neptune", a.notice):
				return fail("the self-off's notice reads %q", s.message)
			case s.who != "run "+a.id:
				return fail("the self-off is on record for %q", s.who)
			}
		}
		return true
	}
	lose := func() { // the record is gone: what the machine knew of runs went with it (a run that was live is over)
		closed[boot] = true
		if a := armsInBoot[boot]; a != nil {
			a.lost = true
		}
		everArmed = map[string]bool{}
		gos = map[string]*goSeen{}
		cancelledRun = map[string]bool{}
		lastClock, lastClockBoot = 0, -1
	}
	for step := 0; step < 70; step++ {
		switch op := rnd.Intn(24); op {
		case 0, 1, 2: // a ticket: mostly good, sometimes old, from the future or for another machine
			id := ids[rnd.Intn(len(ids))]
			age := r.up() + time.Duration(rnd.Intn(300)-100)*time.Second // signed around the moment the machine started
			if rnd.Intn(6) == 0 {
				age = time.Duration(rnd.Intn(3000)) * time.Second
			}
			machine := approvaltest.MachineID
			if rnd.Intn(8) == 0 {
				machine = "another-machine-BBBBBBBBBB"
			}
			tk := &ticketSeen{id: id, signed: realNow.Add(-age), valid: 120 + rnd.Intn(481), wait: 120 + rnd.Intn(900), notice: 30 + rnd.Intn(120), mine: machine == approvaltest.MachineID}
			tk.ap = r.signed(tk.signed, ticketEntry(machine, id, tk.valid, tk.wait, tk.notice))
			tickets = append(tickets, tk)
			if !present(tk) {
				return false
			}
		case 3: // a ticket that was presented before, taken or not, is presented again
			if len(tickets) > 0 && !present(tickets[rnd.Intn(len(tickets))]) {
				return false
			}
		case 4, 5: // a confirmation
			id := ids[rnd.Intn(len(ids))]
			if l := liveID(); l != "" && rnd.Intn(3) > 0 {
				id = l
			}
			to := []string{"19-abc", "-"}[rnd.Intn(2)]
			delay, within := 10+rnd.Intn(100), 300+rnd.Intn(1501)
			up, liveBefore := r.up(), liveID()
			if _, ref := r.confirm(goReq(id, to, delay, within)); ref != nil {
				break
			}
			if r.bootID == "" {
				return fail("took a confirmation and cannot say which boot this is")
			}
			if liveBefore != "" && liveBefore != id {
				return fail("took a confirmation of run %s while run %s was live", id, liveBefore)
			}
			if a := armsInBoot[boot]; a != nil && a.id == id && !a.lost {
				if up >= a.up+time.Duration(a.wait)*time.Second {
					return fail("took a confirmation after the wait was over")
				}
				confirmedInBoot[boot] = true
			}
			if cancelledRun[id] {
				return fail("took a confirmation of a run that was cancelled here")
			}
			gos[id] = &goSeen{boot: boot, up: up, within: within, delay: delay, to: to}
		case 6, 7, 8: // the update or the shutdown of a run
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
				req = power([]string{"shutdown", "shutdown", "shutdown", "reboot", "sleep"}[rnd.Intn(5)], d)
			}
			up := r.up()
			use := rnd.Intn(4) > 0
			var to string
			var ref *approval.Refusal
			if use {
				to, ref = r.g.AdmitRun(req, id)
			} else {
				to, ref = r.g.RunCovers(req, id) // the look that uses nothing up
			}
			if ref != nil {
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
				if g.updates > 0 || g.to == "-" || to != g.to {
					return fail("let an update through (number %d, the confirmation named %q, handed back %q)", g.updates+1, g.to, to)
				}
				if use {
					g.updates++
				}
			} else {
				if *req.Action != "shutdown" || *req.DelayS != g.delay {
					return fail("let %s with delay_s %d through, the confirmation named a shutdown with %d", *req.Action, *req.DelayS, g.delay)
				}
				if use {
					g.shutoff++
				}
			}
		case 9: // the cancel route
			l := liveID()
			was, err := r.w.Cancel("random")
			if err != nil {
				return fail("cancel: %v", err)
			}
			if was != "" {
				closed[boot], cancelledRun[l] = true, true
				if was == api.RunOffPending {
					r.pending = false // the route stops the countdown next
				}
				if st := r.state(); st != api.RunCancelled {
					return fail("after a cancel the run is %q", st)
				}
			}
		case 10: // helper-run cancel on the machine
			l := liveID()
			if _, changed, err := r.files.RunCancel(r.stamp()); err != nil {
				return fail("helper-run cancel: %v", err)
			} else if changed && l != "" {
				closed[boot], cancelledRun[l] = true, true
				r.w.Tick()
			}
		case 11: // the service restarts
			restart()
		case 12, 13: // a new boot: after a night, or at once
			off := time.Duration(1+rnd.Intn(3000)) * time.Second
			up := time.Duration(5+rnd.Intn(700)) * time.Second
			if rnd.Intn(3) == 0 {
				off, up = time.Duration(1+rnd.Intn(30))*time.Second, time.Duration(15+rnd.Intn(60))*time.Second
			}
			r.reboot(off, up)
			watch()
			realNow = realNow.Add(off + up)
			boot++
			seenOff = len(offsSeen)
		case 14: // the clock is set, by any amount
			j := time.Duration(rnd.Intn(4000)-2000) * time.Second
			switch rnd.Intn(6) {
			case 0:
				j = time.Duration(rnd.Intn(60*24*3600)-30*24*3600) * time.Second
			case 1:
				j = realNow.Sub(r.Now()) // put right
			}
			r.jump(j)
		case 15:
			if liveID() == "" || r.state() != api.RunOffPending { // not while the self-off itself is the pending action
				r.pending = rnd.Intn(4) == 0
			}
		case 16:
			r.guests = rnd.Intn(3) == 0
		case 17:
			r.updating = rnd.Intn(3) == 0
		case 18: // the record is removed on the machine (an administrator), sometimes with the service stopped
			if rnd.Intn(4) == 0 {
				if r.files.RunShow().Exists {
					lose()
				}
				os.Remove(r.files.RunPath())
				if rnd.Intn(2) == 0 {
					restart()
				}
			}
		default: // time passes
			pass(time.Duration(1+rnd.Intn(400)) * time.Second)
		}
		r.w.Tick()
		if !checkOffs() {
			return false
		}
		if r.bootID == "" && (len(offsSeen) != 0 || r.run() != nil || r.touched()) {
			return fail("something of a run on a machine that cannot say which boot this is: %+v, record %s", r.run(), r.record(t))
		}
		// the clock on record does not go back while the machine can still be armed in this boot
		if c := r.files.RunClockSeen(); c != 0 {
			if boot == lastClockBoot && c < lastClock && r.up() < 600*time.Second {
				return fail("the clock on record went back from %d to %d", lastClock, c)
			}
			lastClock, lastClockBoot = c, boot
		}
		// what the machine says of itself fits what the test saw
		if run := r.run(); run != nil {
			switch {
			case run.State == api.RunArmed && (armsInBoot[boot] == nil || armsInBoot[boot].id != run.ID):
				return fail("says it is armed for %s, and no such ticket was taken in this boot", run.ID)
			case run.State == api.RunArmed && closed[boot]:
				return fail("says it is armed after a cancel in this boot")
			case run.State == api.RunConfirmed && (gos[run.ID] == nil || gos[run.ID].boot != boot):
				return fail("says run %s is confirmed, and no confirmation was taken in this boot", run.ID)
			case run.State == api.RunConfirmed && r.up() >= gos[run.ID].up+time.Duration(gos[run.ID].within)*time.Second:
				return fail("says run %s is confirmed %s after the confirmation (within_s %d)", run.ID, r.up()-gos[run.ID].up, gos[run.ID].within)
			case run.State == api.RunOffPending && offs[boot] != 1:
				return fail("says it is counting down, and %d self-offs were scheduled in this boot", offs[boot])
			}
		}
	}
	before := t.Failed()
	r.noTokenAnywhere(t)
	return !t.Failed() || before
}
