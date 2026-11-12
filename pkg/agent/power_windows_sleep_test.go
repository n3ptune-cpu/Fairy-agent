package agent

// Review of fix7, RF7-01: Windows, the sleep that was carried out and the cancel of the next shutdown.
//
// pendingSleep is the product's code (power.go) and runs here as it runs on Windows. What stands under it in
// the tests that go through Power and RememberedPower is winOS (power_remember_one_test.go): the steps of
// power_windows.go's systemPower in their order, with counters in the place of SetSuspendState,
// InitiateSystemShutdownEx and AbortSystemShutdown. That those lines of power_windows.go are what winOS says
// is by reading; nothing here ran on Windows.

import (
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// waitFor waits (briefly) until ok says yes.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		if ok() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("waited 2 s for: %s", what)
}

// A sleep is "waiting" only until its timer runs. Afterwards stop finds nothing, also inside the timer's own
// function (so a sleep that fails there leaves nothing behind either).
func TestASleepThatRanIsNoLongerWaiting(t *testing.T) {
	var s pendingSleep
	var ran, waitingInside atomic.Int32
	s.set(10*time.Millisecond, func() {
		if s.stop() {
			waitingInside.Add(1)
		}
		ran.Add(1)
	})
	waitFor(t, "the sleep's timer", func() bool { return ran.Load() == 1 })
	if waitingInside.Load() != 0 {
		t.Fatal("a sleep was still waiting while it was being carried out")
	}
	if s.stop() {
		t.Fatal("stop found a sleep after the sleep was carried out: the next Cancel would stop that and abort nothing")
	}
	time.Sleep(30 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("the sleep ran %d times", ran.Load())
	}
}

// Stopped in time: never run, and stop finds it once. Replaced by a later sleep: only the later one runs.
func TestASleepThatWasStoppedOrReplacedNeverRuns(t *testing.T) {
	var s pendingSleep
	var first, second atomic.Int32
	s.set(time.Hour, func() { first.Add(1) })
	if !s.stop() || s.stop() {
		t.Fatal("stop: want yes once, then no")
	}
	s.set(30*time.Millisecond, func() { first.Add(1) })
	s.set(40*time.Millisecond, func() { second.Add(1) })
	waitFor(t, "the later sleep", func() bool { return second.Load() == 1 })
	time.Sleep(30 * time.Millisecond)
	if first.Load() != 0 || second.Load() != 1 || s.stop() {
		t.Fatalf("the replaced sleep ran %d time(s), the later one %d", first.Load(), second.Load())
	}
}

// A stop in the moment the timer fires, and a replacement in that moment: every round either the stop (or the
// replacement) took the sleep away and it never runs, or it ran once and stop says "nothing waiting".
func TestStopAndTheSleepTimerNeverBothWin(t *testing.T) {
	var s pendingSleep
	stopped, ran := 0, 0
	for i := 0; i < 400; i++ {
		var n atomic.Int32
		delay := time.Duration(i%8) * 50 * time.Microsecond
		s.set(delay, func() { n.Add(1) })
		time.Sleep(delay)
		took := s.stop()
		time.Sleep(time.Millisecond)
		switch {
		case took && n.Load() == 0:
			stopped++
		case !took:
			waitFor(t, "the sleep that stop did not find", func() bool { return n.Load() == 1 })
			ran++
		default:
			t.Fatalf("round %d: stop said it took the sleep away, and the sleep ran %d time(s)", i, n.Load())
		}
	}
	var old, later atomic.Int32
	for i := 0; i < 200; i++ {
		delay := time.Duration(i%8) * 50 * time.Microsecond
		was := old.Load()
		s.set(delay, func() { old.Add(1) })
		time.Sleep(delay)
		s.set(time.Hour, func() { later.Add(1) })
		time.Sleep(time.Millisecond)
		if !s.stop() || later.Load() != 0 || old.Load()-was > 1 {
			t.Fatalf("round %d: the later sleep was not the one waiting (it ran %d time(s), the old one %d)", i, later.Load(), old.Load()-was)
		}
	}
	t.Logf("400 rounds: stopped in time %d, ran %d", stopped, ran)
}

// winRig is one helper service over "Windows", and the agent over it, on a clock the test moves.
type winRig struct {
	win    *winOS
	c      *clock
	helper *RememberedPower
	cl     *statusClient
	agent  *Power
}

func newWinRig(t *testing.T, fast time.Duration) *winRig {
	t.Helper()
	r := &winRig{win: &winOS{fast: fast}, c: newClock()}
	r.helper = start(r.win, PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}, r.c)
	r.cl = &statusClient{helper: r.helper}
	r.agent = agentOver(r.cl, r.c)
	t.Cleanup(func() { r.win.sleep.stop() })
	return r
}

func (r *winRig) ask(t *testing.T, action string, delayS int, who string) {
	t.Helper()
	if st, b := r.agent.Handle(PowerRequest{Action: action, DelayS: &delayS, RequestedBy: who}); st != 200 {
		t.Fatalf("%s: %d %v", action, st, b)
	}
	r.cl.refresh()
}

// shutdownThenCancel asks for a shutdown and cancels it a minute later: Windows must be asked to abort, once,
// and count nothing down afterwards; the helper's record and the agent's are gone; a further cancel asks nobody.
func (r *winRig) shutdownThenCancel(t *testing.T, after string) {
	t.Helper()
	r.ask(t, "shutdown", 3600, "bob")
	if _, _, counting := r.win.Snap(); counting != "shutdown" {
		t.Fatalf("%s: the shutdown was not taken (Windows counts %q)", after, counting)
	}
	if r.win.sleepWaiting() {
		t.Fatalf("%s: a sleep is waiting next to the shutdown", after)
	}
	r.c.advance(time.Minute)
	_, before, _ := r.win.Snap()
	st, b := r.agent.Handle(PowerRequest{Action: "cancel", RequestedBy: "bob"})
	r.cl.refresh()
	_, aborts, counting := r.win.Snap()
	if st != 200 || aborts-before != 1 || counting != "" {
		t.Fatalf("%s, then a shutdown and its cancel: %d %v; Windows was asked to abort %d time(s) and still counts down %q; want 200, 1 and nothing",
			after, st, b, aborts-before, counting)
	}
	if _, on := r.helper.PendingAction(); on || r.agent.State()["pending"] != nil {
		t.Fatalf("%s: still on record after the cancel", after)
	}
	if st, _ := r.agent.Handle(PowerRequest{Action: "cancel"}); st != 200 {
		t.Fatalf("%s: a second cancel: %d", after, st)
	}
	if _, again, _ := r.win.Snap(); again != aborts {
		t.Fatalf("%s: a cancel with nothing pending asked Windows to abort", after)
	}
}

// The order of the finding, with no clock gap and no restart: Sleep from the panel, the PC sleeps and is
// woken, half an hour later Shut down, then Cancel. The cancel must abort the shutdown. It answered
// "cancelled", stopped the sleep timer that had run half an hour before, and aborted nothing.
func TestACancelAfterASleepThatWasCarriedOutAbortsTheShutdown(t *testing.T) {
	r := newWinRig(t, 20*time.Millisecond)
	r.ask(t, "sleep", 60, "alice")
	waitFor(t, "SetSuspendState", func() bool { n, _, _ := r.win.Snap(); return n == 1 })
	r.c.advance(31 * time.Minute) // the PC slept, was woken, and half an hour went by
	r.cl.refresh()
	if p := r.agent.State()["pending"]; p != nil {
		t.Fatalf("the sleep is still shown: %v", p)
	}
	r.shutdownThenCancel(t, "a sleep that was carried out")
	if n, _, _ := r.win.Snap(); n != 1 {
		t.Fatalf("SetSuspendState was called %d times", n)
	}
}

// The other ways a sleep can end, each followed by a shutdown and its cancel: cancelled in time; still
// waiting in the helper while its record has ended (the helper's record ends by Windows' uptime, the timer
// runs on the process's own clock: when the two come apart, the sleep is dropped as the shutdown is taken, and
// never runs); one sleep in the place of another.
func TestACancelAbortsTheShutdownHoweverTheSleepBeforeItEnded(t *testing.T) {
	t.Run("the sleep was cancelled", func(t *testing.T) {
		r := newWinRig(t, 0)
		r.ask(t, "sleep", 60, "alice")
		if st, b := r.agent.Handle(PowerRequest{Action: "cancel"}); st != 200 || r.win.sleepWaiting() {
			t.Fatal(st, b)
		}
		if _, aborts, _ := r.win.Snap(); aborts != 0 {
			t.Fatal("the cancel of a sleep asked Windows to abort a shutdown") // somebody else's: not Fairy's to abort
		}
		r.cl.refresh()
		r.shutdownThenCancel(t, "a sleep that was cancelled")
	})
	t.Run("the sleep still waits and its record has ended", func(t *testing.T) {
		r := newWinRig(t, 150*time.Millisecond)
		r.ask(t, "sleep", 60, "alice")
		r.c.advance(31 * time.Minute) // by the uptime its time is long over; its timer has not run
		r.cl.refresh()
		if !r.win.sleepWaiting() {
			t.Skip("the timer ran before the test got here")
		}
		r.shutdownThenCancel(t, "a sleep that still waited")
		time.Sleep(250 * time.Millisecond)
		if n, _, _ := r.win.Snap(); n != 0 {
			t.Fatalf("the dropped sleep was carried out all the same (%d)", n)
		}
	})
	t.Run("a sleep, cancelled, and a second sleep that was carried out", func(t *testing.T) {
		r := newWinRig(t, 20*time.Millisecond)
		r.win.fast = time.Hour
		r.ask(t, "sleep", 60, "alice")
		if st, b := r.agent.Handle(PowerRequest{Action: "cancel"}); st != 200 {
			t.Fatal(st, b)
		}
		r.cl.refresh()
		r.win.fast = 20 * time.Millisecond
		r.ask(t, "sleep", 60, "alice")
		waitFor(t, "SetSuspendState", func() bool { n, _, _ := r.win.Snap(); return n == 1 })
		r.c.advance(31 * time.Minute)
		r.cl.refresh()
		r.shutdownThenCancel(t, "a second sleep that was carried out")
	})
}
