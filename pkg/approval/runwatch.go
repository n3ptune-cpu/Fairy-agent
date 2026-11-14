package approval

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// RunHooks are the parts of the machine a run needs, as the checker reaches them (Windows: the helper's power
// part and the updater service; Linux: the agent's). Fakes in the tests.
type RunHooks struct {
	// Pending reports whether a shutdown, reboot or sleep of Fairy's own is pending.
	Pending func() bool
	// Shutdown schedules the normal delayed shutdown of this machine, the one POST /power schedules: the same
	// countdown, the same notice of the system, on record as pending, stopped by the same cancel. message is
	// shown where the system shows one; who is the requester on record.
	Shutdown func(delay time.Duration, message, who string) error
	// Cancel stops the pending power action (the countdown of a self-off, when the run that started it ended
	// in another way than through the cancel route).
	Cancel func() error
	// Updating reports whether an update is being installed (nil: never).
	Updating func() bool
	// Guests reports whether a guest (a virtual machine or a container) runs on this machine (nil: a machine
	// that has none). An error counts as "one runs".
	Guests func() (bool, error)
}

// RunWatch carries a run out on the checker's side: it takes the ticket (with the look at what is pending),
// counts the wait down on the uptime, starts the self-off when the wait is over, and takes the cancel.
type RunWatch struct {
	g *Gate
	h RunHooks
	// mu makes "the wait is over: schedule the shutdown" and "cancel" one after the other: a cancel that comes
	// while the shutdown is being scheduled waits, and then stops it.
	mu sync.Mutex
	// waitingFor is the run whose self-off this process put off at its time because an update was being
	// installed ("": none). Only that run may still be switched off later than runOffGrace after its time.
	waitingFor string
}

// NewRunWatch returns the watch of g's runs.
func NewRunWatch(g *Gate, h RunHooks) *RunWatch { return &RunWatch{g: g, h: h} }

// Arm is Gate.Arm with this machine's pending power action.
func (w *RunWatch) Arm(ap *api.Approval) (api.RunAnswer, *Refusal) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.g.Arm(ap, w.h.Pending != nil && w.h.Pending())
}

// Go is Gate.Go.
func (w *RunWatch) Go(req api.ApprovalRequest, ap *api.Approval) (api.RunAnswer, *Refusal) {
	return w.g.Go(req, ap)
}

// Cancel is the cancel of a run, as part of every cancel of a power action (the panel's Cancel) on this
// machine: the live run ends, armed, counting down or confirmed. It does not stop a countdown itself: the
// caller's cancel of the pending power action, which comes next, does. An error: the cancel could not be
// written down (see Gate.DisarmRun).
func (w *RunWatch) Cancel(why string) (was string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.g.DisarmRun(why)
}

// Run looks once a second until ctx ends.
func (w *RunWatch) Run(ctx context.Context) {
	w.Tick() // a run from before this service restarted is taken over now, not at the first request
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick()
		}
	}
}

// RunNotice is the text of the self-off's notice (Windows shows it with its countdown): fixed, but for the
// name of who signed the ticket (cleaned when the token was read; its hyphens are written as U+2011, as in
// every notice of Fairy's, see agent.PowerMessage) and the seconds.
func RunNotice(name string, noticeS int) string {
	if name == "" {
		name = "an administrator"
	}
	return fmt.Sprintf("Fairy: this PC was started for an update by %s and nobody confirmed it. Shutdown in %d seconds. To keep it on: shutdown /a",
		strings.ReplaceAll(name, "-", "‑"), noticeS)
}

// Tick is one look. With no live run it does nothing (and reads no file).
//
// When the wait of an armed run is over: not over another pending power action and not on a machine where a
// guest runs (the run is disarmed: the machine stays on); not while an update is being installed (it waits,
// RunUpdateWait at most). Then the shutdown is scheduled with the ticket's notice, once: from here on it is
// the pending power action of this machine, shown and cancelled like any other. A machine that is still
// running a minute after the countdown ended was kept on (`shutdown /a`): the run is over.
//
// A time that passed while nothing looked never ends in a late action. The ticket says "wait_s after the
// arming", not "whenever the service next runs": this watch looks every second, so it finds the wait over more
// than runOffGrace late only when it was not running at that moment (the service was stopped, which the
// holder of the control token can do to the Windows helper; the machine slept, or was "shut down" with Fast
// Startup, and the uptime went on counting). Then the run is disarmed for good and the machine stays on. The
// one exception is the run this same process saw at its time and put off for an update; that one is switched
// off when the update is done, RunUpdateWait after its time at the latest, and no later than runOffGrace
// after that. The countdown itself is the power part's: Windows counts it down and is on time by itself; the
// Linux agent's own timer drops an action whose time passed while it stood still (agent.systemPower).
func (w *RunWatch) Tick() {
	w.mu.Lock()
	defer w.mu.Unlock()
	r, up, stop := w.g.runPoll()
	if stop && w.h.Cancel != nil {
		if err := w.h.Cancel(); err != nil {
			w.g.o.Log.Error("approval: the countdown of a run that ended could not be stopped", "error", firstLine(err.Error()))
		}
	}
	if r == nil || r.State != api.RunArmed || w.waitingFor != r.ID {
		w.waitingFor = ""
	}
	if r == nil {
		return
	}
	ms := func(n int64) time.Duration { return time.Duration(n) * time.Millisecond }
	switch r.State {
	case api.RunArmed:
		deadline := ms(r.ArmedUpMS) + time.Duration(r.WaitS)*time.Second
		if up < deadline {
			return
		}
		if late := up - deadline; late >= RunUpdateWait+runOffGrace || (late >= runOffGrace && w.waitingFor != r.ID) {
			w.waitingFor = ""
			w.g.DisarmRun("the wait ended " + late.Round(time.Second).String() + " ago while nothing looked (this service was not running, or the machine slept): no self-off now, the machine stays on")
			return
		}
		if w.h.Shutdown == nil || (w.h.Pending != nil && w.h.Pending()) {
			w.g.DisarmRun("the wait is over and another power action is pending: no self-off over it")
			return
		}
		if w.h.Guests != nil {
			if on, err := w.h.Guests(); on || err != nil {
				w.g.DisarmRun("the wait is over and a guest runs on this machine (or that cannot be told): no self-off")
				return
			}
		}
		if w.h.Updating != nil && w.h.Updating() && up < deadline+RunUpdateWait {
			if w.waitingFor != r.ID {
				w.waitingFor = r.ID
				w.g.o.Log.Warn("approval: run self-off waits, an update is being installed", "run", r.ID)
			}
			return
		}
		if !w.g.runBeginOff(r.ID) {
			return
		}
		if err := w.h.Shutdown(time.Duration(r.NoticeS)*time.Second, RunNotice(r.Name, r.NoticeS), "run "+r.ID); err != nil {
			w.g.o.Log.Error("approval: run self-off could not be scheduled; the machine stays on", "run", r.ID, "error", firstLine(err.Error()))
			w.g.runOffEnded(r.ID, "the shutdown could not be scheduled")
			return
		}
		w.g.o.Log.Warn("approval: run self-off scheduled", "run", r.ID, "sub", r.Sub, "kid", r.Kid, "notice_s", r.NoticeS)
	case api.RunOffPending:
		if up >= ms(r.OffUpMS)+time.Duration(r.NoticeS)*time.Second+runOffGrace {
			w.g.runOffEnded(r.ID, "the machine is still running after the countdown: the shutdown was stopped on the machine")
		}
	}
}
