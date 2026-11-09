package migrate

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Account kinds (Facts.Kind): what the agent's process runs as.
const (
	KindNew         = "new"          // NT SERVICE\fairy-agent
	KindLocalSystem = "local_system" // can move itself (unless Facts.Ineligible)
	KindOther       = "other"        // LocalService, NetworkService, a user: cannot (needs_admin)
	KindNotService  = "not_service"  // run in a console: nothing to move
)

// Facts are what the platform code found out at start.
type Facts struct {
	Kind    string
	Account string // for /metrics, e.g. "LocalSystem"
	// Ineligible: LocalSystem, but this program may not move itself (not the signed, installed program in
	// C:\Program Files\Fairy, or the service runs another program): why. It then reports needs_admin.
	Ineligible string
	Command    string // what an administrator runs instead
}

func rfc(t int64) string {
	if t <= 0 {
		return ""
	}
	return time.Unix(t, 0).UTC().Format(time.RFC3339)
}

// Report is the /metrics block for facts and st (st may be nil).
func Report(f Facts, st *State, firstTry time.Time) api.MigrationStatus {
	out := api.MigrationStatus{Account: f.Account}
	if st != nil {
		out.Attempts, out.Since = st.Attempt, rfc(st.Updated)
	}
	switch f.Kind {
	case KindNotService:
		out.State = api.MigrationNotNeeded
		return out
	case KindNew:
		switch {
		case st != nil && st.Phase == PhaseDone:
			out.State = api.MigrationDone
		case st != nil && st.unverifiedSwitch():
			out.State, out.Step = api.MigrationPending, StepRestart
		default:
			out.State, out.Attempts, out.Since = api.MigrationNotNeeded, 0, ""
		}
		return out
	case KindLocalSystem:
		if f.Ineligible == "" {
			break
		}
		fallthrough
	default:
		out.State, out.Reason, out.Command = api.MigrationNeedsAdmin, f.Ineligible, f.Command
		if out.Reason == "" {
			out.Reason = "the service runs as " + f.Account + ", which may not change services; an administrator moves it once"
		}
		return out
	}
	switch {
	case st == nil || st.Phase == PhaseDone:
		out.State, out.Step = api.MigrationPending, "waiting"
		if !firstTry.IsZero() {
			out.NextTry = firstTry.UTC().Format(time.RFC3339)
		}
	case st.Phase == PhaseFailed:
		out.State, out.Step, out.Error, out.RolledBack = api.MigrationFailed, st.Step, st.Error, st.RolledBack
		out.NextTry, out.Command = rfc(st.NextTry), f.Command
	default:
		out.State, out.Step = api.MigrationPending, st.Step
	}
	return out
}

// Runner is the agent's side: when to run the Machine, and the /metrics block.
type Runner struct {
	Machine *Machine
	Facts   Facts
	// Ready says what the first attempt still waits for ("": nothing), e.g. the installer that just put this
	// version in place has not reported yet, or a power action is scheduled. Asked every Poll.
	Ready func() string
	// Kick starts the updater service (the new account may): for a switch the Supervisor has not verified.
	Kick func() error
	// MinWait before the first attempt after the agent started listening (default 2 min: an installer that
	// just started this version checks it for up to 90 s and must not see it restart).
	MinWait time.Duration
	// HandoverTimeout: still running as LocalSystem this long after the hand-over, the Supervisor never came
	// (default 10 min).
	HandoverTimeout time.Duration
	Poll            time.Duration // default 10 s
	StoreRetry      time.Duration // after a state read / write error (default 1 h)
	Sleep           func(ctx context.Context, d time.Duration)

	busy     atomic.Bool
	mu       sync.Mutex
	firstTry time.Time
	waiting  string
	cached   *State
	cachedAt time.Time
}

func (r *Runner) sleep(ctx context.Context, d time.Duration) {
	if r.Sleep != nil {
		r.Sleep(ctx, d)
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (r *Runner) now() time.Time { return r.Machine.now() }

// Busy reports whether the migration is changing things now (the agent's Update waits meanwhile).
func (r *Runner) Busy() bool { return r.busy.Load() }

// Status is the /metrics "migration" block (the state file is read at most every 10 s, and after each change).
func (r *Runner) Status() api.MigrationStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cachedAt.IsZero() || r.now().Sub(r.cachedAt) > 10*time.Second {
		if st, err := r.Machine.Store.Load(); err == nil {
			r.cached = st
		}
		r.cachedAt = r.now()
	}
	out := Report(r.Facts, r.cached, r.firstTry)
	if out.State == api.MigrationPending && out.Step == "waiting" && r.waiting != "" {
		out.Reason = r.waiting
	}
	return out
}

func (r *Runner) setWaiting(s string) {
	r.mu.Lock()
	r.waiting = s
	r.cachedAt = time.Time{}
	r.mu.Unlock()
}

// Loop runs until ctx ends (the agent stops) or there is nothing left to do.
func (r *Runner) Loop(ctx context.Context) {
	switch {
	case r.Facts.Kind == KindNew:
		r.kickLoop(ctx)
		return
	case r.Facts.Kind != KindLocalSystem || r.Facts.Ineligible != "":
		return
	}
	logf := r.Machine.logf
	minWait := durOr(r.MinWait, 2*time.Minute)
	poll := durOr(r.Poll, 10*time.Second)
	r.mu.Lock()
	r.firstTry = r.now().Add(minWait)
	r.mu.Unlock()
	r.sleep(ctx, minWait)
	for ctx.Err() == nil {
		if r.Ready != nil {
			if why := r.Ready(); why != "" {
				r.setWaiting(why)
				r.sleep(ctx, poll)
				continue
			}
		}
		r.setWaiting("")
		r.busy.Store(true)
		out := r.Machine.Run(ctx)
		r.mu.Lock()
		r.cachedAt = time.Time{}
		r.mu.Unlock()
		switch out.Kind {
		case OutHanded:
			// the Supervisor stops this process now; if it is still here much later, it never came
			r.sleep(ctx, durOr(r.HandoverTimeout, 10*time.Minute))
			if ctx.Err() != nil {
				return
			}
			logf("migration: still running as LocalSystem %s after the hand-over", durOr(r.HandoverTimeout, 10*time.Minute))
			out = r.Machine.TakeBack(ctx, out.Attempt)
			r.busy.Store(false)
			if out.Kind == OutFailed {
				r.sleepUntil(ctx, out.At)
			}
		case OutFailed, OutWait:
			r.busy.Store(false)
			r.sleepUntil(ctx, out.At)
		case OutInterrupted:
			r.busy.Store(false)
			return // the agent is stopping; the next start resumes
		default: // store error
			r.busy.Store(false)
			retry := durOr(r.StoreRetry, time.Hour)
			why := "the migration state cannot be written"
			if out.Err != nil {
				why += ": " + out.Err.Error()
			}
			r.setWaiting(why + "; trying again in " + retry.String())
			r.sleep(ctx, retry)
			r.setWaiting("")
		}
		r.mu.Lock()
		r.cachedAt = time.Time{}
		r.mu.Unlock()
	}
}

// sleepUntil waits until t, at least a minute (never a tight loop, whatever the clock says).
func (r *Runner) sleepUntil(ctx context.Context, t time.Time) {
	r.sleep(ctx, max(t.Sub(r.now()), time.Minute))
}

// kickLoop: running as the new account while the Supervisor has not verified the switch (e.g. a reboot in
// the middle): give the updater service (started with Windows meanwhile) three minutes, then start it once.
func (r *Runner) kickLoop(ctx context.Context) {
	st, err := r.Machine.Store.Load()
	if err != nil || st == nil || !st.unverifiedSwitch() || r.Kick == nil {
		return
	}
	r.sleep(ctx, 3*time.Minute)
	if ctx.Err() != nil {
		return
	}
	if st, err = r.Machine.Store.Load(); err != nil || st == nil || !st.unverifiedSwitch() {
		return
	}
	r.Machine.logf("migration: the switch to NT SERVICE\\fairy-agent is not confirmed yet; starting the updater service to finish it")
	if err := r.Kick(); err != nil {
		r.Machine.logf("migration: starting the updater service: %v", err)
	}
}
