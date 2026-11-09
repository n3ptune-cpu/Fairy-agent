package migrate

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// AgentInfo is the agent's service as the service manager sees it.
type AgentInfo struct {
	Running    bool
	NewAccount bool   // its process runs as NT SERVICE\fairy-agent
	PID        uint32 // 0 when not running
}

// SupervisorOps are the Supervisor's hands (platform code, as LocalSystem).
type SupervisorOps interface {
	Agent(ctx context.Context) (AgentInfo, error)
	StopAgent(ctx context.Context) error  // stop it and wait until it has stopped
	StartAgent(ctx context.Context) error // start it and wait until the service manager says running
	Healthy(ctx context.Context) error    // /metrics answers with this version
	Rollback(ctx context.Context, o Original) error
	Finish(ctx context.Context) error // the updater service back to manual start
}

// Supervisor finishes a switch in the fairy-agent-update service.
type Supervisor struct {
	Store Store
	Ops   SupervisorOps
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) // default: a timer
	Logf  func(format string, args ...any)
	// Settle is how long the new process must keep running (same pid) to count; default 20 s.
	Settle time.Duration
	// Timeout for the new agent to become healthy; default 120 s.
	Timeout time.Duration
	// Interval between checks; default 1 s.
	Interval time.Duration
	Backoff  []time.Duration
}

func (s *Supervisor) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Supervisor) sleep(ctx context.Context, d time.Duration) {
	if s.Sleep != nil {
		s.Sleep(ctx, d)
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func (s *Supervisor) logf(f string, a ...any) {
	if s.Logf != nil {
		s.Logf(f, a...)
	}
}

func durOr(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Run finishes an unverified switch, if the state says there is one (handled true); otherwise it does
// nothing (handled false: the caller goes on with its normal work, e.g. installing a staged update).
func (s *Supervisor) Run(ctx context.Context) (handled bool, err error) {
	st, err := s.Store.Load()
	if err != nil {
		return false, err
	}
	if st == nil || !st.unverifiedSwitch() {
		return false, nil
	}
	s.logf("migration: attempt %d: restarting fairy-agent under NT SERVICE\\fairy-agent", st.Attempt)
	info, err := s.Ops.Agent(ctx)
	if err != nil {
		return true, s.fail(ctx, st, fmt.Errorf("asking the service manager: %w", err), false)
	}
	// The normal hand-over: the old agent answered /metrics a moment ago, so the new one must too. After a
	// reboot (the agent stopped, or already running as the new account) the network may not be up yet: then
	// running steadily as the new account is enough.
	requireMetrics := info.Running && !info.NewAccount
	if !(info.Running && info.NewAccount) {
		if info.Running {
			if err := s.Ops.StopAgent(ctx); err != nil {
				return true, s.fail(ctx, st, fmt.Errorf("stopping the agent: %w", err), true)
			}
		}
		if err := s.Ops.StartAgent(ctx); err != nil {
			return true, s.fail(ctx, st, fmt.Errorf("starting the agent as NT SERVICE\\fairy-agent: %w", err), true)
		}
	}
	if err := s.verify(ctx, requireMetrics); err != nil {
		return true, s.fail(ctx, st, err, true)
	}
	st.Phase, st.Step, st.Error = PhaseDone, "", ""
	st.Switched, st.RolledBack, st.Failures, st.Resumes, st.NextTry = false, false, 0, 0, 0
	if !st.done(StepRestart) {
		st.Done = append(st.Done, StepRestart)
	}
	st.Updated = s.now().Unix()
	if err := s.Store.Save(st); err != nil {
		s.logf("migration: done, but the state could not be written: %v", err)
	}
	if err := s.Ops.Finish(ctx); err != nil {
		s.logf("migration: setting the updater service back to manual start: %v", err)
	}
	s.logf("migration: done: fairy-agent runs as NT SERVICE\\fairy-agent")
	return true, nil
}

// verify waits until the agent runs as the new account, the same process for Settle, and (requireMetrics)
// answers /metrics twice in a row.
func (s *Supervisor) verify(ctx context.Context, requireMetrics bool) error {
	settle, every := durOr(s.Settle, 20*time.Second), durOr(s.Interval, time.Second)
	deadline := s.now().Add(durOr(s.Timeout, 120*time.Second))
	var pid uint32
	var since time.Time
	passes := 0
	last := errors.New("not running yet")
	for {
		info, err := s.Ops.Agent(ctx)
		switch {
		case err != nil:
			last, pid = err, 0
		case !info.Running:
			last, pid = errors.New("the agent's service is not running"), 0
		case !info.NewAccount:
			last, pid = errors.New("the agent's process does not run as NT SERVICE\\fairy-agent"), 0
		default:
			if info.PID != pid { // first seen, or restarted by the service manager (it exited)
				pid, since, passes = info.PID, s.now(), 0
			}
			if requireMetrics {
				if herr := s.Ops.Healthy(ctx); herr != nil {
					last, passes = herr, 0
				} else {
					passes++
				}
			}
			if s.now().Sub(since) >= settle && (!requireMetrics || passes >= 2) {
				return nil
			}
			if !requireMetrics || passes > 0 {
				last = errors.New("the new process did not keep running long enough")
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if s.now().After(deadline) {
			return fmt.Errorf("the agent did not come up as NT SERVICE\\fairy-agent: %w", last)
		}
		s.sleep(ctx, every)
	}
}

// fail puts the service back on LocalSystem (stopped first when restart is set) and starts it again. When ctx
// has ended (Windows is shutting down, the updater service is being stopped) it does nothing: the state still
// says the switch is unverified, so the next start of the updater service (with Windows) finishes it.
func (s *Supervisor) fail(ctx context.Context, st *State, cause error, restart bool) error {
	if ctx.Err() != nil {
		s.logf("migration: interrupted (%v); the next start of the updater service finishes it", cause)
		return ctx.Err()
	}
	ctx = context.WithoutCancel(ctx)
	s.logf("migration: %v; rolling back to LocalSystem", cause)
	msg := cause.Error()
	if restart {
		if err := s.Ops.StopAgent(ctx); err != nil {
			s.logf("migration: stopping the agent before the rollback: %v", err)
		}
	}
	o := Original{Account: LocalSystem}
	if st.Orig != nil {
		o = *st.Orig
	}
	rolled := true
	if err := s.Ops.Rollback(ctx, o); err != nil {
		rolled = false
		msg += "; rolling back FAILED: " + err.Error()
	}
	if err := s.Ops.StartAgent(ctx); err != nil {
		msg += "; starting the agent again: " + err.Error()
	}
	st.Phase, st.Step, st.Error = PhaseFailed, StepRestart, truncate(msg)
	st.Failures++
	st.Switched, st.RolledBack = !rolled, rolled
	st.Done, st.Resumes = nil, 0
	next := s.now().Add(Backoff(s.Backoff, st.Failures))
	st.NextTry, st.Updated = next.Unix(), s.now().Unix()
	if err := s.Store.Save(st); err != nil {
		s.logf("migration: cannot write the state: %v", err)
	}
	if err := s.Ops.Finish(ctx); err != nil {
		s.logf("migration: setting the updater service back to manual start: %v", err)
	}
	s.logf("migration: failed: %s; next try %s", st.Error, next.Format(time.RFC3339))
	return errors.New(st.Error)
}
