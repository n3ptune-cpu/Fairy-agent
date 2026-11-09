// Package migrate moves a Windows agent that still runs as LocalSystem (installed by fairy-agent 0.4.x, then
// updated through the panel) to its own account NT SERVICE\fairy-agent by itself: the same end state as
// `fairy-agent setup-self-update`, without an administrator at the PC.
//
// The work is split in two:
//
//   - Machine runs in the agent while it is still LocalSystem: one step after another (Steps), each one
//     idempotent, the state written to an administrators-only file before and after each step. The switch step
//     changes the service's account (effective at its next start); the restart step hands over to the
//     Supervisor and the agent waits to be stopped.
//   - Supervisor runs in the fairy-agent-update service (LocalSystem, the installed program): it stops the
//     agent, starts it under the new account and checks it (running as the new account, the same process for a
//     while, /metrics answering with this version). If that fails, it puts the service back on LocalSystem,
//     starts it again and records the failure.
//
// Interrupted anywhere (crash, reboot, Stop-Service), the next start resumes: the old account resumes the
// steps, a service already switched is finished by the Supervisor (the updater service starts with Windows
// while a switch is not yet verified, and the new agent starts it too). A failed attempt is rolled back and
// retried only after a growing pause (Backoff), never in a loop. Nothing here takes a path or command from
// config.yaml or the network: the platform code (cmd/fairy-agent) does the steps with fixed paths.
package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"
)

// The steps, in order.
const (
	StepProgramFolder = "program_folder" // the program folder: administrators only (0.4.2 let the service write it)
	StepFolders       = "folders"        // C:\ProgramData\fairy-agent: config and tokens readable by the new account
	StepUpdater       = "updater"        // the fairy-agent-update service, update\ and state\ folders
	StepFans          = "fans"           // fans to the BMC's automatic mode (fan control in this process only)
	StepHelper        = "helper"         // the fairy-agent-helper service, when config.yaml needs it (or one exists)
	StepFirewall      = "firewall"       // the helper's block rules, in and out, for its service SID
	StepCounters      = "counters"       // the new account into Performance Monitor Users (performance counters)
	StepSwitch        = "switch"         // the service: NT SERVICE\fairy-agent, SeChangeNotifyPrivilege only
	StepRestart       = "restart"        // the updater service restarts the agent under the new account
)

// Steps is the order the Machine works in.
var Steps = []string{StepProgramFolder, StepFolders, StepUpdater, StepFans, StepHelper, StepFirewall, StepCounters, StepSwitch, StepRestart}

// Phases (State.Phase).
const (
	PhaseRunning    = "running"    // the agent (old account) works through the steps
	PhaseRestarting = "restarting" // switched; the Supervisor restarts the agent under the new account
	PhaseDone       = "done"       // verified running as the new account
	PhaseFailed     = "failed"     // rolled back (or not switched yet); see Error, NextTry
)

// LocalSystem is the only account this package moves from, and the only one a rollback restores.
const LocalSystem = "LocalSystem"

// State is the state file (C:\ProgramData\fairy-agent\migration\state.json, administrators only).
type State struct {
	Phase    string `json:"phase"`
	Attempt  int    `json:"attempt"`  // attempts so far, the current one included
	Failures int    `json:"failures"` // failed attempts in a row (the pause before the next grows with it)
	Resumes  int    `json:"resumes"`  // how often the current attempt was resumed after an interruption
	// Done are the steps of the current attempt that finished.
	Done []string `json:"done,omitempty"`
	// Step is the step in progress (running) or the one that failed (failed).
	Step  string `json:"step,omitempty"`
	Error string `json:"error,omitempty"`
	// Switched: the service's account may have been changed in this attempt (set before the change), so a
	// failure must roll it back.
	Switched   bool      `json:"switched,omitempty"`
	RolledBack bool      `json:"rolled_back,omitempty"`
	Orig       *Original `json:"orig,omitempty"` // what a rollback restores, saved before the switch
	Version    string    `json:"version,omitempty"`
	Started    int64     `json:"started,omitempty"` // Unix seconds: this attempt began
	Updated    int64     `json:"updated"`           // Unix seconds: last write
	NextTry    int64     `json:"next_try,omitempty"`
}

// Original is the service configuration before the switch.
type Original struct {
	Account string `json:"account"` // always LocalSystem (Validate refuses anything else)
	SidType uint32 `json:"sid_type"`
	// Privileges the service is given back (its RequiredPrivileges before, or every privilege its LocalSystem
	// token held when that list was empty).
	Privileges []string `json:"privileges,omitempty"`
}

var privRe = regexp.MustCompile(`^Se[A-Za-z]{2,64}Privilege$`)

// Validate refuses a state file that does not look like one this package wrote.
func (s *State) Validate() error {
	switch s.Phase {
	case PhaseRunning, PhaseRestarting, PhaseDone, PhaseFailed:
	default:
		return fmt.Errorf("unknown phase %q", s.Phase)
	}
	if s.Step != "" && !slices.Contains(Steps, s.Step) {
		return fmt.Errorf("unknown step %q", s.Step)
	}
	if len(s.Done) > len(Steps) {
		return errors.New("too many steps")
	}
	for _, d := range s.Done {
		if !slices.Contains(Steps, d) {
			return fmt.Errorf("unknown step %q", d)
		}
	}
	if s.Attempt < 0 || s.Failures < 0 || s.Resumes < 0 || len(s.Error) > 2000 || len(s.Version) > 64 {
		return errors.New("out of range")
	}
	if o := s.Orig; o != nil {
		if o.Account != LocalSystem {
			return fmt.Errorf("original account %q: only LocalSystem is restored", o.Account)
		}
		if o.SidType > 3 || len(o.Privileges) > 64 {
			return errors.New("original service settings out of range")
		}
		for _, p := range o.Privileges {
			if !privRe.MatchString(p) {
				return fmt.Errorf("not a privilege name: %q", p)
			}
		}
	}
	return nil
}

func (s *State) done(step string) bool { return slices.Contains(s.Done, step) }

// unverifiedSwitch: the service may run as the new account, not yet checked by the Supervisor.
func (s *State) unverifiedSwitch() bool {
	return s.Phase == PhaseRestarting || (s.Phase == PhaseRunning && s.Switched)
}

// Store keeps the State.
type Store interface {
	Load() (*State, error) // nil, nil: there is none yet
	Save(*State) error
}

// MaxStateSize bounds the state file.
const MaxStateSize = 16 << 10

// FileStore is a Store in one JSON file, replaced atomically (written next to it, then renamed).
type FileStore struct {
	Path string
	// Prepare makes the folder safe before a write (Windows: administrators-only, owned by Administrators).
	Prepare func(dir string) error
	// Check refuses a folder others could have written (Windows: collect.TrustedFolder) before a read.
	Check func(dir string) error
}

// Load reads the state; a missing file is (nil, nil).
func (f *FileStore) Load() (*State, error) {
	dir := filepath.Dir(f.Path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if f.Check != nil {
		if err := f.Check(dir); err != nil {
			return nil, fmt.Errorf("migration state folder: %w", err)
		}
	}
	st, err := os.Lstat(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", f.Path)
	}
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, MaxStateSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxStateSize {
		return nil, fmt.Errorf("%s is too large", f.Path)
	}
	var s State
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	return &s, nil
}

// Save writes the state.
func (f *FileStore) Save(s *State) error {
	if err := s.Validate(); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if f.Prepare != nil {
		if err := f.Prepare(dir); err != nil {
			return fmt.Errorf("migration state folder: %w", err)
		}
	}
	tmp, err := os.CreateTemp(dir, ".state-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), f.Path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// Ops does the steps (platform code).
type Ops interface {
	// Step runs one step; each is idempotent (run again after an interruption, it changes nothing done).
	Step(ctx context.Context, step string) error
	// Capture reads the service's configuration before the switch (it must be LocalSystem).
	Capture(ctx context.Context) (Original, error)
	// Rollback puts the service back on o (account, SID type, privileges) and the updater on manual start.
	Rollback(ctx context.Context, o Original) error
}

// DefaultBackoff is the pause after the 1st, 2nd and 3rd failed attempt in a row (the last one repeats).
var DefaultBackoff = []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour}

// Outcomes of Machine.Run.
const (
	OutHanded      = "handed"      // all steps done; the Supervisor restarts the agent now
	OutFailed      = "failed"      // the attempt failed (rolled back where needed); wait for NextTry
	OutWait        = "wait"        // nothing done: a failed attempt's pause is not over (At)
	OutInterrupted = "interrupted" // ctx ended during a step: the next start resumes
	OutStoreError  = "store_error" // the state could not be read or written: nothing was changed after that
)

// Outcome is what Machine.Run did.
type Outcome struct {
	Kind    string
	At      time.Time // OutWait, OutFailed: no new attempt before this
	Err     error
	Attempt int
}

// Machine runs the steps in the agent (old account).
type Machine struct {
	Store      Store
	Ops        Ops
	Version    string
	Now        func() time.Time
	Logf       func(format string, args ...any)
	Backoff    []time.Duration // default DefaultBackoff
	MaxResumes int             // resumes of one attempt after interruptions (default 2), then it counts as failed
}

func (m *Machine) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func (m *Machine) logf(f string, a ...any) {
	if m.Logf != nil {
		m.Logf(f, a...)
	}
}

func (m *Machine) maxResumes() int {
	if m.MaxResumes > 0 {
		return m.MaxResumes
	}
	return 2
}

// Backoff is the pause after the n-th failed attempt in a row (n >= 1).
func Backoff(b []time.Duration, n int) time.Duration {
	if len(b) == 0 {
		b = DefaultBackoff
	}
	return b[min(max(n, 1), len(b))-1]
}

// Decision kinds (Decide).
const (
	DoStart  = "start"  // a new attempt
	DoResume = "resume" // continue the interrupted attempt
	DoAbort  = "abort"  // interrupted too often: count it as failed (roll back)
	DoWait   = "wait"   // a failed attempt's pause is not over
)

// Decide says what the agent, running as LocalSystem, does with st at now.
func Decide(st *State, now time.Time, maxResumes int) (string, time.Time) {
	switch {
	case st == nil, st.Phase == PhaseDone: // done but LocalSystem again: someone put it back; start over
		return DoStart, time.Time{}
	case st.Phase == PhaseFailed:
		if next := time.Unix(st.NextTry, 0); now.Before(next) {
			return DoWait, next
		}
		return DoStart, time.Time{}
	}
	// running or restarting: the last attempt was interrupted (crash, reboot, stop), or the restart did not
	// happen although the service is still LocalSystem
	if st.Resumes >= maxResumes {
		return DoAbort, time.Time{}
	}
	return DoResume, time.Time{}
}

func (m *Machine) save(st *State) error {
	st.Updated = m.now().Unix()
	st.Version = m.Version
	return m.Store.Save(st)
}

// Run is one attempt: start (or resume) and go through the steps, until the hand-over to the Supervisor or a
// failure. Call it at most once per start and not again before Outcome.At.
func (m *Machine) Run(ctx context.Context) Outcome {
	st, err := m.Store.Load()
	if err != nil {
		m.logf("migration: cannot read the state (%v); starting over", err)
		st = nil
	}
	action, at := Decide(st, m.now(), m.maxResumes())
	switch action {
	case DoWait:
		return Outcome{Kind: OutWait, At: at, Attempt: st.Attempt}
	case DoStart:
		next := &State{Phase: PhaseRunning, Attempt: 1, Started: m.now().Unix()}
		if st != nil {
			next.Attempt = st.Attempt + 1
			if st.Phase == PhaseFailed {
				next.Failures = st.Failures
			}
		}
		st = next
		m.logf("migration: attempt %d: moving the service to NT SERVICE\\fairy-agent", st.Attempt)
	case DoResume:
		st.Resumes++
		if st.Phase == PhaseRestarting { // still LocalSystem: switch again, hand over again
			st.Phase = PhaseRunning
			st.Done = slices.DeleteFunc(st.Done, func(s string) bool { return s == StepSwitch || s == StepRestart })
		}
		m.logf("migration: resuming attempt %d after an interruption (step %s)", st.Attempt, st.Step)
	case DoAbort:
		m.logf("migration: attempt %d was interrupted %d times; giving up on it", st.Attempt, st.Resumes+1)
		return m.fail(ctx, st, st.Step, fmt.Errorf("interrupted %d times (last at step %s)", st.Resumes+1, orNone(st.Step)))
	}
	if err := m.save(st); err != nil {
		return Outcome{Kind: OutStoreError, Err: err, Attempt: st.Attempt}
	}
	for _, step := range Steps {
		if st.done(step) {
			continue
		}
		if ctx.Err() != nil {
			return Outcome{Kind: OutInterrupted, Err: ctx.Err(), Attempt: st.Attempt}
		}
		st.Step = step
		switch step {
		case StepSwitch:
			if st.Orig == nil {
				o, err := m.Ops.Capture(ctx)
				if err == nil {
					o.Account = LocalSystem
					st.Orig = &o
					if err = st.Validate(); err != nil {
						st.Orig = nil
					}
				}
				if err != nil {
					return m.fail(ctx, st, step, fmt.Errorf("reading the service's settings: %w", err))
				}
			}
			st.Switched = true // before the change: a crash in the middle still rolls back
		case StepRestart:
			st.Phase = PhaseRestarting // the Supervisor acts only on this
		}
		if err := m.save(st); err != nil {
			return m.storeFailed(ctx, st, err)
		}
		m.logf("migration: step %s", step)
		if err := m.Ops.Step(ctx, step); err != nil {
			if ctx.Err() != nil {
				m.logf("migration: step %s interrupted: %v", step, err)
				return Outcome{Kind: OutInterrupted, Err: err, Attempt: st.Attempt}
			}
			return m.fail(ctx, st, step, err)
		}
		st.Done = append(st.Done, step)
		if step != StepRestart {
			if err := m.save(st); err != nil {
				return m.storeFailed(ctx, st, err)
			}
		}
		m.logf("migration: step %s done", step)
	}
	return Outcome{Kind: OutHanded, Attempt: st.Attempt}
}

// storeFailed: the state cannot be written. Undo the switch (if any) so nothing is left half done, but do
// not count it as an attempt (the pause comes from the caller).
func (m *Machine) storeFailed(ctx context.Context, st *State, err error) Outcome {
	if st.Switched && st.Orig != nil {
		if rerr := m.Ops.Rollback(context.WithoutCancel(ctx), *st.Orig); rerr != nil {
			m.logf("migration: rolling back after a state write error failed: %v", rerr)
		}
	}
	m.logf("migration: cannot write the state: %v", err)
	return Outcome{Kind: OutStoreError, Err: err, Attempt: st.Attempt}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// fail records a failed attempt, rolls the account back if it may have been switched, and sets the pause.
func (m *Machine) fail(ctx context.Context, st *State, step string, cause error) Outcome {
	st.Phase, st.Step, st.Error = PhaseFailed, step, truncate(cause.Error())
	st.Failures++
	st.RolledBack = false
	if st.Switched {
		o := Original{Account: LocalSystem}
		if st.Orig != nil {
			o = *st.Orig
		}
		if err := m.Ops.Rollback(context.WithoutCancel(ctx), o); err != nil {
			st.Error = truncate(st.Error + "; rolling back FAILED: " + err.Error())
		} else {
			st.Switched, st.RolledBack = false, true
		}
	}
	st.Done, st.Resumes = nil, 0
	next := m.now().Add(Backoff(m.Backoff, st.Failures))
	st.NextTry = next.Unix()
	m.logf("migration: attempt %d failed at step %s: %s; the agent keeps running as LocalSystem, next try %s",
		st.Attempt, step, st.Error, next.Format(time.RFC3339))
	if err := m.save(st); err != nil {
		m.logf("migration: cannot write the state: %v", err)
	}
	return Outcome{Kind: OutFailed, At: next, Err: cause, Attempt: st.Attempt}
}

func truncate(s string) string {
	if len(s) > 1000 {
		return s[:1000] + "..."
	}
	return s
}

// TakeBack is for the agent that handed over (OutHanded) and is, much later, still running as LocalSystem:
// the Supervisor never came. If the state still says restarting for that attempt, it fails it (rollback).
func (m *Machine) TakeBack(ctx context.Context, attempt int) Outcome {
	st, err := m.Store.Load()
	if err != nil {
		return Outcome{Kind: OutStoreError, Err: err}
	}
	if st == nil || st.Attempt != attempt || !st.unverifiedSwitch() {
		if st != nil && st.Phase == PhaseFailed {
			return Outcome{Kind: OutFailed, At: time.Unix(st.NextTry, 0), Attempt: st.Attempt}
		}
		return Outcome{Kind: OutWait, Attempt: attempt}
	}
	return m.fail(ctx, st, StepRestart, errors.New("the fairy-agent-update service did not restart the agent"))
}
