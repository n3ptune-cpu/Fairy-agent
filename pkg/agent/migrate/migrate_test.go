package migrate

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)} }
func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}
func (c *clock) Sleep(ctx context.Context, d time.Duration) {
	if ctx.Err() == nil {
		c.Advance(d)
	}
}

// memStore is a Store that round-trips through JSON (like the file) and can fail.
type memStore struct {
	mu       sync.Mutex
	b        []byte
	saves    int
	failSave int // fail the n-th save (1-based); 0 never
}

func (m *memStore) Load() (*State, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.b == nil {
		return nil, nil
	}
	var s State
	if err := json.Unmarshal(m.b, &s); err != nil {
		return nil, err
	}
	return &s, s.Validate()
}

func (m *memStore) Save(s *State) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.saves++
	if m.failSave == m.saves {
		return errors.New("disk full")
	}
	if err := s.Validate(); err != nil {
		return err
	}
	m.b, _ = json.Marshal(s)
	return nil
}

func (m *memStore) state(t *testing.T) *State {
	t.Helper()
	s, err := m.Load()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type fakeOps struct {
	mu        sync.Mutex
	calls     []string
	fail      map[string]error
	captured  int
	rollbacks []Original
	rbErr     error
	onStep    func(step string)
}

func (f *fakeOps) Step(ctx context.Context, step string) error {
	f.mu.Lock()
	f.calls = append(f.calls, step)
	err := f.fail[step]
	cb := f.onStep
	f.mu.Unlock()
	if cb != nil {
		cb(step)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (f *fakeOps) Capture(context.Context) (Original, error) {
	f.captured++
	return Original{Account: "LocalSystem", SidType: 1, Privileges: []string{"SeChangeNotifyPrivilege", "SeShutdownPrivilege", "SeTcbPrivilege"}}, f.fail["capture"]
}

func (f *fakeOps) Rollback(_ context.Context, o Original) error {
	f.rollbacks = append(f.rollbacks, o)
	return f.rbErr
}

func newMachine(st *memStore, ops *fakeOps, c *clock) *Machine {
	return &Machine{Store: st, Ops: ops, Version: "12-abcdef0", Now: c.Now}
}

func TestRunAllSteps(t *testing.T) {
	c, st, ops := newClock(), &memStore{}, &fakeOps{}
	out := newMachine(st, ops, c).Run(context.Background())
	if out.Kind != OutHanded || out.Attempt != 1 {
		t.Fatalf("outcome %+v", out)
	}
	if !slices.Equal(ops.calls, Steps) {
		t.Fatalf("steps %v", ops.calls)
	}
	s := st.state(t)
	if s.Phase != PhaseRestarting || !s.Switched || s.Orig == nil || s.Orig.Account != LocalSystem || ops.captured != 1 {
		t.Fatalf("state %+v", s)
	}
	if !slices.Equal(s.Done, Steps[:len(Steps)-1]) { // restart belongs to the Supervisor from here on
		t.Fatalf("done %v", s.Done)
	}
	if len(ops.rollbacks) != 0 {
		t.Fatal("rolled back")
	}
}

// The state is written with Phase restarting BEFORE the Supervisor is started, and Switched before the switch.
func TestStateOrderAroundSwitchAndRestart(t *testing.T) {
	c, st, ops := newClock(), &memStore{}, &fakeOps{}
	ops.onStep = func(step string) {
		s := st.state(t)
		if s.Step != step {
			t.Errorf("step %s ran while the state said %s", step, s.Step)
		}
		switch step {
		case StepSwitch:
			if !s.Switched || s.Orig == nil {
				t.Errorf("switch before Switched / Orig were written: %+v", s)
			}
		case StepRestart:
			if s.Phase != PhaseRestarting {
				t.Errorf("restart before the phase was written: %s", s.Phase)
			}
		default:
			if s.Switched {
				t.Errorf("Switched already at %s", step)
			}
		}
	}
	if out := newMachine(st, ops, c).Run(context.Background()); out.Kind != OutHanded {
		t.Fatal(out)
	}
}

func TestEachStepFailing(t *testing.T) {
	for i, step := range append([]string{"capture"}, Steps...) {
		t.Run(step, func(t *testing.T) {
			c, st, ops := newClock(), &memStore{}, &fakeOps{fail: map[string]error{step: errors.New("boom")}}
			out := newMachine(st, ops, c).Run(context.Background())
			if out.Kind != OutFailed {
				t.Fatalf("outcome %+v", out)
			}
			s := st.state(t)
			want := step
			if step == "capture" {
				want = StepSwitch
			}
			if s.Phase != PhaseFailed || s.Step != want || !strings.Contains(s.Error, "boom") || s.Failures != 1 {
				t.Fatalf("state %+v", s)
			}
			if got, exp := time.Unix(s.NextTry, 0), c.Now().Add(time.Hour); !got.Equal(exp) || !out.At.Equal(exp) {
				t.Fatalf("next try %v, want %v", got, exp)
			}
			// nothing after the failed step ran
			if last := ops.calls[len(ops.calls)-1]; step != "capture" && last != step {
				t.Fatalf("ran %v after %s", ops.calls, step)
			}
			switched := step == StepSwitch || step == StepRestart
			if switched != (len(ops.rollbacks) == 1) {
				t.Fatalf("step %s (index %d): rollbacks %v", step, i, ops.rollbacks)
			}
			if switched {
				if !s.RolledBack || s.Switched || ops.rollbacks[0].Account != LocalSystem || len(ops.rollbacks[0].Privileges) != 3 {
					t.Fatalf("rollback %+v state %+v", ops.rollbacks, s)
				}
			}
			if s.Done != nil {
				t.Fatalf("done kept: %v", s.Done)
			}
		})
	}
}

func TestRollbackFailureIsReported(t *testing.T) {
	c, st := newClock(), &memStore{}
	ops := &fakeOps{fail: map[string]error{StepRestart: errors.New("cannot start the updater")}, rbErr: errors.New("access denied")}
	newMachine(st, ops, c).Run(context.Background())
	s := st.state(t)
	if !strings.Contains(s.Error, "rolling back FAILED: access denied") || !s.Switched || s.RolledBack {
		t.Fatalf("state %+v", s)
	}
}

// No tight loop: a failed attempt is not retried before its pause, and the pause grows.
func TestBackoff(t *testing.T) {
	c, st := newClock(), &memStore{}
	ops := &fakeOps{fail: map[string]error{StepHelper: errors.New("helper did not start")}}
	m := newMachine(st, ops, c)
	want := []time.Duration{time.Hour, 6 * time.Hour, 24 * time.Hour, 24 * time.Hour}
	for i, w := range want {
		out := m.Run(context.Background())
		if out.Kind != OutFailed || out.Attempt != i+1 {
			t.Fatalf("attempt %d: %+v", i+1, out)
		}
		if !out.At.Equal(c.Now().Add(w)) {
			t.Fatalf("attempt %d: next %v, want +%v", i+1, out.At, w)
		}
		n := len(ops.calls)
		for range 5 { // restarts of the agent during the pause do nothing
			c.Advance(w / 10)
			if o := m.Run(context.Background()); o.Kind != OutWait || !o.At.Equal(out.At) {
				t.Fatalf("retried during the pause: %+v", o)
			}
		}
		if len(ops.calls) != n {
			t.Fatalf("steps ran during the pause: %v", ops.calls[n:])
		}
		c.Advance(w)
	}
	if s := st.state(t); s.Failures != 4 || s.Attempt != 4 {
		t.Fatalf("state %+v", s)
	}
	// it works now: the counter starts over only when the Supervisor confirms (Phase done)
	ops.fail = nil
	if out := m.Run(context.Background()); out.Kind != OutHanded || out.Attempt != 5 {
		t.Fatalf("%+v", out)
	}
}

func TestBackoffFunc(t *testing.T) {
	for n, w := range map[int]time.Duration{0: time.Hour, 1: time.Hour, 2: 6 * time.Hour, 3: 24 * time.Hour, 99: 24 * time.Hour} {
		if g := Backoff(nil, n); g != w {
			t.Errorf("Backoff(%d) = %v, want %v", n, g, w)
		}
	}
}

// A crash (or Stop-Service) in the middle: the next start resumes at the step that was running.
func TestResumeAfterCrash(t *testing.T) {
	c, st := newClock(), &memStore{}
	ctx, cancel := context.WithCancel(context.Background())
	ops := &fakeOps{onStep: func(step string) {
		if step == StepHelper {
			cancel() // the agent is being stopped while the helper is set up
		}
	}}
	out := newMachine(st, ops, c).Run(ctx)
	if out.Kind != OutInterrupted {
		t.Fatalf("%+v", out)
	}
	s := st.state(t)
	if s.Phase != PhaseRunning || s.Step != StepHelper || !slices.Equal(s.Done, []string{StepProgramFolder, StepFolders, StepUpdater, StepFans}) {
		t.Fatalf("state after the interruption %+v", s)
	}
	ops2 := &fakeOps{}
	out = newMachine(st, ops2, c).Run(context.Background())
	if out.Kind != OutHanded || out.Attempt != 1 {
		t.Fatalf("%+v", out)
	}
	if !slices.Equal(ops2.calls, []string{StepHelper, StepFirewall, StepSwitch, StepRestart}) {
		t.Fatalf("resumed with %v", ops2.calls)
	}
	if s := st.state(t); s.Resumes != 1 {
		t.Fatalf("resumes %d", s.Resumes)
	}
}

// A crash during the switch itself: resumed, the saved original is kept (not read again from a service that
// may already be switched), and a failure after that still rolls back.
func TestCrashDuringSwitch(t *testing.T) {
	c, st := newClock(), &memStore{}
	ctx, cancel := context.WithCancel(context.Background())
	ops := &fakeOps{onStep: func(step string) {
		if step == StepSwitch {
			cancel()
		}
	}}
	newMachine(st, ops, c).Run(ctx)
	s := st.state(t)
	if !s.Switched || s.Orig == nil || s.Step != StepSwitch {
		t.Fatalf("%+v", s)
	}
	ops2 := &fakeOps{fail: map[string]error{StepRestart: errors.New("no updater")}}
	newMachine(st, ops2, c).Run(context.Background())
	if ops2.captured != 0 {
		t.Fatal("captured again after the switch had started")
	}
	if len(ops2.rollbacks) != 1 || ops2.rollbacks[0].SidType != 1 {
		t.Fatalf("rollbacks %+v", ops2.rollbacks)
	}
}

// Interrupted again and again (e.g. the step crashes the agent): after MaxResumes it is a failure, rolled back,
// with the pause, so a crashing step cannot make the service restart in a loop.
func TestInterruptedTooOften(t *testing.T) {
	c, st := newClock(), &memStore{}
	m := newMachine(st, nil, c)
	for i := range 4 {
		ctx, cancel := context.WithCancel(context.Background())
		ops := &fakeOps{onStep: func(step string) {
			if step == StepRestart {
				cancel()
			}
		}}
		m.Ops = ops
		out := m.Run(ctx)
		if i < 3 && out.Kind != OutInterrupted {
			t.Fatalf("run %d: %+v", i, out)
		}
		if i == 3 {
			if out.Kind != OutFailed || len(ops.calls) != 0 || len(ops.rollbacks) != 1 {
				t.Fatalf("run %d: %+v calls %v rollbacks %v", i, out, ops.calls, ops.rollbacks)
			}
			s := st.state(t)
			if s.Phase != PhaseFailed || !strings.Contains(s.Error, "interrupted 3 times") || s.NextTry == 0 {
				t.Fatalf("%+v", s)
			}
		}
		cancel()
	}
}

// Still LocalSystem although the state says restarting (the restart never happened): switch again.
func TestRestartingButStillLocalSystem(t *testing.T) {
	c, st := newClock(), &memStore{}
	newMachine(st, &fakeOps{}, c).Run(context.Background())
	ops := &fakeOps{}
	out := newMachine(st, ops, c).Run(context.Background())
	if out.Kind != OutHanded || !slices.Equal(ops.calls, []string{StepSwitch, StepRestart}) || ops.captured != 0 {
		t.Fatalf("%+v %v", out, ops.calls)
	}
}

// Done, but running as LocalSystem again (someone went back to 0.4.x and updated again): start over.
func TestDoneButLocalSystemAgain(t *testing.T) {
	c, st := newClock(), &memStore{}
	_ = st.Save(&State{Phase: PhaseDone, Attempt: 3, Failures: 0})
	ops := &fakeOps{}
	out := newMachine(st, ops, c).Run(context.Background())
	if out.Kind != OutHanded || out.Attempt != 4 || len(ops.calls) != len(Steps) {
		t.Fatalf("%+v %v", out, ops.calls)
	}
}

func TestStoreErrors(t *testing.T) {
	c := newClock()
	// the very first write fails: nothing is done
	st, ops := &memStore{failSave: 1}, &fakeOps{}
	if out := newMachine(st, ops, c).Run(context.Background()); out.Kind != OutStoreError || len(ops.calls) != 0 {
		t.Fatalf("%+v %v", out, ops.calls)
	}
	// a write fails right after Switched was set: the switch is not done, and rolled back to be sure
	st = &memStore{}
	ops = &fakeOps{}
	m := newMachine(st, ops, c)
	m.Run(context.Background())
	saves := st.saves // all writes of a full run: ..., switch before + after, restart before
	st2, ops2 := &memStore{failSave: saves - 2}, &fakeOps{}
	out := newMachine(st2, ops2, c).Run(context.Background())
	if out.Kind != OutStoreError || slices.Contains(ops2.calls, StepSwitch) || len(ops2.rollbacks) != 1 {
		t.Fatalf("%+v calls %v rollbacks %v", out, ops2.calls, ops2.rollbacks)
	}
}

func TestTakeBack(t *testing.T) {
	c, st, ops := newClock(), &memStore{}, &fakeOps{}
	m := newMachine(st, ops, c)
	out := m.Run(context.Background())
	if o := m.TakeBack(context.Background(), out.Attempt); o.Kind != OutFailed || len(ops.rollbacks) != 1 {
		t.Fatalf("%+v %v", o, ops.rollbacks)
	}
	if s := st.state(t); s.Phase != PhaseFailed || s.Step != StepRestart || !s.RolledBack {
		t.Fatalf("%+v", s)
	}
	// already settled by the Supervisor: nothing more
	if o := m.TakeBack(context.Background(), out.Attempt); o.Kind != OutFailed || len(ops.rollbacks) != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestValidate(t *testing.T) {
	bad := []State{
		{Phase: "weird"},
		{Phase: PhaseRunning, Step: "format_c"},
		{Phase: PhaseRunning, Done: []string{"x"}},
		{Phase: PhaseFailed, Orig: &Original{Account: `.\Administrator`}},
		{Phase: PhaseFailed, Orig: &Original{Account: LocalSystem, Privileges: []string{"SeTcbPrivilege; rm"}}},
		{Phase: PhaseFailed, Orig: &Original{Account: LocalSystem, SidType: 9}},
		{Phase: PhaseFailed, Attempt: -1},
	}
	for i, s := range bad {
		if s.Validate() == nil {
			t.Errorf("bad state %d accepted: %+v", i, s)
		}
	}
	if err := (&State{Phase: PhaseRestarting, Orig: &Original{Account: LocalSystem, SidType: 1, Privileges: []string{"SeDebugPrivilege"}}}).Validate(); err != nil {
		t.Error(err)
	}
}

func TestFileStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "migration")
	prepared, checked := 0, 0
	f := &FileStore{Path: filepath.Join(dir, "state.json"),
		Prepare: func(string) error { prepared++; return nil },
		Check:   func(string) error { checked++; return nil }}
	if s, err := f.Load(); s != nil || err != nil {
		t.Fatalf("missing: %v %v", s, err)
	}
	in := &State{Phase: PhaseRunning, Attempt: 1, Done: []string{StepProgramFolder}, Step: StepFolders}
	if err := f.Save(in); err != nil {
		t.Fatal(err)
	}
	out, err := f.Load()
	if err != nil || out.Step != StepFolders || out.Attempt != 1 || prepared != 1 || checked != 1 {
		t.Fatalf("%+v %v %d %d", out, err, prepared, checked)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("leftover temp files: %v", ents)
	}
	if err := f.Save(&State{Phase: "nope"}); err == nil {
		t.Fatal("saved an invalid state")
	}
	for name, content := range map[string]string{"corrupt": "{", "invalid": `{"phase":"x"}`,
		"too large": `{"phase":"running","error":"` + strings.Repeat("a", MaxStateSize) + `"}`} {
		if err := os.WriteFile(f.Path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := f.Load(); err == nil {
			t.Errorf("%s state accepted", name)
		}
	}
	// a link instead of the file is refused
	os.Remove(f.Path)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	_ = os.WriteFile(target, []byte(`{"phase":"done"}`), 0o600)
	if err := os.Symlink(target, f.Path); err == nil {
		if _, err := f.Load(); err == nil {
			t.Error("followed a symlink")
		}
	}
	// an untrusted folder is refused
	f.Check = func(string) error { return errors.New("others may write it") }
	if _, err := f.Load(); err == nil {
		t.Error("untrusted folder accepted")
	}
	f.Prepare = func(string) error { return errors.New("cannot secure") }
	if err := f.Save(in); err == nil {
		t.Error("saved into a folder that could not be secured")
	}
}

// ---- Supervisor

type fakeSup struct {
	mu        sync.Mutex
	c         *clock
	info      AgentInfo
	stopErr   error
	startErr  error
	healthy   func() error
	afterStop func(*fakeSup) // what the service looks like once started (default: new account, pid 200)
	calls     []string
	rollbacks int
	finished  int
	agentErr  error
}

func (f *fakeSup) log(s string) { f.calls = append(f.calls, s) }
func (f *fakeSup) Agent(context.Context) (AgentInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.info, f.agentErr
}
func (f *fakeSup) StopAgent(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("stop")
	if f.stopErr != nil {
		return f.stopErr
	}
	f.info = AgentInfo{}
	return nil
}
func (f *fakeSup) StartAgent(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("start")
	if f.startErr != nil {
		return f.startErr
	}
	if f.rollbacks > 0 {
		f.info = AgentInfo{Running: true, PID: 300} // LocalSystem again
		return nil
	}
	if f.afterStop != nil {
		f.afterStop(f)
	} else {
		f.info = AgentInfo{Running: true, NewAccount: true, PID: 200}
	}
	return nil
}
func (f *fakeSup) Healthy(context.Context) error {
	if f.healthy != nil {
		return f.healthy()
	}
	return nil
}
func (f *fakeSup) Rollback(context.Context, Original) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("rollback")
	f.rollbacks++
	return nil
}
func (f *fakeSup) Finish(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log("finish")
	f.finished++
	return nil
}

func handedState(t *testing.T, c *clock) *memStore {
	st := &memStore{}
	if out := newMachine(st, &fakeOps{}, c).Run(context.Background()); out.Kind != OutHanded {
		t.Fatal(out)
	}
	return st
}

func newSup(st Store, ops SupervisorOps, c *clock) *Supervisor {
	return &Supervisor{Store: st, Ops: ops, Now: c.Now, Sleep: c.Sleep}
}

func TestSupervisorNormal(t *testing.T) {
	c := newClock()
	st := handedState(t, c)
	ops := &fakeSup{c: c, info: AgentInfo{Running: true, PID: 100}}
	healthCalls := 0
	ops.healthy = func() error { healthCalls++; return nil }
	handled, err := newSup(st, ops, c).Run(context.Background())
	if !handled || err != nil {
		t.Fatal(handled, err)
	}
	if !slices.Equal(ops.calls, []string{"stop", "start", "finish"}) || healthCalls < 2 {
		t.Fatalf("calls %v health %d", ops.calls, healthCalls)
	}
	s := st.state(t)
	if s.Phase != PhaseDone || s.Switched || s.Failures != 0 || !s.done(StepRestart) {
		t.Fatalf("%+v", s)
	}
	// and nothing more next time (an ordinary update then runs)
	if handled, _ := newSup(st, ops, c).Run(context.Background()); handled {
		t.Fatal("handled a finished migration")
	}
}

func TestSupervisorNothingToDo(t *testing.T) {
	c := newClock()
	for _, s := range []*State{nil, {Phase: PhaseDone}, {Phase: PhaseFailed}, {Phase: PhaseRunning}} {
		st := &memStore{}
		if s != nil {
			_ = st.Save(s)
		}
		ops := &fakeSup{c: c}
		if handled, err := newSup(st, ops, c).Run(context.Background()); handled || err != nil || len(ops.calls) != 0 {
			t.Fatalf("state %+v: %v %v %v", s, handled, err, ops.calls)
		}
	}
}

func TestSupervisorRollsBack(t *testing.T) {
	cases := map[string]func(*fakeSup){
		"never healthy":     func(f *fakeSup) { f.healthy = func() error { return errors.New("connection refused") } },
		"wrong account":     func(f *fakeSup) { f.afterStop = func(f *fakeSup) { f.info = AgentInfo{Running: true, PID: 200} } },
		"does not start":    func(f *fakeSup) { f.startErr = errors.New("logon failure") },
		"exits":             func(f *fakeSup) { f.afterStop = func(f *fakeSup) { f.info = AgentInfo{} } },
		"cannot stop":       func(f *fakeSup) { f.stopErr = errors.New("timeout") },
		"scm not reachable": func(f *fakeSup) { f.agentErr = errors.New("access denied") },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			c := newClock()
			st := handedState(t, c)
			ops := &fakeSup{c: c, info: AgentInfo{Running: true, PID: 100}}
			setup(ops)
			handled, err := newSup(st, ops, c).Run(context.Background())
			if !handled || err == nil {
				t.Fatal(handled, err)
			}
			if ops.rollbacks != 1 || ops.finished != 1 {
				t.Fatalf("calls %v", ops.calls)
			}
			if i := slices.Index(ops.calls, "rollback"); i < 0 || !slices.Contains(ops.calls[i:], "start") {
				t.Fatalf("not started again after the rollback: %v", ops.calls)
			}
			s := st.state(t)
			if s.Phase != PhaseFailed || s.Step != StepRestart || !s.RolledBack || s.Switched || s.Failures != 1 ||
				s.NextTry != c.Now().Add(time.Hour).Unix() {
				t.Fatalf("%+v", s)
			}
			// the agent, LocalSystem again, waits for the pause
			if out := newMachine(st, &fakeOps{}, c).Run(context.Background()); out.Kind != OutWait {
				t.Fatalf("%+v", out)
			}
		})
	}
}

// A process that keeps exiting (the service manager restarts it with a new pid) never counts as running.
func TestSupervisorUnstable(t *testing.T) {
	c := newClock()
	st := handedState(t, c)
	pid := uint32(200)
	ops := &fakeSup{c: c, info: AgentInfo{Running: true, PID: 100}}
	ops.afterStop = func(f *fakeSup) { f.info = AgentInfo{Running: true, NewAccount: true, PID: pid} }
	sup := newSup(st, ops, c)
	sup.Sleep = func(ctx context.Context, d time.Duration) {
		c.Advance(5 * time.Second)
		ops.mu.Lock()
		pid++
		if ops.info.NewAccount {
			ops.info.PID = pid
		}
		ops.mu.Unlock()
	}
	if handled, err := sup.Run(context.Background()); !handled || err == nil || ops.rollbacks != 1 {
		t.Fatal(handled, err, ops.calls)
	}
}

// After a reboot in the middle: the agent already runs as the new account. Not restarted again, and /metrics is
// not required (the network may not be up yet); steady running is enough.
func TestSupervisorAfterReboot(t *testing.T) {
	c := newClock()
	st := handedState(t, c)
	ops := &fakeSup{c: c, info: AgentInfo{Running: true, NewAccount: true, PID: 42},
		healthy: func() error { return errors.New("no network yet") }}
	if handled, err := newSup(st, ops, c).Run(context.Background()); !handled || err != nil {
		t.Fatal(handled, err)
	}
	if !slices.Equal(ops.calls, []string{"finish"}) || st.state(t).Phase != PhaseDone {
		t.Fatalf("%v", ops.calls)
	}
	// stopped after the reboot (the updater service came first): started, then steady is enough
	st = handedState(t, c)
	ops = &fakeSup{c: c, healthy: func() error { return errors.New("no network yet") }}
	if handled, err := newSup(st, ops, c).Run(context.Background()); !handled || err != nil {
		t.Fatal(handled, err)
	}
	if !slices.Equal(ops.calls, []string{"start", "finish"}) {
		t.Fatalf("%v", ops.calls)
	}
}

// Switched but crashed before the restart step: the Supervisor finishes it too.
func TestSupervisorSwitchedRunning(t *testing.T) {
	c, st := newClock(), &memStore{}
	ctx, cancel := context.WithCancel(context.Background())
	newMachine(st, &fakeOps{onStep: func(s string) {
		if s == StepSwitch {
			cancel()
		}
	}}, c).Run(ctx)
	ops := &fakeSup{c: c, info: AgentInfo{Running: true, NewAccount: true, PID: 7}}
	if handled, err := newSup(st, ops, c).Run(context.Background()); !handled || err != nil {
		t.Fatal(handled, err)
	}
}

// ---- Report and Runner

func TestReport(t *testing.T) {
	first := time.Date(2026, 11, 9, 12, 2, 0, 0, time.UTC)
	ls := Facts{Kind: KindLocalSystem, Account: "LocalSystem", Command: "cmd"}
	cases := []struct {
		name  string
		f     Facts
		st    *State
		state string
		check func(api.MigrationStatus) bool
	}{
		{"console", Facts{Kind: KindNotService}, nil, api.MigrationNotNeeded, nil},
		{"new, fresh install", Facts{Kind: KindNew, Account: `NT SERVICE\fairy-agent`}, nil, api.MigrationNotNeeded, nil},
		{"new, moved", Facts{Kind: KindNew}, &State{Phase: PhaseDone, Attempt: 1}, api.MigrationDone, nil},
		{"new, unverified", Facts{Kind: KindNew}, &State{Phase: PhaseRestarting}, api.MigrationPending,
			func(m api.MigrationStatus) bool { return m.Step == StepRestart }},
		{"new, admin fixed a failure", Facts{Kind: KindNew}, &State{Phase: PhaseFailed, Error: "x"}, api.MigrationNotNeeded,
			func(m api.MigrationStatus) bool { return m.Error == "" }},
		{"local service", Facts{Kind: KindOther, Account: "LocalService", Command: "cmd"}, nil, api.MigrationNeedsAdmin,
			func(m api.MigrationStatus) bool {
				return m.Command == "cmd" && strings.Contains(m.Reason, "LocalService")
			}},
		{"local system, not installed right", Facts{Kind: KindLocalSystem, Ineligible: "not in Program Files", Command: "cmd"}, nil,
			api.MigrationNeedsAdmin, func(m api.MigrationStatus) bool { return m.Reason == "not in Program Files" }},
		{"local system, before the first", ls, nil, api.MigrationPending,
			func(m api.MigrationStatus) bool { return m.Step == "waiting" && m.NextTry == "2026-11-09T12:02:00Z" }},
		{"local system, step", ls, &State{Phase: PhaseRunning, Step: StepHelper, Attempt: 1}, api.MigrationPending,
			func(m api.MigrationStatus) bool { return m.Step == StepHelper && m.Attempts == 1 }},
		{"local system, failed", ls, &State{Phase: PhaseFailed, Step: StepRestart, Error: "boom", RolledBack: true, NextTry: first.Unix()},
			api.MigrationFailed, func(m api.MigrationStatus) bool {
				return m.Error == "boom" && m.RolledBack && m.NextTry == "2026-11-09T12:02:00Z" && m.Command == "cmd"
			}},
	}
	for _, tc := range cases {
		m := Report(tc.f, tc.st, first)
		if m.State != tc.state || (tc.check != nil && !tc.check(m)) {
			t.Errorf("%s: %+v", tc.name, m)
		}
	}
}

func TestRunnerWaitsAndHandsOver(t *testing.T) {
	c, st := newClock(), &memStore{}
	ops := &fakeOps{}
	readyCalls := 0
	r := &Runner{Machine: newMachine(st, ops, c), Facts: Facts{Kind: KindLocalSystem, Account: "LocalSystem"}, Sleep: c.Sleep}
	r.Ready = func() string {
		readyCalls++
		if readyCalls < 3 {
			if s := r.Status(); s.State != api.MigrationPending || s.Reason != "" && readyCalls > 1 && s.Reason != "an update is installing" {
				t.Errorf("status while waiting %+v", s)
			}
			return "an update is installing"
		}
		return ""
	}
	ctx, cancel := context.WithCancel(context.Background())
	ops.onStep = func(step string) {
		if !r.Busy() {
			t.Error("not busy during the steps")
		}
		if step == StepRestart {
			cancel() // the Supervisor stops the agent
		}
	}
	start := c.Now()
	r.Loop(ctx)
	if readyCalls != 3 || len(ops.calls) != len(Steps) {
		t.Fatalf("ready %d calls %v", readyCalls, ops.calls)
	}
	if c.Now().Sub(start) < 2*time.Minute {
		t.Fatal("did not wait MinWait")
	}
}

func TestRunnerTakesBack(t *testing.T) {
	c, st := newClock(), &memStore{}
	ops := &fakeOps{}
	r := &Runner{Machine: newMachine(st, ops, c), Facts: Facts{Kind: KindLocalSystem}}
	ctx, cancel := context.WithCancel(context.Background())
	sleeps := 0
	r.Sleep = func(ctx context.Context, d time.Duration) {
		sleeps++
		c.Advance(d)
		if sleeps == 3 { // MinWait, hand-over timeout, then the pause after the take-back
			if d < 50*time.Minute {
				t.Errorf("pause after the take-back only %v", d)
			}
			cancel()
		}
	}
	r.Loop(ctx)
	if len(ops.rollbacks) != 1 || st.state(t).Phase != PhaseFailed || r.Busy() {
		t.Fatalf("rollbacks %v state %+v busy %v", ops.rollbacks, st.state(t), r.Busy())
	}
}

func TestRunnerDoesNothingWhenItMayNot(t *testing.T) {
	c := newClock()
	for _, f := range []Facts{{Kind: KindOther}, {Kind: KindNotService}, {Kind: KindLocalSystem, Ineligible: "unsigned"}, {Kind: KindNew}} {
		st, ops := &memStore{}, &fakeOps{}
		r := &Runner{Machine: newMachine(st, ops, c), Facts: f, Sleep: func(context.Context, time.Duration) { t.Error("slept") }}
		r.Loop(context.Background())
		if len(ops.calls) != 0 || st.b != nil {
			t.Errorf("%+v: did something", f)
		}
	}
}

func TestRunnerKicksUnverifiedSwitch(t *testing.T) {
	c := newClock()
	st := handedState(t, c)
	kicks := 0
	r := &Runner{Machine: newMachine(st, &fakeOps{}, c), Facts: Facts{Kind: KindNew}, Sleep: c.Sleep,
		Kick: func() error { kicks++; return nil }}
	r.Loop(context.Background())
	if kicks != 1 {
		t.Fatal(kicks)
	}
}

// Stopped in the middle (Windows shutting down): no rollback, the switch stays unverified for the next start.
func TestSupervisorInterrupted(t *testing.T) {
	c := newClock()
	st := handedState(t, c)
	ctx, cancel := context.WithCancel(context.Background())
	ops := &fakeSup{c: c, info: AgentInfo{Running: true, PID: 100}, healthy: func() error { cancel(); return errors.New("x") }}
	handled, err := newSup(st, ops, c).Run(ctx)
	if !handled || !errors.Is(err, context.Canceled) || ops.rollbacks != 0 {
		t.Fatal(handled, err, ops.calls)
	}
	if s := st.state(t); !s.unverifiedSwitch() {
		t.Fatalf("%+v", s)
	}
	ops2 := &fakeSup{c: c, info: AgentInfo{Running: true, NewAccount: true, PID: 5}}
	if handled, err := newSup(st, ops2, c).Run(context.Background()); !handled || err != nil {
		t.Fatal(handled, err)
	}
}

// The state cannot be written (e.g. the folder cannot be secured): nothing is done, /metrics says why, and it
// is tried again only after StoreRetry.
func TestRunnerStoreError(t *testing.T) {
	c := newClock()
	st, ops := &memStore{failSave: 1}, &fakeOps{}
	r := &Runner{Machine: newMachine(st, ops, c), Facts: Facts{Kind: KindLocalSystem, Account: "LocalSystem"}}
	ctx, cancel := context.WithCancel(context.Background())
	var during api.MigrationStatus
	r.Sleep = func(ctx context.Context, d time.Duration) {
		if d == time.Hour {
			during = r.Status()
			cancel()
		}
		c.Advance(d)
	}
	r.Loop(ctx)
	if len(ops.calls) != 0 || during.State != api.MigrationPending || !strings.Contains(during.Reason, "disk full") {
		t.Fatalf("calls %v status %+v", ops.calls, during)
	}
}
