package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeOS is the operating system's side of a power action: like Windows, it goes on counting a shutdown down
// whatever happens to the program that asked for it.
type fakeOS struct {
	scheduled []string
	cancels   int
	cancelErr error
}

func (f *fakeOS) Schedule(action string, delay time.Duration, msg string) error {
	f.scheduled = append(f.scheduled, action+"@"+delay.String()+" "+msg)
	return nil
}
func (f *fakeOS) Cancel() error {
	if f.cancelErr != nil {
		return f.cancelErr
	}
	f.cancels++
	return nil
}
func (f *fakeOS) CanSleep() (bool, string) { return true, "" }

type clock struct {
	now  time.Time
	boot time.Time
}

func (c *clock) Now() time.Time { return c.now }

// Uptime is the operating system's own count of the time since it started (boot zero: there is none).
func (c *clock) Uptime() (time.Duration, bool) { return c.now.Sub(c.boot), !c.boot.IsZero() }
func (c *clock) advance(d time.Duration)       { c.now = c.now.Add(d) }

// correct sets the clock forward (or back) by d; the machine goes on running, so its uptime is what it was.
func (c *clock) correct(d time.Duration) { c.now, c.boot = c.now.Add(d), c.boot.Add(d) }
func notSleep(action string) bool        { return action != "sleep" }
func newClock() *clock {
	now := time.Unix(1_800_000_000, 0)
	return &clock{now: now, boot: now.Add(-3 * time.Hour)}
}

// start is one run of the program (the helper service): it reads what the previous run remembered.
func start(os PowerExec, store PowerStore, c *clock) *RememberedPower {
	return rememberPower(os, store, notSleep, c.Uptime, c.Now)
}

// L21: a shutdown scheduled on Windows goes on counting down while the service restarts. The next run must
// still report it and Cancel must abort it.
func TestRememberedShutdownSurvivesARestart(t *testing.T) {
	dir := t.TempDir()
	store := PowerFile{Path: filepath.Join(dir, "power-pending.json")}
	win, c := &fakeOS{}, newClock()

	r1 := start(win, store, c)
	if _, ok := r1.PendingAction(); ok {
		t.Fatal("pending before anything was scheduled")
	}
	if err := r1.ScheduleBy("shutdown", time.Hour, "neptune@example.com"); err != nil {
		t.Fatal(err)
	}
	if len(win.scheduled) != 1 || win.scheduled[0] != "shutdown@1h0m0s Fairy: shutdown requested by neptune@example.com in 3600 seconds." {
		t.Fatal(win.scheduled)
	}
	want := Pending{Action: "shutdown", At: float64(c.now.Unix() + 3600), DelayS: 3600, RequestedBy: "neptune@example.com"}
	if p, ok := r1.PendingAction(); !ok || p != want {
		t.Fatalf("%+v %v", p, ok)
	}

	// the helper restarts (an update, a crash, Stop / Start in the panel) ten minutes later
	c.advance(10 * time.Minute)
	r2 := start(win, store, c)
	if p, ok := r2.PendingAction(); !ok || p != want {
		t.Fatalf("after the restart: %+v %v", p, ok)
	}
	if err := r2.Cancel(); err != nil || win.cancels != 1 {
		t.Fatal(err, win.cancels)
	}
	if _, ok := r2.PendingAction(); ok {
		t.Fatal("still pending after Cancel")
	}
	if _, err := os.Stat(store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the record was not removed:", err)
	}
	// cancelled is cancelled: a second Cancel and a third run ask the operating system nothing
	if err := r2.Cancel(); err != nil || win.cancels != 1 {
		t.Fatal(err, win.cancels)
	}
	if r3 := start(win, store, c); r3.Cancel() != nil || win.cancels != 1 {
		t.Fatal(win.cancels)
	}
}

// Fairy never aborts a shutdown it did not start: with no record of its own, Cancel does not reach the
// operating system at all (a Windows Update restart or `shutdown /s` typed by someone stays untouched).
func TestCancelWithoutOwnActionAsksNothing(t *testing.T) {
	win, c := &fakeOS{}, newClock()
	for name, store := range map[string]PowerStore{"file": PowerFile{Path: filepath.Join(t.TempDir(), "p.json")}, "memory": nil} {
		r := start(win, store, c)
		for i := 0; i < 3; i++ {
			if err := r.Cancel(); err != nil {
				t.Fatal(name, err)
			}
		}
	}
	if win.cancels != 0 {
		t.Fatalf("AbortSystemShutdown reached %d times without an action of Fairy's own", win.cancels)
	}
}

func TestRememberedRecordEnds(t *testing.T) {
	newStore := func() PowerFile { return PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")} }
	exists := func(s PowerFile) bool { _, err := os.Stat(s.Path); return err == nil }

	// its time has passed (the PC did shut down and is up again, or the action was aborted on the PC itself)
	win, c, store := &fakeOS{}, newClock(), newStore()
	r := start(win, store, c)
	_ = r.ScheduleBy("reboot", 5*time.Minute, "panel")
	c.advance(5*time.Minute + 59*time.Second)
	if _, ok := start(win, store, c).PendingAction(); !ok {
		t.Fatal("dropped inside the minute of grace")
	}
	c.advance(2 * time.Second)
	r = start(win, store, c)
	if _, ok := r.PendingAction(); ok || exists(store) {
		t.Fatal("a record whose time has passed is still there")
	}
	if r.Cancel() != nil || win.cancels != 0 {
		t.Fatal("Cancel reached the operating system for a record whose time has passed")
	}

	// the machine was started again before the time came (reset button, power cut, a restart from the Start
	// menu): the countdown died with the old Windows session
	win, c, store = &fakeOS{}, newClock(), newStore()
	_ = start(win, store, c).ScheduleBy("shutdown", 12*time.Hour, "panel")
	c.advance(20 * time.Minute)
	c.boot = c.now.Add(-90 * time.Second) // up for 90 seconds
	r = start(win, store, c)
	if _, ok := r.PendingAction(); ok || exists(store) {
		t.Fatal("a record from before the last start of Windows is still there")
	}
	if r.Cancel() != nil || win.cancels != 0 {
		t.Fatal("Cancel reached the operating system after a reboot")
	}

	// the uptime is not known at all (not Windows): the clock decides, as before
	win, c, store = &fakeOS{}, newClock(), newStore()
	c.boot = time.Time{}
	_ = start(win, store, c).ScheduleBy("shutdown", time.Hour, "panel")
	c.advance(time.Minute)
	if _, ok := start(win, store, c).PendingAction(); !ok {
		t.Fatal("dropped because the uptime is unknown")
	}
	c.advance(time.Hour + time.Minute)
	if _, ok := start(win, store, c).PendingAction(); ok {
		t.Fatal("a record whose time has passed by the clock is still there")
	}
}

// N6 (review of the Windows side; L21 again): the record must not depend on the clock. Windows counts a
// shutdown down by its own time; a correction of the clock while it is pending changes nothing about it.
func TestClockCorrectionsDoNotEndTheRecord(t *testing.T) {
	for _, step := range []time.Duration{31 * time.Second, 5 * time.Minute, 3 * time.Hour, 400 * 24 * time.Hour,
		-31 * time.Second, -5 * time.Minute, -3 * time.Hour, -400 * 24 * time.Hour} {
		win, c := &fakeOS{}, newClock()
		store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
		p := start(win, store, c)
		if err := p.ScheduleBy("shutdown", 10*time.Minute, "panel"); err != nil {
			t.Fatal(err)
		}
		c.advance(time.Minute)
		c.correct(step)
		for name, r := range map[string]*RememberedPower{"the same run": p, "after a restart of the service": start(win, store, c)} {
			got, ok := r.PendingAction()
			if !ok {
				t.Fatalf("clock corrected by %s, %s: the pending shutdown is no longer shown (Windows still counts it down)", step, name)
			}
			// ... and the time shown is the time it happens by the corrected clock: nine minutes from now
			if want := float64(c.now.Add(9*time.Minute).UnixMilli()) / 1000; got.At != want || got.DelayS != 600 {
				t.Errorf("clock corrected by %s, %s: shown for %v, want %v", step, name, got.At, want)
			}
		}
		// its time passes by the machine's own count, wherever the clock is: gone a minute after
		c.advance(9*time.Minute + 59*time.Second)
		if _, ok := p.PendingAction(); !ok {
			t.Fatalf("clock corrected by %s: dropped inside the minute of grace", step)
		}
		if err := p.Cancel(); err != nil || win.cancels != 1 {
			t.Fatalf("clock corrected by %s: Cancel asked Windows to abort %d times (%v): the PC still shuts down", step, win.cancels, err)
		}
		// a second one: not cancelled, its time passes
		if err := p.ScheduleBy("reboot", 10*time.Minute, "panel"); err != nil {
			t.Fatal(err)
		}
		c.correct(-step)
		c.advance(11*time.Minute + time.Second)
		if _, ok := p.PendingAction(); ok {
			t.Fatalf("clock corrected by %s: a record whose time has passed is still shown", step)
		}
		if _, err := os.Stat(store.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("clock corrected by %s: the record's file is still there", step)
		}
		if p.Cancel() != nil || win.cancels != 1 {
			t.Fatalf("clock corrected by %s: Cancel reached Windows for a record whose time has passed", step)
		}
	}
	// the other half stays true with a corrected clock: Windows was restarted, the record is from before
	win, c := &fakeOS{}, newClock()
	store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	_ = start(win, store, c).ScheduleBy("shutdown", 12*time.Hour, "panel")
	c.advance(20 * time.Minute)
	c.boot = c.now.Add(-90 * time.Second) // restarted: up for 90 seconds
	c.correct(-20 * time.Minute)          // and the clock went back to where it was when the record was written
	r := start(win, store, c)
	if _, ok := r.PendingAction(); ok || r.Cancel() != nil || win.cancels != 0 {
		t.Fatal("a record from before the last start of Windows was believed because the clock agreed with it")
	}
}

// The review's proof of N6, as it was written (it failed before the fix): one minute after a shutdown in ten
// minutes was scheduled, the clock is set forward by five minutes; the PC was not restarted.
func TestCancelAfterAClockCorrection(t *testing.T) {
	c, osx := newClock(), &fakeOS{}
	store := PowerFile{Path: t.TempDir() + "/power-pending.json"}
	p := start(osx, store, c)
	if err := p.ScheduleBy("shutdown", 10*time.Minute, "nika"); err != nil {
		t.Fatal(err)
	}
	c.advance(time.Minute)
	c.now, c.boot = c.now.Add(5*time.Minute), c.boot.Add(5*time.Minute)
	if _, ok := p.PendingAction(); !ok {
		t.Errorf("the pending shutdown is no longer shown after a clock correction (Windows still counts it down)")
	}
	if err := p.Cancel(); err != nil {
		t.Fatal(err)
	}
	if osx.cancels != 1 {
		t.Errorf("Cancel answered ok but asked Windows to abort %d times: the PC still shuts down", osx.cancels)
	}
}

func TestPowerRecordEnded(t *testing.T) {
	rec := &PowerRecord{Action: "shutdown", At: 10_000, DelayS: 600, Up: 5000}
	for _, c := range []struct {
		name    string
		now, up float64
		known   bool
		ended   bool
	}{
		{"just scheduled", 9400, 5000, true, false},
		{"half way", 9700, 5300, true, false},
		{"inside the minute of grace", 10_059, 5659, true, false},
		{"its time has passed", 10_061, 5661, true, true},
		{"restarted: the uptime is smaller", 9700, 90, true, true},
		{"the clock says long past, the uptime does not", 99_999, 5300, true, false},
		{"the clock says not yet, the uptime says past", 9500, 5661, true, true},
		{"no uptime to ask: the clock, not yet", 10_059, 0, false, false},
		{"no uptime to ask: the clock, past", 10_061, 0, false, true},
	} {
		if got := rec.ended(c.now, c.up, c.known); got != c.ended {
			t.Errorf("%s: ended = %v", c.name, got)
		}
	}
	// a record without an uptime (written where there is none): the clock
	old := &PowerRecord{Action: "shutdown", At: 10_000, DelayS: 600}
	if old.ended(9700, 123456, true) || !old.ended(10_061, 123456, true) {
		t.Error("a record without an uptime is not decided by the clock")
	}
}

// Sleep is a timer inside the service: it ends with the service, so it is not written down, and after a restart
// nothing is pending and Cancel asks the operating system nothing (it must not abort somebody's shutdown).
func TestSleepIsNotRememberedAcrossARestart(t *testing.T) {
	store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	win, c := &fakeOS{}, newClock()
	r1 := start(win, store, c)
	if err := r1.ScheduleBy("sleep", time.Hour, "panel"); err != nil {
		t.Fatal(err)
	}
	if p, ok := r1.PendingAction(); !ok || p.Action != "sleep" {
		t.Fatal(p, ok)
	}
	if _, err := os.Stat(store.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("sleep was written to the file")
	}
	r2 := start(win, store, c)
	if _, ok := r2.PendingAction(); ok {
		t.Fatal("sleep pending after a restart")
	}
	if r2.Cancel() != nil || win.cancels != 0 {
		t.Fatal(win.cancels)
	}
	// in the same run it is cancelled as before
	if r1.Cancel() != nil || win.cancels != 1 {
		t.Fatal(win.cancels)
	}
}

func TestCancelFailureKeepsTheRecord(t *testing.T) {
	store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	win, c := &fakeOS{cancelErr: errors.New("access denied")}, newClock()
	r := start(win, store, c)
	_ = r.ScheduleBy("shutdown", time.Hour, "panel")
	if err := r.Cancel(); err == nil {
		t.Fatal("no error")
	}
	if _, ok := r.PendingAction(); !ok {
		t.Fatal("the record was dropped although the shutdown was not aborted")
	}
	win.cancelErr = nil
	if err := start(win, store, c).Cancel(); err != nil || win.cancels != 1 {
		t.Fatal(err, win.cancels)
	}
}

func TestPowerFile(t *testing.T) {
	dir := t.TempDir()
	f := PowerFile{Path: filepath.Join(dir, "power-pending.json")}
	if r, err := f.Load(); r != nil || err != nil {
		t.Fatal(r, err)
	}
	if r, err := (PowerFile{Path: filepath.Join(dir, "missing", "p.json"), Check: func(string) error { return errors.New("x") }}).Load(); r != nil || err != nil {
		t.Fatal("a folder that does not exist is not an error:", r, err)
	}
	rec := &PowerRecord{Action: "reboot", At: 1_800_000_600, DelayS: 600, By: "panel", Up: 10_800}
	if err := f.Save(rec); err != nil {
		t.Fatal(err)
	}
	if got, err := f.Load(); err != nil || *got != *rec {
		t.Fatal(got, err)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatal("temporary file left behind:", ents)
	}
	// what is not a record of a pending action is refused, never half believed
	for name, body := range map[string]string{
		"not JSON":       "shutdown",
		"unknown action": `{"action":"format","at":1800000600,"delay_s":10,"by":"x"}`,
		"cancel":         `{"action":"cancel","at":1800000600}`,
		"no time":        `{"action":"shutdown","delay_s":10}`,
		"negative time":  `{"action":"shutdown","at":-1}`,
		"absurd time":    `{"action":"shutdown","at":1e300}`,
		"absurd delay":   `{"action":"shutdown","at":1800000600,"delay_s":99999999}`,
		"too large":      `{"action":"shutdown","at":1800000600,"by":"` + strings.Repeat("a", 5000) + `"}`,
	} {
		if err := os.WriteFile(f.Path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if r, err := f.Load(); err == nil {
			t.Errorf("%s: accepted %+v", name, r)
		}
		win, c := &fakeOS{}, newClock()
		r := start(win, f, c)
		if _, ok := r.PendingAction(); ok || r.Cancel() != nil || win.cancels != 0 {
			t.Errorf("%s: acted on", name)
		}
	}
	// who asked is cleaned when read (it is shown in the panel)
	_ = os.WriteFile(f.Path, []byte(`{"action":"shutdown","at":1800000600,"delay_s":10,"by":"a<script>b\n"}`), 0o600)
	if r, err := f.Load(); err != nil || r.By != "ascriptb" {
		t.Fatal(r, err)
	}
	// a link under the name is not followed (regular files only)
	target := filepath.Join(t.TempDir(), "elsewhere.json")
	_ = os.WriteFile(target, []byte(`{"action":"shutdown","at":1800000600,"delay_s":10,"by":"x"}`), 0o600)
	_ = os.Remove(f.Path)
	if err := os.Symlink(target, f.Path); err == nil {
		if r, err := f.Load(); err == nil {
			t.Errorf("a symbolic link was read: %+v", r)
		}
		if err := f.Save(rec); err != nil { // Save replaces the link itself
			t.Fatal(err)
		}
		if st, _ := os.Lstat(f.Path); st == nil || !st.Mode().IsRegular() {
			t.Error("Save wrote through the link")
		}
		if b, _ := os.ReadFile(target); !strings.Contains(string(b), `"by":"x"`) {
			t.Error("the link's target was changed")
		}
	}
	if err := f.Save(nil); err != nil {
		t.Fatal(err)
	}
	if err := f.Save(nil); err != nil { // nothing to remove is fine
		t.Fatal(err)
	}
}

// A folder that is not safe to write as LocalSystem: nothing is read or written there. The shutdown is still
// scheduled and can be cancelled in the same run; only a restart forgets it (the behaviour before L21).
func TestPowerFileFolderCheck(t *testing.T) {
	dir := t.TempDir()
	refused := errors.New("C:\\ProgramData\\fairy-agent\\helper is owned by S-1-5-21-1-2-3-1001")
	f := PowerFile{Path: filepath.Join(dir, "power-pending.json"), Check: func(string) error { return refused }}
	_ = os.WriteFile(f.Path, []byte(`{"action":"shutdown","at":1800003600,"delay_s":3600,"by":"planted"}`), 0o600)
	win, c := &fakeOS{}, newClock()
	r := start(win, f, c)
	if _, ok := r.PendingAction(); ok {
		t.Fatal("a record in an unsafe folder was believed")
	}
	if err := r.ScheduleBy("shutdown", time.Hour, "panel"); err != nil || len(win.scheduled) != 1 {
		t.Fatal(err, win.scheduled)
	}
	if b, _ := os.ReadFile(f.Path); !strings.Contains(string(b), "planted") {
		t.Fatal("wrote into an unsafe folder")
	}
	if err := r.Cancel(); err != nil || win.cancels != 1 {
		t.Fatal(err, win.cancels)
	}
}

func TestAbortGone(t *testing.T) {
	if !abortGone(1116) { // ERROR_NO_SHUTDOWN_IN_PROGRESS: aborted on the PC itself
		t.Fatal("1116")
	}
	for _, code := range []uint32{0, 5, 1115, 1190, 21} { // success is not an error; access denied, in progress ... are failures
		if abortGone(code) {
			t.Fatal(code)
		}
	}
}

// The agent's own memory is gone after it restarts; what the exec still remembers is shown and cancellable.
func TestPowerAdoptsWhatTheExecRemembers(t *testing.T) {
	store := PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	win, c := &fakeOS{}, newClock()
	newAgent := func() *Power {
		p := NewPower(start(win, store, c), 10)
		p.now = c.Now
		return p
	}
	a1 := newAgent()
	d := 3600
	if st, b := a1.Handle(PowerRequest{Action: "shutdown", DelayS: &d, RequestedBy: "neptune@example.com"}); st != 200 {
		t.Fatal(st, b)
	}
	c.advance(time.Minute)

	a2 := newAgent() // the agent (and with it the exec) restarted
	pend, _ := a2.State()["pending"].(Pending)
	if pend.Action != "shutdown" || pend.RequestedBy != "neptune@example.com" || pend.DelayS != 3600 || pend.At != float64(c.now.Unix()+3540) {
		t.Fatalf("after the restart /metrics shows %+v", a2.State()["pending"])
	}
	if !a2.Scheduled() {
		t.Fatal("Scheduled() is false")
	}
	if st, _ := a2.Handle(PowerRequest{Action: "reboot", DelayS: &d}); st != 409 { // still one action at a time
		t.Fatal(st)
	}
	if st, b := a2.Handle(PowerRequest{Action: "cancel"}); st != 200 || b["pending"] != nil || win.cancels != 1 {
		t.Fatal(st, b, win.cancels)
	}
	if a2.State()["pending"] != nil || a2.Scheduled() {
		t.Fatal("still pending after Cancel")
	}
	// nothing of Fairy's pending: Cancel answers ok and asks the operating system nothing
	if st, _ := a2.Handle(PowerRequest{Action: "cancel"}); st != 200 || win.cancels != 1 {
		t.Fatal(st, win.cancels)
	}
}

// staleSource keeps reporting an action for a while after it was cancelled, like the helper's cached status.
type staleSource struct {
	fakeOS
	p Pending
}

func (s *staleSource) PendingAction() (Pending, bool) { return s.p, s.p.Action != "" }

func TestPowerDoesNotShowACancelledActionAgain(t *testing.T) {
	c := newClock()
	src := &staleSource{p: Pending{Action: "shutdown", At: float64(c.now.Unix() + 600), DelayS: 600, RequestedBy: "panel"}}
	p := NewPower(src, 10)
	p.now = c.Now
	if p.State()["pending"] == nil {
		t.Fatal("not adopted")
	}
	if st, _ := p.Handle(PowerRequest{Action: "cancel"}); st != 200 || src.cancels != 1 {
		t.Fatal(st, src.cancels)
	}
	if p.State()["pending"] != nil { // src still reports it (stale)
		t.Fatal("the cancelled action is shown again")
	}
	if st, _ := p.Handle(PowerRequest{Action: "cancel"}); st != 200 || src.cancels != 1 {
		t.Fatal("cancelled twice", src.cancels)
	}
	// the same when this process scheduled the action itself and the exec's record of it is a few milliseconds
	// off (the helper reads its own clock)
	d := 600
	src.p = Pending{}
	if st, _ := p.Handle(PowerRequest{Action: "reboot", DelayS: &d, RequestedBy: "panel"}); st != 200 {
		t.Fatal(st)
	}
	own := p.State()["pending"].(Pending)
	src.p = Pending{Action: "reboot", At: own.At - 0.004, DelayS: 600, RequestedBy: "panel"}
	if st, _ := p.Handle(PowerRequest{Action: "cancel"}); st != 200 || src.cancels != 2 {
		t.Fatal(st, src.cancels)
	}
	if p.State()["pending"] != nil {
		t.Fatal("the cancelled action is shown again (the exec's time differs by 4 ms)")
	}
	// a new action later is shown again, also one adopted with another time
	src.p.At += 100
	if p.State()["pending"] == nil {
		t.Fatal("a later action is hidden")
	}
	// what the exec reports past its time is not shown
	c.advance(2 * time.Hour)
	if p.State()["pending"] != nil {
		t.Fatal("an action whose time has passed is shown")
	}
}

// N9 (review of the Windows side): helper\power-pending.json was believed when its folder passed the check.
// A file put there before the folder was locked (on a PC prepared before an install up to 0.5.3 that got only
// the new program) keeps its own owner and permissions, and whoever planted it can still write it: the panel
// showed a pending shutdown that is not Fairy's, and Cancel aborted a shutdown Fairy did not start. The file
// itself is checked now before it is read.
func TestPlantedPowerRecordIsNotBelieved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "power-pending.json")
	planted := `{"action":"shutdown","at":1800000600,"delay_s":600,"by":"panel","up":10800}`
	if err := os.WriteFile(path, []byte(planted), 0o600); err != nil {
		t.Fatal(err)
	}
	var folders, files []string
	theirs := errors.New(`C:\ProgramData\fairy-agent\helper\power-pending.json is owned by S-1-5-21-1-2-3-1001, not by Administrators / SYSTEM`)
	store := PowerFile{Path: path,
		Check: func(d string) error { folders = append(folders, d); return nil }, // the folder is fine today
		CheckFile: func(p string) error {
			files = append(files, p)
			if b, _ := os.ReadFile(p); string(b) == planted { // stands for: someone else owns it
				return theirs
			}
			return nil
		}}
	// without the file check this is a valid record of a shutdown in ten minutes
	if r, err := (PowerFile{Path: path}).Load(); err != nil || r == nil || r.Action != "shutdown" {
		t.Fatal("fixture:", r, err)
	}
	if r, err := store.Load(); r != nil || !errors.Is(err, theirs) {
		t.Fatalf("the planted record was believed: %+v %v", r, err)
	}
	if len(files) != 1 || files[0] != path || len(folders) != 1 {
		t.Fatalf("asked about files %v, folders %v", files, folders)
	}
	win, c := &fakeOS{}, newClock()
	c.now = time.Unix(1_800_000_060, 0) // inside the planted record's ten minutes
	r := start(win, store, c)
	if p, ok := r.PendingAction(); ok {
		t.Fatalf("the panel is shown a shutdown that is not Fairy's: %+v", p)
	}
	if err := r.Cancel(); err != nil || win.cancels != 0 {
		t.Fatalf("Cancel asked Windows to abort %d times because of a planted file (%v)", win.cancels, err)
	}
	if b, _ := os.ReadFile(path); string(b) != planted {
		t.Fatal("the planted file was changed by reading it")
	}
	// Fairy's own next action replaces the file (a new file, written by this service), and that one is believed
	if err := r.ScheduleBy("reboot", 5*time.Minute, "panel"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) == planted || !strings.Contains(string(b), `"reboot"`) {
		t.Fatalf("the record was not replaced: %s", b)
	}
	r2 := start(win, store, c)
	if p, ok := r2.PendingAction(); !ok || p.Action != "reboot" {
		t.Fatalf("Fairy's own record is not believed after a restart: %+v %v", p, ok)
	}
	if err := r2.Cancel(); err != nil || win.cancels != 1 {
		t.Fatal(err, win.cancels)
	}
	// no file, no question
	files = nil
	if rec, err := store.Load(); rec != nil || err != nil || len(files) != 0 {
		t.Fatal(rec, err, files)
	}
}
