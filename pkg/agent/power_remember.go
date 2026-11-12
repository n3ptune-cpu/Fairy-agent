package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
)

// Remembering Fairy's own pending shutdown.
//
// On Windows a delayed shutdown or reboot is counted down by Windows itself (InitiateSystemShutdownEx), so it
// goes on when the program that asked for it restarts: an update, a crash, Stop / Start of the helper. Without
// a memory of it the panel showed nothing pending after such a restart and Cancel did nothing while the PC
// still shut down. RememberedPower keeps a record of the one action Fairy scheduled (in a small file for the
// actions the operating system counts down, in memory for the others), so that after a restart
//   - the pending action is still reported (PendingAction), and
//   - Cancel aborts it.
//
// Cancel aborts only that: with no record of an action of Fairy's own, Cancel does not ask the operating system
// to abort anything, so a shutdown Fairy did not start (a Windows Update restart, `shutdown /s` typed by
// someone) is never cancelled from the panel. Windows allows one scheduled shutdown at a time and refuses a
// second one, so while Fairy's record is valid the pending shutdown is Fairy's.
//
// A record ends when its time has passed, when it is cancelled, and when the machine has been started again
// since it was written (the countdown died with the old Windows session). Both are decided by the operating
// system's own count of the time since it started (uptime), not by the clock: see ended.

// PowerRecord is the remembered action.
type PowerRecord struct {
	Action string  `json:"action"`  // shutdown | reboot | sleep
	At     float64 `json:"at"`      // when it happens, unix seconds
	DelayS int     `json:"delay_s"` // the delay it was asked with
	By     string  `json:"by"`      // who asked (cleaned)
	// Up is how long the operating system had been running when the action was scheduled, in seconds
	// (Windows: GetTickCount64); 0 = not known. Unlike the clock it does not move when the time is corrected.
	Up float64 `json:"up"`
}

// powerRecordGrace is how long after its time a record is still reported (as Power does for its own).
const powerRecordGrace = 60 * time.Second

// atSlack is how far the time an action happens, counted by the uptime, may be from the time on record before
// the uptime's is reported instead (the clock was corrected since).
const atSlack = 2 * time.Second

var powerRecordActions = []string{"shutdown", "reboot", "sleep"}

// valid reports whether a record read from the file can be believed at all.
func (r *PowerRecord) valid() bool {
	return r != nil && slices.Contains(powerRecordActions, r.Action) &&
		!math.IsNaN(r.At) && !math.IsInf(r.At, 0) && r.At > 0 && r.At < 1e11 &&
		r.DelayS >= 0 && r.DelayS <= 86400 && !math.IsNaN(r.Up) && !math.IsInf(r.Up, 0) && r.Up >= 0
}

// ended reports whether a record no longer stands for a pending action. now is the clock in unix seconds; up
// is the operating system's uptime in seconds (upKnown false: there is none to ask).
//
// With an uptime on record and one to compare it with, only those two decide, never the clock:
//   - the uptime is smaller than the one on record: the operating system was started again since, and the
//     countdown died with the old session;
//   - more uptime has passed than the delay plus the minute of grace: its time has passed.
//
// Before, "started again" was read off "clock minus uptime", which moves with every correction of the clock:
// a first time synchronisation after a start with a wrong hardware clock, a dual-boot PC, a virtual machine
// resumed from a snapshot. A correction of more than 30 seconds while a shutdown was pending dropped the
// record, the panel showed nothing and Cancel answered ok without aborting anything, while Windows went on
// counting down. A clock set forward past the action's time did the same.
//
// What the uptime cannot tell: a restart after which the machine has again been up for longer than it had been
// when the action was scheduled, inside the delay. The record then stays until that time has passed, and
// Cancel asks Windows to abort (it answers "nothing in progress", unless someone else scheduled a shutdown in
// that very time). That is the smaller harm of the two: a Cancel that does nothing lets the PC shut down.
//
// Without an uptime (not Windows, where the agent itself waits for the time and the record lives in memory)
// the clock decides, as before.
func (rec *PowerRecord) ended(now, up float64, upKnown bool) bool {
	grace := powerRecordGrace.Seconds()
	if upKnown && rec.Up > 0 {
		return up < rec.Up || up-rec.Up > float64(rec.DelayS)+grace
	}
	return now > rec.At+grace
}

// at is when the action happens, in unix seconds: the time on record, or, when the clock was corrected since
// the action was scheduled, the time by today's clock (what is left of the delay by the uptime).
func (rec *PowerRecord) at(now, up float64, upKnown bool) float64 {
	if !upKnown || rec.Up <= 0 {
		return rec.At
	}
	if at := now + float64(rec.DelayS) - (up - rec.Up); math.Abs(at-rec.At) > atSlack.Seconds() {
		return math.Round(at*1000) / 1000
	}
	return rec.At
}

// PowerStore keeps the record across restarts of the program. Save(nil) removes it; Load returns nil, nil when
// there is none.
type PowerStore interface {
	Load() (*PowerRecord, error)
	Save(*PowerRecord) error
}

// PowerFile is a PowerStore in one small JSON file, replaced in one step. Check, when set, must accept the
// file's folder before every read and write (Windows: only administrators and SYSTEM may change it; the
// helper is LocalSystem and writes nowhere else). CheckFile, when set, must accept the file itself before it
// is read: a folder that is safe today can still hold a file that was put there before it was locked, and
// that file keeps its own owner and permissions. Such a file is not a record of Fairy's.
type PowerFile struct {
	Path      string
	Check     func(dir string) error
	CheckFile func(path string) error
}

const powerFileMax = 4 << 10

// Load reads the record.
func (f PowerFile) Load() (*PowerRecord, error) {
	dir := filepath.Dir(f.Path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if f.Check != nil {
		if err := f.Check(dir); err != nil {
			return nil, err
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
	if f.CheckFile != nil {
		if err := f.CheckFile(f.Path); err != nil {
			return nil, err
		}
	}
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, powerFileMax+1))
	if err != nil {
		return nil, err
	}
	if len(b) > powerFileMax {
		return nil, fmt.Errorf("%s is too large", f.Path)
	}
	var r PowerRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	if !r.valid() {
		return nil, fmt.Errorf("%s: not a pending power action", f.Path)
	}
	r.By = cleanWho(r.By)
	return &r, nil
}

// Save writes the record (nil: removes the file).
func (f PowerFile) Save(r *PowerRecord) error {
	dir := filepath.Dir(f.Path)
	if f.Check != nil {
		if err := f.Check(dir); err != nil {
			return err
		}
	}
	if r == nil {
		if err := os.Remove(f.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".power-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), f.Path) // replaces a link under the final name, never follows it
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// RememberedPower is a PowerExec that remembers the action it scheduled (see the top of this file).
type RememberedPower struct {
	exec  PowerExec
	store PowerStore // nil: memory only
	// kept reports whether the operating system itself counts an action down, so that it goes on when this
	// program restarts (Windows: shutdown and reboot). Only those are written to the store; the others live in
	// this process (a timer) and end with it.
	kept func(action string) bool
	// uptime is how long the operating system has been running (false: unknown). It must not move when the
	// clock is corrected (Windows: GetTickCount64).
	uptime func() (time.Duration, bool)
	now    func() time.Time

	mu  sync.Mutex
	rec *PowerRecord
}

// RememberPower wraps exec. store may be nil (nothing survives a restart); kept and uptime may be nil.
func RememberPower(exec PowerExec, store PowerStore, kept func(action string) bool, uptime func() (time.Duration, bool)) *RememberedPower {
	return rememberPower(exec, store, kept, uptime, time.Now)
}

func rememberPower(exec PowerExec, store PowerStore, kept func(action string) bool, uptime func() (time.Duration, bool), now func() time.Time) *RememberedPower {
	r := &RememberedPower{exec: exec, store: store, kept: kept, uptime: uptime, now: now}
	r.restore()
	return r
}

// clocks reads the clock (unix seconds) and the uptime (seconds).
func (r *RememberedPower) clocks() (now, up float64, upKnown bool) {
	now = float64(r.now().UnixMilli()) / 1000
	if r.uptime != nil {
		if d, ok := r.uptime(); ok && d > 0 {
			return now, d.Seconds(), true
		}
	}
	return now, 0, false
}

// restore reads the stored record when the program starts.
func (r *RememberedPower) restore() {
	if r.store == nil {
		return
	}
	rec, err := r.store.Load()
	if err != nil {
		slog.Warn("power: the remembered pending action could not be read; Cancel will not abort a shutdown scheduled before this start", "error", err.Error())
		return
	}
	if rec == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rec = rec
	if r.current() != nil {
		now, up, upKnown := r.clocks()
		slog.Warn("power: an action scheduled before this start is still pending", "action", rec.Action,
			"at", time.Unix(int64(rec.at(now, up, upKnown)), 0).Format(time.RFC3339), "requested_by", rec.By)
	}
}

// current returns the record if it is still valid, and forgets it otherwise. Caller holds r.mu.
func (r *RememberedPower) current() *PowerRecord {
	if r.rec == nil {
		return nil
	}
	if r.rec.ended(r.clocks()) {
		r.forget()
	}
	return r.rec
}

// forget drops the record and its file. Caller holds r.mu.
func (r *RememberedPower) forget() {
	stored := r.rec != nil && r.store != nil && (r.kept == nil || r.kept(r.rec.Action))
	r.rec = nil
	if stored {
		if err := r.store.Save(nil); err != nil {
			slog.Warn("power: could not remove the remembered pending action", "error", err.Error())
		}
	}
}

// PendingAction is the action of Fairy's own that is still pending, if any.
func (r *RememberedPower) PendingAction() (Pending, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.current()
	if rec == nil {
		return Pending{}, false
	}
	return Pending{Action: rec.Action, At: rec.at(r.clocks()), DelayS: rec.DelayS, RequestedBy: rec.By}, true
}

// PowerMessage is the text handed to the operating system with a shutdown or reboot; Windows shows it to
// whoever is signed in (InitiateSystemShutdownExW takes it as UTF-16). It is for display only, and the one
// place where it is made.
//
// No word of it begins with "-": every hyphen of the requester's name is written as U+2011, the non-breaking
// hyphen, which looks the same. On a real PC the notice for "test-admin" read "Fairy: shutdown requested by
// test" and nothing more; whatever in Windows cuts it there, a name is free to hold " -x", and no part of
// this text may look like a switch to a program it is handed to. The rest of the sentence has no "-" and no
// "/" (the action is one of three words, the delay is never negative, a cleaned name has no "/"). The name
// itself is not changed anywhere else: the record, requested_by in every answer, the log and the helper's
// audit keep it as it was sent.
func PowerMessage(action, who string, delay time.Duration) string {
	return fmt.Sprintf("Fairy: %s requested by %s in %d seconds.", action, strings.ReplaceAll(who, "-", "\u2011"), int(delay/time.Second))
}

// Schedule schedules action and remembers it. The requester is not known here (see ScheduleBy).
func (r *RememberedPower) Schedule(action string, delay time.Duration, message string) error {
	return r.schedule(action, delay, message, "unknown")
}

// ScheduleBy is Schedule with the requester, who is remembered with the action; the message is built here.
func (r *RememberedPower) ScheduleBy(action string, delay time.Duration, who string) error {
	who = cleanWho(who)
	return r.schedule(action, delay, PowerMessage(action, who, delay), who)
}

func (r *RememberedPower) schedule(action string, delay time.Duration, message, who string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current() // forget a record whose time has passed, with its file
	if err := r.exec.Schedule(action, delay, message); err != nil {
		return err
	}
	now, up, _ := r.clocks()
	at := now + delay.Seconds()
	r.rec = &PowerRecord{Action: action, At: math.Round(at*1000) / 1000, DelayS: int(delay / time.Second), By: who, Up: math.Round(up*1000) / 1000}
	if r.store != nil && (r.kept == nil || r.kept(action)) {
		if err := r.store.Save(r.rec); err != nil {
			// the action is scheduled all the same; only a restart of this program would forget it
			slog.Warn("power: could not remember the pending action; after a restart of this service Cancel will not abort it",
				"action", action, "error", err.Error())
		}
	}
	return nil
}

// Cancel aborts the pending action of Fairy's own. With none on record it does nothing and asks the operating
// system nothing: a shutdown someone else scheduled is not Fairy's to cancel.
func (r *RememberedPower) Cancel() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.current() == nil {
		return nil
	}
	if err := r.exec.Cancel(); err != nil {
		return err // the record stays: Cancel can be asked again
	}
	r.forget()
	return nil
}

// CanSleep passes through.
func (r *RememberedPower) CanSleep() (bool, string) { return r.exec.CanSleep() }

// SystemPowerAt is SystemPower with the folder for the record of a pending shutdown (Windows; elsewhere the
// folder is not used: the agent itself waits and the action ends with it).
func SystemPowerAt(dir string) PowerExec { return systemPowerAt(dir) }
