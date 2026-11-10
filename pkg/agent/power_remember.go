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
// since it was written (the countdown died with the old Windows session; see sameBoot).

// PowerRecord is the remembered action.
type PowerRecord struct {
	Action string  `json:"action"`  // shutdown | reboot | sleep
	At     float64 `json:"at"`      // when it happens, unix seconds
	DelayS int     `json:"delay_s"` // the delay it was asked with
	By     string  `json:"by"`      // who asked (cleaned)
	Boot   float64 `json:"boot"`    // when the operating system started, unix seconds; 0 = not known
}

// powerRecordGrace is how long after its time a record is still reported (as Power does for its own).
const powerRecordGrace = 60 * time.Second

// bootSlack is how far two readings of the operating system's start time may differ and still mean the same
// start. The start time is "now minus uptime", so it moves when the clock is corrected; a real restart moves
// it by the time the machine was up before plus the time it took to start again.
const bootSlack = 30 * time.Second

var powerRecordActions = []string{"shutdown", "reboot", "sleep"}

// valid reports whether a record read from the file can be believed at all.
func (r *PowerRecord) valid() bool {
	return r != nil && slices.Contains(powerRecordActions, r.Action) &&
		!math.IsNaN(r.At) && !math.IsInf(r.At, 0) && r.At > 0 && r.At < 1e11 &&
		r.DelayS >= 0 && r.DelayS <= 86400 && !math.IsNaN(r.Boot) && !math.IsInf(r.Boot, 0) && r.Boot >= 0
}

// sameBoot reports whether the operating system has not been started again since a record with start time
// recorded was written (both in unix seconds; 0 = unknown, which never ends a record).
func sameBoot(recorded, now float64) bool {
	if recorded == 0 || now == 0 {
		return true
	}
	return math.Abs(now-recorded) <= bootSlack.Seconds()
}

// PowerStore keeps the record across restarts of the program. Save(nil) removes it; Load returns nil, nil when
// there is none.
type PowerStore interface {
	Load() (*PowerRecord, error)
	Save(*PowerRecord) error
}

// PowerFile is a PowerStore in one small JSON file, replaced in one step. Check, when set, must accept the
// file's folder before every read and write (Windows: only administrators and SYSTEM may change it; the
// helper is LocalSystem and writes nowhere else).
type PowerFile struct {
	Path  string
	Check func(dir string) error
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
	// boot is when the operating system started (false: unknown).
	boot func() (time.Time, bool)
	now  func() time.Time

	mu  sync.Mutex
	rec *PowerRecord
}

// RememberPower wraps exec. store may be nil (nothing survives a restart); kept and boot may be nil.
func RememberPower(exec PowerExec, store PowerStore, kept func(action string) bool, boot func() (time.Time, bool)) *RememberedPower {
	return rememberPower(exec, store, kept, boot, time.Now)
}

func rememberPower(exec PowerExec, store PowerStore, kept func(action string) bool, boot func() (time.Time, bool), now func() time.Time) *RememberedPower {
	r := &RememberedPower{exec: exec, store: store, kept: kept, boot: boot, now: now}
	r.restore()
	return r
}

func (r *RememberedPower) bootUnix() float64 {
	if r.boot == nil {
		return 0
	}
	t, ok := r.boot()
	if !ok {
		return 0
	}
	return float64(t.UnixMilli()) / 1000
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
		slog.Warn("power: an action scheduled before this start is still pending", "action", rec.Action,
			"at", time.Unix(int64(rec.At), 0).Format(time.RFC3339), "requested_by", rec.By)
	}
}

// current returns the record if it is still valid, and forgets it otherwise. Caller holds r.mu.
func (r *RememberedPower) current() *PowerRecord {
	if r.rec == nil {
		return nil
	}
	now := float64(r.now().UnixMilli()) / 1000
	if now > r.rec.At+powerRecordGrace.Seconds() || !sameBoot(r.rec.Boot, r.bootUnix()) {
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
	return Pending{Action: rec.Action, At: rec.At, DelayS: rec.DelayS, RequestedBy: rec.By}, true
}

// powerMessage is the text Windows shows to whoever is signed in.
func powerMessage(action, who string, delay time.Duration) string {
	return fmt.Sprintf("Fairy: %s requested by %s in %d seconds.", action, who, int(delay/time.Second))
}

// Schedule schedules action and remembers it. The requester is not known here (see ScheduleBy).
func (r *RememberedPower) Schedule(action string, delay time.Duration, message string) error {
	return r.schedule(action, delay, message, "unknown")
}

// ScheduleBy is Schedule with the requester, who is remembered with the action; the message is built here.
func (r *RememberedPower) ScheduleBy(action string, delay time.Duration, who string) error {
	who = cleanWho(who)
	return r.schedule(action, delay, powerMessage(action, who, delay), who)
}

func (r *RememberedPower) schedule(action string, delay time.Duration, message, who string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current() // forget a record whose time has passed, with its file
	if err := r.exec.Schedule(action, delay, message); err != nil {
		return err
	}
	at := float64(r.now().UnixMilli())/1000 + delay.Seconds()
	r.rec = &PowerRecord{Action: action, At: math.Round(at*1000) / 1000, DelayS: int(delay / time.Second), By: who, Boot: r.bootUnix()}
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
