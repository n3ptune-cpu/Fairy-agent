package approval

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// RunFileName is the run record: the file next to the trust file in which the checker (Windows: the helper;
// elsewhere the agent) keeps what a run ticket and a run confirmation gave this machine. It holds no token and
// no part of one. It has two halves.
//
// The live run ("run"): armed (the machine switches itself off at a moment counted on its uptime), counting
// down, or confirmed (one update and one shutdown of the run are still let through). Only the checker writes
// it, and only after it verified a token itself. It is taken out of the file when it is used up, when it is
// cancelled, when its time is over, and when the file is found in a later boot than it was written in.
//
// The mark ("arm", "used", "last"): in which boot a ticket was accepted last, the ids of the runs that were
// accepted here, and how the last run ended. It gives nothing: it only refuses. "One ticket per boot" and "a
// run that was cancelled does not arm again" must hold after the service restarts (whoever holds the control
// token can restart the Windows helper), and "a ticket of a run that was accepted before" after the machine
// restarts, so they cannot live in memory only.
const RunFileName = "approval-run.json"

const (
	// maxRunFile bounds the run record (a full one is under 1 KiB).
	maxRunFile = 8 << 10
	// runUsedMax is how many run ids the mark remembers. A ticket is good for 11 minutes at most, so the id of
	// a run falls out of the list only after sixteen later runs were accepted on this machine.
	runUsedMax     = 16
	runTempPattern = ".approval-run-*.tmp"
)

// bootRef says when something was written: the system's own id of the boot where it has one (Linux), this
// machine's clock (Unix seconds) and how long the system had been up (milliseconds).
type bootRef struct {
	BootID string `json:"boot_id,omitempty"`
	Wall   int64  `json:"wall"`
	UpMS   int64  `json:"up_ms"`
}

// runLast is how the last run ended.
type runLast struct {
	ID    string `json:"id"`
	State string `json:"state"` // api.RunCancelled | api.RunDone
}

// runLive is the live run.
type runLive struct {
	ID    string `json:"id"`
	State string `json:"state"` // api.RunArmed | api.RunOffPending | api.RunConfirmed
	// Who signed the token this state rests on: for the log and, the name, for the notice.
	Sub  string `json:"sub,omitempty"`
	Name string `json:"name,omitempty"`
	Kid  string `json:"kid,omitempty"`
	// armed, off_pending: the uptime at which the ticket was accepted, and the ticket's wait and notice.
	ArmedUpMS int64 `json:"armed_up_ms,omitempty"`
	WaitS     int   `json:"wait_s,omitempty"`
	NoticeS   int   `json:"notice_s,omitempty"`
	// off_pending: the uptime at which the shutdown was scheduled.
	OffUpMS int64 `json:"off_up_ms,omitempty"`
	// confirmed: the uptime at which the confirmation was accepted, what it named, and what is left of it.
	GoUpMS         int64  `json:"go_up_ms,omitempty"`
	WithinS        int    `json:"within_s,omitempty"`
	To             string `json:"to,omitempty"`
	ShutdownDelayS int    `json:"shutdown_delay_s,omitempty"`
	Update         int    `json:"update,omitempty"`   // updates still let through: 1 or 0
	Shutdown       int    `json:"shutdown,omitempty"` // shutdowns still let through: 1 or 0
}

// runFile is the run record.
type runFile struct {
	Version int `json:"version"` // 1
	// At: when, and in which boot, the checker wrote this file last. The live run counts only in that boot.
	At bootRef `json:"at"`
	// Arm: when the last ticket was accepted, or a run was cancelled: no ticket is accepted again in that boot.
	Arm  *bootRef `json:"arm,omitempty"`
	Used []string `json:"used,omitempty"` // ids of the runs accepted here, oldest first, at most runUsedMax
	Last *runLast `json:"last,omitempty"`
	Run  *runLive `json:"run,omitempty"`
	// Clock is the latest time this machine's clock showed when the checker looked (Unix seconds; 0: not known).
	// No ticket is taken while the clock is more than RunClockBack behind it (Gate.runClockKeep says when it is
	// written, and when it follows a clock that was put right backwards).
	Clock int64 `json:"clock,omitempty"`
}

func (r bootRef) valid() bool {
	return len(r.BootID) <= 128 && r.Wall > 0 && r.Wall < 1e11 && r.UpMS >= 0 && r.UpMS < 1e14
}

// validate says whether a record read from disk can be believed: every value is one this program writes.
func (f *runFile) validate() error {
	no := errors.New("not a run record of this program")
	if f.Version != 1 || !f.At.valid() || (f.Arm != nil && !f.Arm.valid()) || len(f.Used) > runUsedMax || f.Clock < 0 || f.Clock >= 1e11 {
		return no
	}
	for _, id := range f.Used {
		if api.CheckRunID(id) != nil {
			return no
		}
	}
	if l := f.Last; l != nil && (api.CheckRunID(l.ID) != nil || (l.State != api.RunCancelled && l.State != api.RunDone)) {
		return no
	}
	r := f.Run
	if r == nil {
		return nil
	}
	if len(r.Sub) > 255 || len(r.Name) > 64 || len(r.Kid) > 128 || r.ArmedUpMS < 0 || r.OffUpMS < 0 || r.GoUpMS < 0 {
		return no
	}
	valid := api.RunValidMinS
	switch r.State {
	case api.RunArmed, api.RunOffPending:
		// the ticket's numbers must be ones a ticket can have, and nothing of a confirmation is in it
		if _, err := (api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &r.ID, ValidS: &valid, WaitS: &r.WaitS, NoticeS: &r.NoticeS}).Canonical(); err != nil {
			return no
		}
		if r.GoUpMS != 0 || r.WithinS != 0 || r.To != "" || r.ShutdownDelayS != 0 || r.Update != 0 || r.Shutdown != 0 {
			return no
		}
		if (r.State == api.RunArmed) != (r.OffUpMS == 0) || (r.OffUpMS != 0 && r.OffUpMS < r.ArmedUpMS) {
			return no
		}
	case api.RunConfirmed:
		if _, err := (api.ApprovalRequest{Verb: api.ApproveRunGo, Run: &r.ID, To: &r.To, ShutdownDelayS: &r.ShutdownDelayS, WithinS: &r.WithinS}).Canonical(); err != nil {
			return no
		}
		if r.ArmedUpMS != 0 || r.WaitS != 0 || r.NoticeS != 0 || r.OffUpMS != 0 {
			return no
		}
		if r.Update < 0 || r.Update > 1 || r.Shutdown < 0 || r.Shutdown > 1 || (r.Update == 1 && r.To == api.RunNoUpdate) {
			return no
		}
	default:
		return no
	}
	return nil
}

func (f Files) runPath() string { return filepath.Join(filepath.Dir(f.Path), RunFileName) }

// readRun reads the run record with the checks the trust file gets: the folder (CheckDir), a plain file and
// not a link, its owner and who can write it (CheckFile), at most maxRunFile bytes, strict JSON, every value
// checked. exists is false when there is no file (or no folder). An error means the file is there and cannot
// be believed; the caller then keeps no live run and accepts nothing new.
func (f Files) readRun() (rec *runFile, sum [32]byte, exists bool, err error) {
	path := f.runPath()
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, sum, false, nil
	}
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return nil, sum, true, fmt.Errorf("the folder of the run record is not safe: %w", err)
		}
	}
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, sum, false, nil
	}
	if err != nil {
		return nil, sum, true, err
	}
	if !st.Mode().IsRegular() {
		return nil, sum, true, fmt.Errorf("%s is not a plain file", path)
	}
	if f.CheckFile != nil {
		if err := f.CheckFile(path); err != nil {
			return nil, sum, true, fmt.Errorf("the run record is not safe: %w", err)
		}
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, sum, true, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxRunFile+1))
	if err != nil {
		return nil, sum, true, err
	}
	if len(b) > maxRunFile {
		return nil, sum, true, fmt.Errorf("%s is larger than %d bytes", path, maxRunFile)
	}
	var r runFile
	if err := decodeStrict(b, &r); err != nil {
		return nil, sum, true, fmt.Errorf("%s is not readable as a run record (%s)", path, err.Error())
	}
	if err := r.validate(); err != nil {
		return nil, sum, true, fmt.Errorf("%s: %w", path, err)
	}
	return &r, sha256.Sum256(b), true, nil
}

// writeRun writes the run record: the complete content goes into a temporary file in the same (checked)
// folder, is synced, and takes the record's name in one step, replacing what is there (a link under that name
// is replaced, never followed). It returns the hash of what was written.
func (f Files) writeRun(rec *runFile) (sum [32]byte, err error) {
	path := f.runPath()
	dir := filepath.Dir(path)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return sum, fmt.Errorf("the folder of the run record does not exist: %s", dir)
	}
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return sum, fmt.Errorf("the folder of the run record is not safe: %w", err)
		}
	}
	if len(rec.Used) > runUsedMax {
		rec.Used = slices.Clone(rec.Used[len(rec.Used)-runUsedMax:])
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return sum, err
	}
	b = append(b, '\n')
	if len(b) > maxRunFile || rec.validate() != nil { // cannot happen: nothing is written that would not be read back
		return sum, errors.New("the run record would not read back")
	}
	tmp, err := os.CreateTemp(dir, runTempPattern)
	if err != nil {
		return sum, err
	}
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && f.Prepare != nil {
		err = f.Prepare(tmp.Name())
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name())
		return sum, err
	}
	syncDir(dir)
	return sha256.Sum256(b), nil
}

// removeRun deletes the run record (the administrator's command, for a record that cannot be read).
func (f Files) removeRun() error {
	dir := filepath.Dir(f.runPath())
	if f.CheckDir != nil {
		if err := f.CheckDir(dir); err != nil {
			return fmt.Errorf("the folder of the run record is not safe: %w", err)
		}
	}
	if err := os.Remove(f.runPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(dir)
	return nil
}

// RunView is the run record as `fairy-agent helper-run` shows it.
type RunView struct {
	Path   string
	Exists bool
	// Err: the file is there and cannot be used (nothing is armed or let through because of it, and no new
	// ticket is accepted until it is removed).
	Err error
	// The live run ("" ID: none).
	ID, State, Name, To      string
	UpMS                     int64 // armed: the uptime at which the self-off begins; off_pending: at which it happens; confirmed: until which it is good
	Update, Shutdown         int
	LastID, LastState        string
	WrittenWall, WrittenUpMS int64
	// Clock: the latest time this machine's clock showed when the checker looked (Unix seconds; 0: not known).
	Clock int64
}

func (f Files) runView(rec *runFile) RunView {
	v := RunView{Path: f.runPath(), Exists: rec != nil}
	if rec == nil {
		return v
	}
	v.WrittenWall, v.WrittenUpMS, v.Clock = rec.At.Wall, rec.At.UpMS, rec.Clock
	if l := rec.Last; l != nil {
		v.LastID, v.LastState = l.ID, l.State
	}
	if r := rec.Run; r != nil {
		v.ID, v.State, v.Name, v.To, v.Update, v.Shutdown = r.ID, r.State, r.Name, r.To, r.Update, r.Shutdown
		switch r.State {
		case api.RunArmed:
			v.UpMS = r.ArmedUpMS + int64(r.WaitS)*1000
		case api.RunOffPending:
			v.UpMS = r.OffUpMS + int64(r.NoticeS)*1000
		case api.RunConfirmed:
			v.UpMS = r.GoUpMS + int64(r.WithinS)*1000
		}
	}
	return v
}

// RunShow reads the run record for `fairy-agent helper-run show`.
func (f Files) RunShow() RunView {
	rec, _, exists, err := f.readRun()
	v := f.runView(rec)
	v.Exists, v.Err = exists, err
	return v
}

// RunCancel is `fairy-agent helper-run cancel`, on the machine, by an administrator: it takes the live run out
// of the record, so the machine does not switch itself off and lets nothing of the run through any more. The
// mark stays (the run is on record as cancelled), so no ticket arms the machine again in this boot. The
// service looks at the record every second while a run is live and stops a countdown that is already running.
// It never creates a record: with no file, or no live run in it, it changes nothing. A record that cannot be
// read is removed (nothing was armed because of it; what it remembered of earlier runs is lost).
// It returns what the record held before, and whether it was changed.
func (f Files) RunCancel() (was RunView, changed bool, err error) {
	rec, _, exists, rerr := f.readRun()
	was = f.runView(rec)
	was.Exists, was.Err = exists, rerr
	if rerr != nil {
		if err := f.removeRun(); err != nil {
			return was, false, err
		}
		return was, true, nil
	}
	if rec == nil || rec.Run == nil {
		return was, false, nil
	}
	rec.Last, rec.Run = &runLast{ID: rec.Run.ID, State: api.RunCancelled}, nil
	if _, err := f.writeRun(rec); err != nil {
		return was, false, err
	}
	return was, true, nil
}
