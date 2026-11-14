package approval

import (
	"encoding/json"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Check is Admit for the tests of this package that ask the gate one question after another: a request that is
// let through counts as carried out and applied at once (so an accepted approval of a fan change opens the fan
// window, as it does when the fan controller answers 200). The tests of the difference use Admit itself.
func (g *Gate) Check(req api.ApprovalRequest, ap *api.Approval) *Refusal {
	pass, ref := g.Admit(req, ap)
	if ref == nil {
		pass.Applied()
	}
	return ref
}

// FoldName is foldName, for the test that holds it against encoding/json.
func FoldName(s string) string { return foldName(s) }

// RunPath is the run record's path.
func (f Files) RunPath() string { return f.runPath() }

// RunRecordCheck reads the run record as the gate does and says whether it is there and can be used.
func (f Files) RunRecordCheck() (exists bool, err error) {
	_, _, exists, err = f.readRun()
	return exists, err
}

// RunRecordTouched reports whether the run record holds anything a ticket, a confirmation or a cancel leaves in
// this boot: a live run, the id of a run, how a run ended, or the mark that closes the boot bootID for tickets.
// The record itself is there on every machine with trust (the checker keeps the clock in it).
func (f Files) RunRecordTouched(bootID string) bool {
	rec, _, exists, err := f.readRun()
	if !exists || err != nil || rec == nil {
		return false
	}
	return rec.Run != nil || len(rec.Used) > 0 || rec.Last != nil || (rec.Arm != nil && rec.Arm.BootID == bootID)
}

// RunClockSeen is the record's "clock" (0: no record, or none in it).
func (f Files) RunClockSeen() int64 {
	rec, _, _, err := f.readRun()
	if err != nil || rec == nil {
		return 0
	}
	return rec.Clock
}

// RunRoundTrip reads b as a run record and, when it is one, writes it out again the way the gate does.
func RunRoundTrip(b []byte) ([]byte, error) {
	var r runFile
	if err := decodeStrict(b, &r); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(&r)
}

// The limits of the run record, for the tests of the file.
const (
	MaxRunFile    = maxRunFile
	RunUsedMax    = runUsedMax
	RunOffGrace   = runOffGrace
	BootSlack     = bootSlack
	RunClockEvery = runClockEvery
)

// SetRunCancelSettle sets how long RunCancel waits before it looks at the record again, and returns the old value.
func SetRunCancelSettle(d time.Duration) time.Duration {
	old := runCancelSettle
	runCancelSettle = d
	return old
}
