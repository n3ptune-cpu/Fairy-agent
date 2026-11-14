package approval

import (
	"encoding/json"

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
	MaxRunFile  = maxRunFile
	RunUsedMax  = runUsedMax
	RunOffGrace = runOffGrace
	BootSlack   = bootSlack
)
