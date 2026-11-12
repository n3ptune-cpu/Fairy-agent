package approval

import "github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"

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
