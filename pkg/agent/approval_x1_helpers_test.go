package agent_test

// The three places where the attack of approval_x1_test.go touches the approval API. For the run against the
// tree from before the fix they are written for the old API (no machine id anywhere); see
// reports/audit5-agent-fix-x1-logs/old-tree-helpers.go.txt.

import (
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// x1Entry is the entry the panel builds for the machine with the id machineID on record.
func x1Entry(machineID, challenge, request string) api.MachineEntry {
	return api.MachineEntry{MachineID: machineID, Challenge: challenge, Request: request}
}

// x1Init is the trust the panel proposes, with the machine id want ("": the machine makes one up).
func x1Init(iss *approvaltest.Issuer, want string) api.TrustInit {
	in := iss.Init()
	in.MachineID = want
	return in
}

// x1ID is the machine id m shows in its "approval" block.
func x1ID(t *testing.T, m *x1m) string {
	t.Helper()
	_, metrics := do(t, m.base, "GET", "/metrics", readTok, nil)
	ap, _ := metrics["approval"].(map[string]any)
	id, _ := ap["machine_id"].(string)
	if ap["state"] != api.ApprovalRequired || api.CheckMachineID(id) != nil {
		t.Fatalf("%s: approval block %v", m.name, ap)
	}
	return id
}
