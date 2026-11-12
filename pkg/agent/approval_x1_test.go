package agent_test

// Audit 5, r1-x1-01: an approval was bound to (challenge, request text) and not to the machine. This file is the
// auditor's attack (audit5/r1-x1/poc, TestR1X1Binding_ApprovalNotBoundToMachine, which runs in the panel's
// tree) rebuilt at the agent level, with the test playing the honest panel and the hostile machine:
//
//   - pc-a and pc-b are two agents with the check on: the same Pocket ID, the same client, the same approver.
//   - The attacker holds pc-a's control token and controls what pc-b answers (a hostile agent, or somebody on
//     the plain-HTTP path between the panel and pc-b).
//   - The admin, at the panel, shuts down pc-b. The panel asks "pc-b" for a challenge; what comes back is a
//     challenge the attacker fetched from pc-a for the same request text. The panel cannot tell: a challenge
//     is 32 random bytes.
//   - The admin confirms "shut down pc-b" with a passkey. The panel sends the approved request to "pc-b"; the
//     attacker forwards it to pc-a with pc-a's control token.
//
// Before the fix pc-a's own verifier accepted it and pc-a was switched off. Now every entry of an approval
// names the machine it is for, the panel writes the id it has on record for the machine it MEANS (pc-b's), and
// pc-a makes the nonce with its own id: the token does not fit.
//
// The file touches the approval API only through x1Entry, x1Init and x1ID (approval_x1_helpers_test.go), so
// the same file, with those three written for the old API, runs against the tree from before the fix and shows
// the attack working there (reports/audit5-agent-fix-x1-logs).

import (
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// x1m is one machine as the panel and the attacker reach it: its control API, and what it would have done.
type x1m struct {
	name  string
	post  func(t *testing.T, path string, body any) (int, map[string]any) // with the machine's control token
	power *agenttest.PowerExec
	iss   *approvaltest.Issuer
	base  string
	log   func() string
	id    string // what the panel has on record for it (x1ID, read when the trust was set)
}

func x1Linux(t *testing.T, name string) *x1m {
	t.Helper()
	r := newLinuxRig(t, true)
	return &x1m{name: name, post: r.post, power: r.power, iss: r.iss, base: r.base, log: r.log.String}
}

// x1TurnOn sets the trust of m the way the panel does ("Turn on"), proposing the machine id want ("": the
// machine makes one up), and takes the machine's id on record.
func x1TurnOn(t *testing.T, m *x1m, want string) {
	t.Helper()
	if st, b := m.post(t, api.PathApprovalTrust, provenTrust(t, m.base, m.iss, x1Init(m.iss, want))); st != 200 {
		t.Fatalf("%s: first-time set: %d %v", m.name, st, b)
	}
	m.id = x1ID(t, m)
}

// x1Launder is the attack: the admin approves req on b, the attacker gets a's challenge approved in its place
// and hands the approved request to a. rewrite, when set, is what the attacker does to the approval before he
// forwards it. It returns a's answer.
func x1Launder(t *testing.T, a, b *x1m, path string, req, body map[string]any, rewrite func(*api.Approval)) (int, map[string]any) {
	t.Helper()
	// the panel asks pc-b for a challenge; the attacker answers with one of pc-a's, for the same request
	st, c := a.post(t, api.PathApprovalChallenge, req)
	if st != 200 || c["needed"] != true {
		t.Fatalf("the attacker's challenge request to %s: %d %v", a.name, st, c)
	}
	// the panel builds the entry for the machine it means, pc-b, and the admin confirms with a passkey
	ap := b.iss.Approve(time.Now(), x1Entry(b.id, c["challenge"].(string), c["request"].(string)))
	t.Logf("the admin approved %q for %s (machine id on record: %q); the challenge in it is %s's", c["request"], b.name, b.id, a.name)
	if rewrite != nil {
		rewrite(ap)
	}
	// the panel sends the approved request to pc-b; the attacker forwards it to pc-a with pc-a's control token
	out := map[string]any{"approval": ap}
	for k, v := range body {
		out[k] = v
	}
	return a.post(t, path, out)
}

// TestApprovalForOneMachineIsRefusedByAnother is the attack, on a shutdown. On the tree from before the fix
// this test fails at "THE ATTACK WORKS": pc-a schedules its shutdown.
func TestApprovalForOneMachineIsRefusedByAnother(t *testing.T) {
	a, b := x1Linux(t, "pc-a"), x1Linux(t, "pc-b")
	x1TurnOn(t, a, "")
	x1TurnOn(t, b, "")
	t.Logf("pc-a: machine id %q; pc-b: machine id %q (same issuer %s, same client, same approver)", a.id, b.id, a.iss.URL)

	shutdown := map[string]any{"action": "shutdown", "delay_s": 60}
	if st, out := a.post(t, "/power", shutdown); st != 403 || out["code"] != api.CodeApprovalRequired {
		t.Fatalf("baseline: pc-a must refuse a shutdown with its control token and no approval: %d %v", st, out)
	}
	req := map[string]any{"verb": api.ApprovePower, "action": "shutdown", "delay_s": 60}
	st, out := x1Launder(t, a, b, "/power", req, shutdown, nil)
	t.Logf("pc-a answered the forwarded request: %d %v", st, out)
	t.Logf("scheduled on pc-a: %v  scheduled on pc-b: %v", a.power.Scheduled, b.power.Scheduled)
	if st == 200 || len(a.power.Scheduled) != 0 {
		t.Fatalf("THE ATTACK WORKS: an approval the admin gave for pc-b was accepted by pc-a, and pc-a is switched off (%d %v, scheduled on pc-a: %v)",
			st, out, a.power.Scheduled)
	}
	msg, _ := out["error"].(string)
	if st != 403 || out["code"] != api.CodeApprovalRefused || !strings.HasPrefix(msg, "approval refused (") {
		t.Fatalf("pc-a refused, but not as an approval that does not fit: %d %v", st, out)
	}
	if len(b.power.Scheduled) != 0 {
		t.Fatalf("pc-b: %v", b.power.Scheduled)
	}
	t.Log("refused: the approval for pc-b does not fit pc-a")
}
