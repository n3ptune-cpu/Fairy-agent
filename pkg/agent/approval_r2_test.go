package agent_test

// Audit 5, round 2: regression tests built from the auditors' proofs (audit5/r2-a1/poc), over the agent's real
// HTTP handler.

import (
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// badUpdateApproval is one approval that no machine accepts for an update, and the reason word of the refusal.
type badUpdateApproval struct {
	name   string
	ap     *api.Approval
	reason string
	// onlyTheCheckerKnows: the approval is wrong only in its challenge (one nobody gave), which the program
	// that gave the challenges can tell and no other.
	onlyTheCheckerKnows bool
}

// badUpdateApprovals are approvals for POST /update that must be refused, made against a machine whose trust
// is iss. ask gets an open challenge for req from that machine.
func badUpdateApprovals(iss *approvaltest.Issuer, ask func(req map[string]any) api.MachineEntry) []badUpdateApproval {
	update := map[string]any{"verb": "apply_update"}
	now := time.Now()
	madeUp := api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: "apply_update"}
	stranger, nobody := *iss, *iss
	stranger.Key = approvaltest.Key(1)
	nobody.Sub = "99999999-0000-4000-8000-000000000000"
	claims := func(e api.MachineEntry, k string, v any) *api.Approval {
		n, _ := api.ApprovalNonce([]api.MachineEntry{e})
		c := iss.Claims(n, now)
		c[k] = v
		return &api.Approval{Token: iss.Token(c), Entries: []api.MachineEntry{e}}
	}
	elsewhere := ask(update)
	elsewhere.MachineID = "another-machine-AAAAAAAAAAAA"
	return []badUpdateApproval{
		{name: "a token that is none, no entries (the auditor's)", ap: &api.Approval{Token: "x", Entries: []api.MachineEntry{}}, reason: approval.ReasonEntries},
		{name: "a token that is none, a made-up challenge", ap: &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{madeUp}}, reason: approval.ReasonFormat, onlyTheCheckerKnows: true},
		{name: "a token that is none, a real challenge", ap: &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{ask(update)}}, reason: approval.ReasonFormat},
		{name: "signed with a key that is not pinned", ap: stranger.Approve(now, ask(update)), reason: approval.ReasonSignature},
		{name: "approved by a user who may not", ap: nobody.Approve(now, ask(update)), reason: approval.ReasonUser},
		{name: "made for another machine's id", ap: iss.Approve(now, elsewhere), reason: approval.ReasonNonce},
		{name: "an approval of a reboot", ap: iss.Approve(now, ask(map[string]any{"verb": "power", "action": "reboot", "delay_s": 60})), reason: approval.ReasonNoChallenge},
		{name: "a token that has expired", ap: claims(ask(update), "exp", now.Add(-2*time.Minute).Unix()), reason: approval.ReasonTokenExp},
		{name: "a sign-in with a password", ap: claims(ask(update), "amr", []string{"pwd"}), reason: approval.ReasonAMR},
		{name: "a passkey check from an hour ago", ap: claims(ask(update), "auth_time", now.Add(-time.Hour).Unix()), reason: approval.ReasonAuthTime},
	}
}

// TestMadeUpUpdateApprovalDownloadsNothing (audit 5, r2-a1-03): on Windows the helper checks the approval of an
// update when the installer is to be started, after the agent has downloaded and staged the release. So with
// trust set, any "approval" member made the agent download: whoever held the control token and no approval
// could have the release fetched again and again, and the owner's approved update was answered 409 meanwhile.
// The agent now looks at the approval itself first (approval.Gate.Preverify, with its own read-only look at
// the helper's trust file) and uses nothing up: what is certain to be refused is refused at once, with the
// answer a Linux agent gives at that point, and nothing is downloaded. The helper still decides.
func TestMadeUpUpdateApprovalDownloadsNothing(t *testing.T) {
	const asset = "fairy-agent-linux-amd64"
	r := newApprovalRig(t)
	r.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{asset: []byte(strings.Repeat("release bytes ", 4096))}, nil)
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	r.approvalBlock(t, api.ApprovalRequired)
	wait := func() agent.UpdateStatus {
		t.Helper()
		for i := 0; i < 1000; i++ {
			if st := r.upd.Status(); st.State != "downloading" && st.State != "applying" {
				return st
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("the update did not finish")
		return agent.UpdateStatus{}
	}
	ask := func(req map[string]any) api.MachineEntry {
		t.Helper()
		st, c := r.post(t, api.PathApprovalChallenge, req)
		if st != 200 || c["needed"] != true {
			t.Fatalf("challenge for %v: %d %v", req, st, c)
		}
		return api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c["challenge"].(string), Request: c["request"].(string)}
	}
	// the same on a Linux agent, which checks when the request arrives: what it answers is what is wanted here
	lin := newLinuxRig(t, true)
	lin.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{asset: []byte("build 42")}, nil)
	if st, b := lin.post(t, api.PathApprovalTrust, provenTrust(t, lin.base, lin.iss, lin.iss.Init())); st != 200 {
		t.Fatalf("first-time set on the Linux agent: %d %v", st, b)
	}
	askLinux := func(req map[string]any) api.MachineEntry {
		t.Helper()
		st, c := lin.post(t, api.PathApprovalChallenge, req)
		if st != 200 || c["needed"] != true {
			t.Fatalf("challenge on the Linux agent for %v: %d %v", req, st, c)
		}
		return api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c["challenge"].(string), Request: c["request"].(string)}
	}
	onLinux := badUpdateApprovals(lin.iss, askLinux)

	for i, c := range badUpdateApprovals(r.iss, ask) {
		st, b := r.post(t, "/update", map[string]any{"requested_by": "thief", "approval": c.ap})
		text, _ := b["error"].(string)
		if st != 403 || b["code"] != api.CodeApprovalRefused || !strings.HasPrefix(text, "approval refused ("+c.reason+"): ") {
			t.Errorf("%s: %d %v, want 403 approval_refused (%s)", c.name, st, b, c.reason)
		}
		if us := r.upd.Status(); us.State == "downloading" || us.State == "applying" || us.State == "failed" {
			t.Errorf("%s: the updater took the request on: %+v", c.name, us)
		}
		if n := r.gh.Downloads(asset); n != 0 {
			t.Fatalf("%s: the release was downloaded (%d times so far)", c.name, n)
		}
		// the Linux agent, asked the same
		lst, lb := lin.post(t, "/update", map[string]any{"requested_by": "thief", "approval": onLinux[i].ap})
		switch {
		case c.onlyTheCheckerKnows:
			if lst != 403 || lb["code"] != api.CodeApprovalRefused || !strings.HasPrefix(lb["error"].(string), "approval refused ("+approval.ReasonNoChallenge+"): ") {
				t.Errorf("%s, on Linux: %d %v", c.name, lst, lb)
			}
		case lst != st || lb["code"] != b["code"] || lb["error"] != b["error"] || len(lb) != len(b):
			t.Errorf("%s: this agent answers %d %v, a Linux agent %d %v", c.name, st, b, lst, lb)
		}
	}
	if n := lin.gh.Downloads(asset); n != 0 || lin.starts.Load() != 0 {
		t.Errorf("the Linux agent: %d downloads, %d installer starts", n, lin.starts.Load())
	}
	if r.helperStarts.Load() != 0 || r.ownStarts.Load() != 0 {
		t.Fatalf("installer started: by the helper %d, with the agent's own right %d", r.helperStarts.Load(), r.ownStarts.Load())
	}
	// none of the refused requests is in the way of the owner's: a good approval is taken at once, the release
	// is downloaded once and the helper starts the installer
	good := r.iss.Approve(time.Now(), ask(map[string]any{"verb": "apply_update"}))
	if st, b := r.post(t, "/update", map[string]any{"requested_by": "owner", "approval": good}); st != 202 || b["state"] != "downloading" {
		t.Fatalf("a good approval: %d %v", st, b)
	}
	// while it runs, another request is answered 409 before anything of its approval is looked at
	if st, b := r.post(t, "/update", map[string]any{"approval": map[string]any{"token": "x", "entries": []any{}}}); st != 409 && r.upd.Status().State == "downloading" {
		t.Errorf("a second request during the owner's update: %d %v", st, b)
	}
	wait()
	if n := r.gh.Downloads(asset); n != 1 || r.helperStarts.Load() != 1 || r.ownStarts.Load() != 0 {
		t.Fatalf("a good approval: %d downloads, installer started by the helper %d times, with the agent's own right %d", n, r.helperStarts.Load(), r.ownStarts.Load())
	}
	// What is left of the finding, on purpose: the same good approval sent again. Its challenge is used up, which
	// only the helper knows. The agent's look passes it, the release is downloaded again, the helper refuses,
	// and what was staged is removed. That takes a real approval of an update on this machine by its owner,
	// not older than its challenge could be (15 minutes), instead of nothing at all.
	if st, b := r.post(t, "/update", map[string]any{"approval": good}); st != 202 {
		t.Fatalf("the same approval again: %d %v", st, b)
	}
	if us := wait(); us.State != "failed" || !strings.Contains(us.Message, "approval refused (no_challenge)") {
		t.Errorf("the same approval again: %+v", us)
	}
	if n := r.gh.Downloads(asset); n != 2 || r.helperStarts.Load() != 1 {
		t.Errorf("the same approval again: %d downloads, installer started by the helper %d times", n, r.helperStarts.Load())
	}
}

// TestUpdateApprovalWithoutTheAgentsOwnLook: where the agent cannot read the helper's trust file itself (its
// account cannot run the checks on the helper's folder), there is nothing to look with, and an update with an
// approval goes the way it went before: the release is staged and the helper decides.
func TestUpdateApprovalWithoutTheAgentsOwnLook(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperRunning, trust: true, blindOwnGate: true})
	r.block(t, api.ApprovalRequired)
	junk := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: "apply_update"}}}
	if st, b := r.post(t, "/update", map[string]any{"approval": junk}); st != 202 {
		t.Fatalf("update with a made-up approval: %d %v", st, b)
	}
	if st := r.waitUpdate(t); st.State != "failed" || !strings.Contains(st.Message, "approval refused") {
		t.Fatalf("made-up approval: %+v", st)
	}
	ok := r.approve(t, map[string]any{"verb": "apply_update"})
	if st, b := r.post(t, "/update", map[string]any{"approval": ok}); st != 202 {
		t.Fatalf("approved update: %d %v", st, b)
	}
	r.waitUpdate(t)
	if r.helperStarts.Load() != 1 || r.ownStarts.Load() != 0 {
		t.Errorf("approved update: own %d, helper %d", r.ownStarts.Load(), r.helperStarts.Load())
	}
}
