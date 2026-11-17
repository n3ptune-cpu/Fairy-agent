package approval_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// The rules of uninstall, the second request that is never carried out without a passkey approval (strict.go).
// A program on the machine can take the control token (AGENT.md, "Security in short"); these tests hold that
// the token alone, in any combination with windows, runs, other approvals or another machine's, removes nothing.

var uninstall = api.ApprovalRequest{Verb: api.ApproveUninstall}

// Its text is the verb and nothing else, and it takes no member at all.
func TestUninstallCanonical(t *testing.T) {
	if s, err := uninstall.Canonical(); err != nil || s != "uninstall" {
		t.Fatalf("canonical: %q, %v", s, err)
	}
	one, word := 1, "x"
	for what, req := range map[string]api.ApprovalRequest{
		"zone":   {Verb: api.ApproveUninstall, Zone: &one},
		"action": {Verb: api.ApproveUninstall, Action: &word},
		"run":    {Verb: api.ApproveUninstall, Run: &word},
		"to":     {Verb: api.ApproveUninstall, To: &word},
		"source": {Verb: api.ApproveUninstall, Source: &word},
	} {
		if s, err := req.Canonical(); err == nil {
			t.Errorf("uninstall with %s has the canonical form %q", what, s)
		}
	}
	for _, v := range []string{"Uninstall", "uninstall ", "uninstall_agent", "remove"} {
		if s, err := (api.ApprovalRequest{Verb: v}).Canonical(); err == nil {
			t.Errorf("verb %q has the canonical form %q", v, s)
		}
	}
}

// No trust file: refused, 409 approval_off, from every question, with or without an approval, and on a nil
// gate. No challenge is given. Fans, power and updates on the same machine still run as they always did.
func TestUninstallIsRefusedWithoutATrustFile(t *testing.T) {
	r := newRig(t, false)
	madeUp := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: approvaltest.MachineID,
		Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Request: "uninstall"}}}
	isOff := func(what string, ref *approval.Refusal) {
		t.Helper()
		if ref == nil || ref.Status != 409 || ref.Code != api.CodeApprovalOff {
			t.Errorf("%s on a machine without a trust file: %v, want 409 %s", what, ref, api.CodeApprovalOff)
		}
	}
	c, ref := r.g.Challenge(uninstall)
	isOff("challenge", ref)
	if c.Needed || c.Challenge != "" || c.Reason != "" {
		t.Errorf("the answer to a refused challenge request says %+v", c)
	}
	isOff("first look, nothing sent", r.g.Precheck(uninstall, false))
	isOff("first look, something sent", r.g.Precheck(uninstall, true))
	isOff("look without an approval", r.g.Look(uninstall, nil))
	isOff("look with an approval", r.g.Look(uninstall, madeUp))
	_, ref = r.g.Admit(uninstall, nil)
	isOff("without an approval", ref)
	_, ref = r.g.Admit(uninstall, madeUp)
	isOff("with a made-up approval", ref)
	_, ref = r.g.RunCovers(uninstall, "0123456789abcdef")
	isOff("in the name of a run", ref)
	_, ref = r.g.AdmitRun(uninstall, "0123456789abcdef")
	isOff("in the name of a run, carried out", ref)

	var none *approval.Gate
	isOff("no gate, first look", none.Precheck(uninstall, true))
	isOff("no gate, look", none.Look(uninstall, madeUp))
	_, ref = none.Admit(uninstall, nil)
	isOff("no gate", ref)
	_, ref = none.RunCovers(uninstall, "0123456789abcdef")
	isOff("no gate, a run", ref)
	_, ref = none.AdmitRun(uninstall, "0123456789abcdef")
	isOff("no gate, a run carried out", ref)

	for _, req := range []api.ApprovalRequest{power("shutdown", 60), fanSet(0, 50), update} {
		if _, ref := r.g.Admit(req, nil); ref != nil {
			t.Errorf("%s without a trust file: %v", req.Verb, ref)
		}
	}
	if n := strings.Count(r.log.String(), "challenge issued"); n != 0 {
		t.Errorf("%d challenges were given on a machine without a trust file", n)
	}
}

// With trust: nothing sent is refused; a good approval is accepted once; the same one again is refused, and so
// is the request right after an accepted one.
func TestUninstallNeedsItsOwnApprovalEveryTime(t *testing.T) {
	r := newRig(t, true)
	refused(t, "first look, none sent", r.g.Precheck(uninstall, false), api.CodeApprovalRequired, "")
	_, ref := r.g.Admit(uninstall, nil)
	refused(t, "none sent", ref, api.CodeApprovalRequired, "")

	c, ref := r.g.Challenge(uninstall)
	if ref != nil || !c.Needed || c.Request != "uninstall" || c.ExpiresInS != int(approval.ChallengeTTL/time.Second) {
		t.Fatalf("challenge: %+v, %v", c, ref)
	}
	ap := r.iss.Approve(r.Now(), approvaltest.Entry(approvaltest.MachineID, c))
	pass, ref := r.g.Admit(uninstall, ap)
	accepted(t, "a good approval", ref)
	if pass != nil {
		t.Error("an accepted uninstall gave a pass: only a fan change opens a window")
	}
	_, ref = r.g.Admit(uninstall, ap)
	refused(t, "the same approval a second time (replay)", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	_, ref = r.g.Admit(uninstall, nil)
	refused(t, "right after an accepted one, none sent", ref, api.CodeApprovalRequired, "")
}

// The challenge lives ChallengeTTL; an approval that comes later is refused.
func TestUninstallChallengeExpires(t *testing.T) {
	r := newRig(t, true)
	ap := r.approve(uninstall)
	r.wait(approval.ChallengeTTL)
	_, ref := r.g.Admit(uninstall, ap)
	refused(t, "after the challenge's time", ref, api.CodeApprovalRefused, approval.ReasonExpired)
}

// One passkey touch is one uninstall of one machine: an approval whose list holds more (other machines, or a
// shutdown of this one that the person did mean to approve) removes nothing and uses nothing up.
func TestUninstallTakesAnApprovalOfOneEntryOnly(t *testing.T) {
	r := newRig(t, true)
	e := r.entry(uninstall)
	other := api.MachineEntry{MachineID: "another-machine-BBBBBBBBBB", Challenge: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		Request: "uninstall"}
	shut := power("shutdown", 60)
	eShut := r.entry(shut)
	for what, ap := range map[string]*api.Approval{
		"with another machine's uninstall": r.iss.Approve(r.Now(), e, other),
		"with a shutdown of this machine":  r.iss.Approve(r.Now(), eShut, e),
	} {
		refused(t, what+", looked at", r.g.Look(uninstall, ap), api.CodeApprovalRefused, approval.ReasonOneEntry)
		_, ref := r.g.Admit(uninstall, ap)
		refused(t, what, ref, api.CodeApprovalRefused, approval.ReasonOneEntry)
	}
	if !r.stillOpen(uninstall, e) {
		t.Fatal("an approval of two entries used the uninstall's challenge up")
	}
	_, ref := r.g.Admit(uninstall, r.iss.Approve(r.Now(), e))
	accepted(t, "the uninstall alone", ref)
}

// An approval is for exactly the text it was asked for: an uninstall's approval does nothing else, and no other
// request's approval uninstalls.
func TestUninstallApprovalIsForUninstallOnly(t *testing.T) {
	r := newRig(t, true)
	e := r.entry(uninstall)
	ap := r.iss.Approve(r.Now(), e)
	for what, req := range map[string]api.ApprovalRequest{
		"a shutdown": power("shutdown", 60), "a fan change": fanMode("full"), "an update": update,
	} {
		if _, ref := r.g.Admit(req, ap); ref == nil {
			t.Fatalf("%s was accepted with the approval of an uninstall", what)
		}
	}
	for what, req := range map[string]api.ApprovalRequest{
		"a shutdown's": power("shutdown", 60), "an update's": update, "a fan change's": fanSet(0, 50),
	} {
		if _, ref := r.g.Admit(uninstall, r.approve(req)); ref == nil {
			t.Fatalf("an uninstall was accepted with %s approval", what)
		}
	}
	if !r.stillOpen(uninstall, e) {
		t.Fatal("a wrong use of the approval used its challenge up")
	}
	_, ref := r.g.Admit(uninstall, ap)
	accepted(t, "the uninstall it was asked for", ref)
}

// Nothing stands in for the approval: not the fan window, not a run.
func TestUninstallHasNoWindow(t *testing.T) {
	r := newRig(t, true)
	fan := fanSet(0, 50)
	accepted(t, "an approved fan change", r.g.Check(fan, r.approve(fan)))
	accepted(t, "a second fan change inside the window", r.g.Check(fanSet(0, 60), nil))
	refused(t, "inside the fan window, first look", r.g.Precheck(uninstall, false), api.CodeApprovalRequired, "")
	_, ref := r.g.Admit(uninstall, nil)
	refused(t, "inside the fan window", ref, api.CodeApprovalRequired, "")
	_, ref = r.g.RunCovers(uninstall, "0123456789abcdef")
	refused(t, "in the name of a run", ref, api.CodeApprovalRequired, "")
	_, ref = r.g.AdmitRun(uninstall, "0123456789abcdef")
	refused(t, "in the name of a run, carried out", ref, api.CodeApprovalRequired, "")
}

// An approval made for machine B, even with machine A's challenge in it, uninstalls nothing on A.
func TestUninstallIsBoundToTheMachine(t *testing.T) {
	a, b := newRigID(t, idA), newRigID(t, idB)
	ca, ref := a.g.Challenge(uninstall)
	if ref != nil {
		t.Fatal(ref)
	}
	forB := b.iss.Approve(a.Now(), approvaltest.Entry(idB, ca))
	_, ref = a.g.Admit(uninstall, forB)
	refused(t, "an approval for B with A's challenge, on A", ref, api.CodeApprovalRefused, approval.ReasonNonce)
	rewritten := &api.Approval{Token: forB.Token, Entries: []api.MachineEntry{approvaltest.Entry(idA, ca)}}
	_, ref = a.g.Admit(uninstall, rewritten)
	refused(t, "the same token with the entry rewritten to A's id", ref, api.CodeApprovalRefused, approval.ReasonNonce)
	_, ref = a.g.Admit(uninstall, a.iss.Approve(a.Now(), approvaltest.Entry(idA, ca)))
	accepted(t, "A's own approval", ref)
}
