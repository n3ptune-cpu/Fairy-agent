package approval_test

// Audit 5, round 1: the gate's part of the fixes.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// admitted checks that ref is nil and returns the pass.
func admitted(t *testing.T, what string, pass *approval.Pass, ref *approval.Refusal) *approval.Pass {
	t.Helper()
	if ref != nil {
		t.Fatalf("%s: refused: %v", what, ref)
	}
	return pass
}

func needsApproval(t *testing.T, what string, g *approval.Gate, req api.ApprovalRequest) {
	t.Helper()
	_, ref := g.Admit(req, nil)
	refused(t, what, ref, api.CodeApprovalRequired, "")
	if c, cref := g.Challenge(req); cref != nil || !c.Needed {
		t.Errorf("%s: the challenge says no approval is needed: %+v, %v", what, c, cref)
	}
}

// TestFanWindowOpensOnlyWhenTheChangeWasApplied (r1-a1-04, r1-a2-02): an accepted approval of a fan change used
// to open the 30 s fan window at once. A request the machine then refused (a duty under the minimum: 400), or
// that changed nothing (not in "full" mode: 409), left every other fan change unapproved for 30 s. The window
// now opens when the caller says the change was applied, and counts from the moment the approval was accepted.
func TestFanWindowOpensOnlyWhenTheChangeWasApplied(t *testing.T) {
	r := newRig(t, true)

	// accepted, then refused by the fan controller: the caller never calls Applied
	req := fanSet(0, 5)
	ap := r.approve(req)
	pass, ref := r.g.Admit(req, ap)
	if admitted(t, "approved fan_set", pass, ref) == nil {
		t.Fatal("an accepted approval of a fan change gave no pass")
	}
	needsApproval(t, "fan mode after an approved request that was not applied", r.g, fanMode("full"))
	needsApproval(t, "fan duty after an approved request that was not applied", r.g, fanSet(1, 30))
	_, ref = r.g.Admit(req, ap)
	refused(t, "the approval is used up all the same", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// accepted and applied: open, for fans only
	req = fanMode("full")
	pass, ref = r.g.Admit(req, r.approve(req))
	admitted(t, "approved fan_mode", pass, ref)
	needsApproval(t, "before Applied", r.g, fanSet(0, 60))
	r.wait(12 * time.Second) // the BMC took its time
	pass.Applied()
	if p, ref := r.g.Admit(fanSet(0, 60), nil); ref != nil || p != nil {
		t.Fatalf("fan change inside the window: pass %v, refusal %v", p, ref)
	}
	if c, cref := r.g.Challenge(fanSet(1, 70)); cref != nil || c.Needed || c.Reason != "fan_window" {
		t.Errorf("challenge in the window: %+v, %v", c, cref)
	}
	needsApproval(t, "shutdown in the fan window", r.g, power("shutdown", 60))
	if !strings.Contains(r.log.String(), "fan window open, the approved fan change was applied") {
		t.Errorf("the log does not say that the window was opened:\n%s", r.log.String())
	}
	// counted from the acceptance, not from Applied: 12 s are gone already
	r.wait(17 * time.Second)
	if _, ref := r.g.Admit(fanSet(0, 61), nil); ref != nil {
		t.Fatalf("29 s after the approval was accepted: %v", ref)
	}
	r.wait(time.Second)
	needsApproval(t, "30 s after the approval was accepted", r.g, fanSet(0, 62))
	// a second Applied of the same pass does not open it again
	pass.Applied()
	needsApproval(t, "Applied twice", r.g, fanSet(0, 62))

	// a change that passes inside the window gives no pass, so it cannot stretch the window
	req = fanMode("optimal")
	pass, ref = r.g.Admit(req, r.approve(req))
	admitted(t, "approved again", pass, ref).Applied()
	r.wait(20 * time.Second)
	p, ref := r.g.Admit(fanSet(0, 70), nil)
	admitted(t, "inside", p, ref).Applied() // nil pass: nothing happens
	r.wait(10 * time.Second)
	needsApproval(t, "the window was not stretched", r.g, fanSet(0, 71))

	// an approved shutdown or update gives no pass at all
	for _, q := range []api.ApprovalRequest{power("shutdown", 60), update} {
		if p, ref := r.g.Admit(q, r.approve(q)); ref != nil || p != nil {
			t.Errorf("%v: pass %v, refusal %v", q.Verb, p, ref)
		}
	}
	needsApproval(t, "fan after an approved shutdown", r.g, fanSet(0, 50))
}

// TestFanWindowNotOpenedUnderAChangedTrust: the approval was accepted under one trust file; when the change is
// reported as applied, the administrator has changed the file (another user list, the window switched off).
// What was given under the old file does not count under the new one.
func TestFanWindowNotOpenedUnderAChangedTrust(t *testing.T) {
	r := newRig(t, true)
	req := fanMode("full")
	pass, ref := r.g.Admit(req, r.approve(req))
	admitted(t, "approved", pass, ref)
	r.setLocal(func(tr *approval.Trust) { tr.Users = []string{"someone-else"} })
	r.g.Status() // the gate has seen the new file
	pass.Applied()
	needsApproval(t, "fan change after the trust changed", r.g, fanSet(0, 60))

	// fan_window_s 0: Applied opens nothing
	r2 := newRig(t, true)
	r2.setLocal(func(tr *approval.Trust) { tr.FanWindowS = ip(0) })
	pass, ref = r2.g.Admit(req, r2.approve(req))
	admitted(t, "approved, window off", pass, ref).Applied()
	needsApproval(t, "window off", r2.g, fanSet(0, 60))
}

// TestPrecheckUsesNothingUp (r1-a1-02, r1-a2-01): the question that is asked when a request arrives. It refuses
// what needs no look at an approval, and it leaves everything as it was: the challenge, the fan window, the
// one shutdown after boot. Only Admit, asked when the request is about to be carried out, uses them.
func TestPrecheckUsesNothingUp(t *testing.T) {
	var none *approval.Gate
	accepted(t, "no gate", none.Precheck(power("shutdown", 60), false))
	off := newRig(t, false)
	accepted(t, "off", off.g.Precheck(power("shutdown", 60), false))
	accepted(t, "off, approval sent", off.g.Precheck(fanSet(0, 50), true))
	hash := api.TrustHash(off.iss.Init())
	refused(t, "trust_set is not a request that runs", off.g.Precheck(api.ApprovalRequest{Verb: api.ApproveTrustSet, TrustHash: &hash}, true), "bad_request", "")

	r := newRig(t, true)
	req := power("shutdown", 60)
	refused(t, "none sent", r.g.Precheck(req, false), api.CodeApprovalRequired, "")
	refused(t, "no canonical form", r.g.Precheck(power("explode", 60), true), "bad_request", "")
	ap := r.approve(req)
	for i := 0; i < 5; i++ {
		accepted(t, "sent", r.g.Precheck(req, true))
	}
	// whatever is in the approval: Precheck does not look, Admit does
	accepted(t, "sent, for another request", r.g.Precheck(power("reboot", 60), true))
	_, ref := r.g.Admit(power("reboot", 60), ap)
	refused(t, "the approval of a shutdown for a reboot", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	_, ref = r.g.Admit(req, ap)
	accepted(t, "the challenge is still open after six prechecks and a refused Admit for another request", ref)
	_, ref = r.g.Admit(req, ap)
	refused(t, "single use", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// the fan window lets a fan request without approval through, here as in Admit
	fan := fanMode("full")
	pass, ref := r.g.Admit(fan, r.approve(fan))
	admitted(t, "approved fan change", pass, ref)
	refused(t, "fan, window not open yet", r.g.Precheck(fanSet(0, 50), false), api.CodeApprovalRequired, "")
	pass.Applied()
	accepted(t, "fan, inside the window", r.g.Precheck(fanSet(0, 50), false))
	refused(t, "shutdown, inside the fan window", r.g.Precheck(req, false), api.CodeApprovalRequired, "")

	// the one shutdown after boot: Precheck says it would pass, as often as it is asked, and records nothing
	b := newRig(t, true)
	b.setLocal(func(tr *approval.Trust) { tr.BootShutdownS = 900 })
	b.mu.Lock()
	b.uptime = 2 * time.Minute
	b.mu.Unlock()
	mark := filepath.Join(filepath.Dir(b.files.Path), approval.BootMarkName)
	for i := 0; i < 3; i++ {
		accepted(t, "shutdown shortly after boot", b.g.Precheck(power("shutdown", 5), false))
	}
	refused(t, "reboot shortly after boot", b.g.Precheck(power("reboot", 5), false), api.CodeApprovalRequired, "")
	refused(t, "a delay over 600 s", b.g.Precheck(power("shutdown", 601), false), api.CodeApprovalRequired, "")
	if _, err := os.Lstat(mark); err == nil {
		t.Fatal("Precheck recorded the shutdown after boot")
	}
	_, ref = b.g.Admit(power("shutdown", 60), nil)
	accepted(t, "the one shutdown, when it is carried out", ref)
	if _, err := os.Lstat(mark); err != nil {
		t.Fatalf("Admit did not record the shutdown after boot: %v", err)
	}
	refused(t, "a second one: Precheck", b.g.Precheck(power("shutdown", 60), false), api.CodeApprovalRequired, "")
	_, ref = b.g.Admit(power("shutdown", 60), nil)
	refused(t, "a second one: Admit", ref, api.CodeApprovalRequired, "")

	// a trust file that cannot be used refuses at once, with or without an approval
	if err := os.WriteFile(r.files.Path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.wait(6 * time.Second)
	refused(t, "broken, none sent", r.g.Precheck(req, false), api.CodeApprovalUnavailable, "")
	refused(t, "broken, sent", r.g.Precheck(req, true), api.CodeApprovalUnavailable, "")
}

// tooMany asks g for a challenge for req and checks that it is refused with too_many_challenges.
func tooMany(t *testing.T, what string, g *approval.Gate, req api.ApprovalRequest, retry string) {
	t.Helper()
	c, ref := g.Challenge(req)
	if ref == nil || ref.Status != 429 || ref.Code != api.CodeTooManyChallenges || c.Needed || c.Challenge != "" {
		t.Fatalf("%s: %+v, %v, want 429 %s", what, c, ref, api.CodeTooManyChallenges)
	}
	if !strings.Contains(ref.Msg, "Try again in "+retry+" s") {
		t.Errorf("%s: the answer does not say when to ask again (%s s): %q", what, retry, ref.Msg)
	}
}

// TestChallengeStoreNeverDropsAYoungChallenge (r1-a1-03, r1-a2-04). A machine keeps 16 open challenges; the 17th
// used to drop the oldest without a word. Whoever holds the control token could so make every approval that
// was in flight fail: the owner confirms with the passkey and gets "no_challenge". Now a challenge is never
// dropped while it is younger than ChallengeProtect (90 s): the 17th request is refused instead, openly. Past
// that age the oldest makes room, so the list cannot be kept shut with a few requests either.
func TestChallengeStoreNeverDropsAYoungChallenge(t *testing.T) {
	r := newRig(t, true)
	owner := power("shutdown", 60)
	e := r.entry(owner) // the owner is at Pocket ID with this one

	// the auditors' run: sixteen more requests for challenges
	for i := 1; i < approval.MaxChallenges; i++ {
		r.entry(fanSet(0, 30+i))
	}
	tooMany(t, "the 17th at once", r.g, update, "90")
	r.wait(89 * time.Second)
	tooMany(t, "the 17th after 89 s", r.g, update, "1")
	if !strings.Contains(r.log.String(), "no challenge given, too many are open") {
		t.Errorf("the refusal is not in the log:\n%s", r.log.String())
	}
	// the owner's approval, confirmed in the meantime, is good
	if _, ref := r.g.Admit(owner, r.iss.Approve(r.Now(), e)); ref != nil {
		t.Fatalf("the approval that was in flight while 16 more challenges were asked for: %v", ref)
	}
	// its place is free again: a used challenge is not an open one
	r.entry(update)
	tooMany(t, "full again", r.g, fanMode("full"), "1")

	// past the protected time the oldest makes room, and the log says which one went
	r.wait(time.Second)
	victim := r.entry(fanMode("full")) // drops fan_set zone=0 percent=31, 90 s old
	_ = victim
	if !strings.Contains(r.log.String(), "the oldest open challenge was dropped for a new one") || !strings.Contains(r.log.String(), `request="fan_set zone=0 percent=31"`) {
		t.Errorf("the log does not say which challenge was dropped:\n%s", r.log.String())
	}

	// expired challenges take no place: after the life of an ordinary challenge only the update's is left
	// (it lives 900 s). It is protected for 90 s like every other, not for its whole life: sixteen requests
	// must not shut the list for 15 minutes. So when the list is full again, it is the one that makes room.
	r.wait(approval.ChallengeTTL)
	for i := 1; i < approval.MaxChallenges; i++ {
		r.entry(fanSet(1, 30+i))
	}
	r.entry(power("reboot", 60))
	if !strings.Contains(r.log.String(), `dropped for a new one" request=apply_update`) {
		t.Errorf("the update's challenge, 181 s old, did not make room:\n%s", r.log.String())
	}
	tooMany(t, "sixteen fresh ones", r.g, power("sleep", 60), "90")

	// what a panel does: sixteen entries for one machine in one confirmation, asked for at once, all used
	p := newRig(t, true)
	var entries []api.MachineEntry
	var reqs []api.ApprovalRequest
	for i := 0; i < approval.MaxChallenges; i++ {
		q := fanSet(i%2, 30+i)
		reqs = append(reqs, q)
		entries = append(entries, p.entry(q))
	}
	ap := p.iss.Approve(p.Now(), entries...)
	for i, q := range reqs {
		if _, ref := p.g.Admit(q, ap); ref != nil {
			t.Fatalf("entry %d of a batch of 16 for one machine: %v", i, ref)
		}
	}
	p.entry(update) // and the list is empty again
}
