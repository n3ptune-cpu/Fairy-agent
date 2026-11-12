package approval_test

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// reader is the gate of a process that does not check: it only reads this machine's trust file and has given
// no challenge (the Windows agent next to the helper).
func (r *rig) reader() *approval.Gate {
	return approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Now: r.Now, ReadOnly: true,
		Log: slog.New(slog.NewTextHandler(r.log, nil))})
}

// TestPreverify (audit 5, r2-a1-03): what a process that hands an approval on can say about it beforehand,
// without the list of open challenges and without using anything up. It must never refuse what the checker
// would accept, and it refuses everything that is wrong whoever gave the challenge. TestTokenChecks runs the
// same look over every bad token of its table.
func TestPreverify(t *testing.T) {
	r := newRig(t, true)
	pre := r.reader()
	upd := api.ApprovalRequest{Verb: api.ApproveApplyUpdate}
	look := func(what string, g *approval.Gate, req api.ApprovalRequest, ap *api.Approval, reason string) {
		t.Helper()
		checked, ref := g.Preverify(req, ap)
		switch {
		case !checked:
			t.Errorf("%s: not looked at", what)
		case reason == "":
			accepted(t, what, ref)
		default:
			refused(t, what, ref, api.CodeApprovalRefused, reason)
			if ref != nil && ref.Status != 403 {
				t.Errorf("%s: status %d", what, ref.Status)
			}
		}
	}
	raw, err := os.ReadFile(r.files.Path)
	must(t, err)

	// a good approval: as often as it is looked at, by the reader or by the checker itself, it is not used up
	good := r.approve(upd)
	look("a good approval", pre, upd, good, "")
	look("a good approval, again", pre, upd, good, "")
	look("a good approval, the checker's own look", r.g, upd, good, "")
	if strings.Contains(r.log.String(), "approval: accepted") {
		t.Error("a look wrote \"accepted\" into the log")
	}
	accepted(t, "the good approval after three looks", r.g.Check(upd, good))
	// what the look cannot know: that it was used a moment ago. The checker says so.
	look("the same approval, used up", pre, upd, good, "")
	refused(t, "the same approval, used up", r.g.Check(upd, good), api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// the list of entries
	look("no entries", pre, upd, &api.Approval{Token: "x", Entries: []api.MachineEntry{}}, approval.ReasonEntries)
	look("no entries, a good token", pre, upd, &api.Approval{Token: good.Token}, approval.ReasonEntries)
	look("a malformed challenge", pre, upd, &api.Approval{Token: good.Token, Entries: []api.MachineEntry{{MachineID: r.id(), Challenge: "short", Request: "apply_update"}}}, approval.ReasonEntries)
	look("an entry without machine id", pre, upd, &api.Approval{Token: good.Token, Entries: []api.MachineEntry{{Challenge: good.Entries[0].Challenge, Request: "apply_update"}}}, approval.ReasonEntries)
	junk := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: r.id(), Challenge: strings.Repeat("A", 43), Request: "apply_update"}}}
	look("a made-up token", pre, upd, junk, approval.ReasonFormat)
	big := &api.Approval{Token: strings.Repeat("a", api.MaxApprovalToken+1), Entries: junk.Entries}
	look("a token that is too large", pre, upd, big, approval.ReasonFormat)

	// a real approval of something else on this machine is none of an update
	shut := power("shutdown", 60)
	other := r.approve(shut)
	look("an approval of a shutdown, for an update", pre, upd, other, approval.ReasonNoChallenge)
	look("an approval of a shutdown, for a shutdown", pre, shut, other, "")
	look("an approval of a shutdown, for another delay", pre, power("shutdown", 61), other, approval.ReasonNoChallenge)
	// the same list with the request text changed after signing
	forged := &api.Approval{Token: other.Token, Entries: []api.MachineEntry{{MachineID: r.id(), Challenge: other.Entries[0].Challenge, Request: "apply_update"}}}
	look("a shutdown's token over a list that says update", pre, upd, forged, approval.ReasonNonce)

	// made for another machine: the nonce is made with THIS machine's id, whatever the entry says
	e := r.entry(upd)
	theirs := api.MachineEntry{MachineID: idB, Challenge: e.Challenge, Request: e.Request}
	look("signed for another machine's id", pre, upd, r.iss.Approve(r.Now(), theirs), approval.ReasonNonce)
	relabelled := r.iss.Approve(r.Now(), theirs)
	relabelled.Entries[0].MachineID = r.id()
	look("signed for another machine's id, the entry relabelled", pre, upd, relabelled, approval.ReasonNonce)
	// one approval for several machines: this machine's entry is found among the others, in any place
	elsewhere := api.MachineEntry{MachineID: idB, Challenge: approvaltest.B64(bytes.Repeat([]byte{7}, 32)), Request: "apply_update"}
	third := api.MachineEntry{MachineID: idA, Challenge: approvaltest.B64(bytes.Repeat([]byte{9}, 32)), Request: "power action=reboot delay_s=60"}
	batch := r.iss.Approve(r.Now(), elsewhere, third, e)
	look("three machines, this one last", pre, upd, batch, "")
	accepted(t, "three machines, this one last, the check", r.g.Check(upd, batch))
	look("two other machines only", pre, upd, r.iss.Approve(r.Now(), elsewhere, third), approval.ReasonNonce)

	// who signed, for whom
	stranger := *r.iss
	stranger.Key = approvaltest.Key(1)
	look("signed with another key", pre, upd, stranger.Approve(r.Now(), r.entry(upd)), approval.ReasonSignature)
	nobody := *r.iss
	nobody.Sub = "99999999-0000-4000-8000-000000000000"
	look("approved by a user who may not", pre, upd, nobody.Approve(r.Now(), r.entry(upd)), approval.ReasonUser)

	// time. The checker compares with the moment it gave the challenge; the look with the earliest moment a
	// challenge that can still be answered was given. An update's challenge lives 15 minutes, another 3.
	late := r.approve(upd)
	r.wait(approval.UpdateChallengeTTL - time.Second)
	look("an update's approval, one second before its challenge ends", pre, upd, late, "")
	accepted(t, "an update's approval, one second before its challenge ends, the check", r.g.Check(upd, late))
	old := r.approve(upd)
	r.wait(approval.UpdateChallengeTTL + approval.ClockAllowance + time.Second)
	look("an update's approval, older than any challenge that is open", pre, upd, old, approval.ReasonClock)
	refused(t, "an update's approval, older than any challenge that is open, the check", r.g.Check(upd, old), api.CodeApprovalRefused, approval.ReasonExpired)
	stale := r.approve(shut)
	r.wait(approval.ChallengeTTL + approval.ClockAllowance + time.Second)
	look("a shutdown's approval after four minutes", pre, shut, stale, approval.ReasonClock)

	// the reader wrote nothing
	if now, _ := os.ReadFile(r.files.Path); !bytes.Equal(now, raw) || len(tempFiles(t, r.files.Path[:len(r.files.Path)-len(approval.TrustFileName)])) != 0 {
		t.Error("a look changed the trust file or its folder")
	}

	// a gate that has no usable trust says nothing: the caller goes on as without the look
	for name, g := range map[string]*approval.Gate{
		"no trust file": newRig(t, false).reader(),
		"no gate":       nil,
	} {
		if checked, ref := g.Preverify(upd, good); checked || ref != nil {
			t.Errorf("%s: %v %v", name, checked, ref)
		}
	}
	broken := newRig(t, true)
	must(t, os.WriteFile(broken.files.Path, []byte("damaged"), 0o600))
	if checked, ref := broken.reader().Preverify(upd, good); checked || ref != nil {
		t.Errorf("a broken trust file: %v %v", checked, ref)
	}
	if checked, ref := pre.Preverify(upd, nil); checked || ref != nil {
		t.Errorf("no approval: %v %v", checked, ref)
	}
	// the trust file changed a moment ago: the look reads the file as it is now, not its last look at it
	r.setLocal(func(tr *approval.Trust) { tr.Users = []string{"somebody-else"} })
	look("after the user was taken out of the trust file", pre, upd, r.iss.Approve(r.Now(), api.MachineEntry{MachineID: r.id(), Challenge: e.Challenge, Request: "apply_update"}), approval.ReasonUser)
}
