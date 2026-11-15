package approval_test

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// The rules of the one request that is never carried out without a passkey approval: socket_set (strict.go).
// Each differs from the fan, power and update requests, and each test here holds the difference.

// socketReq is the request for one socket of a made-up powerbar; the tag is the one that socket would have.
func socketReq(socket, to string) api.ApprovalRequest {
	return api.SocketSetRequest("desk-bar", socket, to, api.SocketTag("desk-bar", socket, "Channel "+socket, "switch.desk_bar_"+socket))
}

// stillOpen reports whether the machine still holds the challenge of e: a fresh good approval of e alone is
// accepted by a look that uses nothing up.
func (r *rig) stillOpen(req api.ApprovalRequest, e api.MachineEntry) bool {
	return r.g.Look(req, r.iss.Approve(r.Now(), e)) == nil
}

// No trust file: every other request runs unchecked, this one is refused with 409 approval_off, whichever
// question is asked and whatever comes with it. No challenge is given for it.
func TestSocketSetIsRefusedWithoutATrustFile(t *testing.T) {
	r := newRig(t, false)
	off, on := socketReq("ch1", "off"), socketReq("ch1", "on")
	madeUp := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: approvaltest.MachineID,
		Challenge: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), Request: "socket_set"}}}
	isOff := func(what string, ref *approval.Refusal) {
		t.Helper()
		if ref == nil || ref.Status != 409 || ref.Code != api.CodeApprovalOff {
			t.Errorf("%s on a machine without a trust file: %v, want 409 %s", what, ref, api.CodeApprovalOff)
		}
	}
	for _, req := range []api.ApprovalRequest{off, on} {
		c, ref := r.g.Challenge(req)
		isOff("challenge", ref)
		if c.Needed || c.Challenge != "" || c.Reason != "" {
			t.Errorf("the answer to a challenge request that is refused says %+v", c)
		}
		isOff("first look, nothing sent", r.g.Precheck(req, false))
		isOff("first look, something sent", r.g.Precheck(req, true))
		isOff("look without an approval", r.g.Look(req, nil))
		isOff("look with an approval", r.g.Look(req, madeUp))
		_, ref = r.g.Admit(req, nil)
		isOff("the request without an approval", ref)
		_, ref = r.g.Admit(req, madeUp)
		isOff("the request with an approval", ref)
		_, ref = r.g.RunCovers(req, "0123456789abcdef")
		isOff("the request in the name of a run", ref)
		_, ref = r.g.AdmitRun(req, "0123456789abcdef")
		isOff("the request in the name of a run, carried out", ref)
	}
	// a part that was built without any gate lets nothing of this kind through either
	var none *approval.Gate
	isOff("no gate, first look", none.Precheck(off, true))
	isOff("no gate, look", none.Look(off, madeUp))
	_, ref := none.Admit(off, madeUp)
	isOff("no gate, the request", ref)
	_, ref = none.RunCovers(off, "0123456789abcdef")
	isOff("no gate, a run", ref)
	_, ref = none.AdmitRun(off, "0123456789abcdef")
	isOff("no gate, a run carried out", ref)

	// the difference, held: on the same machine everything else runs, as it always did
	for _, req := range []api.ApprovalRequest{power("shutdown", 60), fanSet(0, 50), fanMode("full"), update} {
		if c, ref := r.g.Challenge(req); ref != nil || c.Needed || c.Reason != "off" {
			t.Errorf("%s without a trust file: challenge %+v, %v", req.Verb, c, ref)
		}
		if ref := r.g.Precheck(req, false); ref != nil {
			t.Errorf("%s without a trust file: %v", req.Verb, ref)
		}
		if ref := r.g.Look(req, nil); ref != nil {
			t.Errorf("%s without a trust file, looked at: %v", req.Verb, ref)
		}
		if _, ref := r.g.Admit(req, nil); ref != nil {
			t.Errorf("%s without a trust file: %v", req.Verb, ref)
		}
		if _, ref := none.Admit(req, nil); ref != nil || none.Precheck(req, false) != nil || none.Look(req, nil) != nil {
			t.Errorf("%s without a gate: %v", req.Verb, ref)
		}
	}
	if n := strings.Count(r.log.String(), "challenge issued"); n != 0 {
		t.Errorf("%d challenges were given on a machine without a trust file", n)
	}
}

// A trust file that cannot be used: 503 approval_unavailable, as for every request that needs an approval.
func TestSocketSetWithATrustFileThatCannotBeUsed(t *testing.T) {
	r := newRig(t, true)
	ap := r.approve(socketReq("ch1", "off"))
	if err := os.WriteFile(r.files.Path, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.wait(6 * time.Second) // past the gate's last look at the file
	req := socketReq("ch1", "off")
	for what, ref := range map[string]*approval.Refusal{
		"first look":      r.g.Precheck(req, true),
		"look":            r.g.Look(req, ap),
		"look, none sent": r.g.Look(req, nil),
	} {
		if ref == nil || ref.Status != 503 || ref.Code != api.CodeApprovalUnavailable {
			t.Errorf("%s: %v, want 503 %s", what, ref, api.CodeApprovalUnavailable)
		}
	}
	if _, ref := r.g.Challenge(req); ref == nil || ref.Status != 503 || ref.Code != api.CodeApprovalUnavailable {
		t.Errorf("challenge: %v", ref)
	}
	if _, ref := r.g.Admit(req, ap); ref == nil || ref.Status != 503 || ref.Code != api.CodeApprovalUnavailable {
		t.Errorf("the request: %v", ref)
	}
}

// With trust: none sent is refused; a good approval is accepted once; the same one again is refused.
func TestSocketSetNeedsItsOwnApprovalEveryTime(t *testing.T) {
	r := newRig(t, true)
	off := socketReq("ch1", "off")
	refused(t, "first look, none sent", r.g.Precheck(off, false), api.CodeApprovalRequired, "")
	refused(t, "look, none sent", r.g.Look(off, nil), api.CodeApprovalRequired, "")
	_, ref := r.g.Admit(off, nil)
	refused(t, "none sent", ref, api.CodeApprovalRequired, "")

	c, ref := r.g.Challenge(off)
	if ref != nil || !c.Needed || approval.ChallengeTTL != 180*time.Second || c.ExpiresInS != 180 {
		t.Fatalf("challenge: %+v, %v", c, ref)
	}
	if want, _ := off.Canonical(); c.Request != want {
		t.Fatalf("the challenge is bound to %q, want %q", c.Request, want)
	}
	ap := r.iss.Approve(r.Now(), approvaltest.Entry(approvaltest.MachineID, c))
	accepted(t, "first look", r.g.Precheck(off, true))
	pass, ref := r.g.Admit(off, ap)
	accepted(t, "a good approval", ref)
	if pass != nil {
		t.Error("an accepted socket approval gave a pass: only a fan change opens a window")
	}
	_, ref = r.g.Admit(off, ap)
	refused(t, "the same approval a second time", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	refused(t, "the same approval a second time, looked at", r.g.Look(off, ap), api.CodeApprovalRefused, approval.ReasonNoChallenge)

	// off, on and off again are three approvals
	for _, to := range []string{"on", "off"} {
		req := socketReq("ch1", to)
		_, ref := r.g.Admit(req, nil)
		refused(t, to+" right after an accepted switch, none sent", ref, api.CodeApprovalRequired, "")
		_, ref = r.g.Admit(req, r.approve(req))
		accepted(t, to+" with its own approval", ref)
	}
}

// A challenge for a socket lives 180 s, like every challenge but an update's.
func TestSocketSetChallengeExpires(t *testing.T) {
	r := newRig(t, true)
	off := socketReq("ch1", "off")
	ap := r.approve(off)
	r.wait(approval.ChallengeTTL - time.Second)
	accepted(t, "a second before the end", r.g.Look(off, ap))
	r.wait(time.Second)
	_, ref := r.g.Admit(off, ap)
	refused(t, "at 180 s", ref, api.CodeApprovalRefused, approval.ReasonExpired)
}

// One approval is one socket and one direction: an approval whose list has two entries switches nothing,
// whatever the two are, and uses nothing up. For every other request such an approval is accepted, as before.
func TestSocketSetTakesAnApprovalOfOneEntryOnly(t *testing.T) {
	r := newRig(t, true)
	one, two := socketReq("ch1", "off"), socketReq("ch2", "off")
	e1, e2 := r.entry(one), r.entry(two)
	both := r.iss.Approve(r.Now(), e1, e2) // one passkey touch for two sockets: "all off"
	for _, c := range []struct {
		what string
		req  api.ApprovalRequest
	}{{"the first socket", one}, {"the second socket", two}} {
		refused(t, c.what+", looked at", r.g.Look(c.req, both), api.CodeApprovalRefused, approval.ReasonOneEntry)
		_, ref := r.g.Admit(c.req, both)
		refused(t, c.what, ref, api.CodeApprovalRefused, approval.ReasonOneEntry)
	}
	if !r.stillOpen(one, e1) || !r.stillOpen(two, e2) {
		t.Fatal("an approval of two entries used a challenge up")
	}
	// the list cannot be shortened afterwards: the token was signed for both
	cut := &api.Approval{Token: both.Token, Entries: []api.MachineEntry{e1}}
	_, ref := r.g.Admit(one, cut)
	refused(t, "the token for two entries with a list of one", ref, api.CodeApprovalRefused, approval.ReasonNonce)
	if !r.stillOpen(one, e1) {
		t.Fatal("the cut list used the challenge up")
	}
	// a second entry of any kind: another machine's, another verb's of this machine
	other := api.MachineEntry{MachineID: "another-machine-BBBBBBBBBB", Challenge: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		Request: "power action=shutdown delay_s=60"}
	_, ref = r.g.Admit(one, r.iss.Approve(r.Now(), e1, other))
	refused(t, "with another machine's entry", ref, api.CodeApprovalRefused, approval.ReasonOneEntry)
	shut := power("shutdown", 60)
	eShut := r.entry(shut)
	mixed := r.iss.Approve(r.Now(), eShut, e1)
	_, ref = r.g.Admit(one, mixed)
	refused(t, "with a shutdown of this machine", ref, api.CodeApprovalRefused, approval.ReasonOneEntry)
	_, ref = r.g.Admit(one, &api.Approval{Token: mixed.Token})
	refused(t, "with no entry at all", ref, api.CodeApprovalRefused, approval.ReasonOneEntry)

	// the difference, held: the shutdown of that same approval of two entries is accepted
	_, ref = r.g.Admit(shut, mixed)
	accepted(t, "the shutdown in the approval of two entries", ref)

	// and each socket with an approval of its own, for the challenge it still has
	_, ref = r.g.Admit(one, r.iss.Approve(r.Now(), e1))
	accepted(t, "the first socket alone", ref)
	_, ref = r.g.Admit(two, r.iss.Approve(r.Now(), e2))
	accepted(t, "the second socket alone", ref)
}

// An approval is for exactly the text it was asked for: not the other direction, not another socket, not the
// same socket described differently (another tag). The wrong use costs nothing, the right one still works.
func TestSocketSetApprovalIsForOneSocketAndOneDirection(t *testing.T) {
	r := newRig(t, true)
	off := socketReq("ch1", "off")
	e := r.entry(off)
	ap := r.iss.Approve(r.Now(), e)
	renamed := api.SocketSetRequest("desk-bar", "ch1", "off", api.SocketTag("desk-bar", "ch1", "Server corner", "switch.desk_bar_ch1"))
	rewired := api.SocketSetRequest("desk-bar", "ch1", "off", api.SocketTag("desk-bar", "ch1", "Channel ch1", "switch.server_corner"))
	for what, req := range map[string]api.ApprovalRequest{
		"the other direction":             socketReq("ch1", "on"),
		"another socket":                  socketReq("ch2", "off"),
		"another source":                  api.SocketSetRequest("other-bar", "ch1", "off", *off.Tag),
		"the socket under another name":   renamed,
		"the socket on another switch":    rewired,
		"a shutdown":                      power("shutdown", 60),
		"a fan change":                    fanMode("full"),
		"an update":                       update,
		"the other direction, other case": api.SocketSetRequest("desk-bar", "ch1", "On", *off.Tag),
	} {
		_, ref := r.g.Admit(req, ap)
		if ref == nil {
			t.Fatalf("%s was accepted with the approval of %q", what, e.Request)
		}
		if ref.Code != api.CodeApprovalRefused && ref.Code != "bad_request" {
			t.Errorf("%s: %v", what, ref)
		}
	}
	if !r.stillOpen(off, e) {
		t.Fatal("a wrong use of the approval used its challenge up")
	}
	_, ref := r.g.Admit(off, ap)
	accepted(t, "the request it was asked for", ref)
}

// Nothing stands in for the approval: not the fan window, not the shutdown after boot, not a second switch
// right after an approved one.
func TestSocketSetHasNoWindow(t *testing.T) {
	r := newRig(t, true)
	fan := fanSet(0, 50)
	accepted(t, "an approved fan change", r.g.Check(fan, r.approve(fan)))
	accepted(t, "a second fan change inside the window", r.g.Check(fanSet(0, 60), nil))
	off := socketReq("ch1", "off")
	if c, ref := r.g.Challenge(off); ref != nil || !c.Needed || c.Reason != "" {
		t.Errorf("inside the fan window a socket needs no approval: %+v, %v", c, ref)
	}
	refused(t, "a socket inside the fan window, first look", r.g.Precheck(off, false), api.CodeApprovalRequired, "")
	_, ref := r.g.Admit(off, nil)
	refused(t, "a socket inside the fan window", ref, api.CodeApprovalRequired, "")
	_, ref = r.g.Admit(off, r.approve(off))
	accepted(t, "the socket with its approval", ref)
	_, ref = r.g.Admit(socketReq("ch2", "off"), nil)
	refused(t, "another socket right after an approved switch", ref, api.CodeApprovalRequired, "")
	_, ref = r.g.Admit(off, nil)
	refused(t, "the same socket right after its approved switch", ref, api.CodeApprovalRequired, "")
	// an approved socket switch opens no window for the fans either
	r.wait(31 * time.Second) // the fan window of the approved fan change is over
	refused(t, "a fan change after a socket switch", r.g.Check(fanSet(0, 70), nil), api.CodeApprovalRequired, "")
	// a run covers an update and a shutdown, never a socket
	_, ref = r.g.RunCovers(off, "0123456789abcdef")
	refused(t, "a socket in the name of a run", ref, api.CodeApprovalRequired, "")
	_, ref = r.g.AdmitRun(off, "0123456789abcdef")
	refused(t, "a socket in the name of a run, carried out", ref, api.CodeApprovalRequired, "")
}

// Look says what Admit will say and uses nothing up: a good approval passes it any number of times and is
// then accepted once; a bad one is refused for Admit's reason and leaves the challenge open.
func TestLookUsesNothingUp(t *testing.T) {
	r := newRig(t, true)
	off := socketReq("ch1", "off")
	e := r.entry(off)
	good := r.iss.Approve(r.Now(), e)
	for i := 0; i < 3; i++ {
		accepted(t, "a look at a good approval", r.g.Look(off, good))
	}
	stranger := *r.iss
	stranger.Key = approvaltest.Key(1)
	late := r.iss.Claims(mustNonce(t, e), r.Now().Add(-time.Hour))
	for what, c := range map[string]struct {
		ap     *api.Approval
		reason string
	}{
		"a token signed with another key":                      {stranger.Approve(r.Now(), e), approval.ReasonSignature},
		"a token of a passkey check from before the challenge": {&api.Approval{Token: r.iss.Token(late), Entries: []api.MachineEntry{e}}, ""},
		"a token for another list":                             {&api.Approval{Token: r.iss.Approve(r.Now(), r.entry(socketReq("ch2", "off"))).Token, Entries: []api.MachineEntry{e}}, approval.ReasonNonce},
		"no token":                                             {&api.Approval{Entries: []api.MachineEntry{e}}, approval.ReasonFormat},
		"a challenge this machine never gave": {r.iss.Approve(r.Now(), api.MachineEntry{MachineID: approvaltest.MachineID,
			Challenge: base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")), Request: e.Request}), approval.ReasonNoChallenge},
	} {
		look := r.g.Look(off, c.ap)
		refused(t, what+", looked at", look, api.CodeApprovalRefused, c.reason)
		_, ref := r.g.Admit(off, c.ap)
		refused(t, what, ref, api.CodeApprovalRefused, c.reason)
		if look != nil && ref != nil && look.Msg != ref.Msg {
			t.Errorf("%s: the look says %q and the request %q", what, look.Msg, ref.Msg)
		}
	}
	if !r.stillOpen(off, e) {
		t.Fatal("a refused approval used the challenge up")
	}
	_, ref := r.g.Admit(off, good)
	accepted(t, "the good approval after all the looks", ref)
	refused(t, "a look after it was used", r.g.Look(off, good), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	if strings.Contains(r.log.String(), good.Token) {
		t.Error("the token is in the log")
	}
}

func mustNonce(t *testing.T, entries ...api.MachineEntry) string {
	t.Helper()
	n, err := api.ApprovalNonce(entries)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// A gate that only reads the trust file (the Windows agent next to the helper: the agent sends the request to
// Home Assistant itself, so it checks itself) gives the challenge and checks the approval like any other; and
// without a trust file it refuses.
func TestSocketSetOnAGateThatOnlyReads(t *testing.T) {
	r := newRig(t, true)
	ro := r.reader()
	off := socketReq("ch1", "off")
	e := r.entryFrom(ro, off)
	if r.g.Look(off, r.iss.Approve(r.Now(), e)) == nil {
		t.Fatal("the gate that owns the file accepted a challenge of the gate that reads it")
	}
	ap := r.iss.Approve(r.Now(), e)
	accepted(t, "look", ro.Look(off, ap))
	_, ref := ro.Admit(off, ap)
	accepted(t, "a good approval on a gate that only reads", ref)
	_, ref = ro.Admit(off, ap)
	refused(t, "the same approval again", ref, api.CodeApprovalRefused, approval.ReasonNoChallenge)
	_, ref = ro.Admit(off, r.iss.Approve(r.Now(), r.entryFrom(ro, off), r.entryFrom(ro, socketReq("ch2", "off"))))
	refused(t, "two entries", ref, api.CodeApprovalRefused, approval.ReasonOneEntry)

	bare := newRig(t, false)
	ro = bare.reader()
	if _, ref := ro.Challenge(off); ref == nil || ref.Status != 409 || ref.Code != api.CodeApprovalOff {
		t.Errorf("challenge from a gate that reads no trust file: %v", ref)
	}
	if _, ref := ro.Admit(off, ap); ref == nil || ref.Status != 409 || ref.Code != api.CodeApprovalOff {
		t.Errorf("the request on a gate that reads no trust file: %v", ref)
	}
}
