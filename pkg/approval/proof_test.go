package approval_test

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// trustEntry asks g for the challenge of a first-time set of in and returns the entry.
func (r *rig) trustEntry(g *approval.Gate, in api.TrustInit) api.ApprovalEntry {
	r.t.Helper()
	c, ref := g.Challenge(api.TrustSetRequest(in))
	if ref != nil || !c.Needed || len(c.Challenge) != api.ChallengeLen || c.ExpiresInS != int(approval.ChallengeTTL/time.Second) {
		r.t.Fatalf("trust_set challenge: %+v, %v", c, ref)
	}
	if c.Request != "trust_set hash="+api.TrustHash(in) || c.Issuer != "" || c.ClientID != "" || c.Reason != "" {
		r.t.Fatalf("trust_set challenge answer %+v", c)
	}
	return api.ApprovalEntry{Challenge: c.Challenge, Request: c.Request}
}

// TestFirstTimeSetMustProveItWorks: a first-time set is accepted only with an approval that verifies against
// the PROPOSED trust. Every way in which the proposal would not work later (a wrong issuer spelling, client,
// user or key, a clock that is off, no passkey) is refused now, with a code of its own, and leaves the machine
// without trust, so the panel can try again.
func TestFirstTimeSetMustProveItWorks(t *testing.T) {
	good := approvaltest.New().Init()
	stranger := *approvaltest.New()
	stranger.Key = approvaltest.Key(1) // signs with a key that is not the proposed one, under the proposed kid
	otherKid := stranger
	otherKid.Kid = "not-proposed"
	type attempt struct {
		// build returns what is sent; e is this machine's entry for the proposal `in` (the good values unless
		// propose changes them).
		propose func(in *api.TrustInit)
		build   func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit
		code    string
		reason  string
	}
	withClaims := func(change func(cl map[string]any, now time.Time)) func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
		return func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
			nonce, _ := api.ApprovalNonce([]api.ApprovalEntry{e})
			cl := r.iss.Claims(nonce, r.Now())
			change(cl, r.Now())
			in.Approval = &api.Approval{Token: r.iss.Token(cl), Entries: []api.ApprovalEntry{e}}
			return in
		}
	}
	signedBy := func(iss *approvaltest.Issuer) func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
		return func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit { return iss.Prove(r.Now(), in, e) }
	}
	honest := func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit { return r.iss.Prove(r.Now(), in, e) }
	for name, c := range map[string]attempt{
		"no proof at all": {build: func(_ *rig, in api.TrustInit, _ api.ApprovalEntry) api.TrustInit { return in },
			code: api.CodeTrustProofRequired},
		// the panel's configuration is wrong, Pocket ID and the user are fine: what a typo looks like
		"issuer with a trailing slash": {propose: func(in *api.TrustInit) { in.Issuer += "/" }, build: honest,
			code: api.CodeTrustProofRefused, reason: approval.ReasonIssuer},
		"the login client's id instead of the action client's": {propose: func(in *api.TrustInit) { in.ClientID = "fairy-login" }, build: honest,
			code: api.CodeTrustProofRefused, reason: approval.ReasonAudience},
		"a user id that is not the approver's": {propose: func(in *api.TrustInit) { in.Users = []string{"someone-else"} }, build: honest,
			code: api.CodeTrustProofRefused, reason: approval.ReasonUser},
		"a key of another issuer under the right kid": {propose: func(in *api.TrustInit) {
			in.Keys = []api.TrustKey{approval.KeyFromRSA(approvaltest.Kid, &approvaltest.Key(1).PublicKey)}
		}, build: honest, code: api.CodeTrustProofRefused, reason: approval.ReasonSignature},
		"a key with another kid than the issuer signs with": {propose: func(in *api.TrustInit) { in.Keys[0].Kid = "old-key" }, build: honest,
			code: api.CodeTrustProofRefused, reason: approval.ReasonKey},
		// the proposal is right, the token is not Pocket ID's
		"token signed by somebody else":         {build: signedBy(&stranger), code: api.CodeTrustProofRefused, reason: approval.ReasonSignature},
		"token with a kid that is not proposed": {build: signedBy(&otherKid), code: api.CodeTrustProofRefused, reason: approval.ReasonKey},
		// this machine's clock and Pocket ID's are further apart than the allowance
		"machine clock behind Pocket ID's": {build: withClaims(func(cl map[string]any, now time.Time) {
			cl["iat"], cl["auth_time"] = now.Add(2*time.Minute).Unix(), now.Add(2*time.Minute).Unix()
		}), code: api.CodeTrustProofRefused, reason: approval.ReasonClock},
		"machine clock ahead of Pocket ID's": {build: withClaims(func(cl map[string]any, now time.Time) {
			cl["iat"], cl["auth_time"], cl["exp"] = now.Add(-2*time.Minute).Unix(), now.Add(-2*time.Minute).Unix(), now.Add(time.Hour).Unix()
		}), code: api.CodeTrustProofRefused, reason: approval.ReasonClock},
		"token expired": {build: withClaims(func(cl map[string]any, now time.Time) { cl["exp"] = now.Add(-2 * time.Minute).Unix() }),
			code: api.CodeTrustProofRefused, reason: approval.ReasonTokenExp},
		// not a fresh passkey check
		"signed in before the challenge": {build: withClaims(func(cl map[string]any, now time.Time) { cl["auth_time"] = now.Add(-10 * time.Minute).Unix() }),
			code: api.CodeTrustProofRefused, reason: approval.ReasonAuthTime},
		"no auth_time": {build: withClaims(func(cl map[string]any, _ time.Time) { delete(cl, "auth_time") }),
			code: api.CodeTrustProofRefused, reason: approval.ReasonAuthTime},
		"password sign-in": {build: withClaims(func(cl map[string]any, _ time.Time) { cl["amr"] = []string{"pwd"} }),
			code: api.CodeTrustProofRefused, reason: approval.ReasonAMR},
		// the approval is for something else
		"token for another nonce": {build: withClaims(func(cl map[string]any, _ time.Time) { cl["nonce"] = strings.Repeat("A", 43) }),
			code: api.CodeTrustProofRefused, reason: approval.ReasonNonce},
		"values changed after the challenge (a user added)": {build: func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
			in.Users = append([]string{}, in.Users...)
			in.Users = append(in.Users, "attacker")
			return r.iss.Prove(r.Now(), in, e)
		}, code: api.CodeTrustProofRefused, reason: approval.ReasonNoChallenge},
		"values changed after the challenge (a key added)": {build: func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
			in.Keys = append([]api.TrustKey{}, in.Keys...)
			in.Keys = append(in.Keys, approval.KeyFromRSA("extra", &approvaltest.Key(1).PublicKey))
			return r.iss.Prove(r.Now(), in, e)
		}, code: api.CodeTrustProofRefused, reason: approval.ReasonNoChallenge},
		"the entry rewritten to the hash of other values": {build: func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
			in.Users = []string{approvaltest.User, "attacker"}
			e.Request = "trust_set hash=" + api.TrustHash(in)
			return r.iss.Prove(r.Now(), in, e)
		}, code: api.CodeTrustProofRefused, reason: approval.ReasonEntries},
		"a challenge this machine never gave": {build: func(r *rig, in api.TrustInit, _ api.ApprovalEntry) api.TrustInit {
			return r.iss.Prove(r.Now(), in, api.ApprovalEntry{Challenge: strings.Repeat("B", 42) + "A", Request: "trust_set hash=" + api.TrustHash(in)})
		}, code: api.CodeTrustProofRefused, reason: approval.ReasonNoChallenge},
		"an empty entry list": {build: func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
			in.Approval = &api.Approval{Token: r.iss.Approve(r.Now(), e).Token}
			return in
		}, code: api.CodeTrustProofRefused, reason: approval.ReasonEntries},
		"junk for a token": {build: func(_ *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
			in.Approval = &api.Approval{Token: "a.b.c", Entries: []api.ApprovalEntry{e}}
			return in
		}, code: api.CodeTrustProofRefused, reason: approval.ReasonFormat},
		"the challenge too old": {build: func(r *rig, in api.TrustInit, e api.ApprovalEntry) api.TrustInit {
			r.wait(approval.ChallengeTTL)
			return r.iss.Prove(r.Now(), in, e)
		}, code: api.CodeTrustProofRefused, reason: approval.ReasonExpired},
	} {
		r := newRig(t, false)
		in := good
		in.Keys, in.Users = append([]api.TrustKey(nil), good.Keys...), append([]string(nil), good.Users...)
		if c.propose != nil {
			c.propose(&in)
		}
		st, ref := r.g.Init(c.build(r, in, r.trustEntry(r.g, in)))
		if ref == nil || ref.Code != c.code || ref.Status != 403 || !strings.Contains(ref.Msg, "Nothing was written") ||
			(c.reason != "" && !strings.HasPrefix(ref.Msg, "proof refused ("+c.reason+")")) {
			t.Errorf("%s: %v, want 403 %s %s", name, ref, c.code, c.reason)
		}
		if st.State != api.ApprovalOff {
			t.Errorf("%s: state %s after a refused set", name, st.State)
		}
		if left, _ := os.ReadDir(filepath.Dir(r.files.Path)); len(left) != 0 {
			t.Errorf("%s: a refused set left %d files", name, len(left))
		}
		// nothing is locked: control still works without approval, and a right proposal with its proof is taken
		accepted(t, name+": still off", r.g.Check(power("shutdown", 60), nil))
		if st, ref := r.firstSet(r.g, r.iss, good); ref != nil || st.State != api.ApprovalRequired {
			t.Errorf("%s: a good set after the refused one: %+v, %v", name, st, ref)
		}
		log := r.log.String()
		if want := "reason=" + c.code; c.reason == "" && !strings.Contains(log, want) {
			t.Errorf("%s: log lacks %q:\n%s", name, want, log)
		}
		if want := "reason=" + c.reason; c.reason != "" && !strings.Contains(log, want) {
			t.Errorf("%s: log lacks %q:\n%s", name, want, log)
		}
	}
}

// TestFirstTimeSetProofIsSingleUseAndBatchReady: one confirmation at Pocket ID switches on several machines
// (one token, each machine's own challenge for the same trust hash in the list); the same proof does not work
// a second time, on the same machine after a local clear or on another one.
func TestFirstTimeSetProofIsSingleUseAndBatchReady(t *testing.T) {
	a, b, c := newRig(t, false), newRig(t, false), newRig(t, false)
	in := a.iss.Init()
	ea, eb := a.trustEntry(a.g, in), b.trustEntry(b.g, in)
	if ea.Request != eb.Request || ea.Challenge == eb.Challenge {
		t.Fatalf("two machines, the same proposal: %+v %+v", ea, eb)
	}
	proven := a.iss.Prove(a.Now(), in, ea, eb) // one token for both
	for name, r := range map[string]*rig{"machine A": a, "machine B": b} {
		if st, ref := r.g.Init(proven); ref != nil || st.State != api.ApprovalRequired || st.Issuer != in.Issuer {
			t.Fatalf("%s: %+v, %v", name, st, ref)
		}
		tr, err := approval.ParseTrust(mustRead(t, r.files.Path))
		if err != nil || tr.SetBy != "panel" || tr.Issuer != in.Issuer || len(tr.Users) != 1 || tr.FanWindow() != approval.DefaultFanWindowS || tr.BootShutdownS != 0 {
			t.Errorf("%s: trust file %+v, %v", name, tr, err)
		}
		if log := r.log.String(); !strings.Contains(log, "proven by a passkey approval") || !strings.Contains(log, "sub="+approvaltest.User) ||
			strings.Contains(log, strings.Split(proven.Approval.Token, ".")[2]) {
			t.Errorf("%s: log:\n%s", name, log)
		}
	}
	// machine C never gave a challenge for it
	_, ref := c.g.Init(proven)
	refused(t, "machine C", ref, api.CodeTrustProofRefused, "")
	// machine A after a local clear: the proof was used, and its challenge is gone anyway
	must(t, a.files.Remove())
	a.wait(6 * time.Second)
	_, ref = a.g.Init(proven)
	refused(t, "the same proof again after a clear", ref, api.CodeTrustProofRefused, "")
	if st := a.g.Status(); st.State != api.ApprovalOff {
		t.Errorf("machine A after the refused replay: %+v", st)
	}

	// two challenges of one machine for the same proposal in one list: which one is meant cannot be told
	d := newRig(t, false)
	e1, e2 := d.trustEntry(d.g, in), d.trustEntry(d.g, in)
	_, ref = d.g.Init(d.iss.Prove(d.Now(), in, e1, e2))
	if ref == nil || ref.Code != api.CodeTrustProofRefused || !strings.HasPrefix(ref.Msg, "proof refused ("+approval.ReasonAmbiguous+")") {
		t.Errorf("two entries of one machine: %v", ref)
	}
	// an approval of an ordinary action is not a proof, and a proof is not an approval of an action
	e := d.trustEntry(d.g, in)
	if _, ref := d.g.Init(d.iss.Prove(d.Now(), in, e)); ref != nil {
		t.Fatal(ref)
	}
	ap := d.approve(power("shutdown", 60))
	late := newRig(t, false)
	lin := late.iss.Init()
	lin.Approval = ap
	_, ref = late.g.Init(lin)
	refused(t, "an action's approval as the proof", ref, api.CodeTrustProofRefused, "")
	refused(t, "trust_set is not a request that runs", d.g.Check(api.TrustSetRequest(in), d.iss.Approve(d.Now(), e)), "bad_request", "")
}

// TestReadOnlyGate: a gate that only reads the trust file (the Windows agent next to the helper) checks
// requests like any other and never writes: no first-time set, no challenge for one, no shutdown after boot.
func TestReadOnlyGate(t *testing.T) {
	r := newRig(t, false)
	ro := approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Now: r.Now, ReadOnly: true,
		Uptime: func() (time.Duration, error) { return 10 * time.Second, nil }, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	in := r.iss.Init()
	if _, ref := ro.Challenge(api.TrustSetRequest(in)); ref == nil || ref.Code != api.CodeApprovalDisabled || ref.Status != 404 {
		t.Errorf("trust_set challenge from a read-only gate: %v", ref)
	}
	proven := r.proven(r.g, r.iss, in) // a good proof, made with the gate that may write
	if _, ref := ro.Init(proven); ref == nil || ref.Code != api.CodeApprovalDisabled {
		t.Errorf("first-time set through a read-only gate: %v", ref)
	}
	if _, err := os.Lstat(r.files.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a read-only gate wrote the trust file")
	}
	accepted(t, "off", ro.Check(power("shutdown", 60), nil))
	if _, ref := r.g.Init(proven); ref != nil {
		t.Fatal(ref)
	}
	r.setLocal(func(tr *approval.Trust) { tr.BootShutdownS = 600 })
	if st := ro.Status(); st.State != api.ApprovalRequired || st.EnforcedBy != api.EnforcedByAgent {
		t.Fatalf("read-only gate: %+v", st)
	}
	if _, ref := ro.Init(in); ref == nil || ref.Code != api.CodeTrustAlreadySet {
		t.Errorf("set on a machine with trust, read-only gate: %v", ref)
	}
	// it checks with its own challenges
	req := fanSet(0, 50)
	refused(t, "no approval", ro.Check(req, nil), api.CodeApprovalRequired, "")
	refused(t, "the other gate's challenge", ro.Check(req, r.approve(req)), api.CodeApprovalRefused, approval.ReasonNoChallenge)
	accepted(t, "its own challenge", ro.Check(req, r.iss.Approve(r.Now(), r.entryFrom(ro, req))))
	// and never gives the shutdown after boot: it could not record it
	refused(t, "shutdown after boot", ro.Check(power("shutdown", 60), nil), api.CodeApprovalRequired, "")
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(r.files.Path), "*boot*")); len(left) != 0 {
		t.Errorf("a read-only gate wrote %v", left)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestTrustHashVectorIsAValidProposal: the first published trust hash vector (protocol, section 6.2; the hash
// itself is checked in pkg/agent/api) is a proposal the value checks accept, so the panel's tests can send the
// vector as a whole body.
func TestTrustHashVectorIsAValidProposal(t *testing.T) {
	n := make([]byte, 256)
	for i := range n {
		n[i] = byte(128 + 3*i)
	}
	in := api.TrustInit{Issuer: "https://id.example.org", ClientID: "3f6c0c0e-0000-4000-8000-000000000000",
		Keys:  []api.TrustKey{{Kty: "RSA", Kid: "abc123", Alg: "RS256", N: approvaltest.B64(n), E: "AQAB"}},
		Users: []string{"11111111-2222-4333-8444-555555555555"}}
	if got := api.TrustHash(in); got != "dRtwOuCOmn_fN8xutDqtllZabcZQcFGbT4ShJzPoXpQ" {
		t.Fatalf("trust hash %s", got)
	}
	if _, err := approval.FromInit(in, nowForTests); err != nil {
		t.Errorf("the vector is not a valid proposal: %v", err)
	}
}
