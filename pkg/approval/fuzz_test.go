package approval_test

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// FuzzToken feeds anything as the ID token of an otherwise good approval. Nothing may panic, and nothing but
// the one good token is accepted (the fuzzer has no key, so whatever else it builds must be refused).
func FuzzToken(f *testing.F) {
	iss := approvaltest.New()
	r := newRig(f, false)
	if _, ref := r.firstSet(r.g, iss, iss.Init()); ref != nil {
		f.Fatal(ref)
	}
	req := power("shutdown", 60)
	c, ref := r.g.Challenge(req)
	if ref != nil {
		f.Fatal(ref)
	}
	entries := []api.MachineEntry{approvaltest.Entry(r.id(), c)}
	nonce, _ := api.ApprovalNonce(entries)
	good := iss.Token(iss.Claims(nonce, r.Now()))
	parts := strings.Split(good, ".")
	for _, seed := range []string{"", "a.b.c", "..", parts[0] + "." + parts[1] + ".", parts[0] + "..", "." + parts[1] + "." + parts[2],
		parts[0] + "." + parts[1] + "." + parts[2] + "A", approvaltest.B64([]byte(`{"alg":"none"}`)) + "." + parts[1] + ".AA",
		approvaltest.B64([]byte(`{"alg":"RS256","kid":"test-key-1","crit":[]}`)) + "." + parts[1] + "." + parts[2],
		approvaltest.B64([]byte(`{"alg":"RS256","kid":"test-key-1"}`)) + "." + approvaltest.B64([]byte(`{"exp":1e999,"iat":[[[[[[[[[[]]]]]]]]]]}`)) + "." + parts[2],
		iss.Sign(iss.Header(nil), `{"iss":"`+iss.URL+`","aud":[],"exp":"x","amr":{"a":1}}`),
		iss.Sign(iss.Header(nil), `{"exp":99999999999999999999999999,"iat":-0,"auth_time":1.5e3,"nbf":0.0000001}`)} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tok string) {
		if tok == good {
			return
		}
		if ref := r.g.Check(req, &api.Approval{Token: tok, Entries: entries}); ref == nil {
			t.Fatalf("a token that is not the issuer's was accepted: %q", tok)
		} else if ref.Code != api.CodeApprovalRefused {
			t.Fatalf("refused with %s", ref.Code)
		}
	})
}

// FuzzApproval feeds anything as the JSON of the "approval" field: the list decoder, the nonce and the search
// for this machine's entry. Nothing may panic or be accepted.
func FuzzApproval(f *testing.F) {
	iss := approvaltest.New()
	r := newRig(f, false)
	if _, ref := r.firstSet(r.g, iss, iss.Init()); ref != nil {
		f.Fatal(ref)
	}
	req := fanSet(0, 50)
	c, _ := r.g.Challenge(req)
	e := api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c.Challenge, Request: c.Request}
	otherNonce, _ := api.ApprovalNonce([]api.MachineEntry{{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: c.Request}})
	tok := iss.Token(iss.Claims(otherNonce, r.Now())) // a real token, for another list
	b, _ := json.Marshal(api.Approval{Token: tok, Entries: []api.MachineEntry{e}})
	f.Add(string(b))
	f.Add(`{"token":"a.b.c","entries":[]}`)
	f.Add(`{"token":"","entries":[{"challenge":"` + c.Challenge + `","request":"power action=shutdown delay_s=10"}]}`)
	f.Add(`{"entries":[{"challenge":"` + c.Challenge + `","request":"` + c.Request + `"},{"challenge":"` + c.Challenge + `","request":"` + c.Request + `"}]}`)
	f.Add(`{"entries":[{"challenge":"\n","request":"\u0000"}]}`)
	// the machine id: the right list with a token for another machine's id, no id, an id that is none, two ids
	forOther := api.MachineEntry{MachineID: "another-machine-AAAAAAAAAA", Challenge: c.Challenge, Request: c.Request}
	otherID, _ := api.ApprovalNonce([]api.MachineEntry{forOther})
	b, _ = json.Marshal(api.Approval{Token: iss.Token(iss.Claims(otherID, r.Now())), Entries: []api.MachineEntry{e}})
	f.Add(string(b))
	b, _ = json.Marshal(api.Approval{Token: iss.Token(iss.Claims(otherID, r.Now())), Entries: []api.MachineEntry{forOther}})
	f.Add(string(b))
	f.Add(`{"token":"a.b.c","entries":[{"machine_id":"","challenge":"` + c.Challenge + `","request":"` + c.Request + `"}]}`)
	f.Add(`{"token":"a.b.c","entries":[{"machine_id":"x y","challenge":"` + c.Challenge + `","request":"` + c.Request + `"}]}`)
	f.Add(`{"token":"a.b.c","entries":[{"machine_id":"` + r.id() + `","MACHINE_ID":"another-machine-AAAAAAAAAA","challenge":"` + c.Challenge + `","request":"` + c.Request + `"}]}`)
	f.Add(`{"token":"a.b.c","entries":[{"machine_id":"","challenge":"` + c.Challenge + `","request":"trust_set hash=` + strings.Repeat("A", 43) + `"}]}`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, raw string) {
		var ap api.Approval
		if json.Unmarshal([]byte(raw), &ap) != nil {
			return
		}
		if n, err := api.ApprovalNonce(ap.Entries); err == nil {
			if len(n) != 43 {
				t.Fatalf("nonce %q", n)
			}
			for _, e := range ap.Entries { // a nonce is never made of an entry without a machine id, the first-time set's apart
				if api.CheckMachineID(e.MachineID) != nil && !(e.MachineID == "" && strings.HasPrefix(e.Request, "trust_set ")) {
					t.Fatalf("a nonce for the entry %+v", e)
				}
			}
		}
		if ref := r.g.Check(req, &ap); ref == nil {
			t.Fatalf("accepted: %q", raw)
		}
	})
}

// FuzzTrustProof feeds anything as the body of a first-time set (POST /approval/trust) to a machine without
// trust that has an open challenge for a good proposal: the body's values, its approval, its entry list. The
// fuzzer has no key of the proposal the challenge is for, and a proposal with a key of its own has another
// hash, so whatever it builds must be refused; nothing may panic, and no trust file may appear.
func FuzzTrustProof(f *testing.F) {
	iss := approvaltest.New()
	r := newRig(f, false)
	in := iss.Init()
	c, ref := r.g.Challenge(api.TrustSetRequest(in))
	if ref != nil {
		f.Fatal(ref)
	}
	e := api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c.Challenge, Request: c.Request}
	otherNonce, _ := api.ApprovalNonce([]api.MachineEntry{{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: c.Request}})
	real := in
	real.Approval = &api.Approval{Token: iss.Token(iss.Claims(otherNonce, r.Now())), Entries: []api.MachineEntry{e}} // a real token, for another list
	b, _ := json.Marshal(real)
	f.Add(string(b))
	bare, _ := json.Marshal(in)
	f.Add(string(bare))
	f.Add(strings.Replace(string(b), iss.URL, iss.URL+"/", 1))
	f.Add(strings.Replace(string(b), c.Request, "trust_set hash="+strings.Repeat("A", 43), 1))
	f.Add(`{"issuer":"https://a","client_id":"c","keys":[{"kty":"RSA","kid":"k","alg":"RS256","n":"AQ","e":"AQAB"}],"users":["u"],"approval":{"token":"a.b.c","entries":[{"challenge":"` + c.Challenge + `","request":"` + c.Request + `"}]}}`)
	f.Add(`{"approval":{"token":"","entries":[{"challenge":"\n","request":"\u0000"}]}}`)
	// the machine id: another one than was proven, none, one that is none
	f.Add(strings.Replace(string(b), `"machine_id":"`+in.MachineID+`"`, `"machine_id":"another-machine-AAAAAAAAAA"`, 1))
	f.Add(strings.Replace(string(b), `"machine_id":"`+in.MachineID+`"`, `"machine_id":""`, -1))
	f.Add(strings.Replace(string(b), `"machine_id":"`+in.MachineID+`"`, `"machine_id":"x"`, -1))
	f.Add(`{"approval":null}`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, raw string) {
		var body api.TrustInit
		if json.Unmarshal([]byte(raw), &body) != nil {
			return
		}
		if h := api.TrustHash(body); len(h) != 43 {
			t.Fatalf("trust hash %q", h)
		}
		st, ref := r.g.Init(body)
		if ref == nil || st.State != api.ApprovalOff {
			t.Fatalf("accepted (state %s): %q", st.State, raw)
		}
		switch ref.Code {
		case api.CodeTrustInvalid, api.CodeTrustUnsupportedKey, api.CodeTrustProofRequired, api.CodeTrustProofRefused:
		default:
			t.Fatalf("refused with %s: %q", ref.Code, raw)
		}
		if _, err := os.Lstat(r.files.Path); err == nil {
			t.Fatalf("a trust file appeared: %q", raw)
		}
	})
}

// FuzzTrustFile feeds anything as the content of the trust file. Nothing may panic; what is accepted obeys
// every limit and reads back as the same trust.
func FuzzTrustFile(f *testing.F) {
	tr, _ := approval.FromInit(approvaltest.New().Init(), nowForTests, nil)
	good := string(tr.Marshal())
	f.Add(good)
	f.Add(strings.Replace(good, `"RS256"`, `"none"`, 1))
	f.Add(strings.Replace(good, `"version": 1`, `"version": 1, "VERSION": 2`, 1))
	f.Add(`{"version":1,"issuer":"https://a","client_id":"c","keys":[{"kty":"RSA","kid":"k","alg":"RS256","n":"AQ","e":"AQAB"}],"users":["u"]}`)
	// the machine id: none (a file from before machine ids), one that is none, two
	f.Add(strings.Replace(good, `  "machine_id": "`+tr.MachineID+`",`+"\n", "", 1))
	f.Add(strings.Replace(good, tr.MachineID, "x y", 1))
	f.Add(strings.Replace(good, `"version": 1`, `"version": 1, "Machine_ID": "another-machine-AAAAAAAAAA"`, 1))
	f.Add(`{}`)
	f.Add(`[`)
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := approval.ParseTrust([]byte(raw))
		if err != nil {
			// a file without a machine id is handed out for its values and never without the error
			if (got != nil) != errors.Is(err, approval.ErrNoMachineID) || (got != nil && got.MachineID != "") {
				t.Fatalf("ParseTrust: %+v, %v", got, err)
			}
			return
		}
		if api.CheckMachineID(got.MachineID) != nil || got.Status().MachineID != got.MachineID {
			t.Fatalf("accepted with the machine id %q", got.MachineID)
		}
		st := got.Status()
		if !strings.HasPrefix(got.Issuer, "https://") || len(got.Keys) == 0 || len(got.Keys) > api.MaxTrustKeys ||
			len(got.Users) == 0 || len(got.Users) > api.MaxTrustUsers || *st.FanWindowS < 0 || *st.FanWindowS > approval.MaxFanWindowS ||
			*st.BootShutdownS < 0 || *st.BootShutdownS > approval.MaxBootShutdownS {
			t.Fatalf("accepted beyond the limits: %+v", st)
		}
		for _, k := range got.Keys {
			if k.Kty != "RSA" || k.Alg != "RS256" || k.E != "AQAB" || len(k.N) < 342 {
				t.Fatalf("accepted key %+v", k)
			}
		}
		again, err := approval.ParseTrust(got.Marshal())
		if err != nil || !reflect.DeepEqual(again.Status(), st) {
			t.Fatalf("does not read back: %v", err)
		}
	})
}
