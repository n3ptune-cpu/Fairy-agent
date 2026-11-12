package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// trustRig: a machine's trust folder in a temp folder, and a made-up Pocket ID on https that publishes keys.
type trustRig struct {
	t      *testing.T
	cfg    string
	files  approval.Files
	issuer *httptest.Server
	jwks   map[string]any // what the issuer publishes
	iss    string         // what its discovery document calls it ("": its own address)
	date   string         // the Date of its answers ("": now)
}

func newTrustRig(t *testing.T) *trustRig {
	t.Helper()
	dir := t.TempDir()
	r := &trustRig{t: t, cfg: filepath.Join(dir, "config.yaml"), files: approval.Files{Path: filepath.Join(dir, "state", approval.TrustFileName)}}
	if err := os.WriteFile(r.cfg, []byte("# test\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "state"), 0o700); err != nil {
		t.Fatal(err)
	}
	k0, k1 := approval.KeyFromRSA("key-1", &approvaltest.Key(0).PublicKey), approval.KeyFromRSA("key-2", &approvaltest.Key(1).PublicKey)
	r.jwks = map[string]any{"keys": []any{
		map[string]any{"kty": "RSA", "kid": k0.Kid, "use": "sig", "alg": "RS256", "n": k0.N, "e": k0.E, "x5c": []string{"ignored"}},
		map[string]any{"kty": "EC", "kid": "ec-1", "crv": "P-256", "x": "AA", "y": "AA"},
		map[string]any{"kty": "RSA", "kid": "enc-1", "use": "enc", "n": k1.N, "e": k1.E},
	}}
	r.issuer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		if r.date != "" {
			w.Header().Set("Date", r.date)
		}
		switch q.URL.Path {
		case "/.well-known/openid-configuration":
			iss := r.iss
			if iss == "" {
				iss = r.issuer.URL
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": iss, "jwks_uri": r.issuer.URL + "/.well-known/jwks.json"})
		case "/.well-known/jwks.json":
			_ = json.NewEncoder(w).Encode(r.jwks)
		default:
			http.NotFound(w, q)
		}
	}))
	t.Cleanup(r.issuer.Close)
	oldFiles, oldAdmin, oldHTTP := trustFiles, trustIsAdmin, trustHTTPClient
	trustFiles = func(*agent.Config) approval.Files { return r.files }
	trustIsAdmin = func() bool { return true }
	trustHTTPClient = func() *http.Client {
		c := r.issuer.Client()
		c.CheckRedirect = oldHTTP().CheckRedirect
		return c
	}
	t.Cleanup(func() { trustFiles, trustIsAdmin, trustHTTPClient = oldFiles, oldAdmin, oldHTTP })
	return r
}

func (r *trustRig) run(stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := helperTrustCmd(append(args, "--config", r.cfg), strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func (r *trustRig) trust() *approval.Trust {
	_, t, _, _ := r.files.Load()
	return t
}

func TestHelperTrustSetShowClear(t *testing.T) {
	r := newTrustRig(t)
	if code, out, _ := r.run("", "show"); code != 0 || !strings.Contains(out, "approval:        off") || !strings.Contains(out, "the panel can set the trust once") {
		t.Fatalf("show without a file: %d\n%s", code, out)
	}
	// what is needed is said
	if code, _, errs := r.run("", "set", "--issuer", r.issuer.URL); code != 1 || !strings.Contains(errs, "--client-id") || !strings.Contains(errs, "--user") {
		t.Fatalf("set with too little: %d %s", code, errs)
	}
	// set: fetches the keys, shows them, asks; "no" changes nothing
	args := []string{"set", "--issuer", r.issuer.URL, "--client-id", "fairy-pc-actions", "--user", "user-a", "--user", "user-b"}
	code, out, _ := r.run("no\n", args...)
	thumb := approval.Thumbprint(approval.KeyFromRSA("key-1", &approvaltest.Key(0).PublicKey))
	for _, want := range []string{"to be written:", "issuer:          " + r.issuer.URL, "client id:       fairy-pc-actions", "kid key-1, RS256, thumbprint " + thumb,
		"allowed users:   2", "may approve:    user-a", "fan window:      30 s", "shutdown after boot: off", "fetched just now from " + r.issuer.URL,
		`key "ec-1" left out`, `key "enc-1" left out: not a signing key`, "[yes/no]", "nothing changed"} {
		if !strings.Contains(out, want) {
			t.Errorf("set, answered no: output lacks %q:\n%s", want, out)
		}
	}
	if code != 1 || r.trust() != nil {
		t.Fatalf("set answered with no: code %d, trust %+v", code, r.trust())
	}
	code, out, errs := r.run("yes\n", args...)
	if code != 0 || !strings.Contains(out, "written.") {
		t.Fatalf("set: %d\n%s\n%s", code, out, errs)
	}
	// the command proves nothing, and says so; the clocks agree, so nothing is said about them
	if !strings.Contains(out, "NOT PROVEN") || !strings.Contains(out, "fairy-agent helper-trust clear") || strings.Contains(out, "THE CLOCK") {
		t.Errorf("set: the output does not say that nothing was proven (or warns about the clock):\n%s", out)
	}
	tr := r.trust()
	if tr == nil || tr.Issuer != r.issuer.URL || tr.ClientID != "fairy-pc-actions" || len(tr.Keys) != 1 || tr.Keys[0].Kid != "key-1" ||
		strings.Join(tr.Users, ",") != "user-a,user-b" || tr.FanWindow() != 30 || tr.BootShutdownS != 0 || tr.SetBy != "admin" {
		t.Fatalf("trust: %+v", tr)
	}
	raw, _ := os.ReadFile(r.files.Path)
	if strings.Contains(string(raw), "x5c") || strings.Contains(string(raw), `"use"`) {
		t.Errorf("the trust file holds more of the JWKS than the key:\n%s", raw)
	}
	// the gate believes this file: a token of the issuer's key 0 for client fairy-pc-actions, user-a
	// (checked in pkg/approval); here: the status a running helper or agent would show
	if st := tr.Status(); st.State != api.ApprovalRequired || st.Users != 2 || st.Keys[0].Thumbprint != thumb {
		t.Fatalf("status: %+v", st)
	}

	// a change of one setting keeps the rest and does not go to the network
	r.issuer.Close()
	if code, out, errs := r.run("", "set", "--fan-window", "0", "--boot-shutdown", "600", "--yes"); code != 0 || !strings.Contains(out, "kept from the existing trust file") {
		t.Fatalf("set --fan-window: %d\n%s\n%s", code, out, errs)
	}
	tr = r.trust()
	if tr.FanWindow() != 0 || tr.BootShutdownS != 600 || tr.Issuer == "" || len(tr.Users) != 2 || len(tr.Keys) != 1 {
		t.Fatalf("after the change: %+v", tr)
	}
	code, out, _ = r.run("", "show")
	for _, want := range []string{"approval:        required", "fan window:      off", "ONE shutdown without approval while the machine has been up for less than 600 s", "set by:          admin"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	// limits are the same as everywhere
	for _, bad := range [][]string{{"--fan-window", "61"}, {"--boot-shutdown", "901"}, {"--issuer", "http://id.test.invalid"}, {"--user", "a b"}, {"--client-id", `a"b`}} {
		if code, _, errs := r.run("", append([]string{"set", "--yes"}, bad...)...); code != 1 || errs == "" {
			t.Errorf("set %v: code %d", bad, code)
		}
	}
	if r.trust().FanWindow() != 0 {
		t.Fatal("a refused set changed the file")
	}

	// a key rotation with overlap: the new key from a file, the old one kept
	next := approval.KeyFromRSA("key-2", &approvaltest.Key(1).PublicKey)
	jw := filepath.Join(t.TempDir(), "jwks.json")
	// some issuers write the modulus with a leading zero byte
	padded := approvaltest.B64(append([]byte{0}, approvaltest.Key(1).PublicKey.N.Bytes()...))
	b, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": next.Kid, "n": padded, "e": next.E}}})
	_ = os.WriteFile(jw, b, 0o600)
	if code, out, errs := r.run("", "set", "--jwks", jw, "--keep-old-keys", "--yes"); code != 0 {
		t.Fatalf("set --jwks --keep-old-keys: %d\n%s\n%s", code, out, errs)
	}
	if tr = r.trust(); len(tr.Keys) != 2 || tr.Keys[0].Kid != "key-2" || tr.Keys[0].N != next.N || tr.Keys[1].Kid != "key-1" {
		t.Fatalf("after the rotation: %+v", tr.Keys)
	}
	// without --keep-old-keys only the new one stays
	if code, _, errs := r.run("", "set", "--jwks", jw, "--yes"); code != 0 || len(r.trust().Keys) != 1 {
		t.Fatalf("set --jwks: %d %s", code, errs)
	}

	// clear: asks; afterwards the first-time set is open again and the output says so
	if code, out, _ := r.run("no\n", "clear"); code != 1 || r.trust() == nil || !strings.Contains(out, "nothing changed") {
		t.Fatalf("clear answered with no: %d\n%s", code, out)
	}
	if code, out, errs := r.run("yes\n", "clear"); code != 0 || !strings.Contains(out, "the panel can now set trust again") {
		t.Fatalf("clear: %d\n%s\n%s", code, out, errs)
	}
	if st, _, _, _ := r.files.Load(); st != api.ApprovalOff {
		t.Fatalf("state after clear: %s", st)
	}
	if code, out, _ := r.run("", "clear"); code != 0 || !strings.Contains(out, "there is no trust file") {
		t.Fatalf("second clear: %d\n%s", code, out)
	}
}

func TestHelperTrustRefusals(t *testing.T) {
	r := newTrustRig(t)
	args := []string{"set", "--yes", "--client-id", "c", "--user", "u", "--issuer"}
	// the issuer calls itself something else (a trailing slash, another host)
	r.iss = r.issuer.URL + "/"
	if code, _, errs := r.run("", append(args, r.issuer.URL)...); code != 1 || !strings.Contains(errs, "calls itself") {
		t.Errorf("issuer with another name: %d %s", code, errs)
	}
	r.iss = ""
	// no usable key
	r.jwks = map[string]any{"keys": []any{map[string]any{"kty": "OKP", "kid": "ed", "crv": "Ed25519", "x": "AA"}}}
	if code, _, errs := r.run("", append(args, r.issuer.URL)...); code != 1 || !strings.Contains(errs, "no RSA signing key") {
		t.Errorf("issuer without an RSA key: %d %s", code, errs)
	}
	// a key that is too small
	small := approval.KeyFromRSA("small", &mustSmallKey(t).PublicKey)
	r.jwks = map[string]any{"keys": []any{map[string]any{"kty": "RSA", "kid": small.Kid, "n": small.N, "e": small.E}}}
	if code, _, errs := r.run("", append(args, r.issuer.URL)...); code != 1 || !strings.Contains(errs, "1024 bits") {
		t.Errorf("small key: %d %s", code, errs)
	}
	// plain http is never fetched
	if code, _, errs := r.run("", append(args, "http://127.0.0.1:1")...); code != 1 {
		t.Errorf("http issuer: %d %s", code, errs)
	}
	if r.trust() != nil {
		t.Fatal("a refused set wrote a trust file")
	}
	// not an administrator
	trustIsAdmin = func() bool { return false }
	for _, sub := range []string{"set", "clear"} {
		if code, _, errs := r.run("", sub, "--yes"); code != 1 || !strings.Contains(errs, "Administrator") {
			t.Errorf("%s as an ordinary user: %d %s", sub, code, errs)
		}
	}
	if code, _, _ := r.run("", "show"); code != 0 {
		t.Error("show as an ordinary user")
	}
	// a broken file: show says so, set replaces it
	trustIsAdmin = func() bool { return true }
	_ = os.WriteFile(r.files.Path, []byte("{"), 0o600)
	if code, out, _ := r.run("", "show"); code != 0 || !strings.Contains(out, "BROKEN") {
		t.Errorf("show with a broken file: %d\n%s", code, out)
	}
	for _, usage := range [][]string{{}, {"sett"}, {"set", "extra"}, {"show", "--nope"}} {
		var out, errb bytes.Buffer
		if code := helperTrustCmd(usage, strings.NewReader(""), &out, &errb); code != 2 {
			t.Errorf("%v: code %d", usage, code)
		}
	}
}

func TestHelperStatusApprovalLines(t *testing.T) {
	tr, err := approval.FromInit(approvaltest.New().Init("a", "b", "c"), approvalTestTime)
	if err != nil {
		t.Fatal(err)
	}
	st := tr.Status()
	st.EnforcedBy = api.EnforcedByHelper
	b, _ := json.Marshal(map[string]any{"version": "x", "proto": 2, "approval": st})
	got := strings.Join(helperApprovalLines(b), "\n")
	for _, want := range []string{"pipe protocol:   2", "approval:        required (checked by the helper)", "issuer:          " + approvaltest.IssuerURL,
		"client id:       " + approvaltest.ClientID, "kid " + approvaltest.Kid + ", RS256, thumbprint ", "allowed users:   3", "fan window:      30 s", "shutdown after boot: off"} {
		if !strings.Contains(got, want) {
			t.Errorf("helper-status lacks %q:\n%s", want, got)
		}
	}
	for _, u := range []string{"\na\n", approvaltest.User, tr.Keys[0].N} {
		if strings.Contains(got, u) {
			t.Errorf("helper-status shows a user or a whole key:\n%s", got)
		}
	}
	off, _ := json.Marshal(map[string]any{"proto": 2, "approval": api.ApprovalStatus{State: api.ApprovalOff, EnforcedBy: api.EnforcedByHelper, Proto: 1}})
	if got := strings.Join(helperApprovalLines(off), "\n"); !strings.Contains(got, "approval:        off (checked by the helper)") {
		t.Errorf("off:\n%s", got)
	}
	broken, _ := json.Marshal(map[string]any{"proto": 2, "approval": api.ApprovalStatus{State: api.ApprovalBroken, EnforcedBy: api.EnforcedByHelper, Error: "not a trust file"}})
	if got := strings.Join(helperApprovalLines(broken), "\n"); !strings.Contains(got, "approval:        broken") || !strings.Contains(got, "not a trust file") {
		t.Errorf("broken:\n%s", got)
	}
	if got := strings.Join(helperApprovalLines([]byte(`{"version":"0.6.0"}`)), "\n"); !strings.Contains(got, "from before passkey approvals") {
		t.Errorf("old helper:\n%s", got)
	}
}

var approvalTestTime = time.Unix(1794000000, 0)

func mustSmallKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestHelperTrustSetWarnsAboutTheClock: when the keys are fetched from the issuer, its answer carries its time.
// A machine whose clock is more than a minute away from it would refuse every approval after the set; the
// command says so before it writes.
func TestHelperTrustSetWarnsAboutTheClock(t *testing.T) {
	r := newTrustRig(t)
	args := []string{"set", "--yes", "--issuer", r.issuer.URL, "--client-id", "c", "--user", "u"}
	r.date = time.Now().Add(-10 * time.Minute).UTC().Format(http.TimeFormat)
	code, out, errs := r.run("", args...)
	if code != 0 || !strings.Contains(out, "THE CLOCK") || !strings.Contains(out, "differ by about 6") || !strings.Contains(out, "more than 60 s") {
		t.Fatalf("issuer's clock 10 minutes behind: %d\n%s\n%s", code, out, errs)
	}
	for _, c := range []struct {
		issuer, now time.Time
		warn        bool
	}{
		{time.Unix(1000, 0), time.Unix(1000, 0), false},
		{time.Unix(1000, 0), time.Unix(1040, 0), false},
		{time.Unix(1000, 0), time.Unix(1046, 0), true},
		{time.Unix(1046, 0), time.Unix(1000, 0), true},
		{time.Unix(1000, 0), time.Unix(5000, 0), true},
		{time.Time{}, time.Unix(5000, 0), false}, // the issuer sent no Date
	} {
		if got := clockNote(c.issuer, c.now) != ""; got != c.warn {
			t.Errorf("issuer %d, machine %d: warned %v, want %v", c.issuer.Unix(), c.now.Unix(), got, c.warn)
		}
	}
}

// TestHelperTrustSetSaysWhatIsInEffect (audit 5, r1-a1-01): `helper-trust set` used to end with "In effect
// within 5 seconds" whatever ran on the machine. With a helper from before passkey approvals still running (an
// update that did not restart it) nothing was in effect at all. The command now says what is true for what
// runs next to the file.
func TestHelperTrustSetSaysWhatIsInEffect(t *testing.T) {
	status := func(v map[string]any) []byte { b, _ := json.Marshal(v); return b }
	newHelper := status(map[string]any{"version": "x", "proto": 2, "approval": map[string]any{"state": "off", "enforced_by": "helper", "proto": 1}})
	oldHelper := status(map[string]any{"version": "0.6.0", "features": []string{"power"}, "sleep_ok": true})
	for _, c := range []struct {
		name, state string
		data        []byte
		err         error
		want, never []string
	}{
		{"not Windows", trustNoHelperHere, nil, nil, []string{"In effect within 5 seconds, if the fairy-agent service runs this version", "An older fairy-agent"}, []string{"NOT IN EFFECT"}},
		{"the new helper runs", trustHelperAsked, newHelper, nil, []string{"In effect within 5 seconds: the running helper (pipe protocol 2)"}, []string{"NOT"}},
		{"the old helper still runs", trustHelperAsked, oldHelper, nil,
			[]string{"NOT IN EFFECT IN THE HELPER YET", "from before passkey approvals", "503 approval_unavailable", "Restart-Service fairy-agent-helper"}, []string{"In effect within"}},
		{"a helper that says proto 2 but reports no approval state", trustHelperAsked, status(map[string]any{"proto": 2}), nil, []string{"NOT IN EFFECT IN THE HELPER YET"}, []string{"In effect within"}},
		{"an answer that is not JSON", trustHelperAsked, []byte("?"), nil, []string{"NOT IN EFFECT IN THE HELPER YET"}, []string{"In effect within"}},
		{"the helper is stopped", api.HelperStopped, nil, nil, []string{"is not running (stopped)", "reads the trust file when it starts"}, []string{"In effect within"}},
		{"no helper installed", api.HelperNotInstalled, nil, nil, []string{"In effect within 5 seconds for what the agent carries out itself"}, []string{"NOT"}},
		{"the helper cannot be asked", "", nil, errors.New("the helper's pipe: access is denied"), []string{"NOT KNOWN whether it is in effect", "access is denied", "pipe protocol:   2"}, []string{"In effect within"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newTrustRig(t)
			old := trustHelper
			trustHelper = func() (string, []byte, error) { return c.state, c.data, c.err }
			t.Cleanup(func() { trustHelper = old })
			code, out, errs := r.run("", "set", "--yes", "--issuer", r.issuer.URL, "--client-id", "c", "--user", "u")
			if code != 0 || !strings.Contains(out, "written. From now on only this command changes it") {
				t.Fatalf("set: %d\n%s\n%s", code, out, errs)
			}
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, n := range c.never {
				if strings.Contains(strings.SplitN(out, "NOT PROVEN", 2)[0], n) {
					t.Errorf("output says %q:\n%s", n, out)
				}
			}
			if r.trust() == nil {
				t.Fatal("the trust file was not written")
			}
		})
	}
}

// TestHelperTrustShowsWhoseTrustItIs (audit 5, r1-a2-05): show prints the hash a panel compares with its own
// (issuer, client id, keys, users) and how the file came to be; clear says that the first-time set it opens
// again is open to whoever holds the control token.
func TestHelperTrustShowsWhoseTrustItIs(t *testing.T) {
	r := newTrustRig(t)
	if code, out, errs := r.run("", "set", "--yes", "--issuer", r.issuer.URL, "--client-id", "c", "--user", "user-a", "--user", "user-b"); code != 0 {
		t.Fatalf("set: %d\n%s\n%s", code, out, errs)
	}
	tr := r.trust()
	want := api.TrustHash(api.TrustInit{Issuer: tr.Issuer, ClientID: tr.ClientID, Keys: tr.Keys, Users: tr.Users})
	code, out, _ := r.run("", "show")
	if code != 0 || !strings.Contains(out, "trust hash:      "+want) || !strings.Contains(out, "set by:          admin, ") || !strings.Contains(out, "on this machine") {
		t.Fatalf("show: %d\n%s", code, out)
	}
	if st := tr.Status(); st.TrustHash != want || st.SetBy != "admin" || st.SetAt == "" {
		t.Fatalf("status: %+v", st)
	}
	// another user list, the same count: another hash
	if code, out, errs := r.run("", "set", "--yes", "--user", "user-a", "--user", "user-c"); code != 0 {
		t.Fatalf("set: %d\n%s\n%s", code, out, errs)
	}
	if got := r.trust().Status(); got.TrustHash == want || got.Users != 2 {
		t.Fatalf("status after the user list changed: %+v", got)
	}
	code, out, _ = r.run("", "clear", "--yes")
	if code != 0 || !strings.Contains(out, "removed. Approval is off") || !strings.Contains(out, "whoever holds the control token") {
		t.Fatalf("clear: %d\n%s", code, out)
	}
}
