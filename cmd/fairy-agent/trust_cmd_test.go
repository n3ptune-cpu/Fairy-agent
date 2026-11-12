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
	tr, err := approval.FromInit(approvaltest.New().Init("a", "b", "c"), approvalTestTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	st := tr.Status()
	st.EnforcedBy = api.EnforcedByHelper
	b, _ := json.Marshal(map[string]any{"version": "x", "proto": 3, "approval": st})
	got := strings.Join(helperApprovalLines(b), "\n")
	for _, want := range []string{"pipe protocol:   3", "approval:        required (checked by the helper)", "issuer:          " + approvaltest.IssuerURL,
		"machine id:      " + approvaltest.MachineID + " (names this machine in every approval", "A machine made from a copy of this disk has the SAME id",
		"until the copy's trust is set anew: fairy-agent helper-trust set --new-machine-id",
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
	off, _ := json.Marshal(map[string]any{"proto": 3, "approval": api.ApprovalStatus{State: api.ApprovalOff, EnforcedBy: api.EnforcedByHelper, Proto: api.ApprovalProto}})
	if got := strings.Join(helperApprovalLines(off), "\n"); !strings.Contains(got, "approval:        off (checked by the helper)") {
		t.Errorf("off:\n%s", got)
	}
	broken, _ := json.Marshal(map[string]any{"proto": 3, "approval": api.ApprovalStatus{State: api.ApprovalBroken, EnforcedBy: api.EnforcedByHelper, Error: "not a trust file"}})
	if got := strings.Join(helperApprovalLines(broken), "\n"); !strings.Contains(got, "approval:        broken") || !strings.Contains(got, "not a trust file") {
		t.Errorf("broken:\n%s", got)
	}
	if got := strings.Join(helperApprovalLines([]byte(`{"version":"0.6.0"}`)), "\n"); !strings.Contains(got, "from before passkey approvals") {
		t.Errorf("old helper:\n%s", got)
	}
	// the helper of the test build of 2026-11-11 (pipe protocol 2): what it says about approvals is not shown as
	// if it counted
	b2, _ := json.Marshal(map[string]any{"version": "x", "proto": 2, "approval": st})
	if got := strings.Join(helperApprovalLines(b2), "\n"); !strings.Contains(got, "pipe protocol:   2 (the test build of 2026-11-11; this agent needs 3)") ||
		!strings.Contains(got, "Install this version of both services") || strings.Contains(got, "required") {
		t.Errorf("the test build's helper:\n%s", got)
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
	newHelper := status(map[string]any{"version": "x", "proto": 3, "approval": map[string]any{"state": "off", "enforced_by": "helper", "proto": 2}})
	testBuild := status(map[string]any{"version": "x", "proto": 2, "approval": map[string]any{"state": "off", "enforced_by": "helper", "proto": 1}})
	oldHelper := status(map[string]any{"version": "0.6.0", "features": []string{"power"}, "sleep_ok": true})
	for _, c := range []struct {
		name, state string
		data        []byte
		err         error
		want, never []string
	}{
		{"not Windows", trustNoHelperHere, nil, nil, []string{"In effect within 5 seconds, if the fairy-agent service runs this version", "An older fairy-agent", "Until then what was in effect before still counts"}, []string{"NOT IN EFFECT"}},
		{"the new helper runs", trustHelperAsked, newHelper, nil, []string{"In effect within 5 seconds: the running helper (pipe protocol 3)", "a user or key you just removed can still approve"}, []string{"NOT"}},
		{"the helper of the test build of 2026-11-11 runs (pipe protocol 2)", trustHelperAsked, testBuild, nil,
			[]string{"NOT IN EFFECT IN THE HELPER: the fairy-agent-helper that is running is the test build of 2026-11-11", "(pipe protocol 2)", "503 approval_unavailable", "Install this version of both services"}, []string{"In effect within"}},
		{"the old helper still runs", trustHelperAsked, oldHelper, nil,
			[]string{"NOT IN EFFECT IN THE HELPER YET", "from before passkey approvals", "503 approval_unavailable", "Restart-Service fairy-agent-helper"}, []string{"In effect within"}},
		{"a helper that says proto 3 but reports no approval state", trustHelperAsked, status(map[string]any{"proto": 3}), nil, []string{"NOT IN EFFECT IN THE HELPER YET"}, []string{"In effect within"}},
		{"an answer that is not JSON", trustHelperAsked, []byte("?"), nil, []string{"NOT IN EFFECT IN THE HELPER YET"}, []string{"In effect within"}},
		{"the helper is stopped", api.HelperStopped, nil, nil, []string{"is not running (stopped)", "reads the trust file when it starts"}, []string{"In effect within"}},
		{"no helper installed", api.HelperNotInstalled, nil, nil, []string{"In effect within 5 seconds for what the agent carries out itself"}, []string{"NOT"}},
		{"the helper cannot be asked", "", nil, errors.New("the helper's pipe: access is denied"), []string{"NOT KNOWN whether it is in effect", "access is denied", "pipe protocol:   3"}, []string{"In effect within"}},
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

// TestHelperTrustMachineID (audit 5, r1-x1-01): the machine id is made up by the first set, shown by show
// together with what a copied disk means, kept by every later set, never taken from another machine's file,
// and replaced only when asked (--new-machine-id) or when the trust is cleared and set anew.
func TestHelperTrustMachineID(t *testing.T) {
	r := newTrustRig(t)
	set := func(args ...string) string {
		t.Helper()
		code, out, errs := r.run("", append([]string{"set", "--yes"}, args...)...)
		if code != 0 {
			t.Fatalf("set %v: %d\n%s\n%s", args, code, out, errs)
		}
		return out
	}
	out := set("--issuer", r.issuer.URL, "--client-id", "c", "--user", "user-a")
	id := r.trust().MachineID
	if api.CheckMachineID(id) != nil || len(id) != 22 {
		t.Fatalf("the first set made up the id %q", id)
	}
	if !strings.Contains(out, "machine id:      "+id) || !strings.Contains(out, "the machine id:   new, made up just now") {
		t.Errorf("the first set does not show the id it made up:\n%s", out)
	}
	// show: the id, and what a copied disk means, and what to do on the copy
	code, out, _ := r.run("", "show")
	for _, want := range []string{"machine id:      " + id + " (names this machine in every approval; the panel keeps it on record)",
		"A machine made from a copy of this disk has the SAME id", "accept each other's", "until the copy's trust is set anew: fairy-agent helper-trust set --new-machine-id"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	// every later set keeps it: other users, other keys, other settings
	for _, args := range [][]string{{"--user", "user-b"}, {"--fetch-keys"}, {"--fan-window", "10", "--boot-shutdown", "120"}, {"--client-id", "other"}} {
		out := set(args...)
		if got := r.trust().MachineID; got != id || !strings.Contains(out, "the machine id:   kept as it was") {
			t.Fatalf("set %v: the id is %q, was %q\n%s", args, got, id, out)
		}
	}
	// --from another machine's trust file: its values, not its id
	other, err := approval.FromInit(approvaltest.New().Init("someone-else"), approvalTestTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	from := filepath.Join(t.TempDir(), "other-machine.json")
	if err := os.WriteFile(from, other.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	set("--from", from)
	if tr := r.trust(); tr.MachineID != id || tr.MachineID == other.MachineID || tr.Issuer != approvaltest.IssuerURL || tr.Users[0] != "someone-else" {
		t.Fatalf("set --from: %+v", tr)
	}
	// ... also when that file is one from before machine ids
	other.MachineID = ""
	if err := os.WriteFile(from, other.Marshal(), 0o600); err != nil {
		t.Fatal(err)
	}
	set("--from", from)
	if tr := r.trust(); tr.MachineID != id {
		t.Fatalf("set --from an old file: %+v", tr)
	}
	// --new-machine-id: another one, said loudly, everything else kept
	before := r.trust()
	out = set("--new-machine-id")
	after := r.trust()
	if after.MachineID == id || api.CheckMachineID(after.MachineID) != nil || !strings.Contains(out, "the machine id:   NEW, it was "+id) ||
		!strings.Contains(out, "until the panel is told the new one") {
		t.Fatalf("set --new-machine-id: %q -> %q\n%s", id, after.MachineID, out)
	}
	if after.Issuer != before.Issuer || after.ClientID != before.ClientID || strings.Join(after.Users, ",") != strings.Join(before.Users, ",") ||
		after.Keys[0].N != before.Keys[0].N || after.FanWindow() != before.FanWindow() || after.BootShutdownS != before.BootShutdownS {
		t.Errorf("set --new-machine-id changed more than the id:\n%+v\n%+v", before, after)
	}
	// clear, then set: the trust is set anew, with a new id
	if code, _, _ := r.run("", "clear", "--yes"); code != 0 {
		t.Fatal("clear")
	}
	set("--issuer", r.issuer.URL, "--client-id", "c", "--user", "user-a")
	if got := r.trust().MachineID; got == id || got == after.MachineID || api.CheckMachineID(got) != nil {
		t.Fatalf("after clear and set: %q", got)
	}
	// no random numbers: nothing is written
	if code, _, _ := r.run("", "clear", "--yes"); code != 0 {
		t.Fatal("clear")
	}
	oldNew := trustNewID
	trustNewID = func() (string, error) { return "", errors.New("no random numbers for a machine id") }
	t.Cleanup(func() { trustNewID = oldNew })
	if code, _, errs := r.run("", "set", "--yes", "--issuer", r.issuer.URL, "--client-id", "c", "--user", "user-a"); code != 1 || !strings.Contains(errs, "no random numbers") || r.trust() != nil {
		t.Fatalf("set without random numbers: %d %s", code, errs)
	}
}

// TestHelperTrustWithAFileFromBeforeMachineIDs: the command does not add the id by itself when it only looks
// (show says what is wrong, and that the service adds it at its start); set keeps the file's values and
// writes it with an id.
func TestHelperTrustWithAFileFromBeforeMachineIDs(t *testing.T) {
	r := newTrustRig(t)
	old, err := approval.FromInit(approvaltest.New().Init("user-a", "user-b"), approvalTestTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	old.MachineID = ""
	raw := old.Marshal()
	if err := os.WriteFile(r.files.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, _ := r.run("", "show")
	if code != 0 || !strings.Contains(out, "BROKEN") || !strings.Contains(out, "has no machine_id") || !strings.Contains(out, "adds one when it starts") ||
		!strings.Contains(out, "fairy-agent helper-trust set") {
		t.Fatalf("show: %d\n%s", code, out)
	}
	if now, _ := os.ReadFile(r.files.Path); !bytes.Equal(now, raw) {
		t.Fatal("show wrote the file")
	}
	code, out, errs := r.run("", "set", "--yes", "--jwks", writeJWKS(t, old.Keys))
	if code != 0 || !strings.Contains(out, "the existing trust file has no machine id; its values are kept and it gets one now") ||
		!strings.Contains(out, "the machine id:   new, made up just now") || strings.Contains(out, "will be replaced") {
		t.Fatalf("set: %d\n%s\n%s", code, out, errs)
	}
	tr := r.trust()
	if tr == nil || api.CheckMachineID(tr.MachineID) != nil || tr.Issuer != old.Issuer || tr.ClientID != old.ClientID || strings.Join(tr.Users, ",") != "user-a,user-b" ||
		tr.Keys[0].N != old.Keys[0].N {
		t.Fatalf("after set: %+v", tr)
	}
}

// writeJWKS writes keys as a JWKS file and returns its name.
func writeJWKS(t *testing.T, keys []api.TrustKey) string {
	t.Helper()
	var list []any
	for _, k := range keys {
		list = append(list, map[string]any{"kty": k.Kty, "kid": k.Kid, "alg": k.Alg, "n": k.N, "e": k.E})
	}
	b, _ := json.Marshal(map[string]any{"keys": list})
	name := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(name, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

// The tests do not wait between writing the trust file and looking at it again (writeTrustChecked). This is
// also true for the parts of this test program that the install tests start as other users.
func init() { trustSettle = func() {} }

// legacyTrust is a good trust file from before machine ids, and the trust `helper-trust set` would write in its
// place (one user removed, an id of the command's own).
func legacyTrust(t *testing.T) (raw []byte, old, admins *approval.Trust) {
	t.Helper()
	old, err := approval.FromInit(approvaltest.New().Init("user-a", "user-b"), approvalTestTime, nil)
	if err != nil {
		t.Fatal(err)
	}
	old.MachineID = ""
	raw = old.Marshal()
	admins, err = approval.NewTrust(approval.Trust{MachineID: "admin-made-id-0000000000", Issuer: old.Issuer, ClientID: old.ClientID, Keys: old.Keys,
		Users: old.Users[:1], FanWindowS: old.FanWindowS, SetBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	return raw, old, admins
}

// TestSetIsNotLostToTheServicesMachineID (second review of 8119ea0..ae9384f, N2): the service adds a machine
// id to a trust file from before machine ids by renaming a file of its own over it. When that rename lands
// right after `helper-trust set` has written, the file on disk is the OLD trust with the service's id, and the
// command used to say "written" all the same (it looked at the state only, and the state was "required").
// The command now reads back what it wrote, at once and after a pause, and writes again when something else
// is there.
func TestSetIsNotLostToTheServicesMachineID(t *testing.T) {
	raw, _, admins := legacyTrust(t)
	files := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	onDisk := func() *approval.Trust {
		t.Helper()
		_, tr, _, err := files.Load()
		if err != nil {
			t.Fatal(err)
		}
		return tr
	}
	// the service's late rename, played at the worst moment: after the command's write and its first look
	withID := bytes.Replace(raw, []byte("{\n"), []byte("{\n  \"machine_id\": \"the-services-id-0000000\",\n"), 1)
	if tr, err := approval.ParseTrust(withID); err != nil || len(tr.Users) != 2 {
		t.Fatalf("the service's file: %+v %v", tr, err)
	}
	late := 0
	serviceRenames := func(times int) func() {
		late = 0
		return func() {
			if late++; late <= times {
				if err := os.WriteFile(files.Path, withID, 0o600); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if err := os.WriteFile(files.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	tries, err := writeTrustChecked(files, admins, serviceRenames(1))
	if err != nil || tries != 2 {
		t.Fatalf("one late rename: %d tries, %v", tries, err)
	}
	if tr := onDisk(); tr.MachineID != admins.MachineID || len(tr.Users) != 1 {
		t.Fatalf("the command said written, and on disk is %+v", tr)
	}
	// nothing in the way: one write, two looks
	if tries, err := writeTrustChecked(files, admins, serviceRenames(0)); err != nil || tries != 1 || late != 1 {
		t.Fatalf("nothing in the way: %d tries, %d looks after the pause, %v", tries, late, err)
	}
	// something that replaces the file every time: the command gives up and says that it did not write it
	tries, err = writeTrustChecked(files, admins, serviceRenames(99))
	if err == nil || tries != trustWriteTries || !strings.Contains(err.Error(), "NOT what this command was asked to write") {
		t.Fatalf("a file that is replaced every time: %d tries, %v", tries, err)
	}
	if tr := onDisk(); tr.MachineID == admins.MachineID {
		t.Fatal("the test did not replace the file")
	}
	// a file that cannot be used after the write is said as before
	if err := os.WriteFile(files.Path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	broken := files
	broken.CheckFile = func(string) error { return errors.New("the file belongs to somebody else") }
	if _, err := writeTrustChecked(broken, admins, func() {}); err == nil || !strings.Contains(err.Error(), "was written but cannot be used") {
		t.Fatalf("a file that cannot be used: %v", err)
	}
}

// TestSetRacesTheServicesMachineID is the reviewer's race (TestReviewMigrationRacesAdminSet) in a short form,
// with the command's write in place of a bare Replace: the service adds the id while the command sets the
// trust. Whichever comes first, when the command says "written" the file on disk is the command's. (The pause
// before the command's second look is, here, the end of the service's attempt.)
func TestSetRacesTheServicesMachineID(t *testing.T) {
	if testing.Short() {
		t.Skip("4000 rounds of two writers")
	}
	raw, _, admins := legacyTrust(t)
	dir := t.TempDir()
	files := approval.Files{Path: filepath.Join(dir, approval.TrustFileName)}
	var rewritten, serviceFirst int
	for i := 0; i < 4000; i++ {
		if err := os.WriteFile(files.Path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		start, added := make(chan struct{}), make(chan error, 1)
		go func() {
			<-start
			_, err := files.AddMachineID(nil)
			added <- err
		}()
		close(start)
		for k := 0; k < i%400; k++ { // another delay every round
			_ = k * k
		}
		var addErr error
		waited := false
		wait := func() { // the service's attempt is over (asked at every pause; it ends once)
			if !waited {
				waited, addErr = true, <-added
			}
		}
		tries, err := writeTrustChecked(files, admins, wait)
		wait() // also when the command never came to its pause
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if tries > 1 {
			rewritten++
		}
		if addErr == nil {
			serviceFirst++
		}
		_, tr, got, lerr := files.Load()
		if lerr != nil || !bytes.Equal(got, admins.Marshal()) {
			t.Fatalf("round %d: the command said written after %d tries, and on disk is %+v (%v)", i, tries, tr, lerr)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 1 {
			t.Fatalf("round %d: left behind: %v", i, ents)
		}
	}
	t.Logf("4000 rounds: the service's id went in %d times (and the command replaced that file), the command had to write a second time %d times", serviceFirst, rewritten)
}
