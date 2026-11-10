package agent

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

type pairRig struct {
	path  string
	srv   *httptest.Server
	now   time.Time
	p     *Pairer
	proof string
	code  string
	key   []byte // the v2 pairing key of code (stored in the state only by newPairRigV2)
}

// newPairRig serves an agent whose pairing state holds a fresh code for the panel at 127.0.0.1 (httptest's
// client address) unless panel says otherwise.
func newPairRig(t *testing.T, cfgYAML, panel string) *pairRig {
	t.Helper()
	cfg := mustParse(t, cfgYAML)
	code, err := enroll.NewCode()
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := enroll.Proof(code)
	key, _ := enroll.PairingKey(code)
	r := &pairRig{path: filepath.Join(t.TempDir(), "pairing.json"), now: time.Unix(1_800_000_000, 0), proof: proof, code: code, key: key}
	st := enroll.State{Version: 1, Verifier: enroll.Verifier(proof), Panel: panel, CreatedAt: r.now.Unix(),
		ExpiresAt: r.now.Add(enroll.TTL).Unix()}
	if err := enroll.WriteState(r.path, st); err != nil {
		t.Fatal(err)
	}
	tok := Tokens{Read: readTok}
	if cfg.ControlEnabled() {
		tok.Control = ctlTok
	}
	d := Deps{Collector: agenttest.NewCollector(), Version: "test"}
	if cfg.PowerControl.Enabled {
		d.Power = NewPower(&agenttest.PowerExec{}, cfg.PowerControl.MinDelayS)
	}
	var a *Agent
	r.p = NewPairer(r.path, func() (Tokens, error) { return tok, nil }, func() enroll.Response { return a.PairInfo() })
	r.p.Now = func() time.Time { return r.now }
	d.Pairer = r.p
	a = New(cfg, tok, d)
	r.srv = httptest.NewServer(a.Handler())
	t.Cleanup(r.srv.Close)
	return r
}

func (r *pairRig) pair(t *testing.T, proof string) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(enroll.Request{Proof: proof})
	resp, err := http.Post(r.srv.URL+enroll.Path, "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp.StatusCode, m
}

func TestPairOnce(t *testing.T) {
	r := newPairRig(t, "power_control: {enabled: true}\n", "127.0.0.1")
	st, body := r.pair(t, r.proof)
	if st != 200 || body["token"] != readTok || body["control_token"] != ctlTok || body["agent_version"] != "test" {
		t.Fatalf("pair: %d %v", st, body)
	}
	if f, _ := body["features"].(map[string]any); f["power_control"] != true {
		t.Fatalf("features: %v", body["features"])
	}
	// never again, not even with the right code
	if st, body := r.pair(t, r.proof); st != 404 || body["code"] != "pairing_inactive" {
		t.Fatalf("second pair: %d %v", st, body)
	}
	s, err := enroll.ReadState(r.path)
	if err != nil || s.Closed != "paired" || s.Verifier != "" || s.PairedBy != "127.0.0.1" {
		t.Fatalf("state after pairing: %+v %v", s, err)
	}
	// the read token still works for /metrics, /pair did not change anything else
	resp, _ := http.Get(r.srv.URL + "/metrics")
	if resp.StatusCode != 401 {
		t.Fatalf("metrics without token: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestPairNoControlTokenWhenReadOnly(t *testing.T) {
	r := newPairRig(t, "", "")
	st, body := r.pair(t, r.proof)
	if st != 200 || body["token"] != readTok {
		t.Fatalf("pair: %d %v", st, body)
	}
	if _, ok := body["control_token"]; ok {
		t.Fatalf("control token sent although no control feature is on: %v", body)
	}
}

func TestPairWrongAddressExpiredAndMissing(t *testing.T) {
	r := newPairRig(t, "", "100.88.109.47")
	if st, body := r.pair(t, r.proof); st != 403 || body["code"] != "wrong_address" {
		t.Fatalf("other address: %d %v", st, body)
	}
	if s, _ := enroll.ReadState(r.path); s.Failures != 0 || !s.Active(r.now) {
		t.Fatalf("a request from elsewhere must not use up the code: %+v", s)
	}

	r = newPairRig(t, "", "127.0.0.1")
	r.now = r.now.Add(enroll.TTL + time.Second)
	if st, _ := r.pair(t, r.proof); st != 404 {
		t.Fatalf("expired: %d", st)
	}

	r = newPairRig(t, "", "127.0.0.1")
	r.p.Path = filepath.Join(t.TempDir(), "none.json")
	if st, _ := r.pair(t, r.proof); st != 404 {
		t.Fatalf("no state file: %d", st)
	}
	var nilPairer *Pairer
	rec := httptest.NewRecorder()
	nilPairer.ServeHTTP(rec, httptest.NewRequest("POST", enroll.Path, strings.NewReader(`{"proof":"x"}`)))
	if rec.Code != 404 {
		t.Fatalf("nil pairer: %d", rec.Code)
	}
}

func TestPairWrongCodesAndRateLimit(t *testing.T) {
	r := newPairRig(t, "", "127.0.0.1")
	other, _ := enroll.NewCode()
	bad, _ := enroll.Proof(other)
	for i := 0; i < enroll.RatePerMin; i++ {
		if st, body := r.pair(t, bad); st != 403 || body["code"] != "wrong_code" {
			t.Fatalf("wrong code %d: %d %v", i, st, body)
		}
	}
	if st, _ := r.pair(t, r.proof); st != 429 {
		t.Fatalf("6th request in a minute: %d, want 429", st)
	}
	// after enroll.MaxFailures wrong codes pairing is closed for good
	r.p.limit = newLimiter(100, time.Minute)
	for i := enroll.RatePerMin; i < enroll.MaxFailures; i++ {
		r.pair(t, bad)
	}
	if st, _ := r.pair(t, r.proof); st != 404 {
		t.Fatalf("after %d wrong codes the right one must not work: %d", enroll.MaxFailures, st)
	}
	if s, _ := enroll.ReadState(r.path); s.Closed != "too many wrong codes" || s.Verifier != "" {
		t.Fatalf("state: %+v", s)
	}
}

// from sends one POST /pair straight to the handler as if it came from addr (httptest's server only ever
// connects from 127.0.0.1).
func (r *pairRig) from(addr, ctype, body string) (int, map[string]any) {
	req := httptest.NewRequest(http.MethodPost, enroll.Path, strings.NewReader(body))
	req.RemoteAddr = net.JoinHostPort(addr, "40000")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	r.p.ServeHTTP(rec, req)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m
}

// L15: the budget used to be one for everybody and was counted before the address check, so any machine that
// reached the port could keep the panel out for the whole Add host window.
func TestPairBudgetOfOthersDoesNotStopThePanel(t *testing.T) {
	const panel = "100.88.109.47"
	r := newPairRig(t, "", panel)
	good := `{"proof":"` + r.proof + `"}`
	// one machine, 100 requests, any content: refused, and after its own budget not even looked at
	seen := map[int]int{}
	for i := 0; i < 100; i++ {
		st, _ := r.from("100.99.0.5", "application/json", good)
		seen[st]++
	}
	if seen[403] != enroll.RatePerMin || seen[429] != 100-enroll.RatePerMin || len(seen) != 2 {
		t.Fatalf("one other address: %v", seen)
	}
	// many machines: the shared budget of the others ends, the table of addresses stays small
	seen = map[int]int{}
	for i := 0; i < 300; i++ {
		st, _ := r.from(fmt.Sprintf("100.99.%d.%d", 1+i/200, 1+i%200), "application/json", `{"proof":"x"}`)
		seen[st]++
	}
	if seen[403] != pairOthersPerMin-enroll.RatePerMin || seen[403]+seen[429] != 300 {
		t.Fatalf("many other addresses: %v", seen)
	}
	if n := len(r.p.each.hits); n > pairOthersPerMin {
		t.Fatalf("%d addresses remembered, want at most %d", n, pairOthersPerMin)
	}
	if s, _ := enroll.ReadState(r.path); s.Failures != 0 || !s.Active(r.now) {
		t.Fatalf("requests from elsewhere must not use up the code: %+v", s)
	}
	// the panel is not affected: its first request pairs
	st, body := r.from(panel, "application/json", good)
	if st != 200 || body["token"] != readTok {
		t.Fatalf("the panel after the flood: %d %v", st, body)
	}
}

// The panel's own budget is still enroll.RatePerMin a minute, and other addresses are told so independently.
func TestPairPanelBudgetIsItsOwn(t *testing.T) {
	const panel = "100.88.109.47"
	r := newPairRig(t, "", panel)
	for i := 0; i < enroll.RatePerMin; i++ {
		if st, body := r.from(panel, "application/json", `{"proof":"x"}`); st != 403 || body["code"] != "wrong_code" {
			t.Fatalf("%d: %d %v", i, st, body)
		}
	}
	if st, body := r.from(panel, "application/json", `{"proof":"`+r.proof+`"}`); st != 429 || body["code"] != "rate_limited" {
		t.Fatalf("the panel over its budget: %d %v", st, body)
	}
	if st, body := r.from("100.99.0.5", "application/json", `{}`); st != 403 || body["code"] != "wrong_address" {
		t.Fatalf("another address while the panel is over its budget: %d %v", st, body)
	}
}

// Only JSON is looked at (the panel has always sent it): a web page cannot make a browser on the panel's
// machine send JSON to this port without a preflight, which the agent does not answer.
func TestPairNeedsJSONContentType(t *testing.T) {
	r := newPairRig(t, "", "127.0.0.1")
	good := `{"proof":"` + r.proof + `"}`
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "multipart/form-data; boundary=x", "application/jsonx", "json"} {
		for i := 0; i < 2*enroll.RatePerMin; i++ { // not counted either
			if st, body := r.from("127.0.0.1", ct, good); st != 415 || body["code"] != "unsupported_media_type" {
				t.Fatalf("Content-Type %q: %d %v", ct, st, body)
			}
		}
	}
	if s, _ := enroll.ReadState(r.path); s.Failures != 0 || !s.Active(r.now) {
		t.Fatalf("state changed: %+v", s)
	}
	if st, _ := r.from("127.0.0.1", "application/json; charset=utf-8", good); st != 200 {
		t.Fatalf("JSON with a charset: %d", st)
	}
}

func TestPairTokensUnreadableKeepsCode(t *testing.T) {
	r := newPairRig(t, "", "127.0.0.1")
	r.p.Tokens = func() (Tokens, error) { return Tokens{}, errors.New("no token file") }
	if st, _ := r.pair(t, r.proof); st != 500 {
		t.Fatalf("want 500, got %d", st)
	}
	if s, _ := enroll.ReadState(r.path); !s.Active(r.now) {
		t.Fatalf("a failed pairing must keep the code usable: %+v", s)
	}
	if st, _ := r.pair(t, "x"); st != 403 {
		t.Fatalf("garbage proof: %d", st)
	}
	if st, _ := r.pair(t, ""); st != 400 {
		t.Fatalf("empty proof: %d", st)
	}
	resp, _ := http.Get(r.srv.URL + enroll.Path)
	if resp.StatusCode != 405 {
		t.Fatalf("GET /pair: %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestListenAddrWaitsForTailscale(t *testing.T) {
	if _, ok := TailscaleIP(systemAddrs()); ok || countTailnet(systemAddrs()) > 0 {
		t.Skip("this machine has a Tailscale-looking address")
	}
	cfg := mustParse(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := ListenAddr(ctx, cfg, WaitForever); !errors.Is(err, context.DeadlineExceeded) || time.Since(start) < 150*time.Millisecond {
		t.Fatalf("WaitForever must wait until the context ends: %v after %v", err, time.Since(start))
	}
	if _, err := ListenAddr(context.Background(), cfg, 0); err == nil || !strings.Contains(err.Error(), "no Tailscale address") {
		t.Fatalf("wait 0: %v", err)
	}
	two := []IfaceAddr{{"tailscale0", net.ParseIP("100.64.0.1")}, {"tailscale1", net.ParseIP("100.64.0.2")}}
	if countTailnet(two) != 2 {
		t.Fatal("countTailnet")
	}
}

// A Proxmox VE node's token (install.sh --proxmox) goes to the panel exactly once, with the agent's tokens, and
// is gone from the pairing state before it leaves; an expired code takes it away too.
func TestPairHandsTheProxmoxTokenOutOnce(t *testing.T) {
	grant := &enroll.ProxmoxGrant{TokenID: "fairy@pve!panel-asus-i7", TokenSecret: "0b7c4e2a-1111-2222-3333-444455556666",
		CAPEM: "-----BEGIN CERTIFICATE-----\n...\n", Node: "asus-i7", URL: "https://asus-i7.ts.net:8006", ServerName: "asus-i7"}
	addGrant := func(r *pairRig) {
		s, _ := enroll.ReadState(r.path)
		s.Proxmox = grant
		if err := enroll.WriteState(r.path, s); err != nil {
			t.Fatal(err)
		}
	}
	r := newPairRig(t, "", "127.0.0.1")
	addGrant(r)
	st, body := r.pair(t, r.proof)
	px, _ := body["proxmox"].(map[string]any)
	if st != 200 || px["token_secret"] != grant.TokenSecret || px["token_id"] != grant.TokenID || px["node"] != "asus-i7" || px["server_name"] != "asus-i7" {
		t.Fatalf("%d %v", st, body)
	}
	if s, _ := enroll.ReadState(r.path); s.Proxmox != nil || s.Closed != "paired" {
		t.Fatalf("the token stayed on disk: %+v", s)
	}
	// without a grant: no proxmox key at all
	r2 := newPairRig(t, "", "127.0.0.1")
	if _, body := r2.pair(t, r2.proof); body["proxmox"] != nil {
		t.Fatal(body)
	}
	// expired: wiped on the next request
	r3 := newPairRig(t, "", "127.0.0.1")
	addGrant(r3)
	r3.now = r3.now.Add(enroll.TTL + time.Minute)
	if st, _ := r3.pair(t, r3.proof); st != 404 {
		t.Fatal(st)
	}
	if s, _ := enroll.ReadState(r3.path); s.Proxmox != nil {
		t.Fatal("expired grant kept")
	}
}

// A join code that runs out unused leaves nothing made from it in the state file: not the v2 pairing key (it
// opens a recorded pairing answer), not the v1 verifier, not a Proxmox token secret. Nobody has to ask for
// that: the running agent sweeps by itself.
func TestExpiredJoinCodeIsWipedFromTheState(t *testing.T) {
	grant := &enroll.ProxmoxGrant{TokenID: "fairy@pve!panel-x", TokenSecret: "0b7c4e2a-1111-2222-3333-444455556666", Node: "x"}
	for name, mk := range map[string]func(t *testing.T) *pairRig{
		"v1": func(t *testing.T) *pairRig { return newPairRig(t, "", "127.0.0.1") },
		"v2": func(t *testing.T) *pairRig { return newPairRigV2(t, "", "127.0.0.1") },
		"v2 with a Proxmox token": func(t *testing.T) *pairRig {
			r := newPairRigV2(t, "", "127.0.0.1")
			s, _ := enroll.ReadState(r.path)
			s.Proxmox = grant
			_ = enroll.WriteState(r.path, s)
			return r
		},
	} {
		r := mk(t)
		before, _ := os.ReadFile(r.path)
		// while the code is good nothing is touched, however often the sweep runs
		for _, d := range []time.Duration{0, time.Minute, enroll.TTL - time.Second} {
			r.now = time.Unix(1_800_000_000, 0).Add(d)
			if r.p.Sweep() {
				t.Fatalf("%s: swept a live code after %s", name, d)
			}
		}
		if now, _ := os.ReadFile(r.path); !bytes.Equal(now, before) {
			t.Fatalf("%s: the state of a live code was rewritten", name)
		}
		// expired: the sweep alone (no /pair request) removes it
		r.now = time.Unix(1_800_000_000, 0).Add(enroll.TTL)
		if !r.p.Sweep() {
			t.Fatalf("%s: not swept", name)
		}
		raw, _ := os.ReadFile(r.path)
		s, err := enroll.ReadState(r.path)
		if err != nil || s.Verifier != "" || s.Key2 != "" || s.Proxmox != nil || s.PairVersion() != 0 {
			t.Fatalf("%s: left in the state: %s (%v)", name, raw, err)
		}
		for _, secret := range []string{hex.EncodeToString(r.key), enroll.Verifier(r.proof), r.proof, grant.TokenSecret, "key2", "verifier", "token_secret"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatalf("%s: %q is still in the file: %s", name, secret, raw)
			}
		}
		// what is left says what happened, for pair-status and the installer
		if !strings.HasPrefix(s.Closed, ExpiredUnused+" at 2027-") || s.Panel != "127.0.0.1" || s.Active(r.now) {
			t.Fatalf("%s: %+v", name, s)
		}
		if d := s.Describe(r.now); !strings.Contains(d, "expired unused") || !strings.Contains(d, "make a new code in the panel") {
			t.Fatalf("%s: pair-status would say %q", name, d)
		}
		if fi, _ := os.Stat(r.path); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v", name, fi.Mode())
		}
		// once is enough: the file is not written again
		if r.p.Sweep() {
			t.Fatalf("%s: swept twice", name)
		}
		// and the right code no longer pairs, with either version
		if st, _ := r.pair(t, r.proof); st != 404 {
			t.Fatalf("%s: v1 after expiry: %d", name, st)
		}
		if st, _, _, _ := panelPairV2(t, r.srv.URL, r.key); st != 404 {
			t.Fatalf("%s: v2 after expiry: %d", name, st)
		}
	}

	// the /pair request that finds the code expired removes it too (the path that already took the Proxmox secret)
	r := newPairRigV2(t, "", "127.0.0.1")
	r.now = r.now.Add(enroll.TTL + time.Second)
	if st, _, _, _ := panelPairV2(t, r.srv.URL, r.key); st != 404 {
		t.Fatal(st)
	}
	if s, _ := enroll.ReadState(r.path); s.Key2 != "" || !strings.HasPrefix(s.Closed, ExpiredUnused) {
		t.Fatalf("%+v", s)
	}

	// states that are not an expired, unused code are left alone
	for name, st := range map[string]enroll.State{
		"paired":                 {Version: 1, Panel: "127.0.0.1", Closed: "paired", PairedBy: "127.0.0.1", PairedAt: 1_800_000_100, ExpiresAt: 1_800_000_900},
		"closed for wrong codes": {Version: 1, Panel: "127.0.0.1", Closed: "too many wrong codes", ExpiresAt: 1_800_000_900},
		"no code at all":         {Version: 1},
	} {
		r := newPairRig(t, "", "127.0.0.1")
		_ = enroll.WriteState(r.path, st)
		before, _ := os.ReadFile(r.path)
		r.now = r.now.Add(24 * time.Hour)
		if r.p.Sweep() {
			t.Fatalf("%s: swept", name)
		}
		if now, _ := os.ReadFile(r.path); !bytes.Equal(now, before) {
			t.Fatalf("%s: rewritten", name)
		}
	}
	// no file, no path, no pairer
	r = newPairRig(t, "", "127.0.0.1")
	r.p.Path = filepath.Join(t.TempDir(), "none.json")
	var none *Pairer
	if r.p.Sweep() || (&Pairer{}).Sweep() || none.Sweep() {
		t.Fatal("swept nothing")
	}
}

// The running agent sweeps without being asked: at start (a code that ran out while it was down) and then
// every half minute.
func TestRunningAgentSweepsExpiredJoinCode(t *testing.T) {
	r := newPairRigV2(t, "", "127.0.0.1")
	r.now = r.now.Add(enroll.TTL + time.Second) // the code ran out while the agent was not running
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.p.KeepClean(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if s, err := enroll.ReadState(r.path); err == nil && s.Key2 == "" && strings.HasPrefix(s.Closed, ExpiredUnused) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the key is still in the state file")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("KeepClean did not end with its context")
	}
}

// ---- pairing v2 (M3) ----

// newPairRigV2 is newPairRig after `fairy-agent join --pair-v2`: the state holds the v2 key and no verifier.
func newPairRigV2(t *testing.T, cfgYAML, panel string) *pairRig {
	t.Helper()
	r := newPairRig(t, cfgYAML, panel)
	st, err := enroll.ReadState(r.path)
	if err != nil {
		t.Fatal(err)
	}
	st.Verifier, st.Key2 = "", hex.EncodeToString(r.key)
	if err := enroll.WriteState(r.path, st); err != nil {
		t.Fatal(err)
	}
	return r
}

func postJSON(t *testing.T, url string, body []byte) (int, []byte) {
	t.Helper()
	resp, err := http.Post(url+enroll.Path, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 128<<10))
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, b
}

// panelPairV2 is what a v2 panel does with one request: a new nonce and MAC, POST /pair, and the answer is
// accepted only when it opens for that request. It never falls back to v1.
func panelPairV2(t *testing.T, url string, key []byte) (status int, resp enroll.Response, raw []byte, err error) {
	t.Helper()
	req, err := enroll.NewRequestV2(key)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(req)
	status, raw = postJSON(t, url, b)
	if status != 200 {
		return status, resp, raw, nil
	}
	resp, err = enroll.OpenAnswer(key, req, raw)
	return status, resp, raw, err
}

func errCode(raw []byte) string {
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(raw, &e)
	return e.Code
}

func TestPairV2Once(t *testing.T) {
	r := newPairRigV2(t, "power_control: {enabled: true}\n", "127.0.0.1")
	st, resp, raw, err := panelPairV2(t, r.srv.URL, r.key)
	if st != 200 || err != nil {
		t.Fatalf("pair: %d %v %s", st, err, raw)
	}
	if resp.Token != readTok || resp.ControlToken != ctlTok || resp.AgentVersion != "test" || !resp.Features["power_control"] {
		t.Fatalf("opened answer: %+v", resp)
	}
	// nothing readable in the answer
	for _, secret := range []string{readTok, ctlTok, "token", "agent_version", "features"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("%q is readable in the v2 answer: %s", secret, raw)
		}
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || len(m) != 3 || m["v"] != float64(2) {
		t.Fatalf("answer shape: %s", raw)
	}
	// never again, and the key is gone from the state
	if st, _, raw, _ := panelPairV2(t, r.srv.URL, r.key); st != 404 || errCode(raw) != "pairing_inactive" {
		t.Fatalf("second pair: %d %s", st, raw)
	}
	s, err := enroll.ReadState(r.path)
	if err != nil || s.Closed != "paired" || s.Key2 != "" || s.Verifier != "" || s.PairedBy != "127.0.0.1" {
		t.Fatalf("state after pairing: %+v %v", s, err)
	}
	if b, _ := os.ReadFile(r.path); bytes.Contains(b, []byte(hex.EncodeToString(r.key))) {
		t.Fatal("the pairing key stayed on disk")
	}
}

// Downgrade, both ways: the join command chose the version, a request cannot.
func TestPairVersionIsNotNegotiable(t *testing.T) {
	// a code stored for v2: the v1 proof OF THE SAME CODE gets nothing, in clear or otherwise
	r := newPairRigV2(t, "power_control: {enabled: true}\n", "127.0.0.1")
	for _, body := range []string{`{"proof":"` + r.proof + `"}`, `{"v":1,"proof":"` + r.proof + `"}`, `{"v":3,"proof":"` + r.proof + `"}`} {
		st, raw := postJSON(t, r.srv.URL, []byte(body))
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		if st != 400 || m["code"] != "wrong_version" || m["pair"] != float64(2) || bytes.Contains(raw, []byte(readTok)) || m["token"] != nil {
			t.Fatalf("%s on a v2 code: %d %s", body, st, raw)
		}
	}
	if s, _ := enroll.ReadState(r.path); !s.Active(r.now) || s.Failures != 0 || s.PairVersion() != 2 {
		t.Fatalf("state: %+v", s)
	}
	// the right version still works afterwards
	if st, resp, _, err := panelPairV2(t, r.srv.URL, r.key); st != 200 || err != nil || resp.Token != readTok {
		t.Fatalf("v2 after refused v1 requests: %d %v", st, err)
	}

	// a code stored for v1 (an old panel's command): a v2 request, even with the right key, is refused; v1 works
	r = newPairRig(t, "", "127.0.0.1")
	st, _, raw, _ := panelPairV2(t, r.srv.URL, r.key)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	if st != 400 || m["code"] != "wrong_version" || m["pair"] != float64(1) {
		t.Fatalf("v2 request on a v1 code: %d %s", st, raw)
	}
	if s, _ := enroll.ReadState(r.path); !s.Active(r.now) || s.Failures != 0 {
		t.Fatalf("state: %+v", s)
	}
	if st, body := r.pair(t, r.proof); st != 200 || body["token"] != readTok {
		t.Fatalf("v1 on a v1 code: %d %v", st, body)
	}
}

func TestPairV2WrongCodeMalformedAndClose(t *testing.T) {
	r := newPairRigV2(t, "", "127.0.0.1")
	r.p.limit = newLimiter(1000, time.Minute)
	// malformed requests are not guesses: 400, not counted
	good, _ := enroll.NewRequestV2(r.key)
	for name, q := range map[string]enroll.RequestV2{
		"short nonce": {V: 2, Nonce: good.Nonce[:8], MAC: good.MAC},
		"no mac":      {V: 2, Nonce: good.Nonce},
		"short mac":   {V: 2, Nonce: good.Nonce, MAC: good.MAC[:16]},
		"no nonce":    {V: 2, MAC: good.MAC},
	} {
		b, _ := json.Marshal(q)
		if st, raw := postJSON(t, r.srv.URL, b); st != 400 || errCode(raw) != "bad_request" {
			t.Fatalf("%s: %d %s", name, st, raw)
		}
	}
	for _, body := range []string{`{}`, `[]`, `{"v":"2"}`, `{"v":2,"nonce":"!","mac":"!"}`, `not json`, ``} {
		if st, raw := postJSON(t, r.srv.URL, []byte(body)); st != 400 || errCode(raw) != "bad_request" {
			t.Fatalf("%q: %d %s", body, st, raw)
		}
	}
	if s, _ := enroll.ReadState(r.path); s.Failures != 0 || !s.Active(r.now) {
		t.Fatalf("malformed requests were counted: %+v", s)
	}
	// a request made with another code: 403, counted, and after enroll.MaxFailures the code is closed
	other, _ := enroll.NewCode()
	wrong, _ := enroll.PairingKey(other)
	for i := 1; i < enroll.MaxFailures; i++ {
		st, _, raw, _ := panelPairV2(t, r.srv.URL, wrong)
		if st != 403 || errCode(raw) != "wrong_code" {
			t.Fatalf("wrong code %d: %d %s", i, st, raw)
		}
		if s, _ := enroll.ReadState(r.path); s.Failures != i || !s.Active(r.now) {
			t.Fatalf("after %d wrong codes: %+v", i, s)
		}
	}
	// a right MAC over another nonce is a wrong MAC
	forged := enroll.RequestV2{V: 2, Nonce: bytes.Repeat([]byte{7}, enroll.NonceSize), MAC: good.MAC}
	b, _ := json.Marshal(forged)
	if st, raw := postJSON(t, r.srv.URL, b); st != 403 || errCode(raw) != "wrong_code" {
		t.Fatalf("MAC of another nonce: %d %s", st, raw)
	}
	if st, _, _, _ := panelPairV2(t, r.srv.URL, r.key); st != 404 {
		t.Fatalf("after %d wrong codes the right one must not work: %d", enroll.MaxFailures, st)
	}
	if s, _ := enroll.ReadState(r.path); s.Closed != "too many wrong codes" || s.Key2 != "" {
		t.Fatalf("state: %+v", s)
	}
}

// Replay. Someone who recorded a panel request and can send from the panel's address gets an answer, but one
// that only the code opens; an answer recorded earlier is useless against a later request.
func TestPairV2Replay(t *testing.T) {
	r := newPairRigV2(t, "power_control: {enabled: true}\n", "127.0.0.1")
	recorded, _ := enroll.NewRequestV2(r.key) // what the panel sent, seen on the way
	rb, _ := json.Marshal(recorded)
	st, raw := postJSON(t, r.srv.URL, rb) // sent again by someone else, before the panel's next request
	if st != 200 {
		t.Fatalf("%d %s", st, raw)
	}
	if bytes.Contains(raw, []byte(readTok)) || bytes.Contains(raw, []byte(ctlTok)) {
		t.Fatalf("the replayed request got readable tokens: %s", raw)
	}
	other, _ := enroll.NewCode()
	wrong, _ := enroll.PairingKey(other)
	if _, err := enroll.OpenAnswer(wrong, recorded, raw); !errors.Is(err, enroll.ErrUnauthentic) {
		t.Fatalf("opened without the code: %v", err)
	}
	// the panel's NEXT request: the recorded answer does not open for it (and the agent is closed: known limit,
	// the admin makes a new code)
	next, _ := enroll.NewRequestV2(r.key)
	if _, err := enroll.OpenAnswer(r.key, next, raw); !errors.Is(err, enroll.ErrUnauthentic) {
		t.Fatalf("an old answer opened for a new request: %v", err)
	}
	if st, _ := postJSON(t, r.srv.URL, rb); st != 404 {
		t.Fatalf("the same request twice: %d", st)
	}
	// two answers to the same request (pairing reopened by a new join) never reuse a key: the nonces differ
	r2 := newPairRigV2(t, "", "127.0.0.1")
	r2.key = r.key
	s, _ := enroll.ReadState(r2.path)
	s.Key2 = hex.EncodeToString(r.key)
	if err := enroll.WriteState(r2.path, s); err != nil {
		t.Fatal(err)
	}
	st2, raw2 := postJSON(t, r2.srv.URL, rb)
	var a1, a2 enroll.AnswerV2
	if st2 != 200 || json.Unmarshal(raw, &a1) != nil || json.Unmarshal(raw2, &a2) != nil || bytes.Equal(a1.Nonce, a2.Nonce) || bytes.Equal(a1.Sealed, a2.Sealed) {
		t.Fatalf("same request, two agents: %d %s %s", st2, raw, raw2)
	}
}

// Impostor (variant B of the audit): something else answers on the agent's port and does not know the code.
// Whatever it answers, the panel's side gets an error and no tokens; it is never taken for the machine.
func TestPairV2ImpostorIsNeverAccepted(t *testing.T) {
	code, _ := enroll.NewCode()
	key, _ := enroll.PairingKey(code)
	// a real answer of the real agent to an earlier request with this code, which the impostor recorded
	early, _ := enroll.NewRequestV2(key)
	real, _ := enroll.SealAnswer(key, early, enroll.Response{AgentVersion: "0.6.0", Platform: "linux", Token: readTok})
	recorded, _ := json.Marshal(real)
	guess, _ := enroll.PairingKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	answers := map[string]func(body []byte) (int, []byte){
		"an old agent's answer, tokens in clear": func([]byte) (int, []byte) {
			b, _ := json.Marshal(enroll.Response{AgentVersion: "0.5.3", Hostname: "nas", Platform: "linux", Features: map[string]bool{}, Token: "impostor-read-token-0123456789"})
			return 200, b
		},
		"the request sent back":  func(body []byte) (int, []byte) { return 200, body },
		"a recorded real answer": func([]byte) (int, []byte) { return 200, recorded },
		"a complete answer sealed with another code": func([]byte) (int, []byte) {
			q, _ := enroll.NewRequestV2(guess)
			a, _ := enroll.SealAnswer(guess, q, enroll.Response{AgentVersion: "0.6.0", Platform: "linux", Token: "impostor-read-token-0123456789"})
			b, _ := json.Marshal(a)
			return 200, b
		},
		"random bytes in the v2 shape": func([]byte) (int, []byte) {
			a := enroll.AnswerV2{V: 2, Nonce: bytes.Repeat([]byte{1}, enroll.NonceSize), Sealed: bytes.Repeat([]byte{2}, 120)}
			b, _ := json.Marshal(a)
			return 200, b
		},
		"v2 shape with v1 fields": func([]byte) (int, []byte) {
			return 200, []byte(`{"v":2,"nonce":"AAAAAAAAAAAAAAAAAAAAAA==","sealed":"","token":"impostor-read-token-0123456789","platform":"linux","agent_version":"0.6.0"}`)
		},
		"empty 200": func([]byte) (int, []byte) { return 200, nil },
	}
	for name, answer := range answers {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			st, b := answer(body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(st)
			_, _ = w.Write(b)
		}))
		st, resp, raw, err := panelPairV2(t, srv.URL, key)
		srv.Close()
		if st != 200 || err == nil || !(errors.Is(err, enroll.ErrNotV2) || errors.Is(err, enroll.ErrUnauthentic)) {
			t.Errorf("%s: accepted (%d, %v): %s", name, st, err, raw)
		}
		if resp.Token != "" || resp.AgentVersion != "" || resp.Platform != "" {
			t.Errorf("%s: a refused answer returned %+v", name, resp)
		}
	}
	// an agent that only knows v1 (0.5.x) reads a v2 request as "no proof": 400 bad_request, nothing to adopt.
	// (The real 0.5.3 handler was run against this request outside the test suite; this is its decoding step.)
	q, _ := enroll.NewRequestV2(key)
	b, _ := json.Marshal(q)
	var old enroll.Request
	if err := json.Unmarshal(b, &old); err != nil || old.Proof != "" {
		t.Fatalf("%+v %v", old, err)
	}
}

// Listener on the path (variant A of the audit): it sees everything that crosses and can send it again.
func TestPairV2ListenerLearnsNothing(t *testing.T) {
	r := newPairRigV2(t, "power_control: {enabled: true}\n", "127.0.0.1")
	target, _ := url.Parse(r.srv.URL)
	var seen bytes.Buffer
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(resp *http.Response) error {
		b, err := io.ReadAll(resp.Body)
		seen.Write(b)
		resp.Body = io.NopCloser(bytes.NewReader(b))
		return err
	}
	tap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		seen.Write(b)
		req.Body = io.NopCloser(bytes.NewReader(b))
		proxy.ServeHTTP(w, req)
	}))
	defer tap.Close()
	st, resp, _, err := panelPairV2(t, tap.URL, r.key)
	if st != 200 || err != nil || resp.Token != readTok || resp.ControlToken != ctlTok {
		t.Fatalf("pair through the tap: %d %v", st, err)
	}
	for _, secret := range []string{readTok, ctlTok, r.proof, hex.EncodeToString(r.key), strings.ReplaceAll(r.code, "-", "")} {
		if bytes.Contains(seen.Bytes(), []byte(secret)) {
			t.Fatalf("the listener saw %q", secret)
		}
	}
	if seen.Len() < 100 {
		t.Fatalf("the tap recorded nothing: %q", seen.String())
	}
}

func TestPairV2KeepsTheCodeWhenNothingWasSent(t *testing.T) {
	// the agent cannot read its tokens: 500, the code stays usable
	r := newPairRigV2(t, "", "127.0.0.1")
	r.p.Tokens = func() (Tokens, error) { return Tokens{}, errors.New("no token file") }
	if st, _, _, _ := panelPairV2(t, r.srv.URL, r.key); st != 500 {
		t.Fatalf("want 500, got %d", st)
	}
	if s, _ := enroll.ReadState(r.path); !s.Active(r.now) || s.PairVersion() != 2 {
		t.Fatalf("a failed pairing must keep the code usable: %+v", s)
	}
	// a damaged key in the state: 500, never an answer
	r = newPairRigV2(t, "", "127.0.0.1")
	s, _ := enroll.ReadState(r.path)
	s.Key2 = "zz"
	if err := enroll.WriteState(r.path, s); err != nil {
		t.Fatal(err)
	}
	if st, _, raw, _ := panelPairV2(t, r.srv.URL, r.key); st != 500 || errCode(raw) != "state_unreadable" || bytes.Contains(raw, []byte(readTok)) {
		t.Fatalf("damaged key: %d %s", st, raw)
	}
	// from another address: refused before anything is checked
	r = newPairRigV2(t, "", "100.88.109.47")
	if st, _, raw, _ := panelPairV2(t, r.srv.URL, r.key); st != 403 || errCode(raw) != "wrong_address" {
		t.Fatalf("other address: %d %s", st, raw)
	}
	// expired
	r = newPairRigV2(t, "", "127.0.0.1")
	r.now = r.now.Add(enroll.TTL + time.Second)
	if st, _, _, _ := panelPairV2(t, r.srv.URL, r.key); st != 404 {
		t.Fatalf("expired: %d", st)
	}
}

func TestPairV2HandsTheProxmoxTokenOutSealed(t *testing.T) {
	r := newPairRigV2(t, "", "127.0.0.1")
	grant := &enroll.ProxmoxGrant{TokenID: "fairy@pve!panel-asus-i7", TokenSecret: "0b7c4e2a-1111-2222-3333-444455556666",
		CAPEM: "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("QUJD", 500) + "\n-----END CERTIFICATE-----\n", Node: "asus-i7", URL: "https://asus-i7.ts.net:8006", ServerName: "asus-i7"}
	s, _ := enroll.ReadState(r.path)
	s.Proxmox = grant
	if err := enroll.WriteState(r.path, s); err != nil {
		t.Fatal(err)
	}
	st, resp, raw, err := panelPairV2(t, r.srv.URL, r.key)
	if st != 200 || err != nil || resp.Proxmox == nil || *resp.Proxmox != *grant {
		t.Fatalf("%d %v %+v", st, err, resp.Proxmox)
	}
	if bytes.Contains(raw, []byte(grant.TokenSecret)) || bytes.Contains(raw, []byte("fairy@pve")) {
		t.Fatalf("the Proxmox token is readable in the answer: %s", raw)
	}
	if s, _ := enroll.ReadState(r.path); s.Proxmox != nil || s.Closed != "paired" {
		t.Fatalf("the token stayed on disk: %+v", s)
	}
}
