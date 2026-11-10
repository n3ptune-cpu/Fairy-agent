package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
	r := &pairRig{path: filepath.Join(t.TempDir(), "pairing.json"), now: time.Unix(1_800_000_000, 0), proof: proof}
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
