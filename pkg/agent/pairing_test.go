package agent

import (
	"bytes"
	"encoding/json"
	"errors"
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
