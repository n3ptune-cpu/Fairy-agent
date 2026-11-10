package agent

// Fuzz targets from the independent review of the fixes: the /pair body and the /metrics encoder.
// They run on their seeds with every `go test`; `go test -fuzz <name>` searches further.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// POST /pair with any body, from the panel's address, against a v2 state: never a 5xx, never a 200 without the
// right MAC, and the tokens never appear in an answer in clear.
func FuzzPairBodyV2(f *testing.F) {
	code, err := enroll.NewCode()
	if err != nil {
		f.Fatal(err)
	}
	key, _ := enroll.PairingKey(code)
	proof, _ := enroll.Proof(code)
	path := filepath.Join(f.TempDir(), "pairing.json")
	now := time.Unix(1_800_000_000, 0)
	tok := Tokens{Read: readTok, Control: ctlTok}
	p := NewPairer(path, func() (Tokens, error) { return tok, nil },
		func() enroll.Response { return enroll.Response{AgentVersion: "test", Platform: "linux"} })
	p.Now = func() time.Time { return now }
	p.limit = newLimiter(1<<30, time.Minute) // the budget is not what is fuzzed
	good, _ := enroll.NewRequestV2(key)
	gb, _ := json.Marshal(good)
	f.Add(gb)
	f.Add(gb[:len(gb)-3])
	f.Add([]byte(`{"proof":"` + proof + `"}`))
	f.Add([]byte(`{"v":2,"nonce":"AAAAAAAAAAAAAAAAAAAAAA==","mac":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`))
	f.Add([]byte(`{"v":1,"proof":"x"}`))
	f.Add([]byte(`{"v":-2}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, body []byte) {
		// a fresh, open v2 state for every input (wrong MACs close pairing after ten)
		st := enroll.State{Version: 1, Key2: hex.EncodeToString(key), Panel: "192.0.2.1", CreatedAt: now.Unix(),
			ExpiresAt: now.Add(enroll.TTL).Unix()}
		if err := enroll.WriteState(path, st); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, enroll.Path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "192.0.2.1:5000"
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		out := w.Body.String()
		if w.Code >= 500 {
			t.Fatalf("%d for %q: %s", w.Code, body, out)
		}
		if strings.Contains(out, readTok) || strings.Contains(out, ctlTok) || strings.Contains(out, hex.EncodeToString(key)) {
			t.Fatalf("a secret in clear in the answer to %q: %s", body, out)
		}
		if w.Code == 200 {
			var q enroll.RequestV2
			if json.Unmarshal(body, &q) != nil || enroll.CheckRequestV2(key, q) != nil {
				t.Fatalf("200 for a request without the right MAC: %q", body)
			}
		}
	})
}

// encodeMetrics with any numbers in the sections: always a body, always JSON, every ordinary key still there.
func FuzzEncodeMetrics(f *testing.F) {
	f.Add(1.0, 2.0, 3.0, uint8(0))
	f.Add(math.NaN(), math.Inf(1), math.Copysign(0, -1), uint8(7)) // a negative zero (the literal -0.0 is plain 0)
	f.Add(1e308, -1e308, math.Inf(-1), uint8(255))
	f.Fuzz(func(t *testing.T, a, b, c float64, mask uint8) {
		pick := func(bit uint8, v float64) float64 {
			if mask&(1<<bit) != 0 {
				return v
			}
			return 1
		}
		m := map[string]any{
			"uptime_s": pick(0, a), "load_avg": []float64{pick(1, b), 1, 1},
			"cpu":           collect.CPU{Percent: collect.P(pick(2, c))},
			"temps":         []collect.Temp{{Sensor: "x", Current: pick(3, a)}, {Sensor: "y", Current: 40}},
			"fans":          []collect.Fan{{Name: "f", RPM: pick(4, b)}},
			"power_sources": []map[string]any{{"id": "p", "watts": pick(5, c)}, {"id": "q", "watts": 5.0}},
			"ups":           []map[string]any{{"name": "u", "watts": pick(6, a)}},
			"power":         collect.Power{GPUW: collect.P(pick(7, b))},
		}
		body, _ := encodeMetrics(m)
		if body == nil {
			t.Fatal("no body")
		}
		var back map[string]json.RawMessage
		if err := json.Unmarshal(body, &back); err != nil {
			t.Fatalf("not JSON: %v", err)
		}
		for k := range m {
			if _, ok := back[k]; !ok {
				t.Fatalf("key %s is gone", k)
			}
		}
	})
}
