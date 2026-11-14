package agent_test

// The run routes as a stranger on the LAN sees them, and odd bodies on them and on "run" of POST /power and
// POST /update (from the independent review of fd6d3be: these held, and stay as tests).

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

func rawDo(t *testing.T, base, method, path, tok string, body []byte) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, base+path, bytes.NewReader(body))
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	var b bytes.Buffer
	b.ReadFrom(resp.Body)
	return resp.StatusCode, b.String()
}

func TestRunRoutesAnswerAStrangerTheSameWhateverTheState(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		// before trust, with trust, armed, confirmed: a stranger (and the read token) gets the same bytes
		var seen []string
		look := func(stage string) {
			for _, path := range []string{api.PathRunArm, api.PathRunGo} {
				for _, tok := range []string{"", readTok} {
					for _, body := range []string{`{"approval":{"token":"a.b.c","entries":[]}}`, `{"run":"` + hRunA + `","to":"-","shutdown_delay_s":30,"within_s":300}`} {
						st, b := rawDo(t, r.base, "POST", path, tok, []byte(body))
						if st != 401 {
							t.Errorf("%s: %s without the control token: %d %s", stage, path, st, b)
						}
						seen = append(seen, fmt.Sprintf("%s|%d|%s", path, st, b))
					}
				}
			}
		}
		look("no trust")
		n := len(seen)
		r.trusted()
		r.arm(hRunA)
		if st, b := r.confirm(hRunA, "-", 30, 300); st != 200 {
			t.Fatalf("go: %d %v", st, b)
		}
		look("confirmed")
		for i := n; i < len(seen); i++ {
			if seen[i] != seen[i%n] {
				t.Errorf("the answer to a stranger differs with the machine's state: %q vs %q", seen[i], seen[i%n])
			}
		}
		// method, size
		if st, _ := rawDo(t, r.base, "GET", api.PathRunArm, ctlTok, nil); st != 405 {
			t.Errorf("GET /run/arm: %d", st)
		}
		big := []byte(`{"approval":{"token":"` + strings.Repeat("A", 40<<10) + `","entries":[]}}`)
		if st, b := rawDo(t, r.base, "POST", api.PathRunArm, ctlTok, big); st != 400 && st != 413 {
			t.Errorf("a 40 KiB ticket: %d %s", st, b)
		}
	})
}

// Odd bodies on the run routes and on "run" of /power and /update, with the control token.
func TestRunRoutesOddBodies(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		r.trusted()
		r.arm(hRunA)
		if st, b := r.confirm(hRunA, "42-bbbbbbb", 30, 300); st != 200 {
			t.Fatalf("go: %d %v", st, b)
		}
		bad := []struct{ path, body string }{
			{"/power", `{"action":"shutdown","delay_s":30,"run":"` + hRunA + `","run":"` + hRunB + `"}`}, // twice
			{"/power", `{"action":"shutdown","delay_s":30,"Run":"` + hRunA + `"}`},                       // another spelling
			{"/power", `{"action":"shutdown","delay_s":30.0,"run":"` + hRunA + `"}`},                     // 30.0
			{"/power", `{"action":"shutdown","delay_s":3e1,"run":"` + hRunA + `"}`},                      // 3e1
			{"/power", `{"action":"shutdown","delay_s":29,"run":"` + hRunA + `"}`},                       // below min_delay and not the confirmed delay
			{"/power", `{"action":"shutdown","delay_s":30,"run":"` + strings.ToUpper(hRunA) + `"}`},      // upper case id
			{"/power", `{"action":"shutdown","delay_s":30,"run":" ` + hRunA + `"}`},                      // space
			{"/power", `{"action":"reboot","delay_s":30,"run":"` + hRunA + `"}`},                         // reboot
			{"/power", `{"action":"shutdown","delay_s":30,"run":["` + hRunA + `"]}`},                     // list
			{"/update", `{"run":"` + hRunB + `"}`},                                                       // other run
			{"/update", `{"run":"` + strings.ToUpper(hRunA) + `"}`},                                      // upper case
			{api.PathRunGo, `{"run":"` + hRunB + `","to":"-","shutdown_delay_s":30,"within_s":300}`},     // no approval
			{api.PathRunGo, `{"run":"` + hRunA + `","to":"-","shutdown_delay_s":-30,"within_s":300}`},    // negative
			{api.PathRunGo, `{"run":"` + hRunA + `","to":"-","shutdown_delay_s":99999999999999999999,"within_s":300}`},
			{api.PathRunArm, `{"approval":null}`},
			{api.PathRunArm, `{"approval":{"token":"a.b.c","entries":[]},"extra":1}`},
		}
		for _, c := range bad {
			st, b := rawDo(t, r.base, "POST", c.path, ctlTok, []byte(c.body))
			if st == 200 || st == 202 {
				t.Errorf("%s %s was accepted: %d %s", c.path, c.body, st, b)
			}
		}
		if len(r.exec.Scheduled) != 0 || r.starts() != 0 {
			t.Fatalf("something ran: %v, %d starts", r.exec.Scheduled, r.starts())
		}
		// and the run is still whole after all of that: the one shutdown works
		if st, b := r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA}); st != 200 {
			t.Errorf("the run's shutdown after the refused bodies: %d %v", st, b)
		}
	})
}
