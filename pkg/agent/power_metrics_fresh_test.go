package agent_test

// Audit 6, r4-p2-10: GET /metrics right after a power request. The agent keeps a /metrics answer for 250 ms;
// one from before a cancel was still served after the cancel had answered 200, so the shutdown it had just
// cancelled was shown as pending once more.

import (
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
)

func TestMetricsRightAfterAPowerRequestShowsWhatItChanged(t *testing.T) {
	cfg, err := agent.Parse([]byte("power_control: {enabled: true}\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ex := &agenttest.PowerExec{}
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Power: agent.NewPower(ex, cfg.PowerControl.MinDelayS)}
	hs := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	defer hs.Close()
	pending := func() any {
		t.Helper()
		st, m := do(t, hs.URL, "GET", "/metrics", readTok, nil)
		pc, ok := m["power_control"].(map[string]any)
		if st != 200 || !ok {
			t.Fatal(st, m)
		}
		return pc["pending"]
	}
	for round := 1; round <= 2; round++ {
		pending() // this answer is kept for 250 ms
		if st, b := do(t, hs.URL, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "alice"}); st != 200 {
			t.Fatal(st, b)
		}
		p, _ := pending().(map[string]any)
		if p["action"] != "shutdown" {
			t.Errorf("round %d: the /metrics right after the shutdown was accepted shows pending = %v", round, p)
		}
		time.Sleep(300 * time.Millisecond)                                 // past the 250 ms: the next answer is made anew whatever the agent does
		if p, _ := pending().(map[string]any); p["action"] != "shutdown" { // ... and kept: it shows the shutdown
			t.Fatalf("round %d: pending = %v", round, p)
		}
		st, b := do(t, hs.URL, "POST", "/power", ctlTok, map[string]any{"action": "cancel"})
		if st != 200 || b["action"] != "cancel" {
			t.Fatal(st, b)
		}
		if p := pending(); p != nil {
			t.Errorf("round %d: the cancel answered 200, and the /metrics right after it still shows %v as pending", round, p)
		}
	}
	if ex.Cancels != 2 || len(ex.Scheduled) != 2 {
		t.Fatalf("the power part saw %d cancels and %v", ex.Cancels, ex.Scheduled)
	}
}
