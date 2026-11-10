package agent_test

// L21 end to end on Linux: the agent's HTTP API, the helper's client, the real helper server behind an
// in-memory pipe, and a power part that remembers its shutdown in a file, as on Windows. "Windows" is a fake
// that counts what it was asked: a shutdown scheduled there goes on whatever restarts.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
)

// startPair starts a helper and an agent that talks to it (one "boot" of both services) and returns the
// agent's address and a function that stops both.
func startPair(t *testing.T, windows agent.PowerExec, store agent.PowerStore) (string, func()) {
	t.Helper()
	cfg, err := agent.Parse([]byte("power_control: {enabled: true}\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	power := agent.RememberPower(windows, store, func(a string) bool { return a != "sleep" }, nil)
	srv := helper.New(helper.Parts{Version: "test", Power: power, MinDelayS: cfg.PowerControl.MinDelayS,
		Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	scm := &fakeSCM{state: api.HelperRunning, srv: srv}
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		if st, _ := scm.State(); st != api.HelperRunning {
			return nil, errors.New("pipe not found")
		}
		a, c := net.Pipe()
		go func() { srv.ServeConn(ctx, a, "test"); a.Close() }()
		return c, nil
	}
	client := agent.NewHelperClient(dial, scm, true)
	client.Every = 5 * time.Millisecond
	go client.Run(ctx)
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: client,
		Power: agent.NewPower(client.Power(), cfg.PowerControl.MinDelayS), HelperSources: []string{api.FeaturePower}}
	hs := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	return hs.URL, func() { hs.Close(); cancel() }
}

// pendingIn waits (briefly) until /metrics shows a pending action (want true) or none.
func pendingIn(t *testing.T, base string, want bool) map[string]any {
	t.Helper()
	var p map[string]any
	for i := 0; i < 400; i++ {
		_, m := do(t, base, "GET", "/metrics", readTok, nil)
		pc, _ := m["power_control"].(map[string]any)
		p, _ = pc["pending"].(map[string]any)
		if (p != nil) == want {
			return p
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("pending = %v, want pending %v", p, want)
	return nil
}

func TestWindowsCancelAfterBothServicesRestarted(t *testing.T) {
	windows := &agenttest.PowerExec{}
	store := agent.PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}

	base, stop := startPair(t, windows, store)
	st, b := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 3600, "requested_by": "alice@example.com"})
	if st != 200 {
		t.Fatal(st, b)
	}
	first := pendingIn(t, base, true)
	stop() // an update replaces the program: agent and helper both stop ...

	base, stop = startPair(t, windows, store) // ... and start again; Windows is still counting down
	defer stop()
	p := pendingIn(t, base, true)
	// the same moment, give or take the milliseconds between the agent's and the helper's reading of the clock
	if d := p["at"].(float64) - first["at"].(float64); p["action"] != "shutdown" || p["requested_by"] != "alice@example.com" ||
		p["delay_s"] != 3600.0 || d < -1 || d > 1 {
		t.Fatalf("after the restart the panel sees %v, before it saw %v", p, first)
	}
	if st, b := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "reboot", "delay_s": 60}); st != 409 {
		t.Fatal("a second action was accepted while the first is pending", st, b)
	}
	if st, b := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
		t.Fatal(st, b)
	}
	if windows.Cancels != 1 {
		t.Fatalf("Windows was asked to abort %d times, want 1", windows.Cancels)
	}
	pendingIn(t, base, false)
	// and it stays cancelled, also for the next start
	stop()
	base, stop2 := startPair(t, windows, store)
	defer stop2()
	pendingIn(t, base, false)
	if st, _ := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 || windows.Cancels != 1 {
		t.Fatal(st, windows.Cancels)
	}
}

// While the helper is stopped nobody can tell whether its shutdown is still pending: Cancel says so (503, as
// for a cancel the agent knows it cannot carry out) instead of answering "ok, nothing pending".
func TestCancelWhileTheHelperIsStopped(t *testing.T) {
	h := newHelperRig(t, api.HelperRunning)
	h.metrics(t, api.HelperRunning)
	if st, b := do(t, h.srv.URL, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
		t.Fatal(st, b)
	}
	if st, _ := do(t, h.srv.URL, "POST", "/helper/stop", ctlTok, nil); st != 200 {
		t.Fatal(st)
	}
	h.metrics(t, api.HelperStopped)
	st, b := do(t, h.srv.URL, "POST", "/power", ctlTok, map[string]any{"action": "cancel"})
	if st != 503 || b["code"] != api.ReasonHelperStopped {
		t.Fatal(st, b)
	}
	if h.power.Cancels != 0 {
		t.Fatal(h.power.Cancels)
	}
}

// A shutdown Fairy did not start (nothing on record): Cancel from the panel answers ok and Windows is never
// asked to abort anything, however often and whichever service restarted.
func TestCancelNeverAbortsAShutdownFairyDidNotStart(t *testing.T) {
	windows := &agenttest.PowerExec{}
	store := agent.PowerFile{Path: filepath.Join(t.TempDir(), "power-pending.json")}
	for i := 0; i < 2; i++ {
		base, stop := startPair(t, windows, store)
		pendingIn(t, base, false)
		for j := 0; j < 3; j++ {
			if st, b := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
				t.Fatal(st, b)
			}
		}
		stop()
	}
	if windows.Cancels != 0 {
		t.Fatalf("Windows was asked to abort %d times", windows.Cancels)
	}
	// straight to the helper's pipe (a compromised agent process): the helper itself refuses to abort
	power := agent.RememberPower(windows, store, nil, nil)
	srv := helper.New(helper.Parts{Power: power, Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if resp := srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"power","action":"cancel"}`)); resp.Status != 200 || windows.Cancels != 0 {
		t.Fatal(resp, windows.Cancels)
	}
}
