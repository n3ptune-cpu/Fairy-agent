package agent_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
)

// cutConn is a pipe connection to the helper that can be cut for a while: nothing is written, as when the
// pipe is busy, the helper is starting again, or it refuses a read because too many were asked this minute.
type cutConn struct {
	io.ReadWriteCloser
	cut *atomic.Bool
}

func (c cutConn) Write(p []byte) (int, error) {
	if c.cut.Load() {
		return 0, errors.New("pipe: broken (test)")
	}
	return c.ReadWriteCloser.Write(p)
}

// cancelRig is a Windows machine as the agent's HTTP API shows it: the real helper code behind an in-memory
// pipe that the test can cut, the agent in front of it, and NO loop that asks the helper's status again: what
// the agent has kept of the helper's status stays "fresh" for nine seconds, as between two looks in the agent.
type cancelRig struct {
	t      *testing.T
	base   string
	iss    *approvaltest.Issuer
	exec   *agenttest.PowerExec
	srv    *helper.Server
	cut    atomic.Bool
	mu     sync.Mutex
	now    time.Time
	up     time.Duration
	client *agent.HelperClient
}

func (r *cancelRig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *cancelRig) uptime() (time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.up, nil
}

func (r *cancelRig) pass(d time.Duration) {
	r.mu.Lock()
	r.now, r.up = r.now.Add(d), r.up+d
	r.mu.Unlock()
	r.srv.Runs().Tick()
}

func (r *cancelRig) post(path string, body any) (int, map[string]any) {
	r.t.Helper()
	return do(r.t, r.base, "POST", path, ctlTok, body)
}

func (r *cancelRig) run() map[string]any {
	r.t.Helper()
	_, m := do(r.t, r.base, "GET", "/metrics", readTok, nil)
	ap, _ := m["approval"].(map[string]any)
	run, _ := ap["run"].(map[string]any)
	return run
}

func newCancelRig(t *testing.T) *cancelRig {
	t.Helper()
	cfg, err := agent.Parse([]byte("power_control: {enabled: true, min_delay_s: 30}\ncontrol_rate_per_min: 60\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &cancelRig{t: t, iss: approvaltest.New(), exec: &agenttest.PowerExec{}, now: time.Now(), up: 60 * time.Second}
	files := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	boot := func() (string, error) { return "0f1e2d3c4b5a69788796a5b4c3d2e1f0", nil } // the helper's volatile registry key
	r.srv = helper.New(helper.Parts{Version: "test", Power: agent.RememberPower(r.exec, nil, nil, nil), MinDelayS: 30, Audit: log,
		Approval: approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByHelper, Log: log, Files: files,
			Now: r.clock, Uptime: r.uptime, BootID: boot, Runs: true, MinDelayS: 30})})
	scm := &fakeSCM{state: api.HelperRunning, srv: r.srv}
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		if r.cut.Load() {
			return nil, errors.New("pipe busy (test)")
		}
		a, c := net.Pipe()
		go func() { r.srv.ServeConn(ctx, a, "test"); a.Close() }()
		return cutConn{c, &r.cut}, nil
	}
	r.client = agent.NewHelperClient(dial, scm, true) // Every 2 s, Timeout 5 s, as in the agent
	hp := r.client.Power()
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: r.client,
		Power: agent.NewPowerForRuns(hp, 30, hp.RunLive), HelperSources: []string{api.FeaturePower}}
	d.Approval = approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByAgent, Files: files, ReadOnly: true, Now: r.clock, Uptime: r.uptime, BootID: boot, Log: log})
	hs := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(hs.Close)
	r.base = hs.URL
	if st, b := r.post(api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 {
		t.Fatalf("trust: %d %v", st, b)
	}
	// the run record this PC has from a boot before (one that is made now would close this boot for tickets)
	if err := approvaltest.EarlierBoot(files, r.clock().Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *cancelRig) arm(run string, wait, notice int) {
	r.t.Helper()
	var ch [32]byte
	rand.Read(ch[:])
	valid := 420
	text, _ := (api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}).Canonical()
	tk := r.iss.Approve(r.clock().Add(-160*time.Second), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: approvaltest.B64(ch[:]), Request: text})
	if st, b := r.post(api.PathRunArm, map[string]any{"approval": tk}); st != 200 {
		r.t.Fatalf("arm: %d %v", st, b)
	}
	if run := r.run(); run == nil || run["state"] != api.RunArmed {
		r.t.Fatalf("not armed in /metrics: %v", run)
	}
}

// The panel's Cancel on a Windows PC with an ARMED run, at a moment when the helper does not answer the one
// question the agent asks it about the run (a hiccup of the pipe, the helper starting again, its limit of
// reads a minute), while what the agent kept of the helper's status is still fresh. The agent answered
// 200 "nothing pending" without the cancel ever reaching the helper: the run stayed armed and the PC switched
// itself off. A cancel is never answered 200 when it was not delivered while a run may be live.
func TestWindowsCancelIsNotAnsweredOKWhileTheRunMayBeLive(t *testing.T) {
	r := newCancelRig(t)
	r.arm(hRunA, 120, 30)
	r.cut.Store(true) // the helper does not answer for a moment
	st, b := r.post("/power", map[string]any{"action": "cancel"})
	r.cut.Store(false)
	if st == 200 {
		t.Errorf("the cancel did not reach the helper and was answered %d %v", st, b)
	}
	if st != 500 && st != 503 {
		t.Errorf("a cancel that could not be delivered: %d %v, want 500 or 503", st, b)
	}
	// the cancel sent again reaches the helper: the run ends, and the wait running out switches nothing off
	r.client.Every, r.client.Timeout = 0, 0 // (as the agent's loop does within two seconds: the helper is asked again)
	if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
		t.Fatalf("the cancel sent again: %d %v", st, b)
	}
	r.pass(130 * time.Second)
	r.pass(time.Second)
	if len(r.exec.Scheduled) != 0 {
		t.Fatalf("the PC switched itself off after a cancel that was answered 200: %v", r.exec.Scheduled)
	}
	if run := r.run(); run == nil || run["state"] != api.RunCancelled {
		t.Errorf("the run after the cancel: %v", run)
	}
}

// The same moment without the second cancel: whatever the agent answered, a 200 and a self-off never go
// together.
func TestWindowsCancelAnswered200MeansTheRunIsOver(t *testing.T) {
	for _, cutFor := range []string{"the question about the run", "nothing"} {
		t.Run(cutFor, func(t *testing.T) {
			r := newCancelRig(t)
			r.arm(hRunB, 120, 30)
			r.cut.Store(cutFor != "nothing")
			st, b := r.post("/power", map[string]any{"action": "cancel"})
			r.cut.Store(false)
			r.pass(130 * time.Second)
			r.pass(time.Second)
			if st == 200 && len(r.exec.Scheduled) != 0 {
				t.Fatalf("POST /power cancel was answered 200 %v and the PC switched itself off: %v", b, r.exec.Scheduled)
			}
			if cutFor == "nothing" && (st != 200 || len(r.exec.Scheduled) != 0) {
				t.Fatalf("a cancel that reached the helper: %d %v, scheduled %v", st, b, r.exec.Scheduled)
			}
		})
	}
}

// A machine without a run pays nothing for this: with the approval check off, or with no run live, a cancel
// with nothing pending is answered 200 as ever, and the helper's power part is not asked to cancel anything.
func TestWindowsCancelWithoutARunIsWhatItWas(t *testing.T) {
	r := newCancelRig(t)
	for i := 0; i < 3; i++ {
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
			t.Fatalf("cancel with nothing pending and no run: %d %v", st, b)
		}
	}
	if r.exec.Cancels != 0 {
		t.Errorf("the system was asked to cancel %d times with nothing pending", r.exec.Cancels)
	}
}
