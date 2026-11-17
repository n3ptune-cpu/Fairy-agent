package agent_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
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

// The panel's "Uninstall agent" on a Windows machine, through the real agent and the real helper over a pipe:
// the agent checks nothing of the approval, the helper checks it with its own trust file, and only then is the
// removal started (counted here; the real one leaves the request for the updater service).

type uhrig struct {
	base    string
	iss     *approvaltest.Issuer
	scm     *fakeSCM
	starts  atomic.Int32
	lastBy  atomic.Value
	trusted bool
}

func newUninstallHelperRig(t *testing.T) *uhrig {
	t.Helper()
	cfg, err := agent.Parse([]byte("uninstall: {enabled: true}\ncontrol_rate_per_min: 60\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !agent.NeedsHelper(cfg) {
		t.Fatal("uninstall.enabled does not make the helper needed")
	}
	r := &uhrig{iss: approvaltest.New()}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	files := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	srv := helper.New(helper.Parts{Version: "test", Audit: log,
		Uninstall: func(_ context.Context, by string) error { r.starts.Add(1); r.lastBy.Store(by); return nil },
		Approval:  approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByHelper, Log: log, Files: files})})
	r.scm = &fakeSCM{state: api.HelperRunning, srv: srv}
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		if st, _ := r.scm.State(); st != api.HelperRunning {
			return nil, errors.New("pipe not found")
		}
		a, c := net.Pipe()
		go func() { srv.ServeConn(ctx, a, "test"); a.Close() }()
		return c, nil
	}
	client := agent.NewHelperClient(dial, r.scm, true)
	client.Every = 10 * time.Millisecond
	go client.Run(ctx)
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: client, Uninstaller: agent.HelperUninstaller(client),
		Approval: approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByAgent, Files: files, ReadOnly: true, Log: log})}
	hs := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(hs.Close)
	r.base = hs.URL
	return r
}

func (r *uhrig) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, r.base, "POST", path, ctlTok, body)
}

func (r *uhrig) approve(t *testing.T) *api.Approval {
	t.Helper()
	st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": api.ApproveUninstall})
	if st != 200 || c["needed"] != true || c["request"] != "uninstall" {
		t.Fatalf("challenge: %d %v", st, c)
	}
	return r.iss.Approve(time.Now(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c["challenge"].(string), Request: c["request"].(string)})
}

func TestUninstallThroughAgentAndHelper(t *testing.T) {
	r := newUninstallHelperRig(t)

	// no trust: the helper says approval_off, for the challenge and the request
	st, b := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": api.ApproveUninstall})
	wantRefusal(t, "challenge without trust", st, b, 409, api.CodeApprovalOff)
	st, b = r.post(t, api.PathUninstall, map[string]any{})
	wantRefusal(t, "uninstall without trust", st, b, 409, api.CodeApprovalOff)

	// the trust, set once from the panel with its proof (through the helper, whose file it is)
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 || b["state"] != api.ApprovalRequired {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	st, b = r.post(t, api.PathUninstall, map[string]any{})
	wantRefusal(t, "no approval", st, b, 403, api.CodeApprovalRequired)
	forged := r.iss.Approve(time.Now(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: "uninstall"})
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": forged})
	wantRefusal(t, "a challenge the helper never gave", st, b, 403, api.CodeApprovalRefused)
	if n := r.starts.Load(); n != 0 {
		t.Fatalf("started %d times without a good approval", n)
	}

	ap := r.approve(t)
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": ap, "requested_by": "admin@example"})
	if st != 202 || b["state"] != api.UninstallStarted {
		t.Fatalf("approved: %d %v", st, b)
	}
	if n, by := r.starts.Load(), r.lastBy.Load(); n != 1 || !strings.Contains(by.(string), "panel 127.0.0.1") || !strings.Contains(by.(string), "admin@example") {
		t.Fatalf("started %d times, by %v", n, by)
	}
	// once: the agent refuses a second request before the helper is asked
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": ap})
	if st != 409 || b["code"] != api.CodeUninstallBusy {
		t.Errorf("a second request: %d %v", st, b)
	}
	if n := r.starts.Load(); n != 1 {
		t.Fatalf("started %d times", n)
	}
}

// Without the helper installed there is nothing that may check the approval or carry the uninstall out: 409
// helper_required, and the agent's own gate is never asked in its place.
func TestUninstallWithoutTheHelper(t *testing.T) {
	r := newUninstallHelperRig(t)
	r.scm.mu.Lock()
	r.scm.state = api.HelperNotInstalled
	r.scm.mu.Unlock()
	time.Sleep(50 * time.Millisecond) // the client's status refresh
	st, b := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": api.ApproveUninstall})
	wantRefusal(t, "challenge", st, b, 409, api.CodeHelperRequired)
	st, b = r.post(t, api.PathUninstall, map[string]any{})
	wantRefusal(t, "uninstall", st, b, 409, api.CodeHelperRequired)
	if n := r.starts.Load(); n != 0 {
		t.Fatalf("started %d times", n)
	}
}
