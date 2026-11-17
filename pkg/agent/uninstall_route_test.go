package agent_test

import (
	"context"
	"errors"
	"log/slog"
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
)

// POST /uninstall on an agent that checks approvals itself (Linux): what reaches the Uninstaller and what never
// does. The Uninstaller here only counts; the real one starts fairy-agent-uninstall.service.

type countingUninstaller struct {
	starts atomic.Int32
	err    atomic.Pointer[error]
}

func (u *countingUninstaller) Start(context.Context) error {
	u.starts.Add(1)
	if e := u.err.Load(); e != nil {
		return *e
	}
	return nil
}

func (u *countingUninstaller) ThroughHelper() bool { return false }

type urig struct {
	base string
	iss  *approvaltest.Issuer
	u    *countingUninstaller
	log  *logBuf
}

type urigOpts struct {
	enabled bool // config.yaml: uninstall.enabled (Run builds an Uninstaller only then)
	gate    bool // the agent has its approval gate (Run always builds one)
	trust   bool // the trust is set from the panel, once, with its proof
}

func newUninstallRig(t *testing.T, o urigOpts) *urig {
	t.Helper()
	conf := "control_rate_per_min: 60\n"
	if o.enabled {
		conf += "uninstall: {enabled: true}\n"
	}
	cfg, err := agent.Parse([]byte(conf), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlEnabled() != o.enabled {
		t.Fatalf("ControlEnabled %v with uninstall.enabled %v", cfg.ControlEnabled(), o.enabled)
	}
	r := &urig{iss: approvaltest.New(), u: &countingUninstaller{}, log: &logBuf{}}
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test"}
	if o.enabled {
		d.Uninstaller = r.u
	}
	if o.gate {
		d.Approval = approval.NewGate(approval.Options{Files: approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)},
			EnforcedBy: api.EnforcedByAgent, Log: slog.New(slog.NewTextHandler(r.log, nil))})
	}
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(srv.Close)
	r.base = srv.URL
	if o.trust {
		st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init()))
		if st != 200 || b["state"] != api.ApprovalRequired {
			t.Fatalf("first-time set: %d %v", st, b)
		}
	}
	return r
}

func (r *urig) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, r.base, "POST", path, ctlTok, body)
}

// approve asks this machine for a challenge for req and has it approved, as the panel and Pocket ID do.
func (r *urig) approve(t *testing.T, req map[string]any) *api.Approval {
	t.Helper()
	st, c := r.post(t, api.PathApprovalChallenge, req)
	if st != 200 || c["needed"] != true {
		t.Fatalf("challenge for %v: %d %v", req, st, c)
	}
	return r.iss.Approve(time.Now(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c["challenge"].(string), Request: c["request"].(string)})
}

var uninstallVerb = map[string]any{"verb": api.ApproveUninstall}

func (r *urig) features(t *testing.T) map[string]any {
	t.Helper()
	time.Sleep(260 * time.Millisecond) // past the /metrics cache
	_, m := do(t, r.base, "GET", "/metrics", readTok, nil)
	f, _ := m["features"].(map[string]any)
	return f
}

// Off in config.yaml: the route and its challenge are closed (404 uninstall_disabled), and the panel is told so.
func TestUninstallClosedUnlessEnabled(t *testing.T) {
	r := newUninstallRig(t, urigOpts{gate: true, trust: false})
	st, b := r.post(t, api.PathUninstall, map[string]any{})
	if st != 404 || b["code"] != api.CodeUninstallDisabled {
		t.Errorf("uninstall while off: %d %v", st, b)
	}
	st, b = r.post(t, api.PathApprovalChallenge, uninstallVerb)
	if st != 404 || b["code"] != api.CodeUninstallDisabled {
		t.Errorf("challenge while off: %d %v", st, b)
	}
	if f := r.features(t); f["uninstall"] != false {
		t.Errorf("features: %v", f)
	}
	if n := r.u.starts.Load(); n != 0 {
		t.Fatalf("the removal was started %d times", n)
	}
}

// On, but no trust file, or no gate at all: 409 approval_off for the challenge and the request, whatever comes
// with it. Never "needs no approval", which every older request gets on such a machine.
func TestUninstallRefusedWithoutTrust(t *testing.T) {
	for _, o := range []urigOpts{{enabled: true, gate: true}, {enabled: true, gate: false}} {
		r := newUninstallRig(t, o)
		what := map[bool]string{true: "no trust file", false: "no gate"}[o.gate]
		st, b := r.post(t, api.PathApprovalChallenge, uninstallVerb)
		wantRefusal(t, what+": challenge", st, b, 409, api.CodeApprovalOff)
		st, b = r.post(t, api.PathUninstall, map[string]any{})
		wantRefusal(t, what+": uninstall", st, b, 409, api.CodeApprovalOff)
		madeUp := map[string]any{"approval": map[string]any{"token": "a.b.c", "entries": []map[string]any{{"machine_id": approvaltest.MachineID,
			"challenge": strings.Repeat("A", 43), "request": "uninstall"}}}}
		st, b = r.post(t, api.PathUninstall, madeUp)
		wantRefusal(t, what+": uninstall with a made-up approval", st, b, 409, api.CodeApprovalOff)
		if f := r.features(t); f["uninstall"] != true {
			t.Errorf("%s: features: %v", what, f)
		}
		if n := r.u.starts.Load(); n != 0 {
			t.Fatalf("%s: the removal was started %d times", what, n)
		}
	}
}

// With trust: only the control token, a strict body and a good approval of this exact request start it, once.
func TestUninstallNeedsAnApproval(t *testing.T) {
	r := newUninstallRig(t, urigOpts{enabled: true, gate: true, trust: true})

	// no token, the read token: refused before anything
	if st, _ := do(t, r.base, "POST", api.PathUninstall, "", map[string]any{}); st != 401 {
		t.Errorf("no token: %d", st)
	}
	if st, _ := do(t, r.base, "POST", api.PathUninstall, readTok, map[string]any{}); st != 401 {
		t.Errorf("the read token: %d", st)
	}
	// a body with a member it does not have
	if st, b := r.post(t, api.PathUninstall, map[string]any{"keep_data": false}); st != 400 {
		t.Errorf("unknown member: %d %v", st, b)
	}
	// no approval
	st, b := r.post(t, api.PathUninstall, map[string]any{})
	wantRefusal(t, "no approval", st, b, 403, api.CodeApprovalRequired)
	// a token for a challenge this machine never gave (whatever was signed, nothing is open for it)
	forged := r.iss.Approve(time.Now(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: "uninstall"})
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": forged})
	wantRefusal(t, "an approval for a challenge this machine never gave", st, b, 403, api.CodeApprovalRefused)
	if n := r.u.starts.Load(); n != 0 {
		t.Fatalf("refused requests started the removal %d times", n)
	}

	// the approval of this request: started, once
	ap := r.approve(t, uninstallVerb)
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": ap, "requested_by": "admin@example"})
	if st != 202 || b["state"] != api.UninstallStarted {
		t.Fatalf("approved: %d %v", st, b)
	}
	if n := r.u.starts.Load(); n != 1 {
		t.Fatalf("started %d times", n)
	}
	// the same approval again: refused (used up)
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": ap})
	wantRefusal(t, "the same approval again", st, b, 403, api.CodeApprovalRefused)
	// a fresh approval: still nothing more, this process has started its removal already; the approval is
	// not used up by that refusal
	ap2 := r.approve(t, uninstallVerb)
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": ap2})
	if st != 409 || b["code"] != api.CodeUninstallBusy {
		t.Errorf("a second uninstall: %d %v", st, b)
	}
	if n := r.u.starts.Load(); n != 1 {
		t.Fatalf("started %d times", n)
	}
	for _, secret := range []string{ap.Token, ap2.Token, ctlTok, readTok} {
		if strings.Contains(r.log.String(), secret) {
			t.Fatal("a token is in the gate's log")
		}
	}
}

// A start that fails is 502 and releases the once: a new approval may try again. The approval of the failed
// try is used up.
func TestUninstallStartThatFails(t *testing.T) {
	r := newUninstallRig(t, urigOpts{enabled: true, gate: true, trust: true})
	e := errors.New("systemctl start --no-block fairy-agent-uninstall.service: exit status 1 Access denied")
	r.u.err.Store(&e)
	ap := r.approve(t, uninstallVerb)
	st, b := r.post(t, api.PathUninstall, map[string]any{"approval": ap})
	if st != 502 || !strings.Contains(b["error"].(string), "could not be started") {
		t.Fatalf("failed start: %d %v", st, b)
	}
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": ap})
	wantRefusal(t, "the approval of the failed try", st, b, 403, api.CodeApprovalRefused)
	r.u.err.Store(nil)
	st, b = r.post(t, api.PathUninstall, map[string]any{"approval": r.approve(t, uninstallVerb)})
	if st != 202 {
		t.Fatalf("after a failed start, with a new approval: %d %v", st, b)
	}
	if n := r.u.starts.Load(); n != 2 {
		t.Fatalf("started %d times", n)
	}
}

// Two requests with two good approvals at the same moment: one removal.
func TestUninstallOnceUnderConcurrency(t *testing.T) {
	r := newUninstallRig(t, urigOpts{enabled: true, gate: true, trust: true})
	aps := []*api.Approval{r.approve(t, uninstallVerb), r.approve(t, uninstallVerb), r.approve(t, uninstallVerb)}
	codes := make(chan int, len(aps))
	for _, ap := range aps {
		go func() {
			st, _ := r.post(t, api.PathUninstall, map[string]any{"approval": ap})
			codes <- st
		}()
	}
	got := map[int]int{}
	for range aps {
		got[<-codes]++
	}
	if got[202] != 1 || r.u.starts.Load() != 1 {
		t.Fatalf("answers %v, %d starts", got, r.u.starts.Load())
	}
}
