package agent_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release/releasetest"
)

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

// aprig is a Windows agent as the panel sees it: the agent's HTTP API in front of a helper that checks
// approvals (the real helper code on an in-memory pipe), with fans, power and self-update.
type aprig struct {
	*hrig
	iss          *approvaltest.Issuer
	gh           *releasetest.Server
	upd          *agent.Updater
	audit        *logBuf
	ownStarts    atomic.Int32 // the agent started the installer with its own right
	helperStarts atomic.Int32 // the helper started it
	base         string
}

func newApprovalRig(t *testing.T) *aprig {
	t.Helper()
	cfg, err := agent.Parse([]byte("ipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\nself_update: {enabled: true}\ncontrol_rate_per_min: 60\n"),
		filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &aprig{hrig: &hrig{bmc: fakebmc.X11SCAF(), power: &agenttest.PowerExec{}}, iss: approvaltest.New(), audit: &logBuf{},
		gh: releasetest.New(t, release.AgentRepo)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b := agent.NewBMC(r.bmc, 20*time.Millisecond)
	go b.Run(ctx)
	fan := agent.NewFan(r.bmc, b, cfg.FanControl, nil)
	log := slog.New(slog.NewTextHandler(r.audit, nil))
	srv := helper.New(helper.Parts{Version: "test", BMC: b, Fan: fan, Power: r.power, Audit: log,
		Updater: func(context.Context) error { r.helperStarts.Add(1); return nil },
		Approval: approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByHelper, Log: log,
			Files: approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}})})
	r.scm = &fakeSCM{state: api.HelperRunning, srv: srv}
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		if st, _ := r.scm.State(); st != api.HelperRunning {
			return nil, errors.New("pipe not found")
		}
		a, c := net.Pipe()
		go func() { srv.ServeConn(ctx, a, "test"); a.Close() }()
		return c, nil
	}
	r.client = agent.NewHelperClient(dial, r.scm, true)
	r.client.Every = 10 * time.Millisecond
	dir := t.TempDir()
	r.upd = agent.NewUpdater(agent.UpdaterOptions{Version: "41-aaaaaaa", Key: r.gh.Pub, Client: r.gh.Client(),
		StageDir: filepath.Join(dir, "state", "update"), ResultPath: filepath.Join(dir, "result", "result.json"),
		Asset: "fairy-agent-linux-amd64", ResultWait: 50 * time.Millisecond,
		Apply:         func(context.Context) error { r.ownStarts.Add(1); return nil },
		ApplyApproved: r.client.ApplyUpdateApproved})
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: r.client,
		Fan: r.client.Fan(cfg.FanControl), Power: agent.NewPower(r.client.Power(), cfg.PowerControl.MinDelayS), Updater: r.upd,
		HelperSources: []string{api.FeatureFans, api.FeaturePower}}
	r.srv = httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(r.srv.Close)
	r.base = r.srv.URL
	return r
}

func (r *aprig) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, r.base, "POST", path, ctlTok, body)
}

// approvalBlock is the "approval" block of /metrics once it shows state want.
func (r *aprig) approvalBlock(t *testing.T, want string) map[string]any {
	t.Helper()
	var m map[string]any
	for i := 0; i < 300; i++ {
		_, m = do(t, r.base, "GET", "/metrics", readTok, nil)
		if ap, ok := m["approval"].(map[string]any); ok && ap["state"] == want {
			return ap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("approval never %s: %v", want, m["approval"])
	return nil
}

// approve asks the agent for a challenge for req (in the panel's terms) and has the issuer approve it.
func (r *aprig) approve(t *testing.T, req map[string]any) *api.Approval {
	t.Helper()
	st, c := r.post(t, api.PathApprovalChallenge, req)
	if st != 200 || c["needed"] != true || c["issuer"] != r.iss.URL || c["client_id"] != r.iss.ClientID {
		t.Fatalf("challenge for %v: %d %v", req, st, c)
	}
	return r.iss.Approve(time.Now(), api.ApprovalEntry{Challenge: c["challenge"].(string), Request: c["request"].(string)})
}

func wantRefusal(t *testing.T, what string, st int, body map[string]any, status int, code string) {
	t.Helper()
	if st != status || body["code"] != code || body["error"] == nil || body["error"] == "" {
		t.Errorf("%s: %d %v, want %d %s", what, st, body, status, code)
	}
}

// TestApprovalThroughAgentAndHelper is the panel's view of a Windows machine: trust off behaves as before, the
// first-time set, then every control route with and without approval.
func TestApprovalThroughAgentAndHelper(t *testing.T) {
	r := newApprovalRig(t)
	m := r.metrics(t, api.HelperRunning)
	if hs := m["helper"].(map[string]any); hs["proto"] != float64(2) {
		t.Fatalf("helper block: %v", hs)
	}
	if ap := r.approvalBlock(t, api.ApprovalOff); ap["enforced_by"] != api.EnforcedByHelper || ap["proto"] != float64(1) || ap["issuer"] != nil {
		t.Fatalf("approval block: %v", ap)
	}
	// trust off: an old panel's requests work as before, and a challenge says none is needed
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full"}); st != 200 {
		t.Fatalf("fan mode without trust: %d %v", st, b)
	}
	if st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "full"}); st != 200 || c["needed"] != false || c["reason"] != "off" {
		t.Fatalf("challenge without trust: %d %v", st, c)
	}

	// first-time set, once
	st, ap := r.post(t, api.PathApprovalTrust, r.iss.Init())
	if st != 200 || ap["state"] != api.ApprovalRequired || ap["issuer"] != r.iss.URL || ap["users"] != float64(1) {
		t.Fatalf("first-time set: %d %v", st, ap)
	}
	blk := r.approvalBlock(t, api.ApprovalRequired)
	keys, _ := blk["keys"].([]any)
	if blk["client_id"] != r.iss.ClientID || len(keys) != 1 || blk["fan_window_s"] != float64(30) || blk["boot_shutdown_s"] != float64(0) {
		t.Fatalf("approval block: %v", blk)
	}
	if k := keys[0].(map[string]any); k["kid"] != r.iss.Kid || k["alg"] != "RS256" || len(k["thumbprint"].(string)) != 43 {
		t.Fatalf("key: %v", k)
	}
	raw, _ := json.Marshal(blk)
	if strings.Contains(string(raw), approvaltest.User) || strings.Contains(string(raw), r.iss.Init().Keys[0].N) {
		t.Error("/metrics shows an allowed user or a whole key")
	}
	st, b := r.post(t, api.PathApprovalTrust, r.iss.Init("somebody-else"))
	wantRefusal(t, "second set", st, b, 409, api.CodeTrustAlreadySet)
	bad := r.iss.Init()
	st, b = r.post(t, api.PathApprovalTrust, map[string]any{"issuer": bad.Issuer, "client_id": bad.ClientID, "keys": bad.Keys, "users": bad.Users, "fan_window_s": 60})
	wantRefusal(t, "set with a setting only the machine has", st, b, 400, api.CodeTrustInvalid)

	// without approval: refused with the helper's code, nothing runs
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "standard"})
	wantRefusal(t, "fan mode", st, b, 403, api.CodeApprovalRequired)
	st, b = r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 50})
	wantRefusal(t, "fan duty", st, b, 403, api.CodeApprovalRequired)
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown", st, b, 403, api.CodeApprovalRequired)
	if r.mode(t) != "full" || len(r.power.Scheduled) != 0 {
		t.Fatalf("something ran: mode %s, power %v", r.mode(t), r.power.Scheduled)
	}
	// cancel is free (nothing pending: 200 as before)
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Errorf("cancel: %d %v", st, b)
	}

	// approved shutdown; the same approval again; the approval of one action for another
	ok := r.approve(t, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "neptune", "approval": ok}); st != 200 || b["pending"] == nil {
		t.Fatalf("approved shutdown: %d %v", st, b)
	}
	if len(r.power.Scheduled) != 1 {
		t.Fatalf("scheduled: %v", r.power.Scheduled)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Fatalf("cancel of the approved shutdown, without approval: %d %v", st, b)
	}
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": ok})
	wantRefusal(t, "replay", st, b, 403, api.CodeApprovalRefused)
	fanOK := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 50})
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": fanOK})
	wantRefusal(t, "fan approval for a reboot", st, b, 403, api.CodeApprovalRefused)
	st, b = r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": fanOK})
	wantRefusal(t, "fan approval for another duty", st, b, 403, api.CodeApprovalRefused)
	// a delay the panel did not name in the challenge: the agent's default (60) is what the helper sees
	def := r.approve(t, map[string]any{"verb": "power", "action": "reboot", "delay_s": 61})
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "approval": def})
	wantRefusal(t, "approved for 61 s, sent without delay_s", st, b, 403, api.CodeApprovalRefused)
	if len(r.power.Scheduled) != 1 {
		t.Fatalf("scheduled: %v", r.power.Scheduled)
	}
	// the approved fan change, then the fan window
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 50, "approval": fanOK}); st != 200 {
		t.Fatalf("approved fan duty: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 1, "percent": 60}); st != 200 {
		t.Errorf("fan duty in the fan window: %d %v", st, b)
	}
	if st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "optimal"}); st != 200 || c["needed"] != false || c["reason"] != "fan_window" {
		t.Errorf("challenge in the fan window: %d %v", st, c)
	}

	// challenge requests that are refused
	for name, c := range map[string]struct {
		body   any
		status int
	}{
		"a read":           {map[string]any{"verb": "status"}, 400},
		"cancel":           {map[string]any{"verb": "power", "action": "cancel"}, 400},
		"fan_auto":         {map[string]any{"verb": "fan_auto"}, 400},
		"missing field":    {map[string]any{"verb": "power", "action": "shutdown"}, 400},
		"extra field":      {map[string]any{"verb": "apply_update", "zone": 0}, 400},
		"unknown member":   {map[string]any{"verb": "apply_update", "by": "x"}, 400},
		"not an object":    {[]string{"apply_update"}, 400},
		"a wrong type":     {map[string]any{"verb": "fan_set", "zone": "0", "percent": 50}, 400},
		"a value too high": {map[string]any{"verb": "fan_set", "zone": 0, "percent": 101}, 400},
		// values the request text allows and the helper does not (its own limits: 30 % at least, 10 s at least)
		"a duty the helper never sets":  {map[string]any{"verb": "fan_set", "zone": 0, "percent": 20}, 400},
		"a delay the helper never uses": {map[string]any{"verb": "power", "action": "reboot", "delay_s": 5}, 400},
	} {
		if st, b := r.post(t, api.PathApprovalChallenge, c.body); st != c.status || b["challenge"] != nil {
			t.Errorf("challenge for %s: %d %v", name, st, b)
		}
	}
	if st, _ := do(t, r.base, "POST", api.PathApprovalChallenge, readTok, map[string]any{"verb": "apply_update"}); st != 401 {
		t.Errorf("challenge with the read token: %d", st)
	}
	if st, _ := do(t, r.base, "POST", api.PathApprovalTrust, "", r.iss.Init()); st != 401 {
		t.Errorf("trust without a token: %d", st)
	}

	// the helper's own log has every decision and no token
	log := r.audit.String()
	for _, want := range []string{"approval: accepted", "approval: refused", "approval: required, none sent", "trust set for the first time"} {
		if !strings.Contains(log, want) {
			t.Errorf("helper log lacks %q", want)
		}
	}
	for _, part := range strings.Split(ok.Token, ".") {
		if strings.Contains(log, part) {
			t.Error("helper log holds a part of a token")
		}
	}
}

// TestUpdateWithHelperApproval: while the helper's check is on, an update needs an approval at the agent
// already and the installer is started by the helper, which checks it; with trust off the agent starts it
// itself, as before.
func TestUpdateWithHelperApproval(t *testing.T) {
	r := newApprovalRig(t)
	r.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{"fairy-agent-linux-amd64": []byte("build 42")}, nil)
	wait := func() agent.UpdateStatus {
		t.Helper()
		for i := 0; i < 500; i++ {
			if st := r.upd.Status(); st.State != "downloading" && st.State != "applying" {
				return st
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("the update did not finish")
		return agent.UpdateStatus{}
	}
	// trust off: as before, also when a panel sends an approval nobody asked for
	r.approvalBlock(t, api.ApprovalOff)
	if st, b := r.post(t, "/update", map[string]any{"requested_by": "neptune", "approval": map[string]any{"token": "x", "entries": []any{}}}); st != 202 {
		t.Fatalf("update without trust: %d %v", st, b)
	}
	wait()
	if r.ownStarts.Load() != 1 || r.helperStarts.Load() != 0 {
		t.Fatalf("trust off: own %d, helper %d", r.ownStarts.Load(), r.helperStarts.Load())
	}

	if st, b := r.post(t, api.PathApprovalTrust, r.iss.Init()); st != 200 {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	r.approvalBlock(t, api.ApprovalRequired)
	st, b := r.post(t, "/update", map[string]any{"requested_by": "neptune"})
	wantRefusal(t, "update without approval", st, b, 403, api.CodeApprovalRequired)
	// a made-up approval: accepted for download (202), refused by the helper when the installer should start
	junk := &api.Approval{Token: "a.b.c", Entries: []api.ApprovalEntry{{Challenge: strings.Repeat("A", 43), Request: "apply_update"}}}
	if st, b := r.post(t, "/update", map[string]any{"approval": junk}); st != 202 {
		t.Fatalf("update with a made-up approval: %d %v", st, b)
	}
	if st := wait(); st.State != "failed" || !strings.Contains(st.Message, "approval refused") {
		t.Fatalf("made-up approval: %+v", st)
	}
	if r.ownStarts.Load() != 1 || r.helperStarts.Load() != 0 {
		t.Fatalf("made-up approval: own %d, helper %d", r.ownStarts.Load(), r.helperStarts.Load())
	}
	// a real one: the helper starts the installer, the agent's own right is not used
	ok := r.approve(t, map[string]any{"verb": "apply_update"})
	if st, b := r.post(t, "/update", map[string]any{"approval": ok}); st != 202 {
		t.Fatalf("approved update: %d %v", st, b)
	}
	wait()
	if r.ownStarts.Load() != 1 || r.helperStarts.Load() != 1 {
		t.Fatalf("approved update: own %d, helper %d", r.ownStarts.Load(), r.helperStarts.Load())
	}
	// the helper stopped: the agent still knows its check was on, and does not fall back to its own right
	if st, b := r.post(t, api.PathHelperStop, map[string]any{}); st != 200 {
		t.Fatalf("helper stop with trust set (fans to automatic needs no approval): %d %v", st, b)
	}
	if blk := r.approvalBlock(t, api.ApprovalUnknown); blk["enforced_by"] != api.EnforcedByHelper {
		t.Fatalf("approval block while stopped: %v", blk)
	}
	st, b = r.post(t, "/update", map[string]any{})
	wantRefusal(t, "update while the helper is stopped", st, b, 403, api.CodeApprovalRequired)
	st, b = r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "apply_update"})
	wantRefusal(t, "challenge while the helper is stopped", st, b, 503, api.ReasonHelperStopped)
	st, b = r.post(t, api.PathApprovalTrust, r.iss.Init())
	wantRefusal(t, "trust while the helper is stopped", st, b, 503, api.ReasonHelperStopped)
	if r.ownStarts.Load() != 1 {
		t.Fatal("the agent started the installer itself while the helper was stopped")
	}
	if st, b := r.post(t, api.PathHelperStart, map[string]any{}); st != 200 {
		t.Fatalf("helper start: %d %v", st, b)
	}
	r.approvalBlock(t, api.ApprovalRequired)
}

// oldHelper answers like fairy-agent-helper 0.6.0: frames of at most 512 bytes, protocol version 1, a status
// without "proto" and "approval".
func oldHelper(t *testing.T, conn net.Conn) {
	defer conn.Close()
	reply := func(r proto.Response) bool {
		b, _ := json.Marshal(r)
		return proto.WriteFrame(conn, b, proto.MaxResponse) == nil
	}
	for {
		f, err := proto.ReadFrame(conn, 512)
		if errors.Is(err, proto.ErrFrameTooLarge) {
			reply(proto.Fail(proto.CodeTooLarge, "request too large"))
			return
		}
		if err != nil {
			return
		}
		var req struct {
			V    int    `json:"v"`
			Verb string `json:"verb"`
		}
		switch {
		case json.Unmarshal(f, &req) != nil || req.V != 1:
			reply(proto.Fail(proto.CodeBadRequest, "protocol version"))
		case req.Verb == proto.VerbStatus:
			reply(proto.OK(map[string]any{"version": "0.6.0", "started": "2026-11-11T10:00:00Z", "features": []string{"power"}, "watchdog": false, "sleep_ok": true}))
		default:
			t.Errorf("the old helper was asked %q", req.Verb)
			reply(proto.OK(map[string]bool{}))
		}
	}
}

// TestNewAgentOldHelper: an agent of this version in front of a helper from before approvals (an update that
// has not restarted the helper yet): no approval block, both routes say helper_too_old, nothing is sent to the
// helper that it does not know.
func TestNewAgentOldHelper(t *testing.T) {
	cfg, err := agent.Parse([]byte("power_control: {enabled: true}\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	scm := &fakeSCM{state: api.HelperRunning}
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		a, c := net.Pipe()
		go oldHelper(t, a)
		return c, nil
	}
	client := agent.NewHelperClient(dial, scm, true)
	client.Every = 10 * time.Millisecond
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: client,
		Power: agent.NewPower(client.Power(), cfg.PowerControl.MinDelayS), HelperSources: []string{api.FeaturePower}}
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(srv.Close)
	var m map[string]any
	for i := 0; i < 200; i++ {
		_, m = do(t, srv.URL, "GET", "/metrics", readTok, nil)
		if hs, ok := m["helper"].(map[string]any); ok && hs["state"] == api.HelperRunning {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if hs := m["helper"].(map[string]any); hs["proto"] != nil || hs["version"] != "0.6.0" {
		t.Fatalf("helper block: %v", hs)
	}
	if _, has := m["approval"]; has {
		t.Fatalf("an approval block with a helper from before approvals: %v", m["approval"])
	}
	st, b := do(t, srv.URL, "POST", api.PathApprovalChallenge, ctlTok, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	wantRefusal(t, "challenge", st, b, 409, api.CodeHelperTooOld)
	st, b = do(t, srv.URL, "POST", api.PathApprovalTrust, ctlTok, approvaltest.New().Init())
	wantRefusal(t, "trust", st, b, 409, api.CodeHelperTooOld)
}

// TestApprovalRoutesWithoutAChecker: an agent with nothing that checks approvals (Windows without the helper;
// here: no helper at all) has no approval block and answers both routes 404 approval_disabled.
func TestApprovalRoutesWithoutAChecker(t *testing.T) {
	h := newHelperRig(t, api.HelperNotInstalled)
	_, m := do(t, h.srv.URL, "GET", "/metrics", readTok, nil)
	if _, has := m["approval"]; has {
		t.Fatalf("approval block: %v", m["approval"])
	}
	for _, path := range []string{api.PathApprovalChallenge, api.PathApprovalTrust} {
		st, b := do(t, h.srv.URL, "POST", path, ctlTok, map[string]any{"verb": "apply_update"})
		wantRefusal(t, path, st, b, 404, api.CodeApprovalDisabled)
	}
}
