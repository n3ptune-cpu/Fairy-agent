package helper

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

const helperRun = "00000000000000e5"

// runHelper is a helper with power control and a gate that keeps runs, on a machine that started 60 s ago.
type runHelper struct {
	srv   *Server
	exec  *agenttest.PowerExec
	audit *syncBuf
	iss   *approvaltest.Issuer
	now   time.Time
	up    time.Duration
}

func newRunHelper(t *testing.T, power bool) *runHelper {
	t.Helper()
	h := &runHelper{exec: &agenttest.PowerExec{}, audit: &syncBuf{}, iss: approvaltest.New(), now: time.Now(), up: 60 * time.Second}
	log := slog.New(slog.NewTextHandler(h.audit, nil))
	files := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	p := Parts{Version: "test", MinDelayS: 30, Audit: log,
		Approval: approval.NewGate(approval.Options{Files: files, EnforcedBy: api.EnforcedByHelper, Log: log, Runs: true, MinDelayS: 30,
			Now: func() time.Time { return h.now }, Uptime: func() (time.Duration, error) { return h.up, nil },
			BootID: func() (string, error) { return "0f1e2d3c4b5a69788796a5b4c3d2e1f0", nil }})}
	if power {
		p.Power = agent.RememberPower(h.exec, nil, nil, nil)
	}
	h.srv = New(p)
	h.srv.limit = proto.NewLimiter(1000, 1000, time.Minute)
	in := h.iss.Init()
	hash := api.TrustHash(in)
	var c api.ChallengeResponse
	resp := h.v3(t, proto.Request{Verb: proto.VerbChallenge, For: ptr(proto.ForTrustSet), TrustHash: &hash})
	if resp.Status != 200 || json.Unmarshal(resp.Data, &c) != nil {
		t.Fatalf("challenge: %+v", resp)
	}
	in = h.iss.Prove(h.now, in, api.MachineEntry{MachineID: in.MachineID, Challenge: c.Challenge, Request: c.Request})
	if resp := h.v3(t, proto.Request{Verb: proto.VerbTrustInit, Trust: &in}); resp.Status != 200 {
		t.Fatalf("trust_init: %+v", resp)
	}
	// the run record this PC has from a boot before (one that is made now would close this boot for tickets)
	if err := approvaltest.EarlierBoot(files, h.now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *runHelper) v3(t *testing.T, req proto.Request) proto.Response {
	t.Helper()
	b, err := proto.EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode %+v: %v", req, err)
	}
	return h.srv.HandleV3(context.Background(), "test-client", b)
}

func (h *runHelper) ticket() *api.Approval {
	var b [32]byte
	rand.Read(b[:])
	run, valid, wait, notice := helperRun, 420, 960, 120
	text, _ := (api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}).Canonical()
	return h.iss.Approve(h.now.Add(-160*time.Second), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: approvaltest.B64(b[:]), Request: text})
}

// The helper takes the ticket itself, says so in its own log with the run, who signed and the key, and shows
// the run in its status. The token is in neither. When the wait is over it schedules the shutdown through its
// own power part, with the notice of a run and under the run's name; a cancel of the pending action ends the run.
func TestHelperKeepsTheRun(t *testing.T) {
	h := newRunHelper(t, true)
	ap := h.ticket()
	resp := h.v3(t, proto.Request{Verb: proto.VerbRunArm, Approval: ap, By: ptr("panel 192.0.2.1")})
	var ans api.RunAnswer
	if resp.Status != 200 || json.Unmarshal(resp.Data, &ans) != nil || ans != (api.RunAnswer{Run: helperRun, State: api.RunArmed, OffInS: 960}) {
		t.Fatalf("run_arm: %+v", resp)
	}
	var sd proto.StatusData
	st := h.srv.Handle(context.Background(), "test-client", []byte(`{"v":1,"verb":"status"}`))
	if json.Unmarshal(st.Data, &sd) != nil || sd.Approval == nil || sd.Approval.Runs != 1 || sd.Approval.Run == nil || sd.Approval.Run.State != api.RunArmed || sd.Approval.Proto != 2 {
		t.Fatalf("status: %s", st.Data)
	}
	log := h.audit.String()
	for _, want := range []string{`msg="approval: run armed"`, "run=" + helperRun, "sub=" + approvaltest.User, "kid=" + approvaltest.Kid, "verb=run_arm", `by="panel 192.0.2.1"`} {
		if !strings.Contains(log, want) {
			t.Errorf("helper.log lacks %s:\n%s", want, log)
		}
	}
	for _, part := range strings.Split(ap.Token, ".") {
		if strings.Contains(log, part[:24]) || strings.Contains(string(st.Data), part[:24]) {
			t.Error("the token is in the helper's log or status")
		}
	}
	// the same ticket again, and a ticket to a challenge
	if resp := h.v3(t, proto.Request{Verb: proto.VerbRunArm, Approval: ap}); resp.Status != 409 || resp.Code != api.CodeRunRefused || resp.Reason != api.RunReasonArmedThisBoot || len(resp.Data) != 0 {
		t.Errorf("the same ticket again: %+v", resp)
	}
	h.up += 960 * time.Second
	h.now = h.now.Add(960 * time.Second)
	h.srv.Runs().Tick()
	if len(h.exec.Scheduled) != 1 || h.exec.Scheduled[0] != "shutdown@2m0s" {
		t.Fatalf("scheduled %v", h.exec.Scheduled)
	}
	st = h.srv.Handle(context.Background(), "test-client", []byte(`{"v":1,"verb":"status"}`))
	sd = proto.StatusData{}
	if json.Unmarshal(st.Data, &sd) != nil || sd.Power == nil || sd.Power.Action != "shutdown" || sd.Power.DelayS != 120 || sd.Power.By != "run "+helperRun || sd.Approval.Run.State != api.RunOffPending {
		t.Fatalf("status during the countdown: %s", st.Data)
	}
	if resp := h.srv.Handle(context.Background(), "test-client", []byte(`{"v":1,"verb":"power","action":"cancel","by":"agent"}`)); resp.Status != 200 {
		t.Fatalf("cancel: %+v", resp)
	}
	if h.exec.Cancels != 1 || h.srv.p.Approval.Status().Run.State != api.RunCancelled {
		t.Fatalf("after the cancel: %d cancels, %+v", h.exec.Cancels, h.srv.p.Approval.Status().Run)
	}
}

// Without power control the helper keeps no runs: a run ends with a shutdown.
func TestHelperWithoutPowerTakesNoRun(t *testing.T) {
	h := newRunHelper(t, false)
	if h.srv.Runs() != nil {
		t.Fatal("a watch without a power part")
	}
	resp := h.v3(t, proto.Request{Verb: proto.VerbRunArm, Approval: h.ticket()})
	wantCode(t, "run_arm", resp, 404, proto.CodeDisabled)
	run, to, delay, within, forGo := helperRun, "-", 30, 300, proto.ForRunGo
	resp = h.v3(t, proto.Request{Verb: proto.VerbChallenge, For: &forGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within})
	wantCode(t, "challenge for run_go", resp, 404, proto.CodeDisabled)
	resp = h.v3(t, proto.Request{Verb: proto.VerbRunGo, Run: &run, To: &to, ShutdownDelayS: &delay, WithinS: &within})
	wantCode(t, "run_go", resp, 404, proto.CodeDisabled)
}
