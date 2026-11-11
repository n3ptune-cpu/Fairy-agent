package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

// arig is a helper with fans, power and the updater, and an approval gate on a trust file in its own folder.
type arig struct {
	*rig
	iss     *approvaltest.Issuer
	files   approval.Files
	updates int
}

func newApprovalRig(t *testing.T) *arig {
	t.Helper()
	a := &arig{rig: &rig{bmc: fakebmc.X11SCAF(), power: &agenttest.PowerExec{}, audit: &syncBuf{}}, iss: approvaltest.New()}
	a.b = agent.NewBMC(a.bmc, 20*time.Millisecond)
	a.fan = agent.NewFan(a.bmc, a.b, fanCfg, nil)
	a.files = approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	a.srv = a.server()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go a.b.Run(ctx)
	waitFor(t, func() bool { tt, _, _ := a.b.Metrics(); return len(tt) > 0 })
	return a
}

// server is a helper process on this machine's trust file (again: the helper restarted).
func (a *arig) server() *Server {
	log := slog.New(slog.NewTextHandler(a.audit, nil))
	srv := New(Parts{Version: "test", BMC: a.b, Fan: a.fan, Power: a.power, MinDelayS: 30, Audit: log,
		Updater:  func(context.Context) error { a.updates++; return nil },
		Approval: approval.NewGate(approval.Options{Files: a.files, EnforcedBy: api.EnforcedByHelper, Log: log})})
	srv.limit = proto.NewLimiter(1000, 1000, time.Minute) // these tests are not about the rate limit
	return srv
}

// v2 sends a protocol version 2 request the way the agent does.
func (a *arig) v2(t *testing.T, req proto.Request) proto.Response {
	t.Helper()
	b, err := proto.EncodeRequest(req)
	if err != nil {
		t.Fatalf("encode %+v: %v", req, err)
	}
	if proto.FrameVersion(req) != proto.Version2 {
		t.Fatalf("%s is not a version 2 request", req.Verb)
	}
	return a.srv.HandleV2(context.Background(), "test-client", b)
}

func (a *arig) trust(t *testing.T) {
	t.Helper()
	in := a.iss.Init()
	if resp := a.v2(t, proto.Request{Verb: proto.VerbTrustInit, Trust: &in}); resp.Status != 200 {
		t.Fatalf("trust_init: %+v", resp)
	}
}

func (a *arig) status(t *testing.T) proto.StatusData {
	t.Helper()
	var sd proto.StatusData
	resp := a.call(t, `{"v":1,"verb":"status"}`)
	if resp.Status != 200 || json.Unmarshal(resp.Data, &sd) != nil {
		t.Fatalf("status: %+v", resp)
	}
	return sd
}

// approvalFor asks the helper for a challenge for req and has the issuer approve it.
func (a *arig) approvalFor(t *testing.T, req proto.Request) *api.Approval {
	t.Helper()
	ch := req
	ch.For, ch.Verb, ch.By, ch.Approval = &req.Verb, proto.VerbChallenge, nil, nil
	resp := a.v2(t, ch)
	var c api.ChallengeResponse
	if resp.Status != 200 || json.Unmarshal(resp.Data, &c) != nil || !c.Needed {
		t.Fatalf("challenge for %s: %+v", req.Verb, resp)
	}
	return a.iss.Approve(time.Now(), api.ApprovalEntry{Challenge: c.Challenge, Request: c.Request})
}

func ptr[T any](v T) *T { return &v }

func fanSetReq(zone, pct int) proto.Request {
	return proto.Request{Verb: proto.VerbFanSet, Zone: &zone, Percent: &pct, By: ptr("test")}
}

func powerReq(action string, delay int) proto.Request {
	return proto.Request{Verb: proto.VerbPower, Action: &action, DelayS: &delay, By: ptr("test")}
}

func wantCode(t *testing.T, what string, resp proto.Response, status int, code string) {
	t.Helper()
	if resp.Status != status || resp.Code != code {
		t.Errorf("%s: %d %s %q, want %d %s", what, resp.Status, resp.Code, resp.Error, status, code)
	}
	if code != "" && len(resp.Data) != 0 {
		t.Errorf("%s: a refusal carries data (an older agent would pass the data on instead of the code)", what)
	}
}

// TestNoTrustBehavesAsBefore: without a trust file every verb answers as it did, and the status says so.
func TestNoTrustBehavesAsBefore(t *testing.T) {
	a := newApprovalRig(t)
	sd := a.status(t)
	if sd.Proto != 2 || sd.Approval == nil || sd.Approval.State != api.ApprovalOff || sd.Approval.EnforcedBy != api.EnforcedByHelper {
		t.Fatalf("status: proto %d, approval %+v", sd.Proto, sd.Approval)
	}
	a.setManual(t, 50)
	if a.duty(t, 0) != 50 {
		t.Fatal("duty not set")
	}
	for _, req := range []string{`{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"test"}`,
		`{"v":1,"verb":"power","action":"cancel","by":"test"}`, `{"v":1,"verb":"apply_update","by":"self-update"}`,
		`{"v":1,"verb":"fan_auto","by":"test"}`} {
		if resp := a.call(t, req); resp.Status != 200 {
			t.Errorf("%s: %+v", req, resp)
		}
	}
	// a challenge says none is needed; an approval that is sent anyway changes nothing
	ch := fanSetReq(0, 60)
	ch.Verb, ch.For, ch.By = proto.VerbChallenge, ptr(proto.VerbFanSet), nil
	var c api.ChallengeResponse
	if resp := a.v2(t, ch); resp.Status != 200 || json.Unmarshal(resp.Data, &c) != nil || c.Needed || c.Reason != "off" {
		t.Errorf("challenge without trust: %+v", resp)
	}
	req := powerReq("reboot", 60)
	req.Approval = &api.Approval{Token: "a.b.c", Entries: []api.ApprovalEntry{{Challenge: strings.Repeat("A", 43), Request: "x"}}}
	if resp := a.v2(t, req); resp.Status != 200 {
		t.Errorf("approval sent without trust: %+v", resp)
	}
}

// TestHelperEnforcesApproval is the whole path on the helper: first-time set, challenge, approved request,
// replay, another action, what stays free, and that an older agent's requests are refused, not run.
func TestHelperEnforcesApproval(t *testing.T) {
	a := newApprovalRig(t)
	a.trust(t)
	sd := a.status(t)
	if st := sd.Approval; st == nil || st.State != api.ApprovalRequired || st.Issuer != a.iss.URL || st.ClientID != a.iss.ClientID ||
		len(st.Keys) != 1 || st.Users != 1 || *st.FanWindowS != 30 || *st.BootShutdownS != 0 {
		t.Fatalf("status: %+v", sd.Approval)
	}
	// trust is locked
	in := a.iss.Init("someone-else")
	wantCode(t, "second trust_init", a.v2(t, proto.Request{Verb: proto.VerbTrustInit, Trust: &in}), 409, api.CodeTrustAlreadySet)

	// an agent from before approvals (plain frames, no approval): refused, nothing runs
	wantCode(t, "v1 fan_mode", a.call(t, `{"v":1,"verb":"fan_mode","mode":"full","by":"test"}`), 403, api.CodeApprovalRequired)
	wantCode(t, "v1 fan_set", a.call(t, `{"v":1,"verb":"fan_set","zone":0,"percent":50,"by":"test"}`), 403, api.CodeApprovalRequired)
	wantCode(t, "v1 shutdown", a.call(t, `{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"test"}`), 403, api.CodeApprovalRequired)
	wantCode(t, "v1 sleep", a.call(t, `{"v":1,"verb":"power","action":"sleep","delay_s":60,"by":"test"}`), 403, api.CodeApprovalRequired)
	wantCode(t, "v1 apply_update", a.call(t, `{"v":1,"verb":"apply_update","by":"self-update"}`), 403, api.CodeApprovalRequired)
	if a.mode(t) == "full" || len(a.power.Scheduled) != 0 || a.updates != 0 {
		t.Fatalf("something ran without approval: mode %s, power %v, updates %d", a.mode(t), a.power.Scheduled, a.updates)
	}
	// what the agent does with nobody present, and every read, stay free
	for _, req := range []string{`{"v":1,"verb":"fan_auto","by":"helper stop"}`, `{"v":1,"verb":"power","action":"cancel","by":"agent"}`,
		`{"v":1,"verb":"ping"}`, `{"v":1,"verb":"status"}`, `{"v":1,"verb":"fan_status"}`, `{"v":1,"verb":"ipmi_sensors"}`} {
		if resp := a.call(t, req); resp.Status != 200 {
			t.Errorf("%s with trust set: %+v", req, resp)
		}
	}

	// approved shutdown
	req := powerReq("shutdown", 60)
	req.Approval = a.approvalFor(t, req)
	if resp := a.v2(t, req); resp.Status != 200 {
		t.Fatalf("approved shutdown: %+v", resp)
	}
	if len(a.power.Scheduled) != 1 || a.power.Scheduled[0] != "shutdown@1m0s" {
		t.Fatalf("scheduled: %v", a.power.Scheduled)
	}
	wantCode(t, "replay", a.v2(t, req), 403, api.CodeApprovalRefused)
	// the approval of one action for another
	fan := fanSetReq(0, 50)
	fan.Approval = a.approvalFor(t, fan)
	swap := powerReq("reboot", 60)
	swap.Approval = fan.Approval
	wantCode(t, "fan approval for a reboot", a.v2(t, swap), 403, api.CodeApprovalRefused)
	other := fanSetReq(0, 100)
	other.Approval = fan.Approval
	wantCode(t, "fan approval for another duty", a.v2(t, other), 403, api.CodeApprovalRefused)
	if len(a.power.Scheduled) != 1 {
		t.Fatalf("scheduled: %v", a.power.Scheduled)
	}
	// the fan approval itself still works (mode full first: also approved), and opens the fan window
	mode := proto.Request{Verb: proto.VerbFanMode, Mode: ptr("full"), By: ptr("test")}
	mode.Approval = a.approvalFor(t, mode)
	if resp := a.v2(t, mode); resp.Status != 200 {
		t.Fatalf("approved fan_mode: %+v", resp)
	}
	if resp := a.v2(t, fan); resp.Status != 200 || a.duty(t, 0) != 50 {
		t.Fatalf("approved fan_set: %+v, duty %d", resp, a.duty(t, 0))
	}
	if resp := a.call(t, `{"v":1,"verb":"fan_set","zone":1,"percent":70,"by":"test"}`); resp.Status != 200 || a.duty(t, 1) != 70 {
		t.Errorf("fan change in the fan window: %+v", resp)
	}
	wantCode(t, "reboot in the fan window", a.call(t, `{"v":1,"verb":"power","action":"reboot","delay_s":60,"by":"test"}`), 403, api.CodeApprovalRequired)

	// approved update
	up := proto.Request{Verb: proto.VerbApplyUpdate, By: ptr("self-update")}
	up.Approval = a.approvalFor(t, up)
	if resp := a.v2(t, up); resp.Status != 200 || a.updates != 1 {
		t.Fatalf("approved update: %+v, %d", resp, a.updates)
	}
	wantCode(t, "update replay", a.v2(t, up), 403, api.CodeApprovalRefused)
	if a.updates != 1 {
		t.Fatal("the updater was started twice")
	}

	// a request that fails after its approval was accepted does not give the approval back
	short := powerReq("reboot", 10) // below this machine's min_delay_s (30)
	short.Approval = a.approvalFor(t, short)
	wantCode(t, "delay below the minimum", a.v2(t, short), 400, proto.CodeBadRequest)
	wantCode(t, "the same approval again", a.v2(t, short), 403, api.CodeApprovalRefused)

	// the helper restarted: trust stays, open challenges are gone
	pending := powerReq("reboot", 60)
	pending.Approval = a.approvalFor(t, pending)
	a.srv = a.server()
	if st := a.status(t).Approval; st.State != api.ApprovalRequired {
		t.Fatalf("after a restart: %+v", st)
	}
	wantCode(t, "approval from before the restart", a.v2(t, pending), 403, api.CodeApprovalRefused)
	wantCode(t, "trust_init after a restart", a.v2(t, proto.Request{Verb: proto.VerbTrustInit, Trust: &in}), 409, api.CodeTrustAlreadySet)

	log := a.audit.String()
	for _, want := range []string{"approval: accepted", "approval: refused", "approval: required, none sent", "sub=" + approvaltest.User,
		"kid=" + approvaltest.Kid, "trust set for the first time", "approval: not needed, fan window", "verb=challenge", "for=power"} {
		if !strings.Contains(log, want) {
			t.Errorf("helper.log lacks %q", want)
		}
	}
	for _, part := range strings.Split(req.Approval.Token, ".") {
		if strings.Contains(log, part) {
			t.Error("helper.log holds a part of a token")
		}
	}
	if strings.Contains(log, req.Approval.Entries[0].Challenge) {
		t.Error("helper.log holds a whole challenge")
	}
}

func TestBrokenTrustRefusesControlVerbs(t *testing.T) {
	a := newApprovalRig(t)
	if err := os.WriteFile(a.files.Path, []byte("not a trust file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := a.status(t).Approval; st.State != api.ApprovalBroken || st.Error == "" {
		t.Fatalf("status: %+v", st)
	}
	wantCode(t, "fan_set", a.call(t, `{"v":1,"verb":"fan_set","zone":0,"percent":50,"by":"test"}`), 503, api.CodeApprovalUnavailable)
	wantCode(t, "shutdown", a.call(t, `{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"test"}`), 503, api.CodeApprovalUnavailable)
	wantCode(t, "apply_update", a.call(t, `{"v":1,"verb":"apply_update","by":"x"}`), 503, api.CodeApprovalUnavailable)
	ch := powerReq("shutdown", 60)
	ch.Verb, ch.For, ch.By = proto.VerbChallenge, ptr(proto.VerbPower), nil
	wantCode(t, "challenge", a.v2(t, ch), 503, api.CodeApprovalUnavailable)
	in := a.iss.Init()
	wantCode(t, "trust_init", a.v2(t, proto.Request{Verb: proto.VerbTrustInit, Trust: &in}), 409, api.CodeTrustAlreadySet)
	// the safe direction still works
	for _, req := range []string{`{"v":1,"verb":"fan_auto","by":"x"}`, `{"v":1,"verb":"power","action":"cancel","by":"x"}`} {
		if resp := a.call(t, req); resp.Status != 200 {
			t.Errorf("%s: %+v", req, resp)
		}
	}
	if len(a.power.Scheduled) != 0 || a.updates != 0 {
		t.Error("something ran with a broken trust file")
	}
}

func TestChallengeForSwitchedOffPart(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(Parts{Audit: log, Approval: approval.NewGate(approval.Options{
		Files: approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}, Log: log})})
	for _, req := range []proto.Request{fanSetReq(0, 50), powerReq("shutdown", 60), {Verb: proto.VerbApplyUpdate}} {
		ch := req
		ch.Verb, ch.For, ch.By = proto.VerbChallenge, &req.Verb, nil
		b, _ := proto.EncodeRequest(ch)
		if resp := srv.HandleV2(context.Background(), "c", b); resp.Status != 404 || resp.Code != proto.CodeDisabled {
			t.Errorf("challenge for %s: %+v", req.Verb, resp)
		}
	}
}

// TestRequestVersions: each request has one version and one kind of frame, and nothing crosses over.
func TestRequestVersions(t *testing.T) {
	a := newApprovalRig(t)
	a.trust(t)
	ctx := context.Background()
	challenge := `{"v":2,"verb":"challenge","for":"power","action":"shutdown","delay_s":60}`
	for name, c := range map[string]struct {
		v2    bool
		frame string
		code  string
	}{
		"v2 request in a plain frame":         {false, challenge, proto.CodeBadRequest},
		"challenge marked v1":                 {false, strings.Replace(challenge, `"v":2`, `"v":1`, 1), proto.CodeBadRequest},
		"challenge marked v1 in a v2 frame":   {true, strings.Replace(challenge, `"v":2`, `"v":1`, 1), proto.CodeBadRequest},
		"plain request in a v2 frame":         {true, `{"v":1,"verb":"ping"}`, proto.CodeBadRequest},
		"plain request marked v2":             {true, `{"v":2,"verb":"ping"}`, proto.CodeBadRequest},
		"control request marked v2, no token": {true, `{"v":2,"verb":"fan_set","zone":0,"percent":50}`, proto.CodeBadRequest},
		"approval in a plain frame":           {false, `{"v":1,"verb":"apply_update","approval":{"token":"a.b.c","entries":[]}}`, proto.CodeBadRequest},
		"v3":                                  {true, `{"v":3,"verb":"ping"}`, proto.CodeBadRequest},
		"challenge for a read":                {true, `{"v":2,"verb":"challenge","for":"status"}`, proto.CodeBadRequest},
		"challenge for fan_auto":              {true, `{"v":2,"verb":"challenge","for":"fan_auto"}`, proto.CodeBadRequest},
		"challenge for cancel":                {true, `{"v":2,"verb":"challenge","for":"power","action":"cancel"}`, proto.CodeBadRequest},
		"challenge for a challenge":           {true, `{"v":2,"verb":"challenge","for":"challenge"}`, proto.CodeBadRequest},
		"challenge without for":               {true, `{"v":2,"verb":"challenge","action":"shutdown","delay_s":60}`, proto.CodeBadRequest},
		"challenge with a bad value":          {true, `{"v":2,"verb":"challenge","for":"fan_set","zone":7,"percent":50}`, proto.CodeBadRequest},
		"challenge with an extra field":       {true, `{"v":2,"verb":"challenge","for":"fan_mode","mode":"full","zone":0}`, proto.CodeBadRequest},
		"approval on cancel":                  {true, `{"v":2,"verb":"power","action":"cancel","approval":{"token":"a","entries":[]}}`, proto.CodeBadRequest},
		"approval on fan_auto":                {true, `{"v":2,"verb":"fan_auto","approval":{"token":"a","entries":[]}}`, proto.CodeBadRequest},
		"approval on a read":                  {true, `{"v":2,"verb":"status","approval":{"token":"a","entries":[]}}`, proto.CodeBadRequest},
		"trust_init without trust":            {true, `{"v":2,"verb":"trust_init"}`, proto.CodeBadRequest},
		"unknown member in the approval":      {true, `{"v":2,"verb":"apply_update","approval":{"token":"a","entries":[],"x":1}}`, proto.CodeBadRequest},
		"unknown member in the trust":         {true, `{"v":2,"verb":"trust_init","trust":{"issuer":"https://a","fan_window_s":60}}`, proto.CodeBadRequest},
		"token over the limit":                {true, `{"v":2,"verb":"apply_update","approval":{"token":"` + strings.Repeat("a", api.MaxApprovalToken+1) + `","entries":[]}}`, proto.CodeTooLarge},
		"plain frame over 512 bytes":          {false, `{"v":1,"verb":"ping","by":"` + strings.Repeat("a", 600) + `"}`, proto.CodeTooLarge},
		"v2 frame over 32 KiB":                {true, `{"v":2,"verb":"trust_init","trust":{"issuer":"` + strings.Repeat("a", proto.MaxRequestV2) + `"}}`, proto.CodeTooLarge},
	} {
		handle := a.srv.Handle
		if c.v2 {
			handle = a.srv.HandleV2
		}
		if resp := handle(ctx, "c", []byte(c.frame)); resp.Code != c.code {
			t.Errorf("%s: %d %s %q, want %s", name, resp.Status, resp.Code, resp.Error, c.code)
		}
	}
	if resp := a.srv.HandleV2(ctx, "c", []byte(challenge)); resp.Status != 200 {
		t.Errorf("a good challenge request: %+v", resp)
	}
}

// TestVersion2Frames: the frame's own mark decides how long a request may be; a helper from before version 2
// (which reads the mark as a length of over 2 GiB) refuses such a frame without reading it.
func TestVersion2Frames(t *testing.T) {
	a := newApprovalRig(t)
	a.trust(t)
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() { a.srv.ServeConn(context.Background(), server, "pipe"); server.Close(); close(done) }()
	ask := func(req proto.Request) proto.Response {
		t.Helper()
		b, err := proto.EncodeRequest(req)
		if err != nil {
			t.Fatal(err)
		}
		if err := proto.WriteRequest(client, b, proto.FrameVersion(req)); err != nil {
			t.Fatal(err)
		}
		f, err := proto.ReadFrame(client, proto.MaxResponse)
		if err != nil {
			t.Fatal(err)
		}
		resp, _ := proto.DecodeResponse(f)
		return resp
	}
	if resp := ask(proto.Request{Verb: proto.VerbPing}); resp.Status != 200 {
		t.Fatal(resp)
	}
	// a full-size approval: a token of 8192 bytes and 64 entries, in one version 2 frame, on the same connection
	big := powerReq("shutdown", 60)
	big.Approval = &api.Approval{Token: strings.Repeat("a", api.MaxApprovalToken)}
	for i := 0; i < api.MaxApprovalEntries; i++ {
		c := make([]byte, 32)
		c[0] = byte(i)
		big.Approval.Entries = append(big.Approval.Entries, api.ApprovalEntry{Challenge: approvaltest.B64(c), Request: strings.Repeat("r", api.MaxApprovalRequest)})
	}
	if resp := ask(big); resp.Status != 403 || resp.Code != api.CodeApprovalRefused {
		t.Fatalf("full-size approval: %+v", resp)
	}
	if resp := ask(proto.Request{Verb: proto.VerbPing}); resp.Status != 200 {
		t.Fatal("the connection is out of step after a version 2 frame:", resp)
	}
	// a version 2 frame that announces more than 32 KiB: too_large, nothing read, connection closed
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], proto.FrameV2|(proto.MaxRequestV2+1))
	if _, err := client.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	f, err := proto.ReadFrame(client, proto.MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := proto.DecodeResponse(f); resp.Status != 413 || resp.Code != proto.CodeTooLarge {
		t.Fatal(resp)
	}
	<-done

	// what a helper from before version 2 does with a version 2 frame: it reads frames with the old limit
	var buf bytes.Buffer
	b, _ := proto.EncodeRequest(proto.Request{Verb: proto.VerbChallenge, For: ptr(proto.VerbApplyUpdate)})
	if err := proto.WriteRequest(&buf, b, proto.Version2); err != nil {
		t.Fatal(err)
	}
	if _, err := proto.ReadFrame(&buf, proto.MaxRequest); !errors.Is(err, proto.ErrFrameTooLarge) {
		t.Fatalf("an old helper would read a version 2 frame: %v", err)
	}
	// and with the JSON alone, had it arrived in a frame it accepts
	if string(b) != `{"v":2,"verb":"challenge","for":"apply_update"}` {
		t.Fatalf("encoded: %s", b)
	}
	// a plain request is encoded exactly as before
	if b, _ := proto.EncodeRequest(fanSetReq(0, 50)); string(b) != `{"v":1,"verb":"fan_set","zone":0,"percent":50,"by":"test"}` {
		t.Fatalf("encoded: %s", b)
	}
}
