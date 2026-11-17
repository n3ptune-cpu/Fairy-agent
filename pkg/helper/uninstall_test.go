package helper

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

// The helper's side of the panel's "Uninstall agent" (Windows): it checks the approval itself and only then
// leaves the request for the updater (Parts.Uninstall, counted here). A compromised agent process holds the
// control token and can send the helper anything; none of these tests gets an uninstall started without a
// good approval for exactly this request on this machine.

type uninstallCalls struct {
	n    atomic.Int32
	by   atomic.Value
	err  atomic.Pointer[error]
	busy atomic.Bool // the updater service runs
}

// uninstallServer is a helper with uninstall switched on, on the rig's trust file (gate false: no gate at all).
func (a *arig) uninstallServer(c *uninstallCalls, gate bool) *Server {
	log := slog.New(slog.NewTextHandler(a.audit, nil))
	p := Parts{Version: "test", Power: a.power, Audit: log,
		Uninstall: func(_ context.Context, by string) error {
			c.n.Add(1)
			c.by.Store(by)
			if e := c.err.Load(); e != nil {
				return *e
			}
			return nil
		},
		Updating: c.busy.Load}
	if gate {
		p.Approval = approval.NewGate(approval.Options{Files: a.files, EnforcedBy: api.EnforcedByHelper, Log: log})
	}
	srv := New(p)
	srv.limit = proto.NewLimiter(1000, 1000, time.Minute)
	return srv
}

func uninstallReq(ap *api.Approval) proto.Request {
	return proto.Request{V: proto.Version3, Verb: proto.VerbUninstall, By: ptr("panel 100.64.0.10"), Approval: ap}
}

// send sends r in the frame its version needs (a request without an approval is a plain one).
func (a *arig) send(t *testing.T, r proto.Request) proto.Response {
	t.Helper()
	r.V = proto.FrameVersion(r)
	b, err := proto.EncodeRequest(r)
	if err != nil {
		t.Fatalf("encode %+v: %v", r, err)
	}
	if r.V == proto.Version3 {
		return a.srv.HandleV3(context.Background(), "test-client", b)
	}
	return a.srv.Handle(context.Background(), "test-client", b)
}

func wantUninstallCode(t *testing.T, what string, r proto.Response, status int, code string) {
	t.Helper()
	if r.Status != status || r.Code != code || r.Error == "" {
		t.Errorf("%s: %d %s %q, want %d %s", what, r.Status, r.Code, r.Error, status, code)
	}
}

func (a *arig) uninstallChallenge(t *testing.T) proto.Response {
	t.Helper()
	return a.v3(t, proto.Request{Verb: proto.VerbChallenge, For: ptr(proto.VerbUninstall)})
}

// Off in config.yaml: "disabled", for the request and its challenge.
func TestHelperUninstallDisabled(t *testing.T) {
	a := newApprovalRig(t)
	a.trust(t)
	wantUninstallCode(t, "challenge", a.uninstallChallenge(t), 404, proto.CodeDisabled)
	ap := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: "uninstall"}}}
	wantUninstallCode(t, "uninstall", a.send(t, uninstallReq(ap)), 404, proto.CodeDisabled)
}

// No trust file, or no gate at all: 409 approval_off for the challenge and the request, with or without an
// approval. Never "needs none".
func TestHelperUninstallWithoutTrust(t *testing.T) {
	for _, gate := range []bool{true, false} {
		a := newApprovalRig(t)
		var c uninstallCalls
		a.srv = a.uninstallServer(&c, gate)
		what := map[bool]string{true: "no trust file", false: "no gate"}[gate]
		wantUninstallCode(t, what+": challenge", a.uninstallChallenge(t), 409, api.CodeApprovalOff)
		wantUninstallCode(t, what+": no approval", a.send(t, uninstallReq(nil)), 409, api.CodeApprovalOff)
		madeUp := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: approvaltest.MachineID,
			Challenge: strings.Repeat("A", 43), Request: "uninstall"}}}
		wantUninstallCode(t, what+": made-up approval", a.send(t, uninstallReq(madeUp)), 409, api.CodeApprovalOff)
		if n := c.n.Load(); n != 0 {
			t.Fatalf("%s: started %d times", what, n)
		}
	}
}

// With trust: an approval of this request on this machine starts it, once; nothing else does.
func TestHelperUninstallNeedsItsApproval(t *testing.T) {
	a := newApprovalRig(t)
	a.trust(t)
	var c uninstallCalls
	a.srv = a.uninstallServer(&c, true)

	wantUninstallCode(t, "no approval", a.send(t, uninstallReq(nil)), 403, api.CodeApprovalRequired)
	// an approval for a shutdown of this machine is no uninstall's
	shut := a.approvalFor(t, proto.Request{Verb: proto.VerbPower, Action: ptr("shutdown"), DelayS: ptr(60)})
	if r := a.send(t, uninstallReq(shut)); r.Status != 403 {
		t.Errorf("a shutdown's approval: %+v", r)
	}
	if n := c.n.Load(); n != 0 {
		t.Fatalf("started %d times without its approval", n)
	}

	ap := a.approvalForVerb(t, proto.VerbUninstall)
	r := a.send(t, uninstallReq(ap))
	var started map[string]bool
	if r.Status != 200 || json.Unmarshal(r.Data, &started) != nil || !started["started"] {
		t.Fatalf("approved: %+v", r)
	}
	if n := c.n.Load(); n != 1 || !strings.Contains(c.by.Load().(string), "panel 100.64.0.10") {
		t.Fatalf("started %d times by %v", n, c.by.Load())
	}
	if r := a.send(t, uninstallReq(ap)); r.Status != 403 || r.Code != api.CodeApprovalRefused {
		t.Errorf("the same approval again: %+v", r)
	}
	wantUninstallCode(t, "a second good approval", a.send(t, uninstallReq(a.approvalForVerb(t, proto.VerbUninstall))), 409, api.CodeUninstallBusy)
	if n := c.n.Load(); n != 1 {
		t.Fatalf("started %d times", n)
	}
	if strings.Contains(a.audit.String(), ap.Token) {
		t.Fatal("the approval's token is in the audit log")
	}
}

// While the updater runs (an update): 409 updater_busy, and the approval is not used up by that.
func TestHelperUninstallWhileTheUpdaterRuns(t *testing.T) {
	a := newApprovalRig(t)
	a.trust(t)
	var c uninstallCalls
	a.srv = a.uninstallServer(&c, true)
	ap := a.approvalForVerb(t, proto.VerbUninstall)
	c.busy.Store(true)
	wantUninstallCode(t, "updater busy", a.send(t, uninstallReq(ap)), 409, api.CodeUpdaterBusy)
	c.busy.Store(false)
	if r := a.send(t, uninstallReq(ap)); r.Status != 200 {
		t.Fatalf("the same approval once the updater is done: %+v", r)
	}
	if n := c.n.Load(); n != 1 {
		t.Fatalf("started %d times", n)
	}
}

// A start that fails: an error, nothing counts as started, and a new approval may try again.
func TestHelperUninstallStartThatFails(t *testing.T) {
	a := newApprovalRig(t)
	a.trust(t)
	var c uninstallCalls
	a.srv = a.uninstallServer(&c, true)
	e := errors.New("the service manager refused")
	c.err.Store(&e)
	if r := a.send(t, uninstallReq(a.approvalForVerb(t, proto.VerbUninstall))); r.Status != 500 || r.Code != proto.CodeFailed {
		t.Fatalf("failed start: %+v", r)
	}
	busy := agent.ErrUpdaterBusy
	c.err.Store(&busy)
	wantUninstallCode(t, "the updater turned busy at the start", a.send(t, uninstallReq(a.approvalForVerb(t, proto.VerbUninstall))), 409, api.CodeUpdaterBusy)
	c.err.Store(nil)
	if r := a.send(t, uninstallReq(a.approvalForVerb(t, proto.VerbUninstall))); r.Status != 200 {
		t.Fatalf("a new approval after a failed start: %+v", r)
	}
	if n := c.n.Load(); n != 3 {
		t.Fatalf("tried %d times", n)
	}
}

// approvalForVerb asks this helper for a challenge for verb (no members) and has it approved.
func (a *arig) approvalForVerb(t *testing.T, verb string) *api.Approval {
	t.Helper()
	resp := a.v3(t, proto.Request{Verb: proto.VerbChallenge, For: &verb})
	var ch api.ChallengeResponse
	if resp.Status != 200 || json.Unmarshal(resp.Data, &ch) != nil || !ch.Needed {
		t.Fatalf("challenge for %s: %+v", verb, resp)
	}
	return a.iss.Approve(time.Now(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: ch.Challenge, Request: ch.Request})
}
