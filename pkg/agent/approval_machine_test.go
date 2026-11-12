package agent_test

// Audit 5, r1-x1-01, the rest of it at the agent's HTTP API: the attack with other requests and with the
// attacker rewriting what he forwards; a Windows machine, where the helper checks with the id of ITS trust
// file; two machines with one id; the machine id in the first-time set and in the "approval" block; and the
// helper of the test build of 2026-11-11, which the agent does not rely on.

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

func x1Windows(t *testing.T, name string) (*x1m, *aprig) {
	t.Helper()
	r := newApprovalRig(t)
	return &x1m{name: name, post: r.post, power: r.power, iss: r.iss, base: r.base, log: r.audit.String}, r
}

// TestApprovalForAnotherMachineIsRefusedWhateverIsForwarded: the attack of approval_x1_test.go with every kind
// of power request and a fan change, and with the attacker rewriting the approval before he forwards it (the
// token he cannot rewrite). None of it uses the victim's challenge up, and the victim's log says what it saw
// without holding a token.
func TestApprovalForAnotherMachineIsRefusedWhateverIsForwarded(t *testing.T) {
	a, b := x1Linux(t, "pc-a"), x1Linux(t, "pc-b")
	x1TurnOn(t, a, "")
	x1TurnOn(t, b, "")
	if a.id == b.id {
		t.Fatal("two machines made up the same id")
	}
	type attack struct {
		path      string
		req, body map[string]any
	}
	power := func(action string) attack {
		return attack{"/power", map[string]any{"verb": api.ApprovePower, "action": action, "delay_s": 60}, map[string]any{"action": action, "delay_s": 60}}
	}
	var tokens []string
	for name, at := range map[string]attack{
		"shutdown": power("shutdown"), "reboot": power("reboot"), "sleep": power("sleep"),
		"fan mode": {"/fan/mode", map[string]any{"verb": api.ApproveFanMode, "mode": "full"}, map[string]any{"mode": "full"}},
	} {
		for how, rewrite := range map[string]func(*api.Approval){
			"as approved":                 nil,
			"the entry rewritten to pc-a": func(ap *api.Approval) { ap.Entries[0].MachineID = a.id },
			"a second entry for pc-a added": func(ap *api.Approval) {
				ap.Entries = append(ap.Entries, api.MachineEntry{MachineID: a.id, Challenge: strings.Repeat("A", 43), Request: ap.Entries[0].Request})
			},
		} {
			st, out := x1Launder(t, a, b, at.path, at.req, at.body, func(ap *api.Approval) {
				tokens = append(tokens, ap.Token)
				if rewrite != nil {
					rewrite(ap)
				}
			})
			msg, _ := out["error"].(string)
			if st != 403 || out["code"] != api.CodeApprovalRefused || !strings.HasPrefix(msg, "approval refused (nonce)") {
				t.Errorf("%s, %s: pc-a answered %d %v", name, how, st, out)
			}
		}
	}
	if len(a.power.Scheduled) != 0 || len(b.power.Scheduled) != 0 {
		t.Fatalf("scheduled on pc-a: %v, on pc-b: %v", a.power.Scheduled, b.power.Scheduled)
	}
	// the answer does not say which part of the nonce was wrong; the victim's own log does
	log := a.log()
	if !strings.Contains(log, "names another machine id than this machine's") {
		t.Errorf("pc-a's log does not say what it saw:\n%s", log)
	}
	for _, tok := range tokens {
		if strings.Contains(log, tok) || strings.Contains(log, strings.Split(tok, ".")[2]) {
			t.Fatal("pc-a's log holds a token")
		}
	}
	// pc-a's challenges are all still good for pc-a: the admin's own shutdown of pc-a works
	st, c := a.post(t, api.PathApprovalChallenge, map[string]any{"verb": api.ApprovePower, "action": "shutdown", "delay_s": 60})
	if st != 200 {
		t.Fatalf("challenge: %d %v", st, c)
	}
	own := a.iss.Approve(time.Now(), x1Entry(a.id, c["challenge"].(string), c["request"].(string)))
	if st, out := a.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": own}); st != 200 || len(a.power.Scheduled) != 1 {
		t.Fatalf("the admin's own shutdown of pc-a: %d %v", st, out)
	}
}

// TestWindowsHelperChecksWithItsOwnMachineID: on Windows the helper checks, with the machine id of the trust
// file in its own folder. The attack is refused there as on Linux, and nothing the agent's service passes over
// the pipe changes which id the helper checks with: not the id in the entry, and not a first-time set with
// another id on a machine that has its trust.
func TestWindowsHelperChecksWithItsOwnMachineID(t *testing.T) {
	a, rig := x1Windows(t, "win-a")
	b := x1Linux(t, "pc-b")
	x1TurnOn(t, a, "")
	x1TurnOn(t, b, "")
	ap := rig.approvalBlock(t, api.ApprovalRequired)
	if ap["enforced_by"] != api.EnforcedByHelper || ap["machine_id"] != a.id || a.id == b.id {
		t.Fatalf("win-a's approval block: %v (pc-b's id: %s)", ap, b.id)
	}
	shutdown := map[string]any{"action": "shutdown", "delay_s": 60}
	req := map[string]any{"verb": api.ApprovePower, "action": "shutdown", "delay_s": 60}
	for how, rewrite := range map[string]func(*api.Approval){
		"as approved":                  nil,
		"the entry rewritten to win-a": func(ap *api.Approval) { ap.Entries[0].MachineID = a.id },
	} {
		st, out := x1Launder(t, a, b, "/power", req, shutdown, rewrite)
		msg, _ := out["error"].(string)
		if st != 403 || out["code"] != api.CodeApprovalRefused || !strings.HasPrefix(msg, "approval refused (nonce)") {
			t.Errorf("%s: win-a answered %d %v", how, st, out)
		}
	}
	// the same over the pipe, as an agent service that was taken over would send it: the helper's answer
	st, c := a.post(t, api.PathApprovalChallenge, req)
	if st != 200 {
		t.Fatalf("challenge: %d %v", st, c)
	}
	forB := b.iss.Approve(time.Now(), x1Entry(b.id, c["challenge"].(string), c["request"].(string)))
	action, delay, by := "shutdown", 60, "attacker"
	for how, entryID := range map[string]string{"B's id in the entry": b.id, "A's id in the entry": a.id} {
		sent := &api.Approval{Token: forB.Token, Entries: []api.MachineEntry{x1Entry(entryID, forB.Entries[0].Challenge, forB.Entries[0].Request)}}
		resp, err := rig.client.Call(context.Background(), proto.Request{Verb: proto.VerbPower, Action: &action, DelayS: &delay, By: &by, Approval: sent})
		if err != nil || resp.Status != 403 || resp.Code != api.CodeApprovalRefused || !strings.HasPrefix(resp.Error, "approval refused (nonce)") {
			t.Errorf("over the pipe, %s: %+v, %v", how, resp, err)
		}
	}
	// a first-time set with another machine id, over the pipe, on a machine that has its trust: already_set
	in := a.iss.Init()
	in.MachineID = b.id
	in.Approval = forB
	resp, err := rig.client.Call(context.Background(), proto.Request{Verb: proto.VerbTrustInit, Trust: &in})
	if err != nil || resp.Status != 409 || resp.Code != api.CodeTrustAlreadySet {
		t.Errorf("trust_init with another id over the pipe: %+v, %v", resp, err)
	}
	if st, out := a.post(t, api.PathApprovalTrust, in); st != 409 || out["code"] != api.CodeTrustAlreadySet {
		t.Errorf("POST /approval/trust with another id: %d %v", st, out)
	}
	if got := x1ID(t, a); got != a.id {
		t.Fatalf("win-a's machine id changed: %q, was %q", got, a.id)
	}
	if len(a.power.Scheduled) != 0 {
		t.Fatalf("the helper scheduled: %v", a.power.Scheduled)
	}
	// the request has no member that could name the machine: what the agent can send is the list below
	fields, _ := json.Marshal(proto.Request{})
	var members map[string]any
	_ = json.Unmarshal(fields, &members)
	for name := range members {
		if strings.Contains(name, "machine") {
			t.Errorf("the pipe request has the member %q", name)
		}
	}
	// and the honest approval for win-a is accepted by the helper
	own := a.iss.Approve(time.Now(), x1Entry(a.id, c["challenge"].(string), c["request"].(string)))
	if st, out := a.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": own}); st != 200 || len(a.power.Scheduled) != 1 {
		t.Fatalf("the admin's own shutdown of win-a: %d %v (%v)", st, out, a.power.Scheduled)
	}
}

// TestCopiedDiskHasTheSameMachineID documents the limit of the binding, at the agent's API: a machine made
// from a copy of another machine's disk has that machine's trust file, and with it the same machine id. Then
// an approval for one of the two is accepted by the other, as before the fix. No agent can see this (it sees
// no other machine): both show the same "machine_id" in /metrics, and it is the panel that must refuse two
// machines with one id. On the copy an administrator sets the trust anew (`fairy-agent helper-trust set
// --new-machine-id`, cmd/fairy-agent: TestHelperTrustMachineID); here that is the file written again with a
// new id, after which the approval for the one no longer fits the other.
func TestCopiedDiskHasTheSameMachineID(t *testing.T) {
	orig := newLinuxRig(t, true)
	a := &x1m{name: "original", post: orig.post, power: orig.power, iss: orig.iss, base: orig.base, log: orig.log.String}
	x1TurnOn(t, a, "")
	raw, err := os.ReadFile(orig.trust)
	if err != nil {
		t.Fatal(err)
	}
	// the copy: another agent, another folder, the same trust file
	clone := newLinuxRig(t, true)
	if err := os.WriteFile(clone.trust, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	b := &x1m{name: "copy", post: clone.post, power: clone.power, iss: clone.iss, base: clone.base, log: clone.log.String}
	b.id = x1ID(t, b)
	if a.id != b.id {
		t.Fatalf("the copy shows the id %q, the original %q", b.id, a.id)
	}
	shutdown := map[string]any{"action": "shutdown", "delay_s": 60}
	req := map[string]any{"verb": api.ApprovePower, "action": "shutdown", "delay_s": 60}
	st, out := x1Launder(t, a, b, "/power", req, shutdown, nil)
	if st != 200 || len(a.power.Scheduled) != 1 {
		t.Fatalf("with one id on two machines the approval for the copy is expected to be accepted by the original (that is what this test documents): %d %v", st, out)
	}
	for _, m := range []*x1m{a, b} {
		if log := m.log(); strings.Contains(log, "another machine") || strings.Contains(log, "copy") {
			t.Errorf("%s claims to have noticed:\n%s", m.name, log)
		}
	}
	// the copy's trust set anew, with an id of its own
	tr, err := approval.ParseTrust(raw)
	if err != nil {
		t.Fatal(err)
	}
	if tr.MachineID, err = approval.NewMachineID(nil); err != nil {
		t.Fatal(err)
	}
	if err := (approval.Files{Path: clone.trust}).Replace(tr); err != nil {
		t.Fatal(err)
	}
	if st, out := a.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 { // the shutdown the attack scheduled
		t.Fatalf("cancel: %d %v", st, out)
	}
	time.Sleep(5200 * time.Millisecond) // the agent looks at the trust file again within five seconds
	if b.id = x1ID(t, b); b.id == a.id {
		t.Fatal("the copy still shows the original's id")
	}
	st, out = x1Launder(t, a, b, "/power", map[string]any{"verb": api.ApprovePower, "action": "reboot", "delay_s": 60}, map[string]any{"action": "reboot", "delay_s": 60}, nil)
	if st != 403 || out["code"] != api.CodeApprovalRefused || len(a.power.Scheduled) != 1 {
		t.Fatalf("after the copy got an id of its own: %d %v (%v)", st, out, a.power.Scheduled)
	}
}

// TestMachineIDInTheFirstTimeSet is POST /approval/trust as the panel sends it: with a machine id of its own
// choice, with none, and with values that are no machine id; and what the answer and /metrics then show.
func TestMachineIDInTheFirstTimeSet(t *testing.T) {
	const chosen = "panel-chose-this-id-0001"
	// the panel's id
	r := newLinuxRig(t, true)
	in := r.iss.Init()
	in.MachineID = chosen
	st, out := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, in))
	if st != 200 || out["state"] != api.ApprovalRequired || out["machine_id"] != chosen || out["proto"] != float64(2) {
		t.Fatalf("set with the panel's id: %d %v", st, out)
	}
	if ap := r.approval(t); ap["machine_id"] != chosen || ap["trust_hash"] != api.TrustHash(in) {
		t.Fatalf("approval block: %v", ap)
	}
	// while it is locked, no id is taken: not another, not the same
	for _, id := range []string{"panel-chose-another-id-02", chosen, ""} {
		in.MachineID = id
		if st, out := r.post(t, api.PathApprovalTrust, in); st != 409 || out["code"] != api.CodeTrustAlreadySet {
			t.Errorf("a set with the id %q on a locked machine: %d %v", id, st, out)
		}
		if st, out := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": api.ApproveTrustSet, "trust_hash": api.TrustHash(in)}); st != 409 || out["code"] != api.CodeTrustAlreadySet {
			t.Errorf("a challenge for a set on a locked machine: %d %v", st, out)
		}
	}
	if ap := r.approval(t); ap["machine_id"] != chosen {
		t.Fatalf("approval block after the refused sets: %v", ap)
	}

	// none: the machine makes one up and says which, in the answer and in /metrics; "" in the body is none
	for _, body := range []func(api.TrustInit) any{
		func(in api.TrustInit) any { return in },
		func(in api.TrustInit) any {
			b, _ := json.Marshal(in)
			var m map[string]any
			_ = json.Unmarshal(b, &m)
			m["machine_id"] = ""
			return m
		},
	} {
		r = newLinuxRig(t, true)
		in = r.iss.Init()
		in.MachineID = ""
		st, out = r.post(t, api.PathApprovalTrust, body(provenTrust(t, r.base, r.iss, in)))
		id, _ := out["machine_id"].(string)
		if st != 200 || api.CheckMachineID(id) != nil || len(id) != 22 {
			t.Fatalf("set without an id: %d %v", st, out)
		}
		if ap := r.approval(t); ap["machine_id"] != id {
			t.Fatalf("approval block: %v", ap)
		}
		raw, _ := os.ReadFile(r.trust)
		if !strings.Contains(string(raw), `"machine_id": "`+id+`"`) {
			t.Fatalf("the trust file:\n%s", raw)
		}
	}

	// values that are no machine id: 400 invalid, nothing written, the machine still off
	for name, id := range map[string]any{
		"too short": "short", "too long": strings.Repeat("a", api.MaxMachineID+1), "a space": "panel chose this id 0001",
		"a slash": "panel/chose/this/id/0001", "a newline": "panel-chose-this-id-000\n", "not ASCII": "panel-chöse-this-id-0001",
		"a number": 1234567890123456, "a list": []string{chosen}, "an object": map[string]any{"id": chosen}, "true": true,
	} {
		r = newLinuxRig(t, true)
		in = r.iss.Init()
		in.MachineID = chosen
		b, _ := json.Marshal(provenTrust(t, r.base, r.iss, in))
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		m["machine_id"] = id
		st, out = r.post(t, api.PathApprovalTrust, m)
		if st != 400 || out["code"] != api.CodeTrustInvalid {
			t.Errorf("%s: %d %v", name, st, out)
		}
		if _, err := os.Lstat(r.trust); err == nil {
			t.Errorf("%s: a trust file was written", name)
		}
		if ap := r.approval(t); ap["state"] != api.ApprovalOff || ap["machine_id"] != nil {
			t.Errorf("%s: approval block %v", name, ap)
		}
	}

	// what a panel of the test build of 2026-11-11 sends, entries without a machine id: refused, on a machine
	// with trust (an action) and on one without (the proof of a set)
	r = newLinuxRig(t, true).trusted(t)
	st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": api.ApprovePower, "action": "reboot", "delay_s": 60})
	if st != 200 || c["machine_id"] != nil { // the challenge answer does not carry the id: the panel uses the one on record
		t.Fatalf("challenge: %d %v", st, c)
	}
	oldStyle := map[string]any{"token": "a.b.c", "entries": []any{map[string]any{"challenge": c["challenge"], "request": c["request"]}}}
	st, out = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": oldStyle})
	if msg, _ := out["error"].(string); st != 403 || out["code"] != api.CodeApprovalRefused || !strings.HasPrefix(msg, "approval refused (entries)") {
		t.Errorf("an action with entries that have no machine id: %d %v", st, out)
	}
	if len(r.power.Scheduled) != 0 {
		t.Fatalf("scheduled: %v", r.power.Scheduled)
	}
}

// testBuildHelper answers like the fairy-agent-helper of the test build of 2026-11-11: pipe protocol 2, an
// approval block (without a machine id), and for every request it is sent an answer of its own. got is every
// request that reached it other than status.
type testBuildHelper struct {
	mu    sync.Mutex
	got   []string
	state string // the approval state it reports
}

func (h *testBuildHelper) requests() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.got...)
}

func (h *testBuildHelper) serve(conn net.Conn) {
	defer conn.Close()
	for {
		f, _, err := proto.ReadRequest(conn) // it reads long frames: it has them too
		if err != nil {
			return
		}
		var req struct {
			V      int     `json:"v"`
			Verb   string  `json:"verb"`
			Action *string `json:"action"`
		}
		_ = json.Unmarshal(f, &req)
		var resp proto.Response
		switch {
		case req.V != 1 && req.V != 2:
			resp = proto.Fail(proto.CodeBadRequest, "protocol version, want 1 or 2")
		case req.Verb == proto.VerbStatus:
			resp = proto.OK(map[string]any{"version": "0.7.0-test", "started": "2026-11-11T20:00:00Z", "features": []string{"power", "fans", "update"},
				"watchdog": true, "sleep_ok": true, "proto": 2,
				"approval": map[string]any{"state": h.state, "enforced_by": "helper", "proto": 1, "issuer": approvaltest.IssuerURL, "client_id": approvaltest.ClientID, "users": 1}})
		default:
			what := req.Verb
			if req.Action != nil {
				what += " " + *req.Action
			}
			h.mu.Lock()
			h.got = append(h.got, what)
			h.mu.Unlock()
			resp = proto.OK(map[string]any{"action": "x"})
		}
		b, _ := json.Marshal(resp)
		if proto.WriteFrame(conn, b, proto.MaxResponse) != nil {
			return
		}
	}
}

type runningSCM struct{}

func (runningSCM) State() (string, error)      { return api.HelperRunning, nil }
func (runningSCM) Stop(context.Context) error  { return nil }
func (runningSCM) Start(context.Context) error { return nil }

// newTestBuildRig: an agent of this version, wired as Run wires it on Windows, in front of the test build's
// helper. trust: what is in the helper's folder ("": no trust file).
func newTestBuildRig(t *testing.T, h *testBuildHelper, trust []byte) string {
	t.Helper()
	cfg, err := agent.Parse([]byte("ipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\ncontrol_rate_per_min: 60\n"),
		filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	files := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	if trust != nil {
		if err := os.WriteFile(files.Path, trust, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		a, c := net.Pipe()
		go h.serve(a)
		return c, nil
	}
	client := agent.NewHelperClient(dial, runningSCM{}, true)
	client.Every = 10 * time.Millisecond
	go client.Run(ctx)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: client,
		Fan: client.Fan(cfg.FanControl), Power: agent.NewPower(client.Power(), cfg.PowerControl.MinDelayS),
		HelperSources: []string{api.FeaturePower, api.FeatureFans},
		Approval:      approval.NewGate(approval.Options{Files: files, EnforcedBy: api.EnforcedByAgent, ReadOnly: true, Log: quiet})}
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(srv.Close)
	for i := 0; i < 300; i++ {
		_, m := do(t, srv.URL, "GET", "/metrics", readTok, nil)
		if hs, ok := m["helper"].(map[string]any); ok && hs["state"] == api.HelperRunning && hs["proto"] == float64(2) {
			return srv.URL
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the helper never showed as running")
	return ""
}

// TestHelperOfTheTestBuildIsNotReliedOn: pipe protocol 2 was the test build of 2026-11-11, whose helper checks
// approvals without a machine id. An agent of this version treats it like a helper from before approvals:
// while the machine has a trust file (that build's file has no machine id, so the agent's own look says
// "broken"; with any other file the same), nothing that needs an approval is handed to it, and the answer is
// the old helper's: 503 approval_unavailable, the block "unknown", the challenge 409 helper_too_old. What needs
// no approval still goes through. Without a trust file everything works as it always did.
func TestHelperOfTheTestBuildIsNotReliedOn(t *testing.T) {
	old, err := approval.FromInit(approvaltest.New().Init(), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	withID := old.Marshal() // a file of this version next to that helper (helper-trust set of the new program)
	old.MachineID = ""
	for name, trust := range map[string][]byte{"the test build's trust file": old.Marshal(), "a trust file of this version": withID} {
		h := &testBuildHelper{state: api.ApprovalRequired}
		base := newTestBuildRig(t, h, trust)
		post := func(path string, body any) (int, map[string]any) { return do(t, base, "POST", path, ctlTok, body) }
		ap := &api.Approval{Token: "a.b.c", Entries: []api.MachineEntry{{MachineID: approvaltest.MachineID, Challenge: strings.Repeat("A", 43), Request: "power action=shutdown delay_s=60"}}}
		for what, c := range map[string]struct {
			path string
			body map[string]any
		}{
			"shutdown":                   {"/power", map[string]any{"action": "shutdown", "delay_s": 60}},
			"shutdown with an approval":  {"/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": ap}},
			"reboot":                     {"/power", map[string]any{"action": "reboot", "delay_s": 60}},
			"fan mode":                   {"/fan/mode", map[string]any{"mode": "full"}},
			"fan mode with an approval":  {"/fan/mode", map[string]any{"mode": "full", "approval": ap}},
			"fan duty with an approval":  {"/fan/duty", map[string]any{"zone": 0, "percent": 50, "approval": ap}},
			"sleep, with an approval":    {"/power", map[string]any{"action": "sleep", "delay_s": 60, "approval": ap}},
			"shutdown, the longest wait": {"/power", map[string]any{"action": "shutdown", "delay_s": 86400}},
		} {
			st, out := post(c.path, c.body)
			msg, _ := out["error"].(string)
			if st != 503 || out["code"] != api.CodeApprovalUnavailable || !strings.Contains(msg, "older than this agent") || !strings.Contains(msg, "install this version of both services") {
				t.Errorf("%s, %s: %d %v", name, what, st, out)
			}
		}
		if st, out := post(api.PathApprovalChallenge, map[string]any{"verb": api.ApprovePower, "action": "shutdown", "delay_s": 60}); st != 409 || out["code"] != api.CodeHelperTooOld {
			t.Errorf("%s: challenge: %d %v", name, st, out)
		}
		if st, out := post(api.PathApprovalTrust, approvaltest.New().Init()); st != 409 || out["code"] != api.CodeHelperTooOld {
			t.Errorf("%s: first-time set: %d %v", name, st, out)
		}
		if got := h.requests(); len(got) != 0 {
			t.Fatalf("%s: the test build's helper was handed %v", name, got)
		}
		_, m := do(t, base, "GET", "/metrics", readTok, nil)
		block, _ := m["approval"].(map[string]any)
		if msg, _ := block["error"].(string); block["state"] != api.ApprovalUnknown || block["enforced_by"] != api.EnforcedByHelper ||
			!strings.HasPrefix(msg, "the running fairy-agent-helper is older than this agent") || block["machine_id"] != nil || block["issuer"] != nil {
			t.Errorf("%s: approval block %v", name, block)
		}
		// what never needs an approval is not refused
		if st, out := post("/power", map[string]any{"action": "cancel"}); st != 200 {
			t.Errorf("%s: cancel: %d %v", name, st, out)
		}
	}
	// no trust file: nothing is asked for, and that helper works as it did (plain requests, protocol 1)
	h := &testBuildHelper{state: api.ApprovalOff}
	base := newTestBuildRig(t, h, nil)
	if st, out := do(t, base, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 60}); st != 200 {
		t.Errorf("without a trust file: %d %v", st, out)
	}
	if _, m := do(t, base, "GET", "/metrics", readTok, nil); m["approval"] != nil {
		t.Errorf("without a trust file: approval block %v", m["approval"])
	}
	if got := h.requests(); len(got) != 1 || got[0] != "power shutdown" {
		t.Errorf("without a trust file the helper was handed %v", got)
	}
}
