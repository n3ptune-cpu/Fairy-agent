package agent_test

// Audit 5, r1-a1-01: a Windows machine whose agent is of this version while the helper that is RUNNING is still
// the program from before approvals (pipe protocol 1: an update that did not restart it). That helper carries
// out power and fan requests without looking at anything. With a trust file on the machine the agent used to
// hand it those requests all the same, and /metrics said "required, enforced by the agent". Built from the
// auditor's proof (audit5/r1-a1/poc/r1-a1-01_oldhelper_test.go.txt).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
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

// releasedHelper answers like the released fairy-agent-helper (a791c55): protocol 1 frames of at most 512
// bytes, a status without "proto" and "approval", and it carries out power and fan requests as that helper
// does, which knows no approval. ran is what it carried out.
type releasedHelper struct {
	mu  sync.Mutex
	ran []string
}

func (o *releasedHelper) did(what string) {
	o.mu.Lock()
	o.ran = append(o.ran, what)
	o.mu.Unlock()
}

func (o *releasedHelper) carriedOut() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.ran...)
}

func (o *releasedHelper) serve(conn net.Conn) {
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
			V      int     `json:"v"`
			Verb   string  `json:"verb"`
			Action *string `json:"action"`
			Mode   *string `json:"mode"`
		}
		switch {
		case json.Unmarshal(f, &req) != nil || req.V != 1:
			reply(proto.Fail(proto.CodeBadRequest, "protocol version"))
		case req.Verb == proto.VerbStatus:
			reply(proto.OK(map[string]any{"version": "0.6.0", "started": "2026-11-11T10:00:00Z",
				"features": []string{"power", "fans", "update"}, "watchdog": true, "sleep_ok": true}))
		case req.Verb == proto.VerbPower:
			o.did("power " + *req.Action)
			reply(proto.OK(proto.PowerData{Action: *req.Action}))
		case req.Verb == proto.VerbFanMode:
			o.did("fan_mode " + *req.Mode)
			reply(proto.WithStatus(200, map[string]any{"mode": *req.Mode}))
		case req.Verb == proto.VerbFanSet:
			o.did("fan_set")
			reply(proto.WithStatus(200, map[string]any{}))
		case req.Verb == proto.VerbApplyUpdate:
			o.did("apply_update")
			reply(proto.OK(map[string]bool{"started": true}))
		default:
			reply(proto.OK(map[string]bool{}))
		}
	}
}

// restartSCM is the service manager of a helper whose program was replaced by an update: what runs first is
// the old program; once the service has been stopped and started, the new one.
type restartSCM struct {
	mu       sync.Mutex
	state    string
	restarts int
}

func (s *restartSCM) State() (string, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.state, nil }
func (s *restartSCM) Stop(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = api.HelperStopped
	return nil
}
func (s *restartSCM) Start(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.restarts = api.HelperRunning, s.restarts+1
	return nil
}
func (s *restartSCM) restarted() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.restarts > 0 }

type oldHelperRig struct {
	base        string
	old         *releasedHelper
	scm         *restartSCM
	iss         *approvaltest.Issuer
	files       approval.Files
	upd         *agent.Updater
	stage       string
	helperPower *agenttest.PowerExec
	ownStarts   atomic.Int32
	wakes       wakes
}

// newOldHelperRig: the agent wired as Run wires it on Windows with the helper (fans, power and approved updates
// through it; the agent's own gate reads the helper's trust file), in front of the released helper. blind: the
// agent's own look into the trust folder fails.
func newOldHelperRig(t *testing.T, blind bool) *oldHelperRig {
	t.Helper()
	cfg, err := agent.Parse([]byte("ipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\nself_update: {enabled: true}\n"+
		"wol: {enabled: true}\ncontrol_rate_per_min: 60\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &oldHelperRig{old: &releasedHelper{}, scm: &restartSCM{state: api.HelperRunning}, iss: approvaltest.New(),
		helperPower: &agenttest.PowerExec{}}
	r.files = approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// the new helper program, which runs once the service has been restarted
	bmc := fakebmc.X11SCAF()
	b := agent.NewBMC(bmc, 20*time.Millisecond)
	go b.Run(ctx)
	waitFirstReading(t, b)
	hlog := slog.New(slog.NewTextHandler(io.Discard, nil))
	newer := helper.New(helper.Parts{Version: "test", Power: r.helperPower, Audit: hlog, BMC: b,
		Fan:      agent.NewFan(bmc, b, cfg.FanControl, nil),
		Updater:  func(context.Context) error { return nil },
		Approval: approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByHelper, Log: hlog, Files: r.files})})
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		if st, _ := r.scm.State(); st != api.HelperRunning {
			return nil, errors.New("pipe not found")
		}
		a, c := net.Pipe()
		if r.scm.restarted() {
			go func() { newer.ServeConn(ctx, a, "test"); a.Close() }()
		} else {
			go r.old.serve(a)
		}
		return c, nil
	}
	client := agent.NewHelperClient(dial, r.scm, true)
	client.Every = 10 * time.Millisecond
	go client.Run(ctx)
	gh := releasetest.New(t, release.AgentRepo)
	gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{"fairy-agent-linux-amd64": []byte("build 42")}, nil)
	dir := t.TempDir()
	r.stage = filepath.Join(dir, "state", "update")
	r.upd = agent.NewUpdater(agent.UpdaterOptions{Version: "41-aaaaaaa", Key: gh.Pub, Client: gh.Client(),
		StageDir: r.stage, ResultPath: filepath.Join(dir, "result", "result.json"),
		Asset: "fairy-agent-linux-amd64", ResultWait: 50 * time.Millisecond,
		Apply:         func(context.Context) error { r.ownStarts.Add(1); return nil },
		ApplyApproved: client.ApplyUpdateApproved})
	own := r.files
	if blind {
		own.CheckDir = func(string) error { return errors.New("access is denied") }
	}
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: client, Updater: r.upd,
		Fan: client.Fan(cfg.FanControl), Power: agent.NewPower(client.Power(), cfg.PowerControl.MinDelayS), WOL: r.wakes.relay(),
		HelperSources: []string{api.FeaturePower, api.FeatureFans},
		// exactly as Run builds it on Windows: the agent's own gate only reads the helper's file
		Approval: approval.NewGate(approval.Options{Files: own, EnforcedBy: api.EnforcedByAgent, ReadOnly: true, Log: hlog})}
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(srv.Close)
	r.base = srv.URL
	for i := 0; i < 300; i++ { // until the agent has seen the helper answer
		_, m := do(t, r.base, "GET", "/metrics", readTok, nil)
		if hs, ok := m["helper"].(map[string]any); ok && hs["state"] == api.HelperRunning {
			return r
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the helper never showed as running")
	return nil
}

// setTrustOnTheMachine is `fairy-agent helper-trust set` of the new program: it writes the file and asks nobody.
func (r *oldHelperRig) setTrustOnTheMachine(t *testing.T) {
	t.Helper()
	tr, err := approval.FromInit(r.iss.Init(), time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.files.Replace(tr); err != nil {
		t.Fatal(err)
	}
}

func (r *oldHelperRig) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, r.base, "POST", path, ctlTok, body)
}

// block is the "approval" block of /metrics once its state is want ("": once there is none).
func (r *oldHelperRig) block(t *testing.T, want string) map[string]any {
	t.Helper()
	var ap map[string]any
	for i := 0; i < 700; i++ { // the agent's own look at the trust file is at most five seconds old
		_, m := do(t, r.base, "GET", "/metrics", readTok, nil)
		ap, _ = m["approval"].(map[string]any)
		if (want == "" && ap == nil) || (ap != nil && ap["state"] == want) {
			return ap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("approval block: want state %q, have %v", want, ap)
	return nil
}

// everyHelperRequest are the requests that need an approval while trust is set and that the helper carries out.
var everyHelperRequest = []struct {
	name, path string
	body       map[string]any
}{
	{"shutdown", "/power", map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "thief"}},
	{"reboot", "/power", map[string]any{"action": "reboot", "delay_s": 10}},
	{"sleep", "/power", map[string]any{"action": "sleep", "delay_s": 60}},
	{"fan mode", "/fan/mode", map[string]any{"mode": "full"}},
	{"fan duty", "/fan/duty", map[string]any{"zone": 0, "percent": 50}},
	{"update", "/update", map[string]any{"requested_by": "thief"}},
}

// TestOldRunningHelperWithATrustFile: the finding. Nothing that needs an approval reaches the old helper, with
// or without an "approval" member, /metrics does not claim that anything is enforced, the exemptions stay, and
// once the helper has been restarted the new one checks.
func TestOldRunningHelperWithATrustFile(t *testing.T) {
	r := newOldHelperRig(t, false)
	r.setTrustOnTheMachine(t)

	// no wait: the agent looks at the trust file when the request is here, not up to five seconds later
	junk := map[string]any{"token": "x.y.z", "entries": []any{map[string]any{"challenge": strings.Repeat("A", 43), "request": "apply_update"}}}
	for _, c := range everyHelperRequest {
		st, b := r.post(t, c.path, c.body)
		wantRefusal(t, c.name+" without approval", st, b, 503, api.CodeApprovalUnavailable)
		if msg, _ := b["error"].(string); !strings.Contains(msg, "older than this agent") || !strings.Contains(msg, "Restart-Service fairy-agent-helper") {
			t.Errorf("%s: the answer does not say what is wrong and how to repair it: %q", c.name, msg)
		}
		with := map[string]any{"approval": junk}
		for k, v := range c.body {
			with[k] = v
		}
		st, b = r.post(t, c.path, with)
		wantRefusal(t, c.name+" with an approval", st, b, 503, api.CodeApprovalUnavailable)
	}
	if ran := r.old.carriedOut(); len(ran) != 0 {
		t.Fatalf("the helper from before approvals carried out, on a machine with a trust file: %q", ran)
	}
	if st := r.upd.Status(); st.State != "idle" || r.ownStarts.Load() != 0 {
		t.Fatalf("an update was started: %+v, own starts %d", st, r.ownStarts.Load())
	}
	if ents, _ := os.ReadDir(r.stage); len(ents) != 0 {
		t.Fatalf("something was downloaded for a refused update: %v", ents)
	}

	// /metrics says the truth: not "required", and not "enforced by the agent"
	ap := r.block(t, api.ApprovalUnknown)
	if ap["enforced_by"] != api.EnforcedByHelper || ap["issuer"] != nil || ap["agent_checks"] != nil {
		t.Fatalf("approval block: %v", ap)
	}
	if msg, _ := ap["error"].(string); !strings.Contains(msg, "older than this agent") || !strings.Contains(msg, "has an approval trust file") {
		t.Fatalf("approval block error: %q", msg)
	}

	// the exemptions stay exempt, and the panel is told why it gets no challenge
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Fatalf("cancel: %d %v", st, b)
	}
	if st, b := r.post(t, "/wol", map[string]any{"mac": "aa:bb:cc:dd:ee:ff"}); st != 200 || len(r.wakes.list()) != 1 || r.wakes.list()[0] != "255.255.255.255:9 102 bytes" {
		t.Fatalf("wake: %d %v, sent %v", st, b, r.wakes.list())
	}
	st, b := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	wantRefusal(t, "challenge", st, b, 409, api.CodeHelperTooOld)
	st, b = r.post(t, api.PathApprovalTrust, r.iss.Init())
	wantRefusal(t, "trust", st, b, 409, api.CodeHelperTooOld)

	// the repair the answer names: stop and start the helper; what starts is the new program, and it checks
	if st, b := r.post(t, api.PathHelperStop, map[string]any{}); st != 200 {
		t.Fatalf("helper stop: %d %v", st, b)
	}
	if st, b := r.post(t, api.PathHelperStart, map[string]any{}); st != 200 {
		t.Fatalf("helper start: %d %v", st, b)
	}
	ap = r.block(t, api.ApprovalRequired)
	if ap["enforced_by"] != api.EnforcedByHelper || ap["issuer"] != r.iss.URL {
		t.Fatalf("approval block after the restart: %v", ap)
	}
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown without approval, new helper", st, b, 403, api.CodeApprovalRequired)
	st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	if st != 200 || c["needed"] != true {
		t.Fatalf("challenge from the new helper: %d %v", st, c)
	}
	good := r.iss.Approve(time.Now(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c["challenge"].(string), Request: c["request"].(string)})
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": good}); st != 200 {
		t.Fatalf("approved shutdown, new helper: %d %v", st, b)
	}
	if n := len(r.helperPower.Scheduled); n != 1 {
		t.Fatalf("the new helper scheduled %d actions", n)
	}
	if ran := r.old.carriedOut(); len(ran) != 0 {
		t.Fatalf("the old helper carried out: %q", ran)
	}
}

// TestOldRunningHelperWithoutATrustFile: no trust file, nothing to enforce: the old helper works as it always
// did and there is no approval block (the version mix "new agent, old helper" of the protocol). The moment an
// administrator sets a trust on the machine, the requests are refused.
func TestOldRunningHelperWithoutATrustFile(t *testing.T) {
	r := newOldHelperRig(t, false)
	r.block(t, "")
	for _, c := range everyHelperRequest[:4] {
		if st, b := r.post(t, c.path, c.body); st != 200 {
			t.Fatalf("%s without a trust file: %d %v", c.name, st, b)
		}
		if c.path == "/power" {
			r.post(t, "/power", map[string]any{"action": "cancel"})
		}
	}
	ran := strings.Join(r.old.carriedOut(), ", ")
	for _, want := range []string{"power shutdown", "power reboot", "power sleep", "fan_mode full"} {
		if !strings.Contains(ran, want) {
			t.Fatalf("the old helper carried out %q, want also %q", ran, want)
		}
	}
	n := len(r.old.carriedOut())
	r.setTrustOnTheMachine(t) // helper-trust set
	st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown right after the trust was set on the machine", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "standard"})
	wantRefusal(t, "fan mode right after the trust was set on the machine", st, b, 503, api.CodeApprovalUnavailable)
	if got := len(r.old.carriedOut()); got != n {
		t.Fatalf("the old helper carried out %q after the trust was set", r.old.carriedOut()[n:])
	}
	r.block(t, api.ApprovalUnknown)
}

// TestOldRunningHelperWhenTheAgentCannotTell: a damaged trust file, and an agent whose account cannot look into
// the helper's folder, are not "no trust file": refused as well, and the block says which of the two it is.
func TestOldRunningHelperWhenTheAgentCannotTell(t *testing.T) {
	for _, c := range []struct {
		name, want string
		blind      bool
	}{
		{"damaged trust file", "trust file cannot be used", false},
		{"folder the agent cannot check", "cannot be used", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newOldHelperRig(t, c.blind)
			if !c.blind {
				if err := os.WriteFile(r.files.Path, []byte("damaged"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, q := range everyHelperRequest {
				st, b := r.post(t, q.path, q.body)
				wantRefusal(t, q.name, st, b, 503, api.CodeApprovalUnavailable)
			}
			if ran := r.old.carriedOut(); len(ran) != 0 {
				t.Fatalf("carried out: %q", ran)
			}
			ap := r.block(t, api.ApprovalUnknown)
			if msg, _ := ap["error"].(string); !strings.Contains(msg, c.want) {
				t.Fatalf("approval block error: %q", msg)
			}
		})
	}
}
