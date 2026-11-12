package agent_test

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release/releasetest"
)

// lrig is a Linux agent as the panel sees it: no helper; fans, power, self-update and Wake-on-LAN in the
// agent's own process, and the agent's own approval gate on a trust file in its state folder.
type lrig struct {
	base   string
	bmc    *fakebmc.BMC
	power  *agenttest.PowerExec
	iss    *approvaltest.Issuer
	gh     *releasetest.Server
	upd    *agent.Updater
	starts atomic.Int32
	trust  string // the trust file
	log    *logBuf
	gated  bool
}

func newLinuxRig(t *testing.T, withGate bool) *lrig {
	t.Helper()
	return newLinuxRigWith(t, lrigOpts{gate: withGate})
}

// lrigOpts say how the Linux agent of a test is set up.
type lrigOpts struct {
	gate bool // the agent has its approval gate (as Run always builds it)
	// uptime: how long the system has been up, for the gate's shutdown-after-boot setting (nil: not known)
	uptime func() time.Duration
	noKey  bool // a build without a release key: self-update answers "unavailable"
	rate   int  // control_rate_per_min (0: 60, so that a test is not held up by it)
}

func newLinuxRigWith(t *testing.T, o lrigOpts) *lrig {
	t.Helper()
	withGate := o.gate
	if o.rate == 0 {
		o.rate = 60
	}
	cfg, err := agent.Parse([]byte("ipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\nself_update: {enabled: true}\n"+
		"wol: {enabled: true}\ncontrol_rate_per_min: "+strconv.Itoa(o.rate)+"\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &lrig{bmc: fakebmc.X11SCAF(), power: &agenttest.PowerExec{}, iss: approvaltest.New(), gh: releasetest.New(t, release.AgentRepo),
		log: &logBuf{}, trust: filepath.Join(t.TempDir(), approval.TrustFileName), gated: withGate}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b := agent.NewBMC(r.bmc, 20*time.Millisecond)
	go b.Run(ctx)
	dir := t.TempDir()
	uo := agent.UpdaterOptions{Version: "41-aaaaaaa", Key: r.gh.Pub, Client: r.gh.Client(),
		StageDir: filepath.Join(dir, "state", "update"), ResultPath: filepath.Join(dir, "result", "result.json"),
		Asset: "fairy-agent-linux-amd64", ResultWait: 50 * time.Millisecond,
		Apply: func(context.Context) error { r.starts.Add(1); return nil }}
	if o.noKey {
		uo.Key = nil
	}
	r.upd = agent.NewUpdater(uo)
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", BMC: b, Fan: agent.NewFan(r.bmc, b, cfg.FanControl, nil),
		Power: agent.NewPower(r.power, cfg.PowerControl.MinDelayS), Updater: r.upd, WOL: agent.NewWOL(nil)}
	if withGate {
		gopts := approval.Options{Files: approval.Files{Path: r.trust}, EnforcedBy: api.EnforcedByAgent,
			Log: slog.New(slog.NewTextHandler(r.log, nil))}
		if o.uptime != nil {
			gopts.Uptime = func() (time.Duration, error) { return o.uptime(), nil }
			gopts.BootID = func() (string, error) { return "11111111-1111-4111-8111-111111111111", nil }
		}
		d.Approval = approval.NewGate(gopts)
	}
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(srv.Close)
	r.base = srv.URL
	return r
}

func (r *lrig) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, r.base, "POST", path, ctlTok, body)
}

func (r *lrig) approval(t *testing.T) map[string]any {
	t.Helper()
	time.Sleep(260 * time.Millisecond) // past the /metrics cache
	_, m := do(t, r.base, "GET", "/metrics", readTok, nil)
	ap, _ := m["approval"].(map[string]any)
	return ap
}

func (r *lrig) approve(t *testing.T, req map[string]any) *api.Approval {
	t.Helper()
	st, c := r.post(t, api.PathApprovalChallenge, req)
	if st != 200 || c["needed"] != true {
		t.Fatalf("challenge for %v: %d %v", req, st, c)
	}
	return r.iss.Approve(time.Now(), api.ApprovalEntry{Challenge: c["challenge"].(string), Request: c["request"].(string)})
}

func (r *lrig) mode(t *testing.T) string {
	t.Helper()
	m, err := ipmi.GetFanMode(context.Background(), r.bmc)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (r *lrig) waitUpdate(t *testing.T) {
	t.Helper()
	for i := 0; i < 500; i++ {
		if st := r.upd.Status(); st.State != "downloading" && st.State != "applying" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the update did not finish")
}

// oldPanel sends what a panel from before approvals sends, and returns the answers' statuses.
func oldPanel(t *testing.T, r *lrig) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, c := range []struct {
		name, path string
		body       any
	}{
		{"fan mode", "/fan/mode", map[string]any{"mode": "full"}},
		{"fan duty", "/fan/duty", map[string]any{"zone": 0, "percent": 50}},
		{"shutdown", "/power", map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "neptune"}},
		{"cancel", "/power", map[string]any{"action": "cancel"}},
		{"reboot without delay", "/power", map[string]any{"action": "reboot"}},
		{"cancel again", "/power", map[string]any{"action": "cancel"}},
		{"bad action", "/power", map[string]any{"action": "explode"}},
		{"bad mode", "/fan/mode", map[string]any{"mode": "silent"}},
		{"update", "/update", map[string]any{"requested_by": "neptune"}},
	} {
		out[c.name], _ = r.post(t, c.path, c.body)
	}
	r.waitUpdate(t)
	return out
}

// TestOldPanelWithoutTrustBehavesAsBefore: an agent with the approval gate and no trust file answers an old
// panel exactly like an agent without the gate.
func TestOldPanelWithoutTrustBehavesAsBefore(t *testing.T) {
	plain, gated := newLinuxRig(t, false), newLinuxRig(t, true)
	for _, r := range []*lrig{plain, gated} {
		r.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{"fairy-agent-linux-amd64": []byte("build 42")}, nil)
	}
	want, got := oldPanel(t, plain), oldPanel(t, gated)
	for name, st := range want {
		if got[name] != st {
			t.Errorf("%s: %d with the gate, %d without", name, got[name], st)
		}
	}
	if want["shutdown"] != 200 || want["fan duty"] != 200 || want["update"] != 202 || want["bad action"] != 400 {
		t.Fatalf("the agent without the gate answered %v", want)
	}
	if gated.starts.Load() != 1 || len(gated.power.Scheduled) != 2 || gated.mode(t) != "full" {
		t.Errorf("with the gate and no trust: updates %d, power %v, mode %s", gated.starts.Load(), gated.power.Scheduled, gated.mode(t))
	}
	if ap := plain.approval(t); ap != nil {
		t.Errorf("an agent that checks nothing shows an approval block: %v", ap)
	}
	if ap := gated.approval(t); ap["state"] != api.ApprovalOff || ap["enforced_by"] != api.EnforcedByAgent || ap["proto"] != float64(1) {
		t.Errorf("approval block: %v", ap)
	}
	if gated.log.String() != "" {
		t.Errorf("without trust the gate wrote to the log:\n%s", gated.log.String())
	}
}

// TestLinuxAgentEnforcesApproval is the whole story on an agent that checks approvals itself: first-time set,
// challenge, approved action, replay, another action, the lock, what stays free, and a broken trust file.
func TestLinuxAgentEnforcesApproval(t *testing.T) {
	r := newLinuxRig(t, true)
	r.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{"fairy-agent-linux-amd64": []byte("build 42")}, nil)

	// a first-time set without the approval that proves it, and one whose proof does not fit the proposal
	// (the issuer's address with a slash too many): refused, nothing is written, nothing is locked
	st, b := r.post(t, api.PathApprovalTrust, r.iss.Init())
	wantRefusal(t, "first-time set without a proof", st, b, 403, api.CodeTrustProofRequired)
	typo := r.iss.Init()
	typo.Issuer += "/"
	st, b = r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, typo))
	wantRefusal(t, "first-time set with a proof that does not fit", st, b, 403, api.CodeTrustProofRefused)
	if _, err := os.Lstat(r.trust); err == nil {
		t.Fatal("a refused first-time set left a trust file")
	}
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "standard"}); st != 200 {
		t.Fatalf("after two refused sets the machine is not locked: fan mode %d %v", st, b)
	}
	// first-time set from the panel with its proof, once
	st, b = r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init()))
	if st != 200 || b["state"] != api.ApprovalRequired || b["enforced_by"] != api.EnforcedByAgent {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	if ap := r.approval(t); ap["state"] != api.ApprovalRequired || ap["issuer"] != r.iss.URL || ap["client_id"] != r.iss.ClientID ||
		ap["users"] != float64(1) || ap["fan_window_s"] != float64(30) || ap["boot_shutdown_s"] != float64(0) {
		t.Fatalf("approval block: %v", ap)
	}
	if fi, err := os.Stat(r.trust); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("trust file: %v %v", fi, err)
	}
	evil := *r.iss
	evil.Key, evil.Kid = approvaltest.Key(1), "evil"
	st, b = r.post(t, api.PathApprovalTrust, evil.Init())
	wantRefusal(t, "second set (locked)", st, b, 409, api.CodeTrustAlreadySet)
	st, b = r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "trust_set", "trust_hash": api.TrustHash(evil.Init())})
	wantRefusal(t, "challenge for a second set (locked)", st, b, 409, api.CodeTrustAlreadySet)

	// an old panel now: refused, nothing runs
	for name, c := range map[string]struct {
		path string
		body any
	}{
		"fan mode": {"/fan/mode", map[string]any{"mode": "full"}},
		"fan duty": {"/fan/duty", map[string]any{"zone": 0, "percent": 50}},
		"shutdown": {"/power", map[string]any{"action": "shutdown", "delay_s": 60}},
		"reboot":   {"/power", map[string]any{"action": "reboot"}},
		"sleep":    {"/power", map[string]any{"action": "sleep", "delay_s": 60}},
		"update":   {"/update", map[string]any{"requested_by": "neptune"}},
	} {
		st, b := r.post(t, c.path, c.body)
		wantRefusal(t, name+" without approval", st, b, 403, api.CodeApprovalRequired)
	}
	if r.mode(t) == "full" || len(r.power.Scheduled) != 0 || r.starts.Load() != 0 {
		t.Fatalf("something ran without approval: mode %s, power %v, updates %d", r.mode(t), r.power.Scheduled, r.starts.Load())
	}
	// the safe direction and waking stay free
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Errorf("cancel: %d %v", st, b)
	}
	if st, b := r.post(t, "/wol", map[string]any{"mac": "aa:bb:cc:dd:ee:ff", "broadcast": "10.255.255.255"}); st == 403 || st == 503 || b["code"] == api.CodeApprovalRequired {
		t.Errorf("wake-on-LAN asked for an approval: %d %v", st, b)
	}

	// approved shutdown
	ok := r.approve(t, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "neptune", "approval": ok}); st != 200 || b["pending"] == nil {
		t.Fatalf("approved shutdown: %d %v", st, b)
	}
	if len(r.power.Scheduled) != 1 || r.power.Scheduled[0] != "shutdown@1m0s" {
		t.Fatalf("scheduled: %v", r.power.Scheduled)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Fatalf("cancel of the approved shutdown: %d %v", st, b)
	}
	// replay
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": ok})
	wantRefusal(t, "replay", st, b, 403, api.CodeApprovalRefused)
	// the approval of one action for another, three ways
	fanOK := r.approve(t, map[string]any{"verb": "fan_mode", "mode": "full"})
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": fanOK})
	wantRefusal(t, "fan approval for a reboot", st, b, 403, api.CodeApprovalRefused)
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "heavyio", "approval": fanOK})
	wantRefusal(t, "fan approval for another mode", st, b, 403, api.CodeApprovalRefused)
	rewritten := &api.Approval{Token: fanOK.Token, Entries: []api.ApprovalEntry{{Challenge: fanOK.Entries[0].Challenge, Request: "power action=reboot delay_s=60"}}}
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": rewritten})
	wantRefusal(t, "fan approval with the entry rewritten", st, b, 403, api.CodeApprovalRefused)
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "approval": r.approve(t, map[string]any{"verb": "power", "action": "reboot", "delay_s": 300})})
	wantRefusal(t, "approved for 300 s, sent without delay_s (60)", st, b, 403, api.CodeApprovalRefused)
	// a token of somebody who is not Pocket ID
	e := r.approve(t, map[string]any{"verb": "power", "action": "reboot", "delay_s": 60}).Entries
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": evil.Approve(time.Now(), e...)})
	wantRefusal(t, "token signed with another key", st, b, 403, api.CodeApprovalRefused)
	if len(r.power.Scheduled) != 1 {
		t.Fatalf("scheduled: %v", r.power.Scheduled)
	}
	// the fan approval itself, then the fan window
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full", "approval": fanOK}); st != 200 || r.mode(t) != "full" {
		t.Fatalf("approved fan mode: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 50}); st != 200 {
		t.Errorf("fan duty in the fan window: %d %v", st, b)
	}
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60})
	wantRefusal(t, "reboot in the fan window", st, b, 403, api.CodeApprovalRequired)

	// approved update: checked when the request arrives, then the usual path
	up := r.approve(t, map[string]any{"verb": "apply_update"})
	if st, b := r.post(t, "/update", map[string]any{"requested_by": "neptune", "approval": up}); st != 202 {
		t.Fatalf("approved update: %d %v", st, b)
	}
	r.waitUpdate(t)
	if r.starts.Load() != 1 {
		t.Fatalf("installer starts: %d", r.starts.Load())
	}
	st, b = r.post(t, "/update", map[string]any{"approval": up})
	wantRefusal(t, "update replay", st, b, 403, api.CodeApprovalRefused)

	log := r.log.String()
	for _, want := range []string{"approval: accepted", "approval: refused", "approval: required, none sent", "sub=" + approvaltest.User,
		"trust set for the first time", "reason=already_set", "approval: not needed, fan window"} {
		if !strings.Contains(log, want) {
			t.Errorf("the agent's log lacks %q", want)
		}
	}
	for _, part := range strings.Split(ok.Token, ".") {
		if strings.Contains(log, part) {
			t.Error("the agent's log holds a part of a token")
		}
	}

	// a damaged trust file: everything that needed an approval is refused, with or without one; not "off"
	if err := os.WriteFile(r.trust, []byte(`{"version": 1`), 0o600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5200 * time.Millisecond) // the gate looks at the file again within 5 s
	if ap := r.approval(t); ap["state"] != api.ApprovalBroken || ap["error"] == nil || ap["issuer"] != nil {
		t.Fatalf("approval block with a damaged file: %v", ap)
	}
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown, damaged trust file", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 60})
	wantRefusal(t, "fan duty, damaged trust file", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, "/update", map[string]any{})
	wantRefusal(t, "update, damaged trust file", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "apply_update"})
	wantRefusal(t, "challenge, damaged trust file", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, api.PathApprovalTrust, r.iss.Init())
	wantRefusal(t, "first-time set over a damaged trust file", st, b, 409, api.CodeTrustAlreadySet)
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Errorf("cancel with a damaged trust file: %d %v", st, b)
	}
	if len(r.power.Scheduled) != 1 || r.starts.Load() != 1 {
		t.Fatalf("something ran with a damaged trust file: power %v, updates %d", r.power.Scheduled, r.starts.Load())
	}

	// the administrator removes the file on the machine (helper-trust clear): off, and the panel can set again
	if err := os.Remove(r.trust); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5200 * time.Millisecond)
	if ap := r.approval(t); ap["state"] != api.ApprovalOff {
		t.Fatalf("after the local clear: %v", ap)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 70}); st != 200 {
		t.Errorf("fan duty after the local clear: %d %v", st, b)
	}
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 {
		t.Errorf("first-time set after the local clear: %d %v", st, b)
	}
}

// provenTrust is in as the panel sends it for a first-time set: with iss's approval of this machine's challenge
// for exactly these values (POST /approval/challenge with the verb trust_set and the hash of the values).
func provenTrust(t *testing.T, base string, iss *approvaltest.Issuer, in api.TrustInit) api.TrustInit {
	t.Helper()
	hash := api.TrustHash(in)
	st, c := do(t, base, "POST", api.PathApprovalChallenge, ctlTok, map[string]any{"verb": api.ApproveTrustSet, "trust_hash": hash})
	if st != 200 || c["needed"] != true || c["request"] != "trust_set hash="+hash || c["expires_in_s"] != float64(180) || c["issuer"] != nil {
		t.Fatalf("challenge for trust_set: %d %v", st, c)
	}
	return iss.Prove(time.Now(), in, api.ApprovalEntry{Challenge: c["challenge"].(string), Request: c["request"].(string)})
}
