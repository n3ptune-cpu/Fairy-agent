package agent_test

// Windows machines on which the agent carries out some requests itself, next to a helper that checks the rest,
// and the agent's own decisions that depend on the helper's state. The tests are the ones of the security
// review of 2026-11-11 (H2, M1, L1), made to pass.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release/releasetest"
)

// mixedOpts say how a Windows machine is set up when its agent starts.
type mixedOpts struct {
	helper string // the helper service's state when the agent starts (api.HelperRunning ...)
	trust  bool   // a trust file is there before the agent starts
	damage bool   // ... and it is damaged
	// what the agent carries out in its own process instead of through the helper
	ownFan, ownPower, ownUpdate bool
	// noOwnGate: the agent is built without its own approval check (what Run never does; the safety net)
	noOwnGate bool
	// blindOwnGate: the agent's own look at the trust folder fails (as it would if its account could not run
	// the folder check on the helper's folder)
	blindOwnGate bool
}

type mixedRig struct {
	base, stage             string
	scm                     *fakeSCM
	bmc                     *fakebmc.BMC
	iss                     *approvaltest.Issuer
	files                   approval.Files
	upd                     *agent.Updater
	helperPower, agentPower *agenttest.PowerExec
	ownStarts, helperStarts atomic.Int32
	agentLog, helperLog     *logBuf
}

// newMixedRig is a Windows agent in front of the real helper code, wired the way Run wires it: the agent's own
// gate reads the helper's trust file and never writes it.
func newMixedRig(t *testing.T, o mixedOpts) *mixedRig {
	t.Helper()
	cfg, err := agent.Parse([]byte("ipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\nself_update: {enabled: true}\ncontrol_rate_per_min: 60\n"),
		filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &mixedRig{bmc: fakebmc.X11SCAF(), iss: approvaltest.New(), helperPower: &agenttest.PowerExec{}, agentPower: &agenttest.PowerExec{},
		agentLog: &logBuf{}, helperLog: &logBuf{}}
	gh := releasetest.New(t, release.AgentRepo)
	gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{"fairy-agent-linux-amd64": []byte("build 42")}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b := agent.NewBMC(r.bmc, 20*time.Millisecond)
	go b.Run(ctx)
	fan := agent.NewFan(r.bmc, b, cfg.FanControl, nil)
	r.files = approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	if o.trust {
		r.setTrustOnTheMachine(t)
	}
	if o.damage {
		if err := os.WriteFile(r.files.Path, []byte("damaged"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	hlog := slog.New(slog.NewTextHandler(r.helperLog, nil))
	parts := helper.Parts{Version: "test", Power: r.helperPower, Audit: hlog,
		Updater:  func(context.Context) error { r.helperStarts.Add(1); return nil },
		Approval: approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByHelper, Log: hlog, Files: r.files})}
	if !o.ownFan { // with fans over ipmitool the helper has no fan part (helper.FromConfig)
		parts.BMC, parts.Fan = b, fan
	}
	srv := helper.New(parts)
	r.scm = &fakeSCM{state: o.helper, srv: srv}
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
	go client.Run(ctx) // as Run does: the status is asked again all the time
	dir := t.TempDir()
	r.stage = filepath.Join(dir, "state", "update")
	uo := agent.UpdaterOptions{Version: "41-aaaaaaa", Key: gh.Pub, Client: gh.Client(),
		StageDir: r.stage, ResultPath: filepath.Join(dir, "result", "result.json"),
		Asset: "fairy-agent-linux-amd64", ResultWait: 50 * time.Millisecond,
		Apply: func(context.Context) error { r.ownStarts.Add(1); return nil }}
	if !o.ownUpdate {
		uo.ApplyApproved = client.ApplyUpdateApproved
	}
	r.upd = agent.NewUpdater(uo)
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: client, Updater: r.upd}
	if o.ownFan {
		d.BMC, d.Fan = b, fan
	} else {
		d.Fan = client.Fan(cfg.FanControl)
	}
	if o.ownPower {
		d.Power = agent.NewPower(r.agentPower, cfg.PowerControl.MinDelayS)
	} else {
		d.Power = agent.NewPower(client.Power(), cfg.PowerControl.MinDelayS)
	}
	if !o.noOwnGate { // as Run: the same file, read only
		own := r.files
		if o.blindOwnGate {
			own.CheckDir = func(string) error { return errors.New("access is denied") }
		}
		d.Approval = approval.NewGate(approval.Options{Files: own, EnforcedBy: api.EnforcedByAgent, ReadOnly: true,
			Log: slog.New(slog.NewTextHandler(r.agentLog, nil))})
	}
	hs := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(hs.Close)
	r.base = hs.URL
	return r
}

// setTrustOnTheMachine writes the trust file the way an administrator's helper-trust set does.
func (r *mixedRig) setTrustOnTheMachine(t *testing.T) {
	t.Helper()
	tr, err := approval.FromInit(r.iss.Init(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.files.Replace(tr); err != nil {
		t.Fatal(err)
	}
}

func (r *mixedRig) post(t *testing.T, path string, body any) (int, map[string]any) {
	t.Helper()
	return do(t, r.base, "POST", path, ctlTok, body)
}

// block is the "approval" block of /metrics once its state is want ("": once there is none).
func (r *mixedRig) block(t *testing.T, want string) map[string]any {
	t.Helper()
	var m map[string]any
	for i := 0; i < 300; i++ {
		_, m = do(t, r.base, "GET", "/metrics", readTok, nil)
		ap, ok := m["approval"].(map[string]any)
		if (want == "" && !ok) || (ok && ap["state"] == want) {
			return ap
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("approval block never %q: %v", want, m["approval"])
	return nil
}

func (r *mixedRig) approve(t *testing.T, req map[string]any) *api.Approval {
	t.Helper()
	st, c := r.post(t, api.PathApprovalChallenge, req)
	if st != 200 || c["needed"] != true || c["issuer"] != r.iss.URL {
		t.Fatalf("challenge for %v: %d %v", req, st, c)
	}
	return r.iss.Approve(time.Now(), api.ApprovalEntry{Challenge: c["challenge"].(string), Request: c["request"].(string)})
}

func (r *mixedRig) waitUpdate(t *testing.T) agent.UpdateStatus {
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

func (r *mixedRig) mode(t *testing.T) string {
	t.Helper()
	m, err := ipmi.GetFanMode(context.Background(), r.bmc)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func strs(v any) []string {
	var out []string
	list, _ := v.([]any)
	for _, x := range list {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

// TestWindowsFansInTheAgentAreCheckedByTheAgent (review H2): Windows with the helper, fans driven by the agent
// itself (ipmi.transport: ipmitool). While trust is set, /fan/mode and /fan/duty are checked by the agent's own
// gate (same trust file, same rules), power and update by the helper, and /metrics says who checks what.
func TestWindowsFansInTheAgentAreCheckedByTheAgent(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperRunning, trust: true, ownFan: true})
	blk := r.block(t, api.ApprovalRequired)
	if blk["enforced_by"] != api.EnforcedByHelper || !slices.Equal(strs(blk["agent_checks"]), []string{api.ApproveFanSet, api.ApproveFanMode}) || blk["agent_error"] != nil {
		t.Fatalf("approval block: %v", blk)
	}
	before := r.mode(t)
	st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full"})
	wantRefusal(t, "fan mode without approval", st, b, 403, api.CodeApprovalRequired)
	st, b = r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 35})
	wantRefusal(t, "fan duty without approval", st, b, 403, api.CodeApprovalRequired)
	if r.mode(t) != before {
		t.Fatalf("a fan request without approval ran: mode %s -> %s", before, r.mode(t))
	}
	// an honest panel can change the fans: the challenge comes from the agent, which is the one that checks
	ok := r.approve(t, map[string]any{"verb": "fan_mode", "mode": "full"})
	// ... and that approval is worth nothing for another request, at the agent or at the helper
	st, b = r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 35, "approval": ok})
	wantRefusal(t, "fan mode approval for a duty", st, b, 403, api.CodeApprovalRefused)
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": ok})
	wantRefusal(t, "the agent's fan approval for a shutdown at the helper", st, b, 403, api.CodeApprovalRefused)
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full", "approval": ok}); st != 200 {
		t.Fatalf("approved fan mode: %d %v", st, b)
	}
	if r.mode(t) != "full" {
		t.Fatalf("mode after the approved change: %s", r.mode(t))
	}
	// the fan window is the agent's too
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 35}); st != 200 {
		t.Errorf("fan duty in the fan window: %d %v", st, b)
	}
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "standard", "approval": ok})
	wantRefusal(t, "the same approval again", st, b, 403, api.CodeApprovalRefused)
	// power and update are the helper's: its challenge, its check
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown without approval", st, b, 403, api.CodeApprovalRequired)
	pok := r.approve(t, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": pok}); st != 200 {
		t.Fatalf("approved shutdown through the helper: %d %v", st, b)
	}
	if len(r.helperPower.Scheduled) != 1 || len(r.agentPower.Scheduled) != 0 {
		t.Fatalf("who scheduled: helper %v, agent %v", r.helperPower.Scheduled, r.agentPower.Scheduled)
	}
	// each program's log has its own decisions
	if l := r.agentLog.String(); !strings.Contains(l, "approval: required, none sent") || !strings.Contains(l, `request="fan_mode mode=full"`) ||
		!strings.Contains(l, "approval: accepted") || strings.Contains(l, "power action") {
		t.Errorf("agent log:\n%s", l)
	}
	if l := r.helperLog.String(); !strings.Contains(l, `request="power action=shutdown delay_s=60"`) || !strings.Contains(l, "approval: accepted") ||
		strings.Contains(l, "fan_mode") {
		t.Errorf("helper log:\n%s", l)
	}
	// the helper stops: fans do not depend on it, and are still checked
	if st, b := r.post(t, api.PathHelperStop, map[string]any{}); st != 200 {
		t.Fatalf("helper stop: %d %v", st, b)
	}
	r.block(t, api.ApprovalUnknown)
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "optimal", "approval": pok}) // an approval that is sent is checked, fan window or not
	wantRefusal(t, "fan mode with a used approval while the helper is stopped", st, b, 403, api.CodeApprovalRefused)
}

// TestWindowsFansInTheAgentWithTrustOff: the same machine without a trust file behaves as before.
func TestWindowsFansInTheAgentWithTrustOff(t *testing.T) {
	for _, noGate := range []bool{false, true} {
		r := newMixedRig(t, mixedOpts{helper: api.HelperRunning, ownFan: true, noOwnGate: noGate})
		blk := r.block(t, api.ApprovalOff)
		if !slices.Equal(strs(blk["agent_checks"]), []string{api.ApproveFanSet, api.ApproveFanMode}) {
			t.Errorf("no own gate %v: approval block: %v", noGate, blk)
		}
		if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full"}); st != 200 {
			t.Errorf("no own gate %v: fan mode with trust off: %d %v", noGate, st, b)
		}
		if st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "full"}); noGate && st != 404 || !noGate && (st != 200 || c["needed"] != false || c["reason"] != "off") {
			t.Errorf("no own gate %v: challenge with trust off: %d %v", noGate, st, c)
		}
	}
}

// TestAgentThatCannotLookAtTheTrustFolder: the agent's own check cannot run (its account cannot check the
// helper's folder). With a trust file that is a refusal of everything the agent would have to check, and
// /metrics says why. Without one, the helper, whose file it is, says "off", and the fans work as they always
// did: a machine that never set a trust must not lose fan control over this.
func TestAgentThatCannotLookAtTheTrustFolder(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperRunning, ownFan: true, blindOwnGate: true})
	blk := r.block(t, api.ApprovalOff)
	if blk["agent_error"] == nil || !strings.Contains(blk["agent_error"].(string), "access is denied") {
		t.Errorf("approval block: %v", blk)
	}
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full"}); st != 200 {
		t.Fatalf("no trust file, fan mode: %d %v", st, b)
	}
	if st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "full"}); st != 200 || c["needed"] != false || c["reason"] != "off" {
		t.Errorf("no trust file, challenge: %d %v", st, c)
	}
	// the helper stops: nobody can say that there is no trust file
	if st, b := r.post(t, api.PathHelperStop, map[string]any{}); st != 200 {
		t.Fatalf("helper stop: %d %v", st, b)
	}
	st, b := r.post(t, "/fan/mode", map[string]any{"mode": "standard"})
	wantRefusal(t, "fan mode, helper stopped", st, b, 503, api.CodeApprovalUnavailable)
	// the same machine with a trust file: the helper says required, the agent cannot check, so it refuses
	r = newMixedRig(t, mixedOpts{helper: api.HelperRunning, ownFan: true, blindOwnGate: true, trust: true})
	if blk := r.block(t, api.ApprovalRequired); blk["agent_error"] == nil {
		t.Errorf("approval block: %v", blk)
	}
	before := r.mode(t)
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "optimal"})
	wantRefusal(t, "fan mode, trust set", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "optimal"})
	wantRefusal(t, "challenge, trust set", st, b, 503, api.CodeApprovalUnavailable)
	if r.mode(t) != before {
		t.Fatalf("a fan request ran unchecked: mode %s -> %s", before, r.mode(t))
	}
	// what the helper carries out is not touched by any of this
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown through the helper", st, b, 403, api.CodeApprovalRequired)
}

// TestAgentWithoutItsOwnCheckRefuses: the review's test as it was written, with an agent that was built without
// a gate of its own. It must not run what it cannot check (the state before the fix: 200 twice).
func TestAgentWithoutItsOwnCheckRefuses(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperRunning, trust: true, ownFan: true, noOwnGate: true})
	blk := r.block(t, api.ApprovalRequired)
	if blk["agent_error"] == nil || len(strs(blk["agent_checks"])) != 2 {
		t.Errorf("approval block: %v", blk)
	}
	before := r.mode(t)
	st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full"})
	wantRefusal(t, "fan mode", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 35})
	wantRefusal(t, "fan duty", st, b, 503, api.CodeApprovalUnavailable)
	st, b = r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "full"})
	wantRefusal(t, "challenge", st, b, 503, api.CodeApprovalUnavailable)
	if r.mode(t) != before {
		t.Fatalf("a fan request ran unchecked: mode %s -> %s", before, r.mode(t))
	}
}

// TestAgentStartedBeforeTheHelperWasInstalled: an agent that started without the helper carries out power and
// update itself. A helper installed later (and trust set through it) does not leave those requests unchecked:
// the agent's own gate reads the same trust file.
func TestAgentStartedBeforeTheHelperWasInstalled(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperNotInstalled, ownFan: true, ownPower: true, ownUpdate: true})
	if blk := r.block(t, ""); blk != nil {
		t.Fatalf("approval block without a helper and without trust: %v", blk)
	}
	for _, path := range []string{api.PathApprovalChallenge, api.PathApprovalTrust} {
		st, b := r.post(t, path, map[string]any{"verb": "apply_update"})
		wantRefusal(t, path+" without a helper", st, b, 404, api.CodeApprovalDisabled)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60}); st != 200 {
		t.Fatalf("shutdown, no helper, no trust: %d %v", st, b)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Fatalf("cancel: %d %v", st, b)
	}
	// the helper is installed and started; the panel sets the trust through it (with its proof)
	r.scm.mu.Lock()
	r.scm.state = api.HelperRunning
	r.scm.mu.Unlock()
	r.block(t, api.ApprovalOff)
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 || b["enforced_by"] != api.EnforcedByHelper {
		t.Fatalf("first-time set through the helper: %d %v", st, b)
	}
	blk := r.block(t, api.ApprovalRequired)
	if !slices.Equal(strs(blk["agent_checks"]), []string{api.ApproveFanSet, api.ApproveFanMode, api.ApprovePower, api.ApproveApplyUpdate}) {
		t.Fatalf("approval block: %v", blk)
	}
	// at once, not five seconds later: the set went through this agent, and its own gate has looked again
	st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown by the agent itself", st, b, 403, api.CodeApprovalRequired)
	st, b = r.post(t, "/update", map[string]any{})
	wantRefusal(t, "update by the agent itself", st, b, 403, api.CodeApprovalRequired)
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "full"})
	wantRefusal(t, "fan mode by the agent itself", st, b, 403, api.CodeApprovalRequired)
	if len(r.agentPower.Scheduled) != 1 || r.ownStarts.Load() != 0 {
		t.Fatalf("something ran unchecked: power %v, updates %d", r.agentPower.Scheduled, r.ownStarts.Load())
	}
	ok := r.approve(t, map[string]any{"verb": "power", "action": "reboot", "delay_s": 60})
	if st, b := r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": ok}); st != 200 {
		t.Fatalf("approved reboot, checked by the agent: %d %v", st, b)
	}
	uok := r.approve(t, map[string]any{"verb": "apply_update"})
	if st, b := r.post(t, "/update", map[string]any{"approval": uok}); st != 202 {
		t.Fatalf("approved update, checked by the agent: %d %v", st, b)
	}
	r.waitUpdate(t)
	if r.ownStarts.Load() != 1 || r.helperStarts.Load() != 0 {
		t.Fatalf("approved update: own %d, helper %d", r.ownStarts.Load(), r.helperStarts.Load())
	}
	// the agent's gate never sets or changes the trust
	st, b = r.post(t, api.PathApprovalTrust, r.iss.Init("somebody-else"))
	wantRefusal(t, "second set", st, b, 409, api.CodeTrustAlreadySet)
}

// TestWindowsWithoutHelperAndATrustFile: the helper was removed after trust was set (or a trust file was put
// there by hand). The agent, which now carries everything out itself, still checks.
func TestWindowsWithoutHelperAndATrustFile(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperNotInstalled, trust: true, ownFan: true, ownPower: true, ownUpdate: true})
	blk := r.block(t, api.ApprovalRequired)
	if blk["enforced_by"] != api.EnforcedByAgent || blk["agent_checks"] != nil {
		t.Fatalf("approval block: %v", blk)
	}
	st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown", st, b, 403, api.CodeApprovalRequired)
	st, b = r.post(t, "/update", map[string]any{})
	wantRefusal(t, "update", st, b, 403, api.CodeApprovalRequired)
	ok := r.approve(t, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": ok}); st != 200 {
		t.Fatalf("approved shutdown: %d %v", st, b)
	}
	st, b = r.post(t, api.PathApprovalTrust, r.iss.Init())
	wantRefusal(t, "set", st, b, 409, api.CodeTrustAlreadySet)
	st, b = r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "trust_set", "trust_hash": api.TrustHash(r.iss.Init())})
	wantRefusal(t, "challenge for a set", st, b, 409, api.CodeTrustAlreadySet)
}

// TestUpdateFailsClosedWithoutTheHelper (review M1): Windows /update is the agent keeping to the rule. It must
// never take "the helper cannot be reached" for "approval is off".
func TestUpdateFailsClosedWithoutTheHelper(t *testing.T) {
	for name, c := range map[string]struct {
		o      mixedOpts
		status int
		code   string
	}{
		// the review's case: trust set, the helper not running when the agent starts
		"trust set, helper stopped since the agent started":                  {mixedOpts{helper: api.HelperStopped, trust: true}, 503, api.CodeApprovalUnavailable},
		"trust set, helper starting":                                         {mixedOpts{helper: api.HelperStarting, trust: true}, 503, api.CodeApprovalUnavailable},
		"damaged trust file, helper stopped":                                 {mixedOpts{helper: api.HelperStopped, trust: true, damage: true}, 503, api.CodeApprovalUnavailable},
		"helper stopped, an agent that cannot look at the trust file":        {mixedOpts{helper: api.HelperStopped, trust: true, noOwnGate: true}, 503, api.CodeApprovalUnavailable},
		"no trust file, helper stopped, agent cannot look":                   {mixedOpts{helper: api.HelperStopped, noOwnGate: true}, 503, api.CodeApprovalUnavailable},
		"no trust file, helper stopped: the agent sees for itself it is off": {mixedOpts{helper: api.HelperStopped}, 202, ""},
		"no trust file, helper running":                                      {mixedOpts{helper: api.HelperRunning}, 202, ""},
		"trust set, helper running":                                          {mixedOpts{helper: api.HelperRunning, trust: true}, 403, api.CodeApprovalRequired},
		"damaged trust file, helper running":                                 {mixedOpts{helper: api.HelperRunning, trust: true, damage: true}, 503, api.CodeApprovalUnavailable},
	} {
		r := newMixedRig(t, c.o)
		// at once: the agent has not had the time to hear from the helper (the moment after boot)
		st, b := r.post(t, "/update", map[string]any{"requested_by": "hostile panel"})
		if st != c.status || (c.code != "" && b["code"] != c.code) {
			t.Errorf("%s: %d %v, want %d %s", name, st, b, c.status, c.code)
		}
		r.waitUpdate(t)
		wantOwn := int32(0)
		if c.status == 202 {
			wantOwn = 1
		}
		if r.ownStarts.Load() != wantOwn || r.helperStarts.Load() != 0 {
			t.Errorf("%s: installer started with the agent's own right %d time(s), through the helper %d", name, r.ownStarts.Load(), r.helperStarts.Load())
		}
		if c.status != 202 {
			if ents, _ := os.ReadDir(r.stage); len(ents) != 0 {
				t.Errorf("%s: a refused update staged %d files", name, len(ents))
			}
		}
	}
}

// TestUpdateWhenTheHelperIsStoppedByThePanel: POST /helper/stop needs no approval. It must not open /update.
func TestUpdateWhenTheHelperIsStoppedByThePanel(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperRunning, trust: true})
	r.block(t, api.ApprovalRequired)
	if st, b := r.post(t, api.PathHelperStop, map[string]any{}); st != 200 {
		t.Fatalf("helper stop: %d %v", st, b)
	}
	st, b := r.post(t, "/update", map[string]any{})
	wantRefusal(t, "update right after the helper was stopped", st, b, 503, api.CodeApprovalUnavailable)
	if !strings.Contains(b["error"].(string), "is not answering") {
		t.Errorf("refusal text: %v", b["error"])
	}
	// the trust file is removed on the machine while the helper is stopped: now the agent sees "off" itself
	if err := r.files.Remove(); err != nil {
		t.Fatal(err)
	}
	if st, b := r.post(t, "/update", map[string]any{}); st != 202 {
		t.Fatalf("update with no trust file and a stopped helper: %d %v", st, b)
	}
	r.waitUpdate(t)
	if r.ownStarts.Load() != 1 {
		t.Fatalf("own starts %d", r.ownStarts.Load())
	}
}

// TestUpdateRightAfterTrustWasSetOnTheMachine: an administrator sets trust with helper-trust set. The helper
// reads the file again within 5 seconds; in between it still says "off". The agent's own look at the file, at
// the moment of the request, closes that gap.
func TestUpdateRightAfterTrustWasSetOnTheMachine(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperRunning})
	r.block(t, api.ApprovalOff) // the helper has looked: off
	r.setTrustOnTheMachine(t)
	st, b := r.post(t, "/update", map[string]any{})
	wantRefusal(t, "update a moment after the local set", st, b, 403, api.CodeApprovalRequired)
	if r.ownStarts.Load() != 0 {
		t.Fatal("the installer was started")
	}
}

// TestRefusedUpdateApprovalLeavesNoStage (review L1): an update with a made-up approval is downloaded and
// staged, the helper refuses to start the installer, and the stage must be gone: a complete stage would be
// installed by whatever starts the updater service next.
func TestRefusedUpdateApprovalLeavesNoStage(t *testing.T) {
	r := newMixedRig(t, mixedOpts{helper: api.HelperRunning, trust: true})
	r.block(t, api.ApprovalRequired)
	junk := &api.Approval{Token: "a.b.c", Entries: []api.ApprovalEntry{{Challenge: strings.Repeat("A", 43), Request: "apply_update"}}}
	if st, b := r.post(t, "/update", map[string]any{"approval": junk}); st != 202 {
		t.Fatalf("update with a made-up approval: %d %v", st, b)
	}
	if st := r.waitUpdate(t); st.State != "failed" || !strings.Contains(st.Message, "approval refused") {
		t.Fatalf("made-up approval: %+v", st)
	}
	if ents, _ := os.ReadDir(r.stage); len(ents) != 0 {
		var names []string
		for _, e := range ents {
			names = append(names, e.Name())
		}
		t.Errorf("stage after a refused approval: %v", names)
	}
	if r.ownStarts.Load() != 0 || r.helperStarts.Load() != 0 {
		t.Errorf("installer starts: own %d, helper %d", r.ownStarts.Load(), r.helperStarts.Load())
	}
	// a real approval afterwards still works (the stage is made again)
	ok := r.approve(t, map[string]any{"verb": "apply_update"})
	if st, b := r.post(t, "/update", map[string]any{"approval": ok}); st != 202 {
		t.Fatalf("approved update: %d %v", st, b)
	}
	r.waitUpdate(t)
	if r.helperStarts.Load() != 1 || r.ownStarts.Load() != 0 {
		t.Errorf("approved update: own %d, helper %d", r.ownStarts.Load(), r.helperStarts.Load())
	}
}
