package agent_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
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
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/release/releasetest"
)

// Runs, as the panel sees them: the agent's HTTP API on a machine that keeps runs itself (Linux: the agent
// checks, writes the record and switches the machine off) and on one whose helper does (Windows: the real
// helper code on an in-memory pipe behind the agent, which only carries). The clock, the uptime and the boot id
// of the checker are the test's.

type rrig struct {
	t       *testing.T
	windows bool
	base    string
	iss     *approvaltest.Issuer
	files   approval.Files
	exec    *agenttest.PowerExec // what the system was asked to do
	audit   *logBuf              // the checker's log (Windows: helper.log)
	gh      *releasetest.Server
	upd     *agent.Updater

	mu     sync.Mutex
	now    time.Time
	up     time.Duration
	bootID string

	watch        atomic.Pointer[approval.RunWatch] // the checker's
	startChecker func(runs bool)                   // (Windows) the helper starts again
	ownStarts    atomic.Int32                      // the agent started the installer with its own right
	helperStarts atomic.Int32                      // the helper started it
	guests       atomic.Bool
	tokens       []string
}

func (r *rrig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *rrig) uptime() (time.Duration, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.up, nil
}
func (r *rrig) boot() (string, error) { r.mu.Lock(); defer r.mu.Unlock(); return r.bootID, nil }

// pass moves time on and lets the checker's watch look.
func (r *rrig) pass(d time.Duration) {
	r.mu.Lock()
	r.now, r.up = r.now.Add(d), r.up+d
	r.mu.Unlock()
	r.watch.Load().Tick()
}

const (
	hRunA = "00000000000000a1"
	hRunB = "00000000000000b2"
)

func newRunsRig(t *testing.T, windows bool) *rrig {
	t.Helper()
	cfg, err := agent.Parse([]byte("power_control: {enabled: true, min_delay_s: 30}\nself_update: {enabled: true}\ncontrol_rate_per_min: 60\n"),
		filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r := &rrig{t: t, windows: windows, iss: approvaltest.New(), exec: &agenttest.PowerExec{}, audit: &logBuf{},
		gh: releasetest.New(t, release.AgentRepo), now: time.Now(), up: 60 * time.Second, bootID: "boot-1"}
	r.files = approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	log := slog.New(slog.NewTextHandler(r.audit, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dir := t.TempDir()
	uo := agent.UpdaterOptions{Version: "41-aaaaaaa", Key: r.gh.Pub, Client: r.gh.Client(),
		StageDir: filepath.Join(dir, "state", "update"), ResultPath: filepath.Join(dir, "result", "result.json"),
		Asset: "fairy-agent-linux-amd64", ResultWait: 50 * time.Millisecond,
		Apply: func(context.Context) error { r.ownStarts.Add(1); return nil }}
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test"}
	if windows {
		r.bootID = "0f1e2d3c4b5a69788796a5b4c3d2e1f0" // the value the helper keeps in its volatile registry key
		var srv atomic.Pointer[helper.Server]
		var conns []net.Conn // the pipe connections of the helper that is running: they end with it
		r.startChecker = func(runs bool) {
			s := helper.New(helper.Parts{Version: "test", Power: agent.RememberPower(r.exec, nil, nil, nil), MinDelayS: 30, Audit: log,
				Updater: func(context.Context) error { r.helperStarts.Add(1); return nil },
				Approval: approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByHelper, Log: log, Files: r.files,
					Now: r.clock, Uptime: r.uptime, BootID: r.boot, Runs: runs, MinDelayS: 30})})
			// under the lock the dial takes: a connection is either one of the helper before, and ends here, or
			// one of this helper. None is left with the helper before.
			r.mu.Lock()
			srv.Store(s)
			for _, c := range conns {
				c.Close()
			}
			conns = nil
			r.mu.Unlock()
			r.watch.Store(s.Runs())
		}
		r.startChecker(true)
		scm := &fakeSCM{state: api.HelperRunning, srv: srv.Load()}
		dial := func(context.Context) (io.ReadWriteCloser, error) {
			if st, _ := scm.State(); st != api.HelperRunning {
				return nil, errors.New("pipe not found")
			}
			a, c := net.Pipe()
			r.mu.Lock()
			s := srv.Load()
			conns = append(conns, a)
			r.mu.Unlock()
			go func() { s.ServeConn(ctx, a, "test"); a.Close() }()
			return c, nil
		}
		client := agent.NewHelperClient(dial, scm, true)
		// As in the agent, the helper's status is asked again all the time. Ten times a second and not more: the
		// helper answers 300 reads a minute (proto.ReadsPerMinute) and then refuses, so a test that asked every
		// 10 ms had three seconds to finish in.
		client.Every = 100 * time.Millisecond
		go client.Run(ctx)
		uo.ApplyApproved, uo.ApplyRun = client.ApplyUpdateApproved, client.ApplyUpdateRun
		hp := client.Power()
		d.Helper, d.Power, d.HelperSources = client, agent.NewPowerForRuns(hp, 30, hp.RunLive), []string{api.FeaturePower}
		// the agent's own gate, as Run builds it on Windows: it only reads the helper's files
		d.Approval = approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByAgent, Files: r.files, ReadOnly: true,
			Now: r.clock, Uptime: r.uptime, BootID: r.boot, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	} else {
		d.Approval = approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByAgent, Files: r.files, Log: log,
			Now: r.clock, Uptime: r.uptime, BootID: r.boot, Runs: true, MinDelayS: 30})
		d.Power = agent.NewPower(r.exec, 30)
		power := d.Power
		d.Runs = approval.NewRunWatch(d.Approval, approval.RunHooks{Pending: power.Scheduled, Shutdown: power.ScheduleOwn,
			Cancel:   func() error { return power.CancelOwn("run") },
			Updating: func() bool { return r.upd != nil && r.upd.Busy() },
			Guests:   func() (bool, error) { return r.guests.Load(), nil }})
		r.watch.Store(d.Runs)
	}
	r.upd = agent.NewUpdater(uo)
	d.Updater = r.upd
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(srv.Close)
	r.base = srv.URL
	r.gh.Publish("build-42", "fairy-agent", "42-bbbbbbb", map[string][]byte{"fairy-agent-linux-amd64": []byte("build 42")}, nil)
	return r
}

func (r *rrig) post(path string, body any) (int, map[string]any) {
	r.t.Helper()
	return do(r.t, r.base, "POST", path, ctlTok, body)
}

func (r *rrig) trusted() *rrig {
	r.t.Helper()
	if st, b := r.post(api.PathApprovalTrust, provenTrust(r.t, r.base, r.iss, r.iss.Init())); st != 200 {
		r.t.Fatalf("first-time set: %d %v", st, b)
	}
	// the run record this machine has from a boot before (one that is made now would close this boot for tickets)
	if err := approvaltest.EarlierBoot(r.files, r.clock().Add(-24*time.Hour)); err != nil {
		r.t.Fatal(err)
	}
	return r
}

// block is the "approval" block of /metrics as it is now.
func (r *rrig) block() map[string]any {
	r.t.Helper()
	var ap map[string]any
	for i := 0; i < 300; i++ {
		_, m := do(r.t, r.base, "GET", "/metrics", readTok, nil)
		if ap, _ = m["approval"].(map[string]any); ap != nil && ap["state"] != api.ApprovalUnknown {
			return ap
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.t.Fatalf("no approval block: %v", ap)
	return nil
}

// runIs waits (for the helper's status to reach the agent) until /metrics shows the run in state want ("":
// no run).
func (r *rrig) runIs(want string) map[string]any {
	r.t.Helper()
	var run map[string]any
	for i := 0; i < 300; i++ {
		run, _ = r.block()["run"].(map[string]any)
		if (want == "" && run == nil) || (run != nil && run["state"] == want) {
			return run
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.t.Fatalf("the run never became %q: %v", want, run)
	return nil
}

// ticket is a run ticket for this machine as the panel would send it: signed age ago, 32 random bytes of the
// panel's in the place of a challenge.
func (r *rrig) ticket(run string, age time.Duration) *api.Approval {
	var b [32]byte
	rand.Read(b[:])
	valid, wait, notice := 420, 960, 120
	text, _ := (api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}).Canonical()
	ap := r.iss.Approve(r.clock().Add(-age), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: approvaltest.B64(b[:]), Request: text})
	r.tokens = append(r.tokens, ap.Token)
	return ap
}

func (r *rrig) arm(run string) {
	r.t.Helper()
	st, b := r.post(api.PathRunArm, map[string]any{"approval": r.ticket(run, 160*time.Second)})
	if st != 200 || b["run"] != run || b["state"] != api.RunArmed || b["off_in_s"] != float64(960) || len(b) != 3 {
		r.t.Fatalf("arm: %d %v", st, b)
	}
}

// confirm is the second passkey: the challenge for run_go, the approval of it, POST /run/go.
func (r *rrig) confirm(run, to string, delay, within int) (int, map[string]any) {
	r.t.Helper()
	body := map[string]any{"run": run, "to": to, "shutdown_delay_s": delay, "within_s": within}
	ch := map[string]any{"verb": api.ApproveRunGo}
	for k, v := range body {
		ch[k] = v
	}
	st, c := r.post(api.PathApprovalChallenge, ch)
	if st != 200 {
		return st, c
	}
	if c["needed"] != true || c["issuer"] != r.iss.URL {
		r.t.Fatalf("challenge for run_go: %v", c)
	}
	ap := r.iss.Approve(r.clock(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c["challenge"].(string), Request: c["request"].(string)})
	r.tokens = append(r.tokens, ap.Token)
	body["approval"] = ap
	return r.post(api.PathRunGo, body)
}

func (r *rrig) updateDone() agent.UpdateStatus {
	r.t.Helper()
	for i := 0; i < 500; i++ {
		if st := r.upd.Status(); !r.upd.Busy() {
			return st
		}
		time.Sleep(10 * time.Millisecond)
	}
	r.t.Fatal("the update never ended")
	return agent.UpdateStatus{}
}

// nothingOfARunOnRecord: the record is there on every machine with trust (the checker keeps the clock in it),
// and nothing a ticket, a confirmation or a cancel leaves is in it.
func (r *rrig) nothingOfARunOnRecord(when string) {
	r.t.Helper()
	rec, err := os.ReadFile(filepath.Join(filepath.Dir(r.files.Path), approval.RunFileName))
	if err != nil {
		return
	}
	for _, member := range []string{`"run"`, `"used"`, `"last"`} {
		if strings.Contains(string(rec), member) {
			r.t.Errorf("the run record holds %s %s: %s", member, when, rec)
		}
	}
	// the mark that closes a boot for tickets is the one of the boot before (approvaltest.EarlierBoot), not of this one
	if strings.Count(string(rec), `"boot_id":"`+r.bootID+`"`) > 1 {
		r.t.Errorf("this boot is closed for tickets %s: %s", when, rec)
	}
}

func (r *rrig) starts() int32 { return r.ownStarts.Load() + r.helperStarts.Load() }

func (r *rrig) noToken(more ...any) {
	r.t.Helper()
	_, m := do(r.t, r.base, "GET", "/metrics", readTok, nil)
	mb, _ := json.Marshal(m)
	ab, _ := json.Marshal(more)
	rec, _ := os.ReadFile(filepath.Join(filepath.Dir(r.files.Path), approval.RunFileName))
	for _, tok := range r.tokens {
		for _, part := range strings.Split(tok, ".") {
			for where, text := range map[string]string{"the checker's log": r.audit.String(), "/metrics": string(mb), "an answer": string(ab), "the record": string(rec)} {
				if strings.Contains(text, part) || strings.Contains(text, part[:24]) {
					r.t.Errorf("%s holds a piece of a token", where)
				}
			}
		}
	}
}

func bothKinds(t *testing.T, f func(t *testing.T, r *rrig)) {
	for _, windows := range []bool{false, true} {
		name := "the agent keeps the run (Linux)"
		if windows {
			name = "the helper keeps the run (Windows)"
		}
		t.Run(name, func(t *testing.T) { f(t, newRunsRig(t, windows)) })
	}
}

// The whole run of a machine that is confirmed: ticket, confirmation, the one update to the version named, the
// one shutdown with the delay named. And the block the panel reads.
func TestRunOverHTTP(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		if ap := r.block(); ap["runs"] != float64(1) || ap["proto"] != float64(2) || ap["state"] != api.ApprovalOff || ap["run"] != nil {
			t.Fatalf("approval block without trust: %v", ap)
		}
		r.trusted()
		if ap := r.block(); ap["runs"] != float64(1) || ap["proto"] != float64(2) || ap["run"] != nil {
			t.Fatalf("approval block: %v", ap)
		}
		// nothing of a run without its confirmation
		st, b := r.post("/update", map[string]any{"run": hRunA})
		wantRefusal(t, "update with a run nobody confirmed", st, b, 403, api.CodeApprovalRequired)
		st, b = r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA})
		wantRefusal(t, "shutdown with a run nobody confirmed", st, b, 403, api.CodeApprovalRequired)

		r.arm(hRunA)
		run := r.runIs(api.RunArmed)
		if run["id"] != hRunA || run["off_at"] != float64(r.clock().Add(960*time.Second).Unix()) || len(run) != 3 {
			t.Fatalf("run block: %v", run)
		}
		st, b = r.post("/update", map[string]any{"run": hRunA})
		wantRefusal(t, "update of a run that is only armed", st, b, 403, api.CodeApprovalRequired)

		st, b = r.confirm(hRunA, "42-bbbbbbb", 30, 1500)
		if st != 200 || b["run"] != hRunA || b["state"] != api.RunConfirmed || b["within_s"] != float64(1500) || len(b) != 3 {
			t.Fatalf("go: %d %v", st, b)
		}
		if run := r.runIs(api.RunConfirmed); run["off_at"] != nil {
			t.Fatalf("run block: %v", run)
		}
		r.pass(1000 * time.Second) // the ticket's wait is over: a confirmed machine does not switch itself off
		if len(r.exec.Scheduled) != 0 {
			t.Fatalf("scheduled %v", r.exec.Scheduled)
		}
		// the one update
		st, b = r.post("/update", map[string]any{"run": hRunB})
		wantRefusal(t, "update with another run", st, b, 403, api.CodeApprovalRequired)
		st, b = r.post("/update", map[string]any{"run": "nonsense"})
		if st != 400 {
			t.Errorf("update with a run id that is none: %d %v", st, b)
		}
		if st, b := r.post("/update", map[string]any{"run": hRunA, "requested_by": "run"}); st != 202 {
			t.Fatalf("the update: %d %v", st, b)
		}
		// (the test's installer reports nothing back, so the update ends "failed: did not report back")
		if us := r.updateDone(); us.Target != "42-bbbbbbb" || r.starts() != 1 || r.gh.Downloads("fairy-agent-linux-amd64") != 1 {
			t.Fatalf("after the update: %+v, %d starts", us, r.starts())
		}
		if r.windows && r.helperStarts.Load() != 1 {
			t.Error("on Windows the helper starts the installer of a run's update")
		}
		st, b = r.post("/update", map[string]any{"run": hRunA})
		wantRefusal(t, "a second update", st, b, 403, api.CodeApprovalRequired)
		if r.starts() != 1 {
			t.Fatalf("%d installer starts", r.starts())
		}
		// the one shutdown
		for name, body := range map[string]map[string]any{
			"another delay": {"action": "shutdown", "delay_s": 31, "run": hRunA}, "no delay (60 s)": {"action": "shutdown", "run": hRunA},
			"a reboot": {"action": "reboot", "delay_s": 30, "run": hRunA}, "a sleep": {"action": "sleep", "delay_s": 30, "run": hRunA},
			"another run": {"action": "shutdown", "delay_s": 30, "run": hRunB}, "no run": {"action": "shutdown", "delay_s": 30},
		} {
			st, b := r.post("/power", body)
			wantRefusal(t, name, st, b, 403, api.CodeApprovalRequired)
		}
		if st, b := r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA, "requested_by": "run"}); st != 200 || b["pending"] == nil {
			t.Fatalf("the shutdown: %d %v", st, b)
		}
		st, b = r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA})
		if st == 200 {
			t.Fatalf("a second shutdown: %d %v", st, b)
		}
		if len(r.exec.Scheduled) != 1 || r.exec.Scheduled[0] != "shutdown@30s" {
			t.Fatalf("scheduled %v", r.exec.Scheduled)
		}
		r.runIs(api.RunDone)
		// the panel's Cancel stops that shutdown as it stops every other
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 || r.exec.Cancels != 1 {
			t.Fatalf("cancel: %d %v, %d", st, b, r.exec.Cancels)
		}
		st, b = r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA})
		wantRefusal(t, "the shutdown again after its cancel", st, b, 403, api.CodeApprovalRequired)
		r.noToken()
	})
}

// Nobody confirms: the machine switches itself off when the wait is over, with the ordinary delayed shutdown.
// It is shown as pending like any other, and the panel's Cancel stops it; nothing arms the machine again.
func TestRunSelfOffOverHTTP(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		r.trusted()
		r.arm(hRunA)
		r.pass(959 * time.Second)
		if len(r.exec.Scheduled) != 0 {
			t.Fatalf("early: %v", r.exec.Scheduled)
		}
		r.pass(time.Second)
		if len(r.exec.Scheduled) != 1 || r.exec.Scheduled[0] != "shutdown@2m0s" {
			t.Fatalf("when the wait is over: %v", r.exec.Scheduled)
		}
		run := r.runIs(api.RunOffPending)
		if run["off_at"] != float64(r.clock().Add(120*time.Second).Unix()) {
			t.Errorf("run block %v", run)
		}
		var pend map[string]any
		for i := 0; i < 300 && pend == nil; i++ {
			_, m := do(t, r.base, "GET", "/metrics", readTok, nil)
			pend, _ = m["power_control"].(map[string]any)["pending"].(map[string]any)
			time.Sleep(10 * time.Millisecond)
		}
		if pend == nil || pend["action"] != "shutdown" || pend["delay_s"] != float64(120) || pend["requested_by"] != "run "+hRunA {
			t.Fatalf("pending: %v", pend)
		}
		// too late for a confirmation
		st, b := r.confirm(hRunA, "42-bbbbbbb", 30, 1500)
		if st != 409 || b["code"] != api.CodeRunRefused || b["reason"] != api.RunReasonTooLate {
			t.Errorf("a confirmation during the countdown: %d %v", st, b)
		}
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 {
			t.Fatalf("cancel: %d %v", st, b)
		}
		if r.exec.Cancels != 1 {
			t.Fatalf("the countdown was stopped %d times", r.exec.Cancels)
		}
		r.runIs(api.RunCancelled)
		r.pass(3000 * time.Second)
		if len(r.exec.Scheduled) != 1 {
			t.Fatalf("scheduled again: %v", r.exec.Scheduled)
		}
		st, b = r.post(api.PathRunArm, map[string]any{"approval": r.ticket(hRunB, 0)})
		if st == 200 {
			t.Errorf("armed again after the cancel: %v", b)
		}
		r.noToken(b)
	})
}

// The panel's Cancel while the machine is armed and nothing is pending yet: it disarms. (On Windows the agent
// has nothing on record to cancel then; the cancel reaches the helper all the same.)
func TestRunCancelOverHTTPWhileArmed(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		r.trusted()
		r.arm(hRunA)
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
			t.Fatalf("cancel: %d %v", st, b)
		}
		r.runIs(api.RunCancelled)
		r.pass(2000 * time.Second)
		if len(r.exec.Scheduled) != 0 {
			t.Fatalf("a cancelled run switched the machine off: %v", r.exec.Scheduled)
		}
		st, b := r.post(api.PathRunArm, map[string]any{"approval": r.ticket(hRunB, 0)})
		if st == 200 {
			t.Errorf("armed again: %v", b)
		}
		st, b = r.confirm(hRunA, "42-bbbbbbb", 30, 1500)
		if st != 409 || b["reason"] != api.RunReasonOver {
			t.Errorf("a confirmation of the cancelled run: %d %v", st, b)
		}
		// and a confirmed run: the cancel takes what was left of it
		r2 := newRunsRig(t, r.windows).trusted()
		r2.arm(hRunA)
		if st, b := r2.confirm(hRunA, "42-bbbbbbb", 30, 1500); st != 200 {
			t.Fatalf("go: %d %v", st, b)
		}
		if st, b := r2.post("/power", map[string]any{"action": "cancel"}); st != 200 {
			t.Fatalf("cancel: %d %v", st, b)
		}
		st, b = r2.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA})
		wantRefusal(t, "the run's shutdown after a cancel", st, b, 403, api.CodeApprovalRequired)
		st, b = r2.post("/update", map[string]any{"run": hRunA})
		wantRefusal(t, "the run's update after a cancel", st, b, 403, api.CodeApprovalRequired)
	})
}

// A request alone arms nothing and confirms nothing: the control token is not enough for either route.
func TestRunRoutesNeedAPasskeyToken(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		// without trust: the routes say that approval is off, and the machine's part of a run needs nothing
		st, b := r.post(api.PathRunArm, map[string]any{"approval": r.ticket(hRunA, 160*time.Second)})
		if st != 409 || b["code"] != api.CodeApprovalOff {
			t.Errorf("arm without trust: %d %v", st, b)
		}
		st, b = r.post(api.PathRunGo, map[string]any{"run": hRunA, "to": "-", "shutdown_delay_s": 30, "within_s": 300, "approval": r.ticket(hRunA, 0)})
		if st != 409 || b["code"] != api.CodeApprovalOff {
			t.Errorf("go without trust: %d %v", st, b)
		}
		if st, b := r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA}); st != 200 {
			t.Errorf("a shutdown that names a run, without trust: %d %v", st, b)
		}
		r.post("/power", map[string]any{"action": "cancel"})
		r.trusted()
		before := len(r.exec.Scheduled)
		good := r.ticket(hRunA, 160*time.Second)
		cut := *good
		cut.Token = cut.Token[:strings.LastIndex(cut.Token, ".")+1] + strings.Repeat("A", 342)
		for name, c := range map[string]struct {
			path   string
			body   any
			status int
		}{
			"arm, an empty body":                  {api.PathRunArm, map[string]any{}, 400},
			"arm, no body":                        {api.PathRunArm, nil, 400},
			"arm, a member it does not take":      {api.PathRunArm, map[string]any{"approval": good, "run": hRunA}, 400},
			"arm, run and numbers and no token":   {api.PathRunArm, map[string]any{"run": hRunA, "wait_s": 120}, 400},
			"arm, an approval without a token":    {api.PathRunArm, map[string]any{"approval": map[string]any{"token": "", "entries": good.Entries}}, 403},
			"arm, a token with another signature": {api.PathRunArm, map[string]any{"approval": cut}, 403},
			"go, no approval":                     {api.PathRunGo, map[string]any{"run": hRunA, "to": "-", "shutdown_delay_s": 30, "within_s": 300}, 403},
			"go, the ticket as its approval":      {api.PathRunGo, map[string]any{"run": hRunA, "to": "-", "shutdown_delay_s": 30, "within_s": 300, "approval": good}, 403},
			"go, a delay outside the limits":      {api.PathRunGo, map[string]any{"run": hRunA, "to": "-", "shutdown_delay_s": 5, "within_s": 300, "approval": good}, 400},
			"go, no numbers":                      {api.PathRunGo, map[string]any{"run": hRunA, "to": "-", "approval": good}, 400},
		} {
			st, b := r.post(c.path, c.body)
			if st != c.status || b["error"] == nil {
				t.Errorf("%s: %d %v, want %d", name, st, b, c.status)
			}
		}
		// the read token is no token for these routes; no token is none
		for _, tok := range []string{readTok, ""} {
			if st, _ := do(t, r.base, "POST", api.PathRunArm, tok, map[string]any{"approval": good}); st != 401 {
				t.Errorf("arm with token %q: %d", tok, st)
			}
		}
		r.pass(2000 * time.Second)
		if r.block()["run"] != nil || len(r.exec.Scheduled) != before {
			t.Fatalf("something was armed: %v, %v", r.block()["run"], r.exec.Scheduled)
		}
		r.nothingOfARunOnRecord("after refusals only")
	})
}

// The confirmation named one version. The newest signed release is another: nothing is downloaded and nothing
// installed, and the run's one update is spent.
func TestRunUpdateInstallsOnlyTheVersionConfirmed(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		r.trusted()
		r.arm(hRunA)
		if st, b := r.confirm(hRunA, "43-ccccccc", 30, 1500); st != 200 {
			t.Fatalf("go: %d %v", st, b)
		}
		if st, b := r.post("/update", map[string]any{"run": hRunA}); st != 202 {
			t.Fatalf("update: %d %v", st, b)
		}
		us := r.updateDone()
		if us.State != "failed" || !strings.Contains(us.Message, "42-bbbbbbb") || !strings.Contains(us.Message, "43-ccccccc") {
			t.Errorf("status %+v", us)
		}
		if r.starts() != 0 || r.gh.Downloads("fairy-agent-linux-amd64") != 0 {
			t.Fatalf("%d installer starts, %d downloads", r.starts(), r.gh.Downloads("fairy-agent-linux-amd64"))
		}
		// "-": no update at all
		r2 := newRunsRig(t, r.windows).trusted()
		r2.arm(hRunA)
		if st, b := r2.confirm(hRunA, "-", 30, 1500); st != 200 {
			t.Fatalf("go: %d %v", st, b)
		}
		st, b := r2.post("/update", map[string]any{"run": hRunA})
		wantRefusal(t, "the update of a run that named none", st, b, 403, api.CodeApprovalRequired)
		if st, b := r2.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA}); st != 200 {
			t.Errorf("its shutdown: %d %v", st, b)
		}
	})
}

// A panel that knows nothing of runs sees the machine it saw before: the same answers to the same requests,
// with the check off and with it on, and nothing of a run in any of them but the two new members of the block.
func TestOldPanelSeesNoDifference(t *testing.T) {
	bothKinds(t, func(t *testing.T, r *rrig) {
		if st, b := r.post("/power", map[string]any{"action": "shutdown", "delay_s": 60}); st != 200 || b["pending"] == nil {
			t.Fatalf("shutdown without trust: %d %v", st, b)
		}
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
			t.Fatalf("cancel without trust: %d %v", st, b)
		}
		r.trusted()
		st, b := r.post("/power", map[string]any{"action": "shutdown", "delay_s": 60})
		wantRefusal(t, "shutdown", st, b, 403, api.CodeApprovalRequired)
		if b["reason"] != nil {
			t.Errorf("an old refusal has a reason member: %v", b)
		}
		st, b = r.post("/update", map[string]any{})
		wantRefusal(t, "update", st, b, 403, api.CodeApprovalRequired)
		if st, b := r.post("/power", map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil || len(b) != 2 {
			t.Fatalf("cancel with nothing pending: %d %v", st, b)
		}
		if r.exec.Cancels != 1 { // the one of the shutdown above, and none for a cancel with nothing pending
			t.Errorf("%d cancels reached the system", r.exec.Cancels)
		}
		st, c := r.post(api.PathApprovalChallenge, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
		if st != 200 || c["needed"] != true {
			t.Fatalf("challenge: %d %v", st, c)
		}
		ap := r.iss.Approve(r.clock(), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: c["challenge"].(string), Request: c["request"].(string)})
		if st, b := r.post("/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": ap}); st != 200 {
			t.Fatalf("approved shutdown: %d %v", st, b)
		}
		blk := r.block()
		for k := range blk {
			if !strings.Contains(" state enforced_by proto machine_id issuer client_id keys users trust_hash set_by set_at fan_window_s boot_shutdown_s runs ", " "+k+" ") {
				t.Errorf("member %q in the approval block", k)
			}
		}
		if blk["proto"] != float64(2) || blk["runs"] != float64(1) {
			t.Errorf("block %v", blk)
		}
		r.pass(3 * time.Hour)
		r.nothingOfARunOnRecord("on a machine no ticket reached")
	})
}

// The update restarts the helper (Windows) or the agent's gate is rebuilt (the test's stand-in for both): what
// was left of the confirmation is what is left, exactly.
func TestRunSurvivesTheHelperRestartOverHTTP(t *testing.T) {
	r := newRunsRig(t, true).trusted()
	r.arm(hRunA)
	if st, b := r.confirm(hRunA, "42-bbbbbbb", 30, 1500); st != 200 {
		t.Fatalf("go: %d %v", st, b)
	}
	if st, b := r.post("/update", map[string]any{"run": hRunA}); st != 202 {
		t.Fatalf("update: %d %v", st, b)
	}
	r.updateDone()
	r.startChecker(true) // the installer restarted the helper
	r.pass(60 * time.Second)
	st, b := r.post("/update", map[string]any{"run": hRunA})
	wantRefusal(t, "a second update after the restart", st, b, 403, api.CodeApprovalRequired)
	if st, b := r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA}); st != 200 {
		t.Fatalf("the shutdown after the restart: %d %v", st, b)
	}
	r.startChecker(true)
	st, b = r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA})
	if st == 200 {
		t.Fatalf("a second shutdown after another restart: %v", b)
	}
	if len(r.exec.Scheduled) != 1 || r.helperStarts.Load() != 1 {
		t.Fatalf("scheduled %v, %d installer starts", r.exec.Scheduled, r.helperStarts.Load())
	}
}

// A helper from before runs behind an agent of this version (the update has not restarted it yet): the block
// has no "runs", the two routes say so, and a request that names a run is answered like one without approval.
func TestRunWithAHelperFromBeforeRuns(t *testing.T) {
	r := newRunsRig(t, true)
	r.startChecker(false)
	r.trusted()
	// the agent asks the helper's status again all the time; until it has, it shows what the helper before said
	var blk map[string]any
	for i := 0; i < 500; i++ {
		if blk = r.block(); blk["runs"] == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if blk["runs"] != nil || blk["run"] != nil {
		t.Fatalf("block %v", blk)
	}
	st, b := r.post(api.PathRunArm, map[string]any{"approval": r.ticket(hRunA, 160*time.Second)})
	if st != 409 || b["code"] != api.CodeHelperTooOld {
		t.Errorf("arm: %d %v", st, b)
	}
	st, b = r.post(api.PathApprovalChallenge, map[string]any{"verb": api.ApproveRunGo, "run": hRunA, "to": "-", "shutdown_delay_s": 30, "within_s": 300})
	if st != 409 || b["code"] != api.CodeHelperTooOld {
		t.Errorf("challenge for run_go: %d %v", st, b)
	}
	st, b = r.post("/power", map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA})
	wantRefusal(t, "a shutdown that names a run", st, b, 403, api.CodeApprovalRequired)
	if len(r.exec.Scheduled) != 0 {
		t.Fatalf("scheduled %v", r.exec.Scheduled)
	}
}

// A guest runs on the node when the wait is over: it stays on.
func TestRunSelfOffNeverWithAGuest(t *testing.T) {
	r := newRunsRig(t, false).trusted()
	r.arm(hRunA)
	r.guests.Store(true)
	r.pass(1000 * time.Second)
	if len(r.exec.Scheduled) != 0 {
		t.Fatalf("scheduled %v", r.exec.Scheduled)
	}
	r.runIs(api.RunCancelled)
}

// Windows without the helper, and every machine whose agent keeps no runs: the routes say so, nothing is armed.
func TestRunRoutesOnAnAgentThatKeepsNoRuns(t *testing.T) {
	cfg, err := agent.Parse([]byte("power_control: {enabled: true}\n"), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	iss := approvaltest.New()
	files := approval.Files{Path: filepath.Join(t.TempDir(), approval.TrustFileName)}
	gate := approval.NewGate(approval.Options{EnforcedBy: api.EnforcedByAgent, Files: files, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	exec := &agenttest.PowerExec{}
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok},
		agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Approval: gate, Power: agent.NewPower(exec, 10)}).Handler())
	defer srv.Close()
	if st, b := do(t, srv.URL, "POST", api.PathApprovalTrust, ctlTok, provenTrust(t, srv.URL, iss, iss.Init())); st != 200 {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	_, m := do(t, srv.URL, "GET", "/metrics", readTok, nil)
	if ap := m["approval"].(map[string]any); ap["runs"] != nil {
		t.Errorf("block %v", ap)
	}
	r := &rrig{t: t, iss: iss, now: time.Now()}
	st, b := do(t, srv.URL, "POST", api.PathRunArm, ctlTok, map[string]any{"approval": r.ticket(hRunA, 160*time.Second)})
	if st != 404 || b["code"] != api.CodeApprovalDisabled {
		t.Errorf("arm: %d %v", st, b)
	}
	st, b = do(t, srv.URL, "POST", api.PathApprovalChallenge, ctlTok, map[string]any{"verb": api.ApproveRunGo, "run": hRunA, "to": "-", "shutdown_delay_s": 30, "within_s": 300})
	if st != 404 || b["code"] != api.CodeApprovalDisabled {
		t.Errorf("challenge for run_go: %d %v", st, b)
	}
	st, b = do(t, srv.URL, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 30, "run": hRunA})
	wantRefusal(t, "a shutdown that names a run", st, b, 403, api.CodeApprovalRequired)
}

// The answer to a challenge request with a verb nobody knows is what v0.8.0 answered, byte for byte: a panel
// (or a person) that knows that sentence still gets it. The two verbs of a run are not in it: run_go is a verb
// that is known and answered, and run_arm has an answer of its own.
func TestUnknownChallengeVerbAnswersAsBefore(t *testing.T) {
	const v080 = `{"error":"not a request that can be approved: verb must be fan_set, fan_mode, power, apply_update or trust_set"}`
	bothKinds(t, func(t *testing.T, r *rrig) {
		for _, trusted := range []bool{false, true} {
			if trusted {
				r.trusted()
			}
			for _, body := range []string{`{"verb":"format_disk"}`, `{"verb":""}`, `{}`, `{"verb":"RUN_GO"}`, `{"verb":"run"}`} {
				st, b := rawPost(t, r.base, api.PathApprovalChallenge, ctlTok, body)
				if st != 400 || strings.TrimSpace(b) != v080 {
					t.Errorf("trust set %v, %s: %d %s", trusted, body, st, b)
				}
			}
		}
	})
}

func rawPost(t *testing.T, base, path, tok, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("POST", base+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
