package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

const cmdRun = "00000000000000c3"

// runCmdRig is trustRig with a service on the same folder: a gate that keeps runs and its watch, on a machine
// that has been up for 100 s.
type runCmdRig struct {
	*trustRig
	g     *approval.Gate
	w     *approval.RunWatch
	offs  int
	stops int
	now   time.Time
}

func newRunCmdRig(t *testing.T) *runCmdRig {
	t.Helper()
	r := &runCmdRig{trustRig: newTrustRig(t), now: time.Now()}
	old, oldBoot := runUptime, runBootID
	runUptime = func() (time.Duration, error) { return 100 * time.Second, nil }
	runBootID = func() (string, error) { return "boot-1", nil }
	t.Cleanup(func() { runUptime, runBootID = old, oldBoot })
	r.g = approval.NewGate(approval.Options{Files: r.files, EnforcedBy: api.EnforcedByAgent, Runs: true,
		Now: func() time.Time { return r.now }, Uptime: runUptime, BootID: func() (string, error) { return "boot-1", nil },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	r.w = approval.NewRunWatch(r.g, approval.RunHooks{
		Shutdown: func(time.Duration, string, string) error { r.offs++; return nil },
		Cancel:   func() error { r.stops++; return nil }})
	iss := approvaltest.New()
	in := iss.Init()
	c, ref := r.g.Challenge(api.TrustSetRequest(in))
	if ref != nil {
		t.Fatal(ref)
	}
	if _, ref := r.g.Init(iss.Prove(r.now, in, api.MachineEntry{MachineID: in.MachineID, Challenge: c.Challenge, Request: c.Request})); ref != nil {
		t.Fatal(ref)
	}
	return r
}

func (r *runCmdRig) arm(t *testing.T) {
	t.Helper()
	var b [32]byte
	rand.Read(b[:])
	run, valid, wait, notice := cmdRun, 420, 960, 120
	text, _ := (api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}).Canonical()
	if !r.files.RunShow().Exists { // the record this machine has from a boot before (one made now would close this boot)
		if err := approvaltest.EarlierBoot(r.files, r.now.Add(-24*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	ap := approvaltest.New().Approve(r.now.Add(-200*time.Second), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: approvaltest.B64(b[:]), Request: text})
	if _, ref := r.w.Arm(ap); ref != nil {
		t.Fatal(ref)
	}
}

func (r *runCmdRig) cmd(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := helperRunCmd(append(args, "--config", r.cfg), &out, &errb)
	return code, out.String(), errb.String()
}

func (r *runCmdRig) runPath() string {
	return filepath.Join(filepath.Dir(r.files.Path), approval.RunFileName)
}

func TestHelperRunShowAndCancel(t *testing.T) {
	r := newRunCmdRig(t)
	for _, args := range [][]string{{}, {"arm"}, {"show", "extra"}} {
		var out, errb bytes.Buffer
		if code := helperRunCmd(args, &out, &errb); code != 2 || !strings.Contains(errb.String(), "fairy-agent helper-run cancel") {
			t.Errorf("helper-run %v: %d %q", args, code, errb.String())
		}
	}
	if code, out, _ := r.cmd("show"); code != 0 || !strings.Contains(out, "none (no record)") || !strings.Contains(out, r.runPath()) {
		t.Fatalf("show without a record: %d\n%s", code, out)
	}
	// cancel without a run changes nothing and makes no record
	if code, out, _ := r.cmd("cancel"); code != 0 || !strings.Contains(out, "nothing changed") {
		t.Fatalf("cancel without a record: %d\n%s", code, out)
	}
	if _, err := os.Lstat(r.runPath()); err == nil {
		t.Fatal("cancel made a record")
	}
	r.arm(t)
	code, out, _ := r.cmd("show")
	if code != 0 || !strings.Contains(out, cmdRun+", armed: this machine switches itself off in 16m0s") || !strings.Contains(out, "signed by:       neptune") {
		t.Fatalf("show, armed: %d\n%s", code, out)
	}
	// cancel is the administrator's
	trustIsAdmin = func() bool { return false }
	if code, _, errs := r.cmd("cancel"); code != 1 || !strings.Contains(errs, "root") {
		t.Fatalf("cancel as somebody else: %d %s", code, errs)
	}
	if code, _, _ := r.cmd("show"); code != 0 {
		t.Errorf("show as somebody else: %d", code)
	}
	trustIsAdmin = func() bool { return true }
	if r.g.Status().Run == nil || r.g.Status().Run.State != api.RunArmed {
		t.Fatal("the refused cancel changed something")
	}
	code, out, _ = r.cmd("cancel")
	if code != 0 || !strings.Contains(out, "run "+cmdRun+" (was armed) is cancelled on this machine") {
		t.Fatalf("cancel: %d\n%s", code, out)
	}
	r.w.Tick() // the service's look, within a second
	if st := r.g.Status().Run; st == nil || st.State != api.RunCancelled {
		t.Fatalf("the service after the cancel: %+v", st)
	}
	if code, out, _ := r.cmd("show"); code != 0 || !strings.Contains(out, "none is armed or confirmed") || !strings.Contains(out, "last run:        "+cmdRun+", cancelled") {
		t.Fatalf("show after the cancel: %d\n%s", code, out)
	}
	if code, out, _ := r.cmd("cancel"); code != 0 || !strings.Contains(out, "nothing changed") {
		t.Fatalf("a second cancel: %d\n%s", code, out)
	}
	if r.offs != 0 || r.stops != 0 {
		t.Errorf("%d self-offs, %d stops", r.offs, r.stops)
	}
}

// A record that cannot be read: show says so and what it means, cancel puts a new one in its place, which
// takes no ticket in this boot.
func TestHelperRunWithARecordThatCannotBeRead(t *testing.T) {
	r := newRunCmdRig(t)
	if err := os.WriteFile(r.runPath(), []byte(`{"version":1,"run":{"state":"armed"`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := r.cmd("show"); code != 0 || !strings.Contains(out, "the record cannot be used") || !strings.Contains(out, "fairy-agent helper-run cancel") {
		t.Fatalf("show: %d\n%s", code, out)
	}
	code, out, _ := r.cmd("cancel")
	if code != 0 || !strings.Contains(out, "was replaced by a new one") || !strings.Contains(out, "no ticket arms this machine until it has been started anew") {
		t.Fatalf("cancel: %d\n%s", code, out)
	}
	if v := r.files.RunShow(); !v.Exists || v.Err != nil || v.Born == 0 || v.ID != "" {
		t.Fatalf("after cancel: %+v", v)
	}
	if code, out, _ := r.cmd("show"); code != 0 || strings.Contains(out, "cannot be used") {
		t.Fatalf("show after cancel: %d\n%s", code, out)
	}
	// the service takes no ticket in this boot: the new record is marked with the boot the command read
	var b [32]byte
	rand.Read(b[:])
	run, valid, wait, notice := cmdRun, 420, 960, 120
	text, _ := (api.ApprovalRequest{Verb: api.ApproveRunArm, Run: &run, ValidS: &valid, WaitS: &wait, NoticeS: &notice}).Canonical()
	r.now = r.now.Add(5 * time.Second)
	ap := approvaltest.New().Approve(r.now.Add(-time.Second), api.MachineEntry{MachineID: approvaltest.MachineID, Challenge: approvaltest.B64(b[:]), Request: text})
	if _, ref := r.w.Arm(ap); ref == nil {
		t.Fatal("a ticket armed the machine in the boot in which the record was made anew")
	}
}

func TestUsageNamesHelperRun(t *testing.T) {
	if !strings.Contains(usage, "fairy-agent helper-run show | cancel") {
		t.Error("the usage text does not name helper-run")
	}
}
