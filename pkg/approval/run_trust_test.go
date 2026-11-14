package approval_test

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// changeTrust writes a trust file that differs from the one in place (in life: a user is taken off the list
// of those whose passkey counts, or the key is changed).
func changeTrust(t *testing.T, r *runRig) {
	t.Helper()
	tr := trustOf(t, r.files)
	w := 0
	if tr.FanWindowS != nil && *tr.FanWindowS == 0 {
		w = 60
	}
	tr.FanWindowS = &w
	nt, err := approval.NewTrust(*tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.files.Replace(nt); err != nil {
		t.Fatal(err)
	}
}

// A changed trust ends a live run. That held only inside the service that was running: a run was tied to the
// trust it was accepted under by a count in memory. A service that started again before it had looked at the
// changed file (it looks every five seconds; POST /helper/stop and /helper/start need the control token and
// no approval), or that was not running when the trust was changed, took the run over under the NEW trust,
// and the run's update and shutdown were let through for a passkey that may just have been taken off the
// list (second review of the runs, U2). The record now names the trust the run was accepted under, and a run
// under another trust is ended when it is found: the machine stays on, as after a cancel.
func TestRunDoesNotSurviveAChangedTrustOverARestartOfTheService(t *testing.T) {
	for _, state := range []string{api.RunArmed, api.RunOffPending, api.RunConfirmed} {
		for _, stopped := range []bool{false, true} {
			r := newRunRig(t)
			r.armed(runA)
			switch state {
			case api.RunOffPending:
				r.ticks(961 * time.Second)
				if len(r.scheduled) != 1 || r.state() != api.RunOffPending {
					t.Fatalf("no countdown: %v %q", r.scheduled, r.state())
				}
			case api.RunConfirmed:
				if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1800)); ref != nil {
					t.Fatal(ref)
				}
			}
			if stopped {
				r.g.RunStop()
			}
			changeTrust(t, r)
			r.restart() // before the service that was running looked at the file again, or after it was stopped
			cancels := r.cancels
			r.w.Tick()
			if st := r.state(); st != api.RunCancelled {
				t.Errorf("%s (service stopped first: %v): after a change of the trust and a start of the service the run is %q", state, stopped, st)
			}
			for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
				if _, ref := r.g.AdmitRun(req, runA); ref == nil {
					t.Errorf("%s (service stopped first: %v): %s of the run let through under a trust it was not accepted under", state, stopped, req.Verb)
				}
			}
			if state == api.RunOffPending && r.cancels != cancels+1 {
				t.Errorf("the countdown of the run that ended was not stopped (%d cancels)", r.cancels-cancels)
			}
			n := len(r.scheduled)
			r.ticks(1200 * time.Second)
			if len(r.scheduled) != n {
				t.Errorf("%s (service stopped first: %v): switched itself off: %+v", state, stopped, r.scheduled[n:])
			}
			if v := r.files.RunShow(); v.ID != "" || v.LastState != api.RunCancelled {
				t.Errorf("%s: the record: %+v", state, v)
			}
			// the boot is closed, as after a cancel
			_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
			if ref == nil {
				t.Errorf("%s: a ticket in the boot of a run that a changed trust ended", state)
			}
		}
	}
}

// The same trust: the run is taken over as before (the helper restarts in the middle of every run that
// updates it).
func TestRunIsTakenOverUnderTheTrustItWasAcceptedUnder(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1800)); ref != nil {
		t.Fatal(ref)
	}
	if to, ref := r.g.AdmitRun(update, runA); ref != nil || to != "19-abc" {
		t.Fatal(to, ref)
	}
	r.restart()
	r.ticks(10 * time.Second)
	if st := r.state(); st != api.RunConfirmed {
		t.Fatalf("after a restart of the service with the trust as it was: %q", st)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref != nil {
		t.Fatalf("the run's shutdown after the restart: %v", ref)
	}
}

// What the record says of the trust is one of this program's values or the record is not believed; and a
// live run that names no trust at all (a record written by a build from before this) is ended, not taken over.
func TestRunRecordNamesTheTrustOfItsRun(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	raw := r.record(t)
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	run := rec["run"].(map[string]any)
	if tr, _ := run["trust"].(string); len(tr) != 64 {
		t.Fatalf("the live run in the record names no trust: %s", raw)
	}
	write := func(v any) {
		t.Helper()
		run["trust"] = v
		if v == nil {
			delete(run, "trust")
		}
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(r.files.RunPath(), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	good := run["trust"].(string)
	for _, bad := range []any{"abc", good[:63], good + "0", "G" + good[1:], "A" + good[1:], 7} {
		write(bad)
		if _, err := r.files.RunRecordCheck(); err == nil {
			t.Errorf("a record whose run names the trust %v is believed", bad)
		}
	}
	write(nil)
	if _, err := r.files.RunRecordCheck(); err != nil {
		t.Fatalf("a record whose run names no trust cannot be read at all: %v", err)
	}
	r.restart()
	r.w.Tick()
	if st := r.state(); st != api.RunCancelled {
		t.Errorf("a live run that names no trust is %q after a start of the service", st)
	}
	r.ticks(1200 * time.Second)
	if len(r.scheduled) != 0 {
		t.Errorf("switched itself off: %+v", r.scheduled)
	}
}

// The Windows agent's own look (a gate that only reads the helper's files) does not see a run under a trust
// it was not accepted under either.
func TestGateThatOnlyReadsSeesNoRunUnderAChangedTrust(t *testing.T) {
	r := newRunRig(t)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1800)); ref != nil {
		t.Fatal(ref)
	}
	r.readOnly = true
	r.restart()
	if to, ref := r.g.RunCovers(update, runA); ref != nil || to != "19-abc" {
		t.Fatalf("the look under the trust of the run: %q %v", to, ref)
	}
	changeTrust(t, r)
	r.restart()
	if _, ref := r.g.RunCovers(update, runA); ref == nil {
		t.Error("the look sees the run under a changed trust")
	}
}
