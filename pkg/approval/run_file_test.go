package approval_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// record is the run record as it is on disk.
func (r *runRig) record(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(r.files.RunPath())
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The record is one plain file next to the trust file, written whole under another name and then renamed,
// readable and writable by its owner only, and it holds what the machine needs and no token.
func TestRunRecordFile(t *testing.T) {
	r := newRunRig(t)
	r.armed(runA)
	dir := filepath.Dir(r.files.Path)
	if r.files.RunPath() != filepath.Join(dir, approval.RunFileName) || approval.RunFileName != "approval-run.json" {
		t.Fatalf("path %s", r.files.RunPath())
	}
	st, err := os.Lstat(r.files.RunPath())
	if err != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 {
		t.Fatalf("the record: %v, %v", st, err)
	}
	if _, err := r.confirm(goReq(runA, "19-abc", 30, 1500)); err != nil {
		t.Fatal(err)
	}
	r.g.AdmitRun(update, runA)
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp") {
			t.Errorf("a temporary file was left: %s", e.Name())
		}
	}
	var m map[string]any
	if err := json.Unmarshal(r.record(t), &m); err != nil {
		t.Fatal(err)
	}
	for k := range m {
		if !strings.Contains(" version at arm used last run clock ", " "+k+" ") {
			t.Errorf("member %q in the record", k)
		}
	}
	live, _ := m["run"].(map[string]any)
	for k := range live {
		if !strings.Contains(" id state sub name kid go_up_ms within_s to shutdown_delay_s update shutdown ", " "+k+" ") {
			t.Errorf("member %q in the live run", k)
		}
	}
	if live["update"] != nil || live["shutdown"] != float64(1) || live["to"] != "19-abc" {
		t.Errorf("after the update: %v", live)
	}
	r.noTokenAnywhere(t)
	// used up: the live run is taken out of the file, the mark stays
	r.g.AdmitRun(power("shutdown", 30), runA)
	m = nil
	json.Unmarshal(r.record(t), &m)
	if m["run"] != nil || m["last"] == nil || m["used"] == nil || m["arm"] == nil {
		t.Errorf("after the shutdown: %s", r.record(t))
	}
	// cancelled: the same
	r = newRunRig(t)
	r.armed(runA)
	r.w.Cancel("test")
	if rec := string(r.record(t)); strings.Contains(rec, `"run"`) || !strings.Contains(rec, `"state":"cancelled"`) {
		t.Errorf("after the cancel: %s", rec)
	}
	// the next boot: the same, written at the first look of the service
	r = newRunRig(t)
	r.armed(runA)
	r.reboot(time.Hour, 30*time.Second)
	r.w.Tick()
	if rec := string(r.record(t)); strings.Contains(rec, `"run"`) || strings.Contains(rec, `"last"`) || !strings.Contains(rec, runA) {
		t.Errorf("in the next boot: %s", rec)
	}
}

// A record that cannot be believed counts as no record: nothing is armed, nothing of a run is let through.
// It is said in the log. And no ticket and no confirmation is taken until an administrator removed it, because
// what it remembered (this boot, the runs that were used) cannot be read either.
func TestRunRecordThatCannotBeUsed(t *testing.T) {
	good := func(t *testing.T) (*runRig, []byte) { // a machine with a confirmed run, and its record
		r := newRunRig(t)
		r.armed(runA)
		if _, ref := r.confirm(goReq(runA, "19-abc", 30, 3600)); ref != nil {
			t.Fatal(ref)
		}
		return r, r.record(t)
	}
	replace := func(b []byte, old, new string) []byte {
		if !bytes.Contains(b, []byte(old)) {
			panic("no " + old + " in " + string(b))
		}
		return bytes.Replace(b, []byte(old), []byte(new), 1)
	}
	for name, damage := range map[string]func(t *testing.T, r *runRig, rec []byte){
		"not JSON": func(t *testing.T, r *runRig, rec []byte) { os.WriteFile(r.files.RunPath(), rec[:len(rec)/2], 0o600) },
		"empty":    func(t *testing.T, r *runRig, rec []byte) { os.WriteFile(r.files.RunPath(), nil, 0o600) },
		"an unknown member": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `{"version":1,`, `{"version":1,"token":"x",`), 0o600)
		},
		"a member twice": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `{"version":1,`, `{"version":1,"version":1,`), 0o600)
		},
		"another version": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `{"version":1,`, `{"version":2,`), 0o600)
		},
		"two updates left": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `"update":1`, `"update":2`), 0o600)
		},
		"a delay of 0": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `"shutdown_delay_s":30`, `"shutdown_delay_s":0`), 0o600)
		},
		"within_s of a day": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `"within_s":3600`, `"within_s":86400`), 0o600)
		},
		"a state it has not": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `"state":"confirmed"`, `"state":"always"`), 0o600)
		},
		"a run id that is none": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), replace(rec, `"id":"`+runA, `"id":"`+strings.ToUpper(runA)), 0o600)
		},
		"too large": func(t *testing.T, r *runRig, rec []byte) {
			os.WriteFile(r.files.RunPath(), append(rec, bytes.Repeat([]byte(" "), approval.MaxRunFile)...), 0o600)
		},
		"a link to a good record": func(t *testing.T, r *runRig, rec []byte) {
			elsewhere := filepath.Join(t.TempDir(), "record.json")
			os.WriteFile(elsewhere, rec, 0o600)
			os.Remove(r.files.RunPath())
			if err := os.Symlink(elsewhere, r.files.RunPath()); err != nil {
				t.Fatal(err)
			}
		},
		"a folder": func(t *testing.T, r *runRig, rec []byte) {
			os.Remove(r.files.RunPath())
			os.Mkdir(r.files.RunPath(), 0o700)
		},
		"the file check refuses it (another owner)": func(t *testing.T, r *runRig, rec []byte) {
			r.files.CheckFile = func(path string) error {
				if path == r.files.RunPath() {
					return errors.New("belongs to user 4242")
				}
				return nil
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, rec := good(t)
			damage(t, r, rec)
			r.restart()
			if exists, err := r.files.RunRecordCheck(); !exists || err == nil {
				t.Fatalf("the damaged record reads: %v, %v", exists, err)
			}
			if run := r.run(); run != nil {
				t.Errorf("run block %+v", run)
			}
			for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
				if _, ref := r.g.RunCovers(req, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
					t.Errorf("%s was let through: %v", req.Verb, ref)
				}
				if _, ref := r.g.AdmitRun(req, runA); ref == nil || ref.Code != api.CodeApprovalRequired {
					t.Errorf("%s was let through: %v", req.Verb, ref)
				}
			}
			r.ticks(3 * time.Second)
			if n := strings.Count(r.log.String(), "the run record cannot be used"); n != 1 {
				t.Errorf("said %d times in the log, want once", n)
			}
			_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
			runRefused(t, "a ticket", ref, 503, api.CodeRunUnavailable, "")
			_, ref = r.confirm(goReq(runB, "19-abc", 30, 1500))
			runRefused(t, "a confirmation", ref, 503, api.CodeRunUnavailable, "")
			// the administrator's command removes it (a link itself, not what it points to), and runs work again
			was, changed, err := r.files.RunCancel()
			if err != nil || !changed || was.Err == nil {
				t.Fatalf("helper-run cancel: %+v, %v, %v", was, changed, err)
			}
			if exists, _ := r.files.RunRecordCheck(); exists {
				t.Fatal("still there")
			}
			if _, ref := r.confirm(goReq(runB, "19-abc", 30, 1500)); ref != nil {
				t.Errorf("a confirmation after the repair: %v", ref)
			}
		})
	}
}

// The link is not followed for writing either: a record that is written replaces whatever has its name.
func TestRunRecordWriteReplacesALink(t *testing.T) {
	r := newRunRig(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.armed(runA)
	rec := r.record(t)
	os.Remove(r.files.RunPath())
	if err := os.Symlink(target, r.files.RunPath()); err != nil {
		t.Fatal(err)
	}
	r.w.Cancel("test") // this process still knows the run, and writes that it is over
	r.w.Tick()
	if b, _ := os.ReadFile(target); string(b) != "untouched" {
		t.Errorf("the link was followed: %q", b)
	}
	_ = rec
}

// Writing comes first. A ticket, a confirmation, an update or a shutdown of a run that cannot be written
// down is refused; a cancel that cannot be written down is said to have failed, holds for the running
// service all the same, and is written at the next step.
func TestRunRecordIsWrittenBeforeTheAnswer(t *testing.T) {
	fail := errors.New("the disk is full")
	broken := func(r *runRig, on bool) {
		if on {
			r.files.Prepare = func(string) error { return fail }
		} else {
			r.files.Prepare = nil
		}
		// the gate holds its own copy of Files: a new gate, with what the old one knew read from the record
		r.restart()
	}
	// the ticket
	r := newRunRig(t)
	ticket := r.ticket(runA, 160*time.Second)
	broken(r, true)
	_, ref := r.w.Arm(ticket)
	runRefused(t, "a ticket that cannot be written down", ref, 503, api.CodeRunUnavailable, "")
	r.ticks(1000 * time.Second)
	if len(r.scheduled) != 0 || r.run() != nil {
		t.Fatalf("armed without a record: %+v", r.scheduled)
	}
	if r.touched() {
		t.Fatal("something of the ticket is in the record")
	}
	// nothing was used up by it
	r = newRunRig(t)
	ticket = r.ticket(runA, 160*time.Second)
	broken(r, true)
	r.w.Arm(ticket)
	broken(r, false)
	if _, ref := r.w.Arm(ticket); ref != nil {
		t.Errorf("the ticket once it can be written down: %v", ref)
	}
	// the confirmation: refused, and the run that was armed stays armed
	broken(r, true)
	_, ref = r.confirm(goReq(runA, "19-abc", 30, 1500))
	runRefused(t, "a confirmation that cannot be written down", ref, 503, api.CodeRunUnavailable, "")
	if r.state() != api.RunArmed {
		t.Fatalf("state %s", r.state())
	}
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Fatal("an update after a confirmation that was not written down")
	}
	// the self-off: not scheduled while "it is counting down" cannot be written down
	r.ticks(1000 * time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("scheduled without a record of it: %+v", r.scheduled)
	}
	broken(r, false)
	r.ticks(2 * time.Second)
	if len(r.scheduled) != 1 {
		t.Fatalf("scheduled once it can be written down: %+v", r.scheduled)
	}
	// the update and the shutdown of a confirmed run
	r = newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	broken(r, true)
	if _, ref := r.g.AdmitRun(update, runA); ref == nil || ref.Status != 503 {
		t.Fatalf("an update that cannot be written down: %v", ref)
	}
	if _, ref := r.g.AdmitRun(power("shutdown", 30), runA); ref == nil || ref.Status != 503 {
		t.Fatalf("a shutdown that cannot be written down: %v", ref)
	}
	// the cancel
	r = newRunRig(t)
	r.armed(runA)
	broken(r, true)
	was, err := r.w.Cancel("test")
	if was != api.RunArmed || err == nil {
		t.Fatalf("a cancel that cannot be written down: %q, %v", was, err)
	}
	r.ticks(1000 * time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("the cancelled run switched the machine off: %+v", r.scheduled)
	}
}

// `fairy-agent helper-run cancel` on the machine: the run is over within one look of the service, a
// countdown that is running is stopped by the service, and nothing arms again. It never makes a record.
func TestRunCancelOnTheMachine(t *testing.T) {
	r := newRunRig(t)
	if was, changed, err := r.files.RunCancel(); changed || err != nil || was.Exists {
		t.Fatalf("cancel without a record: %+v, %v, %v", was, changed, err)
	}
	if exists, _ := r.files.RunRecordCheck(); exists {
		t.Fatal("the command made a record")
	}
	r.armed(runA)
	r.ticks(10 * time.Second)
	if v := r.files.RunShow(); v.ID != runA || v.State != api.RunArmed || v.UpMS != 1020_000 || v.Name != "neptune" || v.Err != nil {
		t.Fatalf("show: %+v", v)
	}
	was, changed, err := r.files.RunCancel()
	if err != nil || !changed || was.ID != runA || was.State != api.RunArmed {
		t.Fatalf("cancel: %+v, %v, %v", was, changed, err)
	}
	r.w.Tick()
	if r.state() != api.RunCancelled || r.cancels != 0 {
		t.Fatalf("after the command: %s, %d", r.state(), r.cancels)
	}
	if _, changed, _ := r.files.RunCancel(); changed {
		t.Error("a second cancel changed the record")
	}
	_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
	runRefused(t, "a ticket after the command", ref, 409, api.CodeRunRefused, api.RunReasonArmedThisBoot)
	r.ticks(1200 * time.Second)
	if len(r.scheduled) != 0 {
		t.Fatalf("switched off after the command: %+v", r.scheduled)
	}

	// during the countdown
	r = newRunRig(t)
	r.armed(runA)
	r.ticks(1000 * time.Second)
	if len(r.scheduled) != 1 || !r.pending {
		t.Fatal("no countdown")
	}
	if _, changed, err := r.files.RunCancel(); !changed || err != nil {
		t.Fatal(err)
	}
	r.w.Tick()
	if r.cancels != 1 || r.pending || r.state() != api.RunCancelled {
		t.Fatalf("the countdown after the command: %d cancels, pending %v, %s", r.cancels, r.pending, r.state())
	}
	r.ticks(10 * time.Second)
	if r.cancels != 1 {
		t.Errorf("stopped %d times", r.cancels)
	}

	// a confirmed run: nothing of it is let through any more, at once (no look of the watch in between)
	r = newRunRig(t)
	r.armed(runA)
	if _, ref := r.confirm(goReq(runA, "19-abc", 30, 1500)); ref != nil {
		t.Fatal(ref)
	}
	if _, changed, err := r.files.RunCancel(); !changed || err != nil {
		t.Fatal(err)
	}
	r.w.Tick()
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Error("an update after the command")
	}
	// the record is removed altogether while the service runs: the same
	r = newRunRig(t)
	r.armed(runA)
	os.Remove(r.files.RunPath())
	r.ticks(1200 * time.Second)
	if len(r.scheduled) != 0 || r.run() != nil {
		t.Fatalf("after the record was removed: %+v, %+v", r.scheduled, r.run())
	}
}

// A live run that the running service did not write itself is not believed: somebody put a record of a
// confirmed run in the place of the service's own.
func TestRunRecordFromOutsideIsNotBelieved(t *testing.T) {
	donor := newRunRig(t)
	donor.armed(runA)
	if _, ref := donor.confirm(goReq(runA, "19-abc", 30, 3600)); ref != nil {
		t.Fatal(ref)
	}
	planted := donor.record(t)

	r := newRunRig(t)
	r.w.Tick() // the service has looked: no record
	if err := os.WriteFile(r.files.RunPath(), planted, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
		if _, ref := r.g.AdmitRun(req, runA); ref == nil {
			t.Errorf("%s of a planted record was let through", req.Verb)
		}
	}
	// the same while the service has a run of its own
	r = newRunRig(t)
	r.armed(runB)
	if err := os.WriteFile(r.files.RunPath(), planted, 0o600); err != nil {
		t.Fatal(err)
	}
	r.w.Tick()
	if _, ref := r.g.AdmitRun(update, runA); ref == nil {
		t.Error("an update of a planted record was let through")
	}
	if r.state() != api.RunCancelled {
		t.Errorf("state %s", r.state())
	}
	r.ticks(1200 * time.Second)
	if len(r.scheduled) != 0 {
		t.Errorf("scheduled %+v", r.scheduled)
	}
}

// The mark remembers sixteen runs.
func TestRunRecordRemembersSixteenRuns(t *testing.T) {
	r := newRunRig(t)
	ids := make([]string, approval.RunUsedMax+1)
	tickets := make([]*api.Approval, len(ids))
	for i := range ids {
		ids[i] = runA[:14] + string("0123456789abcdefg"[i/16]) + string("0123456789abcdef"[i%16])
		tickets[i] = r.signed(r.Now(), ticketEntry("test-machine-AAAAAAAAAAAA", ids[i], 2100, 120, 30))
		r.reboot(time.Second, 20*time.Second)
		if _, ref := r.w.Arm(tickets[i]); ref != nil {
			t.Fatalf("run %d: %v", i, ref)
		}
	}
	r.reboot(time.Second, 20*time.Second)
	for i := 1; i < len(ids); i++ {
		_, ref := r.w.Arm(tickets[i])
		runRefused(t, "a run on record", ref, 409, api.CodeRunRefused, api.RunReasonRunUsed)
	}
	if len(r.record(t)) > approval.MaxRunFile/2 {
		t.Errorf("the full record is %d bytes", len(r.record(t)))
	}
}
