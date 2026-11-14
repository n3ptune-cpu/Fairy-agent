package approval_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
)

// FuzzRunTicket feeds anything as the body's "approval" of POST /run/arm to a machine that would take a good
// ticket at this moment. The fuzzer has real tokens for other lists and no key, so whatever it builds must be
// refused: nothing may panic, nothing may be armed, and no record may be written.
func FuzzRunTicket(f *testing.F) {
	r := newRunRig(f)
	at := r.Now().Add(-160 * time.Second)
	e := ticketEntry(approvaltest.MachineID, runA, 420, 960, 120)
	forOther := ticketEntry("another-machine-BBBBBBBBBB", runA, 420, 960, 120)
	otherNonce, _ := api.ApprovalNonce([]api.MachineEntry{forOther})
	tok := r.iss.Token(r.iss.Claims(otherNonce, at)) // a real token, for another machine's ticket
	add := func(tok string, entries ...api.MachineEntry) {
		b, _ := json.Marshal(api.Approval{Token: tok, Entries: entries})
		f.Add(string(b))
	}
	add(tok, e)
	add(tok, forOther)
	add(tok, e, forOther)
	add("a.b.c", e)
	add("", e)
	wide := e
	wide.Request = armText(runA, 2100, 120, 30)
	add(tok, wide)
	c, _ := r.g.Challenge(power("shutdown", 60))
	add(r.iss.Approve(r.Now(), approvaltest.Entry(approvaltest.MachineID, c)).Token, approvaltest.Entry(approvaltest.MachineID, c))
	crossed := e
	crossed.Challenge = c.Challenge
	add(tok, crossed)
	f.Add(`{"token":"a.b.c","entries":[{"machine_id":"` + approvaltest.MachineID + `","challenge":"` + e.Challenge + `","request":"run_arm run=` + runA + ` valid_s=420 wait_s=960 notice_s=120 "}]}`)
	f.Add(`{"token":"a.b.c","entries":[{"machine_id":"","challenge":"` + e.Challenge + `","request":"run_arm run=` + runA + ` valid_s=420 wait_s=960 notice_s=120"}]}`)
	f.Add(`{"entries":[{"challenge":"\n","request":"run_arm \u0000"}]}`)
	f.Add(`null`)
	f.Fuzz(func(t *testing.T, raw string) {
		var ap api.Approval
		if json.Unmarshal([]byte(raw), &ap) != nil {
			return
		}
		if ans, ref := r.w.Arm(&ap); ref == nil {
			t.Fatalf("armed %+v by %q", ans, raw)
		}
		if r.touched() {
			t.Fatalf("something in the record after %q", raw)
		}
	})
}

// FuzzRunRecord feeds anything as the content of the run record to a service that starts. Nothing may panic.
// What is not a record of this program counts as no record: no run, nothing let through, no ticket taken.
// What is one reads back as itself.
func FuzzRunRecord(f *testing.F) {
	donor := newRunRig(f)
	donor.armed(runA)
	f.Add(donor.record(f))
	donor.confirm(goReq(runA, "19-abc", 30, 1500))
	f.Add(donor.record(f))
	donor.g.AdmitRun(update, runA)
	f.Add(donor.record(f))
	donor.w.Cancel("seed")
	f.Add(donor.record(f))
	f.Add([]byte(`{"version":1,"at":{"wall":1,"up_ms":0}}`))
	f.Add([]byte(`{"version":1,"at":{"wall":1,"up_ms":0},"run":{"id":"00000000000000aa","state":"confirmed","within_s":300,"to":"-","shutdown_delay_s":10,"update":1,"shutdown":1}}`))
	f.Add([]byte(`{"version":1,"at":{"wall":1,"up_ms":0},"run":{"id":"00000000000000aa","state":"armed","wait_s":120,"notice_s":30,"off_up_ms":5}}`))
	f.Add([]byte(`{"version":1,"at":{"boot_id":"boot-1","wall":1794000000,"up_ms":60000},"used":["00000000000000aa","x"]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(``))
	f.Add([]byte(`[]`))
	r := newRunRig(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if err := os.WriteFile(r.files.RunPath(), data, 0o600); err != nil {
			t.Fatal(err)
		}
		back, rerr := approval.RunRoundTrip(data)
		exists, err := r.files.RunRecordCheck()
		if !exists || (err == nil) != (rerr == nil && len(data) <= approval.MaxRunFile) {
			t.Fatalf("the file reads %v, its content %v", err, rerr)
		}
		r.restart()
		r.w.Tick()
		run := r.run()
		_, covered := r.g.RunCovers(update, runA)
		if err != nil {
			if run != nil || covered == nil {
				t.Fatalf("a record that cannot be read gave run %+v, update refused: %v", run, covered)
			}
			if _, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second)); ref == nil {
				t.Fatal("a ticket was taken with a record that cannot be read")
			}
			return
		}
		again, err := approval.RunRoundTrip(back)
		if err != nil || !bytes.Equal(again, back) {
			t.Fatalf("an accepted record does not read back as itself: %v", err)
		}
		if strings.Contains(string(back), `"token"`) {
			t.Fatal("a record with a token member")
		}
	})
}
