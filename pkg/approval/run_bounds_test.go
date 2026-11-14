package approval_test

import (
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// The uptimes of the live run (when it was armed, confirmed, when its countdown began) were only checked for
// "not negative". Every one of them was written at or before the moment the record itself was written, whose
// uptime is in the record ("at"): a record in which one is later than that is not one this program wrote. It
// is not believed, like every other record with an impossible value (review of fd6d3be, T8).
func TestRunRecordWithAnUptimeLaterThanItsOwn(t *testing.T) {
	set := func(rec []byte, member, value string) []byte {
		re := regexp.MustCompile(`"` + member + `":[0-9]+`)
		if !re.Match(rec) {
			t.Fatalf("no %s in %s", member, rec)
		}
		return re.ReplaceAll(rec, []byte(`"`+member+`":`+value))
	}
	for _, state := range []string{api.RunArmed, api.RunOffPending, api.RunConfirmed} {
		r := newRunRig(t)
		r.armed(runA) // at 60 s
		member := "armed_up_ms"
		switch state {
		case api.RunOffPending:
			r.ticks(961 * time.Second)
			member = "off_up_ms"
		case api.RunConfirmed:
			if _, ref := r.confirm(goReq(runA, "9.9.9", 30, 600)); ref != nil {
				t.Fatal(ref)
			}
			member = "go_up_ms"
		}
		if r.state() != state {
			t.Fatalf("state %q, want %q", r.state(), state)
		}
		good := r.record(t)
		if _, err := approval.RunRoundTrip(good); err != nil {
			t.Fatalf("%s: the record as written: %v", state, err)
		}
		at := r.up().Milliseconds()
		// exactly the record's own uptime is what the program writes; one millisecond more is not
		for _, c := range []struct {
			value int64
			ok    bool
		}{{at, true}, {at + 1, false}, {at + 3600_000, false}, {92233720368547, false}, {9223372036854775, false}, {9223372036854775807, false}} {
			mod := set(good, member, strconv.FormatInt(c.value, 10))
			if state == api.RunOffPending && c.ok {
				continue // (its off_up_ms is the uptime of an earlier write than the last)
			}
			_, err := approval.RunRoundTrip(mod)
			if (err == nil) != c.ok {
				t.Errorf("%s with %s=%d (the record was written at %d): %v, want believed %v", state, member, c.value, at, err, c.ok)
			}
			if c.ok {
				continue
			}
			// the service that finds it: no run, nothing switched off, nothing let through, and no ticket taken
			n := len(r.scheduled)
			if err := os.WriteFile(r.files.RunPath(), mod, 0o600); err != nil {
				t.Fatal(err)
			}
			r.restart()
			r.pending = false
			r.ticks(3 * time.Second)
			if len(r.scheduled) != n {
				t.Errorf("%s with %s=%d: the service switched the machine off: %+v", state, member, c.value, r.scheduled[n:])
			}
			if run := r.run(); run != nil {
				t.Errorf("%s with %s=%d: the run is believed: %+v", state, member, c.value, run)
			}
			for _, req := range []api.ApprovalRequest{update, power("shutdown", 30)} {
				if _, ref := r.g.AdmitRun(req, runA); ref == nil {
					t.Errorf("%s with %s=%d: %s let through", state, member, c.value, req.Verb)
				}
			}
			_, ref := r.w.Arm(r.ticket(runB, r.up()+100*time.Second))
			runRefused(t, "a ticket with such a record", ref, 503, api.CodeRunUnavailable, "")
		}
	}
}
