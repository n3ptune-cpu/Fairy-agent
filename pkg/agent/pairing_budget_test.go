package agent

// Audit 4, T-55: to learn whether a /pair request comes from the panel, the handler opened and read the
// pairing state file (up to 64 KiB) under its lock, for every request, before any budget was asked. Requests
// need no token, so only the connection caps limited that work.

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
)

// budgetRig is a pair rig set up as the running agent sets it up (the panel's address from PairedPanel), with
// a count of how often the handler reads the state file. Everything in it reads one clock, the rig's: the
// first version of these tests gave the handler the rig's fixed time and PairedPanel the real time, so they
// would have failed from the day the real clock passed the rig's (2027-01-15).
func budgetRig(t *testing.T, panel string) (*pairRig, *atomic.Int32) {
	return budgetRigAt(t, panel, time.Time{})
}

// budgetRigAt is budgetRig with the rig's clock, and the join code, moved to at (the zero time: left alone).
func budgetRigAt(t *testing.T, panel string, at time.Time) (*pairRig, *atomic.Int32) {
	t.Helper()
	r := newPairRig(t, "", panel)
	if !at.IsZero() {
		r.now = at
		st, err := enroll.ReadState(r.path)
		if err != nil {
			t.Fatal(err)
		}
		st.CreatedAt, st.ExpiresAt = at.Unix(), at.Add(enroll.TTL).Unix()
		if err := enroll.WriteState(r.path, st); err != nil {
			t.Fatal(err)
		}
	}
	r.p.Panel = pairedPanel(r.path, r.p.Now)
	reads := new(atomic.Int32)
	r.p.read = func(path string) (enroll.State, error) {
		reads.Add(1)
		return enroll.ReadState(path)
	}
	return r, reads
}

// The test must not depend on the day it runs: it runs with the rig's own date, with one long past and with
// one far ahead of the real clock, and with the real time itself.
func TestPairCountsARequestBeforeItReadsTheStateFile(t *testing.T) {
	for name, at := range map[string]time.Time{
		"the rig's date": {},
		"long ago":       time.Unix(1_000_000_000, 0),
		"far ahead":      time.Unix(4_000_000_000, 0),
		"now":            time.Now(),
	} {
		t.Run(name, func(t *testing.T) { pairCountsBeforeItReads(t, at) })
	}
}

func pairCountsBeforeItReads(t *testing.T, at time.Time) {
	const panel = "100.64.0.10"
	r, reads := budgetRigAt(t, panel, at)
	good := `{"proof":"` + r.proof + `"}`
	// one machine, 100 requests: its budget lets five be looked at, and only those five read the file
	seen := map[int]int{}
	for i := 0; i < 100; i++ {
		st, _ := r.from("100.99.0.5", "application/json", good)
		seen[st]++
	}
	if seen[403] != enroll.RatePerMin || seen[429] != 100-enroll.RatePerMin || len(seen) != 2 {
		t.Fatalf("one other address: %v", seen)
	}
	if n := reads.Load(); n != enroll.RatePerMin {
		t.Fatalf("100 requests of one stranger, %d within its budget: the state file was read %d times", enroll.RatePerMin, n)
	}
	// many machines: the others' shared budget, and no read beyond it
	for i := 0; i < 300; i++ {
		r.from(fmt.Sprintf("100.99.%d.%d", 1+i/200, 1+i%200), "application/json", `{"proof":"x"}`)
	}
	if n := reads.Load(); n != pairOthersPerMin {
		t.Fatalf("400 requests of strangers, %d within the budgets: the state file was read %d times", pairOthersPerMin, n)
	}
	if s, _ := enroll.ReadState(r.path); s.Failures != 0 || !s.Active(r.now) {
		t.Fatalf("requests from elsewhere must not use up the code: %+v", s)
	}
	// the panel has its own budget, as before: its first request pairs
	st, body := r.from(panel, "application/json", good)
	if st != 200 || body["token"] != readTok {
		t.Fatalf("the panel after the flood: %d %v", st, body)
	}
}

// The panel over its own budget: refused without a look at the file, and others are still told "wrong address".
func TestPairPanelOverItsBudgetReadsNothing(t *testing.T) {
	const panel = "100.64.0.10"
	r, reads := budgetRig(t, panel)
	for i := 0; i < enroll.RatePerMin; i++ {
		if st, body := r.from(panel, "application/json", `{"proof":"x"}`); st != 403 || body["code"] != "wrong_code" {
			t.Fatalf("%d: %d %v", i, st, body)
		}
	}
	before := reads.Load()
	for i := 0; i < 50; i++ {
		if st, body := r.from(panel, "application/json", `{"proof":"`+r.proof+`"}`); st != 429 || body["code"] != "rate_limited" {
			t.Fatalf("the panel over its budget: %d %v", st, body)
		}
	}
	if n := reads.Load() - before; n != 0 {
		t.Fatalf("50 requests over the budget read the state file %d times", n)
	}
	if st, body := r.from("100.99.0.5", "application/json", `{}`); st != 403 || body["code"] != "wrong_address" {
		t.Fatalf("another address while the panel is over its budget: %d %v", st, body)
	}
}

// The address on record may be a few seconds old (PairedPanel reads the file at most every five seconds). A
// code that `fairy-agent join` has just written for a new panel still pairs: the new panel's first request is
// counted in the others' budget, and who may pair is read from the file itself.
func TestPairWithAnAddressOnRecordThatIsStale(t *testing.T) {
	r, _ := budgetRig(t, "100.64.0.10")
	if st, body := r.from("100.64.0.10", "application/json", `{"proof":"x"}`); st != 403 || body["code"] != "wrong_code" {
		t.Fatal(st, body) // the address on record is now 100.64.0.10
	}
	st, err := enroll.ReadState(r.path)
	if err != nil {
		t.Fatal(err)
	}
	st.Panel, st.Failures = "100.64.0.77", 0 // a new join, for another panel
	if err := enroll.WriteState(r.path, st); err != nil {
		t.Fatal(err)
	}
	if st, body := r.from("100.64.0.10", "application/json", `{"proof":"`+r.proof+`"}`); st != 403 || body["code"] != "wrong_address" {
		t.Fatalf("the old panel's address after a new join: %d %v", st, body)
	}
	if st, body := r.from("100.64.0.77", "application/json", `{"proof":"`+r.proof+`"}`); st != 200 || body["token"] != readTok {
		t.Fatalf("the new panel's first request: %d %v", st, body)
	}
}

// The address on record is read with the clock it is given, and the five seconds between two looks at the file
// are counted on that clock too.
func TestPairedPanelUsesTheClockItIsGiven(t *testing.T) {
	r := newPairRig(t, "", "100.64.0.10") // a code that is open at the rig's time, for 100.64.0.10
	for name, c := range map[string]struct {
		at   time.Time
		want string
	}{
		"while the code is open": {r.now.Add(time.Minute), "100.64.0.10"},
		"after the code ran out": {r.now.Add(enroll.TTL + time.Second), ""},
		"long after":             {r.now.Add(100 * 365 * 24 * time.Hour), ""},
		"long before":            {time.Unix(1_000_000_000, 0), "100.64.0.10"}, // a code is open until it runs out
	} {
		if got := pairedPanel(r.path, func() time.Time { return c.at })(); got != c.want {
			t.Errorf("%s: the panel on record is %q, want %q", name, got, c.want)
		}
	}
	now := r.now
	panel := pairedPanel(r.path, func() time.Time { return now })
	if got := panel(); got != "100.64.0.10" {
		t.Fatal(got)
	}
	st, err := enroll.ReadState(r.path)
	if err != nil {
		t.Fatal(err)
	}
	st.Panel = "100.64.0.77"
	if err := enroll.WriteState(r.path, st); err != nil {
		t.Fatal(err)
	}
	if got := panel(); got != "100.64.0.10" {
		t.Fatalf("the file was read again within five seconds of the given clock: %q", got)
	}
	now = now.Add(6 * time.Second)
	if got := panel(); got != "100.64.0.77" {
		t.Fatalf("six seconds later on the given clock: %q", got)
	}
}
