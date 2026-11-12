package agent_test

// Audit 5, round 1: regression tests built from the auditors' proofs (audit5/r1-a1/poc, audit5/r1-a2/poc), over
// the agent's real HTTP handler: the Linux agent with its own gate (newLinuxRig) and the Windows agent in front
// of the real helper code (newApprovalRig).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// trusted sets the trust of a rig's machine the way the panel does (first-time set with its proof).
func (r *lrig) trusted(t *testing.T) *lrig {
	t.Helper()
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	return r
}

func (r *aprig) trusted(t *testing.T) *aprig {
	t.Helper()
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, r.iss, r.iss.Init())); st != 200 {
		t.Fatalf("first-time set: %d %v", st, b)
	}
	r.approvalBlock(t, api.ApprovalRequired)
	return r
}

// fanWindowClosed checks, over HTTP, that no fan change runs without an approval right now and that the fan
// window never lets a shutdown through.
func fanWindowClosed(t *testing.T, when string, post func(*testing.T, string, any) (int, map[string]any)) {
	t.Helper()
	st, b := post(t, "/fan/mode", map[string]any{"mode": "full"})
	wantRefusal(t, when+": fan mode without approval", st, b, 403, api.CodeApprovalRequired)
	st, b = post(t, "/fan/duty", map[string]any{"zone": 1, "percent": 30})
	wantRefusal(t, when+": fan duty without approval", st, b, 403, api.CodeApprovalRequired)
	st, c := post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "heavyio"})
	if st != 200 || c["needed"] != true {
		t.Errorf("%s: a challenge says that no approval is needed: %d %v", when, st, c)
	}
	st, b = post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, when+": shutdown without approval", st, b, 403, api.CodeApprovalRequired)
}

// TestFanWindowNeedsAnAppliedFanChange (r1-a1-04, r1-a2-02), on the Linux agent. The auditors' two runs:
// an approved fan_set of 5 % that the fan controller refuses (400: the lowest duty is 30 %), and an approved
// fan_set while the fan mode is not "full" (409: nothing changes). After either, fan changes without approval
// ran for 30 s. Only an approved change that was applied opens the window.
func TestFanWindowNeedsAnAppliedFanChange(t *testing.T) {
	r := newLinuxRig(t, true).trusted(t)
	if r.mode(t) == "full" {
		t.Fatal("the test needs a fan mode other than full at the start")
	}
	start := r.mode(t)

	// r1-a1-04: approved, then refused by the fan controller
	low := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 5})
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 5, "approval": low}); st != 400 {
		t.Fatalf("approved fan_set of 5 %%: %d %v, want 400", st, b)
	}
	fanWindowClosed(t, "after an approved fan_set the machine refused (400)", r.post)

	// r1-a2-02 (S8): approved, and nothing changes because the mode is not "full"
	full := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 100})
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": full}); st != 409 {
		t.Fatalf("approved fan_set while the mode is %s: %d %v, want 409", start, st, b)
	}
	fanWindowClosed(t, "after an approved fan_set that changed nothing (409)", r.post)
	if r.mode(t) != start {
		t.Fatalf("the fan mode changed without an approval: %s", r.mode(t))
	}

	// an approved change that is applied opens it, for fan changes only
	mode := r.approve(t, map[string]any{"verb": "fan_mode", "mode": "full"})
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full", "approval": mode}); st != 200 || r.mode(t) != "full" {
		t.Fatalf("approved fan mode: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 1, "percent": 60}); st != 200 {
		t.Errorf("fan duty inside the window: %d %v", st, b)
	}
	if st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "optimal"}); st != 200 || c["needed"] != false || c["reason"] != "fan_window" {
		t.Errorf("challenge inside the window: %d %v", st, c)
	}
	st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "shutdown inside the fan window", st, b, 403, api.CodeApprovalRequired)
}

// TestFanWindowNeedsAnAppliedFanChangeThroughTheHelper: the same on Windows, where the helper checks and holds
// the window: an approved fan_set that the helper's fan controller answers with 409 (the mode is not "full")
// opens nothing.
func TestFanWindowNeedsAnAppliedFanChangeThroughTheHelper(t *testing.T) {
	r := newApprovalRig(t).trusted(t)
	full := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 100})
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": full}); st != 409 {
		t.Fatalf("approved fan_set while the mode is not full: %d %v, want 409", st, b)
	}
	fanWindowClosed(t, "after an approved fan_set that changed nothing (409)", r.post)

	mode := r.approve(t, map[string]any{"verb": "fan_mode", "mode": "full"})
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full", "approval": mode}); st != 200 {
		t.Fatalf("approved fan mode: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 1, "percent": 60}); st != 200 {
		t.Errorf("fan duty inside the window: %d %v", st, b)
	}
}

// setTrustOnTheMachine writes the trust file as the administrator's command does, before the agent's first look.
func (r *lrig) setTrustOnTheMachine(t *testing.T, change func(*approval.Trust)) *lrig {
	t.Helper()
	in := r.iss.Init()
	w := approval.DefaultFanWindowS
	tr := approval.Trust{Issuer: in.Issuer, ClientID: in.ClientID, Keys: in.Keys, Users: in.Users, FanWindowS: &w, SetBy: "admin"}
	if change != nil {
		change(&tr)
	}
	nt, err := approval.NewTrust(tr)
	if err != nil {
		t.Fatal(err)
	}
	if err := (approval.Files{Path: r.trust}).Replace(nt); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestARefusedRequestCostsNoApproval (r1-a2-01, r1-a1-02), on the Linux agent, where the agent itself checks.
// The approval of a request used to be used up when the request arrived, before the request's own checks; a
// request the agent then refused (400, 409, 503) had cost the passkey confirmation. The auditor's runs: an
// approved shutdown with a delay under min_delay_s, an approved sleep on a machine that cannot sleep, an
// approved request while another action is pending, an approved fan duty while the mode is not "full". Now
// the approval is looked at, and used up, only when the request has passed its own checks.
func TestARefusedRequestCostsNoApproval(t *testing.T) {
	r := newLinuxRig(t, true).trusted(t)
	r.power.NoSleep = "no suspend to RAM here"
	accepted := func() int { return strings.Count(r.log.String(), "approval: accepted") }
	base := accepted()

	// S6: a delay under min_delay_s (10). Refused for that reason, every time; the approval is never looked at.
	short := r.approve(t, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 5})
	for i := 0; i < 2; i++ {
		st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 5, "approval": short})
		if st != 400 || b["code"] != nil || !strings.Contains(b["error"].(string), "delay_s must be between 10") {
			t.Fatalf("approved shutdown with delay 5, try %d: %d %v", i+1, st, b)
		}
	}
	// S6: a machine that cannot sleep
	sleep := r.approve(t, map[string]any{"verb": "power", "action": "sleep", "delay_s": 60})
	st, b := r.post(t, "/power", map[string]any{"action": "sleep", "delay_s": 60, "approval": sleep})
	wantRefusal(t, "approved sleep on a machine that cannot sleep", st, b, 409, "sleep_unavailable")
	if n := accepted() - base; n != 0 {
		t.Fatalf("%d approvals were used up by requests the agent refused", n)
	}

	// 409 "already pending": the second approval survives the refusal and works once the first action is cancelled
	first := r.approve(t, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	second := r.approve(t, map[string]any{"verb": "power", "action": "reboot", "delay_s": 60})
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": first}); st != 200 {
		t.Fatalf("approved shutdown: %d %v", st, b)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": second}); st != 409 || b["code"] != nil {
		t.Fatalf("approved reboot while a shutdown is pending: %d %v", st, b)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Fatalf("cancel: %d %v", st, b)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": second}); st != 200 {
		t.Fatalf("the approval of the request that was refused with 409, after the cancel: %d %v", st, b)
	}
	// still single use, still bound to the exact request
	st, b = r.post(t, "/power", map[string]any{"action": "cancel"})
	if st != 200 {
		t.Fatalf("cancel: %d %v", st, b)
	}
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": second})
	wantRefusal(t, "replay", st, b, 403, api.CodeApprovalRefused)
	st, b = r.post(t, "/power", map[string]any{"action": "reboot", "delay_s": 61, "approval": r.approve(t, map[string]any{"verb": "power", "action": "reboot", "delay_s": 60})})
	wantRefusal(t, "approved for 60 s, sent with 61", st, b, 403, api.CodeApprovalRefused)
	if got := strings.Join(r.power.Scheduled, ","); got != "shutdown@1m0s,reboot@1m0s" {
		t.Fatalf("scheduled: %s", got)
	}

	// fans: a duty while the mode is not "full" changes nothing (409); the approval works after the mode was set
	duty := r.approve(t, map[string]any{"verb": "fan_set", "zone": 0, "percent": 100})
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": duty}); st != 409 {
		t.Fatalf("approved duty while the mode is not full: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 5, "approval": duty}); st != 400 {
		t.Fatalf("a duty under the minimum: %d %v", st, b)
	}
	mode := r.approve(t, map[string]any{"verb": "fan_mode", "mode": "full"})
	if st, b := r.post(t, "/fan/mode", map[string]any{"mode": "full", "approval": mode}); st != 200 {
		t.Fatalf("approved fan mode: %d %v", st, b)
	}
	if st, b := r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": duty}); st != 200 {
		t.Fatalf("the approval of the duty that was refused with 409, now that the mode is full: %d %v", st, b)
	}
	st, b = r.post(t, "/fan/duty", map[string]any{"zone": 0, "percent": 100, "approval": duty})
	wantRefusal(t, "duty replay (an approval that is sent is checked, fan window or not)", st, b, 403, api.CodeApprovalRefused)

	// without an approval the answer is approval_required whatever else is wrong with the request: nothing of
	// the machine is told to somebody who has only the control token
	for name, c := range map[string]struct {
		path string
		body map[string]any
	}{
		"shutdown with a delay under the minimum": {"/power", map[string]any{"action": "shutdown", "delay_s": 5}},
		"sleep on a machine that cannot sleep":    {"/power", map[string]any{"action": "sleep", "delay_s": 60}},
	} {
		st, b := r.post(t, c.path, c.body)
		wantRefusal(t, name+", no approval", st, b, 403, api.CodeApprovalRequired)
	}
}

// TestARefusedUpdateCostsNoApproval (r1-a2-01, S10): an approved update on a build that cannot update itself
// (no release key) is refused with 503 self_update_unavailable, and that used to use the approval up.
func TestARefusedUpdateCostsNoApproval(t *testing.T) {
	r := newLinuxRigWith(t, lrigOpts{gate: true, noKey: true}).trusted(t)
	up := r.approve(t, map[string]any{"verb": "apply_update"})
	for i := 0; i < 2; i++ {
		st, b := r.post(t, "/update", map[string]any{"approval": up})
		wantRefusal(t, "approved update on a build without a release key", st, b, 503, "self_update_unavailable")
	}
	if strings.Contains(r.log.String(), "approval: accepted") || strings.Contains(r.log.String(), "approval: refused") {
		t.Fatalf("the approval of a refused update was looked at:\n%s", r.log.String())
	}
	st, b := r.post(t, "/update", map[string]any{})
	wantRefusal(t, "update without approval", st, b, 403, api.CodeApprovalRequired)
}

// TestARefusedShutdownDoesNotSpendTheOneAfterBoot (r1-a1-02): with boot_shutdown_s set, the machine accepts one
// shutdown without approval shortly after boot. A request the agent then refused (the auditor's: a delay under
// min_delay_s) used that one up; the machine that was woken only to be updated stayed on. It is recorded now
// when a shutdown is really scheduled.
func TestARefusedShutdownDoesNotSpendTheOneAfterBoot(t *testing.T) {
	r := newLinuxRigWith(t, lrigOpts{gate: true, uptime: func() time.Duration { return 120 * time.Second }})
	r.setTrustOnTheMachine(t, func(tr *approval.Trust) { tr.BootShutdownS = 900 })
	mark := filepath.Join(filepath.Dir(r.trust), approval.BootMarkName)

	st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 5})
	if st != 200 || c["needed"] != false || c["reason"] != "boot_shutdown" {
		t.Fatalf("challenge for a shutdown shortly after boot: %d %v", st, c)
	}
	st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 5})
	if st != 400 {
		t.Fatalf("shutdown with a delay under min_delay_s: %d %v", st, b)
	}
	if _, err := os.Lstat(mark); err == nil {
		t.Fatal("the shutdown after boot was recorded for a request that was refused")
	}
	if len(r.power.Scheduled) != 0 {
		t.Fatalf("scheduled: %v", r.power.Scheduled)
	}
	// the correct request of the same run: accepted, once
	if st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60}); st != 200 {
		t.Fatalf("the one shutdown without approval after boot: %d %v (the refused request before it used it up)", st, b)
	}
	if _, err := os.Lstat(mark); err != nil {
		t.Fatalf("the accepted shutdown was not recorded: %v", err)
	}
	if got := strings.Join(r.power.Scheduled, ","); got != "shutdown@1m0s" {
		t.Fatalf("scheduled: %s", got)
	}
	if st, b := r.post(t, "/power", map[string]any{"action": "cancel"}); st != 200 {
		t.Fatalf("cancel: %d %v", st, b)
	}
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
	wantRefusal(t, "a second shutdown without approval in the same boot", st, b, 403, api.CodeApprovalRequired)
	// never reboot, never sleep, never a long delay
	for _, body := range []map[string]any{{"action": "reboot", "delay_s": 60}, {"action": "shutdown", "delay_s": 601}} {
		st, b := r.post(t, "/power", body)
		wantRefusal(t, "boot window", st, b, 403, api.CodeApprovalRequired)
	}
	if !strings.Contains(r.log.String(), "UNAPPROVED shutdown accepted shortly after boot") {
		t.Error("the accepted shutdown is not in the log")
	}
}

// TestChallengesAndCancelHaveBudgetsOfTheirOwn (r1-a2-03). All control routes shared one budget (default 12 a
// minute), POST /approval/challenge among them: twelve challenges, and POST /power cancel, the request that
// stops a shutdown, was answered 429 (the auditor's run). Challenges and cancel now each have a budget of
// their own, of the same size, and none can use up another's.
func TestChallengesAndCancelHaveBudgetsOfTheirOwn(t *testing.T) {
	const rate = 12 // the default
	r := newLinuxRigWith(t, lrigOpts{gate: true, rate: rate})
	r.setTrustOnTheMachine(t, nil)
	challenge := func() (int, map[string]any) {
		return r.post(t, api.PathApprovalChallenge, map[string]any{"verb": "apply_update"})
	}
	cancel := func() (int, map[string]any) { return r.post(t, "/power", map[string]any{"action": "cancel"}) }
	tooMany := func(what string, st int, b map[string]any, text string) {
		t.Helper()
		if msg, _ := b["error"].(string); st != 429 || !strings.Contains(msg, text) {
			t.Fatalf("%s: %d %v, want 429 %q", what, st, b, text)
		}
	}

	// the auditor's run: twelve challenges, then cancel
	for i := 0; i < rate; i++ {
		if st, b := challenge(); st != 200 {
			t.Fatalf("challenge %d: %d %v", i+1, st, b)
		}
	}
	st, b := challenge()
	tooMany("the 13th challenge", st, b, "too many approval challenge requests")
	if st, b := cancel(); st != 200 {
		t.Fatalf("POST /power cancel after twelve challenges: %d %v (challenges used its budget up)", st, b)
	}
	// ... and every other control request still has its whole budget
	for i := 0; i < rate; i++ {
		st, b := r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60})
		wantRefusal(t, "shutdown without approval", st, b, 403, api.CodeApprovalRequired)
	}
	st, b = r.post(t, "/fan/mode", map[string]any{"mode": "full"})
	tooMany("the 13th control request", st, b, "too many control requests")
	// a /power body that cannot be read is a control request, not a free one
	st, b = do(t, r.base, "POST", "/power", ctlTok, "not an object")
	tooMany("a /power body that is not an object", st, b, "too many control requests")

	// neither twelve challenges nor twelve refused control requests keep a cancel out
	for i := 1; i < rate; i++ {
		if st, b := cancel(); st != 200 {
			t.Fatalf("cancel %d, with the challenge budget and the control budget used up: %d %v", i+1, st, b)
		}
	}
	st, b = cancel()
	tooMany("the 13th cancel", st, b, "too many cancel requests")
}

// challengeFlood is the auditors' run (r1-a1-03 ChallengeFlood, r1-a2-04 S9) over HTTP: one challenge that the
// owner is confirming, then sixteen more requests for challenges, then the owner's approval.
func challengeFlood(t *testing.T, post func(*testing.T, string, any) (int, map[string]any), approve func(*testing.T, map[string]any) *api.Approval) {
	t.Helper()
	owner := approve(t, map[string]any{"verb": "power", "action": "reboot", "delay_s": 60})
	for i := 0; i < approval.MaxChallenges; i++ {
		st, c := post(t, api.PathApprovalChallenge, map[string]any{"verb": "apply_update"})
		switch {
		case i < approval.MaxChallenges-1 && (st != 200 || c["needed"] != true):
			t.Fatalf("challenge %d of the flood: %d %v", i+1, st, c)
		case i == approval.MaxChallenges-1:
			// the one that would have dropped the owner's challenge: refused, and it says so
			wantRefusal(t, "the 17th open challenge", st, c, 429, api.CodeTooManyChallenges)
			if msg, _ := c["error"].(string); !strings.Contains(msg, "Try again in") {
				t.Errorf("the refusal does not say when to ask again: %q", msg)
			}
		}
	}
	if st, b := post(t, "/power", map[string]any{"action": "reboot", "delay_s": 60, "approval": owner}); st != 200 {
		t.Fatalf("the owner's approval after sixteen more requests for challenges: %d %v (before the fix: 403 no_challenge)", st, b)
	}
	// the place of the used challenge is free at once
	if st, c := post(t, api.PathApprovalChallenge, map[string]any{"verb": "fan_mode", "mode": "full"}); st != 200 || c["needed"] != true {
		t.Fatalf("a challenge after one was used: %d %v", st, c)
	}
}

// TestChallengeFloodDoesNotKillAnApprovalInFlight: on the Linux agent (its own list of challenges).
func TestChallengeFloodDoesNotKillAnApprovalInFlight(t *testing.T) {
	r := newLinuxRig(t, true).trusted(t)
	challengeFlood(t, r.post, r.approve)
}

// TestChallengeFloodDoesNotKillAnApprovalInFlightThroughTheHelper: on Windows the list is the helper's; its
// refusal reaches the panel with its status and code.
func TestChallengeFloodDoesNotKillAnApprovalInFlightThroughTheHelper(t *testing.T) {
	r := newApprovalRig(t).trusted(t)
	challengeFlood(t, r.post, r.approve)
}

// TestMetricsShowWhoseTrustAMachineHas (r1-a2-05). The first-time set needs only the control token and a proof
// against the PROPOSED values, so whoever holds a stolen control token can set a trust of his own on a machine
// that has none, and the owner's approvals are refused there until somebody repairs it on the machine. That is
// an accepted limit of the design. What must hold is that the owner's panel can see it: /metrics shows the
// issuer, the client id, the key thumbprints, a hash over all of it and the user ids, and how the file came to
// be.
func TestMetricsShowWhoseTrustAMachineHas(t *testing.T) {
	r := newLinuxRig(t, true)
	mine := r.iss.Init() // what the owner's panel would set

	// the thief is first. Case 1 of two: the owner's own Pocket ID, client and keys, and the thief's user id
	// (he has an account there): issuer, client id and thumbprints look right, the count of users is 1
	thief := *r.iss
	thief.Sub = "thief-user-id"
	in := thief.Init(thief.Sub)
	if st, b := r.post(t, api.PathApprovalTrust, provenTrust(t, r.base, &thief, in)); st != 200 {
		t.Fatalf("the thief's first-time set: %d %v", st, b)
	}
	// the owner is locked out, as the guide says
	st, b := r.post(t, api.PathApprovalTrust, provenTrustOrPlain(t, r, mine))
	wantRefusal(t, "the owner's set afterwards", st, b, 409, api.CodeTrustAlreadySet)
	ok := r.approve(t, map[string]any{"verb": "power", "action": "shutdown", "delay_s": 60})
	st, b = r.post(t, "/power", map[string]any{"action": "shutdown", "delay_s": 60, "approval": ok})
	wantRefusal(t, "the owner's approval", st, b, 403, api.CodeApprovalRefused)

	// ... and the owner's panel can tell from /metrics alone
	ap := r.approval(t)
	if ap["issuer"] != mine.Issuer || ap["client_id"] != mine.ClientID || ap["users"] != float64(1) {
		t.Fatalf("approval block: %v", ap)
	}
	if ap["trust_hash"] == api.TrustHash(mine) || ap["trust_hash"] != api.TrustHash(api.TrustInit{Issuer: in.Issuer, ClientID: in.ClientID, Keys: in.Keys, Users: in.Users}) {
		t.Fatalf("trust_hash %v does not tell the thief's trust (%s) from the owner's (%s)", ap["trust_hash"], api.TrustHash(in), api.TrustHash(mine))
	}
	if ap["set_by"] != "panel" || ap["set_at"] == nil {
		t.Fatalf("approval block does not say how the trust was set: %v", ap)
	}
	for k, v := range ap {
		if s, _ := v.(string); strings.Contains(s, "thief-user-id") {
			t.Fatalf("the block sends a user id (%s)", k)
		}
	}

	// the repair on the machine (helper-trust set with the owner's values): the hash is the panel's again
	r.setTrustOnTheMachine(t, nil)
	time.Sleep(5200 * time.Millisecond) // the gate looks at the file again within 5 s
	ap = r.approval(t)
	if ap["trust_hash"] != api.TrustHash(mine) || ap["set_by"] != "admin" {
		t.Fatalf("approval block after the repair: %v", ap)
	}
}

// provenTrustOrPlain is in with a proof when the machine still gives a challenge for it, else in as it is.
func provenTrustOrPlain(t *testing.T, r *lrig, in api.TrustInit) api.TrustInit {
	t.Helper()
	st, c := r.post(t, api.PathApprovalChallenge, map[string]any{"verb": api.ApproveTrustSet, "trust_hash": api.TrustHash(in)})
	if st != 200 {
		return in
	}
	return r.iss.Prove(time.Now(), in, api.ApprovalEntry{Challenge: c["challenge"].(string), Request: c["request"].(string)})
}
