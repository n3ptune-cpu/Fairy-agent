package api

// The passkey approval of control actions, as the panel sees it: the two routes, the "approval" field of the
// action routes, the "approval" block of GET /metrics, and the two things the panel has to compute exactly like
// the machine does: the canonical text of a request and the nonce of a list of entries. The checking itself is
// in pkg/approval; nothing here trusts its input.
//
// One approval is one ID token of the Pocket ID client "Fairy PC actions" whose nonce is ApprovalNonce of a list
// of entries, one entry per (machine id, machine challenge, exact request). Each machine checks the token
// offline against the key it has pinned and finds its own entry in the list: the one with a challenge it has
// open, for the request it is about to carry out, hashed with ITS OWN machine id (the one in its trust file),
// whatever the entry says. So an approval that was asked for one machine is not accepted by another, also when
// somebody handed the panel the other machine's challenge.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Approval routes (POST, control token). PathApprovalChallenge has a request budget of its own
// (control_rate_per_min a minute, like the control requests' budget and separate from it): asking for a
// challenge does not use up what the action itself, or POST /power cancel, needs. PathApprovalTrust counts as
// a control request.
const (
	// PathApprovalChallenge: body ApprovalRequest; 200 ChallengeResponse.
	PathApprovalChallenge = "/approval/challenge"
	// PathApprovalTrust: body TrustInit, with the approval that proves the proposed trust works; 200
	// ApprovalStatus. Only while the machine has no trust file.
	PathApprovalTrust = "/approval/trust"
	// PathRunArm: body RunArm (a run ticket: an approval whose list holds a "run_arm ..." entry for this
	// machine); 200 RunAnswer. See "Runs" below.
	PathRunArm = "/run/arm"
	// PathRunGo: body RunGo (the exact run_go request and the approval of a challenge of this machine for it);
	// 200 RunAnswer.
	PathRunGo = "/run/go"
)

// ApprovalProto is the version of the scheme below (canonical text, nonce, token checks). It is the "proto" of
// the "approval" block of GET /metrics; a panel that reads another number does not know this machine's rules.
//
// 2 (2026-11-12): every entry names the machine it is for, and the nonce is made of that too (MachineEntry,
// ApprovalNonce). 1 was the scheme of the test build of 2026-11-11, never released: its nonce had no machine in
// it, and no nonce of 1 equals a nonce of 2.
const ApprovalProto = 2

// Limits. A machine refuses anything beyond them before it looks at the content.
const (
	MaxApprovalToken   = 8192 // bytes of the compact ID token
	MaxApprovalEntries = 64   // entries of one approval
	MaxApprovalRequest = 128  // bytes of one entry's canonical request
	ChallengeLen       = 43   // characters of a challenge: 32 bytes, base64url without padding
	MaxTrustKeys       = 4    // pinned keys
	MaxTrustUsers      = 32   // allowed users
	MinMachineID       = 22   // characters of a machine id: 16 random bytes in base64url (32 in hex)
	MaxMachineID       = 64
)

// Error codes ("code" of a refused request).
const (
	CodeApprovalRequired    = "approval_required"    // 403: this request needs an approval and carried none
	CodeApprovalRefused     = "approval_refused"     // 403: the approval it carried was not accepted
	CodeApprovalUnavailable = "approval_unavailable" // 503: the trust file is there but cannot be used; nothing is approved until an administrator repairs it on the machine
	CodeApprovalDisabled    = "approval_disabled"    // 404: this agent has nothing that checks approvals (Windows without the helper)
	CodeTrustAlreadySet     = "already_set"          // 409: a trust file exists; only an administrator on the machine changes it
	CodeTrustInvalid        = "invalid"              // 400: the trust values were refused
	CodeTrustUnsupportedKey = "unsupported_key"      // 400: a key of a kind, algorithm or size this version does not check
	CodeTrustProofRequired  = "proof_required"       // 403: a first-time set of the trust without the approval that proves it; nothing was written
	CodeTrustProofRefused   = "proof_refused"        // 403: the approval sent with a first-time set does not verify against the proposed trust; nothing was written
	CodeHelperTooOld        = "helper_too_old"       // 409: the Windows helper is older than this protocol
	// CodeTooManyChallenges: 429 from POST /approval/challenge. The machine holds its sixteen open challenges
	// and none of them is old enough (90 s) to be dropped for a new one. In how many seconds to ask again (1 to
	// 90) is in the Retry-After header, in the member "retry_after_s" of the answer, and in its text. A panel
	// that asks for one challenge per machine and action and uses it never sees this.
	CodeTooManyChallenges = "too_many_challenges"
	// CodeApprovalOff: 409 from POST /run/arm and /run/go on a machine without a trust file. A run ticket and
	// a confirmation are passkey approvals; a machine that checks none takes neither, and its part of a run is
	// done as before (POST /update and POST /power without anything).
	CodeApprovalOff = "approval_off"
	// CodeRunRefused: 409 from POST /run/arm and /run/go (and from POST /approval/challenge for run_go): the
	// token may be good, and a rule of runs says no. Which one is the member "reason" of the answer (RunReason...).
	CodeRunRefused = "run_refused"
	// CodeRunUnavailable: 503 from the same routes: the run record on this machine cannot be read or written
	// (or the machine cannot say how long it has been up), so nothing is armed and nothing is confirmed.
	CodeRunUnavailable = "run_unavailable"
)

// ApprovalRuns is the "runs" of the "approval" block: the version of the run scheme below that this machine
// speaks. Absent: an agent (or, on Windows, a helper) from before runs, or a machine that cannot keep a run
// (Windows without the helper). It is not part of ApprovalProto, which stays what it was: every approval that
// existed before is made and checked exactly as before.
const ApprovalRuns = 1

// Runs: approvals inside a wake / update / shutdown run of the panel. Two request texts, both approved by an
// ordinary ID token of the same client, with the same nonce over the same list of entries:
//
//	run_arm run=<16 hex> valid_s=<n> wait_s=<n> notice_s=<n>                 (the run ticket)
//	run_go run=<16 hex> to=<version or -> shutdown_delay_s=<n> within_s=<n>  (the confirmation)
//
// The ticket is the one approval that answers no challenge of the machine: the machine was off when it was
// signed. Its entry carries 32 random bytes of the panel's in the challenge member. The machine accepts it only
// through POST /run/arm, only for what it says (switch yourself off again wait_s after this, with a notice of
// notice_s), and only when it started after the ticket was signed (pkg/approval, Gate.Arm). No challenge is
// ever given for a run_arm text, so a ticket is never the answer to one.
//
// The confirmation answers a challenge of the machine like every other approval (POST /approval/challenge with
// the verb run_go, then POST /run/go). It stops the self-off and lets exactly one POST /update {"run": id} (to
// exactly the version "to"; with "-" none) and one POST /power {"action":"shutdown","delay_s":
// shutdown_delay_s,"run": id} through without a token, in this boot, for within_s seconds.
//
// Limits of the numbers (a text outside them has no canonical form, so nothing can be signed or accepted for it).
const (
	RunValidMinS, RunValidMaxS                 = 120, 600  // valid_s: how old a ticket may be when it is presented (the panel signs 420)
	RunWaitMinS, RunWaitMaxS                   = 120, 3600 // wait_s: from the arming to the start of the self-off
	RunNoticeMinS, RunNoticeMaxS               = 30, 600   // notice_s: the countdown of the self-off (never below power_control.min_delay_s)
	RunWithinMinS, RunWithinMaxS               = 300, 1800 // within_s: how long the confirmation's one update and one shutdown stay good
	RunShutdownDelayMinS, RunShutdownDelayMaxS = 10, 600   // shutdown_delay_s: the delay of that shutdown (never below power_control.min_delay_s)
	// RunArmUptimeS: a ticket arms only a machine that has been up for less than this.
	RunArmUptimeS = 600
	// RunIDLen: a run id is 16 lower-case hex characters (8 random bytes of the panel's).
	RunIDLen = 16
	// RunNoUpdate is the "to" of a confirmation that admits no update, only the shutdown.
	RunNoUpdate = "-"
	// MaxRunVersion: the longest version a confirmation may name.
	MaxRunVersion = 48
)

// Reasons of a run_refused answer (its "reason").
const (
	RunReasonNotFresh      = "not_fresh"         // arm: the machine has been up for RunArmUptimeS or longer (or cannot say)
	RunReasonStartedBefore = "started_before"    // arm: the machine was already running when the ticket was signed
	RunReasonArmedThisBoot = "already_armed"     // arm: a ticket was accepted in this boot already (one per boot, whatever became of it)
	RunReasonRunUsed       = "run_used"          // arm: a ticket of this run was accepted before
	RunReasonPowerPending  = "power_pending"     // arm: a shutdown, reboot or sleep is pending
	RunReasonLimits        = "limits"            // notice_s or shutdown_delay_s is below this machine's power_control.min_delay_s
	RunReasonOtherRun      = "other_run"         // another run is armed or confirmed on this machine
	RunReasonConfirmed     = "already_confirmed" // go: this run is confirmed already
	RunReasonTooLate       = "too_late"          // go: the wait is over, the machine is switching itself off
	RunReasonOver          = "run_over"          // go: this run was armed or confirmed here before and is over (cancelled, finished, or the machine was started again)
	// RunReasonClockBack (arm): this machine's clock is more than two minutes behind a time it showed before. A
	// ticket is judged by the clock (how old it is, whether the machine started after it was signed), so none is
	// taken while the clock is known to have been set back; the machine stays on. See approval.RunClockBack.
	RunReasonClockBack = "clock_back"
)

// Run states (RunStatus.State).
const (
	RunArmed      = "armed"       // a ticket was accepted: the machine switches itself off at OffAt unless it is confirmed or cancelled
	RunConfirmed  = "confirmed"   // the confirmation was accepted: no self-off; one update and one shutdown of the run are let through
	RunOffPending = "off_pending" // the self-off is counting down (the normal delayed shutdown, with its notice)
	RunCancelled  = "cancelled"   // called off: a cancel (panel, the machine itself, helper-run cancel), a veto at the deadline, a changed trust
	RunDone       = "done"        // over: the run's shutdown was let through, or the confirmation's time ran out
)

// RunStatus is the "run" of the "approval" block: the run this machine is in, or was in last in this boot.
type RunStatus struct {
	ID    string `json:"id"`
	State string `json:"state"`
	// OffAt (armed): when the self-off begins, by this machine's clock at the moment of the answer (Unix
	// seconds); the countdown of notice_s starts then. (off_pending): when the countdown ends. The machine
	// counts both on its uptime; this is that moment as today's clock shows it.
	OffAt int64 `json:"off_at,omitempty"`
}

// RunArm is the body of POST /run/arm.
type RunArm struct {
	Approval *Approval `json:"approval"`
}

// RunGo is the body of POST /run/go: the members of the run_go request, exactly as they were sent to POST
// /approval/challenge, and the approval of that challenge.
type RunGo struct {
	Run            string    `json:"run"`
	To             string    `json:"to"`
	ShutdownDelayS *int      `json:"shutdown_delay_s"`
	WithinS        *int      `json:"within_s"`
	Approval       *Approval `json:"approval"`
}

// Request is the run_go request the body names.
func (b RunGo) Request() ApprovalRequest {
	return ApprovalRequest{Verb: ApproveRunGo, Run: &b.Run, To: &b.To, ShutdownDelayS: b.ShutdownDelayS, WithinS: b.WithinS}
}

// RunAnswer is the 200 answer of POST /run/arm and /run/go.
type RunAnswer struct {
	Run   string `json:"run"`
	State string `json:"state"` // RunArmed | RunConfirmed
	// OffInS (armed): in how many seconds the self-off begins (the ticket's wait_s).
	OffInS int `json:"off_in_s,omitempty"`
	// WithinS (confirmed): for how many seconds the one update and the one shutdown are let through.
	WithinS int `json:"within_s,omitempty"`
}

// CheckRunID says whether s can be a run id.
func CheckRunID(s string) error {
	if len(s) != RunIDLen {
		return fmt.Errorf("a run id is %d lower-case hex characters", RunIDLen)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return fmt.Errorf("a run id is %d lower-case hex characters", RunIDLen)
		}
	}
	return nil
}

// checkRunVersion says whether s can be the "to" of a confirmation: RunNoUpdate, or a version of 1 to
// MaxRunVersion characters of A-Z a-z 0-9 . _ + - that does not begin with "-".
func checkRunVersion(s string) error {
	if s == RunNoUpdate {
		return nil
	}
	if len(s) == 0 || len(s) > MaxRunVersion || s[0] == '-' {
		return fmt.Errorf("to must be a version of 1-%d characters, or %q for no update", MaxRunVersion, RunNoUpdate)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '+' || c == '-') {
			return errors.New("to must be made of A-Z a-z 0-9 . _ + - only")
		}
	}
	return nil
}

// Approval states (ApprovalStatus.State).
const (
	ApprovalOff      = "off"      // no trust file: nothing is checked, and the panel may set the trust once
	ApprovalRequired = "required" // trust is set: the requests listed in NeedsApproval need an approval
	ApprovalBroken   = "broken"   // a trust file exists but cannot be used: those requests are refused
	ApprovalUnknown  = "unknown"  // Windows: the helper, which does the checking, is not answering
)

// Who checks (ApprovalStatus.EnforcedBy).
const (
	EnforcedByHelper = "helper" // Windows: the LocalSystem helper; the agent only passes things on
	EnforcedByAgent  = "agent"  // everywhere else: the agent itself
)

// Verbs of an ApprovalRequest: the four requests that need an approval when trust is set, and the one request
// that needs one while there is none: the first-time set of the trust itself.
const (
	ApproveFanSet      = "fan_set"      // POST /fan/duty
	ApproveFanMode     = "fan_mode"     // POST /fan/mode
	ApprovePower       = "power"        // POST /power, every action but cancel
	ApproveApplyUpdate = "apply_update" // POST /update
	ApproveTrustSet    = "trust_set"    // POST /approval/trust (only while the machine has no trust file)
	// The two requests of a run (see "Runs").
	ApproveRunArm = "run_arm" // POST /run/arm: the ticket; never the answer to a challenge
	ApproveRunGo  = "run_go"  // POST /run/go: the confirmation
)

var (
	approveFanModes     = []string{"standard", "full", "optimal", "heavyio"}
	approvePowerActions = []string{"shutdown", "reboot", "sleep"}
)

// ApprovalRequest is one exact request: the body of POST /approval/challenge, and what a challenge is bound to.
type ApprovalRequest struct {
	Verb    string  `json:"verb"`
	Zone    *int    `json:"zone,omitempty"`    // fan_set
	Percent *int    `json:"percent,omitempty"` // fan_set
	Mode    *string `json:"mode,omitempty"`    // fan_mode
	Action  *string `json:"action,omitempty"`  // power: shutdown | reboot | sleep
	DelayS  *int    `json:"delay_s,omitempty"` // power
	// TrustHash (trust_set): TrustHash of the trust the panel is about to propose, 43 characters.
	TrustHash *string `json:"trust_hash,omitempty"`
	// The members of the two run requests (run_arm: run, valid_s, wait_s, notice_s; run_go: run, to,
	// shutdown_delay_s, within_s).
	Run            *string `json:"run,omitempty"`
	ValidS         *int    `json:"valid_s,omitempty"`
	WaitS          *int    `json:"wait_s,omitempty"`
	NoticeS        *int    `json:"notice_s,omitempty"`
	To             *string `json:"to,omitempty"`
	ShutdownDelayS *int    `json:"shutdown_delay_s,omitempty"`
	WithinS        *int    `json:"within_s,omitempty"`
}

// Canonical is the one text form of the request, the "request" of an entry:
//
//	fan_set zone=<0|1> percent=<0-100>
//	fan_mode mode=<standard|full|optimal|heavyio>
//	power action=<shutdown|reboot|sleep> delay_s=<0-86400>
//	apply_update
//	trust_set hash=<43 characters: TrustHash of the proposed trust>
//	run_arm run=<16 hex> valid_s=<120-600> wait_s=<120-3600> notice_s=<30-600>
//	run_go run=<16 hex> to=<version | -> shutdown_delay_s=<10-600> within_s=<300-1800>
//
// ASCII, single spaces, numbers in decimal without sign or leading zeros, the fields in exactly this order.
// Every value is a small number, one word of a fixed list, 43 characters of the base64url alphabet, 16 hex
// characters or a version of A-Z a-z 0-9 . _ + -, so no value can contain a space or "=".
// A request with a missing or an extra field, or a value outside these lists, has no canonical form.
func (r ApprovalRequest) Canonical() (string, error) {
	set := map[string]bool{"zone": r.Zone != nil, "percent": r.Percent != nil, "mode": r.Mode != nil,
		"action": r.Action != nil, "delay_s": r.DelayS != nil, "trust_hash": r.TrustHash != nil,
		"run": r.Run != nil, "valid_s": r.ValidS != nil, "wait_s": r.WaitS != nil, "notice_s": r.NoticeS != nil,
		"to": r.To != nil, "shutdown_delay_s": r.ShutdownDelayS != nil, "within_s": r.WithinS != nil}
	only := func(fields ...string) error {
		for f, present := range set {
			if want := slices.Contains(fields, f); present != want {
				if want {
					return fmt.Errorf("%s needs %s", r.Verb, f)
				}
				return fmt.Errorf("%s does not take %s", r.Verb, f)
			}
		}
		return nil
	}
	switch r.Verb {
	case ApproveFanSet:
		if err := only("zone", "percent"); err != nil {
			return "", err
		}
		if *r.Zone != 0 && *r.Zone != 1 {
			return "", errors.New("zone must be 0 or 1")
		}
		if *r.Percent < 0 || *r.Percent > 100 {
			return "", errors.New("percent must be 0-100")
		}
		return "fan_set zone=" + strconv.Itoa(*r.Zone) + " percent=" + strconv.Itoa(*r.Percent), nil
	case ApproveFanMode:
		if err := only("mode"); err != nil {
			return "", err
		}
		if !slices.Contains(approveFanModes, *r.Mode) {
			return "", errors.New("mode must be standard, full, optimal or heavyio")
		}
		return "fan_mode mode=" + *r.Mode, nil
	case ApprovePower:
		if err := only("action", "delay_s"); err != nil {
			return "", err
		}
		if !slices.Contains(approvePowerActions, *r.Action) {
			return "", errors.New("action must be shutdown, reboot or sleep (cancel needs no approval)")
		}
		if *r.DelayS < 0 || *r.DelayS > 86400 {
			return "", errors.New("delay_s must be 0-86400")
		}
		return "power action=" + *r.Action + " delay_s=" + strconv.Itoa(*r.DelayS), nil
	case ApproveApplyUpdate:
		if err := only(); err != nil {
			return "", err
		}
		return "apply_update", nil
	case ApproveTrustSet:
		if err := only("trust_hash"); err != nil {
			return "", err
		}
		if _, err := decode32(*r.TrustHash); err != nil {
			return "", errors.New("trust_hash must be 43 characters of base64url (32 bytes, no padding)")
		}
		return "trust_set hash=" + *r.TrustHash, nil
	case ApproveRunArm:
		if err := only("run", "valid_s", "wait_s", "notice_s"); err != nil {
			return "", err
		}
		if err := CheckRunID(*r.Run); err != nil {
			return "", err
		}
		for _, n := range []struct {
			name      string
			v, lo, hi int
		}{{"valid_s", *r.ValidS, RunValidMinS, RunValidMaxS}, {"wait_s", *r.WaitS, RunWaitMinS, RunWaitMaxS}, {"notice_s", *r.NoticeS, RunNoticeMinS, RunNoticeMaxS}} {
			if n.v < n.lo || n.v > n.hi {
				return "", fmt.Errorf("%s must be %d-%d", n.name, n.lo, n.hi)
			}
		}
		return "run_arm run=" + *r.Run + " valid_s=" + strconv.Itoa(*r.ValidS) + " wait_s=" + strconv.Itoa(*r.WaitS) + " notice_s=" + strconv.Itoa(*r.NoticeS), nil
	case ApproveRunGo:
		if err := only("run", "to", "shutdown_delay_s", "within_s"); err != nil {
			return "", err
		}
		if err := CheckRunID(*r.Run); err != nil {
			return "", err
		}
		if err := checkRunVersion(*r.To); err != nil {
			return "", err
		}
		if *r.ShutdownDelayS < RunShutdownDelayMinS || *r.ShutdownDelayS > RunShutdownDelayMaxS {
			return "", fmt.Errorf("shutdown_delay_s must be %d-%d", RunShutdownDelayMinS, RunShutdownDelayMaxS)
		}
		if *r.WithinS < RunWithinMinS || *r.WithinS > RunWithinMaxS {
			return "", fmt.Errorf("within_s must be %d-%d", RunWithinMinS, RunWithinMaxS)
		}
		return "run_go run=" + *r.Run + " to=" + *r.To + " shutdown_delay_s=" + strconv.Itoa(*r.ShutdownDelayS) + " within_s=" + strconv.Itoa(*r.WithinS), nil
	}
	return "", errors.New("verb must be fan_set, fan_mode, power, apply_update, trust_set, run_arm or run_go")
}

// ParseRunRequest reads the canonical text of a run request (run_arm or run_go) back into the request. It
// accepts exactly what Canonical writes: the text it returns a request for is that request's canonical form,
// byte for byte. Everything else is refused: another verb, a member missing, twice or in another order, a
// number with a sign, a leading zero or outside its limits, a second space, anything after the last value.
func ParseRunRequest(text string) (ApprovalRequest, error) {
	no := func() (ApprovalRequest, error) {
		return ApprovalRequest{}, errors.New("not the canonical text of a run_arm or run_go request")
	}
	if len(text) > MaxApprovalRequest {
		return no()
	}
	parts := strings.Split(text, " ")
	val := func(i int, name string) (string, bool) {
		return strings.CutPrefix(parts[i], name+"=")
	}
	num := func(i int, name string) (*int, bool) {
		v, ok := val(i, name)
		if !ok || len(v) == 0 || len(v) > 5 {
			return nil, false
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			return nil, false
		}
		return &n, true
	}
	var r ApprovalRequest
	var ok [4]bool
	switch {
	case len(parts) == 5 && parts[0] == ApproveRunArm:
		var run string
		run, ok[0] = val(1, "run")
		r = ApprovalRequest{Verb: ApproveRunArm, Run: &run}
		r.ValidS, ok[1] = num(2, "valid_s")
		r.WaitS, ok[2] = num(3, "wait_s")
		r.NoticeS, ok[3] = num(4, "notice_s")
	case len(parts) == 5 && parts[0] == ApproveRunGo:
		var run, to string
		run, ok[0] = val(1, "run")
		to, ok[1] = val(2, "to")
		r = ApprovalRequest{Verb: ApproveRunGo, Run: &run, To: &to}
		r.ShutdownDelayS, ok[2] = num(3, "shutdown_delay_s")
		r.WithinS, ok[3] = num(4, "within_s")
	default:
		return no()
	}
	if !(ok[0] && ok[1] && ok[2] && ok[3]) {
		return no()
	}
	if canon, err := r.Canonical(); err != nil || canon != text { // "+5", "05", a value outside its limits
		return no()
	}
	return r, nil
}

// MachineEntry is one (machine, challenge, request) triple of an approval: this request, on this machine, for
// this challenge of that machine.
//
// MachineID is the "machine_id" of the machine the entry is for: the id that machine keeps in its trust file
// and shows in its "approval" block. Whoever builds the list (the panel) writes the id it has on record for the
// machine it MEANS, never one that came with the challenge: the challenge is asked over the network and may be
// another machine's, and the id is what ties the approval to the machine the person saw on the screen. The
// machine that checks does not read this member of its own entry: it hashes its own id in its place.
//
// The one entry whose MachineID may be empty is the proof of a first-time set ("trust_set hash=...") that
// proposes no machine id (TrustInit.MachineID absent: the machine picks one).
type MachineEntry struct {
	MachineID string `json:"machine_id"`
	Challenge string `json:"challenge"` // as the machine gave it: 43 characters
	Request   string `json:"request"`   // ApprovalRequest.Canonical
}

// Approval is the "approval" field of POST /fan/mode, /fan/duty, /power and /update: the ID token and the whole
// list its nonce was made from, in the same order.
type Approval struct {
	Token   string         `json:"token"`
	Entries []MachineEntry `json:"entries"`
}

// nonceDomain starts every nonce input: nothing else Fairy hashes begins with it. "v1" was the nonce without a
// machine id (the test build of 2026-11-11); the two differ in this text, so no input of one is an input of the
// other.
const nonceDomain = "fairy-approval-v2"

// trustSetPrefix starts the canonical text of the first-time set of the trust, and of nothing else.
const trustSetPrefix = ApproveTrustSet + " "

// CheckMachineID says whether s can be a machine id: MinMachineID to MaxMachineID characters of the base64url
// alphabet (A-Z a-z 0-9 - _), which hex is a part of. 16 random bytes are 22 characters in base64url and 32 in
// hex. The id is a name, not a secret, and it is compared and hashed as the text it is.
func CheckMachineID(s string) error {
	if len(s) < MinMachineID || len(s) > MaxMachineID {
		return fmt.Errorf("a machine id is %d-%d characters (at least 16 random bytes, in base64url or hex)", MinMachineID, MaxMachineID)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return errors.New("a machine id is made of A-Z a-z 0-9 - _ only")
		}
	}
	return nil
}

// DecodeChallenge returns the 32 bytes of a challenge. Exactly 43 characters of the URL-safe alphabet, no
// padding, no stray bits.
func DecodeChallenge(s string) ([]byte, error) {
	b, err := decode32(s)
	if err != nil {
		return nil, errors.New("a challenge is " + err.Error())
	}
	return b, nil
}

// decode32 returns the 32 bytes of s: exactly 43 characters of the URL-safe alphabet, no padding, no stray
// bits. The error says what s must be.
func decode32(s string) ([]byte, error) {
	if len(s) != ChallengeLen {
		return nil, errors.New("43 characters")
	}
	for i := 0; i < len(s); i++ { // encoding/base64 skips line breaks even in strict mode
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, errors.New("base64url")
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("32 bytes in base64url without padding")
	}
	return b, nil
}

// ApprovalNonce is the nonce of the one Pocket ID request that approves entries:
//
//	base64url_nopad( SHA-256( "fairy-approval-v2" || 0x00 || be32(len(entries)) ||
//	    for each entry, in order: challenge (its 32 bytes) || be32(len(request)) || request ||
//	                              be32(len(machine_id)) || machine_id ) )
//
// be32 is a 4-byte big-endian number; request is the canonical text as bytes, machine_id the id as the text it
// is. Every part has a fixed length or its length in front, so two different lists never give the same input.
// It refuses a list that is empty or longer than MaxApprovalEntries, a malformed challenge, a challenge that is
// in the list twice, a request that is empty, longer than MaxApprovalRequest or not printable ASCII, and a
// machine id that is not one (CheckMachineID). A machine id may be empty in one place only: an entry whose
// request is the first-time set of the trust ("trust_set hash=..."), for a set that proposes no id.
//
// The panel and the machine both call this one function. The panel passes, for each entry, the machine id it
// has on record for the machine it means. The machine passes the list it was sent with its own id written into
// its own entry.
func ApprovalNonce(entries []MachineEntry) (string, error) {
	in, err := nonceInput(entries)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(in)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// nonceInput is what ApprovalNonce hashes: the checks of the list, and the bytes.
func nonceInput(entries []MachineEntry) ([]byte, error) {
	if len(entries) == 0 || len(entries) > MaxApprovalEntries {
		return nil, fmt.Errorf("an approval has 1-%d entries", MaxApprovalEntries)
	}
	in := make([]byte, 0, len(nonceDomain)+5+len(entries)*(32+4+MaxApprovalRequest+4+MaxMachineID))
	in = append(in, nonceDomain...)
	in = append(in, 0)
	in = binary.BigEndian.AppendUint32(in, uint32(len(entries)))
	seen := make(map[[32]byte]bool, len(entries))
	for _, e := range entries {
		c, err := DecodeChallenge(e.Challenge)
		if err != nil {
			return nil, err
		}
		if seen[[32]byte(c)] {
			return nil, errors.New("a challenge is in the list twice")
		}
		seen[[32]byte(c)] = true
		if len(e.Request) == 0 || len(e.Request) > MaxApprovalRequest {
			return nil, fmt.Errorf("a request is 1-%d bytes", MaxApprovalRequest)
		}
		for i := 0; i < len(e.Request); i++ {
			if e.Request[i] < 0x20 || e.Request[i] > 0x7e {
				return nil, errors.New("a request is printable ASCII")
			}
		}
		// every entry names its machine; only the proof of a first-time set that proposes no id has none
		if e.MachineID != "" || !strings.HasPrefix(e.Request, trustSetPrefix) {
			if err := CheckMachineID(e.MachineID); err != nil {
				return nil, err
			}
		}
		in = append(in, c...)
		in = binary.BigEndian.AppendUint32(in, uint32(len(e.Request)))
		in = append(in, e.Request...)
		in = binary.BigEndian.AppendUint32(in, uint32(len(e.MachineID)))
		in = append(in, e.MachineID...)
	}
	return in, nil
}

// ChallengeResponse is the 200 answer of POST /approval/challenge.
type ChallengeResponse struct {
	// Needed: the request needs an approval now. false: send it without one (Reason says why). For trust_set it
	// is always true (or the request is refused: already_set).
	Needed bool `json:"needed"`
	// Reason when not needed: "off" (no trust set), "fan_window" (an approved fan change was applied a moment ago) or
	// "boot_shutdown" (the machine's own setting allows one shutdown shortly after it started).
	Reason string `json:"reason,omitempty"`
	// Request is the canonical text the machine bound the challenge to. The panel compares it with its own.
	Request string `json:"request"`
	// Challenge: 43 characters, single use (needed only).
	Challenge string `json:"challenge,omitempty"`
	// ExpiresInS: seconds until the challenge is dropped (needed only).
	ExpiresInS int `json:"expires_in_s,omitempty"`
	// Issuer and ClientID the machine will accept the token from (needed only; absent for trust_set, where the
	// machine has none yet and the token is checked against the proposed ones).
	Issuer   string `json:"issuer,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// TrustKey is one pinned signing key: an RSA public key as a JWK (RFC 7517) with exactly these members.
type TrustKey struct {
	Kty string `json:"kty"`           // "RSA"
	Kid string `json:"kid"`           // the key id the token header names
	Alg string `json:"alg"`           // "RS256"
	Use string `json:"use,omitempty"` // absent or "sig"
	N   string `json:"n"`             // modulus, base64url without padding, 2048-8192 bits
	E   string `json:"e"`             // "AQAB"
}

// TrustInit is the body of POST /approval/trust: what a machine without a trust file is told to trust. The fan
// window and the shutdown-after-boot setting are not in it: they start at their defaults (30 s, off) and only
// an administrator on the machine changes them.
//
// A first-time set must prove that it works: Approval is an approval of the request "trust_set hash=<TrustHash
// of these four values>" (a challenge of this machine for exactly that request, POST /approval/challenge with
// the verb trust_set), and its token is checked like every approval, against the PROPOSED values: signed by a
// proposed key, "iss" the proposed issuer, "aud" the proposed client, "sub" one of the proposed users, and the
// nonce made with the proposed machine id in this machine's entry. Only then is the trust written. So a wrong
// issuer spelling, client id, user id or key, or a machine whose clock is off, is found out before the machine
// locks, not after; and a proof that was given for one machine id does not set another.
type TrustInit struct {
	Issuer   string     `json:"issuer"`    // https://..., exactly the "iss" of the tokens
	ClientID string     `json:"client_id"` // the Pocket ID client "Fairy PC actions"
	Keys     []TrustKey `json:"keys"`      // 1-MaxTrustKeys
	Users    []string   `json:"users"`     // 1-MaxTrustUsers "sub" values that may approve
	// MachineID is the machine id this machine is to have from now on (CheckMachineID): the panel makes it up,
	// from at least 16 random bytes, and keeps it on record for this machine. Absent or "": the machine makes
	// one up itself and says which in its answer. Either way it is written into the trust file with the first
	// trust and stays as long as that file does. It is not part of TrustHash; what binds it to the proof is the
	// proof's own entry, whose MachineID must be exactly this value (also when it is empty).
	MachineID string `json:"machine_id,omitempty"`
	// Approval is the proof (see above). Without it the set is refused with proof_required.
	Approval *Approval `json:"approval,omitempty"`
}

// trustDomain starts every trust hash input: nothing else Fairy hashes begins with it.
const trustDomain = "fairy-trust-v1"

// TrustHash is the hash of the four values of a proposed trust, the "hash" of the request "trust_set
// hash=...":
//
//	base64url_nopad( SHA-256( "fairy-trust-v1" || 0x00 ||
//	    str(issuer) || str(client_id) ||
//	    be32(number of keys)  || for each key, in the order of "keys":   str(kty) || str(kid) || str(alg) || str(n) || str(e) ||
//	    be32(number of users) || for each user, in the order of "users": str(user) ) )
//
// str(x) is be32(len(x)) || x, the bytes of the string as it is in the JSON body (n and e stay base64url text);
// be32 is a 4-byte big-endian number. A key's "use" is not part of it. The order of keys and users counts: the
// body that is sent must list them in the order that was hashed. Every part has its length in front, so two
// different proposals never give the same input. The values are not checked here. The machine id is not part
// of it (TrustInit.MachineID): two machines that trust the same Pocket ID have the same hash.
func TrustHash(in TrustInit) string {
	h := sha256.New()
	h.Write([]byte(trustDomain))
	h.Write([]byte{0})
	var n [4]byte
	num := func(v int) {
		binary.BigEndian.PutUint32(n[:], uint32(v))
		h.Write(n[:])
	}
	str := func(s string) {
		num(len(s))
		h.Write([]byte(s))
	}
	str(in.Issuer)
	str(in.ClientID)
	num(len(in.Keys))
	for _, k := range in.Keys {
		str(k.Kty)
		str(k.Kid)
		str(k.Alg)
		str(k.N)
		str(k.E)
	}
	num(len(in.Users))
	for _, u := range in.Users {
		str(u)
	}
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// TrustSetRequest is the request a first-time set of in must be approved as: the body of the POST
// /approval/challenge that comes before it.
func TrustSetRequest(in TrustInit) ApprovalRequest {
	hash := TrustHash(in)
	return ApprovalRequest{Verb: ApproveTrustSet, TrustHash: &hash}
}

// ApprovalKey is one pinned key in ApprovalStatus.
type ApprovalKey struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	// Thumbprint: the JWK SHA-256 thumbprint (RFC 7638), base64url without padding, 43 characters.
	Thumbprint string `json:"thumbprint"`
}

// ApprovalStatus is the "approval" block of GET /metrics (absent: an agent from before approvals), the answer
// of POST /approval/trust and what `fairy-agent helper-status` and `helper-trust show` print. No secrets.
type ApprovalStatus struct {
	State      string `json:"state"`
	EnforcedBy string `json:"enforced_by"`
	Proto      int    `json:"proto"`
	// The rest is set while State is required.
	//
	// MachineID is this machine's id: made up when the trust was set for the first time, kept in the trust
	// file, and part of every approval's nonce (MachineEntry). It is a name, not a secret. It is the same
	// until the trust file is removed or an administrator on the machine asks for a new one. What it is worth
	// rests on the panel: the panel keeps each machine's id on record from the first-time set (or from the
	// first time it sees one), builds every entry with the id on record, and treats two machines that show the
	// same id, or a machine whose id is suddenly another, as an alarm. A machine cannot see either by itself.
	MachineID string        `json:"machine_id,omitempty"`
	Issuer    string        `json:"issuer,omitempty"`
	ClientID  string        `json:"client_id,omitempty"`
	Keys      []ApprovalKey `json:"keys,omitempty"`
	Users     int           `json:"users,omitempty"` // how many users may approve
	// TrustHash is TrustHash of what this machine trusts: issuer, client id, keys and users, in the file's
	// order. The user ids themselves are not sent; with the hash a panel can still tell whether the machine
	// trusts exactly what the panel would set (the hash it computed for its own first-time set), users
	// included. A machine whose hash is another one was set by somebody else, or changed on the machine.
	TrustHash string `json:"trust_hash,omitempty"`
	// SetBy says how the trust file came to be: "panel" (a first-time set over the network, by whoever held
	// the control token at that moment) or "admin" (helper-trust set on the machine). SetAt: when (RFC 3339).
	SetBy string `json:"set_by,omitempty"`
	SetAt string `json:"set_at,omitempty"`
	// FanWindowS: after an approved fan change that was applied, further fan changes need none for this long,
	// counted from the moment that approval was accepted (0: off).
	FanWindowS *int `json:"fan_window_s,omitempty"`
	// BootShutdownS: one shutdown without approval is accepted while the machine has been up for less than this
	// (0: off, the default).
	BootShutdownS *int `json:"boot_shutdown_s,omitempty"`
	// Error: why the trust file cannot be used (broken), or why the state is unknown.
	Error string `json:"error,omitempty"`
	// AgentChecks: on a machine where EnforcedBy is the helper, the requests (verbs) this agent process
	// carries out itself, without the helper, and therefore checks itself with the same trust file and the
	// same rules: a Windows agent that drives the fans over the network (ipmi.transport: ipmitool), or one
	// started before the helper was installed. Absent: none, the helper checks everything.
	AgentChecks []string `json:"agent_checks,omitempty"`
	// AgentError: why the agent's own check of AgentChecks cannot be used; those requests are refused.
	AgentError string `json:"agent_error,omitempty"`
	// Runs is ApprovalRuns when whoever checks on this machine takes run tickets and confirmations (POST
	// /run/arm, /run/go, "run" on POST /update and POST /power). Absent: it does not (an older agent or helper,
	// or Windows without the helper); a panel then leaves this machine out of a run, as before.
	Runs int `json:"runs,omitempty"`
	// Run is the run this machine is armed for or confirmed in, or the one that ended last in this boot.
	// Absent: none.
	Run *RunStatus `json:"run,omitempty"`
}
