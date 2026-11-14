package agent

// The passkey approval of control actions, the agent's part. The protocol is described in pkg/agent/api
// (approval.go); the checking is pkg/approval.
//
// The rule, on every system and with every way of reaching the hardware: while trust is set, each request that
// needs an approval is checked by the program that carries it out.
//
// Windows with the helper: what the helper carries out, the helper checks, and this agent is not trusted by
// it. The agent only carries the challenge, the first-time trust and each request's "approval" field to the
// helper and the answers back (helperRuns).
//
// What this agent process carries out itself, it checks itself (Deps.Approval), with the same trust file, the
// same package and the same rules: everything where there is no helper (every system but Windows), and on
// Windows the parts that do not go through the helper: fans driven over the network (ipmi.transport:
// ipmitool), and power, fans and update of an agent that was started without the helper. On Windows the trust
// file is the helper's and this agent only reads it. The agent's own check protects against a panel that was
// taken over and against a stolen control token; it does not protect against this agent process being taken
// over, because the process is the one that checks.
//
// What needs an approval while trust is set: POST /fan/duty and /fan/mode, POST /power with shutdown, reboot
// or sleep, POST /update. What never does: POST /power cancel, POST /wol and POST /bmc/power (they wake
// machines; the relay has no "off"), POST /helper/stop and /start (the service manager, and stop only hands
// the fans back to the BMC), and everything the agent does by itself with nobody present (the fan watchdog,
// fans to automatic when it stops).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// approvalBody is the largest body of the routes that take an approval: a token of at most 8192 bytes and 64
// entries of about 200 bytes, or a first trust (4 keys of 8192 bits, 32 users).
const approvalBody = 32 << 10

// approvedFan is a FanControl that passes the request's approval on to whoever checks it (the Windows helper).
type approvedFan interface {
	SetModeApproved(ctx context.Context, mode, who string, ap *api.Approval) (int, map[string]any)
	SetDutyApproved(ctx context.Context, zone, percent int, who string, ap *api.Approval) (int, map[string]any)
}

// helperApproval is the helper's approval check when a helper is installed that this agent reaches.
func (a *Agent) helperApproval() (HelperApproval, bool) {
	h, ok := a.d.Helper.(HelperApproval)
	if !ok || a.d.Helper.Status(context.Background()).State == api.HelperNotInstalled {
		return nil, false
	}
	return h, true
}

// approvalVerbs are the requests that need an approval while trust is set.
var approvalVerbs = []string{api.ApproveFanSet, api.ApproveFanMode, api.ApprovePower, api.ApproveApplyUpdate}

// helperRuns reports whether the Windows helper carries out the request verb, and so is the one that checks
// its approval: fans through the helper (ipmi.transport: wmi), power through the helper, and the update of an
// agent that hands approved updates to the helper. Everything else this process carries out itself.
func (a *Agent) helperRuns(verb string) bool {
	switch verb {
	case api.ApproveFanSet, api.ApproveFanMode:
		_, ok := a.d.Fan.(approvedFan)
		return ok
	case api.ApprovePower:
		return a.d.Power != nil && a.d.Power.throughHelper()
	case api.ApproveApplyUpdate:
		return a.d.Updater != nil && a.d.Updater.throughHelper()
	case api.ApproveRunArm, api.ApproveRunGo: // a run is kept by whoever carries out its shutdown
		return a.d.Power != nil && a.d.Power.throughHelper()
	}
	return false
}

// ownChecks are the requests this agent carries out itself, of the parts that are switched on.
func (a *Agent) ownChecks() []string {
	var out []string
	for _, verb := range approvalVerbs {
		if a.featureOff(verb) == "" && !a.helperRuns(verb) {
			out = append(out, verb)
		}
	}
	return out
}

// hasApproval reports whether something on this machine checks approvals (else the two routes answer 404
// approval_disabled): the agent itself where there is no helper; on Windows the helper, or, without one, the
// agent as soon as a trust file is there all the same.
func (a *Agent) hasApproval() bool {
	if a.d.Helper == nil {
		return a.d.Approval != nil
	}
	if _, ok := a.helperApproval(); ok {
		return true
	}
	return a.d.Approval != nil && a.d.Approval.Status().State != api.ApprovalOff
}

// noOwnCheck is the answer when this agent would have to check a request itself and has nothing to check it
// with, on a machine whose helper says that approvals are not off. Run always gives the agent its own check;
// this is what keeps a request from running unchecked if that is ever forgotten.
func noOwnCheck() *approval.Refusal {
	return &approval.Refusal{Status: 503, Code: api.CodeApprovalUnavailable,
		Msg: "this agent carries out this request itself, without the helper, and has nothing to check an approval with, so it is not run"}
}

// ownGateMissing reports whether a request this agent carries out itself must be refused because the agent has
// no check of its own while the machine's helper does not say that approvals are off.
func (a *Agent) ownGateMissing(ctx context.Context) bool {
	if a.d.Approval != nil {
		return false
	}
	h, ok := a.helperApproval()
	if !ok {
		return false // no helper and no gate: nothing on this machine knows approvals (tests of other parts)
	}
	st, ok := h.ApprovalStatus(ctx)
	return ok && st.State != api.ApprovalOff
}

// helperUnchecked says why a request that the helper carries out would run without the check this machine may
// ask for ("": it would not, send it). The agent hands such requests to the helper and relies on the helper's
// check, so it must know that the helper has one: a helper from before approvals (the program that is still
// running after an update that did not restart it) carries out fan and power requests without looking at
// anything. While the helper is not known to check, only "this machine has no trust file", seen by the agent
// itself at this moment, lets the request through: then there is nothing to enforce, and the old helper works
// as it always did. A trust file, a broken one, or a folder the agent cannot look into all refuse.
func (a *Agent) helperUnchecked(ctx context.Context) string {
	h, ok := a.helperApproval()
	if !ok {
		return "" // no helper installed: a request for it fails by itself
	}
	seen, checks := h.Checks(ctx)
	if checks {
		return ""
	}
	own := ""
	if a.d.Approval != nil {
		own = a.d.Approval.StatusNow().State
	}
	if own == api.ApprovalOff {
		return ""
	}
	return uncheckedText(seen, own)
}

// uncheckedText is the sentence for a helper that cannot be relied on to check approvals: seen says whether it
// answered at all since this agent started (then it is one from before approvals), own is what the agent itself
// sees of the trust file ("": it has no check of its own).
func uncheckedText(seen bool, own string) string {
	why := "the fairy-agent-helper has not answered since this agent started, so it is not known whether it checks passkey approvals"
	if seen {
		why = "the running fairy-agent-helper is older than this agent: it does not know this version's passkey approvals, and what it is sent it may carry out unchecked"
	}
	switch own {
	case api.ApprovalRequired:
		why += ", and this machine has an approval trust file"
	case api.ApprovalBroken:
		why += ", and this machine's approval trust file cannot be used"
	default:
		why += ", and this agent cannot tell whether this machine has an approval trust file"
	}
	return why + " (restart the helper: POST " + api.PathHelperStop + ", then " + api.PathHelperStart + ", or Restart-Service fairy-agent-helper on the machine; if it is still older after that, install this version of both services)"
}

// Gated is the passkey check of one request, handed to the part that carries the request out (Fan, Power,
// Updater). That part calls it once, at the moment the request has passed every check of its own and the next
// step is the system call or the BMC command. A refusal: nothing is carried out, and the answer is the
// refusal's. Otherwise the request is carried out, and a fan change that was applied tells the pass so
// (approval.Pass.Applied). The approval's challenge, or the one shutdown after boot, is used up inside this
// call and not before, so a request that fails a check of its own costs neither.
type Gated func() (*approval.Pass, *approval.Refusal)

// retryAfterMember is the member of a refusal's body that says in how many seconds to ask again. It is always
// sent together with the Retry-After header of the same value (retryAfter).
const retryAfterMember = "retry_after_s"

// refusalBody is the JSON body of a refusal.
func refusalBody(ref *approval.Refusal) map[string]any {
	body := map[string]any{"error": ref.Msg}
	if ref.Code != "bad_request" {
		body["code"] = ref.Code
	}
	if ref.RetryAfterS > 0 {
		body[retryAfterMember] = ref.RetryAfterS
	}
	if ref.Reason != "" {
		body["reason"] = ref.Reason
	}
	return body
}

// retryAfter sets the Retry-After header of an answer whose body says when to ask again (retryAfterMember):
// the refusal of the agent's own gate, and the helper's, which reaches the agent as such a body.
func retryAfter(w http.ResponseWriter, body any) {
	if m, ok := body.(map[string]any); ok {
		if n, ok := m[retryAfterMember].(int); ok && n > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(n))
		}
	}
}

// approved is the passkey check of a request that changes something, in two steps.
//
// The first step is here, when the request arrives; false: it answered already and nothing may run. What the
// helper carries out, the helper checks when the request reaches it, so that passes here, unless the helper is
// not known to check at all while this machine may have a trust file (helperUnchecked): then the request is
// refused here and never reaches the helper. What this process carries out itself is asked of the agent's own
// gate, which at this point uses nothing up (approval.Gate.Precheck): it refuses a request that needs an
// approval and carries none, and everything while the trust file cannot be used.
//
// The second step is the Gated that is returned (nil where the helper checks): the part that carries the
// request out calls it when the request has passed its own checks (approval.Gate.Admit). There the approval is
// verified and its challenge used up, or the one shutdown after boot recorded.
func (a *Agent) approved(w http.ResponseWriter, r *http.Request, req api.ApprovalRequest, ap *api.Approval) (Gated, bool) {
	ctx := r.Context()
	if a.helperRuns(req.Verb) {
		if why := a.helperUnchecked(ctx); why != "" {
			a.logOnce("unchecked-helper", "approval: request for the helper refused, the helper does not check approvals", "verb", req.Verb, "reason", why)
			writeRefusal(w, &approval.Refusal{Status: 503, Code: api.CodeApprovalUnavailable, Msg: "not run: " + why})
			return nil, false
		}
		return nil, true
	}
	if _, ref := a.ownCheck(ctx, req, ap, false); ref != nil {
		writeRefusal(w, ref)
		return nil, false
	}
	return func() (*approval.Pass, *approval.Refusal) { return a.ownCheck(ctx, req, ap, true) }, true
}

// ownCheck asks the agent's own gate about a request this process carries out: when it arrives (final false:
// Precheck) and when it is about to be carried out (final true: Admit).
func (a *Agent) ownCheck(ctx context.Context, req api.ApprovalRequest, ap *api.Approval, final bool) (*approval.Pass, *approval.Refusal) {
	var pass *approval.Pass
	var ref *approval.Refusal
	switch {
	case a.ownGateMissing(ctx):
		ref = noOwnCheck()
	case final:
		pass, ref = a.d.Approval.Admit(req, ap)
	default:
		ref = a.d.Approval.Precheck(req, ap != nil)
	}
	if ref != nil && ref.Code == api.CodeApprovalUnavailable && a.helperSaysOff(ctx) {
		return nil, nil
	}
	return pass, ref
}

// helperSaysOff reports whether the helper, asked at this moment, says that this machine has no trust file.
// It is for one case only: this agent's own look at the trust file fails (its low-rights account cannot run
// the checks on the helper's folder), while the helper, whose file it is and who can, sees that there is none.
// Then there is nothing to enforce, and what the agent carries out itself runs as it does without trust,
// instead of being refused on every machine that never set one. With a trust file, or a helper that does not
// answer, the agent's own failure stays a refusal.
func (a *Agent) helperSaysOff(ctx context.Context) bool {
	h, ok := a.helperApproval()
	if !ok {
		return false
	}
	st, known := h.ApprovalNow(ctx)
	return known && st.State == api.ApprovalOff
}

func writeRefusal(w http.ResponseWriter, ref *approval.Refusal) {
	body := refusalBody(ref)
	retryAfter(w, body)
	writeJSON(w, ref.Status, body)
}

// approvalStatus is the "approval" block of GET /metrics. Where the helper checks, it is the helper's, with
// the requests this agent checks itself named in it ("agent_checks"): the block says who enforces what.
func (a *Agent) approvalStatus(ctx context.Context) (api.ApprovalStatus, bool) {
	if a.d.Helper == nil { // not Windows: this agent is the checker
		if a.d.Approval == nil {
			return api.ApprovalStatus{}, false
		}
		return a.d.Approval.Status(), true
	}
	if h, ok := a.helperApproval(); ok {
		if st, ok := h.ApprovalStatus(ctx); ok {
			if own := a.ownChecks(); len(own) > 0 {
				st.AgentChecks = own
				switch {
				case a.d.Approval == nil:
					st.AgentError = "this agent has no check of its own; these requests are refused while approval is not off"
				default:
					if os := a.d.Approval.Status(); os.State == api.ApprovalBroken {
						st.AgentError = os.Error
					}
				}
			}
			return st, true
		}
	}
	// Windows without a helper that knows approvals.
	own := api.ApprovalStatus{}
	if a.d.Approval != nil {
		own = a.d.Approval.Status()
	}
	if own.State == api.ApprovalOff {
		return api.ApprovalStatus{}, false // and no trust file: nothing is checked and nothing asks for it, as before
	}
	if h, ok := a.helperApproval(); ok {
		// A helper from before approvals is installed (an update that has not restarted it yet), and this
		// machine has a trust file, or the agent cannot tell. Nobody enforces what the file asks for where
		// the helper carries requests out, so those are refused (approved, updateApproval), and the block
		// says exactly that: "unknown", not the agent's own "required".
		seen, _ := h.Checks(ctx)
		st := api.ApprovalStatus{State: api.ApprovalUnknown, EnforcedBy: api.EnforcedByHelper, Proto: api.ApprovalProto,
			Error: uncheckedText(seen, own.State)}
		if checks := a.ownChecks(); len(checks) > 0 {
			st.AgentChecks = checks
			switch {
			case a.d.Approval == nil:
				st.AgentError = "this agent has no check of its own; these requests are refused while approval is not off"
			case own.State == api.ApprovalBroken:
				st.AgentError = own.Error
			}
		}
		return st, true
	}
	// No helper at all, and a trust file is there all the same (the helper was removed after trust was set):
	// this agent checks what it carries out.
	if a.d.Approval != nil {
		return own, true
	}
	return api.ApprovalStatus{}, false
}

// decodeStrictBody reads a body that must be exactly one JSON object with no member v does not have, no
// member twice and no member spelled in another way than its name (strictBodyFor).
func decodeStrictBody(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body too large")
	}
	if err := strictBodyFor(b, v); err != nil && err.Error() != "invalid JSON body" { // those two keep their texts below
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("invalid JSON body (or a member this request does not take)")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("invalid JSON body: data after the object")
	}
	return nil
}

// featureOff is the 404 answer when the part a request is for is switched off on this agent ("": it is on).
func (a *Agent) featureOff(verb string) string {
	switch {
	case (verb == api.ApproveFanSet || verb == api.ApproveFanMode) && a.d.Fan == nil:
		return "fan_control_disabled"
	case (verb == api.ApprovePower || verb == api.ApproveRunArm || verb == api.ApproveRunGo) && a.d.Power == nil:
		return "power_control_disabled" // a run ends with a shutdown
	case verb == api.ApproveApplyUpdate && a.d.Updater == nil:
		return "self_update_disabled"
	}
	return "" // also trust_set: no part to switch off
}

func approvalDisabled(w http.ResponseWriter) {
	writeJSON(w, 404, map[string]any{"error": "approval is disabled on this agent", "code": api.CodeApprovalDisabled})
}

// approvalChallenge is POST /approval/challenge: a challenge for one exact request, from whoever will check
// its approval: the helper for what the helper carries out and for the first-time set of the trust (the trust
// file is the helper's), this agent for what it carries out itself.
func (a *Agent) approvalChallenge(w http.ResponseWriter, r *http.Request) {
	var req api.ApprovalRequest
	if err := decodeStrictBody(r, &req); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if _, err := req.Canonical(); err != nil {
		writeJSON(w, 400, map[string]any{"error": "not a request that can be approved: " + err.Error()})
		return
	}
	if req.Verb == api.ApproveRunArm { // the same answer whoever checks on this machine: no challenge is given for a ticket
		writeJSON(w, 400, map[string]any{"error": "a run ticket (run_arm) answers no challenge: it is sent to POST " + api.PathRunArm})
		return
	}
	if code := a.featureOff(req.Verb); code != "" {
		writeJSON(w, 404, map[string]any{"error": "that is disabled on this agent", "code": code})
		return
	}
	h, viaHelper := a.helperApproval()
	if viaHelper && req.Verb != api.ApproveTrustSet && !a.helperRuns(req.Verb) {
		viaHelper = false // a helper is here, and this request is one the agent carries out itself
	}
	if viaHelper {
		st, body := h.Challenge(r.Context(), req)
		retryAfter(w, body)
		writeJSON(w, st, body)
		return
	}
	switch {
	case a.ownGateMissing(r.Context()):
		writeRefusal(w, noOwnCheck())
	case a.d.Approval == nil:
		approvalDisabled(w)
	default:
		c, ref := a.d.Approval.Challenge(req)
		if ref != nil && ref.Code == api.CodeApprovalUnavailable && req.Verb != api.ApproveTrustSet && a.helperSaysOff(r.Context()) {
			c, ref = api.ChallengeResponse{Reason: "off", Request: c.Request}, nil // as approved: no trust file, says the helper
		}
		if ref != nil {
			writeRefusal(w, ref)
			return
		}
		writeJSON(w, 200, c)
	}
}

// approvalTrust is POST /approval/trust: the first-time set of the trust, with the approval that proves it.
// Whoever owns the trust file decides (Windows: the helper; elsewhere this agent); it is accepted only while
// the machine has no trust file.
func (a *Agent) approvalTrust(w http.ResponseWriter, r *http.Request) {
	var in api.TrustInit
	if err := decodeStrictBody(r, &in); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "code": api.CodeTrustInvalid})
		return
	}
	defer func() {
		a.cacheMu.Lock()
		a.cache = nil // the next GET /metrics shows the new state
		a.cacheMu.Unlock()
	}()
	if h, ok := a.helperApproval(); ok {
		st, body := h.TrustInit(r.Context(), in)
		if a.d.Approval != nil {
			// The helper may have written the trust file a moment ago. What this agent carries out itself is
			// checked by its own gate, which would otherwise look at the file again only within five seconds.
			a.d.Approval.StatusNow()
		}
		writeJSON(w, st, body)
		return
	}
	if a.d.Approval == nil {
		approvalDisabled(w)
		return
	}
	// not Windows: this agent writes the trust file. Windows without the helper: the agent's gate only reads
	// (already_set when a trust file is there, else it says that the trust is set on the machine).
	st, ref := a.d.Approval.Init(in)
	if ref != nil {
		writeRefusal(w, ref)
		return
	}
	writeJSON(w, 200, st)
}

// helperCheckState is what an update that goes through the helper has to go by, found out now, when the
// request is here: api.ApprovalOff (nothing is checked), api.ApprovalRequired (the helper checks an approval),
// or api.ApprovalBroken / api.ApprovalUnknown with the reason (nothing can be approved).
//
// The helper's own answer counts when it answers at this moment. When it does not (stopped, starting, the
// agent started before it, its pipe is down), the agent looks at the trust file itself, and only "there is no
// trust file, in a folder that passes its check" counts as off. A helper that cannot be reached is never taken
// as "approval is off".
func (a *Agent) helperCheckState(ctx context.Context) (string, string) {
	own := ""
	if a.d.Approval != nil {
		own = a.d.Approval.StatusNow().State
	}
	h, ok := a.helperApproval()
	if ok {
		if st, known := h.ApprovalNow(ctx); known {
			if st.State == api.ApprovalOff && own == api.ApprovalRequired {
				return api.ApprovalRequired, "" // set on the machine a moment ago; the helper reads it within seconds
			}
			return st.State, st.Error
		}
	}
	if own == api.ApprovalOff {
		return api.ApprovalOff, ""
	}
	if ok {
		if seen, checks := h.Checks(ctx); seen && !checks { // it answers, and it is one from before approvals
			return api.ApprovalUnknown, uncheckedText(true, own)
		}
	}
	why := "the helper, which checks the approval of an update on this machine, is not answering"
	switch own {
	case api.ApprovalRequired:
		why += ", and this machine has an approval trust file"
	case api.ApprovalBroken:
		why += ", and this machine's approval trust file cannot be used"
	default:
		why += ", so whether an update needs an approval is not known"
	}
	return api.ApprovalUnknown, why + " (start it: POST /helper/start, or Start-Service fairy-agent-helper on the machine)"
}

// updateApproval decides what POST /update does with the request's approval where approved updates go through
// the helper (Windows with the helper); false: it answered already.
//
// The agent normally starts the updater service with its own right, which the helper never sees. So while
// approvals are not off, an update needs an approval here already, and the installer is then started through
// the helper, which checks the approval (Updater.ApplyApproved). When the state cannot be established, or the
// trust file is broken, the update is refused: nothing is downloaded and nothing is started. This is the
// agent keeping to the rule, not the helper enforcing it: an agent process that was taken over can still
// start the updater service itself (which installs only a newer release signed with the release key).
func (a *Agent) updateApproval(w http.ResponseWriter, r *http.Request, b *UpdateRequest) bool {
	state, why := a.helperCheckState(r.Context())
	switch state {
	case api.ApprovalOff:
		b.Approval, b.Run = nil, "" // nothing checks it: as before
		return true
	case api.ApprovalRequired:
		if b.Approval == nil && b.Run != "" {
			return a.updateOfRun(w, r, b)
		}
		if b.Approval == nil {
			writeJSON(w, 403, map[string]any{"code": api.CodeApprovalRequired,
				"error": "this needs a passkey approval (Pocket ID) and the request carried none"})
			return false
		}
		// Before anything is downloaded, this agent looks at the approval itself, with its own (read-only) look
		// at the helper's trust file, and uses nothing up (approval.Gate.Preverify): an approval the helper is
		// certain to refuse is refused here, at the point and with the answer of an agent that checks itself
		// (Updater.Start asks b.Gate after its own checks). Without this, any "approval" member made the agent
		// download the release, and the owner's update was answered 409 meanwhile (audit 5, r2-a1-03). The
		// helper still checks the approval in full and is the only one that uses it up; where this agent
		// cannot read the trust file, everything is as before.
		if ap, gate := b.Approval, a.d.Approval; gate != nil {
			b.Gate = func() (*approval.Pass, *approval.Refusal) {
				_, ref := gate.Preverify(api.ApprovalRequest{Verb: api.ApproveApplyUpdate}, ap)
				return nil, ref
			}
		}
		return true
	}
	if why == "" {
		why = "the approval trust file on this machine cannot be used"
	}
	writeJSON(w, 503, map[string]any{"code": api.CodeApprovalUnavailable, "error": "the update was not started: " + why})
	return false
}

// approvedRun is approved for a request that carries no approval and names a confirmed run in its place
// (POST /power shutdown with "run"): the two steps, asked of whoever keeps the run. Where the helper carries
// the request out, the helper does (the run id goes to it with the request). Where this process does, its own
// gate: approval.Gate.RunCovers when the request arrives, which uses nothing up, and AdmitRun when the request
// has passed its own checks, which uses the run's one shutdown up. A request the run does not cover is refused
// like every request without approval; the fan window and the shutdown after boot are not asked.
func (a *Agent) approvedRun(w http.ResponseWriter, r *http.Request, req api.ApprovalRequest, run string) (Gated, bool) {
	ctx := r.Context()
	if a.helperRuns(req.Verb) {
		if why := a.helperUnchecked(ctx); why != "" {
			a.logOnce("unchecked-helper", "approval: request for the helper refused, the helper does not check approvals", "verb", req.Verb, "reason", why)
			writeRefusal(w, &approval.Refusal{Status: 503, Code: api.CodeApprovalUnavailable, Msg: "not run: " + why})
			return nil, false
		}
		return nil, true
	}
	check := func(final bool) *approval.Refusal {
		var ref *approval.Refusal
		switch {
		case a.ownGateMissing(ctx):
			ref = noOwnCheck()
		case final:
			_, ref = a.d.Approval.AdmitRun(req, run)
		default:
			_, ref = a.d.Approval.RunCovers(req, run)
		}
		if ref != nil && ref.Code == api.CodeApprovalUnavailable && a.helperSaysOff(ctx) {
			return nil // as ownCheck: no trust file, says the helper
		}
		return ref
	}
	if ref := check(false); ref != nil {
		writeRefusal(w, ref)
		return nil, false
	}
	return func() (*approval.Pass, *approval.Refusal) { return nil, check(true) }, true
}

// updateOfRun is updateApproval for a request without approval that names a run, on a machine whose helper
// keeps the run: before anything is downloaded this agent looks at the run record itself (its read-only look
// at the helper's folder; nothing is used up), refuses what the run does not cover, and learns the version the
// confirmation named. The installer is then started through the helper, which uses the run's one update up
// (Updater.ApplyRun). Like the rule that an update needs an approval at all, the version is the agent's check;
// that the installer installs only a newer release signed with the release key is the installer's.
func (a *Agent) updateOfRun(w http.ResponseWriter, r *http.Request, b *UpdateRequest) bool {
	gate := a.d.Approval
	if gate == nil {
		writeRefusal(w, noOwnCheck())
		return false
	}
	req, run, pin := api.ApprovalRequest{Verb: api.ApproveApplyUpdate}, b.Run, ""
	look := func() (*approval.Pass, *approval.Refusal) {
		to, ref := gate.RunCovers(req, run)
		pin = to
		return nil, ref
	}
	if _, ref := look(); ref != nil {
		writeRefusal(w, ref)
		return false
	}
	b.Gate, b.Pin = look, &pin
	return true
}

// runArm is POST /run/arm: a run ticket, to whoever keeps runs on this machine (Windows: the helper;
// elsewhere this agent, on Linux).
func (a *Agent) runArm(w http.ResponseWriter, r *http.Request) {
	var b api.RunArm
	if err := decodeStrictBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	if b.Approval == nil {
		writeJSON(w, 400, map[string]any{"error": "a run ticket is an approval: the body needs \"approval\""})
		return
	}
	a.runRequest(w, r, api.ApproveRunArm, func(h HelperRuns) (int, any) { return h.RunArm(r.Context(), b.Approval) },
		func(rw *approval.RunWatch) (api.RunAnswer, *approval.Refusal) { return rw.Arm(b.Approval) })
}

// runGo is POST /run/go: the confirmation of a run.
func (a *Agent) runGo(w http.ResponseWriter, r *http.Request) {
	var b api.RunGo
	if err := decodeStrictBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	req := b.Request()
	if b.ShutdownDelayS == nil || b.WithinS == nil {
		writeJSON(w, 400, map[string]any{"error": "not a run confirmation: run, to, shutdown_delay_s and within_s are needed"})
		return
	}
	if _, err := req.Canonical(); err != nil {
		writeJSON(w, 400, map[string]any{"error": "not a run confirmation: " + err.Error()})
		return
	}
	a.runRequest(w, r, api.ApproveRunGo, func(h HelperRuns) (int, any) { return h.RunGo(r.Context(), b) },
		func(rw *approval.RunWatch) (api.RunAnswer, *approval.Refusal) { return rw.Go(req, b.Approval) })
}

// runRequest hands a run request to whoever keeps runs here and writes the answer.
func (a *Agent) runRequest(w http.ResponseWriter, r *http.Request, verb string, viaHelper func(HelperRuns) (int, any),
	own func(*approval.RunWatch) (api.RunAnswer, *approval.Refusal)) {
	if code := a.featureOff(verb); code != "" {
		writeJSON(w, 404, map[string]any{"error": "a run ends with a shutdown, and power control is disabled on this agent", "code": code})
		return
	}
	defer a.cacheOld.Store(true) // the next GET /metrics shows the run
	if h, ok := a.helperApproval(); ok && a.helperRuns(verb) {
		hr, ok := h.(HelperRuns)
		if !ok {
			writeRefusal(w, approval.NoRuns())
			return
		}
		st, body := viaHelper(hr)
		writeJSON(w, st, body)
		return
	}
	if a.d.Runs == nil { // Windows without the helper, or a system whose uptime the agent cannot read
		writeRefusal(w, approval.NoRuns())
		return
	}
	ans, ref := own(a.d.Runs)
	if ref != nil {
		writeRefusal(w, ref)
		return
	}
	writeJSON(w, 200, ans)
}
