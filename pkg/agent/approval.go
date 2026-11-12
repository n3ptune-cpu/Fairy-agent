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
		why = "the running fairy-agent-helper is older than this agent: it knows no passkey approvals and carries out what it is sent unchecked"
	}
	switch own {
	case api.ApprovalRequired:
		why += ", and this machine has an approval trust file"
	case api.ApprovalBroken:
		why += ", and this machine's approval trust file cannot be used"
	default:
		why += ", and this agent cannot tell whether this machine has an approval trust file"
	}
	return why + " (restart the helper: POST " + api.PathHelperStop + ", then " + api.PathHelperStart + ", or Restart-Service fairy-agent-helper on the machine)"
}

// approved is the passkey check of a request that changes something; false: it answered already and nothing
// may run. What the helper carries out, the helper checks when the request reaches it, so that passes here,
// unless the helper is not known to check at all while this machine may have a trust file (helperUnchecked):
// then the request is refused here and never reaches the helper.
// What this process carries out itself is checked here, by the agent's own gate, and the approval's challenge
// is used up before the request is carried out.
//
// The pass is for the fan routes: they tell it when the change was applied (approval.Pass.Applied), which is
// what opens the fan window. It is nil where the helper checks (the helper opens its own window).
func (a *Agent) approved(w http.ResponseWriter, r *http.Request, req api.ApprovalRequest, ap *api.Approval) (*approval.Pass, bool) {
	if a.helperRuns(req.Verb) {
		if why := a.helperUnchecked(r.Context()); why != "" {
			a.logOnce("unchecked-helper", "approval: request for the helper refused, the helper does not check approvals", "verb", req.Verb, "reason", why)
			writeRefusal(w, &approval.Refusal{Status: 503, Code: api.CodeApprovalUnavailable, Msg: "not run: " + why})
			return nil, false
		}
		return nil, true
	}
	var pass *approval.Pass
	var ref *approval.Refusal
	if a.ownGateMissing(r.Context()) {
		ref = noOwnCheck()
	} else {
		pass, ref = a.d.Approval.Admit(req, ap)
	}
	if ref == nil || (ref.Code == api.CodeApprovalUnavailable && a.helperSaysOff(r.Context())) {
		return pass, true
	}
	writeRefusal(w, ref)
	return nil, false
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
	body := map[string]any{"error": ref.Msg}
	if ref.Code != "bad_request" {
		body["code"] = ref.Code
	}
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

// decodeStrictBody reads a body that must be exactly one JSON object with no member v does not have.
func decodeStrictBody(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body too large")
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
	case verb == api.ApprovePower && a.d.Power == nil:
		return "power_control_disabled"
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
		b.Approval = nil // nothing checks it: as before
		return true
	case api.ApprovalRequired:
		if b.Approval == nil {
			writeJSON(w, 403, map[string]any{"code": api.CodeApprovalRequired,
				"error": "this needs a passkey approval (Pocket ID) and the request carried none"})
			return false
		}
		return true
	}
	if why == "" {
		why = "the approval trust file on this machine cannot be used"
	}
	writeJSON(w, 503, map[string]any{"code": api.CodeApprovalUnavailable, "error": "the update was not started: " + why})
	return false
}
