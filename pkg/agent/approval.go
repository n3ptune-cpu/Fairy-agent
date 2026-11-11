package agent

// The passkey approval of control actions, the agent's part. The protocol is described in pkg/agent/api
// (approval.go); the checking is pkg/approval.
//
// Windows with the helper: the helper checks, and this agent is not trusted by it. The agent only carries the
// challenge, the first-time trust and each request's "approval" field to the helper and the answers back.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
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

// hasApproval reports whether something on this machine checks approvals (else the two routes answer 404
// approval_disabled).
func (a *Agent) hasApproval() bool {
	_, ok := a.helperApproval()
	return ok
}

// approvalStatus is the "approval" block of GET /metrics.
func (a *Agent) approvalStatus(ctx context.Context) (api.ApprovalStatus, bool) {
	if h, ok := a.helperApproval(); ok {
		return h.ApprovalStatus(ctx)
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
	return ""
}

// approvalChallenge is POST /approval/challenge: a challenge for one exact request.
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
	h, _ := a.helperApproval()
	st, body := h.Challenge(r.Context(), req)
	writeJSON(w, st, body)
}

// approvalTrust is POST /approval/trust: the first-time set of the trust. Whoever checks approvals decides; it
// is accepted only while the machine has no trust file.
func (a *Agent) approvalTrust(w http.ResponseWriter, r *http.Request) {
	var in api.TrustInit
	if err := decodeStrictBody(r, &in); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error(), "code": api.CodeTrustInvalid})
		return
	}
	h, _ := a.helperApproval()
	st, body := h.TrustInit(r.Context(), in)
	a.cacheMu.Lock()
	a.cache = nil // the next GET /metrics shows the new state
	a.cacheMu.Unlock()
	writeJSON(w, st, body)
}

// updateApproval decides what POST /update does with the request's approval; false: it answered already.
//
// Windows with the helper: the agent normally starts the updater service with its own right, which the helper
// never sees. So while the helper's check is on, an update needs an approval here already, and the installer
// is then started through the helper, which checks the approval (Updater.ApplyApproved). This is the agent
// keeping to the rule, not the helper enforcing it: an agent process that was taken over can still start the
// updater service itself (which installs only a newer release signed with the release key).
func (a *Agent) updateApproval(w http.ResponseWriter, b *UpdateRequest) bool {
	h, ok := a.helperApproval()
	if !ok || !h.ApprovalNeeded() {
		b.Approval = nil // nothing checks it: as before
		return true
	}
	if b.Approval == nil {
		writeJSON(w, 403, map[string]any{"code": api.CodeApprovalRequired,
			"error": "this needs a passkey approval (Pocket ID) and the request carried none"})
		return false
	}
	return true
}
