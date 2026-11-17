package agent

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// uninstallStartTimeout bounds the start of the removal (Linux: one systemctl call that does not wait).
const uninstallStartTimeout = 30 * time.Second

// Uninstaller removes this agent's services from the machine: what POST /uninstall (the panel's "Uninstall
// agent") sets going once its approval holds.
type Uninstaller interface {
	// Start sets the removal going and returns as soon as it is under way. It never waits for the removal,
	// which stops this very process. Linux: `systemctl start --no-block fairy-agent-uninstall.service`, the
	// fixed root unit that the polkit rule lets this user start and nothing else.
	Start(ctx context.Context) error
	// ThroughHelper reports whether the Windows helper carries it out (and so checks its approval itself).
	ThroughHelper() bool
}

// HelperUninstall is the Uninstaller of a system where the helper checks the approval and carries the
// uninstall out (Windows). The agent hands it the approval and does not look inside; the answer is the
// helper's, as an HTTP status and body.
type HelperUninstall interface {
	Uninstaller
	Ask(ctx context.Context, by string, ap *api.Approval) (int, any)
}

// uninstallOn reports whether POST /uninstall is open: switched on in config.yaml (Run builds an Uninstaller
// only then) and something on this system can carry it out.
func (a *Agent) uninstallOn() bool { return a.d.Uninstaller != nil }

// uninstallGateOff reports whether this agent's own passkey check says "no trust file" (or there is none at
// all): uninstall is then 409 approval_off. As for a plug socket (socketGate), never "let it through": the
// request did not exist before approvals.
func (a *Agent) uninstallGateOff(ctx context.Context) bool {
	return a.socketGate(ctx, true) == api.WhyApprovalOff
}

// uninstallChallenge is POST /approval/challenge for an uninstall this agent checks itself. It never answers
// "needs no approval": a machine without a trust file is 409 approval_off, where fans, power and updates are
// told "needed: false, reason: off" (approvalChallenge).
func (a *Agent) uninstallChallenge(w http.ResponseWriter, r *http.Request, req api.ApprovalRequest) {
	if a.uninstallGateOff(r.Context()) {
		slog.Warn("uninstall: no challenge given", "reason", api.CodeApprovalOff, "remote", clientIP(r))
		writeRefusal(w, approval.Off())
		return
	}
	c, ref := a.d.Approval.Challenge(req) // not nil: uninstallGateOff says approval_off for an agent without a gate
	if ref != nil {
		writeRefusal(w, ref)
		return
	}
	writeJSON(w, 200, c)
}

// uninstall is POST /uninstall.
//
// The order keeps a refused request from costing anything and from touching the machine:
//
//  1. Handler has checked the method, the control token, that uninstall is on (404 otherwise), the budget and
//     the body's size.
//  2. The body is strict JSON with no member it does not have (400).
//  3. The passkey check, looked at and not used up: no trust file, or no gate, is 409 approval_off; a trust
//     file that cannot be used is 503; no approval is 403 approval_required; one that does not hold, or lists
//     more than this one entry, is 403 approval_refused. Like the plug switch, this never goes through
//     approved(), whose "the helper says there is no trust file: let it through" is wrong for this request.
//  4. One at a time, once: a second request while one was started by this process is 409, before its approval
//     is used.
//  5. The gate's Admit uses the approval up; only then is the removal started.
//
// Every request that got past step 1 is logged at WARN with what became of it, never with a token.
func (a *Agent) uninstall(w http.ResponseWriter, r *http.Request) {
	remote := clientIP(r)
	var b api.UninstallRequest
	if err := decodeStrictBody(r, &b); err != nil {
		slog.Warn("uninstall: refused", "reason", "bad_request", "remote", remote)
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	who := cleanWho(b.RequestedBy)
	refused := func(code string) {
		slog.Warn("uninstall: refused", "reason", code, "requested_by", who, "remote", remote)
	}
	if hu, ok := a.d.Uninstaller.(HelperUninstall); ok && hu.ThroughHelper() {
		a.uninstallThroughHelper(w, r, hu, b, who, remote)
		return
	}
	req := api.ApprovalRequest{Verb: api.ApproveUninstall}
	if a.uninstallGateOff(r.Context()) {
		refused(api.CodeApprovalOff)
		writeRefusal(w, approval.Off())
		return
	}
	if ref := a.d.Approval.Look(req, b.Approval); ref != nil {
		refused(ref.Code)
		writeRefusal(w, ref)
		return
	}
	if !a.uninstallOnce.CompareAndSwap(false, true) {
		refused(api.CodeUninstallBusy)
		writeJSON(w, 409, map[string]any{"error": "an uninstall was already started on this machine", "code": api.CodeUninstallBusy})
		return
	}
	if _, ref := a.d.Approval.Admit(req, b.Approval); ref != nil {
		a.uninstallOnce.Store(false) // nothing was started: a request with a good approval may come
		refused(ref.Code)
		writeRefusal(w, ref)
		return
	}
	// The request's own context ends with the answer; the start must not.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), uninstallStartTimeout)
	defer cancel()
	if err := a.d.Uninstaller.Start(ctx); err != nil {
		a.uninstallOnce.Store(false)
		slog.Error("uninstall: approved, but the removal could not be started", "requested_by", who, "remote", remote, "error", safeErr(err))
		writeJSON(w, 502, map[string]any{"error": "the removal could not be started: " + safeErr(err)})
		return
	}
	slog.Warn("uninstall: approved and started, this agent is being removed", "requested_by", who, "remote", remote)
	writeJSON(w, 202, map[string]any{"state": api.UninstallStarted})
}

// uninstallThroughHelper is POST /uninstall where the helper checks the approval (Windows). The agent checks
// nothing of the approval itself: the helper owns the trust file and refuses without one (approval_off), and
// keeps its own once. Here only the agent's own once is kept, so a second request is refused before it costs
// the helper anything.
func (a *Agent) uninstallThroughHelper(w http.ResponseWriter, r *http.Request, hu HelperUninstall, b api.UninstallRequest, who, remote string) {
	if !a.uninstallOnce.CompareAndSwap(false, true) {
		slog.Warn("uninstall: refused", "reason", api.CodeUninstallBusy, "requested_by", who, "remote", remote)
		writeJSON(w, 409, map[string]any{"error": "an uninstall was already started on this machine", "code": api.CodeUninstallBusy})
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), uninstallStartTimeout)
	defer cancel()
	st, body := hu.Ask(ctx, "panel "+remote+" "+who, b.Approval)
	if st != 200 {
		a.uninstallOnce.Store(false)
		code := ""
		if m, ok := body.(map[string]any); ok {
			code, _ = m["code"].(string)
		}
		slog.Warn("uninstall: refused by the helper", "status", st, "reason", code, "requested_by", who, "remote", remote)
		writeJSON(w, st, body)
		return
	}
	slog.Warn("uninstall: approved by the helper and started, this agent is being removed", "requested_by", who, "remote", remote)
	writeJSON(w, 202, map[string]any{"state": api.UninstallStarted})
}

// HelperUninstaller is the Uninstaller that hands the request to the helper (Windows): the helper checks the
// approval and carries the uninstall out; the agent only passes it on, as it does for power and fans through
// the helper.
func HelperUninstaller(c *HelperClient) HelperUninstall { return helperUninstaller{c: c} }

type helperUninstaller struct{ c *HelperClient }

func (helperUninstaller) ThroughHelper() bool { return true }

func (helperUninstaller) Start(context.Context) error {
	return errors.New("the helper carries an uninstall out (Ask)")
}

func (u helperUninstaller) Ask(ctx context.Context, by string, ap *api.Approval) (int, any) {
	if !u.c.Installed() {
		return 409, map[string]any{"code": api.CodeHelperRequired,
			"error": "uninstall from the panel needs the fairy-agent-helper service, which checks the approval and carries it out; it is not installed. " + HelperSetupHint}
	}
	return u.c.Uninstall(ctx, by, ap)
}
