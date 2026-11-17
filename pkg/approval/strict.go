package approval

import (
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
)

// Requests that are never carried out without a passkey approval.
//
// Every request the gate knew before runs unchecked on a machine without a trust file: Challenge answers
// "needed: false, reason: off" and Admit lets it through. That is right for fans, power and updates, which
// worked before approvals existed. It is wrong for a request that only ever existed together with the passkey
// check: switching a plug socket (api.ApproveSocketSet) and uninstalling the agent (api.ApproveUninstall: it
// cannot be undone from the panel, and a program that took the control token must not be able to do it). For
// such a verb:
//
//   - no trust file: refused, 409 approval_off, from Challenge, Precheck, Look, Admit, RunCovers and AdmitRun,
//     and from each of them on a nil Gate too (a part that was built without a gate lets nothing of this kind
//     through);
//   - the approval that comes with it has a list of exactly one entry (oneEntry);
//   - no window and no setting stands in for the approval: the fan window and the one shutdown after boot are
//     tied to their own verbs (isFan, isShutdown), and a run covers an update and a shutdown and nothing else
//     (runCover);
//   - there is no ticket for it: an approval answers a challenge of this machine, which lives ChallengeTTL.
func isStrict(verb string) bool { return verb == api.ApproveSocketSet || verb == api.ApproveUninstall }

// strictOff is the answer to a strict request on a machine without a trust file.
func strictOff() *Refusal {
	return &Refusal{Status: 409, Code: api.CodeApprovalOff,
		Msg: "this machine has no passkey check (no approval trust file), and this request is carried out only with a passkey approval, so it is refused. Set the check up first: from the panel, or on the machine with fairy-agent helper-trust set"}
}

// Off is strictOff for a caller that has to give the answer itself: the agent, where its own gate cannot read
// the trust file and the helper, whose file it is, says that there is none.
func Off() *Refusal { return strictOff() }

// strictWithoutGate is what a nil Gate answers: nothing for the requests it has always let run, strictOff for
// a strict one.
func strictWithoutGate(verb string) *Refusal {
	if isStrict(verb) {
		return strictOff()
	}
	return nil
}

// oneEntry refuses the approval of a strict request whose list does not hold exactly one entry. Nothing of the
// token is looked at and nothing is used up.
//
// Why: one approval is one ID token, and its nonce covers the whole list, up to api.MaxApprovalEntries entries
// for as many machines and requests. That is what lets one passkey touch approve "shut these five machines
// down". For sockets it would let a panel that was taken over collect a challenge for every socket of a
// machine and have them all approved with one touch that the person meant for one socket: "all off". With
// this rule a token that was signed for more than one entry switches nothing: the list cannot be shortened
// afterwards, because the nonce is the hash of the whole list. So one touch is one socket and one direction,
// on the machine and not only in the panel. Caller holds g.mu.
func (g *Gate) oneEntry(req api.ApprovalRequest, canon string, ap *api.Approval) *Refusal {
	if !isStrict(req.Verb) || ap == nil || len(ap.Entries) == 1 {
		return nil
	}
	g.o.Log.Warn("approval: refused", "result", "refused", "reason", ReasonOneEntry, "request", canon, "entries", len(ap.Entries))
	return refuse(ReasonOneEntry, refusalText[ReasonOneEntry])
}

// Look is the first question about a request whose approval is at hand, for a part that has to ask somebody
// else something before it can carry the request out (the plug route reads the socket's state from Home
// Assistant first). It is Precheck, and then the approval is looked at exactly as Admit will look at it: the
// list, this machine's open challenge for this exact request, the token. It uses nothing up and records
// nothing: an approval that passes here is still whole, and Admit is asked afterwards, at the moment the
// request is carried out, and is the only one that lets anything through.
//
// What it is for: without it, a request with anything in its "approval" member got as far as the part's own
// questions. With it, whoever holds the control token and no approval of a person causes no request to Home
// Assistant at all.
//
// The refusals are Admit's. A request without an approval is refused as by Precheck (for a strict request
// always; otherwise unless the fan window or the shutdown after boot would let it through now).
func (g *Gate) Look(req api.ApprovalRequest, ap *api.Approval) *Refusal {
	if ref := g.Precheck(req, ap != nil); ref != nil || g == nil || ap == nil {
		return ref
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	canon, on, ref := g.enforced(req)
	if !on || ref != nil {
		return ref
	}
	if ref := g.oneEntry(req, canon, ap); ref != nil {
		return ref
	}
	c, cl, reason, _ := g.check(g.trust, g.trust.MachineID, canon, ap, g.o.Now(), false)
	if reason != "" {
		g.o.Log.Warn("approval: refused at the first look (nothing was asked of anybody, nothing was used up)", "result", "refused", "reason", reason,
			"request", canon, "sub", cl.Sub, "kid", cl.Kid, "challenge", c)
		return refuse(reason, refusalText[reason])
	}
	return nil
}
