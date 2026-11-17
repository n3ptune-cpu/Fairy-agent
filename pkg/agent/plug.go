package agent

// Plug sockets, the agent's part (PLUGS-DESIGN.md, stage 1a): the "sockets" of a power source's row in
// GET /metrics, the challenge for a switch, and POST /plug/switch. The sockets and what may be done with them
// come from this machine's config.yaml alone (Config.NewPlugs); their states are read, and the one request
// that switches is sent, by pkg/plugs.

import (
	"context"
	"log/slog"
	"maps"
	"net/http"
	"strconv"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs"
)

// socketGate says why no socket of this machine can be switched for a reason of the passkey check, as the word
// of a row ("": the check is on and usable).
//
// A socket is switched only with a passkey approval that this agent process checks itself. So without a trust
// file it is "approval_off", the opposite of the fan, power and update requests, which run unchecked there;
// and so it is for an agent that was built without a gate. A trust file that cannot be used is
// "approval_unavailable". On Windows the trust file is the helper's and this agent only reads it: when its own
// look fails and the helper says that there is no trust file, that is "approval_off" as well, never "let it
// through" (which is what ownCheck makes of that case for the other requests).
//
// now: ask the helper at this moment (a request); else its latest status answer is enough (GET /metrics).
func (a *Agent) socketGate(ctx context.Context, now bool) string {
	if a.d.Approval == nil {
		return api.WhyApprovalOff
	}
	var state string
	if now {
		state = a.d.Approval.StatusNow().State
	} else {
		state = a.d.Approval.Status().State
	}
	switch state {
	case api.ApprovalRequired:
		return ""
	case api.ApprovalOff:
		return api.WhyApprovalOff
	}
	if h, ok := a.helperApproval(); ok {
		var st api.ApprovalStatus
		var known bool
		if now {
			st, known = h.ApprovalNow(ctx)
		} else {
			st, known = h.ApprovalStatus(ctx)
		}
		if known && st.State == api.ApprovalOff {
			return api.WhyApprovalOff
		}
	}
	return api.WhyApprovalUnavailable
}

// withSockets returns the power source rows with the member "sockets" added to each row whose source has
// sockets. The rows that come in are the relay's own and are not changed: a row that gets the member is a copy.
//
// A socket's row says its state as Home Assistant gave it last, whether a switch request for it would be
// refused for a reason that is known beforehand and which (the first that applies: api.Why...), and its tag.
// It does not say the entity id. A row of a power source stays what its reading made it, whatever its sockets
// say: ok with its watts also when no socket's state could be read.
func (a *Agent) withSockets(ctx context.Context, rows []map[string]any) []map[string]any {
	if a.d.Plugs.Empty() {
		return rows
	}
	gate := a.socketGate(ctx, false)
	noToken := !a.d.Plugs.HA().TokenSet()
	out := make([]map[string]any, len(rows))
	for i, row := range rows {
		out[i] = row
		id, _ := row["id"].(string)
		socks := a.d.Plugs.Rows(id)
		if len(socks) == 0 {
			continue
		}
		list := make([]api.SocketRow, 0, len(socks))
		for _, s := range socks {
			r := api.SocketRow{ID: s.ID, Name: s.Name, State: s.State, Tag: s.Tag}
			why := a.d.Plugs.Lock(s.Socket)
			switch {
			case why != "":
			case noToken:
				why = api.WhyNoToken
			default:
				why = gate
			}
			if why == "" {
				r.Switchable = true
			} else {
				r.Why = &why
			}
			if s.Error != "" {
				msg := s.Error
				r.Error = &msg
			}
			list = append(list, r)
		}
		row = maps.Clone(row)
		row["sockets"] = list
		out[i] = row
	}
	return out
}

// challengeOpen reports whether POST /approval/challenge answers on this agent: where something checks
// approvals (hasApproval), and on every agent that switches plug sockets. The second is for a machine without
// any passkey check: it must answer a socket's challenge request with 409 approval_off itself, where the route
// used to be 404 for everybody (approvalChallenge keeps that answer for every other request).
func (a *Agent) challengeOpen() bool {
	return a.hasApproval() || a.d.Plugs.Switching() || a.uninstallOn() // the last two: to answer approval_off
}

// plugRefusal is the answer of POST /plug/switch for a refusal of the agent's own (the gate has its own).
// Every text is a fixed sentence of this file: nothing Home Assistant sent is ever repeated.
type plugRefusal struct {
	status int
	text   string
}

var plugRefusals = map[string]plugRefusal{
	api.CodeUnknownSocket: {404, "this machine has no such socket (the power source and the socket are named by their ids, as GET /metrics shows them)"},
	api.CodeNotAllowed:    {403, "this socket may not be switched: its switch is not in home_assistant.switch_allow in this machine's config.yaml. Nothing was switched"},
	api.CodeFeedsSelf: {403, "this socket is never switched: this machine's config says that it feeds this machine, Home Assistant or the network " +
		"(home_assistant.feeds_self, or a system_hint on its meter that means this machine). Nothing was switched"},
	api.CodeSocketChanged: {409, "this socket is not what it was when the request was made: its name or its switch was changed in this machine's config (the tag is another one). " +
		"Nothing was switched; look at the socket again"},
	api.CodeNoSwitchToken: {409, "this machine has no token for switching: the variable that home_assistant.token_env names holds nothing that can be a token " +
		"(on the machine: fairy-agent secret set <that variable>, then restart the agent). Nothing was switched"},
	api.CodeSocketUnavailable: {409, "Home Assistant has no \"on\" or \"off\" for this socket right now (it does not reach it, or has no state for it). Nothing was switched, " +
		"and the approval was not used"},
	api.CodeSwitchInProgress: {409, "another socket is being switched on this machine right now; one at a time. Nothing was switched, and the approval was not used"},
	api.CodeTooSoon:          {429, "this socket was switched a moment ago; the same socket is not switched again so soon (home_assistant.min_gap_s). Nothing was switched"},
	api.CodeHAUnreachable:    {502, "the socket's state could not be read from Home Assistant, so nothing was switched and the approval was not used"},
	api.CodeHARefused:        {502, "Home Assistant answered the switch request with an error. Nothing more was sent, and the socket was not looked at again; the approval is used up"},
	api.CodeNoAnswer: {502, "the switch request got no answer from Home Assistant, and the socket did not show the new state within 10 s. " +
		"It may still switch: look at the socket. The approval is used up"},
	api.CodePlugSwitchingDisabled: {404, "plug switching is disabled on this agent"},
}

// refusePlug writes a refusal of the agent's own for code, with why (a short fixed text of pkg/plugs, or "")
// after the sentence. retry, when not 0, is in how long the same request can have another answer: the
// Retry-After header and "retry_after_s".
func refusePlug(w http.ResponseWriter, code, why string, retry time.Duration) {
	ref := plugRefusals[code]
	text := ref.text
	if why != "" {
		text += " (" + why + ")"
	}
	body := map[string]any{"error": text, "code": code}
	if retry > 0 {
		s := max(1, int((retry+time.Second-1)/time.Second))
		body[retryAfterMember] = s
		w.Header().Set("Retry-After", strconv.Itoa(s))
	}
	writeJSON(w, ref.status, body)
}

// socketKnown is what is checked about a socket_set request before anybody is asked for anything: the socket
// exists in this machine's config, the config lets it be switched, the tag is the tag it has now, and there
// is a token to switch with. It returns the socket, or the code of the refusal ("": none). The same check
// stands before a challenge is given and before a switch: nobody is sent to Pocket ID for a request that
// would be refused anyway, and a request that is refused here causes no request to Home Assistant.
func (a *Agent) socketKnown(source, socket, tag string) (plugs.Socket, string) {
	s, ok := a.d.Plugs.Find(source, socket)
	if !ok {
		return s, api.CodeUnknownSocket
	}
	switch a.d.Plugs.Lock(s) {
	case "":
	case api.WhyFeedsSelf:
		return s, api.CodeFeedsSelf
	case api.WhySwitchingOff: // the route and featureOff have said so already
		return s, api.CodePlugSwitchingDisabled
	default:
		return s, api.CodeNotAllowed
	}
	if tag != s.Tag {
		return s, api.CodeSocketChanged
	}
	if !a.d.Plugs.HA().TokenSet() {
		return s, api.CodeNoSwitchToken
	}
	return s, ""
}

// socketChallenge is POST /approval/challenge for the verb socket_set. This agent process sends the request
// to Home Assistant, so this agent's own gate gives the challenge and checks the approval, also on Windows
// next to a helper (the helper never uses the network).
//
// It never answers "needs no approval". What would be refused at the switch for a reason that needs no
// approval to know is refused here (socketKnown), and so is a machine without a passkey check: 409
// approval_off, where every other verb is told "needed: false, reason: off". And while the wait after a
// refused token is on, it answers what the switch would: 502 ha_unreachable with Retry-After.
func (a *Agent) socketChallenge(w http.ResponseWriter, r *http.Request, req api.ApprovalRequest) {
	if _, code := a.socketKnown(*req.Source, *req.Socket, *req.Tag); code != "" {
		slog.Warn("plug: no challenge given", "source", *req.Source, "socket", *req.Socket, "to", *req.To, "reason", code, "remote", clientIP(r))
		refusePlug(w, code, "", 0)
		return
	}
	gate := a.socketGate(r.Context(), true)
	if gate == api.WhyApprovalOff {
		slog.Warn("plug: no challenge given", "source", *req.Source, "socket", *req.Socket, "to", *req.To, "reason", api.CodeApprovalOff, "remote", clientIP(r))
		writeRefusal(w, approval.Off())
		return
	}
	// While the wait after a refused token is on, the switch itself would be answered 502 ha_unreachable without
	// Home Assistant being asked (plugs.Switch). The same answer is given here, with the time that is left:
	// nobody is sent to the passkey for a switch that is certain to be refused. Only where the passkey check
	// can be used: a trust file that cannot is said by the gate below, as at the switch.
	if left := a.d.Plugs.Held(); gate == "" && left > 0 {
		slog.Warn("plug: no challenge given", "source", *req.Source, "socket", *req.Socket, "to", *req.To, "reason", api.CodeHAUnreachable, "remote", clientIP(r))
		refusePlug(w, api.CodeHAUnreachable, plugs.HeldWhy, left)
		return
	}
	c, ref := a.d.Approval.Challenge(req) // not nil: socketGate says approval_off for an agent without a gate
	if ref != nil {
		writeRefusal(w, ref)
		return
	}
	writeJSON(w, 200, c)
}

// plugSwitch is POST /plug/switch: one socket, one direction, one passkey approval.
//
// The order is what keeps a refused request from costing anything, and from reaching Home Assistant:
//
//  1. Handler has checked the method, the control token, that switching is on (404 otherwise), the request
//     budget and the body's size.
//  2. The body is strict JSON with no member it does not have; source, socket, to and tag have the form of the
//     request text (400). A request names ids only: never an entity, an address or a service.
//  3. socketKnown: the socket exists (404), may be switched (403), has this tag (409), and there is a token
//     (409).
//  4. The passkey check, looked at and not used up: no trust file, or no gate at all, is 409 approval_off;
//     a trust file that cannot be used is 503; no approval in the body is 403 approval_required; an approval
//     that does not hold, or lists more than one entry, is 403 approval_refused (approval.Gate.Look).
//     This step never goes through approved(): its ownCheck turns "this agent cannot read the trust file and
//     the helper says there is none" into "let it through", which is right for requests that ran before
//     approvals existed and wrong for this one.
//     Up to here nothing was asked of Home Assistant.
//  5. pkg/plugs does the rest (Plugs.Switch): one switch at a time, the gap, the state read, then the gate's
//     Admit, which uses the approval up, then the one request, then the looks at the state.
//
// One line is logged for every request that got past step 1, at WARN, with what was asked and what became of
// it. The token is never in it, and nothing of an answer of Home Assistant but a state word.
func (a *Agent) plugSwitch(w http.ResponseWriter, r *http.Request) {
	remote := clientIP(r)
	var b api.PlugSwitch
	if err := decodeStrictBody(r, &b); err != nil {
		slog.Warn("plug: refused", "reason", "bad_request", "remote", remote)
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	req := b.Request()
	if _, err := req.Canonical(); err != nil {
		slog.Warn("plug: refused", "reason", "bad_request", "remote", remote)
		writeJSON(w, 400, map[string]any{"error": "not a switch request: " + err.Error()})
		return
	}
	who := cleanWho(b.RequestedBy)
	said := []any{"source", b.Source, "socket", b.Socket, "to", b.To, "requested_by", who, "remote", remote}
	refused := func(code string) {
		slog.Warn("plug: refused", append([]any{"reason", code}, said...)...)
	}
	s, code := a.socketKnown(b.Source, b.Socket, b.Tag)
	if code != "" {
		refused(code)
		refusePlug(w, code, "", 0)
		return
	}
	said = append(said, "name", s.Name, "entity", s.Entity)
	if a.socketGate(r.Context(), true) == api.WhyApprovalOff {
		refused(api.CodeApprovalOff)
		writeRefusal(w, approval.Off())
		return
	}
	if ref := a.d.Approval.Look(req, b.Approval); ref != nil {
		refused(ref.Code)
		writeRefusal(w, ref)
		return
	}
	var gateSaid *approval.Refusal
	res := a.d.Plugs.Switch(r.Context(), b.Source, b.Socket, b.To == api.SocketOn, func() bool {
		_, gateSaid = a.d.Approval.Admit(req, b.Approval)
		return gateSaid == nil
	})
	took := res.Took.Milliseconds()
	switch {
	case res.Code == plugs.CodeNotAdmitted:
		if gateSaid == nil { // cannot happen: the function above is the only one that says no
			gateSaid = &approval.Refusal{Status: 500, Code: "failed", Msg: "the approval was not accepted"}
		}
		refused(gateSaid.Code)
		writeRefusal(w, gateSaid)
	case res.Code == "":
		a.cacheOld.Store(true) // the next GET /metrics shows the socket as it is now
		msg := "plug: switched"
		if !res.Confirmed {
			msg = "plug: not confirmed"
		}
		slog.Warn(msg, append(said, "was", res.Was, "state", res.State, "confirmed", res.Confirmed, "took_ms", took)...)
		writeJSON(w, 200, api.PlugSwitched{Source: b.Source, Socket: b.Socket, To: b.To, Was: res.Was, State: res.State, Confirmed: res.Confirmed, TookMS: took})
	default:
		a.cacheOld.Store(true)
		if res.Spent { // the request was sent, or the approval was used up for it: said louder than a refusal
			slog.Error("plug: failed after the approval was used", append([]any{"reason", res.Code, "why", res.Why}, append(said, "was", res.Was, "state", res.State, "took_ms", took)...)...)
		} else {
			slog.Warn("plug: refused", append([]any{"reason", res.Code, "why", res.Why}, said...)...)
		}
		why := res.Why
		if res.Code == api.CodeNoSwitchToken { // the sentence says it, without the variable's name
			why = ""
		}
		refusePlug(w, res.Code, why, res.RetryAfter)
	}
}
