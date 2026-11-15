package agent

// Plug sockets, the agent's part (PLUGS-DESIGN.md, stage 1a): the "sockets" of a power source's row in
// GET /metrics. The sockets and what may be done with them come from this machine's config.yaml alone
// (Config.NewPlugs); their states are read by pkg/plugs.

import (
	"context"
	"maps"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
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
