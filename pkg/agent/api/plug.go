package api

// Plug sockets, as the panel sees them: the "sockets" member of a row of "power_sources" in GET /metrics, and
// the route that switches one. The request text and the tag are in approval.go (ApproveSocketSet, SocketTag);
// the rules are fairy-agent's (pkg/agent, plug.go) and the checking is pkg/approval.

// PathPlugSwitch (POST, control token, counts as a control request): body PlugSwitch; 200 PlugSwitched. It
// answers 404 plug_switching_disabled on an agent whose own config does not turn switching on.
const PathPlugSwitch = "/plug/switch"

// FeaturePlugSwitching is the member of "features" (GET /metrics, the /pair answer) that says whether this
// agent's own config turns switching on (home_assistant.switching). The panel cannot change it.
const FeaturePlugSwitching = "plug_switching"

// States of a socket (SocketRow.State, and "was" and "state" of PlugSwitched).
const (
	SocketStateOn          = "on"
	SocketStateOff         = "off"
	SocketStateUnavailable = "unavailable" // Home Assistant does not reach the socket
	SocketStateUnknown     = "unknown"     // Home Assistant has no state for it, said something else, or was not reached
)

// Why a socket cannot be switched (SocketRow.Why). The first that applies, in this order.
const (
	WhySwitchingOff = "switching_off" // home_assistant.switching is false on this machine: nothing is ever switched
	WhyFeedsSelf    = "feeds_self"    // its switch is in home_assistant.feeds_self, or its meter says system_hint: self; never switched, in either direction
	WhyNotAllowed   = "not_allowed"   // its switch is not in home_assistant.switch_allow
	WhyNoToken      = "no_token"      // the variable of the switching token holds nothing on this machine
	// WhyApprovalOff: this machine has no passkey check (no trust file). A socket is switched only with one.
	WhyApprovalOff = "approval_off"
	// WhyApprovalUnavailable: the trust file is there and cannot be used.
	WhyApprovalUnavailable = "approval_unavailable"
)

// SocketRow is one socket in the "sockets" list of a power source's row. The entity id of its switch is not
// in it: the panel does not need it, and Tag stands for it.
type SocketRow struct {
	ID   string `json:"id"`   // unique in the power source: 1-16 lower-case letters, digits and dashes
	Name string `json:"name"` // what the machine's config calls it: at most 48 bytes
	// State is one of the SocketState words, as Home Assistant said it at the last read (every 10 s).
	State string `json:"state"`
	// Switchable: POST /plug/switch for this socket is not refused for a reason that is known beforehand. Why
	// says the reason when it is (null otherwise).
	Switchable bool    `json:"switchable"`
	Why        *string `json:"why"`
	// Tag is SocketTag of the socket as this machine describes it now. A switch request carries it back.
	Tag string `json:"tag"`
	// Error is a short fixed text when the state could not be read (null otherwise): "timeout", "connection
	// failed", "http 500", "entity not found", "home assistant refused the token", or that the token's variable
	// holds nothing. Never anything Home Assistant sent.
	Error *string `json:"error"`
}

// PlugSwitch is the body of POST /plug/switch. Source, Socket, To and Tag are the members of the socket_set
// request, exactly as they were sent to POST /approval/challenge; Approval is the approval of that challenge,
// with a list of exactly one entry. A member the body does not have here is refused.
type PlugSwitch struct {
	Source string `json:"source"`
	Socket string `json:"socket"`
	To     string `json:"to"` // SocketOn | SocketOff
	Tag    string `json:"tag"`
	// RequestedBy is for the machine's log only (cut to 64 characters).
	RequestedBy any       `json:"requested_by,omitempty"`
	Approval    *Approval `json:"approval,omitempty"`
}

// Request is the socket_set request the body names.
func (b PlugSwitch) Request() ApprovalRequest {
	return SocketSetRequest(b.Source, b.Socket, b.To, b.Tag)
}

// PlugSwitched is the 200 answer of POST /plug/switch: the request was sent to Home Assistant.
type PlugSwitched struct {
	Source string `json:"source"`
	Socket string `json:"socket"`
	To     string `json:"to"`
	Was    string `json:"was"`   // the state read before the request was sent
	State  string `json:"state"` // the state read last, after it
	// Confirmed: State is the state that was asked for. false: Home Assistant took the request and the socket
	// did not show the new state within 10 s (it may still follow).
	Confirmed bool  `json:"confirmed"`
	TookMS    int64 `json:"took_ms"`
}
