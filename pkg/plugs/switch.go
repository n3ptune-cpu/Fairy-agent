package plugs

import (
	"context"
	"errors"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// Timing of one switch. The longest a switch takes is ReadTimeout + SwitchTimeout + ConfirmFor (18 s) and the
// last state read that was under way.
const (
	// ReadTimeout is how long the state read before the switch may take.
	ReadTimeout = StateTimeout
	// SwitchTimeout is how long Home Assistant has to answer the switch request.
	SwitchTimeout = 5 * time.Second
	// ConfirmFor is how long the state is read after the request, to see the socket follow: first after
	// ConfirmFirst, then every ConfirmEvery, until it shows the state that was asked for or ConfirmFor is over.
	ConfirmFor   = 10 * time.Second
	ConfirmFirst = 500 * time.Millisecond
	ConfirmEvery = time.Second
)

// Result is what became of one Switch.
type Result struct {
	// Code is "" when the request was sent to Home Assistant and answered (Confirmed says whether the socket
	// followed). Otherwise it is why not, one of the api.Code... of POST /plug/switch (unknown_socket,
	// plug_switching_disabled, not_allowed, feeds_self, switch_in_progress, too_soon, no_token, ha_unreachable,
	// socket_unavailable, ha_refused, no_answer), or CodeNotAdmitted.
	Code string
	// Why is a short fixed text for the log and the answer ("timeout", "http 500", "home assistant refused the
	// token", the state Home Assistant gave): never anything Home Assistant sent beyond a state word.
	Why string
	// Spent: the admit function was called and said yes: the approval is used up, whatever Code says.
	Spent bool
	// Was is the state read before the request; State the state read last after it ("unknown": none could be
	// read); Confirmed: State is the state that was asked for.
	Was, State string
	Confirmed  bool
	// RetryAfter (too_soon): how long until this socket may be switched again.
	RetryAfter time.Duration
	Took       time.Duration
	Socket     Socket // the socket as the config describes it (zero for unknown_socket)
}

// CodeNotAdmitted is Result.Code when the admit function said no: nothing was sent to Home Assistant but the
// state read, and the caller knows why (its own function refused).
const CodeNotAdmitted = "not_admitted"

// Switch turns one socket on (on true) or off. It is the only way this agent changes anything in Home
// Assistant, and it sends the one request of HA.Switch at most once.
//
// The socket is named by the ids of its power source and of the socket; everything else, the entity above
// all, comes from this machine's config. admit is asked exactly once, at the last moment before the request
// is sent, and the request is sent only if it says yes: the agent's route puts the passkey check there
// (approval.Gate.Admit), which uses the approval up in that call. Everything that can refuse the switch
// without an approval is checked before admit is asked, so a switch that is refused for a reason of its own
// costs no approval. admit must not be nil.
//
// The order:
//
//  1. This machine's own rules, again, whatever the caller checked: the socket exists; switching is on; the
//     socket is not locked (feeds_self, system_hint self, not in switch_allow). No request is made.
//  2. One switch at a time on this agent: a second one is not queued but refused (switch_in_progress).
//  3. Not sooner than MinGap after the last switch of this socket (too_soon). And not while the wait after a
//     refused token is on (ha_unreachable): the token is not sent again before that is over.
//  4. The state is read. No state (ha_unreachable, no_token) and a state that is neither on nor off
//     (socket_unavailable) refuse: Home Assistant answers a switch request for an entity it does not reach
//     with 200 and does nothing, so a socket that is known to be unreachable is refused while the approval
//     is still whole.
//  5. admit. From here on the approval is spent.
//  6. The time is noted for MinGap, and the one request is sent: turn_on or turn_off, never anything else. It
//     is sent also when the state read in 4 is the one asked for: Home Assistant's state can be old, the
//     request does nothing to a socket that is in that state already, and the person approved "make it off".
//     An error status ends here (ha_refused). No answer does not: the request may have arrived.
//  7. The state is read again, after ConfirmFirst and then every ConfirmEvery for ConfirmFor at the most,
//     until it is the one asked for. Only that makes Confirmed true: the answer to the request is never
//     taken for success. No answer in 6 and no change here is no_answer.
//
// From step 5 on the work no longer depends on ctx: a caller that hangs up does not leave a request half sent
// or a result unlogged.
func (p *Plugs) Switch(ctx context.Context, source, socket string, on bool, admit func() bool) (res Result) {
	start := p.o.Now()
	defer func() { res.Took = p.o.Now().Sub(start) }()
	want := api.SocketStateOff
	if on {
		want = api.SocketStateOn
	}
	s, ok := p.Find(source, socket)
	if !ok {
		return Result{Code: api.CodeUnknownSocket}
	}
	res.Socket = s
	switch p.Lock(s) {
	case "":
	case api.WhySwitchingOff:
		res.Code = api.CodePlugSwitchingDisabled
		return res
	case api.WhyFeedsSelf:
		res.Code = api.CodeFeedsSelf
		return res
	default:
		res.Code = api.CodeNotAllowed
		return res
	}
	key := [2]string{s.Source, s.ID}

	p.mu.Lock()
	if p.busy {
		p.mu.Unlock()
		res.Code = api.CodeSwitchInProgress
		return res
	}
	if last, switched := p.lastAt[key]; switched {
		if since := p.o.Now().Sub(last); since >= 0 && since < p.o.MinGap {
			p.mu.Unlock()
			res.Code, res.RetryAfter = api.CodeTooSoon, p.o.MinGap-since
			return res
		}
	}
	if left := p.held(); left > 0 {
		p.mu.Unlock()
		res.Code, res.Why, res.RetryAfter = api.CodeHAUnreachable, "home assistant refused the token a while ago, and it is not sent again before the wait is over", left
		return res
	}
	p.busy = true
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.busy = false
		p.mu.Unlock()
	}()

	was, err := p.o.HA.State(ctx, s.Entity, p.o.ReadTimeout)
	var nt *NoToken
	switch {
	case errors.As(err, &nt):
		res.Code, res.Why = api.CodeNoSwitchToken, Describe(err)
		return res
	case err != nil:
		p.mu.Lock()
		if power.Refused(err) {
			p.refused(Describe(err))
		} else {
			p.note(s, api.SocketStateUnknown, Describe(err))
		}
		p.mu.Unlock()
		res.Code, res.Why = api.CodeHAUnreachable, Describe(err)
		return res
	}
	res.Was = was
	p.mu.Lock()
	p.note(s, was, "")
	p.mu.Unlock()
	if was != api.SocketStateOn && was != api.SocketStateOff {
		res.Code, res.Why = api.CodeSocketUnavailable, was
		return res
	}

	if !admit() {
		res.Code = CodeNotAdmitted
		return res
	}
	res.Spent, res.State = true, api.SocketStateUnknown
	ctx = context.WithoutCancel(ctx)
	p.mu.Lock()
	p.lastAt[key] = p.o.Now()
	p.mu.Unlock()
	p.o.Log.Warn("plug: switching", "source", s.Source, "socket", s.ID, "name", s.Name, "entity", s.Entity, "to", want, "was", was)

	noAnswer := false
	if err := p.o.HA.Switch(ctx, s.Entity, on, p.o.SwitchTimeout); err != nil {
		var se *SwitchError
		switch {
		case !errors.As(err, &se) || se.NotSent: // the token's variable was emptied since the state was read
			res.Code, res.Why = api.CodeNoSwitchToken, Describe(err)
			return res
		case se.Status != 0:
			if se.Refused() {
				p.mu.Lock()
				p.refused(Describe(err))
				p.mu.Unlock()
			}
			res.Code, res.Why = api.CodeHARefused, Describe(err)
			return res
		}
		noAnswer, res.Why = true, Describe(err)
	}

	// read the state until it is the one asked for
	deadline := p.o.Now().Add(ConfirmFor)
	for wait := ConfirmFirst; !p.o.Now().Add(wait).After(deadline); wait = ConfirmEvery {
		if !p.o.Pause(ctx, wait) {
			break
		}
		st, err := p.o.HA.State(ctx, s.Entity, StateTimeout)
		if err != nil {
			if power.Refused(err) {
				p.mu.Lock()
				p.refused(Describe(err))
				p.mu.Unlock()
				break
			}
			continue
		}
		res.State = st
		if st == want {
			res.Confirmed = true
			break
		}
	}
	p.mu.Lock()
	if p.held() == 0 {
		p.note(s, res.State, "")
	}
	p.mu.Unlock()
	if noAnswer && !res.Confirmed {
		res.Code = api.CodeNoAnswer
		return res
	}
	res.Why = ""
	return res
}
