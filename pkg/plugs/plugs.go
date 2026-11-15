package plugs

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/power"
)

// Socket is one socket as this machine's config describes it. Nothing of it comes from a request.
type Socket struct {
	Source     string // the id of the power source (the meter) it belongs to
	SourceName string // that source's name
	ID         string // unique in the source
	Name       string
	Entity     string // the entity id of its switch in Home Assistant
	Tag        string // api.SocketTag(Source, ID, Name, Entity)
	// Allowed: Entity is in home_assistant.switch_allow.
	Allowed bool
	// FeedsSelf: Entity is in home_assistant.feeds_self. SelfHint: the meter says system_hint: self (it
	// measures the machine this agent runs on). Either one: never switched, in either direction, whatever
	// Allowed says.
	FeedsSelf, SelfHint bool
}

// Timing of the state reader.
const (
	// DefaultInterval is how often the states are read; MinInterval the least a caller may ask for. Home
	// Assistant itself hears from most plugs every 10 to 60 s.
	DefaultInterval = 10 * time.Second
	MinInterval     = 5 * time.Second
	// StateTimeout is how long one state read may take.
	StateTimeout = 3 * time.Second
)

// notReadYet is a socket's error before its first read.
const notReadYet = "not read yet"

// Options build a Plugs.
type Options struct {
	HA      *HA
	Sockets []Socket // in config order
	// Switching: home_assistant.switching. false: states are read and shown, Switch refuses everything.
	Switching bool
	// MinGap is the least time between two switches of one socket (home_assistant.min_gap_s).
	MinGap time.Duration
	// Interval between two rounds of state reads (0: DefaultInterval; never below MinInterval).
	Interval time.Duration
	// Now is the clock and Pause the wait (nil: time.Now, and a timer that ends early when ctx does). Tests put
	// their own here.
	Now   func() time.Time
	Pause func(ctx context.Context, d time.Duration) bool
	Log   *slog.Logger // nil: slog.Default()
}

type reading struct {
	state string
	err   string // "" when the state was read
}

// Plugs are the sockets of this machine's config and their states, read from Home Assistant by a loop of its
// own.
//
// The states are not part of the meters' readings. A meter's reading is limited to its four requests for
// sensors (power.MaxHARequests), and the type that reads watts can send nothing but a GET for a sensor. The
// states are read here instead: one GET for each socket's switch, one after the other, every Interval, with
// the block's own token.
type Plugs struct {
	o       Options
	sockets []Socket
	index   map[[2]string]int

	mu       sync.Mutex
	states   []reading
	refusals int       // refusals of the token in a row
	holdTill time.Time // no request is made before this (zero: none): the long wait after a refused token
}

// New returns the sockets' keeper. Nothing is asked of Home Assistant before Run or PollOnce.
func New(o Options) *Plugs {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Pause == nil {
		o.Pause = pauseFor
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	if o.Interval == 0 {
		o.Interval = DefaultInterval
	}
	o.Interval = max(o.Interval, MinInterval)
	p := &Plugs{o: o, sockets: append([]Socket(nil), o.Sockets...), index: map[[2]string]int{}}
	p.states = make([]reading, len(p.sockets))
	for i, s := range p.sockets {
		p.index[[2]string{s.Source, s.ID}] = i
		p.states[i] = reading{state: api.SocketStateUnknown, err: notReadYet}
	}
	return p
}

func pauseFor(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Switching reports whether this machine's config turns switching on.
func (p *Plugs) Switching() bool { return p != nil && p.o.Switching }

// HA is the Home Assistant the sockets are in (for the config check's lines).
func (p *Plugs) HA() *HA { return p.o.HA }

// MinGap is the least time between two switches of one socket.
func (p *Plugs) MinGap() time.Duration { return p.o.MinGap }

// Empty reports whether there is no socket to read.
func (p *Plugs) Empty() bool { return p == nil || len(p.sockets) == 0 }

// Sockets are all sockets, in config order (a copy).
func (p *Plugs) Sockets() []Socket {
	if p == nil {
		return nil
	}
	return append([]Socket(nil), p.sockets...)
}

// Find returns the socket with this id of this power source.
func (p *Plugs) Find(source, socket string) (Socket, bool) {
	if p == nil {
		return Socket{}, false
	}
	i, ok := p.index[[2]string{source, socket}]
	if !ok {
		return Socket{}, false
	}
	return p.sockets[i], true
}

// Lock says why this machine's config never lets the socket be switched, as the word of a row ("": it does
// not forbid it): switching is off; it feeds this machine, Home Assistant or the network (feeds_self, or its
// meter's system_hint: self), which counts before the allow list; or it is not in the allow list.
func (p *Plugs) Lock(s Socket) string {
	switch {
	case !p.Switching():
		return api.WhySwitchingOff
	case s.FeedsSelf || s.SelfHint:
		return api.WhyFeedsSelf
	case !s.Allowed:
		return api.WhyNotAllowed
	}
	return ""
}

// Row is a socket with its state as it was read last.
type Row struct {
	Socket
	State string // api.SocketState...
	Error string // why the state could not be read ("": it was)
}

// Rows are the sockets of one power source with their states, in config order.
func (p *Plugs) Rows(source string) []Row {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []Row
	for i, s := range p.sockets {
		if s.Source == source {
			out = append(out, Row{Socket: s, State: p.states[i].state, Error: p.states[i].err})
		}
	}
	return out
}

// Run reads the states every Interval until ctx ends.
//
// After a refusal of the token (401 or 403) nothing is asked for power.RefusedWait: 5 minutes, then 15, then
// an hour for the third and every further refusal in a row. A revoked token would otherwise be sent with every
// socket every ten seconds, and Home Assistant counts each as a failed login and can ban this machine's
// address, which would end the meters' readings too. The count goes back to zero with the first state that is
// read; a restart of the agent starts it anew.
func (p *Plugs) Run(ctx context.Context) {
	if p.Empty() {
		return
	}
	for ctx.Err() == nil {
		if !p.o.Pause(ctx, p.round(ctx)) {
			return
		}
	}
}

// PollOnce reads every state once, unless the wait after a refusal is on (first report, tests).
func (p *Plugs) PollOnce(ctx context.Context) {
	if !p.Empty() {
		p.round(ctx)
	}
}

// held is how much of the wait after a refusal is left (0: none). Caller holds p.mu.
func (p *Plugs) held() time.Duration {
	if p.holdTill.IsZero() {
		return 0
	}
	left := p.holdTill.Sub(p.o.Now())
	if left <= 0 {
		p.holdTill = time.Time{}
		return 0
	}
	return left
}

// refused counts one refusal of the token and starts the wait. Every socket's state is unknown from now on:
// nothing was read with a token that works. Caller holds p.mu.
func (p *Plugs) refused(why string) time.Duration {
	p.refusals++
	wait := power.RefusedWait(p.refusals)
	p.holdTill = p.o.Now().Add(wait)
	for i := range p.states {
		p.states[i] = reading{state: api.SocketStateUnknown, err: why}
	}
	p.o.Log.Warn("plugs: home assistant refused the token for switching; the sockets' states are not asked for again before the wait is over",
		"refusals", p.refusals, "wait_s", int(wait/time.Second), "token_env", p.o.HA.TokenEnv())
	return wait
}

// unreachable reports whether err says that Home Assistant itself did not answer (and not that it answered
// something about one entity): the next socket would wait for the same timeout.
func unreachable(err error) bool {
	switch devices.Describe(err) {
	case "timeout", "connection failed", "tls verification failed":
		return true
	}
	return false
}

// round reads every socket's state once, one after the other, and returns how long to wait before the next
// round. One after the other: a token that Home Assistant does not accept is then sent once in a round, not
// once for every socket at the same moment.
//
// A round ends early in two cases, and the sockets it did not get to are given the same reason without being
// asked: the token was refused (then the long wait starts); or Home Assistant did not answer at all (a
// timeout, no connection, a certificate that does not verify), where every further read would only wait for
// the same timeout again.
func (p *Plugs) round(ctx context.Context) time.Duration {
	p.mu.Lock()
	if left := p.held(); left > 0 {
		p.mu.Unlock()
		return left
	}
	p.mu.Unlock()
	for i, s := range p.sockets {
		if ctx.Err() != nil {
			return p.o.Interval
		}
		state, err := p.o.HA.State(ctx, s.Entity, StateTimeout)
		p.mu.Lock()
		switch {
		case err == nil:
			p.states[i] = reading{state: state}
			p.refusals = 0
		case power.Refused(err):
			wait := p.refused(Describe(err))
			p.mu.Unlock()
			return wait
		default:
			why := Describe(err)
			p.states[i] = reading{state: api.SocketStateUnknown, err: why}
			var nt *NoToken
			if unreachable(err) || asNoToken(err, &nt) {
				for j := i + 1; j < len(p.sockets); j++ {
					p.states[j] = reading{state: api.SocketStateUnknown, err: why}
				}
				p.mu.Unlock()
				return p.o.Interval
			}
		}
		p.mu.Unlock()
	}
	return p.o.Interval
}
