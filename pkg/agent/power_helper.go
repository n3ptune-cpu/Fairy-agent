package agent

import (
	"context"
	"math"
	"slices"
)

// PendingAction is the power action the helper says it scheduled and that is still pending, from its latest
// status answer (the helper remembers its own shutdown across restarts of itself and of the agent, see
// RememberedPower). Nothing while the helper is not running, and nothing from a helper too old to say.
func (p *HelperPower) PendingAction() (Pending, bool) {
	if st := p.c.Status(context.Background()); !st.Running() {
		return Pending{}, false
	}
	p.c.stMu.Lock()
	defer p.c.stMu.Unlock()
	if !p.c.hasLast || p.c.last.Power == nil {
		return Pending{}, false
	}
	h := p.c.last.Power
	if !slices.Contains(powerRecordActions, h.Action) || math.IsNaN(h.At) || math.IsInf(h.At, 0) || h.At <= 0 ||
		h.DelayS < 0 || h.DelayS > 86400 {
		return Pending{}, false
	}
	return Pending{Action: h.Action, At: h.At, DelayS: h.DelayS, RequestedBy: cleanWho(h.By)}, true
}

// PendingKnown reports whether the helper could be asked: while it is not running, an action it scheduled
// earlier (Windows goes on counting a shutdown down) can be neither seen nor cancelled.
func (p *HelperPower) PendingKnown() bool {
	if st := p.c.Status(context.Background()); !st.Running() {
		return false
	}
	p.c.stMu.Lock()
	defer p.c.stMu.Unlock()
	return p.c.hasLast
}
