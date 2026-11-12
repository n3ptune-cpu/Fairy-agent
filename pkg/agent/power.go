package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"math"
	"regexp"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// PowerExec carries out a delayed shutdown, reboot or sleep (platform code: power_linux.go, power_windows.go).
type PowerExec interface {
	// Schedule arranges action ("shutdown" | "reboot" | "sleep") to happen after delay; message is shown to
	// logged-in users where the OS can.
	Schedule(action string, delay time.Duration, message string) error
	// Cancel stops a scheduled action.
	Cancel() error
	// CanSleep reports whether this machine can be put to sleep (suspend to RAM), and why not.
	CanSleep() (ok bool, why string)
}

// powerBy is a PowerExec that wants the (cleaned) requester instead of a ready message: the Windows helper,
// which takes no free text.
type powerBy interface {
	ScheduleBy(action string, delay time.Duration, who string) error
}

// powerApproved is a PowerExec that passes the request's approval on to whoever checks it (the Windows helper).
type powerApproved interface {
	ScheduleApproved(action string, delay time.Duration, who string, ap *api.Approval) error
}

// pendingSource is a PowerExec that knows which action of Fairy's own is pending, also one scheduled before
// this process started: RememberedPower (the operating system counts the shutdown down, a file remembers it)
// and the Windows helper's client (the helper remembers it and says so in its status).
type pendingSource interface {
	PendingAction() (Pending, bool)
}

// Pending is the scheduled power action as /metrics and /power report it.
type Pending struct {
	Action      string  `json:"action"`
	At          float64 `json:"at"`
	DelayS      int     `json:"delay_s"`
	RequestedBy string  `json:"requested_by"`
}

// Power handles POST /power: one pending shutdown, reboot or sleep at a time, cancellable until it happens.
type Power struct {
	exec     PowerExec
	minDelay int
	now      func() time.Time
	// steady is the clock the pending action's countdown is read from: time.Now, whose readings carry Go's
	// steady (monotonic) clock, so the time between two of them does not move when the machine's time of day
	// is set. The exec counts the same way (Linux: a timer in this process). Tests put their own in.
	steady func() time.Time

	mu      sync.Mutex
	pending *Pending
	// since is steady's reading when the pending action was scheduled, kept as it was read (no .UTC(), no unix
	// seconds: either would drop the steady part). pending.At is the time of day it was scheduled for.
	since time.Time
	// unstopped: this process scheduled an action and the exec has not been asked to stop it since (or the
	// asking failed). The record above is what this process believes; the countdown is the exec's. While this
	// is set, Cancel asks the exec also when the record shows nothing.
	unstopped bool
	// dropped is the time (Pending.At) of the action this process cancelled last: what the exec still reports
	// for a moment afterwards (the helper's status is cached for a few seconds) is not shown again. Compared
	// within two seconds.
	dropped float64
	sleep   struct {
		ok    bool
		why   string
		until time.Time
	}
}

// canSleep is CanSleep, asked at most every 10 minutes. Caller holds p.mu.
func (p *Power) canSleep() (bool, string) {
	if _, live := p.exec.(interface{ LiveSleep() }); live {
		return p.exec.CanSleep()
	}
	if now := p.now(); now.After(p.sleep.until) {
		p.sleep.ok, p.sleep.why = p.exec.CanSleep()
		p.sleep.until = now.Add(10 * time.Minute)
	}
	return p.sleep.ok, p.sleep.why
}

// defaultPowerDelayS is the delay of a POST /power without delay_s. It is also the delay an approval must have
// been given for when the request names none.
const defaultPowerDelayS = 60

// NewPower returns the power controller.
func NewPower(exec PowerExec, minDelayS int) *Power {
	return &Power{exec: exec, minDelay: minDelayS, now: time.Now, steady: time.Now}
}

var whoClean = regexp.MustCompile(`[^A-Za-z0-9 ._@-]`)

// cleanWho keeps requested_by printable and short (it is shown to users and written to the log).
func cleanWho(v any) string {
	s, _ := v.(string)
	s = whoClean.ReplaceAllString(s, "")
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		s = "unknown"
	}
	return s
}

// current returns the pending action, dropping it once its time has passed. When this process has none of
// its own (it restarted since), it is the one the exec still remembers: a Windows shutdown goes on counting
// down while the agent restarts, and must stay visible and cancellable. Caller holds p.mu.
//
// The action this process scheduled ends by the steady clock, as the exec's countdown does, never by the time
// of day: it was compared with the time of day before, so a clock set forward by more than the rest of the
// countdown plus the minute of grace (the first time synchronisation after weeks without power, an empty
// clock battery) made the agent show nothing pending, and Cancel answer ok without stopping anything, while
// the timer went on and switched the machine off. The time shown (At) is the time of day the action happens
// by today's clock: the one on record, or, when the clock was set since, now plus what is left.
//
// One thing the time of day still decides, and only after the countdown is over by the steady clock: a sleep
// is on record for the minute of grace or until the time of day is a minute past its time, whichever comes
// first. A machine that slept wakes up with this process still running and with a steady clock that stood
// still meanwhile (Linux); the time of day is what tells that the sleep is over, as it did before.
func (p *Power) current() *Pending {
	wall := p.now()
	now := float64(wall.Unix())
	if p.pending != nil {
		// over: how long ago the action's time was by the steady clock (negative: still to come)
		over := p.steady().Sub(p.since) - time.Duration(p.pending.DelayS)*time.Second
		woke := p.pending.Action == "sleep" && over >= 0 && now > p.pending.At+powerRecordGrace.Seconds()
		if over > powerRecordGrace || woke {
			p.pending = nil
		} else {
			c := *p.pending
			if at := float64(wall.UnixMilli())/1000 - over.Seconds(); math.Abs(at-c.At) > atSlack.Seconds() {
				c.At = collect.Round(at, 3)
			}
			return &c
		}
	}
	if src, ok := p.exec.(pendingSource); ok {
		// the exec's clock reading for the same action differs from this process's by a few milliseconds
		if c, ok := src.PendingAction(); ok && math.Abs(c.At-p.dropped) > 2 && now <= c.At+60 {
			return &c
		}
	}
	return nil
}

// Scheduled reports whether a shutdown, reboot or sleep is pending.
func (p *Power) Scheduled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.current() != nil
}

// State is the /metrics `power_control` block.
func (p *Power) State() map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	var pend any
	if c := p.current(); c != nil {
		cp := *c
		pend = cp
	}
	ok, why := p.canSleep()
	st := map[string]any{"enabled": true, "pending": pend, "min_delay_s": p.minDelay, "sleep": ok}
	if !ok {
		st["sleep_note"] = why
	}
	return st
}

// PowerRequest is the POST /power body.
type PowerRequest struct {
	Action      string `json:"action"`
	DelayS      *int   `json:"delay_s"`
	RequestedBy any    `json:"requested_by"`
	// Approval is the passkey approval the request carried (nil: none). Power does not look inside.
	Approval *api.Approval `json:"-"`
	// Gate is the passkey check of a request this process carries out itself (nil: none, or the helper checks).
	// Handle asks it when the request has passed every check of its own and is about to be scheduled.
	Gate Gated `json:"-"`
}

// throughHelper reports whether shutdown, reboot and sleep are carried out by the Windows helper, which then is
// the one that checks their approval.
func (p *Power) throughHelper() bool {
	_, ok := p.exec.(powerApproved)
	return ok
}

// Handle carries out one request and returns the HTTP status and body.
func (p *Power) Handle(req PowerRequest) (int, map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	who := cleanWho(req.RequestedBy)
	switch req.Action {
	case "cancel":
		// Only an action of Fairy's own is cancelled. With none pending the operating system is not asked to
		// abort anything: a shutdown Fairy did not start is not the panel's to cancel.
		c := p.current()
		if c == nil {
			// the helper is the one that remembers; while it is stopped nobody can tell (or cancel)
			if k, ok := p.exec.(interface{ PendingKnown() bool }); ok && !k.PendingKnown() {
				return 503, map[string]any{"error": "helper stopped: cannot tell whether a shutdown is pending, and cannot cancel one",
					"code": api.ReasonHelperStopped}
			}
			// Nothing on record. What this process scheduled itself and never asked the exec to stop is stopped
			// all the same (the exec's Cancel stops what the exec scheduled and nothing else; with nothing left
			// it does nothing): "ok" without asking, when the record was wrong, left the countdown running.
			if !p.unstopped {
				return 200, map[string]any{"action": "cancel", "pending": nil}
			}
		}
		if err := p.exec.Cancel(); errors.Is(err, api.ErrHelperStopped) {
			return 503, map[string]any{"error": "helper stopped: cannot cancel", "code": api.ReasonHelperStopped}
		} else if err != nil {
			slog.Error("power: cancel failed", "error", err.Error(), "requested_by", who)
			return 500, map[string]any{"error": "could not cancel: " + safeErr(err)}
		}
		p.unstopped = false
		if c != nil {
			slog.Warn("power: cancelled", "action", c.Action, "requested_by", who)
			p.pending, p.dropped = nil, c.At
		}
		return 200, map[string]any{"action": "cancel", "pending": nil}
	case "shutdown", "reboot":
	case "sleep":
		if ok, why := p.canSleep(); !ok {
			return 409, map[string]any{"error": "this machine cannot sleep: " + why, "code": "sleep_unavailable"}
		}
	default:
		return 400, map[string]any{"error": "action must be shutdown, reboot, sleep or cancel"}
	}
	delay := defaultPowerDelayS
	if req.DelayS != nil {
		delay = *req.DelayS
	}
	if delay < p.minDelay || delay > 86400 {
		return 400, map[string]any{"error": fmt.Sprintf("delay_s must be between %d and 86400", p.minDelay)}
	}
	if c := p.current(); c != nil {
		return 409, map[string]any{"error": fmt.Sprintf("a %s is already pending; cancel it first", c.Action)}
	}
	// The request's own checks are done; it is scheduled next. Only now is its approval used up, or the one
	// shutdown after boot recorded: a request refused above costs neither.
	if req.Gate != nil {
		if _, ref := req.Gate(); ref != nil {
			slog.Warn("power: not scheduled", "action", req.Action, "code", ref.Code, "requested_by", who)
			return ref.Status, refusalBody(ref)
		}
	}
	msg := fmt.Sprintf("Fairy: %s requested by %s in %d seconds.", req.Action, who, delay)
	var err error
	if ap, ok := p.exec.(powerApproved); ok && req.Approval != nil {
		err = ap.ScheduleApproved(req.Action, time.Duration(delay)*time.Second, who, req.Approval)
	} else if by, ok := p.exec.(powerBy); ok { // the Windows helper builds the message itself from who
		err = by.ScheduleBy(req.Action, time.Duration(delay)*time.Second, who)
	} else {
		err = p.exec.Schedule(req.Action, time.Duration(delay)*time.Second, msg)
	}
	if errors.Is(err, api.ErrHelperStopped) {
		return 503, map[string]any{"error": "helper stopped: start fairy-agent-helper to " + req.Action + " this machine", "code": api.ReasonHelperStopped}
	}
	var refused *ApprovalError
	if errors.As(err, &refused) { // the machine's approval check said no: its status, code and text
		slog.Warn("power: not scheduled", "action", req.Action, "code", refused.Code, "requested_by", who)
		return refused.Status, map[string]any{"error": refused.Msg, "code": refused.Code}
	}
	if err != nil {
		slog.Error("power: could not schedule", "action", req.Action, "error", err.Error(), "requested_by", who)
		return 500, map[string]any{"error": "could not schedule the " + req.Action + ": " + safeErr(err)}
	}
	at := collect.Round(float64(p.now().UnixMilli())/1000+float64(delay), 3)
	p.pending, p.dropped, p.since = &Pending{Action: req.Action, At: at, DelayS: delay, RequestedBy: who}, 0, p.steady()
	p.unstopped = true
	slog.Warn("power: scheduled", "action", req.Action, "delay_s", delay, "requested_by", who)
	return 200, map[string]any{"action": req.Action, "pending": *p.pending}
}

// errNoShutdownInProgress is Windows' ERROR_NO_SHUTDOWN_IN_PROGRESS: AbortSystemShutdown found nothing to abort.
const errNoShutdownInProgress = 1116

// abortGone reports whether the error code of a failed AbortSystemShutdown means there was nothing to abort
// (the shutdown was already aborted on the machine itself, e.g. with `shutdown /a`). Nothing is left to
// cancel then, so Cancel succeeds and the remembered action is dropped.
func abortGone(code uint32) bool { return code == errNoShutdownInProgress }

// sleepFromCaps reads SYSTEM_POWER_CAPABILITIES (Windows): SystemS1-S3 at bytes 3-5, AoAc (Modern Standby) at
// byte 20.
func sleepFromCaps(c []byte) (bool, string) {
	if len(c) < 21 {
		return false, "power capabilities not readable"
	}
	if c[3] != 0 || c[4] != 0 || c[5] != 0 {
		return true, ""
	}
	if c[20] != 0 {
		return false, "only Modern Standby (S0 low power idle), which a service cannot start; sleep (S3) is not available"
	}
	return false, "sleep (S1-S3) is not available on this machine (firmware or a hypervisor turned it off?)"
}
