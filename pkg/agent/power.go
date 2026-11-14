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

// errTooLate is a PowerExec's answer to a Cancel that came after it carried the action out (Linux: after the
// agent's timer ran `systemctl poweroff`): nothing is left that could be stopped.
var errTooLate = errors.New("too late to cancel")

// powerBy is a PowerExec that wants the (cleaned) requester instead of a ready message: the Windows helper,
// which takes no free text.
type powerBy interface {
	ScheduleBy(action string, delay time.Duration, who string) error
}

// powerApproved is a PowerExec that passes the request's approval on to whoever checks it (the Windows helper).
type powerApproved interface {
	ScheduleApproved(action string, delay time.Duration, who string, ap *api.Approval) error
}

// powerRun is a PowerExec that passes the id of the confirmed run a shutdown names on to whoever checks it
// (the Windows helper).
type powerRun interface {
	ScheduleRun(action string, delay time.Duration, who, run string) error
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
	// unstopped: this process scheduled an action, or showed one the exec remembers, and the exec has not been
	// asked to stop it since (or the asking failed). The record above is what this process believes; the
	// countdown is the exec's. While this is set, Cancel asks the exec also when the record shows nothing.
	unstopped bool
	// maybe is steady's reading when a shutdown, reboot or sleep (maybeWhat) got no answer from the exec (zero:
	// none, or settled): the helper has the request and may still take it. For unansweredFor after that, or
	// until the exec itself shows a pending action, a cancel is passed on whatever the record says, and one
	// that found nothing is not answered "ok" (review of fix7, RF7-02). A later request that was accepted does
	// not end it: the earlier one can still be taken once the later one is cancelled.
	maybe     time.Time
	maybeWhat string
	// runLive, when set, reports whether whoever checks on this machine has a run that a cancel must end (the
	// Windows helper, asked at this moment: HelperPower.RunLive). A cancel is then passed on to the exec also
	// when nothing is on record as pending: the run may be armed with nothing scheduled yet, and the cancel is
	// what disarms it. nil, or false: nothing changes for a cancel.
	runLive func() bool
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

// unansweredFor is how long after a request that got no answer the exec may still take it, as far as Power
// goes: see Power.maybe. What can hold a request up inside the helper before its power part has it (its request
// budget, the approval's check, a disk that stalls) takes milliseconds as a rule; a helper that does not answer
// at all is "not running" to the agent, and a cancel then says so (503).
const unansweredFor = time.Minute

// maybePending reports whether a request that got no answer may still be taken by the exec. Caller holds p.mu.
func (p *Power) maybePending() bool {
	if p.maybe.IsZero() {
		return false
	}
	if p.steady().Sub(p.maybe) > unansweredFor {
		p.maybe = time.Time{}
		return false
	}
	return true
}

// defaultPowerDelayS is the delay of a POST /power without delay_s. It is also the delay an approval must have
// been given for when the request names none.
const defaultPowerDelayS = 60

// NewPower returns the power controller.
func NewPower(exec PowerExec, minDelayS int) *Power {
	return &Power{exec: exec, minDelay: minDelayS, now: time.Now, steady: time.Now}
}

// NewPowerForRuns is NewPower for a machine whose power part also ends runs when it is asked to cancel (the
// Windows helper): runLive says, asked at the moment of a cancel, whether it has a run to end (HelperPower.
// RunLive). A cancel is then passed on to it also when nothing is on record as pending.
func NewPowerForRuns(exec PowerExec, minDelayS int, runLive func() bool) *Power {
	p := NewPower(exec, minDelayS)
	p.runLive = runLive
	return p
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
			// Shown as Fairy's own, so Cancel asks the exec for it also when a later look shows nothing: what the
			// helper said is a few seconds old, and its time is compared with the time of day here (a clock set
			// forward hides it until the helper's next status, which gives it its new time).
			p.unstopped = true
			p.maybe = time.Time{} // the exec has an action: a request that got no answer has arrived
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
	// Run is the id of the confirmed run a shutdown without approval names ("": none). Where the helper checks,
	// it is passed on with the request; where this process checks, Gate is the check of it.
	Run string `json:"-"`
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
		maybe := p.maybePending()
		if maybe {
			// A request got no answer a moment ago. What counts for this cancel is the helper's word of now, not
			// its status of some seconds ago, in which the request may not be yet.
			if a, ok := p.exec.(interface{ AskAgain() }); ok {
				a.AskAgain()
			}
		}
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
			if !p.unstopped && !maybe && !(p.runLive != nil && p.runLive()) {
				return 200, map[string]any{"action": "cancel", "pending": nil}
			}
		}
		err := p.exec.Cancel()
		if errors.Is(err, errTooLate) {
			// The exec has carried the action out: there is nothing it could still stop, now or later.
			p.unstopped = false
			if c != nil {
				// Still on record (the minute after its time): not "cancelled". 409, the agent's own "no" for
				// a request the state does not allow; the record stays for its minute, as without a cancel.
				slog.Warn("power: cancel came too late", "action", c.Action, "error", err.Error(), "requested_by", who)
				return 409, map[string]any{"error": safeErr(err) + ": the " + c.Action + " is being carried out"}
			}
			err = nil // nothing on record, nothing left to stop: a cancel with nothing pending
		}
		if errors.Is(err, api.ErrHelperStopped) {
			return 503, map[string]any{"error": "helper stopped: cannot cancel", "code": api.ReasonHelperStopped}
		} else if unanswered(err) {
			// The helper has the cancel and did not answer: the action may be stopped or not. Not "could not
			// cancel", and not "cancelled": the record stays, and the cancel can be sent again.
			slog.Error("power: the cancel got no answer", "error", err.Error(), "requested_by", who)
			return helperUnanswered("the cancel", "the pending action may be cancelled or not: look at what the machine shows as pending, and cancel again if it is still there")
		} else if err != nil {
			slog.Error("power: cancel failed", "error", err.Error(), "requested_by", who)
			return 500, map[string]any{"error": "could not cancel: " + safeErr(err)}
		}
		if c == nil && p.maybePending() {
			// The helper took the cancel and had nothing to stop, or stopped what had just arrived: its answer
			// does not say which. The request that got no answer may still be on its way inside the helper, and
			// then it is scheduled after this cancel. "ok, nothing pending" for that was wrong (a run wrote "it is
			// ON" and the machine went off): 409, the agent's own "not now", and the flag stays, so the cancel
			// sent again is passed on again.
			slog.Warn("power: a cancel found nothing to stop; a request that got no answer may still be scheduled", "action", p.maybeWhat, "requested_by", who)
			return 409, map[string]any{"error": "nothing was pending when the cancel reached the helper, but the " + p.maybeWhat +
				" that got no answer a moment ago may still be scheduled: send the cancel again (for a minute after such a request the agent cannot say that nothing is pending)"}
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
	msg := PowerMessage(req.Action, who, time.Duration(delay)*time.Second)
	var err error
	if ap, ok := p.exec.(powerApproved); ok && req.Approval != nil {
		err = ap.ScheduleApproved(req.Action, time.Duration(delay)*time.Second, who, req.Approval)
	} else if rn, ok := p.exec.(powerRun); ok && req.Run != "" { // the helper checks the run, as it checks an approval
		err = rn.ScheduleRun(req.Action, time.Duration(delay)*time.Second, who, req.Run)
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
	if unanswered(err) {
		// The helper has the request and did not answer in its time: the countdown may be running (audit 6,
		// r4-a1-01: "could not schedule" for a shutdown that Windows was counting down). Nothing is put on
		// record here, because nobody knows; what the helper's next status says is shown (its old one is not
		// used again: HelperClient.call). And a cancel asks the helper from now on, also while nothing is shown;
		// for a minute, or until the helper shows the action, one that finds nothing is not "ok" (maybe). What
		// the helper reports from now on is this request, not the echo of an action cancelled before (dropped).
		p.unstopped = true
		p.maybe, p.maybeWhat, p.dropped = p.steady(), req.Action, 0
		slog.Error("power: the request got no answer; it may be scheduled all the same", "action", req.Action, "error", err.Error(), "requested_by", who)
		return helperUnanswered("the "+req.Action, "it may be scheduled all the same, now or in a moment. Look at what the machine shows as pending; every cancel of the next minute is passed on to the helper")
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

// ScheduleOwn schedules a shutdown that this process decided itself, with nobody's request: the self-off of a
// run, where the agent is the checker (approval.RunWatch). It is the same delayed shutdown POST /power
// schedules, through the same exec, and it is on record like one: /metrics shows it as pending, and POST /power
// cancel stops it. It is refused while another action is pending.
func (p *Power) ScheduleOwn(delay time.Duration, message, who string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if c := p.current(); c != nil {
		return fmt.Errorf("a %s is already pending", c.Action)
	}
	who = cleanWho(who)
	if err := p.exec.Schedule("shutdown", delay, message); err != nil {
		slog.Error("power: could not schedule", "action", "shutdown", "error", err.Error(), "requested_by", who)
		return err
	}
	d := int(delay / time.Second)
	at := collect.Round(float64(p.now().UnixMilli())/1000+float64(d), 3)
	p.pending, p.dropped, p.since = &Pending{Action: "shutdown", At: at, DelayS: d, RequestedBy: who}, 0, p.steady()
	p.unstopped = true
	slog.Warn("power: scheduled", "action", "shutdown", "delay_s", d, "requested_by", who)
	return nil
}

// CancelOwn is POST /power cancel asked by this process itself (the countdown of a run that ended).
func (p *Power) CancelOwn(who string) error {
	if st, body := p.Handle(PowerRequest{Action: "cancel", RequestedBy: who}); st != 200 {
		return fmt.Errorf("%v", body["error"])
	}
	return nil
}

// pendingSleep is the one sleep the Windows power part waits for: a timer in the process, because Windows
// counts no sleep down (power_windows.go). It lives here, with the other pieces of that file that need no
// Windows call, so that its tests run everywhere.
//
// It knows of a sleep only while the sleep is still to come. The timer used to stay on record after it had
// run (review of fix7, RF7-01): the next Cancel, of a shutdown asked for any time later, found "a sleep",
// stopped the timer that had long run, answered ok, and never asked Windows to abort. The helper forgot its
// record, the agent answered "cancelled", and Windows went on counting the shutdown down.
type pendingSleep struct {
	mu    sync.Mutex
	timer *time.Timer // nil: no sleep is waiting
}

// set arranges for run to be called after delay, in the place of a sleep that was waiting. Either stop took
// the sleep away or run is called, never both; and from the moment run is called no sleep is waiting, whatever
// becomes of it (the sleep was carried out, or it failed).
func (s *pendingSleep) set(delay time.Duration, run func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer != nil {
		s.timer.Stop()
	}
	var t *time.Timer
	t = time.AfterFunc(delay, func() {
		s.mu.Lock()
		if s.timer != t { // stopped, or replaced by a later sleep, in the moment it fired
			s.mu.Unlock()
			return
		}
		s.timer = nil
		s.mu.Unlock()
		run()
	})
	s.timer = t
}

// stop takes a waiting sleep away and reports whether there was one.
func (s *pendingSleep) stop() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer == nil {
		return false
	}
	s.timer.Stop()
	s.timer = nil
	return true
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
