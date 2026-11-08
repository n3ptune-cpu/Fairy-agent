package agent

import (
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

// PowerExec carries out a delayed shutdown or reboot (platform code: power_linux.go, power_windows.go).
type PowerExec interface {
	// Schedule arranges action ("shutdown" | "reboot") to happen after delay; message is shown to logged-in
	// users where the OS can.
	Schedule(action string, delay time.Duration, message string) error
	// Cancel stops a scheduled action.
	Cancel() error
}

// Pending is the scheduled power action as /metrics and /power report it.
type Pending struct {
	Action      string  `json:"action"`
	At          float64 `json:"at"`
	DelayS      int     `json:"delay_s"`
	RequestedBy string  `json:"requested_by"`
}

// Power handles POST /power: one pending shutdown or reboot at a time, cancellable until it happens.
type Power struct {
	exec     PowerExec
	minDelay int
	now      func() time.Time

	mu      sync.Mutex
	pending *Pending
}

// NewPower returns the power controller.
func NewPower(exec PowerExec, minDelayS int) *Power {
	return &Power{exec: exec, minDelay: minDelayS, now: time.Now}
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

// current returns the pending action, dropping it once its time has passed. Caller holds p.mu.
func (p *Power) current() *Pending {
	if p.pending != nil && float64(p.now().Unix()) > p.pending.At+60 {
		p.pending = nil
	}
	return p.pending
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
	return map[string]any{"enabled": true, "pending": pend, "min_delay_s": p.minDelay}
}

// PowerRequest is the POST /power body.
type PowerRequest struct {
	Action      string `json:"action"`
	DelayS      *int   `json:"delay_s"`
	RequestedBy any    `json:"requested_by"`
}

// Handle carries out one request and returns the HTTP status and body.
func (p *Power) Handle(req PowerRequest) (int, map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	who := cleanWho(req.RequestedBy)
	switch req.Action {
	case "cancel":
		if p.current() == nil {
			return 200, map[string]any{"action": "cancel", "pending": nil}
		}
		if err := p.exec.Cancel(); err != nil {
			slog.Error("power: cancel failed", "error", err.Error(), "requested_by", who)
			return 500, map[string]any{"error": "could not cancel: " + safeErr(err)}
		}
		slog.Warn("power: cancelled", "action", p.pending.Action, "requested_by", who)
		p.pending = nil
		return 200, map[string]any{"action": "cancel", "pending": nil}
	case "shutdown", "reboot":
	default:
		return 400, map[string]any{"error": "action must be shutdown, reboot or cancel"}
	}
	delay := 60
	if req.DelayS != nil {
		delay = *req.DelayS
	}
	if delay < p.minDelay || delay > 86400 {
		return 400, map[string]any{"error": fmt.Sprintf("delay_s must be between %d and 86400", p.minDelay)}
	}
	if c := p.current(); c != nil {
		return 409, map[string]any{"error": fmt.Sprintf("a %s is already pending; cancel it first", c.Action)}
	}
	msg := fmt.Sprintf("Fairy: %s requested by %s in %d seconds.", req.Action, who, delay)
	if err := p.exec.Schedule(req.Action, time.Duration(delay)*time.Second, msg); err != nil {
		slog.Error("power: could not schedule", "action", req.Action, "error", err.Error(), "requested_by", who)
		return 500, map[string]any{"error": "could not schedule the " + req.Action + ": " + safeErr(err)}
	}
	at := collect.Round(float64(p.now().UnixMilli())/1000+float64(delay), 3)
	p.pending = &Pending{Action: req.Action, At: at, DelayS: delay, RequestedBy: who}
	slog.Warn("power: scheduled", "action", req.Action, "delay_s", delay, "requested_by", who)
	return 200, map[string]any{"action": req.Action, "pending": *p.pending}
}
