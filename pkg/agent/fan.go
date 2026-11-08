package agent

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
)

// FanEvent is one entry of the fan log (/fan/status `events`).
type FanEvent struct {
	T      float64 `json:"t"`
	Action string  `json:"action"`
	Detail string  `json:"detail"`
}

// Fan is Supermicro BMC fan control: read and set the fan mode, set a zone's duty in "full" mode (never below
// MinDuty), and a watchdog that puts the fans back to 100 % when the CPU reaches MaxTempC (or when no temperature
// can be read) while a manual duty is in effect.
type Fan struct {
	t          ipmi.Transport
	bmc        *BMC
	cfg        FanConfig
	localTemps func() []collect.Temp
	now        func() time.Time

	mu     sync.Mutex // one fan change at a time (API and watchdog)
	evMu   sync.Mutex
	events []FanEvent
	noTemp int
}

// NewFan returns the fan controller.
func NewFan(t ipmi.Transport, bmc *BMC, cfg FanConfig, localTemps func() []collect.Temp) *Fan {
	return &Fan{t: t, bmc: bmc, cfg: cfg, localTemps: localTemps, now: time.Now}
}

func (f *Fan) event(action, detail string) {
	f.evMu.Lock()
	defer f.evMu.Unlock()
	f.events = append(f.events, FanEvent{T: collect.Round(float64(f.now().UnixMilli())/1000, 3), Action: action, Detail: detail})
	if len(f.events) > 50 {
		f.events = f.events[len(f.events)-50:]
	}
	slog.Info("fan", "action", action, "detail", detail)
}

func (f *Fan) recentEvents() []FanEvent {
	f.evMu.Lock()
	defer f.evMu.Unlock()
	n := len(f.events)
	return append([]FanEvent{}, f.events[max(0, n-10):]...)
}

func ctxTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 20*time.Second)
}

// Status is /fan/status. BMC errors are reported in `error` (HTTP 200), so the panel can show them.
func (f *Fan) Status(ctx context.Context) map[string]any {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	out := map[string]any{"enabled": true, "vendor": f.cfg.Vendor, "mode": nil, "error": nil, "overridden": false,
		"duty": map[string]int{}, "min_duty": f.cfg.MinDuty, "max_temp_c": f.cfg.MaxTempC, "fans": f.bmc.FanList(),
		"events": f.recentEvents()}
	f.mu.Lock()
	defer f.mu.Unlock()
	mode, err := ipmi.GetFanMode(ctx, f.t)
	if err != nil {
		out["error"] = "cannot read the fan mode: " + safeErr(err)
		return out
	}
	out["mode"] = mode
	out["overridden"] = mode != f.cfg.AutoMode
	if mode == "full" {
		duty := map[string]int{}
		for z := byte(0); z <= 1; z++ {
			if d, err := ipmi.GetDuty(ctx, f.t, z); err == nil {
				duty[strconv.Itoa(int(z))] = d
			}
		}
		out["duty"] = duty
	}
	return out
}

// SetMode is POST /fan/mode.
func (f *Fan) SetMode(ctx context.Context, mode, who string) (int, map[string]any) {
	if _, ok := ipmi.ModeByte(mode); !ok {
		return 400, map[string]any{"error": "mode must be standard, full, optimal or heavyio"}
	}
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ipmi.SetFanMode(ctx, f.t, mode); err != nil {
		return 502, map[string]any{"error": "BMC refused the fan mode: " + safeErr(err)}
	}
	f.noTemp = 0
	f.event("mode="+mode, who)
	return 200, map[string]any{"mode": mode}
}

// SetDuty is POST /fan/duty: only in "full" mode (the BMC ignores duties otherwise), never below MinDuty.
func (f *Fan) SetDuty(ctx context.Context, zone, percent int, who string) (int, map[string]any) {
	if zone != 0 && zone != 1 {
		return 400, map[string]any{"error": "zone must be 0 or 1"}
	}
	if percent < f.cfg.MinDuty || percent > 100 {
		return 400, map[string]any{"error": fmt.Sprintf("percent must be an integer between %d and 100", f.cfg.MinDuty)}
	}
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	mode, err := ipmi.GetFanMode(ctx, f.t)
	if err != nil {
		return 502, map[string]any{"error": "cannot read the fan mode: " + safeErr(err)}
	}
	if mode != "full" {
		return 409, map[string]any{"error": fmt.Sprintf("fan mode is %s; set mode 'full' first (duty is ignored otherwise)", mode)}
	}
	if err := ipmi.SetDuty(ctx, f.t, byte(zone), percent); err != nil {
		return 502, map[string]any{"error": "BMC refused the duty: " + safeErr(err)}
	}
	f.event(fmt.Sprintf("duty zone %d=%d%%", zone, percent), who)
	return 200, map[string]any{"zone": zone, "percent": percent}
}

// WatchdogInterval is how often the watchdog looks at the temperature while a manual duty is set.
const WatchdogInterval = 10 * time.Second

// RunWatchdog checks every WatchdogInterval until ctx ends.
func (f *Fan) RunWatchdog(ctx context.Context) {
	t := time.NewTicker(WatchdogInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f.WatchdogOnce(ctx)
		}
	}
}

// WatchdogOnce is one watchdog check (exported for tests). Nothing happens in the BMC's automatic modes or when
// both zones already run at 100 %.
func (f *Fan) WatchdogOnce(ctx context.Context) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	mode, err := ipmi.GetFanMode(ctx, f.t)
	if err != nil || mode != "full" {
		f.noTemp = 0
		return
	}
	manual := false
	for z := byte(0); z <= 1; z++ {
		if d, err := ipmi.GetDuty(ctx, f.t, z); err != nil || d < 100 {
			manual = true
		}
	}
	if !manual {
		f.noTemp = 0
		return
	}
	var local []collect.Temp
	if f.localTemps != nil {
		local = f.localTemps()
	}
	temp, name, ok := MaxCPUTemp(f.bmc.Readings(), local)
	switch {
	case !ok:
		f.noTemp++
		if f.noTemp >= 3 {
			f.failSafe(ctx, "no temperature reading for 30 s while fans were set manually")
		}
	case temp >= f.cfg.MaxTempC:
		f.failSafe(ctx, fmt.Sprintf("%s %.1f °C >= %.0f °C", name, temp, f.cfg.MaxTempC))
	default:
		f.noTemp = 0
	}
}

// failSafe sets both zones to 100 % (mode stays "full"). Caller holds f.mu.
func (f *Fan) failSafe(ctx context.Context, why string) {
	f.noTemp = 0
	firstErr := ipmi.SetDuty(ctx, f.t, 0, 100)
	_ = ipmi.SetDuty(ctx, f.t, 1, 100) // boards without a peripheral zone refuse this; zone 0 is what matters
	if firstErr != nil {
		slog.Error("fan watchdog could not set 100 %", "reason", why, "error", safeErr(firstErr))
		f.event("watchdog failed", why+": "+safeErr(firstErr))
		return
	}
	slog.Warn("fan watchdog: fans to 100 %", "reason", why)
	f.event("watchdog: duty 100%", why)
}
