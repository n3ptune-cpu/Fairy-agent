package agent

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
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

// FanControl is what the HTTP API needs from fan control: the in-process Fan, or (Windows) the elevated
// helper's Fan reached over its pipe.
type FanControl interface {
	Status(ctx context.Context) map[string]any
	SetMode(ctx context.Context, mode, who string) (int, map[string]any)
	SetDuty(ctx context.Context, zone, percent int, who string) (int, map[string]any)
}

// SensorSource feeds the BMC's readings into /metrics: the in-process BMC, or (Windows) the helper's.
type SensorSource interface {
	Metrics() ([]collect.Temp, []collect.Fan, []collect.Voltage)
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

	mu          sync.Mutex // one fan change at a time (API and watchdog)
	unsupported map[string]bool
	evMu        sync.Mutex
	events      []FanEvent
	noTemp      int
}

// NewFan returns the fan controller.
func NewFan(t ipmi.Transport, bmc *BMC, cfg FanConfig, localTemps func() []collect.Temp) *Fan {
	return &Fan{t: t, bmc: bmc, cfg: cfg, localTemps: localTemps, now: time.Now, unsupported: map[string]bool{}}
}

// modeUnsupported reports whether a SetFanMode error means "this board has no such mode" (the BMC rejects the
// mode byte itself), rather than a failure worth retrying.
func modeUnsupported(err error) bool {
	return ipmi.IsCompletion(err, 0xCC) || ipmi.IsCompletion(err, 0xC9)
}

// unsupportedModes are the modes the BMC refused since the agent started, sorted. Caller holds f.mu.
func (f *Fan) unsupportedModes() []string {
	out := []string{}
	for m := range f.unsupported {
		out = append(out, m)
	}
	slices.Sort(out)
	return out
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
// unsupported_modes lists the modes this board's BMC refused (since the agent started), so the panel can grey
// them out; auto_mode is the configured "not overridden" mode.
func (f *Fan) Status(ctx context.Context) map[string]any {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	out := map[string]any{"enabled": true, "vendor": f.cfg.Vendor, "mode": nil, "error": nil, "overridden": false,
		"duty": map[string]int{}, "min_duty": f.cfg.MinDuty, "max_temp_c": f.cfg.MaxTempC, "fans": f.bmc.FanList(),
		"events": f.recentEvents(), "auto_mode": f.cfg.AutoMode}
	f.mu.Lock()
	defer f.mu.Unlock()
	out["unsupported_modes"] = f.unsupportedModes()
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

// SetMode is POST /fan/mode. A mode the BMC rejects as invalid (completion code 0xCC / 0xC9: the board has no
// such mode) is remembered and reported in /fan/status `unsupported_modes`; the answer is 422 with code
// "fan_mode_unsupported". The mode is still tried again on the next request (a BMC firmware update may add it).
func (f *Fan) SetMode(ctx context.Context, mode, who string) (int, map[string]any) {
	if _, ok := ipmi.ModeByte(mode); !ok {
		return 400, map[string]any{"error": "mode must be standard, full, optimal or heavyio"}
	}
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := ipmi.SetFanMode(ctx, f.t, mode); err != nil {
		if !modeUnsupported(err) {
			return 502, map[string]any{"error": "BMC refused the fan mode: " + safeErr(err)}
		}
		if !f.unsupported[mode] {
			f.unsupported[mode] = true
			f.event("mode "+mode+" unsupported", "BMC refused it: "+safeErr(err))
		}
		if mode == f.cfg.AutoMode {
			slog.Warn("fan_control.auto_mode is a mode this board's BMC does not support; set it to one the BMC accepts, "+
				"e.g. `fairy-agent config set fan_control.auto_mode standard`, then restart fairy-agent",
				"auto_mode", mode, "error", safeErr(err))
		}
		return 422, map[string]any{"error": fmt.Sprintf("BMC refused the fan mode %s: %s; this board's BMC does not support it",
			mode, safeErr(err)), "code": "fan_mode_unsupported", "mode": mode}
	}
	delete(f.unsupported, mode)
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

// Auto hands the fans back to the BMC's automatic mode: auto_mode, or "standard" when the board refuses that.
// With force false it does so only while a fixed duty can be in effect (mode "full", or the mode cannot be
// read); a mode the owner chose (standard, optimal, heavyio) is left alone. The Windows helper calls it when it
// stops, so fans never keep a fixed duty without the watchdog. It returns the mode the fans are in afterwards.
func (f *Fan) Auto(ctx context.Context, who string, force bool) (string, error) {
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	f.mu.Lock()
	defer f.mu.Unlock()
	mode, err := ipmi.GetFanMode(ctx, f.t)
	if err == nil && !force && mode != "full" {
		return mode, nil
	}
	f.noTemp = 0
	want := f.cfg.AutoMode
	err = ipmi.SetFanMode(ctx, f.t, want)
	if err != nil && modeUnsupported(err) && want != "standard" {
		f.unsupported[want] = true
		want = "standard"
		err = ipmi.SetFanMode(ctx, f.t, want)
	}
	if err != nil {
		f.event("auto failed", who+": "+safeErr(err))
		return "", err
	}
	f.event("mode="+want+" (BMC automatic)", who)
	return want, nil
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
	case !(temp < f.cfg.MaxTempC):
		// written as "not below the limit": a reading or a limit that is not a number (NaN) compares false
		// with everything, so `temp >= limit` would never act on it
		f.failSafe(ctx, tooHot(name, temp, f.cfg.MaxTempC))
	default:
		f.noTemp = 0
	}
}

// tooHot words why temp counts as "at or above the limit" (also when one of the two is not a number).
func tooHot(name string, temp, limit float64) string {
	if temp >= limit {
		return fmt.Sprintf("%s %.1f °C >= %.0f °C", name, temp, limit)
	}
	return fmt.Sprintf("%s %v °C cannot be compared with the limit %v °C (not a number)", name, temp, limit)
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
