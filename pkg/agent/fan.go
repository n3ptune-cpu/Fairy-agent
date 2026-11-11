package agent

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"math"
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
	actedAt     time.Time // when the watchdog last sent the fans to 100 % (zero: not since the start)
	modeFails   int       // watchdog checks in a row that could not read the fan mode (counted up to fanBlindAfter)
	blindAt     time.Time // when the watchdog last acted without knowing the fan mode (zero: not in this spell)
	blindSaid   string    // what that action came to, as last logged (so one spell is logged once, not every 30 s)
	closed      bool      // Shutdown was called: no more changes from the API
	changed     bool      // SetMode or SetDuty changed the fans since this process started

	// /fan/status and the watchdog (see reading). Lock order: statusMu, watchdogMu, mu.
	statusMu   sync.Mutex // held by the one status request that asks the BMC
	last       fanReading // what that request was told, for the requests that waited behind it (statusMu)
	watchdogMu sync.Mutex // held by a watchdog check from before it waits for mu until it is done
}

// fanReading is what /fan/status asks the BMC: the fan mode, in "full" mode the duty of both zones, and the
// modes the BMC refused so far.
type fanReading struct {
	at          time.Time // when the BMC had answered
	mode        string
	duty        map[string]int
	unsupported []string
	err         string // why the mode could not be read ("": it could)
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

// fanBMCTimeout is the time one fan operation has for all its BMC commands. (A variable for the tests, which
// run ten times faster.)
var fanBMCTimeout = 20 * time.Second

func ctxTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, fanBMCTimeout)
}

// Status is /fan/status. BMC errors are reported in `error` (HTTP 200), so the panel can show them.
// unsupported_modes lists the modes this board's BMC refused (since the agent started), so the panel can grey
// them out; auto_mode is the configured "not overridden" mode.
func (f *Fan) Status(ctx context.Context) map[string]any {
	out := map[string]any{"enabled": true, "vendor": f.cfg.Vendor, "mode": nil, "error": nil, "overridden": false,
		"duty": map[string]int{}, "min_duty": f.cfg.MinDuty, "max_temp_c": f.cfg.MaxTempC, "fans": f.bmc.FanList(),
		"events": f.recentEvents(), "auto_mode": f.cfg.AutoMode}
	r := f.reading(ctx)
	out["unsupported_modes"] = slices.Clone(r.unsupported)
	if r.err != "" {
		out["error"] = r.err
		return out
	}
	out["mode"] = r.mode
	out["overridden"] = r.mode != f.cfg.AutoMode
	if r.duty != nil {
		out["duty"] = maps.Clone(r.duty)
	}
	return out
}

// reading asks the BMC for the fan mode and, in "full" mode, the duty of both zones.
//
// /fan/status needs only the read token, four requests may be in flight, and each made up to three BMC
// commands under f.mu, the lock the watchdog needs. With a BMC that takes 1.5 s for a command, four callers
// that asked without a pause kept the watchdog waiting for longer than its own time limit, check after check
// (audit 4, T-08). Now:
//
//   - one status request asks the BMC at a time (statusMu). A request that waited behind it is answered with
//     what that one was told, which is newer than the request itself. Nothing is kept beyond that: a request
//     that arrives later asks the BMC again;
//   - a watchdog check goes first (watchdogMu): while one is running or waiting, no status request starts to
//     ask the BMC. So the watchdog waits for the one status request that was already asking, at most.
func (f *Fan) reading(ctx context.Context) fanReading {
	asked := time.Now()
	f.statusMu.Lock()
	defer f.statusMu.Unlock()
	if f.last.at.After(asked) {
		return f.last
	}
	f.watchdogMu.Lock() // waits for a watchdog check that is running or waiting for mu
	f.mu.Lock()
	f.watchdogMu.Unlock()
	defer f.mu.Unlock()
	ctx, cancel := ctxTimeout(ctx) // counted from here: the time spent waiting for the locks is not the BMC's
	defer cancel()
	r := fanReading{unsupported: f.unsupportedModes()}
	mode, err := ipmi.GetFanMode(ctx, f.t)
	if err != nil {
		r.err = "cannot read the fan mode: " + safeErr(err)
		return r // not passed on: it may be this caller's own time that was over
	}
	r.mode = mode
	if mode == "full" {
		r.duty = map[string]int{}
		for z := byte(0); z <= 1; z++ {
			if d, err := ipmi.GetDuty(ctx, f.t, z); err == nil {
				r.duty[strconv.Itoa(int(z))] = d
			}
		}
	}
	if ctx.Err() == nil { // a reading that was cut short by this caller's own limit is not passed on either
		r.at = time.Now()
		f.last = r
	}
	return r
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
	if f.closed {
		return 503, stoppingBody()
	}
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
	f.changed = true
	f.event("mode="+mode, who)
	return 200, map[string]any{"mode": mode}
}

// FanHoldOff is how long after the watchdog sent the fans to 100 % a duty below 100 % is refused.
const FanHoldOff = 5 * time.Minute

// dutyRefusal says why a duty below 100 % cannot be set now ("" when it can): the hottest CPU reading is at or
// above MaxTempC (or is not a number), there is no temperature reading at all, or the watchdog acted less than
// FanHoldOff ago. Without this a request for the minimum right after the watchdog's 100 % was accepted, and
// repeating it kept the fans low while the CPU stayed over the limit. Caller holds f.mu.
func (f *Fan) dutyRefusal() (code, msg string) {
	if !f.actedAt.IsZero() {
		if left := FanHoldOff - f.now().Sub(f.actedAt); left > 0 {
			return "fan_watchdog_hold", fmt.Sprintf("the temperature watchdog set the fans to 100 %% a moment ago; "+
				"a lower speed is accepted again in %d s", int(left.Seconds())+1)
		}
	}
	var local []collect.Temp
	if f.localTemps != nil {
		local = f.localTemps()
	}
	readings := f.bmc.WatchdogReadings() // as for the watchdog: an old reading is no reading
	temp, name, ok := MaxCPUTemp(readings, local)
	if ok && !(temp < f.cfg.MaxTempC) {
		return "fan_too_hot", tooHot(name, temp, f.cfg.MaxTempC) + ": only 100 % is accepted until it is cooler"
	}
	if !ok {
		// MaxCPUTemp leaves out a reading that is not a number, so "no usable reading" can mean that a sensor
		// is there and reports NaN. That is not "below the limit" either.
		if name, v, bad := unusableTemp(readings, local); bad {
			return "fan_too_hot", tooHot(name, v, f.cfg.MaxTempC) + ": only 100 % is accepted until it reads a temperature"
		}
		return "fan_no_temperature", "no temperature reading (neither from the BMC nor from the operating system; " +
			"right after a start the BMC's sensors take a moment): only 100 % is accepted until there is one"
	}
	return "", ""
}

// unusableTemp returns the first temperature sensor whose reading MaxCPUTemp cannot use (NaN or -Inf).
func unusableTemp(bmc []ipmi.Reading, local []collect.Temp) (string, float64, bool) {
	unusable := func(v float64) bool { return math.IsNaN(v) || math.IsInf(v, -1) }
	for _, r := range bmc {
		if r.Sensor.Type == ipmi.TypeTemperature && unusable(r.Value) {
			return r.Sensor.Name, r.Value, true
		}
	}
	for _, t := range local {
		if unusable(t.Current) {
			name := t.Sensor
			if t.Label != nil {
				name += " " + *t.Label
			}
			return name, t.Current, true
		}
	}
	return "", 0, false
}

// SetDuty is POST /fan/duty: only in "full" mode (the BMC ignores duties otherwise), never below MinDuty, and
// below 100 % only while dutyRefusal has no objection (409 otherwise).
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
	if f.closed {
		return 503, stoppingBody()
	}
	mode, err := ipmi.GetFanMode(ctx, f.t)
	if err != nil {
		return 502, map[string]any{"error": "cannot read the fan mode: " + safeErr(err)}
	}
	if mode != "full" {
		return 409, map[string]any{"error": fmt.Sprintf("fan mode is %s; set mode 'full' first (duty is ignored otherwise)", mode)}
	}
	if percent < 100 {
		if code, msg := f.dutyRefusal(); code != "" {
			slog.Warn("fan duty refused", "zone", zone, "percent", percent, "by", who, "reason", msg)
			return 409, map[string]any{"error": msg, "code": code}
		}
	}
	if err := ipmi.SetDuty(ctx, f.t, byte(zone), percent); err != nil {
		return 502, map[string]any{"error": "BMC refused the duty: " + safeErr(err)}
	}
	f.changed = true
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
	return f.auto(ctx, who, force)
}

// auto is Auto for a caller that holds f.mu.
func (f *Fan) auto(ctx context.Context, who string, force bool) (string, error) {
	mode, err := ipmi.GetFanMode(ctx, f.t)
	if err == nil && !force && mode != "full" {
		return mode, nil
	}
	want, err := f.setAuto(ctx)
	if err != nil {
		f.event("auto failed", who+": "+safeErr(err))
		return "", err
	}
	f.event("mode="+want+" (BMC automatic)", who)
	return want, nil
}

// setAuto sends the BMC's automatic mode (auto_mode, or "standard" when the board refuses that) and returns
// the mode that was taken. It writes no event. Caller holds f.mu.
func (f *Fan) setAuto(ctx context.Context) (string, error) {
	f.noTemp = 0
	want := f.cfg.AutoMode
	err := ipmi.SetFanMode(ctx, f.t, want)
	if err != nil && modeUnsupported(err) && want != "standard" {
		f.unsupported[want] = true
		want = "standard"
		err = ipmi.SetFanMode(ctx, f.t, want)
	}
	if err != nil {
		return "", err
	}
	return want, nil
}

func stoppingBody() map[string]any {
	return map[string]any{"error": "the agent is stopping; the fans are handed back to the BMC", "code": "stopping"}
}

// FanStopLimit is how long handing the fans back may take when the agent stops.
const FanStopLimit = 10 * time.Second

// Shutdown is for the process that runs the watchdog, when it stops: from now on SetMode and SetDuty are
// refused (503), then the fans go back to the BMC's automatic mode as with Auto(ctx, who, false), so no fixed
// duty stays set with nothing watching the temperature. If the BMC does not take the automatic mode, both zones
// are sent to 100 % instead. It returns the mode the fans are in afterwards.
func (f *Fan) Shutdown(ctx context.Context, who string) (string, error) {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	mode, err := f.Auto(ctx, who, false)
	if err != nil {
		fctx, cancel := context.WithTimeout(context.Background(), FanStopLimit/2)
		defer cancel()
		f.mu.Lock()
		f.failSafe(fctx, who+": the BMC did not take its automatic mode")
		f.mu.Unlock()
	}
	return mode, err
}

// Run is the watchdog's goroutine in the process that owns the fans. A fixed duty found at the start was left
// by a process that ended without handing the fans back (killed, crashed, power cut): it goes back to the BMC's
// automatic mode first, as it would have on a clean stop (not if a request already changed the fans in the
// meantime). Then it checks every WatchdogInterval until ctx ends.
func (f *Fan) Run(ctx context.Context) {
	actx, cancel := ctxTimeout(ctx)
	f.mu.Lock()
	var err error
	if !f.changed && !f.closed {
		_, err = f.auto(actx, "agent starting", false)
	}
	f.mu.Unlock()
	cancel()
	if err != nil && ctx.Err() == nil {
		slog.Warn("fan control: could not hand the fans back to the BMC at start; the watchdog is running", "error", safeErr(err))
	}
	f.RunWatchdog(ctx)
}

// ipmiTransport builds the BMC connection (a fake in tests).
var ipmiTransport = IPMITransport

// FansAuto is `fairy-agent fans-auto`, which systemd runs after the agent has ended for any reason
// (ExecStopPost): with fan control on, it hands the fans back to the BMC's automatic mode if a fixed duty may
// be in effect, exactly as the agent does itself on a clean stop. It takes nothing but the agent's own config.
// done is false when fan control is not switched on (nothing was sent to the BMC).
func FansAuto(ctx context.Context, cfg *Config) (mode string, done bool, err error) {
	if !cfg.FanControl.Enabled || !cfg.IPMI.Enabled {
		return "", false, nil
	}
	if _, err := LoadEnvFile(cfg.EnvFile); err != nil {
		return "", true, err
	}
	t, err := ipmiTransport(cfg.IPMI)
	if err != nil {
		return "", true, err
	}
	defer t.Close()
	mode, err = NewFan(t, nil, cfg.FanControl, nil).Shutdown(ctx, "fans-auto (the agent has ended)")
	return mode, true, err
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

// fanBlindAfter is how many watchdog checks in a row must fail to read the fan mode before the watchdog acts
// without knowing it. One failed question (a BMC that is busy for a moment answers 0xC0, a lost packet) is
// not a reason to send fans to 100 %: with the 10 s between checks, three in a row are a BMC that has not
// said its mode for 20 s, the same patience as "no temperature for 30 s".
const fanBlindAfter = 3

// fanBlindRetry is how long the watchdog waits before it acts again while it cannot read the fan mode: its
// commands then go to a BMC that is busy or not answering, and one try in 30 s is enough of them.
const fanBlindRetry = 30 * time.Second

// WatchdogOnce is one watchdog check (exported for tests). Nothing happens in the BMC's automatic modes or when
// both zones already run at 100 %.
//
// When the BMC does not say which mode the fans are in, a fixed duty may be in effect. The check used to stop
// there and forget its count of checks without a temperature, so a BMC that failed that one question now and
// then kept the fans at a manual speed with no temperature known at all, and a check that could not read the
// mode did nothing about a hot CPU (review N9). Now:
//
//   - the count of checks without a temperature goes on over a check that could not read the mode;
//   - one or two such checks in a row change nothing by themselves: the next check that reads the mode acts as
//     always (so a single failed question delays the watchdog by one check, and never moves a fan);
//   - from the third in a row (fanBlindAfter) the watchdog goes on as if the mode were "full": at the
//     temperature limit or without a temperature it does what failSafeBlind says, 100 % first;
//   - the first check that reads the mode again ends that, and the watchdog is back to what it does with a
//     known mode.
//
// The check's time limit starts when it has the lock. It used to start before, so a check that waited for the
// lock behind /fan/status requests came to the BMC with its time already over (audit 4, T-08). And it goes
// before status requests that have not started to ask the BMC (see reading).
func (f *Fan) WatchdogOnce(ctx context.Context) {
	f.watchdogMu.Lock()
	defer f.watchdogMu.Unlock()
	f.mu.Lock()
	defer f.mu.Unlock()
	ctx, cancel := ctxTimeout(ctx)
	defer cancel()
	mode, modeErr := ipmi.GetFanMode(ctx, f.t)
	if modeErr == nil {
		if f.modeFails >= fanBlindAfter {
			slog.Info("fan watchdog: the BMC says its fan mode again", "mode", mode)
		}
		f.modeFails, f.blindAt, f.blindSaid = 0, time.Time{}, ""
		if mode != "full" {
			f.noTemp = 0
			return
		}
	} else if f.modeFails < fanBlindAfter {
		if f.modeFails++; f.modeFails == fanBlindAfter {
			slog.Warn("fan watchdog: the BMC has not said which fan mode is set for three checks in a row; until "+
				"it does, a fixed speed is assumed: 100 % at the temperature limit or without a temperature reading",
				"error", safeErr(modeErr))
		}
	}
	manual := false
	for z := byte(0); z <= 1; z++ {
		if d, err := ipmi.GetDuty(ctx, f.t, z); err != nil || d < 100 {
			manual = true
		}
	}
	if !manual { // both zones answer 100 %: nothing lower is in effect, whatever the mode
		f.noTemp = 0
		return
	}
	act := func(why string) {
		switch {
		case modeErr == nil:
			f.failSafe(ctx, why)
		case f.modeFails >= fanBlindAfter:
			f.failSafeBlind(ctx, why, modeErr)
		}
		// otherwise: one or two checks without the mode. Nothing is sent, and nothing is forgotten (the
		// count of checks without a temperature stays).
	}
	var local []collect.Temp
	if f.localTemps != nil {
		local = f.localTemps()
	}
	temp, name, ok := MaxCPUTemp(f.bmc.WatchdogReadings(), local)
	switch {
	case !ok:
		f.noTemp++
		if f.noTemp >= 3 {
			act("no temperature reading for 30 s while fans were set manually")
		}
	case !(temp < f.cfg.MaxTempC):
		// written as "not below the limit": a reading or a limit that is not a number (NaN) compares false
		// with everything, so `temp >= limit` would never act on it
		act(tooHot(name, temp, f.cfg.MaxTempC))
	default:
		f.noTemp = 0
	}
}

// failSafeBlind is the watchdog's action while the fan mode cannot be read (for fanBlindAfter checks in a
// row). It does what failSafe does, both zones to 100 %: in "full" mode that is the watchdog's own safe state,
// in an automatic mode the BMC goes on by its own curve, and in no mode can it make a fan slower. Only if the
// BMC does not take 100 % either are the fans handed back to its automatic mode (as when the agent stops), so
// that the BMC's own control is in charge and not a fixed duty that nothing can change. It never sets a duty
// below 100 %. Because nothing can be read back from such a BMC, it acts at most once in fanBlindRetry, and it
// writes its log line and its events once for a spell: again only when a later try ends differently. Caller
// holds f.mu.
func (f *Fan) failSafeBlind(ctx context.Context, why string, modeErr error) {
	now := f.now()
	if !f.blindAt.IsZero() {
		if since := now.Sub(f.blindAt); since >= 0 && since < fanBlindRetry {
			return
		}
	}
	f.blindAt = now
	why += " (the BMC does not say which fan mode is set: " + safeErr(modeErr) + ")"
	dutyErr := f.setFull(ctx)
	if dutyErr == nil {
		if f.blindSaid != "100" {
			f.blindSaid = "100"
			f.saidFull(why, nil)
		}
		return
	}
	mode, autoErr := f.setAuto(ctx)
	said := "auto " + mode
	if autoErr != nil {
		said = "nothing taken"
	}
	if f.blindSaid == said {
		return
	}
	f.blindSaid = said
	f.saidFull(why, dutyErr)
	const who = "watchdog: the BMC did not take 100 %"
	if autoErr != nil {
		f.event("auto failed", who+": "+safeErr(autoErr))
		slog.Error("fan watchdog could not hand the fans back to the BMC either", "reason", why, "error", safeErr(autoErr))
		return
	}
	f.event("mode="+mode+" (BMC automatic)", who)
	slog.Warn("fan watchdog: fans handed back to the BMC", "mode", mode, "reason", why)
}

// tooHot words why temp counts as "at or above the limit" (also when one of the two is not a number).
func tooHot(name string, temp, limit float64) string {
	if temp >= limit {
		return fmt.Sprintf("%s %.1f °C >= %.0f °C", name, temp, limit)
	}
	return fmt.Sprintf("%s %v °C cannot be compared with the limit %v °C (not a number)", name, temp, limit)
}

// failSafe sets both zones to 100 % (mode stays "full") and reports whether the BMC took it for zone 0. Caller
// holds f.mu.
func (f *Fan) failSafe(ctx context.Context, why string) bool {
	err := f.setFull(ctx)
	f.saidFull(why, err)
	return err == nil
}

// setFull sends 100 % to both zones and returns what the BMC said for zone 0. It writes no event. Caller
// holds f.mu.
func (f *Fan) setFull(ctx context.Context) error {
	f.noTemp = 0
	f.actedAt = f.now()
	firstErr := ipmi.SetDuty(ctx, f.t, 0, 100)
	_ = ipmi.SetDuty(ctx, f.t, 1, 100) // boards without a peripheral zone refuse this; zone 0 is what matters
	return firstErr
}

// saidFull writes the log line and the event for a setFull that ended with err.
func (f *Fan) saidFull(why string, err error) {
	if err != nil {
		slog.Error("fan watchdog could not set 100 %", "reason", why, "error", safeErr(err))
		f.event("watchdog failed", why+": "+safeErr(err))
		return
	}
	slog.Warn("fan watchdog: fans to 100 %", "reason", why)
	f.event("watchdog: duty 100%", why)
}
