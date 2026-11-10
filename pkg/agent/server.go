package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/enroll"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/redact"
)

// GPUSource reports GPUs and per-process VRAM (collect.NvidiaSMI, or a fake in tests).
type GPUSource interface {
	GPUs() []collect.GPU
	ComputeApps(ctx context.Context) map[int][]int64
}

// CombineGPUs lists the GPUs of several sources one after the other (NVIDIA first). Per-process VRAM from each
// source is moved to its GPUs' positions in that combined list (gpu_mem_by_gpu follows the `gpus` order) and
// merged. nil sources are skipped.
func CombineGPUs(sources ...GPUSource) GPUSource {
	var m multiGPU
	for _, s := range sources {
		if s != nil {
			m = append(m, s)
		}
	}
	if len(m) == 1 {
		return m[0]
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

type multiGPU []GPUSource

func (m multiGPU) GPUs() []collect.GPU {
	var out []collect.GPU
	for _, s := range m {
		out = append(out, s.GPUs()...)
	}
	return out
}

func (m multiGPU) ComputeApps(ctx context.Context) map[int][]int64 {
	offs := make([]int, len(m))
	total := 0
	for i, s := range m {
		offs[i] = total
		total += len(s.GPUs())
	}
	var all []map[int][]int64
	for i, s := range m {
		apps := s.ComputeApps(ctx)
		if len(apps) == 0 {
			continue
		}
		moved := make(map[int][]int64, len(apps))
		for pid, v := range apps {
			w := make([]int64, total)
			for j, b := range v {
				if offs[i]+j < total {
					w[offs[i]+j] = b
				}
			}
			moved[pid] = w
		}
		all = append(all, moved)
	}
	return collect.MergeComputeApps(all...)
}

// ProcessGPUMemory reads per-process GPU memory for a list of GPUs, by position (collect.ProcGPU: Windows'
// `\GPU Process Memory` counter).
type ProcessGPUMemory interface {
	ComputeAppsFor(gpus []collect.GPU) map[int][]int64
}

// WithProcessGPUMemory adds a per-process GPU memory reader to src: per process and GPU the larger of what src
// and pm report (nvidia-smi reports nothing per process on Windows; Windows' counters cover every card).
func WithProcessGPUMemory(src GPUSource, pm ProcessGPUMemory) GPUSource {
	if src == nil || pm == nil {
		return src
	}
	return withProcMem{src, pm}
}

type withProcMem struct {
	GPUSource
	pm ProcessGPUMemory
}

func (w withProcMem) ComputeApps(ctx context.Context) map[int][]int64 {
	return collect.MergeComputeApps(w.GPUSource.ComputeApps(ctx), w.pm.ComputeAppsFor(w.GPUSource.GPUs()))
}

// Deps are the parts the agent is built from (real ones in cmd/fairy-agent, fakes in tests).
type Deps struct {
	Collector collect.Collector
	GPU       GPUSource    // may be nil
	BMC       SensorSource // nil unless ipmi is enabled (*BMC, or the Windows helper's sensors)
	Fan       FanControl   // nil unless fan_control is enabled (*Fan, or the Windows helper's)
	Power     *Power       // nil unless power_control is enabled
	WOL       *WOL         // nil unless wol is enabled
	Relay     *Relay       // may be nil
	Updater   *Updater     // nil unless self_update is enabled
	BMCRelay  *BMCRelay    // nil unless bmc_relay is enabled
	Pairer    *Pairer      // POST /pair ("Add host" in the panel); nil = never answers
	// Helper is the Windows elevated helper (fairy-agent-helper); nil on Linux. Its state goes into /metrics
	// and /helper/stop, /helper/start control it.
	Helper HelperControl
	// HelperSources are the readings and actions this agent gets through the helper (api.FeatureCoreTemp ...):
	// while the helper is not running they are listed in /metrics "unavailable".
	HelperSources []string
	// Migration is the Windows move from LocalSystem to NT SERVICE\fairy-agent (/metrics "migration"); nil on
	// Linux.
	Migration interface{ Status() api.MigrationStatus }
	Version   string
}

// Agent answers the panel.
type Agent struct {
	cfg     *Config
	d       Deps
	readH   [32]byte
	ctlH    [32]byte
	hasCtl  bool
	control *limiter
	badAuth *limiter
	never   map[string]bool

	mu          sync.Mutex
	lastLog     map[string]time.Time
	cache       []byte
	cacheAt     time.Time
	cacheMu     sync.Mutex
	procMu      sync.Mutex
	sampleMu    sync.Mutex
	lastTemps   []collect.Temp
	lastTempsAt time.Time // when lastTemps was sampled (zero: never)
	now         func() time.Time
	sampling    chan struct{} // holds one token while LocalTemps takes its own sample
	tempWait    time.Duration // how long LocalTemps waits for that sample
}

// New builds the agent. tokens come from Config.LoadTokens.
func New(cfg *Config, tokens Tokens, d Deps) *Agent {
	a := &Agent{cfg: cfg, d: d, readH: sha256.Sum256([]byte(tokens.Read)),
		control: newLimiter(cfg.ControlRatePerMin, time.Minute), badAuth: newLimiter(20, time.Minute),
		lastLog: map[string]time.Time{}, never: map[string]bool{}, now: time.Now, sampling: make(chan struct{}, 1),
		tempWait: localTempWait}
	if tokens.Control != "" {
		a.ctlH, a.hasCtl = sha256.Sum256([]byte(tokens.Control)), true
	}
	for _, n := range cfg.Processes.NeverOpen {
		a.never[strings.ToLower(strings.TrimSpace(n))] = true
	}
	return a
}

// LocalTempMaxAge is how old the OS's temperatures may be for the fan watchdog. The latest sample is normally
// the panel's last /metrics poll; when the panel stops asking, that value must not count for ever.
const LocalTempMaxAge = 30 * time.Second

// localTempWait is how long LocalTemps waits for its own sample before it reports "no reading".
const localTempWait = 5 * time.Second

// LocalTemps are the OS's own temperatures for the fan watchdog: those of the latest sample when it is at most
// LocalTempMaxAge old, otherwise those of a fresh sample taken now. It returns nil (no reading, which the
// watchdog treats as a reason to go to 100 %) when the collector has none or does not answer in time; an old
// value is never returned.
func (a *Agent) LocalTemps() []collect.Temp {
	if temps, at := a.LastLocalTemps(); !at.IsZero() {
		if age := a.now().Sub(at); age >= 0 && age <= LocalTempMaxAge {
			return temps
		}
	}
	select {
	case a.sampling <- struct{}{}:
	default:
		return nil // the previous sample has not come back yet
	}
	done := make(chan []collect.Temp, 1)
	go func() {
		defer func() { <-a.sampling }()
		ctx, cancel := context.WithTimeout(context.Background(), a.tempWait)
		defer cancel()
		at := a.now()
		s := a.d.Collector.Sample(ctx)
		a.setLocalTemps(s.Temps, at)
		done <- s.Temps
	}()
	t := time.NewTimer(a.tempWait)
	defer t.Stop()
	select {
	case temps := <-done:
		return temps
	case <-t.C:
		return nil
	}
}

// LastLocalTemps are the OS's temperatures of the latest sample and when it was taken (zero time: no sample
// yet), however old.
func (a *Agent) LastLocalTemps() ([]collect.Temp, time.Time) {
	a.sampleMu.Lock()
	defer a.sampleMu.Unlock()
	return a.lastTemps, a.lastTempsAt
}

// setLocalTemps keeps a sample's temperatures with the time the sample was started; an older sample that comes
// back late does not replace a newer one.
func (a *Agent) setLocalTemps(t []collect.Temp, at time.Time) {
	a.sampleMu.Lock()
	if !at.Before(a.lastTempsAt) {
		a.lastTemps, a.lastTempsAt = t, at
	}
	a.sampleMu.Unlock()
}

// safeErr is an error message that is safe to send: context errors become "timeout".
func safeErr(err error) string {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// limiter allows n events per window per key (sliding window).
type limiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(n int, window time.Duration) *limiter {
	return &limiter{n: n, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	h := l.hits[key]
	i := 0
	for i < len(h) && now.Sub(h[i]) > l.window {
		i++
	}
	h = h[i:]
	if len(h) >= l.n {
		l.hits[key] = h
		return false
	}
	l.hits[key] = append(h, now)
	if len(l.hits) > 1000 { // forget idle keys
		for k, v := range l.hits {
			if len(v) == 0 || now.Sub(v[len(v)-1]) > l.window {
				delete(l.hits, k)
			}
		}
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		status, b = 500, []byte(`{"error":"internal error"}`)
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// logOnce logs at most once a minute per key (failed sign-ins must not fill the disk).
func (a *Agent) logOnce(key, msg string, args ...any) {
	a.mu.Lock()
	t, ok := a.lastLog[key]
	if ok && time.Since(t) < time.Minute {
		a.mu.Unlock()
		return
	}
	a.lastLog[key] = time.Now()
	if len(a.lastLog) > 1000 {
		clear(a.lastLog)
	}
	a.mu.Unlock()
	slog.Warn(msg, args...)
}

// tokenIs compares the request's bearer token with a stored hash in constant time.
func tokenIs(r *http.Request, want [32]byte) bool {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 || !strings.EqualFold(auth[:7], "bearer ") {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(auth[7:])))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

type route struct {
	method  string
	control bool
	feature func() bool // POST: is the feature on? (off = 404, nothing happens)
	code    string      // the 404 code when the feature is off
	h       func(w http.ResponseWriter, r *http.Request)
}

// Handler is the agent's HTTP handler.
func (a *Agent) Handler() http.Handler {
	routes := map[string]route{
		"/metrics":          {method: http.MethodGet, h: a.metrics},
		"/processes":        {method: http.MethodGet, h: a.processes},
		"/fan/status":       {method: http.MethodGet, h: a.fanStatus},
		"/fan/mode":         {method: http.MethodPost, control: true, feature: func() bool { return a.d.Fan != nil }, code: "fan_control_disabled", h: a.fanMode},
		"/fan/duty":         {method: http.MethodPost, control: true, feature: func() bool { return a.d.Fan != nil }, code: "fan_control_disabled", h: a.fanDuty},
		"/power":            {method: http.MethodPost, control: true, feature: func() bool { return a.d.Power != nil }, code: "power_control_disabled", h: a.power},
		"/wol":              {method: http.MethodPost, control: true, feature: func() bool { return a.d.WOL != nil }, code: "wol_disabled", h: a.wol},
		"/update":           {method: http.MethodPost, control: true, feature: func() bool { return a.d.Updater != nil }, code: "self_update_disabled", h: a.update},
		"/bmc/power":        {method: http.MethodPost, control: true, feature: func() bool { return a.d.BMCRelay != nil }, code: "bmc_relay_disabled", h: a.bmcPower},
		api.PathHelperStop:  {method: http.MethodPost, control: true, feature: a.hasHelper, h: a.helperStop},
		api.PathHelperStart: {method: http.MethodPost, control: true, feature: a.hasHelper, h: a.helperStart},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if r.URL.Path == enroll.Path { // no bearer token yet: the join code is the credential (see Pairer)
			a.d.Pairer.ServeHTTP(w, r)
			return
		}
		rt, ok := routes[r.URL.Path]
		if !ok {
			writeJSON(w, 404, map[string]any{"error": "not found"})
			return
		}
		if r.Method != rt.method {
			w.Header().Set("Allow", rt.method)
			writeJSON(w, 405, map[string]any{"error": "method not allowed"})
			return
		}
		if !a.badAuth.allowPeek(ip) {
			writeJSON(w, 429, map[string]any{"error": "too many failed requests"})
			return
		}
		authed := false
		switch {
		case rt.control && rt.feature():
			authed = a.hasCtl && tokenIs(r, a.ctlH)
		case rt.control && rt.code == "":
			// the helper endpoints: no helper service on this machine (always so on Linux)
			writeJSON(w, 409, map[string]any{"error": "not_installed", "code": "not_installed"})
			return
		case rt.control:
			// Feature off: nothing can happen, so say so (also to a panel whose control token this agent does
			// not know, so the panel shows "disabled" instead of "wrong token").
			writeJSON(w, 404, map[string]any{"error": strings.ReplaceAll(strings.TrimSuffix(rt.code, "_disabled"), "_", " ") + " is disabled on this agent", "code": rt.code})
			return
		default:
			authed = tokenIs(r, a.readH)
		}
		if !authed {
			a.badAuth.allow(ip)
			a.logOnce("auth:"+ip, "rejected request: wrong or missing token", "remote", ip, "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Bearer realm="fairy-agent"`)
			writeJSON(w, 401, map[string]any{"error": "unauthorized"})
			return
		}
		if rt.control {
			if !a.control.allow("control") {
				a.logOnce("rate", "control request rate limited", "remote", ip, "path", r.URL.Path)
				writeJSON(w, 429, map[string]any{"error": "too many control requests; try again in a minute"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
		}
		rt.h(w, r)
	})
}

// allowPeek reports whether key is below its limit without counting a hit.
func (l *limiter) allowPeek(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	n := 0
	for _, t := range l.hits[key] {
		if now.Sub(t) <= l.window {
			n++
		}
	}
	return n < l.n
}

func decodeBody(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body too large")
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

// Metrics builds the /metrics payload.
func (a *Agent) Metrics(ctx context.Context) map[string]any {
	st := a.d.Collector.Static()
	sampledAt := a.now()
	s := a.d.Collector.Sample(ctx)
	a.setLocalTemps(s.Temps, sampledAt)

	temps, fans, volts := orEmpty(s.Temps), orEmpty(s.Fans), orEmpty(s.Voltages)
	if a.d.BMC != nil && a.cfg.IPMISensors() {
		bt, bf, bv := a.d.BMC.Metrics()
		temps, fans, volts = append(temps, bt...), append(fans, bf...), append(volts, bv...)
	}
	gpus := []collect.GPU{}
	pw := s.Power
	if pw.Sensors == nil {
		pw.Sensors = []collect.PowerSensor{}
	}
	if pw.Source == nil {
		pw.Source = []string{}
	}
	if a.d.GPU != nil {
		var sum float64
		has := false
		for _, g := range a.d.GPU.GPUs() {
			gpus = append(gpus, g)
			if g.PowerW != nil {
				sum += *g.PowerW
				has = true
			}
		}
		if has {
			pw.GPUW = collect.P(collect.Round(sum, 1))
			pw.Source = append(pw.Source, "gpu")
		}
	}
	feat := map[string]any{}
	for k, v := range a.Features() {
		feat[k] = v
	}
	ps, us := a.d.Relay.Rows()
	m := map[string]any{
		"agent_version": a.d.Version, "timestamp": collect.Round(float64(time.Now().UnixMilli())/1000, 3),
		"hostname": nil, "uptime_s": s.UptimeS, "platform": st.Platform,
		"cpu":    collect.CPU{Percent: s.CPUPercent, Logical: st.Logical, Physical: st.Physical},
		"memory": s.Memory, "disks": orEmpty(s.Disks), "net": s.Net, "load_avg": s.LoadAvg,
		"temps": temps, "fans": fans, "voltages": volts, "gpus": gpus,
		"features": feat, "power_sources": ps, "ups": us,
	}
	if !pw.Empty() {
		m["power"] = pw
	}
	if s.Battery != nil {
		m["battery"] = s.Battery
	}
	if a.cfg.HideHostDetails {
		m["platform"] = collect.Platform{System: st.Platform.System, Pretty: st.Platform.System}
	} else {
		if st.Hostname != "" {
			m["hostname"] = st.Hostname
		}
		if st.Hardware != nil {
			m["hardware"] = st.Hardware
		}
	}
	if a.d.Power != nil {
		m["power_control"] = a.d.Power.State()
	}
	if a.d.BMCRelay != nil {
		m["bmc_relay"] = map[string]any{"enabled": true, "targets": a.d.BMCRelay.Targets()}
	}
	if a.d.Updater != nil {
		m["self_update"] = a.d.Updater.Status()
	}
	if a.d.Migration != nil {
		m["migration"] = a.d.Migration.Status()
	}
	if a.d.Helper != nil {
		hs := a.d.Helper.Status(ctx)
		m["helper"] = hs
		if un := unavailable(hs, a.d.HelperSources); len(un) > 0 {
			m["unavailable"] = un
			if pc, ok := m["power_control"].(map[string]any); ok && slices.Contains(a.d.HelperSources, api.FeaturePower) {
				pc["available"], pc["reason"] = false, un[0].Reason
			}
		}
	}
	return m
}

// unavailable lists the helper-backed sources while the helper is not running.
func unavailable(hs api.HelperStatus, sources []string) []api.Unavailable {
	if hs.Running() || len(sources) == 0 {
		return nil
	}
	reason := api.ReasonHelperStopped
	if hs.State == api.HelperError {
		reason = api.ReasonHelperError
	}
	out := make([]api.Unavailable, 0, len(sources))
	for _, s := range sources {
		out = append(out, api.Unavailable{Source: s, Reason: reason})
	}
	return out
}

func (a *Agent) hasHelper() bool { return a.d.Helper != nil }

// helperStop is POST /helper/stop: fans back to the BMC's automatic mode, then the helper service stops.
func (a *Agent) helperStop(w http.ResponseWriter, r *http.Request) { a.helperControl(w, r, false) }

// helperStart is POST /helper/start.
func (a *Agent) helperStart(w http.ResponseWriter, r *http.Request) { a.helperControl(w, r, true) }

func (a *Agent) helperControl(w http.ResponseWriter, r *http.Request, start bool) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "request body too large"})
		return
	}
	if len(bytes.TrimSpace(b)) > 0 {
		var v map[string]json.RawMessage
		if json.Unmarshal(b, &v) != nil {
			writeJSON(w, 400, map[string]any{"error": "invalid JSON body"})
			return
		}
	}
	who := "panel " + clientIP(r)
	var st api.HelperStatus
	if start {
		st, err = a.d.Helper.Start(r.Context(), who)
	} else {
		st, err = a.d.Helper.Stop(r.Context(), who)
	}
	action := map[bool]string{true: "start", false: "stop"}[start]
	switch {
	case errors.Is(err, api.ErrHelperNotInstalled):
		writeJSON(w, 409, map[string]any{"error": "not_installed", "code": "not_installed"})
	case err != nil:
		slog.Error("helper: "+action+" failed", "requested_by", who, "error", safeErr(err))
		writeJSON(w, 502, map[string]any{"error": "could not " + action + " the helper: " + safeErr(err), "state": st.State})
	default:
		slog.Warn("helper: "+action, "requested_by", who, "state", st.State)
		writeJSON(w, 200, st)
	}
}

// Features are the panel-visible switches (the "features" block of /metrics and the /pair answer).
func (a *Agent) Features() map[string]bool {
	return map[string]bool{"processes": a.cfg.ProcessesEnabled(), "cmdline": a.cfg.ProcessesEnabled() && a.cfg.CmdlineEnabled(),
		"fan_control": a.d.Fan != nil, "power_control": a.d.Power != nil, "wol_relay": a.d.WOL != nil,
		"self_update": a.d.Updater != nil, "bmc_relay": a.d.BMCRelay != nil}
}

// PairInfo is the /pair answer without the tokens.
func (a *Agent) PairInfo() enroll.Response {
	r := enroll.Response{AgentVersion: a.d.Version, Platform: runtime.GOOS, Features: a.Features()}
	if !a.cfg.HideHostDetails {
		r.Hostname = a.d.Collector.Static().Hostname
	}
	return r
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// metrics serves GET /metrics (computed at most every 250 ms, however many panels ask).
func (a *Agent) metrics(w http.ResponseWriter, r *http.Request) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if a.cache == nil || time.Since(a.cacheAt) > 250*time.Millisecond {
		b, err := json.Marshal(a.Metrics(r.Context()))
		if err != nil {
			writeJSON(w, 500, map[string]any{"error": "internal error"})
			return
		}
		a.cache, a.cacheAt = b, time.Now()
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(a.cache)
}

// processes serves GET /processes?limit=N&sort=cpu|mem|gpu.
func (a *Agent) processes(w http.ResponseWriter, r *http.Request) {
	if !a.cfg.ProcessesEnabled() {
		writeJSON(w, 403, map[string]any{"error": "process list disabled on this host", "code": "processes_disabled"})
		return
	}
	q := r.URL.Query()
	limit := 25
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			writeJSON(w, 400, map[string]any{"error": "limit must be 1-200"})
			return
		}
		limit = n
	}
	sortBy := q.Get("sort")
	if sortBy == "" {
		sortBy = "cpu"
	}
	if sortBy != "cpu" && sortBy != "mem" && sortBy != "gpu" {
		writeJSON(w, 400, map[string]any{"error": "sort must be cpu, mem or gpu"})
		return
	}
	a.procMu.Lock() // one listing at a time: the CPU sample is shared
	defer a.procMu.Unlock()
	mem := a.d.Collector.Sample(r.Context()).Memory.Total
	o := collect.ProcOptions{Cmdline: a.cfg.CmdlineEnabled(), NeverOpen: a.never, MemTotal: mem, Interval: 500 * time.Millisecond}
	procs, total, err := a.d.Collector.Processes(r.Context(), o)
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "could not list processes"})
		return
	}
	if a.d.GPU != nil {
		if apps := a.d.GPU.ComputeApps(r.Context()); apps != nil {
			for i := range procs {
				if by, ok := apps[procs[i].PID]; ok {
					var sum int64
					for _, v := range by {
						sum += v
					}
					procs[i].GPUMem, procs[i].GPUMemByGPU = collect.P(sum), by
				}
			}
		}
	}
	SortProcesses(procs, sortBy)
	if len(procs) > limit {
		procs = procs[:limit]
	}
	for i := range procs {
		if c := procs[i].Cmdline; c != nil {
			v := redact.Cmdline(*c, 300)
			procs[i].Cmdline = &v
		}
	}
	writeJSON(w, 200, map[string]any{"sampled_at": collect.Round(float64(time.Now().UnixMilli())/1000, 3),
		"sort": sortBy, "total_processes": total, "processes": orEmpty(procs)})
}

// SortProcesses orders by CPU, memory (RSS) or GPU memory, highest first; unknown values last, then by pid.
func SortProcesses(p []collect.Process, by string) {
	key := func(x collect.Process) (float64, bool) {
		switch by {
		case "mem":
			if x.RSS != nil {
				return float64(*x.RSS), true
			}
		case "gpu":
			if x.GPUMem != nil {
				return float64(*x.GPUMem), true
			}
		default:
			if x.CPUPercent != nil {
				return *x.CPUPercent, true
			}
		}
		return 0, false
	}
	sort.SliceStable(p, func(i, j int) bool {
		a, aok := key(p[i])
		b, bok := key(p[j])
		if aok != bok {
			return aok
		}
		if a != b {
			return a > b
		}
		return p[i].PID < p[j].PID
	})
}

func (a *Agent) fanStatus(w http.ResponseWriter, r *http.Request) {
	if a.d.Fan == nil {
		writeJSON(w, 404, map[string]any{"error": "fan control is not enabled on this agent", "code": "fan_control_disabled"})
		return
	}
	writeJSON(w, 200, a.d.Fan.Status(r.Context()))
}

// intField accepts a JSON integer (50, not 50.5 or "50").
func intField(v json.RawMessage) (int, bool) {
	var n json.Number
	if len(v) == 0 || json.Unmarshal(v, &n) != nil {
		return 0, false
	}
	i, err := strconv.Atoi(n.String())
	return i, err == nil
}

func (a *Agent) fanMode(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Mode string `json:"mode"`
	}
	if err := decodeBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	st, body := a.d.Fan.SetMode(r.Context(), b.Mode, "panel "+clientIP(r))
	writeJSON(w, st, body)
}

func (a *Agent) fanDuty(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Zone    json.RawMessage `json:"zone"`
		Percent json.RawMessage `json:"percent"`
	}
	if err := decodeBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	zone, ok1 := intField(b.Zone)
	pct, ok2 := intField(b.Percent)
	if !ok1 || !ok2 {
		writeJSON(w, 400, map[string]any{"error": "zone and percent must be integers"})
		return
	}
	st, body := a.d.Fan.SetDuty(r.Context(), zone, pct, "panel "+clientIP(r))
	writeJSON(w, st, body)
}

func (a *Agent) power(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Action      string          `json:"action"`
		DelayS      json.RawMessage `json:"delay_s"`
		RequestedBy any             `json:"requested_by"`
	}
	if err := decodeBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	req := PowerRequest{Action: b.Action, RequestedBy: b.RequestedBy}
	if len(b.DelayS) > 0 && string(b.DelayS) != "null" {
		d, ok := intField(b.DelayS)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "delay_s must be an integer"})
			return
		}
		req.DelayS = &d
	}
	st, body := a.d.Power.Handle(req)
	writeJSON(w, st, body)
}

func (a *Agent) bmcPower(w http.ResponseWriter, r *http.Request) {
	var b BMCRequest
	if err := decodeBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	st, body := a.d.BMCRelay.Handle(r.Context(), b)
	writeJSON(w, st, body)
}

func (a *Agent) wol(w http.ResponseWriter, r *http.Request) {
	var b WOLRequest
	if err := decodeBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	st, body := a.d.WOL.Handle(b)
	writeJSON(w, st, body)
}

func (a *Agent) update(w http.ResponseWriter, r *http.Request) {
	var b UpdateRequest
	if err := decodeBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	st, body := a.d.Updater.Start(b)
	writeJSON(w, st, body)
}

// Server wraps the handler with the timeouts every connection gets.
func (a *Agent) Server() *http.Server {
	return &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 16 << 10,
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)}
}
