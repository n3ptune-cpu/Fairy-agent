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
	"math"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/devices"
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
	// Approval is this agent's own passkey check (pkg/approval) of the requests it carries out itself: all of
	// them where there is no helper (every system but Windows); on Windows the ones that do not go through the
	// helper, with a gate that only reads the helper's trust file. Run always sets it. nil (tests of other
	// parts): this agent checks nothing itself, and on a machine whose helper says that approvals are not off
	// it refuses what it would have to check.
	Approval *approval.Gate
	Version  string
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

	mu           sync.Mutex
	lastLog      map[string]time.Time
	cache        []byte
	cacheAt      time.Time
	cacheMu      sync.Mutex
	procMu       sync.Mutex    // guards procCall and procLast
	procCall     *procCall     // the process listing that is being made now (nil: none)
	procLast     *procList     // the latest finished one
	procWaiters  chan struct{} // one token per /processes request that waits for a listing
	procAnswerMu sync.Mutex    // one /processes answer is sorted and written as JSON at a time
	fanStatuses  chan struct{} // one token per /fan/status request in flight
	sampleMu     sync.Mutex
	lastTemps    []collect.Temp
	lastTempsAt  time.Time // when lastTemps was sampled (zero: never)
	now          func() time.Time
	sampling     chan struct{} // holds one token while LocalTemps takes its own sample
	tempWait     time.Duration // how long LocalTemps waits for that sample
}

// New builds the agent. tokens come from Config.LoadTokens.
func New(cfg *Config, tokens Tokens, d Deps) *Agent {
	a := &Agent{cfg: cfg, d: d, readH: sha256.Sum256([]byte(tokens.Read)),
		control: newLimiter(cfg.ControlRatePerMin, time.Minute), badAuth: newLimiter(20, time.Minute),
		lastLog: map[string]time.Time{}, never: map[string]bool{}, now: time.Now, sampling: make(chan struct{}, 1),
		tempWait: localTempWait, procWaiters: make(chan struct{}, maxProcessWaiters), fanStatuses: make(chan struct{}, maxFanStatus)}
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
	// busy: at most cap(busy) requests of this route are in flight; one more is answered 503 "busy" at once.
	// For the reads that can take long (they wait for a process listing or for the BMC): however many of
	// them the panel passes on, they never hold more than this many of its connections, so its /metrics poll
	// and its control requests always find one.
	busy chan struct{}
	// maxBody is the largest body of a control request (0: 4096 bytes). The routes that take a passkey approval
	// (an ID token and the list it was given for) get approvalBody.
	maxBody int64
	// budget is the request budget a control route counts in (control_rate_per_min a minute each, see
	// controlBudget). "": the route counts itself once it has read the request (POST /power, whose cancel has
	// a budget of its own).
	budget  string
	feature func() bool // POST: is the feature on? (off = 404, nothing happens)
	code    string      // the 404 code when the feature is off
	h       func(w http.ResponseWriter, r *http.Request)
}

// Handler is the agent's HTTP handler.
func (a *Agent) Handler() http.Handler {
	routes := map[string]route{
		"/metrics":          {method: http.MethodGet, h: a.metrics},
		"/processes":        {method: http.MethodGet, busy: a.procWaiters, h: a.processes},
		"/fan/status":       {method: http.MethodGet, busy: a.fanStatuses, h: a.fanStatus},
		"/fan/mode":         {method: http.MethodPost, control: true, budget: budgetControl, maxBody: approvalBody, feature: func() bool { return a.d.Fan != nil }, code: "fan_control_disabled", h: a.fanMode},
		"/fan/duty":         {method: http.MethodPost, control: true, budget: budgetControl, maxBody: approvalBody, feature: func() bool { return a.d.Fan != nil }, code: "fan_control_disabled", h: a.fanDuty},
		"/power":            {method: http.MethodPost, control: true, maxBody: approvalBody, feature: func() bool { return a.d.Power != nil }, code: "power_control_disabled", h: a.power},
		"/wol":              {method: http.MethodPost, control: true, budget: budgetControl, feature: func() bool { return a.d.WOL != nil }, code: "wol_disabled", h: a.wol},
		"/update":           {method: http.MethodPost, control: true, budget: budgetControl, maxBody: approvalBody, feature: func() bool { return a.d.Updater != nil }, code: "self_update_disabled", h: a.update},
		"/bmc/power":        {method: http.MethodPost, control: true, budget: budgetControl, feature: func() bool { return a.d.BMCRelay != nil }, code: "bmc_relay_disabled", h: a.bmcPower},
		api.PathHelperStop:  {method: http.MethodPost, control: true, budget: budgetControl, feature: a.hasHelper, h: a.helperStop},
		api.PathHelperStart: {method: http.MethodPost, control: true, budget: budgetControl, feature: a.hasHelper, h: a.helperStart},
		// the passkey approval of the routes above (approval.go)
		api.PathApprovalChallenge: {method: http.MethodPost, control: true, budget: budgetChallenge, maxBody: approvalBody, feature: a.hasApproval, code: api.CodeApprovalDisabled, h: a.approvalChallenge},
		api.PathApprovalTrust:     {method: http.MethodPost, control: true, budget: budgetControl, maxBody: approvalBody, feature: a.hasApproval, code: api.CodeApprovalDisabled, h: a.approvalTrust},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if r.URL.Path == enroll.Path { // no bearer token yet: the join code is the credential (see Pairer)
			a.d.Pairer.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == HealthPath && a.health(w, r) {
			return // the update's health check, from this machine (health.go); for everybody else there is no such path
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
		// The token is looked at first. A request with the right token for its route is always served and
		// never counted. Only a request whose token is missing or wrong is counted, and refused with 429 once
		// its address has 20 of those in the last minute (and then not counted again). Before, the 429 came
		// first, for every request of the address: 20 requests without any token from the panel's address
		// (another user or a container on the panel's host, a machine behind the same NAT) kept the panel's
		// own tokens out, the cancel of a shutdown included (audit 5, r2-a2-01 = r2-a1-02).
		//
		// What that gives up: while an address was refused, nobody at it could try tokens; now a wrong token
		// is told from a right one at any rate (429 against the route's answer). The tokens carry that alone:
		// the ones this program makes are 32 random bytes (256 bits; main.go, newToken), and none shorter
		// than MinTokenLen characters is taken. The comparison is as before: SHA-256 of what was sent against
		// the stored hash, in constant time, whatever the address's count is.
		locked := func() bool {
			if a.badAuth.allowPeek(ip) {
				return false
			}
			writeJSON(w, 429, map[string]any{"error": "too many failed requests"})
			return true
		}
		// hasToken: the request shows one of this agent's tokens. For the two answers below that are the same
		// for everybody (no token is needed for them): who shows a token gets them also from a refused address.
		hasToken := func() bool {
			ctl := a.hasCtl && tokenIs(r, a.ctlH)
			return tokenIs(r, a.readH) || ctl
		}
		authed := false
		switch {
		case rt.control && rt.feature():
			authed = a.hasCtl && tokenIs(r, a.ctlH) // the read token is a wrong token here, and counted
		case rt.control && rt.code == "":
			// the helper endpoints: no helper service on this machine (always so on Linux)
			if hasToken() || !locked() {
				writeJSON(w, 409, map[string]any{"error": "not_installed", "code": "not_installed"})
			}
			return
		case rt.control:
			// Feature off: nothing can happen, so say so (also to a panel whose control token this agent does
			// not know, so the panel shows "disabled" instead of "wrong token").
			if hasToken() || !locked() {
				writeJSON(w, 404, map[string]any{"error": strings.ReplaceAll(strings.TrimSuffix(rt.code, "_disabled"), "_", " ") + " is disabled on this agent", "code": rt.code})
			}
			return
		default:
			authed = tokenIs(r, a.readH)
		}
		if !authed {
			if locked() {
				return
			}
			a.badAuth.allow(ip)
			a.logOnce("auth:"+ip, "rejected request: wrong or missing token", "remote", ip, "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Bearer realm="fairy-agent"`)
			writeJSON(w, 401, map[string]any{"error": "unauthorized"})
			return
		}
		// the connection carried a valid token: LimitConns does not close it for a stranger, and on an agent
		// without a panel address on record its sender gets the panel's share from now on
		if c, ok := r.Context().Value(connKey{}).(interface{ Vouch() }); ok {
			c.Vouch()
		}
		if rt.control {
			if rt.budget != "" && !a.controlBudget(w, r, rt.budget) {
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, max(rt.maxBody, 4096))
		}
		if rt.busy != nil {
			select {
			case rt.busy <- struct{}{}:
				defer func() { <-rt.busy }()
			default:
				w.Header().Set("Retry-After", "1")
				writeJSON(w, 503, map[string]any{"error": "too many of these requests at once; try again in a moment", "code": BusyCode})
				return
			}
		}
		rt.h(w, r)
	})
}

// The request budgets of the control routes. Each allows control_rate_per_min requests a minute, for
// everybody together, and none can use up another's:
//
//   - budgetControl: everything that changes something or sends something out (fan, power other than cancel,
//     Wake-on-LAN, the BMC relay, update, helper stop / start, the first-time set of the trust);
//   - budgetChallenge: POST /approval/challenge. A challenge changes nothing on the machine, and every approved
//     action needs one first. In the one budget of before, an approved action cost two requests, and twelve
//     challenges (the default limit) left none for anything else, POST /power cancel included (audit 5,
//     r1-a2-03);
//   - budgetCancel: POST /power with the action cancel, the request that stops a shutdown. No other budget
//     can keep it out: not challenges, and not twelve refused requests of somebody who has the control token
//     and no approval. Requests with a wrong token or none cannot either (they are counted per address, and
//     only they are refused for it: Handler). What can: control_rate_per_min other cancels in the same minute,
//     which need the control token. (The caps on open connections are another matter: listen.go, LimitConns.)
const (
	budgetControl   = "control"
	budgetChallenge = "challenge"
	budgetCancel    = "cancel"
)

var budgetText = map[string]string{
	budgetControl:   "too many control requests; try again in a minute",
	budgetChallenge: "too many approval challenge requests; try again in a minute (they have a budget of their own: control requests and cancel are not affected)",
	budgetCancel:    "too many cancel requests; try again in a minute",
}

// controlBudget counts one request in budget; false: the budget is used up and the request was answered 429.
func (a *Agent) controlBudget(w http.ResponseWriter, r *http.Request, budget string) bool {
	if a.control.allow(budget) {
		return true
	}
	a.logOnce("rate:"+budget, budget+" request rate limited", "remote", clientIP(r), "path", r.URL.Path)
	w.Header().Set("Retry-After", "60")
	writeJSON(w, 429, map[string]any{"error": budgetText[budget]})
	return false
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

// decodeBody reads the body of a control request: one JSON value and nothing after it, no member twice in one
// object, and no member of the request spelled in another way than its name (strictBodyFor). Members the
// request does not know are ignored, as before.
func decodeBody(r *http.Request, v any) error {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return errors.New("request body too large")
	}
	if err := strictBodyFor(b, v); err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

// strictBody refuses a body that encoding/json would read and that is not one plain JSON text: a member that
// is there twice (json takes the last one, also when the names differ only in case; another reader of the same
// request, or of its approval, could take the first), text that is not UTF-8, objects nested deeper than any
// request is. The panel's bodies are made by a JSON encoder and have none of these (audit 5, r2-a1-06).
func strictBody(b []byte) error { return strictBodyFor(b, nil) }

// strictBodyFor is strictBody for a body that is read into v, and refuses one thing more: a member that
// encoding/json would read into a field of v (or of the approval inside it) although it is not spelled as
// that field is. To encoding/json "DELAY_S", and "delay_s" written with a long s (U+017F), are "delay_s". The
// panel's encoder writes every name exactly (audit 5, r3-a1-02).
func strictBodyFor(b []byte, v any) error {
	err := approval.CheckJSONFor(b, v)
	if err == nil {
		return nil
	}
	if msg := err.Error(); msg != "not valid JSON" && msg != "data after the JSON value" {
		return errors.New("invalid JSON body: " + msg)
	}
	return errors.New("invalid JSON body")
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
		has, bad := false, false
		for _, g := range a.d.GPU.GPUs() {
			// a GPU reader's number that cannot be a reading (NaN, an infinity, beyond devices.MaxMagnitude,
			// negative watts) becomes unknown in the card's row; the row itself stays
			reported := g.PowerW != nil
			g.UtilPercent, g.TempC = devices.Num(g.UtilPercent), devices.Num(g.TempC)
			g.PowerW = devices.NumIn(g.PowerW, 0, devices.MaxMagnitude)
			gpus = append(gpus, g)
			if g.PowerW != nil {
				sum += *g.PowerW
				has = true
			} else if reported {
				bad = true
			}
		}
		// one card with impossible watts makes the total unknown (not "the sum of the rest"), and possible
		// numbers can still add up to an impossible one
		if sum = collect.Round(sum, 1); has && !bad && devices.Finite(sum) {
			pw.GPUW = collect.P(sum)
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
	if st, ok := a.approvalStatus(ctx); ok {
		m["approval"] = st
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

// DroppedSectionsKey is the one key GET /metrics gains when a part of the answer could not be written as JSON:
// the names of the top-level sections that were shortened (a list without its unwritable entries) or replaced
// by null. It is absent from every ordinary answer.
const DroppedSectionsKey = "dropped_sections"

// encodeMetrics writes the /metrics answer. encoding/json refuses a whole document for one value it cannot
// write (NaN, an infinity), which used to turn one bad sensor into a 500 for the whole machine. When the
// answer cannot be written in one piece, each top-level section is written on its own: a list of rows (sensors,
// cards, disks) keeps the rows that can be written, any other section that cannot be written becomes null,
// and DroppedSectionsKey names them. Every key of the ordinary answer is still there. body is nil only if
// even that fails.
func encodeMetrics(m map[string]any) (body []byte, dropped []string) {
	if b, err := json.Marshal(m); err == nil {
		return b, nil
	}
	out := make(map[string]json.RawMessage, len(m)+1)
	for k, v := range m {
		b, err := json.Marshal(v)
		if err != nil {
			b = writableEntries(v)
			dropped = append(dropped, k)
		}
		out[k] = b
	}
	slices.Sort(dropped)
	names, _ := json.Marshal(dropped)
	out[DroppedSectionsKey] = names
	b, err := json.Marshal(out)
	if err != nil {
		return nil, dropped
	}
	return b, dropped
}

// writableEntries is the JSON of a list of rows without the rows that cannot be written; null for anything
// else. A list of plain values (load_avg: 1, 5 and 15 minutes) is not shortened: there the place of a value is
// its meaning, so it is all or nothing.
func writableEntries(v any) json.RawMessage {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice && rv.Kind() != reflect.Array {
		return json.RawMessage("null")
	}
	if k := rv.Type().Elem().Kind(); k != reflect.Struct && k != reflect.Map {
		return json.RawMessage("null")
	}
	keep := make([]json.RawMessage, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		if b, err := json.Marshal(rv.Index(i).Interface()); err == nil {
			keep = append(keep, b)
		}
	}
	b, err := json.Marshal(keep)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// metrics serves GET /metrics (computed at most every 250 ms, however many panels ask).
func (a *Agent) metrics(w http.ResponseWriter, r *http.Request) {
	a.cacheMu.Lock()
	defer a.cacheMu.Unlock()
	if a.cache == nil || time.Since(a.cacheAt) > 250*time.Millisecond {
		b, dropped := encodeMetrics(a.Metrics(r.Context()))
		if b == nil {
			writeJSON(w, 500, map[string]any{"error": "internal error"})
			return
		}
		if len(dropped) > 0 {
			a.logOnce("metrics-dropped", "metrics: a section could not be written as JSON (a reading that is not a number?); "+
				"it was left out or shortened", "sections", strings.Join(dropped, ","))
		}
		a.cache, a.cacheAt = b, time.Now()
	}
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(a.cache)
}

// How the process list is made. A listing reads all of /proc and takes half a second the first time. Requests
// used to be served one listing each, one after the other: every viewer's open Processes tab asks through the
// panel every two seconds, so a dozen of them (or one script with a viewer's session) had a dozen of the
// panel's connections waiting in line here, and the panel's own next connection was over a cap.
const (
	// processMaxAge: a finished listing answers every request of the next second. However many ask, /proc is
	// read once a second at most, and requests that arrive while a listing is being made share it.
	processMaxAge = time.Second
	// processListLimit is how long one listing may take.
	processListLimit = 20 * time.Second
	// maxProcessRows is the most rows a request can ask for; a kept listing holds the maxProcessRows highest by
	// CPU, by memory and by GPU memory, which is every row any request can be answered with.
	maxProcessRows = 200
	// maxProcessWaiters / maxFanStatus: see route.busy.
	maxProcessWaiters = 16
	maxFanStatus      = 4
)

// BusyCode is the code of the 503 answer to a /processes or /fan/status request over its cap (route.busy).
const BusyCode = "busy"

// procList is one finished process listing.
type procList struct {
	rows  []collect.Process // not sorted; never changed once it is here
	total int
	at    time.Time
}

type procCall struct {
	done chan struct{} // closed when list and err are set
	list *procList
	err  error
}

// processList returns the latest listing if it is at most processMaxAge old, or the one being made now, or
// starts one. The listing itself does not belong to any request: one that gives up does not stop it for the
// others.
func (a *Agent) processList(ctx context.Context) (*procList, error) {
	a.procMu.Lock()
	if l := a.procLast; l != nil {
		if age := time.Since(l.at); age >= 0 && age <= processMaxAge {
			a.procMu.Unlock()
			return l, nil
		}
	}
	call := a.procCall
	if call == nil {
		call = &procCall{done: make(chan struct{})}
		a.procCall = call
		go func() {
			lctx, cancel := context.WithTimeout(context.Background(), processListLimit)
			defer cancel()
			call.list, call.err = a.listProcesses(lctx)
			a.procMu.Lock()
			if call.err == nil {
				a.procLast = call.list
			}
			a.procCall = nil
			a.procMu.Unlock()
			close(call.done)
		}()
	}
	a.procMu.Unlock()
	select {
	case <-call.done:
		return call.list, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// listProcesses makes one listing: every row a request can be answered with, numbers cleaned, command lines
// with their secrets hidden.
func (a *Agent) listProcesses(ctx context.Context) (*procList, error) {
	mem := a.d.Collector.Sample(ctx).Memory.Total
	var apps map[int][]int64 // pid -> GPU memory per card
	if a.d.GPU != nil {
		apps = a.d.GPU.ComputeApps(ctx)
	}
	// The collector may leave out every row that no request can be answered with (maxProcessRows is the most a
	// request may ask for): its memory then does not grow with the number of processes. The rows that use GPU
	// memory are named, because that order is made here.
	o := collect.ProcOptions{Cmdline: a.cfg.CmdlineEnabled(), NeverOpen: a.never, MemTotal: mem, Interval: 500 * time.Millisecond,
		Top: maxProcessRows, Keep: func(pid int) bool { _, ok := apps[pid]; return ok }}
	procs, total, err := a.d.Collector.Processes(ctx, o)
	if err != nil {
		return nil, err
	}
	at := time.Now()
	for i := range procs {
		if by, ok := apps[procs[i].PID]; ok {
			var sum int64
			for _, v := range by {
				sum += v
			}
			procs[i].GPUMem, procs[i].GPUMemByGPU = collect.P(sum), by
		}
	}
	// before sorting: a value that is not a number has no place in an order either (it sorts last, as unknown)
	if n := cleanProcessNumbers(procs); n > 0 {
		a.logOnce("processes-nan", "processes: a value that is not a number was left out (null in the answer)", "values", n)
	}
	procs = topProcesses(procs, maxProcessRows)
	for i := range procs {
		if c := procs[i].Cmdline; c != nil {
			v := redact.Cmdline(*c, 300)
			procs[i].Cmdline = &v
		}
	}
	return &procList{rows: procs, total: total, at: at}, nil
}

// topProcesses returns the rows that are among the n highest by CPU, by memory or by GPU memory (a new slice;
// p is sorted in place).
func topProcesses(p []collect.Process, n int) []collect.Process {
	if len(p) <= n {
		return slices.Clone(p)
	}
	keep := make(map[int]bool, 3*n)
	var out []collect.Process
	for _, by := range []string{"cpu", "mem", "gpu"} {
		SortProcesses(p, by)
		for _, x := range p[:n] {
			if !keep[x.PID] {
				keep[x.PID] = true
				out = append(out, x)
			}
		}
	}
	return out
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
		if err != nil || n < 1 || n > maxProcessRows {
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
	list, err := a.processList(r.Context())
	if err != nil {
		writeJSON(w, 503, map[string]any{"error": "could not list processes"})
		return
	}
	// One answer is put together at a time, as one listing was made at a time before: requests without a pause
	// keep one processor busy at most, not all of them.
	a.procAnswerMu.Lock()
	procs := slices.Clone(list.rows) // the listing is shared: sort a copy
	SortProcesses(procs, sortBy)
	if len(procs) > limit {
		procs = procs[:limit]
	}
	b, err := json.Marshal(map[string]any{"sampled_at": collect.Round(float64(list.at.UnixMilli())/1000, 3),
		"sort": sortBy, "total_processes": list.total, "processes": orEmpty(procs)})
	a.procAnswerMu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": "internal error"})
		return
	}
	writeJSON(w, 200, json.RawMessage(b))
}

// cleanProcessNumbers replaces every CPU percent, memory percent and start time that is not a number (NaN, an
// infinity) by "unknown" (null in the answer) and returns how many it found. encoding/json refuses a whole
// document for one such value, which turned one odd process into a 500 for the whole list; the rows stay, as
// in GET /metrics.
func cleanProcessNumbers(procs []collect.Process) (cleaned int) {
	bad := func(v **float64) {
		if *v != nil && (math.IsNaN(**v) || math.IsInf(**v, 0)) {
			*v = nil
			cleaned++
		}
	}
	for i := range procs {
		bad(&procs[i].CPUPercent)
		bad(&procs[i].MemPercent)
		bad(&procs[i].CreateTime)
	}
	return cleaned
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
		Mode     string        `json:"mode"`
		Approval *api.Approval `json:"approval"`
	}
	if err := decodeBody(r, &b); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	gate, ok := a.approved(w, r, api.ApprovalRequest{Verb: api.ApproveFanMode, Mode: &b.Mode}, b.Approval)
	if !ok {
		return
	}
	who := "panel " + clientIP(r)
	if f, ok := a.d.Fan.(approvedFan); ok && b.Approval != nil { // the Windows helper checks it
		st, body := f.SetModeApproved(r.Context(), b.Mode, who, b.Approval)
		writeJSON(w, st, body)
		return
	}
	st, body := gatedFanChange(a.d.Fan, gate, func(f FanControl) (int, map[string]any) { return f.SetMode(r.Context(), b.Mode, who) },
		func(f gatedFan) (int, map[string]any) { return f.SetModeGated(r.Context(), b.Mode, who, gate) })
	writeJSON(w, st, body)
}

// gatedFan is a FanControl that asks a request's passkey check itself, at the moment the request has passed
// its own checks (the in-process Fan).
type gatedFan interface {
	SetModeGated(ctx context.Context, mode, who string, gate Gated) (int, map[string]any)
	SetDutyGated(ctx context.Context, zone, percent int, who string, gate Gated) (int, map[string]any)
}

// gatedFanChange carries out a fan change that has a passkey check of this agent's own (gate; nil: none, or
// the helper checks). A fan control that asks the check itself does so after its own checks. For one that
// cannot, the check is asked here, right before the change, and the pass is told when the change was applied.
func gatedFanChange(fan FanControl, gate Gated, plain func(FanControl) (int, map[string]any), gated func(gatedFan) (int, map[string]any)) (int, map[string]any) {
	if gate == nil {
		return plain(fan)
	}
	if g, ok := fan.(gatedFan); ok {
		return gated(g)
	}
	pass, ref := gate()
	if ref != nil {
		return ref.Status, refusalBody(ref)
	}
	st, body := plain(fan)
	if st == 200 {
		pass.Applied()
	}
	return st, body
}

func (a *Agent) fanDuty(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Zone     json.RawMessage `json:"zone"`
		Percent  json.RawMessage `json:"percent"`
		Approval *api.Approval   `json:"approval"`
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
	gate, ok := a.approved(w, r, api.ApprovalRequest{Verb: api.ApproveFanSet, Zone: &zone, Percent: &pct}, b.Approval)
	if !ok {
		return
	}
	who := "panel " + clientIP(r)
	if f, ok := a.d.Fan.(approvedFan); ok && b.Approval != nil { // the Windows helper checks it
		st, body := f.SetDutyApproved(r.Context(), zone, pct, who, b.Approval)
		writeJSON(w, st, body)
		return
	}
	st, body := gatedFanChange(a.d.Fan, gate, func(f FanControl) (int, map[string]any) { return f.SetDuty(r.Context(), zone, pct, who) },
		func(f gatedFan) (int, map[string]any) { return f.SetDutyGated(r.Context(), zone, pct, who, gate) })
	writeJSON(w, st, body)
}

func (a *Agent) power(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Action      string          `json:"action"`
		DelayS      json.RawMessage `json:"delay_s"`
		RequestedBy any             `json:"requested_by"`
		Approval    *api.Approval   `json:"approval"`
	}
	err := decodeBody(r, &b)
	// This route counts its requests itself: cancel has a budget of its own, everything else (a body that
	// cannot be read too) counts as a control request.
	budget := budgetControl
	if err == nil && b.Action == "cancel" {
		budget = budgetCancel
	}
	if !a.controlBudget(w, r, budget) {
		return
	}
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	req := PowerRequest{Action: b.Action, RequestedBy: b.RequestedBy, Approval: b.Approval}
	if len(b.DelayS) > 0 && string(b.DelayS) != "null" {
		d, ok := intField(b.DelayS)
		if !ok {
			writeJSON(w, 400, map[string]any{"error": "delay_s must be an integer"})
			return
		}
		req.DelayS = &d
	}
	if b.Action == "shutdown" || b.Action == "reboot" || b.Action == "sleep" { // cancel needs no approval
		delay := defaultPowerDelayS
		if req.DelayS != nil {
			delay = *req.DelayS
		}
		// the first step of the passkey check; the second is req.Gate, which Power.Handle asks after its own checks
		gate, ok := a.approved(w, r, api.ApprovalRequest{Verb: api.ApprovePower, Action: &b.Action, DelayS: &delay}, b.Approval)
		if !ok {
			return
		}
		req.Gate = gate
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
	if a.helperRuns(api.ApproveApplyUpdate) { // Windows with the helper: it checks, when the installer is started
		if !a.updateApproval(w, r, &b) {
			return
		}
	} else { // this agent starts the installer itself and checks itself: Updater.Start asks b.Gate after its own checks
		gate, ok := a.approved(w, r, api.ApprovalRequest{Verb: api.ApproveApplyUpdate}, b.Approval)
		if !ok {
			return
		}
		b.Gate, b.Approval = gate, nil // nothing further down looks at the approval itself
	}
	st, body := a.d.Updater.Start(b)
	writeJSON(w, st, body)
}

// connKey is the context key under which Server keeps a request's connection.
type connKey struct{}

// Server wraps the handler with the timeouts every connection gets. A request's header must arrive within two
// seconds and fit in 4 KiB (the panel's is a few hundred bytes): an unfinished request holds little memory and
// not for long. How many connections may be open at all is LimitConns' part.
func (a *Agent) Server() *http.Server {
	return &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 45 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 4096,
		// LimitConns' connections learn when they are idle (kept open after an answer, for a next request) and
		// when a request with a valid token arrived on them (Handler)
		ConnContext: func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, connKey{}, c) },
		ConnState: func(c net.Conn, s http.ConnState) {
			if lc, ok := c.(interface{ ConnState(http.ConnState) }); ok {
				lc.ConnState(s)
			}
		},
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug)}
}
