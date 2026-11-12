package agent

// The Windows elevated helper, as the agent sees it. On Windows the agent runs as the virtual account
// NT SERVICE\fairy-agent with almost no rights. What needs more (Core Temp's shared memory, Windows' IPMI
// driver for BMC sensors and fans, shutdown / reboot / sleep) is done by the separate LocalSystem service
// fairy-agent-helper, which has no network at all and answers only a fixed list of verbs on a local named pipe
// that only this agent's service account (and SYSTEM / Administrators) may open (pkg/helper, pkg/helper/proto).
// The fan watchdog runs inside the helper, so it keeps working even when the agent stops.
//
// HelperClient is the agent's end: one pipe connection, one call at a time, a cached status for /metrics, and
// adapters that make the helper look like the in-process parts (FanControl, SensorSource, PowerExec, the Core
// Temp reader). Everything here is platform-independent; the pipe and the service manager are injected
// (helper_windows.go), fakes in the tests.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

// HelperControl is the helper as the HTTP API sees it (GET /metrics "helper", POST /helper/stop and /start).
type HelperControl interface {
	Status(ctx context.Context) api.HelperStatus
	Stop(ctx context.Context, who string) (api.HelperStatus, error)
	Start(ctx context.Context, who string) (api.HelperStatus, error)
}

// HelperService is the helper's service as the service manager reports and controls it.
type HelperService interface {
	// State is api.HelperRunning, HelperStopped, HelperStarting or HelperNotInstalled.
	State() (string, error)
	// Stop stops the service and waits until it has stopped; Start starts it and waits until it runs.
	Stop(ctx context.Context) error
	Start(ctx context.Context) error
}

// NeedsHelper reports whether config.yaml switches on something that needs the Windows helper: Core Temp,
// IPMI through Windows' driver (and with it fan control), or power control.
func NeedsHelper(c *Config) bool {
	return c.Sensors.CoreTemp || (c.IPMI.Enabled && c.IPMI.Transport == "wmi") || c.PowerControl.Enabled
}

// HelperClient talks to fairy-agent-helper.
type HelperClient struct {
	Dial    func(ctx context.Context) (io.ReadWriteCloser, error)
	Service HelperService
	Needed  bool
	Timeout time.Duration // per call (default 5 s)
	Every   time.Duration // status refresh (default 2 s)
	now     func() time.Time

	callMu sync.Mutex // one call at a time on the one connection
	conn   io.ReadWriteCloser

	stMu     sync.Mutex
	st       api.HelperStatus
	stAt     time.Time
	last     proto.StatusData // the latest status answer (sleep capability)
	hasLast  bool
	seen     string
	seenAt   time.Time
	loggedAs string
}

// NewHelperClient returns a client; nothing is dialled until the first call.
func NewHelperClient(dial func(ctx context.Context) (io.ReadWriteCloser, error), svc HelperService, needed bool) *HelperClient {
	return &HelperClient{Dial: dial, Service: svc, Needed: needed, Timeout: 5 * time.Second, Every: 2 * time.Second, now: time.Now}
}

// Installed reports whether the helper service exists.
func (c *HelperClient) Installed() bool {
	st, err := c.Service.State()
	return err == nil && st != api.HelperNotInstalled
}

type deadliner interface{ SetDeadline(time.Time) error }

// Call sends one request and returns the helper's answer. A broken connection is dialled again once (the
// helper may have restarted). When the helper does not answer because its service is not running, the error
// is api.ErrHelperStopped (or api.ErrHelperNotInstalled). A request that changes something and was written to
// the helper whole without an answer coming back is a *HelperUnanswered: it may have been carried out.
func (c *HelperClient) Call(ctx context.Context, req proto.Request) (proto.Response, error) {
	return c.call(ctx, req, c.Timeout)
}

// HelperUnanswered is the error of a request that changes something (proto.Control), was written to the
// helper whole, and got no answer in its time (or one that cannot be read). The helper reads what is in its
// pipe and carries it out whether or not anybody still waits for the answer, so such a request may have been
// carried out: it is not a refusal, and nobody may say "not done" because of it. It is not sent a second time.
type HelperUnanswered struct{ Err error }

func (e *HelperUnanswered) Error() string {
	return "the helper was sent the request and did not answer in time; it may have carried it out all the same (" + safeErr(e.Err) + ")"
}

// unanswered reports whether err is a *HelperUnanswered.
func unanswered(err error) bool {
	var un *HelperUnanswered
	return errors.As(err, &un)
}

func (c *HelperClient) call(ctx context.Context, req proto.Request, timeout time.Duration) (proto.Response, error) {
	b, err := proto.EncodeRequest(req)
	if err != nil {
		return proto.Response{}, err
	}
	version := proto.FrameVersion(req)
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	c.callMu.Lock()
	defer c.callMu.Unlock()
	// The time limit starts here, with the connection in hand, not before the wait for it. It started before
	// (audit 6, r4-a1-01): a request that had waited behind another call (a fan change may take 25 s) went out
	// with little or nothing of its 5 s left. The helper carried it out all the same, and the agent, which read
	// no answer in the time left, said the request had failed. A caller that gave up during the wait (its own
	// context) sends nothing.
	if err := ctx.Err(); err != nil {
		return proto.Response{}, c.notRunning(err)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if c.conn == nil {
			conn, err := c.Dial(ctx)
			if err != nil {
				return proto.Response{}, c.notRunning(err)
			}
			c.conn = conn
		}
		r, sent, err := c.roundTrip(ctx, b, version)
		if err == nil {
			return r, nil
		}
		_ = c.conn.Close()
		c.conn = nil
		if sent && proto.Control(req.Verb) {
			// The helper has the request. Whether it carried it out nobody knows here; its next status may tell
			// (a pending shutdown), so the copy /metrics is answered from is not used again.
			c.invalidate()
			return proto.Response{}, &HelperUnanswered{Err: err}
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return proto.Response{}, c.notRunning(lastErr)
}

// roundTrip writes the request and reads the answer. sent reports whether the whole request was written: from
// then on the helper may carry it out, whatever becomes of the answer.
func (c *HelperClient) roundTrip(ctx context.Context, b []byte, version int) (r proto.Response, sent bool, err error) {
	// Nothing is written once the time is over: a pipe takes a small write at once and never looks at the
	// deadline (winpipe.Conn.do), so the request would go out with nobody left to read its answer.
	if err := ctx.Err(); err != nil {
		return proto.Response{}, false, err
	}
	if d, ok := c.conn.(deadliner); ok {
		dl, _ := ctx.Deadline()
		_ = d.SetDeadline(dl)
	}
	if err := proto.WriteRequest(c.conn, b, version); err != nil {
		return proto.Response{}, false, err
	}
	f, err := proto.ReadFrame(c.conn, proto.MaxResponse)
	if err != nil {
		return proto.Response{}, true, err
	}
	r, err = proto.DecodeResponse(f)
	return r, true, err
}

// notRunning turns a connection error into api.ErrHelperStopped / ErrHelperNotInstalled when the service
// manager says the helper is not running.
func (c *HelperClient) notRunning(err error) error {
	st, serr := c.Service.State()
	switch {
	case serr != nil:
		return err
	case st == api.HelperNotInstalled:
		return api.ErrHelperNotInstalled
	case st != api.HelperRunning:
		return api.ErrHelperStopped
	}
	return fmt.Errorf("helper not answering: %w", err)
}

// data calls a read verb and decodes its data into v.
func (c *HelperClient) data(ctx context.Context, verb string, v any) (proto.Response, error) {
	r, err := c.Call(ctx, proto.Request{Verb: verb})
	if err != nil {
		return r, err
	}
	if r.Status != 200 {
		return r, &proto.Error{Code: r.Code, Msg: r.Error}
	}
	if err := json.Unmarshal(r.Data, v); err != nil {
		return r, errors.New("invalid answer from the helper")
	}
	return r, nil
}

// Run refreshes the status every Every until ctx ends (so /metrics never waits for the helper).
func (c *HelperClient) Run(ctx context.Context) {
	for ctx.Err() == nil {
		c.refresh(ctx)
		select {
		case <-ctx.Done():
		case <-time.After(c.Every):
		}
	}
}

// Status is the latest helper state (refreshed by Run; computed now if it is older than two refreshes).
func (c *HelperClient) Status(ctx context.Context) api.HelperStatus {
	c.stMu.Lock()
	fresh := !c.stAt.IsZero() && c.now().Sub(c.stAt) < 2*c.Every+c.Timeout
	st := c.st
	c.stMu.Unlock()
	if fresh {
		return st
	}
	return c.refresh(ctx)
}

func (c *HelperClient) refresh(ctx context.Context) api.HelperStatus {
	state, err := c.Service.State()
	st := api.HelperStatus{State: state, Needed: c.Needed}
	var sd proto.StatusData
	if err != nil {
		st.State, st.Error = api.HelperError, "service manager: "+safeErr(err)
	} else if state == api.HelperRunning {
		if _, err := c.data(ctx, proto.VerbStatus, &sd); err != nil {
			if errors.Is(err, api.ErrHelperStopped) { // stopped between the two questions
				st.State = api.HelperStopped
			} else {
				st.State, st.Error = api.HelperError, "not answering: "+safeErr(err)
			}
		} else {
			wd := sd.Watchdog
			st.Version, st.Since, st.Features, st.Watchdog, st.Proto = sd.Version, sd.Started, sd.Features, &wd, sd.Proto
		}
	}
	c.stMu.Lock()
	defer c.stMu.Unlock()
	now := c.now()
	if st.State != c.seen {
		c.seen, c.seenAt = st.State, now
	}
	if st.Since == "" && st.State != api.HelperRunning {
		st.Since = c.seenAt.UTC().Format(time.RFC3339)
	}
	if st.State == api.HelperRunning {
		c.last, c.hasLast = sd, true
	}
	if c.loggedAs != st.State {
		c.loggedAs = st.State
		lvl := slog.LevelInfo
		if st.State == api.HelperError || (st.State == api.HelperNotInstalled && c.Needed) {
			lvl = slog.LevelWarn
		}
		slog.Log(context.Background(), lvl, "fairy-agent-helper: "+st.State, "needed", c.Needed, "version", st.Version, "error", st.Error)
	}
	c.st, c.stAt = st, now
	return st
}

func (c *HelperClient) invalidate() {
	c.stMu.Lock()
	c.stAt = time.Time{}
	c.stMu.Unlock()
}

// Stop hands the fans back to the BMC's automatic mode (the helper does it again itself when it stops), then
// stops the helper service.
func (c *HelperClient) Stop(ctx context.Context, who string) (api.HelperStatus, error) {
	state, err := c.Service.State()
	if err != nil {
		return c.Status(ctx), err
	}
	if state == api.HelperNotInstalled {
		return c.Status(ctx), api.ErrHelperNotInstalled
	}
	if state == api.HelperRunning && slices.Contains(c.Status(ctx).Features, api.FeatureFans) {
		by := who
		cctx, cancel := context.WithTimeout(ctx, 25*time.Second)
		r, err := c.callWithTimeout(cctx, proto.Request{Verb: proto.VerbFanAuto, By: &by}, 25*time.Second)
		cancel()
		if err != nil || r.Status != 200 {
			slog.Warn("helper stop: handing the fans back to the BMC failed; the helper tries again as it stops", "error", errOrCode(err, r))
		}
	}
	c.closeConn()
	err = c.Service.Stop(ctx)
	c.invalidate()
	return c.Status(ctx), err
}

// Start starts the helper service and waits (up to 10 s) until it answers.
func (c *HelperClient) Start(ctx context.Context, _ string) (api.HelperStatus, error) {
	state, err := c.Service.State()
	if err != nil {
		return c.Status(ctx), err
	}
	if state == api.HelperNotInstalled {
		return c.Status(ctx), api.ErrHelperNotInstalled
	}
	if err := c.Service.Start(ctx); err != nil {
		c.invalidate()
		return c.Status(ctx), err
	}
	deadline := c.now().Add(10 * time.Second)
	for {
		c.invalidate()
		st := c.Status(ctx)
		if st.Running() || c.now().After(deadline) || ctx.Err() != nil {
			return st, nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// callWithTimeout is Call with a longer time limit (fan changes: the BMC may take a while).
func (c *HelperClient) callWithTimeout(ctx context.Context, req proto.Request, d time.Duration) (proto.Response, error) {
	return c.call(ctx, req, d)
}

func (c *HelperClient) closeConn() {
	c.callMu.Lock()
	defer c.callMu.Unlock()
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}

func errOrCode(err error, r proto.Response) string {
	if err != nil {
		return safeErr(err)
	}
	return r.Code + " " + r.Error
}

// CoreTempRead is the Core Temp reader for collect.WithCoreTempReader: the helper's copy of the shared memory.
func (c *HelperClient) CoreTempRead() ([]byte, string, error) {
	var d proto.CoreTempData
	_, err := c.data(context.Background(), proto.VerbCoreTempRead, &d)
	var pe *proto.Error
	switch {
	case errors.As(err, &pe) && pe.Code == proto.CodeUnavailable:
		return nil, "", collect.ErrCoreTempAbsent
	case errors.As(err, &pe) && pe.Code == proto.CodeDenied:
		return nil, d.Name, collect.ErrCoreTempDenied
	case errors.Is(err, api.ErrHelperNotInstalled):
		return nil, "", api.ErrHelperStopped
	case err != nil:
		return nil, "", err
	}
	if len(d.Block) > collect.CoreTempExSize {
		d.Block = d.Block[:collect.CoreTempExSize]
	}
	return d.Block, d.Name, nil
}

// ApplyUpdate asks the helper to start the updater service (when the agent may not start it itself).
func (c *HelperClient) ApplyUpdate(ctx context.Context) error { return c.ApplyUpdateApproved(ctx, nil) }

// ApplyUpdateApproved asks the helper to start the updater service and hands it the approval POST /update
// carried. The helper checks it; the agent does not look inside.
func (c *HelperClient) ApplyUpdateApproved(ctx context.Context, ap *api.Approval) error {
	by := "self-update"
	r, err := c.Call(ctx, proto.Request{Verb: proto.VerbApplyUpdate, By: &by, Approval: ap})
	if err != nil {
		return err
	}
	if r.Status != 200 {
		return errors.New("helper: " + r.Error)
	}
	return nil
}

// Sensors returns the BMC sensor source served by the helper; run it with Run.
func (c *HelperClient) Sensors(interval time.Duration) *HelperSensors {
	return &HelperSensors{c: c, interval: interval}
}

// HelperSensors is a SensorSource fed by the helper's ipmi_sensors.
type HelperSensors struct {
	c        *HelperClient
	interval time.Duration

	mu     sync.Mutex
	data   proto.SensorsData
	at     time.Time
	logged string
}

// Run asks the helper for the BMC's readings every interval until ctx ends.
func (s *HelperSensors) Run(ctx context.Context) {
	for ctx.Err() == nil {
		s.refresh(ctx)
		select {
		case <-ctx.Done():
		case <-time.After(s.interval):
		}
	}
}

func (s *HelperSensors) refresh(ctx context.Context) {
	var d proto.SensorsData
	_, err := s.c.data(ctx, proto.VerbIPMISensors, &d)
	s.mu.Lock()
	defer s.mu.Unlock()
	state := "ok"
	if err != nil {
		state = safeErr(err)
	}
	if state != s.logged {
		s.logged = state
		switch {
		case err == nil:
			slog.Info("BMC sensors through the helper")
		case errors.Is(err, api.ErrHelperStopped) || errors.Is(err, api.ErrHelperNotInstalled):
			slog.Info("BMC sensors: helper stopped")
		default:
			slog.Warn("BMC sensors through the helper unavailable", "error", state)
		}
	}
	if err != nil {
		return
	}
	d.Bound()
	s.data, s.at = d, time.Now()
}

// Metrics returns the latest readings if fresh (three intervals), like BMC.Metrics.
func (s *HelperSensors) Metrics() ([]collect.Temp, []collect.Fan, []collect.Voltage) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.at.IsZero() || time.Since(s.at) > 3*s.interval+30*time.Second {
		return nil, nil, nil
	}
	return s.data.Temps, s.data.Fans, s.data.Voltages
}

// Fan returns the fan control served by the helper.
func (c *HelperClient) Fan(cfg FanConfig) *HelperFan { return &HelperFan{c: c, cfg: cfg} }

// HelperFan is a FanControl that forwards to the helper (which runs the BMC commands and the watchdog).
type HelperFan struct {
	c   *HelperClient
	cfg FanConfig
}

// helperUnanswered is the HTTP answer to a request the helper was sent and did not answer (*HelperUnanswered):
// 504, the status of a gateway whose other side did not answer in time, which is what the agent is to the
// helper here. It is not one of the agent's refusals (4xx, 500, 503 with a code): a panel reads 504 as "no
// answer, the request may have arrived", never as "refused" or "not done". what names the request, maybe what
// may have happened.
func helperUnanswered(what, maybe string) (int, map[string]any) {
	return http.StatusGatewayTimeout, map[string]any{"error": "the helper was sent " + what + " and did not answer in time: " + maybe}
}

func helperReason(err error) string {
	if errors.Is(err, api.ErrHelperStopped) || errors.Is(err, api.ErrHelperNotInstalled) {
		return api.ReasonHelperStopped
	}
	return api.ReasonHelperError
}

// Status is /fan/status. While the helper is stopped: "available": false, "reason": "helper_stopped" (and no
// error: nothing is wrong with the fans, the helper is just not running).
func (f *HelperFan) Status(ctx context.Context) map[string]any {
	var m map[string]any
	_, err := f.c.data(ctx, proto.VerbFanStatus, &m)
	if err == nil && m != nil {
		m["available"] = true
		return m
	}
	out := map[string]any{"enabled": true, "vendor": f.cfg.Vendor, "mode": nil, "error": nil, "overridden": false,
		"duty": map[string]int{}, "min_duty": f.cfg.MinDuty, "max_temp_c": f.cfg.MaxTempC, "fans": []collect.Fan{},
		"events": []FanEvent{}, "auto_mode": f.cfg.AutoMode, "unsupported_modes": []string{}, "available": false}
	var pe *proto.Error
	if errors.As(err, &pe) {
		out["error"], out["available"] = pe.Msg, true
	} else {
		out["reason"] = helperReason(err)
	}
	return out
}

func (f *HelperFan) change(ctx context.Context, req proto.Request) (int, map[string]any) {
	r, err := f.c.callWithTimeout(ctx, req, 25*time.Second)
	if unanswered(err) {
		return helperUnanswered("the fan change", "the fans may have been changed all the same: look at the fan status")
	}
	if err != nil {
		reason := helperReason(err)
		msg := "helper stopped: start fairy-agent-helper to change the fans"
		if reason == api.ReasonHelperError {
			msg = "the helper did not answer: " + safeErr(err)
		}
		return 503, map[string]any{"error": msg, "code": reason}
	}
	var body map[string]any
	if len(r.Data) > 0 {
		if json.Unmarshal(r.Data, &body) != nil {
			return 502, map[string]any{"error": "invalid answer from the helper"}
		}
	}
	if body == nil {
		body = map[string]any{"error": r.Error}
		if r.Code != "" {
			body["code"] = r.Code
		}
	}
	return r.Status, body
}

// SetMode is POST /fan/mode through the helper.
func (f *HelperFan) SetMode(ctx context.Context, mode, who string) (int, map[string]any) {
	return f.SetModeApproved(ctx, mode, who, nil)
}

// SetModeApproved is SetMode with the approval the request carried (nil: none). It is passed to the helper as
// it came; the helper decides.
func (f *HelperFan) SetModeApproved(ctx context.Context, mode, who string, ap *api.Approval) (int, map[string]any) {
	if _, ok := modeByteOK(mode); !ok {
		return 400, map[string]any{"error": "mode must be standard, full, optimal or heavyio"}
	}
	return f.change(ctx, proto.Request{Verb: proto.VerbFanMode, Mode: &mode, By: byOf(who), Approval: ap})
}

// SetDuty is POST /fan/duty through the helper (it refuses less than 30 % whatever is asked).
func (f *HelperFan) SetDuty(ctx context.Context, zone, percent int, who string) (int, map[string]any) {
	return f.SetDutyApproved(ctx, zone, percent, who, nil)
}

// SetDutyApproved is SetDuty with the approval the request carried (nil: none).
func (f *HelperFan) SetDutyApproved(ctx context.Context, zone, percent int, who string, ap *api.Approval) (int, map[string]any) {
	if zone != 0 && zone != 1 {
		return 400, map[string]any{"error": "zone must be 0 or 1"}
	}
	if percent < max(f.cfg.MinDuty, proto.MinDuty) || percent > 100 {
		return 400, map[string]any{"error": fmt.Sprintf("percent must be an integer between %d and 100", max(f.cfg.MinDuty, proto.MinDuty))}
	}
	return f.change(ctx, proto.Request{Verb: proto.VerbFanSet, Zone: &zone, Percent: &percent, By: byOf(who), Approval: ap})
}

func modeByteOK(mode string) (string, bool) { return mode, slices.Contains(proto.FanModes, mode) }

// byOf is who, cleaned to what the protocol accepts.
func byOf(who string) *string {
	s := cleanWho(who)
	return &s
}

// Power returns the PowerExec served by the helper.
func (c *HelperClient) Power() *HelperPower { return &HelperPower{c: c} }

// HelperPower is a PowerExec that forwards to the helper (which holds SeShutdownPrivilege).
type HelperPower struct{ c *HelperClient }

// Schedule is ScheduleBy without a requester (the helper writes its own message).
func (p *HelperPower) Schedule(action string, delay time.Duration, _ string) error {
	return p.ScheduleBy(action, delay, "agent")
}

// ScheduleBy asks the helper for a delayed shutdown, reboot or sleep.
func (p *HelperPower) ScheduleBy(action string, delay time.Duration, who string) error {
	return p.ScheduleApproved(action, delay, who, nil)
}

// ScheduleApproved is ScheduleBy with the approval the request carried (nil: none). The helper checks it.
func (p *HelperPower) ScheduleApproved(action string, delay time.Duration, who string, ap *api.Approval) error {
	d := int(delay / time.Second)
	return p.call(proto.Request{Verb: proto.VerbPower, Action: &action, DelayS: &d, By: byOf(who), Approval: ap})
}

// Cancel cancels a pending action.
func (p *HelperPower) Cancel() error {
	a := "cancel"
	return p.call(proto.Request{Verb: proto.VerbPower, Action: &a, By: byOf("agent")})
}

func (p *HelperPower) call(req proto.Request) error {
	r, err := p.c.Call(context.Background(), req)
	if errors.Is(err, api.ErrHelperNotInstalled) {
		return api.ErrHelperStopped
	}
	if err != nil {
		return err
	}
	if r.Status != 200 {
		if approvalCode(r.Code) { // Power.Handle answers with the helper's status and code
			return &ApprovalError{Status: r.Status, Code: r.Code, Msg: r.Error}
		}
		return errors.New(r.Error)
	}
	return nil
}

// LiveSleep tells Power not to cache CanSleep (the helper's answer is already cached and changes when the
// helper stops or starts).
func (p *HelperPower) LiveSleep() {}

// CanSleep is what the helper last reported (false while it is not running).
func (p *HelperPower) CanSleep() (bool, string) {
	st := p.c.Status(context.Background())
	if !st.Running() {
		return false, "helper stopped"
	}
	p.c.stMu.Lock()
	defer p.c.stMu.Unlock()
	if !p.c.hasLast {
		return false, "helper stopped"
	}
	return p.c.last.SleepOK, p.c.last.SleepNote
}

// HelperSetupHint is how to install the helper (and move the agent to its own low-rights account).
const HelperSetupHint = `in an Administrator PowerShell: & "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update --helper`

// ApprovalError is a request the machine's approval check refused: what the HTTP answer says.
type ApprovalError struct {
	Status int
	Code   string
	Msg    string
}

func (e *ApprovalError) Error() string { return e.Msg }

func approvalCode(code string) bool {
	return code == api.CodeApprovalRequired || code == api.CodeApprovalRefused || code == api.CodeApprovalUnavailable
}

// HelperApproval is the helper's approval check as the HTTP API sees it (the "approval" block of GET /metrics,
// POST /approval/challenge and /approval/trust). On Windows the helper does all the checking; the agent only
// carries requests and answers.
type HelperApproval interface {
	// ApprovalStatus is the "approval" block; ok is false when there is nothing to report (no helper installed,
	// or one from before approvals).
	ApprovalStatus(ctx context.Context) (st api.ApprovalStatus, ok bool)
	// ApprovalNow asks the helper for its approval state at this moment. known is false when it does not
	// answer now (stopped, starting, its pipe down) or is a helper from before approvals: then nothing is known,
	// and what it said earlier does not count.
	ApprovalNow(ctx context.Context) (st api.ApprovalStatus, known bool)
	// Checks reports what this agent knows of the approval check of the helper it reaches, from the helper's
	// latest status answer. seen is false while no helper has answered since this agent started. checks is true
	// when the helper that answered last speaks pipe protocol 3 and reports an approval state; it is false for a
	// helper from before approvals (an update that has not restarted the helper yet), which carries out fan and
	// power requests without looking at any approval, and for the helper of the test build of 2026-11-11 (pipe
	// protocol 2), whose check does not bind an approval to this machine.
	Checks(ctx context.Context) (seen, checks bool)
	// Challenge and TrustInit pass the request to the helper and return the HTTP status and body.
	Challenge(ctx context.Context, req api.ApprovalRequest) (int, any)
	TrustInit(ctx context.Context, in api.TrustInit) (int, any)
}

// ApprovalStatus is the helper's approval state from its latest status answer; "unknown" while it is installed
// and not answering.
func (c *HelperClient) ApprovalStatus(ctx context.Context) (api.ApprovalStatus, bool) {
	st := c.Status(ctx)
	c.stMu.Lock()
	defer c.stMu.Unlock()
	switch {
	case st.State == api.HelperNotInstalled:
		return api.ApprovalStatus{}, false
	case !st.Running():
		if c.hasLast && !c.checksLocked() {
			return api.ApprovalStatus{}, false // the helper that ran before was one from before approvals
		}
		return api.ApprovalStatus{State: api.ApprovalUnknown, EnforcedBy: api.EnforcedByHelper, Proto: api.ApprovalProto,
			Error: "the helper is not answering (" + st.State + ")"}, true
	case !c.checksLocked():
		return api.ApprovalStatus{}, false
	}
	return *c.last.Approval, true
}

// checksLocked reports whether the helper that answered last checks approvals the way this agent relies on:
// it speaks pipe protocol 3 and reports an approval state. Not one from before approvals (no state, protocol
// 1), and not the test build of 2026-11-11 (protocol 2), whose check knows no machine id: what such a helper
// says about approvals is not passed on, and nothing that needs an approval is handed to it. Caller holds
// c.stMu.
func (c *HelperClient) checksLocked() bool {
	return c.hasLast && c.last.Proto >= proto.Version3 && c.last.Approval != nil
}

// ApprovalNow: see HelperApproval. It asks the helper now and does not use the cached status.
func (c *HelperClient) ApprovalNow(ctx context.Context) (api.ApprovalStatus, bool) {
	st := c.refresh(ctx)
	c.stMu.Lock()
	defer c.stMu.Unlock()
	if !st.Running() || !c.checksLocked() {
		return api.ApprovalStatus{}, false
	}
	return *c.last.Approval, true
}

// Checks: see HelperApproval. The helper that answered last counts, also while it is not running: what starts
// again is seen within one status refresh.
func (c *HelperClient) Checks(ctx context.Context) (seen, checks bool) {
	c.Status(ctx)
	c.stMu.Lock()
	defer c.stMu.Unlock()
	return c.hasLast, c.checksLocked()
}

// approvalCall sends a protocol version 3 request and turns the helper's answer into an HTTP answer.
func (c *HelperClient) approvalCall(ctx context.Context, req proto.Request) (int, any) {
	st := c.Status(ctx)
	c.stMu.Lock()
	old := st.Running() && c.hasLast && c.last.Proto < proto.Version3
	c.stMu.Unlock()
	if old {
		return 409, map[string]any{"code": api.CodeHelperTooOld,
			"error": "the running fairy-agent-helper is older than this agent and does not know this version's approvals (restart it: Restart-Service fairy-agent-helper; if it is still older after that, install this version of both services)"}
	}
	r, err := c.Call(ctx, req)
	var bad *proto.Error
	if errors.As(err, &bad) { // the request itself is not one the helper takes (a value outside its limits): not sent
		return 400, map[string]any{"error": bad.Msg}
	}
	if unanswered(err) {
		if req.Verb == proto.VerbTrustInit {
			return helperUnanswered("the trust", "it may be written all the same: look at the machine's approval state before anything else")
		}
		return helperUnanswered("the question about an approval", "nothing was done; ask again")
	}
	if err != nil {
		reason := helperReason(err)
		msg := "helper stopped: start fairy-agent-helper"
		if reason == api.ReasonHelperError {
			msg = "the helper did not answer: " + safeErr(err)
		}
		return 503, map[string]any{"error": msg, "code": reason}
	}
	if r.Status == 200 && len(r.Data) > 0 {
		return 200, r.Data
	}
	body := map[string]any{"error": r.Error}
	if r.Code != "" {
		body["code"] = r.Code
	}
	if r.RetryAfterS > 0 { // too_many_challenges: when to ask again (retryAfter makes the header of it)
		body[retryAfterMember] = r.RetryAfterS
	}
	return r.Status, body
}

// Challenge is POST /approval/challenge through the helper.
func (c *HelperClient) Challenge(ctx context.Context, req api.ApprovalRequest) (int, any) {
	return c.approvalCall(ctx, proto.Request{Verb: proto.VerbChallenge, For: &req.Verb, Zone: req.Zone, Percent: req.Percent,
		Mode: req.Mode, Action: req.Action, DelayS: req.DelayS, TrustHash: req.TrustHash})
}

// TrustInit is POST /approval/trust through the helper: the first-time set of the trust, with the approval
// that proves it. The helper checks both; the agent does not look inside.
func (c *HelperClient) TrustInit(ctx context.Context, in api.TrustInit) (int, any) {
	st, body := c.approvalCall(ctx, proto.Request{Verb: proto.VerbTrustInit, Trust: &in})
	c.invalidate() // the next /metrics shows the new state
	return st, body
}
