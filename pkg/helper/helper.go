// Package helper is fairy-agent-helper, the small LocalSystem service that does for the Windows agent what the
// agent's own low-rights account (NT SERVICE\fairy-agent) may not: read Core Temp's shared memory, talk to the
// BMC through Windows' IPMI driver (sensors and Supermicro fans), shut down / reboot / sleep, and start the
// signature-checking updater. It opens no network connection and listens on nothing but one local named pipe
// whose access list admits only the agent's service account, SYSTEM and Administrators (and it checks every
// client's token again). It answers a fixed list of verbs (pkg/helper/proto): no paths, no commands, no free
// text. The fan watchdog (100 % at 80 °C, or after 30 s without a temperature, while a fixed duty is set) runs
// here, so it keeps working when the agent stops; when the helper itself stops it hands the fans back to the
// BMC's automatic mode first.
//
// This file is the platform-independent core (verbs, rate limits, audit log, watchdog wiring); serve_windows.go
// is the pipe and the service glue.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

// Parts are what the helper serves; nil parts are switched off in config.yaml and their verbs answer "disabled".
type Parts struct {
	Version  string
	CoreTemp func() ([]byte, string, error) // Core Temp's shared memory
	BMC      *agent.BMC                     // BMC sensors (IPMI through Windows' driver)
	Fan      *agent.Fan                     // fan control on that BMC (and its watchdog)
	Power    agent.PowerExec                // shutdown, reboot, sleep
	// MinDelayS is power_control.min_delay_s of config.yaml: the shortest delay a shutdown, reboot or sleep may
	// be asked with. The helper enforces it itself (the agent does too): a compromised agent process cannot
	// shorten the warning time below what the administrator set. 0 means the protocol's minimum.
	MinDelayS int
	Updater   func(ctx context.Context) error
	// Approval is the passkey check (pkg/approval): with a trust file in the helper's folder, fan_set, fan_mode,
	// power (other than cancel) and apply_update run only with an approval the helper has verified itself. The
	// agent is not trusted with any part of it. nil: no check (tests of the other parts).
	Approval *approval.Gate
	// Runs carries the runs of Approval out (approval.RunWatch): it takes the ticket and the confirmation,
	// counts the wait and switches the PC off through Power. nil: New builds it from Approval, Power and
	// Updating (none without power control: the self-off needs it).
	Runs *approval.RunWatch
	// Updating reports whether the updater service is installing an update (nil: never): a self-off waits for it.
	Updating func() bool
	Audit    *slog.Logger // the audit log (helper.log); nil = slog.Default()
	Now      func() time.Time
}

// Server answers the agent's requests.
type Server struct {
	p       Parts
	limit   *proto.Limiter
	started time.Time

	sleepMu   sync.Mutex
	sleepOK   bool
	sleepNote string
	sleepAt   time.Time
}

// New returns the server.
func New(p Parts) *Server {
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.Audit == nil {
		p.Audit = slog.Default()
	}
	l := proto.NewLimiter(proto.ReadsPerMinute, proto.ChangesPerMinute, time.Minute)
	l.Now = p.Now
	if p.Runs == nil && p.Approval != nil && p.Power != nil {
		p.Runs = approval.NewRunWatch(p.Approval, runHooks(p.Power, p.Updating))
	}
	return &Server{p: p, limit: l, started: p.Now()}
}

// runHooks are the parts of the machine a run needs, from the helper's power part: what is pending is what
// that part remembers; the self-off is its ordinary delayed shutdown (Windows counts it down and shows its own
// notice with the text; the action is remembered like every other, shown as pending and cancelled the same
// way); and the stop of a countdown is its Cancel.
func runHooks(power agent.PowerExec, updating func() bool) approval.RunHooks {
	return approval.RunHooks{
		Pending: func() bool {
			src, ok := power.(interface{ PendingAction() (agent.Pending, bool) })
			if !ok {
				return false
			}
			_, pending := src.PendingAction()
			return pending
		},
		Shutdown: func(delay time.Duration, message, who string) error {
			if n, ok := power.(interface {
				ScheduleNotice(action string, delay time.Duration, message, who string) error
			}); ok {
				return n.ScheduleNotice("shutdown", delay, message, who)
			}
			return power.Schedule("shutdown", delay, message)
		},
		Cancel:   power.Cancel,
		Updating: updating,
	}
}

// FromConfig builds the parts config.yaml switches on: Core Temp (sensors.coretemp), IPMI through Windows
// (ipmi.enabled with transport wmi) and fan control, power control and self-update. The returned close function
// stops the IPMI transport.
//
// Before anything is built, the variables config.yaml names for a device's secret are hidden from the programs
// the helper starts (agent.HideDeviceSecrets), as the agent hides them: the helper does not read env_file, but
// a secret kept as a variable of the whole machine is in its environment too, and PowerShell (IPMI through
// Windows) would get it.
func FromConfig(cfg *agent.Config, version string, audit *slog.Logger) (Parts, func(), error) {
	agent.HideDeviceSecrets(cfg)
	p := Parts{Version: version, Audit: audit}
	// The helper is the one that takes run tickets and confirmations on Windows and keeps the run record (in its
	// own folder, next to the trust file). The notice of a self-off and the delay of a run's shutdown are never
	// shorter than the shortest delay it accepts for any shutdown.
	p.Approval = approval.NewGate(approval.Options{Files: agent.ApprovalFiles(cfg), EnforcedBy: api.EnforcedByHelper,
		Uptime: agent.SystemUptime, BootID: agent.SystemBootIDOwner, Log: audit, // the helper makes the id of the boot (agent/bootid.go)
		Runs: true, MinDelayS: max(cfg.PowerControl.MinDelayS, proto.MinDelayS)})
	closer := func() {}
	if cfg.Sensors.CoreTemp {
		p.CoreTemp = collect.ReadCoreTemp
	}
	if cfg.IPMI.Enabled && cfg.IPMI.Transport == "wmi" {
		t, err := agent.IPMITransport(cfg.IPMI)
		if err != nil {
			return p, closer, err
		}
		closer = t.Close
		p.BMC = agent.NewBMC(t, time.Duration(cfg.IPMI.SensorIntervalS*float64(time.Second)))
		if cfg.FanControl.Enabled {
			read := p.CoreTemp
			p.Fan = agent.NewFan(t, p.BMC, cfg.FanControl, func() []collect.Temp { return coreTemps(read) })
		}
	}
	if cfg.PowerControl.Enabled {
		// a pending shutdown is remembered in the helper's own folder, so Cancel still works after a restart
		p.Power = agent.SystemPowerAt(filepath.Join(cfg.Dir(), "helper"))
		p.MinDelayS = cfg.PowerControl.MinDelayS
	}
	if cfg.SelfUpdate.Enabled {
		p.Updater = agent.StartUpdaterService
		p.Updating = agent.UpdaterRunning
	}
	return p, closer, nil
}

// coreTemps are Core Temp's core temperatures for the watchdog (none when Core Temp is off or not running).
func coreTemps(read func() ([]byte, string, error)) []collect.Temp {
	if read == nil {
		return nil
	}
	b, _, err := read()
	if err != nil {
		return nil
	}
	d, err := collect.ParseCoreTemp(b)
	if err != nil {
		return nil
	}
	return d.Temps()
}

// Runs is the watch of this helper's runs (nil: it keeps none). The service does not use it; it is for whoever
// drives a helper in a test and wants the watch to look now instead of in a second.
func (s *Server) Runs() *approval.RunWatch { return s.p.Runs }

// Features are what this helper serves (api.FeatureCoreTemp ...).
func (s *Server) Features() []string {
	var f []string
	for _, x := range []struct {
		on   bool
		name string
	}{{s.p.CoreTemp != nil, api.FeatureCoreTemp}, {s.p.BMC != nil, api.FeatureIPMI}, {s.p.Fan != nil, api.FeatureFans},
		{s.p.Power != nil, api.FeaturePower}, {s.p.Updater != nil, api.FeatureUpdate}} {
		if x.on {
			f = append(f, x.name)
		}
	}
	return f
}

// Start runs the BMC reader and the fan watchdog until ctx ends.
func (s *Server) Start(ctx context.Context) {
	if s.p.BMC != nil {
		go s.p.BMC.Run(ctx)
	}
	if s.p.Fan != nil {
		go s.p.Fan.RunWatchdog(ctx)
	}
	s.p.Audit.Info("helper started", "version", s.p.Version, "features", strings.Join(s.Features(), ","))
	if s.p.Approval != nil {
		// The trust file is read now, not at the first request: the helper owns it, and a file from before
		// machine ids gets its id here, at the start (approval.Gate.reload), before anybody asks.
		if st := s.p.Approval.Status(); st.State != api.ApprovalOff {
			s.p.Audit.Info("passkey approval of fan, power and update requests", "state", st.State, "issuer", st.Issuer, "machine_id", st.MachineID, "error", st.Error)
		}
	}
	if s.p.Runs != nil {
		// A run from before this helper restarted (the update restarts it) is taken over from the record now:
		// the wait goes on by the uptime, and what was left of a confirmation is what is left.
		go s.p.Runs.Run(ctx)
	}
}

// Shutdown hands the fans back to the BMC's automatic mode if a fixed duty may be in effect (the watchdog
// stops with the helper, so no fixed duty is left without it). Call it when the service stops or Windows
// shuts down.
func (s *Server) Shutdown(ctx context.Context) {
	s.p.Approval.RunStop() // the clock goes into the run record (approval.Gate.runClockKeep)
	if s.p.Fan == nil {
		s.p.Audit.Info("helper stopping")
		return
	}
	mode, err := s.p.Fan.Auto(ctx, "helper stopping", false)
	if err != nil {
		s.p.Audit.Error("helper stopping: could not hand the fans back to the BMC", "error", err.Error())
		return
	}
	s.p.Audit.Info("helper stopping: fans in BMC mode", "mode", mode)
}

// Handle answers one plain (protocol version 1) request frame from client (a description for the audit log).
func (s *Server) Handle(ctx context.Context, client string, frame []byte) proto.Response {
	return s.handle(ctx, client, frame, proto.Version)
}

// HandleV3 answers one request frame that arrived as a version 3 frame.
func (s *Server) HandleV3(ctx context.Context, client string, frame []byte) proto.Response {
	return s.handle(ctx, client, frame, proto.Version3)
}

func (s *Server) handle(ctx context.Context, client string, frame []byte, version int) proto.Response {
	decode := proto.DecodeRequest
	if version == proto.Version3 {
		decode = proto.DecodeRequestV3
	}
	req, err := decode(frame)
	if err != nil {
		s.p.Audit.Warn("refused request", "client", client, "reason", err.Error())
		return proto.FromError(err)
	}
	if !s.limit.AllowRequest(req) {
		s.p.Audit.Warn("rate limited", "client", client, "verb", req.Verb)
		return proto.Fail(proto.CodeRateLimited, "too many requests")
	}
	resp := s.dispatch(ctx, req)
	if proto.Control(req.Verb) {
		s.p.Audit.Warn("request", "client", client, "by", deref(req.By), "verb", req.Verb, "args", args(req),
			"status", resp.Status, "error", resp.Error)
	}
	return resp
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func args(r proto.Request) string {
	var a []string
	if r.For != nil {
		a = append(a, "for="+*r.For)
	}
	if r.Zone != nil {
		a = append(a, fmt.Sprintf("zone=%d", *r.Zone))
	}
	if r.Percent != nil {
		a = append(a, fmt.Sprintf("percent=%d", *r.Percent))
	}
	if r.Mode != nil {
		a = append(a, "mode="+*r.Mode)
	}
	if r.Action != nil {
		a = append(a, "action="+*r.Action)
	}
	if r.DelayS != nil {
		a = append(a, fmt.Sprintf("delay_s=%d", *r.DelayS))
	}
	if r.Run != nil {
		a = append(a, "run="+*r.Run)
	}
	if r.To != nil {
		a = append(a, "to="+*r.To)
	}
	if r.ShutdownDelayS != nil {
		a = append(a, fmt.Sprintf("shutdown_delay_s=%d", *r.ShutdownDelayS))
	}
	if r.WithinS != nil {
		a = append(a, fmt.Sprintf("within_s=%d", *r.WithinS))
	}
	return strings.Join(a, " ")
}

func disabled(what string) proto.Response {
	return proto.Fail(proto.CodeDisabled, what+" is not switched on for the helper (config.yaml)")
}

func (s *Server) who(r proto.Request) string { return "agent (" + deref(r.By) + ")" }

// off is the "disabled" answer when the part that would carry out verb is switched off (nil: it is on).
func (s *Server) off(verb string) *proto.Response {
	var resp proto.Response
	switch {
	case (verb == proto.VerbFanSet || verb == proto.VerbFanMode) && s.p.Fan == nil:
		resp = disabled("fan control")
	case (verb == proto.VerbPower || verb == proto.VerbRunArm || verb == proto.VerbRunGo) && s.p.Power == nil:
		resp = disabled("power control") // a run ends with a shutdown, the self-off or the confirmed one
	case verb == proto.VerbApplyUpdate && s.p.Updater == nil:
		resp = disabled("self-update")
	default:
		return nil
	}
	return &resp
}

func refusal(ref *approval.Refusal) proto.Response {
	return proto.Response{Status: ref.Status, Code: ref.Code, Error: ref.Msg, RetryAfterS: ref.RetryAfterS, Reason: ref.Reason}
}

// The passkey check of a request that changes something. While trust is set, fan_set, fan_mode, power (other
// than cancel) and apply_update run only with an approval this helper verified itself (or inside the fan
// window, which an approved fan change opens once it was applied, or as the one shutdown shortly after boot).
// fan_auto and power cancel are never asked: they only make things safer, and the agent sends them with nobody
// present.
//
// It is asked in two steps, so that a request the helper refuses for a reason of its own (a delay under the
// minimum, a machine that cannot sleep, a duty while the fan mode is not "full") costs neither the approval nor
// the one shutdown after boot:
//
//   - precheck, when the request arrives, before any of its own checks: it uses nothing up. It refuses a
//     request that needs an approval and carries none, and everything while the trust file cannot be used. So
//     a request without approval is answered approval_required whatever else is wrong with it;
//   - admit, when the request has passed its own checks and the next step is the system call or the BMC
//     command: here the approval is verified and its challenge used up, or the shutdown after boot recorded.

// approvable is r as the gate knows it; false: r is not a request the gate is asked about (or there is no gate).
func (s *Server) approvable(r proto.Request) (api.ApprovalRequest, bool) {
	ar, needs := proto.ApprovalRequestOf(r)
	return ar, needs && r.Verb != proto.VerbChallenge && s.p.Approval != nil
}

// precheck is the first step (nil: go on).
func (s *Server) precheck(r proto.Request) *proto.Response {
	ar, ok := s.approvable(r)
	if !ok {
		return nil
	}
	var ref *approval.Refusal
	if r.Run != nil && r.Approval == nil { // it names a confirmed run in the place of an approval
		_, ref = s.p.Approval.RunCovers(ar, *r.Run)
	} else {
		ref = s.p.Approval.Precheck(ar, r.Approval != nil)
	}
	if ref != nil {
		resp := refusal(ref)
		return &resp
	}
	return nil
}

// admit is the second step (a nil answer: carry r out now). The pass is for the fan verbs: it is told when
// the change was applied (approval.Pass.Applied), which is what opens the fan window.
func (s *Server) admit(r proto.Request) (*approval.Pass, *proto.Response) {
	ar, ok := s.approvable(r)
	if !ok {
		return nil, nil
	}
	var pass *approval.Pass
	var ref *approval.Refusal
	if r.Run != nil && r.Approval == nil { // the one update, or the one shutdown, of the confirmed run is used up here
		_, ref = s.p.Approval.AdmitRun(ar, *r.Run)
	} else {
		pass, ref = s.p.Approval.Admit(ar, r.Approval)
	}
	if ref != nil {
		resp := refusal(ref)
		return nil, &resp
	}
	return pass, nil
}

// fanChange carries out a fan verb with the second step asked by the fan controller itself, after its own
// checks. A refusal of the passkey check is answered as the helper answers every such refusal (status, code
// and text of the refusal), not as a fan controller's answer.
func (s *Server) fanChange(r proto.Request, change func(gate agent.Gated) (int, map[string]any)) proto.Response {
	if no := s.precheck(r); no != nil {
		return *no
	}
	var refused *proto.Response
	st, body := change(func() (*approval.Pass, *approval.Refusal) {
		ar, ok := s.approvable(r)
		if !ok {
			return nil, nil
		}
		pass, ref := s.p.Approval.Admit(ar, r.Approval)
		if ref != nil {
			resp := refusal(ref)
			refused = &resp
		}
		return pass, ref
	})
	if refused != nil {
		return *refused
	}
	return proto.WithStatus(st, body)
}

// challenge answers the verb challenge: a challenge bound to the request it names (one of the four that need an
// approval while trust is set, or the first-time set of the trust for one exact proposal).
func (s *Server) challenge(r proto.Request) proto.Response {
	if resp := s.off(*r.For); resp != nil {
		return *resp
	}
	ar, _ := proto.ApprovalRequestOf(r)
	if s.p.Approval == nil {
		if ar.Verb == api.ApproveTrustSet || ar.Verb == api.ApproveRunGo {
			return proto.Fail(proto.CodeDisabled, "this helper has no approval check")
		}
		canon, _ := ar.Canonical()
		return proto.OK(api.ChallengeResponse{Reason: "off", Request: canon})
	}
	c, ref := s.p.Approval.Challenge(ar)
	if ref != nil {
		return refusal(ref)
	}
	return proto.OK(c)
}

// approvalStatus is the approval block of the status answer.
func (s *Server) approvalStatus() *api.ApprovalStatus {
	st := api.ApprovalStatus{State: api.ApprovalOff, EnforcedBy: api.EnforcedByHelper, Proto: api.ApprovalProto}
	if s.p.Approval != nil {
		st = s.p.Approval.Status()
	}
	return &st
}

func (s *Server) dispatch(ctx context.Context, r proto.Request) proto.Response {
	switch r.Verb {
	case proto.VerbPing:
		return proto.OK(map[string]bool{"pong": true})
	case proto.VerbStatus:
		ok, note := s.canSleep()
		return proto.OK(proto.StatusData{Version: s.p.Version, Started: s.started.UTC().Format(time.RFC3339),
			Features: s.Features(), Watchdog: s.p.Fan != nil, SleepOK: ok, SleepNote: note, Power: s.pendingPower(),
			Proto: proto.MaxVersion, Approval: s.approvalStatus()})
	case proto.VerbChallenge:
		return s.challenge(r)
	case proto.VerbTrustInit:
		if s.p.Approval == nil {
			return proto.Fail(proto.CodeDisabled, "this helper has no approval check")
		}
		st, ref := s.p.Approval.Init(*r.Trust)
		if ref != nil {
			return refusal(ref)
		}
		return proto.OK(st)
	case proto.VerbRunArm, proto.VerbRunGo:
		if resp := s.off(r.Verb); resp != nil {
			return *resp
		}
		if s.p.Runs == nil {
			return proto.Fail(proto.CodeDisabled, "this helper has no approval check")
		}
		var ans api.RunAnswer
		var ref *approval.Refusal
		if r.Verb == proto.VerbRunArm {
			ans, ref = s.p.Runs.Arm(r.Approval)
		} else {
			ans, ref = s.p.Runs.Go(proto.RunGoRequestOf(r), r.Approval)
		}
		if ref != nil {
			return refusal(ref)
		}
		return proto.OK(ans)
	case proto.VerbCoreTempRead:
		if s.p.CoreTemp == nil {
			return disabled("Core Temp")
		}
		b, name, err := s.p.CoreTemp()
		switch {
		case errors.Is(err, collect.ErrCoreTempAbsent):
			return proto.Fail(proto.CodeUnavailable, "Core Temp is not running (or its global shared memory is off)")
		case errors.Is(err, collect.ErrCoreTempDenied):
			return proto.Fail(proto.CodeDenied, "Core Temp's shared memory refused the helper")
		case errors.Is(err, collect.ErrCoreTempUntrusted): // the whole reason: it names the object, its owner and the fix
			return proto.Fail(proto.CodeFailed, "Core Temp: "+err.Error())
		case err != nil:
			return proto.Fail(proto.CodeFailed, "Core Temp: "+short(err))
		}
		if len(b) > collect.CoreTempExSize {
			b = b[:collect.CoreTempExSize]
		}
		return proto.OK(proto.CoreTempData{Name: name, Block: b})
	case proto.VerbIPMISensors:
		if s.p.BMC == nil {
			return disabled("IPMI")
		}
		t, f, v := s.p.BMC.Metrics()
		d := proto.SensorsData{Temps: orEmpty(t), Fans: orEmpty(f), Voltages: orEmpty(v)}
		d.Bound()
		return proto.OK(d)
	case proto.VerbFanStatus:
		if s.p.Fan == nil {
			return disabled("fan control")
		}
		return proto.OK(s.p.Fan.Status(ctx))
	case proto.VerbFanSet:
		if s.p.Fan == nil {
			return disabled("fan control")
		}
		return s.fanChange(r, func(gate agent.Gated) (int, map[string]any) {
			return s.p.Fan.SetDutyGated(ctx, *r.Zone, *r.Percent, s.who(r), gate)
		})
	case proto.VerbFanMode:
		if s.p.Fan == nil {
			return disabled("fan control")
		}
		return s.fanChange(r, func(gate agent.Gated) (int, map[string]any) {
			return s.p.Fan.SetModeGated(ctx, *r.Mode, s.who(r), gate)
		})
	case proto.VerbFanAuto:
		if s.p.Fan == nil {
			return disabled("fan control")
		}
		mode, err := s.p.Fan.Auto(ctx, s.who(r), true)
		if err != nil {
			return proto.WithStatus(502, map[string]any{"error": "BMC refused the automatic mode: " + short(err)})
		}
		return proto.OK(proto.AutoData{Mode: mode})
	case proto.VerbPower:
		return s.power(r)
	case proto.VerbApplyUpdate:
		if s.p.Updater == nil {
			return disabled("self-update")
		}
		// nothing of its own to check in between: both steps at once
		if no := s.precheck(r); no != nil {
			return *no
		}
		if _, no := s.admit(r); no != nil {
			return *no
		}
		if err := s.p.Updater(ctx); err != nil {
			return proto.Fail(proto.CodeFailed, "starting the updater: "+short(err))
		}
		return proto.OK(map[string]bool{"started": true})
	}
	return proto.Fail(proto.CodeUnknownVerb, "unknown verb") // DecodeRequest already refuses these
}

func (s *Server) power(r proto.Request) proto.Response {
	if s.p.Power == nil {
		return disabled("power control")
	}
	action := *r.Action
	if action == "cancel" {
		// A cancel also ends the run this PC is in, armed, counting down or confirmed, and nothing arms it again
		// in this boot. First the run, so that its self-off is not scheduled behind this cancel; then the
		// pending action, which may be that self-off.
		var runErr error
		if s.p.Runs != nil {
			_, runErr = s.p.Runs.Cancel("a cancel of the pending power action")
		}
		if err := s.p.Power.Cancel(); err != nil {
			return proto.Fail(proto.CodeFailed, "cancel: "+short(err))
		}
		if runErr != nil { // not "cancelled": a restart of this service would find the run again
			return proto.Fail(proto.CodeFailed, "cancel: the pending action is stopped, but the end of the run could not be written down ("+short(runErr)+"); cancel again")
		}
		return proto.OK(proto.PowerData{Action: "cancel"})
	}
	if no := s.precheck(r); no != nil { // before anything else of a shutdown, reboot or sleep; uses nothing up
		return *no
	}
	if min := s.minDelay(); *r.DelayS < min {
		return proto.Fail(proto.CodeBadRequest, fmt.Sprintf("delay_s must be %d-%d (power_control.min_delay_s in config.yaml, read when the helper starts)", min, proto.MaxDelayS))
	}
	if action == "sleep" {
		if ok, why := s.canSleep(); !ok {
			return proto.WithStatus(409, map[string]any{"error": "this machine cannot sleep: " + why, "code": "sleep_unavailable"})
		}
	}
	// The request's own checks are done; the system is told next. Only now is the approval used up, or the one
	// shutdown after boot recorded.
	if _, no := s.admit(r); no != nil {
		return *no
	}
	delay := time.Duration(*r.DelayS) * time.Second
	var err error
	if by, ok := s.p.Power.(interface {
		ScheduleBy(action string, delay time.Duration, who string) error
	}); ok && r.By != nil { // remembers who asked with the action (agent.RememberedPower); the same message
		err = by.ScheduleBy(action, delay, *r.By)
	} else {
		err = s.p.Power.Schedule(action, delay, agent.PowerMessage(action, deref(r.By), delay))
	}
	if err != nil {
		return proto.Fail(proto.CodeFailed, action+": "+short(err))
	}
	return proto.OK(proto.PowerData{Action: action})
}

// pendingPower is the action the helper scheduled that is still pending (nil: none, or the power part does
// not remember).
func (s *Server) pendingPower() *proto.PowerPending {
	src, ok := s.p.Power.(interface{ PendingAction() (agent.Pending, bool) })
	if !ok {
		return nil
	}
	c, ok := src.PendingAction()
	if !ok {
		return nil
	}
	return &proto.PowerPending{Action: c.Action, At: c.At, DelayS: c.DelayS, By: c.RequestedBy}
}

// minDelay is the shortest delay the helper accepts: config.yaml's, never below the protocol's.
func (s *Server) minDelay() int { return max(s.p.MinDelayS, proto.MinDelayS) }

// canSleep asks the power part at most every 10 minutes.
func (s *Server) canSleep() (bool, string) {
	if s.p.Power == nil {
		return false, "power control is off"
	}
	s.sleepMu.Lock()
	defer s.sleepMu.Unlock()
	if now := s.p.Now(); s.sleepAt.IsZero() || now.Sub(s.sleepAt) > 10*time.Minute {
		s.sleepOK, s.sleepNote = s.p.Power.CanSleep()
		s.sleepAt = now
	}
	return s.sleepOK, s.sleepNote
}

func short(err error) string {
	m := err.Error()
	if len(m) > 160 {
		m = m[:160]
	}
	return m
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// deadliner is a connection with a deadline (the Windows pipe; net.Pipe in the tests).
type deadliner interface{ SetDeadline(time.Time) error }

// Connection timeouts: how long a connection may sit idle between requests, and how long reading the rest of
// a request or writing an answer may take.
var (
	IdleTimeout = 2 * time.Minute
	IOTimeout   = 10 * time.Second
)

// ServeConn answers requests on one connection until the peer closes it, it idles out, or a frame is broken
// (an oversized frame is answered with too_large, then the connection is closed: the stream cannot be resynced).
func (s *Server) ServeConn(ctx context.Context, rw io.ReadWriter, client string) {
	d, _ := rw.(deadliner)
	for ctx.Err() == nil {
		if d != nil {
			_ = d.SetDeadline(time.Now().Add(IdleTimeout))
		}
		frame, version, err := proto.ReadRequest(rw)
		if errors.Is(err, proto.ErrFrameTooLarge) {
			s.p.Audit.Warn("refused request", "client", client, "reason", "too large")
			s.reply(rw, d, proto.Fail(proto.CodeTooLarge, "request too large"))
			return
		}
		if err != nil {
			return
		}
		if !s.reply(rw, d, s.handle(ctx, client, frame, version)) {
			return
		}
	}
}

func (s *Server) reply(w io.Writer, d deadliner, r proto.Response) bool {
	b, err := jsonMarshal(r)
	if err != nil || len(b) > proto.MaxResponse {
		b, _ = jsonMarshal(proto.Fail(proto.CodeFailed, "answer too large"))
	}
	if d != nil {
		_ = d.SetDeadline(time.Now().Add(IOTimeout))
	}
	return proto.WriteFrame(w, b, proto.MaxResponse) == nil
}

var jsonMarshal = json.Marshal
