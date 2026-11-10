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
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
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
	Audit     *slog.Logger // the audit log (helper.log); nil = slog.Default()
	Now       func() time.Time
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
	return &Server{p: p, limit: l, started: p.Now()}
}

// FromConfig builds the parts config.yaml switches on: Core Temp (sensors.coretemp), IPMI through Windows
// (ipmi.enabled with transport wmi) and fan control, power control and self-update. The returned close function
// stops the IPMI transport.
func FromConfig(cfg *agent.Config, version string, audit *slog.Logger) (Parts, func(), error) {
	p := Parts{Version: version, Audit: audit}
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
		p.Power = agent.SystemPower()
		p.MinDelayS = cfg.PowerControl.MinDelayS
	}
	if cfg.SelfUpdate.Enabled {
		p.Updater = agent.StartUpdaterService
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
}

// Shutdown hands the fans back to the BMC's automatic mode if a fixed duty may be in effect (the watchdog
// stops with the helper, so no fixed duty is left without it). Call it when the service stops or Windows
// shuts down.
func (s *Server) Shutdown(ctx context.Context) {
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

// Handle answers one request frame from client (a description for the audit log).
func (s *Server) Handle(ctx context.Context, client string, frame []byte) proto.Response {
	req, err := proto.DecodeRequest(frame)
	if err != nil {
		s.p.Audit.Warn("refused request", "client", client, "reason", err.Error())
		return proto.FromError(err)
	}
	if !s.limit.Allow(req.Verb) {
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
	return strings.Join(a, " ")
}

func disabled(what string) proto.Response {
	return proto.Fail(proto.CodeDisabled, what+" is not switched on for the helper (config.yaml)")
}

func (s *Server) who(r proto.Request) string { return "agent (" + deref(r.By) + ")" }

func (s *Server) dispatch(ctx context.Context, r proto.Request) proto.Response {
	switch r.Verb {
	case proto.VerbPing:
		return proto.OK(map[string]bool{"pong": true})
	case proto.VerbStatus:
		ok, note := s.canSleep()
		return proto.OK(proto.StatusData{Version: s.p.Version, Started: s.started.UTC().Format(time.RFC3339),
			Features: s.Features(), Watchdog: s.p.Fan != nil, SleepOK: ok, SleepNote: note})
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
		st, body := s.p.Fan.SetDuty(ctx, *r.Zone, *r.Percent, s.who(r))
		return proto.WithStatus(st, body)
	case proto.VerbFanMode:
		if s.p.Fan == nil {
			return disabled("fan control")
		}
		st, body := s.p.Fan.SetMode(ctx, *r.Mode, s.who(r))
		return proto.WithStatus(st, body)
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
		if err := s.p.Power.Cancel(); err != nil {
			return proto.Fail(proto.CodeFailed, "cancel: "+short(err))
		}
		return proto.OK(proto.PowerData{Action: "cancel"})
	}
	if min := s.minDelay(); *r.DelayS < min {
		return proto.Fail(proto.CodeBadRequest, fmt.Sprintf("delay_s must be %d-%d (power_control.min_delay_s in config.yaml, read when the helper starts)", min, proto.MaxDelayS))
	}
	if action == "sleep" {
		if ok, why := s.canSleep(); !ok {
			return proto.WithStatus(409, map[string]any{"error": "this machine cannot sleep: " + why, "code": "sleep_unavailable"})
		}
	}
	msg := fmt.Sprintf("Fairy: %s requested by %s in %d seconds.", action, deref(r.By), *r.DelayS)
	if err := s.p.Power.Schedule(action, time.Duration(*r.DelayS)*time.Second, msg); err != nil {
		return proto.Fail(proto.CodeFailed, action+": "+short(err))
	}
	return proto.OK(proto.PowerData{Action: action})
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
		frame, err := proto.ReadFrame(rw, proto.MaxRequest)
		if errors.Is(err, proto.ErrFrameTooLarge) {
			s.p.Audit.Warn("refused request", "client", client, "reason", "too large")
			s.reply(rw, d, proto.Fail(proto.CodeTooLarge, "request too large"))
			return
		}
		if err != nil {
			return
		}
		if !s.reply(rw, d, s.Handle(ctx, client, frame)) {
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
