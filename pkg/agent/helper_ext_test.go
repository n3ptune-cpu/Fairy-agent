package agent_test

// The agent with the Windows helper, end to end on Linux: the real helper server (pkg/helper) behind an
// in-memory pipe, a fake service manager, a fake BMC; the agent's HTTP API in front.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper"
)

const (
	readTok = "read-token-aaaaaaaaaaaaaaaaaaaaaaaa"
	ctlTok  = "control-token-bbbbbbbbbbbbbbbbbbbbbb"
)

// fakeSCM is the helper's service as the service manager sees it; stopping it runs the helper's Shutdown,
// like the real service's stop handler.
type fakeSCM struct {
	mu    sync.Mutex
	state string
	srv   *helper.Server
	stops int
}

func (f *fakeSCM) State() (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state, nil
}

func (f *fakeSCM) Stop(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state == api.HelperNotInstalled {
		return api.ErrHelperNotInstalled
	}
	if f.state == api.HelperRunning {
		f.srv.Shutdown(ctx)
		f.stops++
	}
	f.state = api.HelperStopped
	return nil
}

func (f *fakeSCM) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = api.HelperRunning
	return nil
}

type hrig struct {
	srv    *httptest.Server
	bmc    *fakebmc.BMC
	scm    *fakeSCM
	client *agent.HelperClient
	power  *agenttest.PowerExec
}

func newHelperRig(t *testing.T, state string) *hrig {
	t.Helper()
	cfg, err := agent.Parse([]byte("sensors: {coretemp: false}\nipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\n"),
		filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	h := &hrig{bmc: fakebmc.X11SCAF(), power: &agenttest.PowerExec{}}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b := agent.NewBMC(h.bmc, 20*time.Millisecond)
	go b.Run(ctx)
	waitFirstReading(t, b)
	fan := agent.NewFan(h.bmc, b, cfg.FanControl, nil)
	srv := helper.New(helper.Parts{Version: "0.5.0", BMC: b, Fan: fan, Power: h.power,
		Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	h.scm = &fakeSCM{state: state, srv: srv}
	dial := func(context.Context) (io.ReadWriteCloser, error) {
		if st, _ := h.scm.State(); st != api.HelperRunning {
			return nil, errors.New("pipe not found")
		}
		a, c := net.Pipe()
		go func() { srv.ServeConn(ctx, a, "test"); a.Close() }()
		return c, nil
	}
	h.client = agent.NewHelperClient(dial, h.scm, true)
	h.client.Every = 10 * time.Millisecond
	sensors := h.client.Sensors(20 * time.Millisecond)
	go sensors.Run(ctx)
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Helper: h.client, BMC: sensors,
		Fan: h.client.Fan(cfg.FanControl), Power: agent.NewPower(h.client.Power(), cfg.PowerControl.MinDelayS),
		HelperSources: []string{api.FeatureIPMI, api.FeatureFans, api.FeaturePower}}
	a := agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d)
	h.srv = httptest.NewServer(a.Handler())
	t.Cleanup(h.srv.Close)
	return h
}

func do(t *testing.T, base, method, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader = http.NoBody
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, base+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// metrics waits (briefly) until /metrics shows the helper in state want.
func (h *hrig) metrics(t *testing.T, want string) map[string]any {
	t.Helper()
	var m map[string]any
	for i := 0; i < 200; i++ {
		time.Sleep(10 * time.Millisecond) // past the 250 ms metrics cache after a few rounds
		_, m = do(t, h.srv.URL, "GET", "/metrics", readTok, nil)
		if hs, ok := m["helper"].(map[string]any); ok && hs["state"] == want {
			return m
		}
	}
	t.Fatalf("helper never %s: %v", want, m["helper"])
	return nil
}

func (h *hrig) mode(t *testing.T) string {
	m, err := ipmi.GetFanMode(context.Background(), h.bmc)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestHelperRunningInMetrics(t *testing.T) {
	h := newHelperRig(t, api.HelperRunning)
	m := h.metrics(t, api.HelperRunning)
	hs := m["helper"].(map[string]any)
	if hs["needed"] != true || hs["version"] != "0.5.0" || hs["watchdog"] != true || hs["since"] == "" || hs["error"] != nil {
		t.Fatal(hs)
	}
	if f, _ := json.Marshal(hs["features"]); string(f) != `["ipmi","fans","power"]` {
		t.Fatal(string(f))
	}
	if _, ok := m["unavailable"]; ok {
		t.Fatal("unavailable while running")
	}
	// the BMC's sensors come through the helper
	for i := 0; i < 200; i++ {
		_, m = do(t, h.srv.URL, "GET", "/metrics", readTok, nil)
		if len(m["temps"].([]any)) == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if temps := m["temps"].([]any); len(temps) != 3 || temps[1].(map[string]any)["label"] != "CPU Temp" {
		t.Fatal(temps)
	}
	if pc := m["power_control"].(map[string]any); pc["available"] != nil {
		t.Fatal(pc)
	}
}

func TestFanControlThroughHelper(t *testing.T) {
	h := newHelperRig(t, api.HelperRunning)
	if st, b := do(t, h.srv.URL, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "full"}); st != 200 || b["mode"] != "full" {
		t.Fatal(st, b)
	}
	if st, b := do(t, h.srv.URL, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": 29}); st != 400 {
		t.Fatal("29 % accepted", st, b)
	}
	if st, b := do(t, h.srv.URL, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": 45}); st != 200 || b["percent"] != 45.0 {
		t.Fatal(st, b)
	}
	if d, _ := ipmi.GetDuty(context.Background(), h.bmc, 0); d != 45 {
		t.Fatal(d)
	}
	st, b := do(t, h.srv.URL, "GET", "/fan/status", readTok, nil)
	if st != 200 || b["mode"] != "full" || b["available"] != true || b["error"] != nil {
		t.Fatal(st, b)
	}
	if st, b := do(t, h.srv.URL, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "pue"}); st != 400 {
		t.Fatal(st, b)
	}
}

func TestHelperStopAndStart(t *testing.T) {
	h := newHelperRig(t, api.HelperRunning)
	h.metrics(t, api.HelperRunning)
	do(t, h.srv.URL, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "full"})
	do(t, h.srv.URL, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": 40})
	if st, _ := do(t, h.srv.URL, "POST", api.PathHelperStop, readTok, map[string]any{}); st != 401 {
		t.Fatal("stopped with the read token", st)
	}
	st, b := do(t, h.srv.URL, "POST", api.PathHelperStop, ctlTok, map[string]any{})
	if st != 200 || b["state"] != api.HelperStopped {
		t.Fatal(st, b)
	}
	if m := h.mode(t); m != "optimal" {
		t.Fatal("fans not handed back to the BMC on stop:", m)
	}
	m := h.metrics(t, api.HelperStopped)
	hs := m["helper"].(map[string]any)
	if hs["version"] != nil || hs["watchdog"] != nil || hs["since"] == "" || hs["needed"] != true {
		t.Fatal(hs)
	}
	un, _ := json.Marshal(m["unavailable"])
	if string(un) != `[{"reason":"helper_stopped","source":"ipmi"},{"reason":"helper_stopped","source":"fans"},{"reason":"helper_stopped","source":"power"}]` {
		t.Fatal(string(un))
	}
	if pc := m["power_control"].(map[string]any); pc["available"] != false || pc["reason"] != api.ReasonHelperStopped {
		t.Fatal(pc)
	}
	// readings say "helper stopped", not errors
	st, b = do(t, h.srv.URL, "GET", "/fan/status", readTok, nil)
	if st != 200 || b["available"] != false || b["reason"] != api.ReasonHelperStopped || b["error"] != nil {
		t.Fatal(st, b)
	}
	st, b = do(t, h.srv.URL, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": 50})
	if st != 503 || b["code"] != api.ReasonHelperStopped {
		t.Fatal(st, b)
	}
	st, b = do(t, h.srv.URL, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 60, "requested_by": "x"})
	if st != 503 || b["code"] != api.ReasonHelperStopped || len(h.power.Scheduled) != 0 {
		t.Fatal(st, b)
	}
	if _, _, err := h.client.CoreTempRead(); !errors.Is(err, api.ErrHelperStopped) {
		t.Fatal(err)
	}
	// start again
	st, b = do(t, h.srv.URL, "POST", api.PathHelperStart, ctlTok, nil)
	if st != 200 || b["state"] != api.HelperRunning {
		t.Fatal(st, b)
	}
	m = h.metrics(t, api.HelperRunning)
	if _, ok := m["unavailable"]; ok {
		t.Fatal(m["unavailable"])
	}
	st, b = do(t, h.srv.URL, "POST", "/power", ctlTok, map[string]any{"action": "reboot", "delay_s": 30, "requested_by": "x"})
	if st != 200 || len(h.power.Scheduled) != 1 || h.power.Scheduled[0] != "reboot@30s" {
		t.Fatal(st, b, h.power.Scheduled)
	}
}

func TestHelperNotInstalled(t *testing.T) {
	h := newHelperRig(t, api.HelperNotInstalled)
	m := h.metrics(t, api.HelperNotInstalled)
	if hs := m["helper"].(map[string]any); hs["needed"] != true {
		t.Fatal(hs)
	}
	for _, p := range []string{api.PathHelperStart, api.PathHelperStop} {
		if st, b := do(t, h.srv.URL, "POST", p, ctlTok, map[string]any{}); st != 409 || b["error"] != "not_installed" {
			t.Fatal(p, st, b)
		}
	}
}

// Linux (no helper at all): no "helper" block, and the endpoints say not_installed.
func TestNoHelperOnLinux(t *testing.T) {
	cfg, err := agent.Parse([]byte(""), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	a := agent.New(cfg, agent.Tokens{Read: readTok}, agent.Deps{Collector: agenttest.NewCollector(), Version: "test"})
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	_, m := do(t, srv.URL, "GET", "/metrics", readTok, nil)
	if _, ok := m["helper"]; ok {
		t.Fatal("helper block without a helper")
	}
	if _, ok := m["unavailable"]; ok {
		t.Fatal("unavailable without a helper")
	}
	if st, b := do(t, srv.URL, "POST", api.PathHelperStop, "", map[string]any{}); st != 409 || b["error"] != "not_installed" {
		t.Fatal(st, b)
	}
}

func TestHelperBadBody(t *testing.T) {
	h := newHelperRig(t, api.HelperRunning)
	req, _ := http.NewRequest("POST", h.srv.URL+api.PathHelperStop, bytes.NewReader([]byte("not json")))
	req.Header.Set("Authorization", "Bearer "+ctlTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal(resp.StatusCode)
	}
	if st, _ := h.scm.State(); st != api.HelperRunning {
		t.Fatal("stopped on a bad request")
	}
}

func TestCoreTempThroughHelper(t *testing.T) {
	block := make([]byte, collect.CoreTempExSize)
	srv := helper.New(helper.Parts{CoreTemp: func() ([]byte, string, error) { return block, "Global\\CoreTempMappingObjectEx", nil },
		Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	scm := &fakeSCM{state: api.HelperRunning, srv: srv}
	c := agent.NewHelperClient(func(ctx context.Context) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() { srv.ServeConn(ctx, a, "t"); a.Close() }()
		return b, nil
	}, scm, true)
	b, name, err := c.CoreTempRead()
	if err != nil || len(b) != collect.CoreTempExSize || name != "Global\\CoreTempMappingObjectEx" {
		t.Fatal(len(b), name, err)
	}
	// Core Temp not running: the collector's "absent"
	srv2 := helper.New(helper.Parts{CoreTemp: func() ([]byte, string, error) { return nil, "", collect.ErrCoreTempAbsent },
		Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	c2 := agent.NewHelperClient(func(ctx context.Context) (io.ReadWriteCloser, error) {
		a, b := net.Pipe()
		go func() { srv2.ServeConn(ctx, a, "t"); a.Close() }()
		return b, nil
	}, &fakeSCM{state: api.HelperRunning, srv: srv2}, true)
	if _, _, err := c2.CoreTempRead(); !errors.Is(err, collect.ErrCoreTempAbsent) {
		t.Fatal(err)
	}
}

func TestNeedsHelper(t *testing.T) {
	for y, want := range map[string]bool{
		"":                               false,
		"wol: {enabled: true}":           false,
		"self_update: {enabled: true}":   false,
		"power_control: {enabled: true}": true,
		"ipmi: {enabled: true, transport: ipmitool}": false,
	} {
		cfg, err := agent.Parse([]byte(y), filepath.Join(t.TempDir(), "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if agent.NeedsHelper(cfg) != want {
			t.Error(y)
		}
	}
	// on Windows also sensors.coretemp and ipmi with the default wmi transport (both refused by Linux's config check)
	cfg, _ := agent.Parse([]byte(""), filepath.Join(t.TempDir(), "config.yaml"))
	cfg.Sensors.CoreTemp = true
	if !agent.NeedsHelper(cfg) {
		t.Error("coretemp")
	}
	cfg.Sensors.CoreTemp, cfg.IPMI.Enabled, cfg.IPMI.Transport = false, true, "wmi"
	if !agent.NeedsHelper(cfg) {
		t.Error("ipmi wmi")
	}
}

// The panel's contract test drives the agent with agenttest.Helper.
func TestFakeHelperContract(t *testing.T) {
	cfg, _ := agent.Parse([]byte(""), filepath.Join(t.TempDir(), "config.yaml"))
	fh := agenttest.NewHelper()
	a := agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, agent.Deps{Collector: agenttest.NewCollector(), Version: "test",
		Helper: fh, HelperSources: []string{api.FeatureCoreTemp}})
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	if st, b := do(t, srv.URL, "POST", api.PathHelperStop, ctlTok, map[string]any{}); st != 200 || b["state"] != api.HelperStopped || fh.Stops != 1 {
		t.Fatal(st, b)
	}
	_, m := do(t, srv.URL, "GET", "/metrics", readTok, nil)
	if m["helper"].(map[string]any)["state"] != api.HelperStopped || m["unavailable"] == nil {
		t.Fatal(m["helper"], m["unavailable"])
	}
	fh.NotInstalled = true
	if st, b := do(t, srv.URL, "POST", api.PathHelperStart, ctlTok, map[string]any{}); st != 409 || b["error"] != "not_installed" {
		t.Fatal(st, b)
	}
}
