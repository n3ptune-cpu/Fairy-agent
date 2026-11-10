package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
)

const (
	readTok = "read-token-aaaaaaaaaaaaaaaaaaaaaaaa"
	ctlTok  = "control-token-bbbbbbbbbbbbbbbbbbbbbb"
)

func mustParse(t *testing.T, y string) *Config {
	t.Helper()
	c, err := Parse([]byte(y), filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type rig struct {
	a     *Agent
	srv   *httptest.Server
	bmc   *fakebmc.BMC
	power *agenttest.PowerExec
	fan   *Fan
	sent  []string
}

func newRig(t *testing.T, y string) *rig {
	t.Helper()
	cfg := mustParse(t, y)
	r := &rig{bmc: fakebmc.X11SCAF(), power: &agenttest.PowerExec{}}
	d := Deps{Collector: agenttest.NewCollector(), GPU: agenttest.GPU{}, Version: "test"}
	tok := Tokens{Read: readTok}
	if cfg.ControlEnabled() {
		tok.Control = ctlTok
	}
	var bmc *BMC
	if cfg.IPMI.Enabled {
		bmc = NewBMC(r.bmc, 10*time.Second)
		if err := bmc.refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		d.BMC = bmc
	}
	var a *Agent
	if cfg.FanControl.Enabled {
		r.fan = NewFan(r.bmc, bmc, cfg.FanControl, func() []collect.Temp { return a.LocalTemps() })
		d.Fan = r.fan
	}
	if cfg.PowerControl.Enabled {
		d.Power = NewPower(r.power, cfg.PowerControl.MinDelayS)
	}
	if cfg.WOL.Enabled {
		d.WOL = NewWOL(cfg.WOL.AllowedMACs)
		d.WOL.Send = func(addr string, pkt []byte) error { r.sent = append(r.sent, addr); return nil }
	}
	if cfg.BMCRelay.Enabled {
		d.BMCRelay = NewBMCRelay(cfg.BMCRelay, "")
		d.BMCRelay.FindIpmitool = func() (string, error) { return os.Args[0], nil } // this test binary as ipmitool
	}
	a = New(cfg, tok, d)
	r.a = a
	r.srv = httptest.NewServer(a.Handler())
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) do(t *testing.T, method, path, tok string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, r.srv.URL+path, rd)
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

func TestConfigValidation(t *testing.T) {
	c := mustParse(t, "")
	if c.Listen != "" || !c.ProcessesEnabled() || c.ControlEnabled() || c.FanControl.MinDuty != 30 ||
		c.FanControl.MaxTempC != 80 || c.ControlRatePerMin != 12 || c.TokenFile != filepath.Join(c.Dir(), "token") {
		t.Fatalf("%+v", c)
	}
	bad := map[string]string{
		"listen: 0.0.0.0:9101":                          "every network",
		"listen: \":9101\"":                             "every network",
		"listen: myhost:9101":                           "IP address",
		"listen: 100.64.0.1":                            "host:port",
		"fan_control: {enabled: true}":                  "needs ipmi",
		"fan_control: {min_duty: 20}":                   "min_duty",
		"fan_control: {max_temp_c: 99}":                 "max_temp_c",
		"power_control: {min_delay_s: 5}":               "min_delay_s",
		"wol: {allowed_macs: [nope]}":                   "MAC",
		"ipmi: {host: 192.168.1.5}":                     "password_env",
		"bogus_key: 1":                                  "bogus_key",
		"processes: {never_open: ['C:\\games\\x.exe']}": "program names",
		"ipmi: {transport: snmp}":                       "transport",
		"gpu: {interval_s: 0.5}":                        "interval_s",
		"control_rate_per_min: 1000":                    "control_rate_per_min",
	}
	for y, want := range bad {
		_, err := Parse([]byte(y), "config.yaml")
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want %q", y, err, want)
		}
	}
	if _, err := Parse([]byte("listen: 0.0.0.0:9101\nallow_all_interfaces: true\n"), "c.yaml"); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if _, err := Parse([]byte("ipmi: {transport: wmi}"), "c.yaml"); err == nil {
			t.Fatal("wmi is Windows-only")
		}
		if _, err := Parse([]byte("sensors: {coretemp: true}"), "c.yaml"); err == nil {
			t.Fatal("coretemp is Windows-only")
		}
	}
	if c, err := Parse([]byte("sensors: {acpi_thermal: true}"), "c.yaml"); err != nil || c.Sensors.CoreTemp {
		t.Fatal("coretemp must default to off", err)
	}
}

// Core Temp's readings (sensor "coretemp", labels "Core N") count as CPU temperatures for the fan watchdog,
// ahead of an ACPI thermal zone.
func TestMaxCPUTempCoreTemp(t *testing.T) {
	zone := "ACPI thermal zone TZ00"
	local := []collect.Temp{{Sensor: "coretemp", Label: collect.P("Core 0"), Current: 61},
		{Sensor: "coretemp", Label: collect.P("Core 1"), Current: 72.5}, {Sensor: "acpi", Label: &zone, Current: 90}}
	v, name, ok := MaxCPUTemp(nil, local)
	if !ok || v != 72.5 || name != "coretemp Core 1" {
		t.Fatal(v, name, ok)
	}
}

func TestTokens(t *testing.T) {
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", "")
	c := mustParse(t, "power_control: {enabled: true}")
	if _, err := c.LoadTokens(); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatal(err)
	}
	_ = os.WriteFile(c.TokenFile, []byte(readTok+"\n"), 0o600)
	if _, err := c.LoadTokens(); err == nil || !strings.Contains(err.Error(), "control token") {
		t.Fatal("control token required when a control feature is on", err)
	}
	_ = os.WriteFile(c.ControlTokenFile, []byte(readTok), 0o600)
	if _, err := c.LoadTokens(); err == nil || !strings.Contains(err.Error(), "differ") {
		t.Fatal(err)
	}
	_ = os.WriteFile(c.ControlTokenFile, []byte(ctlTok), 0o600)
	tk, err := c.LoadTokens()
	if err != nil || tk.Read != readTok || tk.Control != ctlTok {
		t.Fatal(tk, err)
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "short")
	if _, err := c.LoadTokens(); err == nil || !strings.Contains(err.Error(), "24") {
		t.Fatal(err)
	}
	t.Setenv("FAIRY_AGENT_TOKEN", "")
	if runtime.GOOS != "windows" {
		_ = os.Chmod(c.TokenFile, 0o644)
		if _, err := c.LoadTokens(); err == nil || !strings.Contains(err.Error(), "readable by every user") {
			t.Fatal(err)
		}
	}
	ro := mustParse(t, "")
	_ = os.WriteFile(ro.TokenFile, []byte(readTok), 0o600)
	if tk, err := ro.LoadTokens(); err != nil || tk.Control != "" {
		t.Fatal("read-only agent needs no control token", err)
	}
}

func TestEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.env")
	_ = os.WriteFile(p, []byte("# plugs\nTUYA_KEY_DESK='abc=def'\nexport SHELLY_PW=pw\n\n"), 0o600)
	t.Setenv("SHELLY_PW", "already-set")
	names, err := LoadEnvFile(p)
	if err != nil || strings.Join(names, ",") != "TUYA_KEY_DESK,SHELLY_PW" || os.Getenv("TUYA_KEY_DESK") != "abc=def" ||
		os.Getenv("SHELLY_PW") != "already-set" {
		t.Fatal(names, err)
	}
	t.Cleanup(func() { os.Unsetenv("TUYA_KEY_DESK") })
	_ = os.WriteFile(p, []byte("not a pair\n"), 0o600)
	if _, err := LoadEnvFile(p); err == nil {
		t.Fatal("bad line")
	}
}

func TestAuth(t *testing.T) {
	r := newRig(t, "power_control: {enabled: true}")
	if st, _ := r.do(t, "GET", "/metrics", "", nil); st != 401 {
		t.Fatal("no token", st)
	}
	if st, _ := r.do(t, "GET", "/metrics", readTok+"x", nil); st != 401 {
		t.Fatal("wrong token", st)
	}
	if st, _ := r.do(t, "GET", "/metrics", ctlTok, nil); st != 401 {
		t.Fatal("control token must not read", st)
	}
	if st, _ := r.do(t, "GET", "/metrics", readTok, nil); st != 200 {
		t.Fatal(st)
	}
	if st, _ := r.do(t, "POST", "/power", readTok, map[string]any{"action": "cancel"}); st != 401 {
		t.Fatal("read token must not control", st)
	}
	if st, _ := r.do(t, "POST", "/metrics", readTok, nil); st != 405 {
		t.Fatal(st)
	}
	if st, _ := r.do(t, "GET", "/../etc/passwd", readTok, nil); st != 404 {
		t.Fatal(st)
	}
	// a disabled feature answers 404
	if st, b := r.do(t, "POST", "/fan/mode", readTok, map[string]any{"mode": "full"}); st != 404 || b["code"] != "fan_control_disabled" {
		t.Fatal(st, b)
	}
	if st, _ := r.do(t, "POST", "/wol", "", map[string]any{}); st != 404 {
		t.Fatal("a disabled feature does nothing, whoever asks", st)
	}
	if st, _ := r.do(t, "POST", "/power", "", map[string]any{"action": "cancel"}); st != 401 {
		t.Fatal("an enabled one needs the control token", st)
	}
	if st, b := r.do(t, "GET", "/fan/status", readTok, nil); st != 404 || b["code"] != "fan_control_disabled" {
		t.Fatal(st, b)
	}
	// lowercase scheme is fine, but the token must match exactly
	req, _ := http.NewRequest("GET", r.srv.URL+"/metrics", nil)
	req.Header.Set("Authorization", "bearer "+readTok)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
}

func TestFailedAuthIsRateLimited(t *testing.T) {
	r := newRig(t, "")
	for i := 0; i < 20; i++ {
		r.do(t, "GET", "/metrics", "nope", nil)
	}
	if st, _ := r.do(t, "GET", "/metrics", readTok, nil); st != 429 {
		t.Fatal("after 20 bad tokens a minute the client is blocked", st)
	}
}

func TestMetricsShape(t *testing.T) {
	r := newRig(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\npower_control: {enabled: true}\n")
	st, m := r.do(t, "GET", "/metrics", readTok, nil)
	if st != 200 {
		t.Fatal(st)
	}
	for _, k := range []string{"agent_version", "timestamp", "hostname", "uptime_s", "platform", "cpu", "memory", "disks", "net",
		"load_avg", "temps", "fans", "voltages", "gpus", "power", "hardware", "features", "power_control", "power_sources", "ups"} {
		if _, ok := m[k]; !ok {
			t.Error("missing", k)
		}
	}
	if m["load_avg"] != nil {
		t.Fatal("no load average = null")
	}
	f := m["features"].(map[string]any)
	if f["fan_control"] != true || f["power_control"] != true || f["wol_relay"] != false || f["processes"] != true {
		t.Fatal(f)
	}
	temps := m["temps"].([]any)
	if len(temps) != 3 || temps[1].(map[string]any)["sensor"] != "IPMI" || temps[1].(map[string]any)["label"] != "CPU Temp" {
		t.Fatal(temps)
	}
	if v := m["voltages"].([]any); len(v) != 1 || v[0].(map[string]any)["name"] != "IPMI 12V" {
		t.Fatal(v)
	}
	if p := m["power"].(map[string]any); p["gpu_w"] != 87.5 || p["cpu_package_w"] != nil {
		t.Fatal(p)
	}
	// hide_host_details
	r2 := newRig(t, "hide_host_details: true\nipmi: {enabled: true, sensors: false}")
	_, m2 := r2.do(t, "GET", "/metrics", readTok, nil)
	if m2["hostname"] != nil || m2["hardware"] != nil || m2["platform"].(map[string]any)["pretty"] != "Windows" {
		t.Fatal(m2)
	}
	if len(m2["temps"].([]any)) != 1 {
		t.Fatal("ipmi.sensors false: no BMC sensors in /metrics")
	}
}

// GET /processes with values that are not numbers in some rows (a collector's division by zero, a counter that
// went backwards): it used to answer 500 for the whole list. The rows stay, the value is null, and such a row
// sorts last like any other unknown value.
func TestProcessesSurviveValuesThatAreNotNumbers(t *testing.T) {
	r := newRig(t, "")
	c := r.a.d.Collector.(*agenttest.Collector)
	c.Procs = append(c.Procs,
		collect.Process{PID: 8000, Name: collect.P("nan-cpu"), CPUPercent: collect.P(math.NaN()), RSS: collect.P(int64(1 << 20)),
			CreateTime: collect.P(1.7e9)},
		collect.Process{PID: 8001, Name: collect.P("inf-cpu"), CPUPercent: collect.P(math.Inf(1)), CreateTime: collect.P(math.Inf(-1))},
		collect.Process{PID: 8002, Name: collect.P("nan-start"), CPUPercent: collect.P(1.5), CreateTime: collect.P(math.NaN())})
	for _, by := range []string{"cpu", "mem", "gpu"} {
		st, b := r.do(t, "GET", "/processes?limit=200&sort="+by, readTok, nil)
		if st != 200 {
			t.Fatalf("sort=%s: %d %v", by, st, b)
		}
		ps := b["processes"].([]any)
		if len(ps) != 7 || b["total_processes"] != 212.0 {
			t.Fatalf("sort=%s: %d rows, total %v", by, len(ps), b["total_processes"])
		}
		rows := map[string]map[string]any{}
		var order []string
		for _, p := range ps {
			m := p.(map[string]any)
			rows[m["name"].(string)] = m
			order = append(order, m["name"].(string))
		}
		if v, has := rows["nan-cpu"]["cpu_percent"]; !has || v != nil || rows["nan-cpu"]["create_time"] != 1.7e9 || rows["nan-cpu"]["rss"] != float64(1<<20) {
			t.Fatalf("sort=%s: nan-cpu %v", by, rows["nan-cpu"])
		}
		if rows["inf-cpu"]["cpu_percent"] != nil || rows["inf-cpu"]["create_time"] != nil || rows["inf-cpu"]["pid"] != 8001.0 {
			t.Fatalf("sort=%s: inf-cpu %v", by, rows["inf-cpu"])
		}
		if rows["nan-start"]["cpu_percent"] != 1.5 || rows["nan-start"]["create_time"] != nil {
			t.Fatalf("sort=%s: nan-start %v", by, rows["nan-start"])
		}
		if rows["Ollama.exe"]["cpu_percent"] != 30.0 || rows["obs64.exe"]["cmdline"] == nil {
			t.Fatalf("sort=%s: the good rows changed: %v", by, rows["Ollama.exe"])
		}
		if by == "cpu" {
			// known values first, highest first; the three without a usable CPU value last, by pid
			want := "Ollama.exe,obs64.exe,backup.exe,nan-start,VALORANT-Win64-Shipping.exe,nan-cpu,inf-cpu"
			if got := strings.Join(order, ","); got != want {
				t.Fatalf("order %s", got)
			}
		}
	}
	// an infinite value does not take the first place when the list is cut
	_, b := r.do(t, "GET", "/processes?limit=1&sort=cpu", readTok, nil)
	if ps := b["processes"].([]any); len(ps) != 1 || ps[0].(map[string]any)["name"] != "Ollama.exe" {
		t.Fatal(ps)
	}
	if n := cleanProcessNumbers([]collect.Process{{CPUPercent: collect.P(1.0), MemPercent: collect.P(0.0)}, {}}); n != 0 {
		t.Fatal("clean values were counted:", n)
	}
}

func TestProcesses(t *testing.T) {
	r := newRig(t, "")
	st, b := r.do(t, "GET", "/processes?limit=3&sort=cpu", readTok, nil)
	if st != 200 || b["total_processes"] != 212.0 || b["sort"] != "cpu" {
		t.Fatal(st, b)
	}
	ps := b["processes"].([]any)
	if len(ps) != 3 || ps[0].(map[string]any)["name"] != "Ollama.exe" || ps[2].(map[string]any)["name"] != "backup.exe" {
		t.Fatal(ps)
	}
	if c := ps[2].(map[string]any)["cmdline"]; c != "backup.exe --password=*** --target s3" {
		t.Fatal("redaction", c)
	}
	if g := ps[0].(map[string]any)["gpu_mem"]; g != float64(5<<30) {
		t.Fatal("gpu mem", g)
	}
	_, b = r.do(t, "GET", "/processes?sort=mem", readTok, nil)
	ps = b["processes"].([]any)
	if len(ps) != 4 || ps[0].(map[string]any)["name"] != "Ollama.exe" || ps[3].(map[string]any)["name"] != "VALORANT-Win64-Shipping.exe" {
		t.Fatal("unknown values sort last", ps)
	}
	for _, q := range []string{"limit=0", "limit=201", "limit=x", "sort=pid"} {
		if st, _ := r.do(t, "GET", "/processes?"+q, readTok, nil); st != 400 {
			t.Fatal(q, st)
		}
	}
	off := newRig(t, "processes: {enabled: false}")
	if st, b := off.do(t, "GET", "/processes", readTok, nil); st != 403 || b["code"] != "processes_disabled" {
		t.Fatal(st, b)
	}
	_, m := off.do(t, "GET", "/metrics", readTok, nil)
	if f := m["features"].(map[string]any); f["processes"] != false || f["cmdline"] != false {
		t.Fatal(f)
	}
	nocmd := newRig(t, "processes: {cmdline: false}")
	_, b = nocmd.do(t, "GET", "/processes", readTok, nil)
	for _, p := range b["processes"].([]any) {
		if p.(map[string]any)["cmdline"] != nil {
			t.Fatal("cmdline off")
		}
	}
}

func TestFanControl(t *testing.T) {
	r := newRig(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\ncontrol_rate_per_min: 60\n")
	st, s := r.do(t, "GET", "/fan/status", readTok, nil)
	if st != 200 || s["mode"] != "optimal" || s["overridden"] != false || s["min_duty"] != 30.0 || s["max_temp_c"] != 80.0 ||
		len(s["fans"].([]any)) != 2 || s["error"] != nil {
		t.Fatal(st, s)
	}
	if st, b := r.do(t, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": 50}); st != 409 || !strings.Contains(b["error"].(string), "full") {
		t.Fatal("duty outside full mode", st, b)
	}
	if st, _ := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "turbo"}); st != 400 {
		t.Fatal(st)
	}
	if st, _ := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "full"}); st != 200 {
		t.Fatal(st)
	}
	for _, bad := range []map[string]any{{"zone": 0, "percent": 29}, {"zone": 0, "percent": 0}, {"zone": 2, "percent": 50},
		{"zone": 0, "percent": 50.5}, {"zone": 0}} {
		if st, _ := r.do(t, "POST", "/fan/duty", ctlTok, bad); st != 400 {
			t.Fatal(bad, st)
		}
	}
	if st, b := r.do(t, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": 40}); st != 200 || b["percent"] != 40.0 {
		t.Fatal(st, b)
	}
	_, s = r.do(t, "GET", "/fan/status", readTok, nil)
	if s["mode"] != "full" || s["overridden"] != true || s["duty"].(map[string]any)["0"] != 40.0 || len(s["events"].([]any)) != 2 {
		t.Fatal(s)
	}
	if _, d := r.bmc.State(); d[0] != 40 {
		t.Fatal(d)
	}
	// watchdog: below the limit nothing happens; at 80 °C both zones go to 100 %
	r.fan.WatchdogOnce(context.Background())
	if _, d := r.bmc.State(); d[0] != 40 {
		t.Fatal("cool: unchanged", d)
	}
	r.bmc.SetRaw(0x01, 81)
	if err := r.a.d.BMC.(*BMC).refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.fan.WatchdogOnce(context.Background())
	if _, d := r.bmc.State(); d != [2]byte{100, 100} {
		t.Fatal("hot: 100 %", d)
	}
	_, s = r.do(t, "GET", "/fan/status", readTok, nil)
	ev := s["events"].([]any)
	if last := ev[len(ev)-1].(map[string]any); !strings.Contains(last["action"].(string), "watchdog") || !strings.Contains(last["detail"].(string), "CPU Temp 81.0") {
		t.Fatal(last)
	}
	// BMC errors are reported in the status, not as a failed request
	r.bmc.Fail = context.DeadlineExceeded
	_, s = r.do(t, "GET", "/fan/status", readTok, nil)
	if s["error"] == nil || s["mode"] != nil {
		t.Fatal(s)
	}
	if st, _ := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "optimal"}); st != 502 {
		t.Fatal(st)
	}
}

func TestWatchdogWithoutTemperature(t *testing.T) {
	r := newRig(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\n")
	ctx := context.Background()
	r.fan.SetMode(ctx, "full", "test")
	r.fan.SetDuty(ctx, 0, 35, "test")
	r.a.d.BMC.(*BMC).mu.Lock()
	r.a.d.BMC.(*BMC).readings = nil // BMC sensors gone, and the OS has no temperature either
	r.a.d.BMC.(*BMC).mu.Unlock()
	r.fan.localTemps = func() []collect.Temp { return nil }
	for i := 0; i < 2; i++ {
		r.fan.WatchdogOnce(ctx)
		if _, d := r.bmc.State(); d[0] != 35 {
			t.Fatal("waits for three misses", d)
		}
	}
	r.fan.WatchdogOnce(ctx)
	if _, d := r.bmc.State(); d[0] != 100 {
		t.Fatal("no temperature for 30 s: 100 %", d)
	}
}

func TestPower(t *testing.T) {
	r := newRig(t, "power_control: {enabled: true, min_delay_s: 30}\ncontrol_rate_per_min: 20\n")
	if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 10}); st != 400 {
		t.Fatal("below min_delay_s", st)
	}
	if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "halt"}); st != 400 {
		t.Fatal(st)
	}
	st, b := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "reboot", "delay_s": 120, "requested_by": "neptune@example.com<script>"})
	p := b["pending"].(map[string]any)
	if st != 200 || p["action"] != "reboot" || p["delay_s"] != 120.0 || p["requested_by"] != "neptune@example.comscript" {
		t.Fatal(st, b)
	}
	if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "shutdown", "delay_s": 60}); st != 409 {
		t.Fatal("one pending action at a time", st)
	}
	_, m := r.do(t, "GET", "/metrics", readTok, nil)
	pc := m["power_control"].(map[string]any)
	if pc["enabled"] != true || pc["min_delay_s"] != 30.0 || pc["pending"].(map[string]any)["action"] != "reboot" {
		t.Fatal(pc)
	}
	if st, b := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 || b["pending"] != nil {
		t.Fatal(st, b)
	}
	if r.power.Cancels != 1 || strings.Join(r.power.Scheduled, ",") != "reboot@2m0s" {
		t.Fatal(r.power)
	}
	// default delay 60 s
	if _, b := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "shutdown"}); b["pending"].(map[string]any)["delay_s"] != 60.0 {
		t.Fatal(b)
	}
}

func TestControlRateLimit(t *testing.T) {
	r := newRig(t, "power_control: {enabled: true}\ncontrol_rate_per_min: 2\n")
	for i := 0; i < 2; i++ {
		if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 {
			t.Fatal(st)
		}
	}
	if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 429 {
		t.Fatal(st)
	}
}

func TestWOL(t *testing.T) {
	pkt, err := MagicPacket("3c:ec:ef:00:11:22", "")
	if err != nil || len(pkt) != 102 || !bytes.Equal(pkt[:6], bytes.Repeat([]byte{0xFF}, 6)) || pkt[6] != 0x3c || pkt[101] != 0x22 {
		t.Fatal(len(pkt), err)
	}
	if p, _ := MagicPacket("3c-ec-ef-00-11-22", "01:02:03:04:05:06"); len(p) != 108 {
		t.Fatal("SecureOn")
	}
	if _, err := MagicPacket("nope", ""); err == nil {
		t.Fatal("bad mac")
	}
	r := newRig(t, "wol: {enabled: true, allowed_macs: ['3c:ec:ef:00:11:22']}\ncontrol_rate_per_min: 20\n")
	st, b := r.do(t, "POST", "/wol", ctlTok, map[string]any{"mac": "3C:EC:EF:00:11:22", "broadcast": "192.168.10.255", "port": 9})
	if st != 200 || b["sent"] != true || b["bytes"] != 102.0 || r.sent[0] != "192.168.10.255:9" {
		t.Fatal(st, b, r.sent)
	}
	if st, _ := r.do(t, "POST", "/wol", ctlTok, map[string]any{"mac": "aa:bb:cc:dd:ee:ff"}); st != 400 {
		t.Fatal("not allowed", st)
	}
	if st, _ := r.do(t, "POST", "/wol", ctlTok, map[string]any{"mac": "3c:ec:ef:00:11:22", "broadcast": "8.8.8.8"}); st != 400 {
		t.Fatal("public address", st)
	}
	if st, _ := r.do(t, "POST", "/wol", ctlTok, map[string]any{"mac": "3c:ec:ef:00:11:22", "port": 80}); st != 400 {
		t.Fatal("port", st)
	}
	if st, _ := r.do(t, "POST", "/wol", ctlTok, map[string]any{"mac": "3c:ec:ef:00:11:22", "broadcast": nil}); st != 200 || r.sent[1] != "255.255.255.255:9" {
		t.Fatal(st, r.sent)
	}
}

func TestBodyLimit(t *testing.T) {
	r := newRig(t, "power_control: {enabled: true}")
	if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": strings.Repeat("x", 5000)}); st != 400 {
		t.Fatal(st)
	}
}

func TestTailscaleIP(t *testing.T) {
	ip := func(s string) net.IP { return net.ParseIP(s) }
	a := []IfaceAddr{{"lo", ip("127.0.0.1")}, {"eth0", ip("192.168.1.10")}, {"tailscale0", ip("100.101.102.103")},
		{"tailscale0", ip("fd7a:115c:a1e0::1")}}
	if got, ok := TailscaleIP(a); !ok || got.String() != "100.101.102.103" {
		t.Fatal(got, ok)
	}
	if _, ok := TailscaleIP(a[:2]); ok {
		t.Fatal("no tailscale")
	}
	two := []IfaceAddr{{"eth0", ip("100.64.0.5")}, {"Tailscale", ip("100.70.0.1")}}
	if got, _ := TailscaleIP(two); got.String() != "100.70.0.1" {
		t.Fatal("prefer the interface named Tailscale", got)
	}
	if _, ok := TailscaleIP([]IfaceAddr{{"a", ip("100.64.0.5")}, {"b", ip("100.64.0.6")}}); ok {
		t.Fatal("ambiguous")
	}
	c := mustParse(t, "listen: 127.0.0.1:19999")
	if addr, err := ListenAddr(context.Background(), c, 0); err != nil || addr != "127.0.0.1:19999" {
		t.Fatal(addr, err)
	}
}

func TestLogRotation(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logs", "agent.log")
	l, err := OpenLog(p, 100)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _ = l.Write([]byte(strings.Repeat("x", 39) + "\n"))
	}
	l.Close()
	a, _ := os.ReadFile(p)
	b, _ := os.ReadFile(p + ".1")
	if len(a) != 40 || len(b) != 80 {
		t.Fatal(len(a), len(b))
	}
}

func TestRelay(t *testing.T) {
	plug := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"apower": 95.5, "voltage": 229.8, "current": 0.41, "aenergy": map[string]any{"total": 12000.0}})
	}))
	defer plug.Close()
	if _, err := NewRelay([]map[string]any{{"id": "x", "type": "agent", "agent": "y"}}, nil); err == nil {
		t.Fatal("type agent")
	}
	r, err := NewRelay([]map[string]any{
		{"id": "desk-plug", "type": "shelly", "name": "Desk plug", "url": plug.URL, "gen": "2", "system_hint": "self"},
		{"id": "dead-plug", "type": "tasmota", "url": "http://127.0.0.1:1"},
	}, []map[string]any{{"id": "local", "host": "127.0.0.1", "port": 1}})
	if err != nil {
		t.Fatal(err)
	}
	r.PollOnce(context.Background())
	ps, us := r.Rows()
	if len(ps) != 2 || ps[0]["ok"] != true || ps[0]["watts"] != 95.5 || ps[0]["system_hint"] != "self" ||
		ps[0]["energy_kwh_total"] != 12.0 || ps[1]["ok"] != false || ps[1]["error"] == nil {
		t.Fatal(ps)
	}
	if len(us) != 1 || us[0]["name"] != "upsd" || us[0]["ok"] != false {
		t.Fatal(us)
	}
}

func TestMain(m *testing.M) {
	if mode := os.Getenv("FAKE_IPMITOOL_MODE"); mode != "" {
		os.Exit(fakeIpmitool(mode, os.Args[1:]))
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

type amdOnly struct{}

func (amdOnly) GPUs() []collect.GPU {
	return []collect.GPU{{Name: "AMD Radeon (amdgpu 1002:15bf)", Vendor: "amd", UtilPercent: collect.P(5.0)}}
}
func (amdOnly) ComputeApps(context.Context) map[int][]int64 { return nil }

func TestCombineGPUs(t *testing.T) {
	if CombineGPUs(nil, nil) != nil {
		t.Fatal("no sources = nil")
	}
	if _, ok := CombineGPUs(nil, amdOnly{}).(amdOnly); !ok {
		t.Fatal("one source is returned as is")
	}
	g := CombineGPUs(agenttest.GPU{}, amdOnly{})
	gpus := g.GPUs()
	if len(gpus) != 2 || gpus[0].Vendor != "nvidia" || gpus[1].Vendor != "amd" {
		t.Fatalf("%+v", gpus)
	}
	if apps := g.ComputeApps(t.Context()); apps[6000][0] != 5<<30 {
		t.Fatalf("%v", apps)
	}
	if c, err := Parse([]byte("gpu: {amdgpu: maybe}"), "c.yaml"); err == nil {
		t.Fatal("amdgpu must be auto or off", c)
	}
	if c, err := Parse(nil, "c.yaml"); err != nil || c.GPU.AMDGPU != "auto" {
		t.Fatal("amdgpu defaults to auto", err)
	}
}

// A board whose BMC has no "optimal" mode (Enginetech EG320W-G20, a Supermicro OEM board: completion code 0xCC):
// the agent answers 422 fan_mode_unsupported, lists the mode in /fan/status, warns when it is auto_mode, and
// forgets it again once the BMC accepts it.
func TestFanModeUnsupported(t *testing.T) {
	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	r := newRig(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\ncontrol_rate_per_min: 60\n")
	r.bmc.RefuseMode(2, 0xCC)
	r.bmc.Mode = 0 // the board runs "standard"
	_, s := r.do(t, "GET", "/fan/status", readTok, nil)
	if um := s["unsupported_modes"].([]any); len(um) != 0 || s["auto_mode"] != "optimal" {
		t.Fatal(s)
	}
	st, b := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "optimal"})
	if st != 422 || b["code"] != "fan_mode_unsupported" || !strings.Contains(b["error"].(string), "0xCC") {
		t.Fatal(st, b)
	}
	if !strings.Contains(logs.String(), "fan_control.auto_mode standard") {
		t.Fatal("auto_mode refused: no warning", logs.String())
	}
	if mode, _ := r.bmc.State(); mode != 0 {
		t.Fatal("mode changed", mode)
	}
	r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "optimal"}) // twice: listed and logged once
	_, s = r.do(t, "GET", "/fan/status", readTok, nil)
	if um := s["unsupported_modes"].([]any); len(um) != 1 || um[0] != "optimal" || len(s["events"].([]any)) != 1 {
		t.Fatal(s)
	}
	if st, _ := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "heavyio"}); st != 200 {
		t.Fatal("other modes still work", st)
	}
	// other completion codes are BMC failures, not "unsupported"
	r.bmc.RefuseMode(0, 0xC3)
	if st, _ := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "standard"}); st != 502 {
		t.Fatal(st)
	}
	r.bmc.RefuseMode(2, 0)
	if st, _ := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "optimal"}); st != 200 {
		t.Fatal(st)
	}
	_, s = r.do(t, "GET", "/fan/status", readTok, nil)
	if um := s["unsupported_modes"].([]any); len(um) != 0 {
		t.Fatal("accepted again: no longer listed", s)
	}
	// a refused mode that is not auto_mode logs no auto_mode warning
	logs.Reset()
	r2 := newRig(t, "ipmi: {enabled: true}\nfan_control: {enabled: true, auto_mode: standard}\n")
	r2.bmc.RefuseMode(2, 0xCC)
	if st, _ := r2.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "optimal"}); st != 422 || strings.Contains(logs.String(), "auto_mode") {
		t.Fatal(st, logs.String())
	}
}

// Sleep: like shutdown (delay, one pending action, cancel), refused with 409 sleep_unavailable when the machine
// cannot sleep; /metrics says which.
func TestPowerSleep(t *testing.T) {
	r := newRig(t, "power_control: {enabled: true, min_delay_s: 10}\ncontrol_rate_per_min: 20\n")
	_, m := r.do(t, "GET", "/metrics", readTok, nil)
	if pc := m["power_control"].(map[string]any); pc["sleep"] != true || pc["sleep_note"] != nil {
		t.Fatal(pc)
	}
	st, b := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "sleep", "delay_s": 15, "requested_by": "neptune"})
	if st != 200 || b["pending"].(map[string]any)["action"] != "sleep" {
		t.Fatal(st, b)
	}
	if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "shutdown"}); st != 409 {
		t.Fatal("one pending action", st)
	}
	if st, _ := r.do(t, "POST", "/power", ctlTok, map[string]any{"action": "cancel"}); st != 200 {
		t.Fatal(st)
	}
	if strings.Join(r.power.Scheduled, ",") != "sleep@15s" || r.power.Cancels != 1 {
		t.Fatal(r.power)
	}

	r2 := newRig(t, "power_control: {enabled: true}\n")
	r2.power.NoSleep = "only Modern Standby"
	st, b = r2.do(t, "POST", "/power", ctlTok, map[string]any{"action": "sleep"})
	if st != 409 || b["code"] != "sleep_unavailable" || !strings.Contains(b["error"].(string), "Modern Standby") {
		t.Fatal(st, b)
	}
	_, m = r2.do(t, "GET", "/metrics", readTok, nil)
	if pc := m["power_control"].(map[string]any); pc["sleep"] != false || pc["sleep_note"] != "only Modern Standby" {
		t.Fatal(pc)
	}
}

func TestSleepCapabilityParsers(t *testing.T) {
	caps := make([]byte, 76)
	if ok, _ := sleepFromCaps(caps); ok {
		t.Fatal("nothing")
	}
	caps[20] = 1
	if ok, why := sleepFromCaps(caps); ok || !strings.Contains(why, "Modern Standby") {
		t.Fatal(why)
	}
	caps[5] = 1 // S3
	if ok, _ := sleepFromCaps(caps); !ok {
		t.Fatal("S3")
	}
	if ok, _ := sleepFromCaps(caps[:10]); ok {
		t.Fatal("short")
	}
}

// fakeProcMem stands in for Windows' per-process GPU memory counter (collect.ProcGPU).
type fakeProcMem struct{ n *int }

func (f fakeProcMem) ComputeAppsFor(gpus []collect.GPU) map[int][]int64 {
	*f.n = len(gpus)
	v := make([]int64, len(gpus))
	v[len(v)-1] = 512 << 20 // a browser on the last GPU (the AMD card)
	return map[int][]int64{6000: make([]int64, len(gpus)), 7100: v}
}

type nvidiaWDDM struct{ agenttest.GPU }

// ComputeApps is what nvidia-smi gives on Windows: no per-process numbers at all, an empty (not nil) map.
func (nvidiaWDDM) ComputeApps(context.Context) map[int][]int64 { return map[int][]int64{} }

func TestProcessGPUMemoryMerge(t *testing.T) {
	// NVIDIA (5 GiB for Ollama from nvidia-smi) + AMD: positions follow the combined list
	g := WithProcessGPUMemory(CombineGPUs(agenttest.GPU{}, amdOnly{}), fakeProcMem{new(int)})
	apps := g.ComputeApps(t.Context())
	if len(apps[6000]) != 2 || apps[6000][0] != 5<<30 || apps[7100][1] != 512<<20 || apps[7100][0] != 0 {
		t.Fatalf("%v", apps)
	}
	// the AMD source's own per-process numbers move to its position in the list
	g = CombineGPUs(amdOnly{}, agenttest.GPU{})
	if apps := g.ComputeApps(t.Context()); len(apps[6000]) != 2 || apps[6000][1] != 5<<30 || apps[6000][0] != 0 {
		t.Fatalf("offset: %v", apps)
	}
	// Windows with only an NVIDIA card: nvidia-smi's empty map no longer hides the counter's numbers
	n := new(int)
	g = WithProcessGPUMemory(nvidiaWDDM{}, fakeProcMem{n})
	if apps := g.ComputeApps(t.Context()); *n != 1 || apps[7100][0] != 512<<20 {
		t.Fatalf("%v", apps)
	}
	if WithProcessGPUMemory(nil, fakeProcMem{n}) != nil {
		t.Fatal("no GPU: nothing to add to")
	}
	// end to end through /processes
	r := newRig(t, "listen: 127.0.0.1:0\n")
	r.a.d.GPU = WithProcessGPUMemory(CombineGPUs(agenttest.GPU{}, amdOnly{}), fakeProcMem{new(int)})
	code, body := r.do(t, "GET", "/processes?sort=gpu", readTok, nil)
	procs, _ := body["processes"].([]any)
	if code != 200 || len(procs) == 0 {
		t.Fatal(code, body)
	}
	top := procs[0].(map[string]any)
	if top["pid"].(float64) != 6000 || top["gpu_mem"].(float64) != 5<<30 || len(top["gpu_mem_by_gpu"].([]any)) != 2 {
		t.Fatalf("%v", top)
	}
}
