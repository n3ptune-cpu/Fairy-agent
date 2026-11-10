package helper

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/helper/proto"
)

var fanCfg = agent.FanConfig{Enabled: true, Vendor: "supermicro", MinDuty: 30, MaxTempC: 80, AutoMode: "optimal"}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type rig struct {
	srv   *Server
	bmc   *fakebmc.BMC
	b     *agent.BMC
	fan   *agent.Fan
	power *agenttest.PowerExec
	audit *syncBuf
}

// newRig: a helper with fans on a fake X11SCA-F. runBMC starts the BMC reader (sensor readings); without it the
// BMC has no readings at all.
func newRig(t *testing.T, runBMC bool, cfg agent.FanConfig) *rig {
	t.Helper()
	r := &rig{bmc: fakebmc.X11SCAF(), power: &agenttest.PowerExec{}, audit: &syncBuf{}}
	r.b = agent.NewBMC(r.bmc, 20*time.Millisecond)
	r.fan = agent.NewFan(r.bmc, r.b, cfg, nil)
	r.srv = New(Parts{Version: "0.5.0-test", BMC: r.b, Fan: r.fan, Power: r.power,
		Audit: slog.New(slog.NewTextHandler(r.audit, nil))})
	if runBMC {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go r.b.Run(ctx)
		waitFor(t, func() bool { tt, _, _ := r.b.Metrics(); return len(tt) > 0 })
	}
	return r
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out")
}

func (r *rig) call(t *testing.T, req string) proto.Response {
	t.Helper()
	return r.srv.Handle(context.Background(), "test-client", []byte(req))
}

func (r *rig) mode(t *testing.T) string {
	t.Helper()
	m, err := ipmi.GetFanMode(context.Background(), r.bmc)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func (r *rig) duty(t *testing.T, z byte) int {
	t.Helper()
	d, err := ipmi.GetDuty(context.Background(), r.bmc, z)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (r *rig) setManual(t *testing.T, pct int) {
	t.Helper()
	if resp := r.call(t, `{"v":1,"verb":"fan_mode","mode":"full","by":"test"}`); resp.Status != 200 {
		t.Fatal(resp)
	}
	for _, z := range []string{"0", "1"} {
		if resp := r.call(t, `{"v":1,"verb":"fan_set","zone":`+z+`,"percent":`+itoa(pct)+`,"by":"test"}`); resp.Status != 200 {
			t.Fatal(resp)
		}
	}
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestRejectsUnknownVerbsAndBadParams(t *testing.T) {
	r := newRig(t, false, fanCfg)
	for req, code := range map[string]string{
		`{"v":1,"verb":"exec","cmd":"cmd.exe"}`:                  proto.CodeBadRequest,
		`{"v":1,"verb":"exec"}`:                                  proto.CodeUnknownVerb,
		`{"v":1,"verb":"read_file"}`:                             proto.CodeUnknownVerb,
		`{"v":1,"verb":"fan_set","zone":0,"percent":29}`:         proto.CodeBadRequest,
		`{"v":1,"verb":"fan_set","zone":0,"percent":10}`:         proto.CodeBadRequest,
		`{"v":1,"verb":"fan_mode","mode":"turbo"}`:               proto.CodeBadRequest,
		`{"v":1,"verb":"power","action":"logoff","delay_s":60}`:  proto.CodeBadRequest,
		`{"v":1,"verb":"coretemp_read","path":"C:\\Windows\\x"}`: proto.CodeBadRequest,
		`not json`: proto.CodeBadRequest,
	} {
		resp := r.call(t, req)
		if resp.Status != 400 || resp.Code != code {
			t.Errorf("%s: %+v", req, resp)
		}
	}
	if d := r.duty(t, 0); d != 100 {
		t.Fatal("a refused request changed the fans:", d)
	}
	if !strings.Contains(r.audit.String(), "refused request") {
		t.Fatal("refusals are not in the audit log")
	}
}

func TestDisabledVerbs(t *testing.T) {
	srv := New(Parts{Version: "x", Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	for _, req := range []string{`{"v":1,"verb":"coretemp_read"}`, `{"v":1,"verb":"ipmi_sensors"}`, `{"v":1,"verb":"fan_status"}`,
		`{"v":1,"verb":"fan_auto"}`, `{"v":1,"verb":"fan_set","zone":0,"percent":50}`,
		`{"v":1,"verb":"power","action":"shutdown","delay_s":60}`, `{"v":1,"verb":"apply_update"}`} {
		if resp := srv.Handle(context.Background(), "c", []byte(req)); resp.Status != 404 || resp.Code != proto.CodeDisabled {
			t.Errorf("%s: %+v", req, resp)
		}
	}
	resp := srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"status"}`))
	var st proto.StatusData
	if resp.Status != 200 || json.Unmarshal(resp.Data, &st) != nil || len(st.Features) != 0 || st.Watchdog {
		t.Fatal(resp)
	}
}

func TestFanSetAndFloor(t *testing.T) {
	r := newRig(t, true, fanCfg)
	r.setManual(t, 30)
	if r.mode(t) != "full" || r.duty(t, 0) != 30 || r.duty(t, 1) != 30 {
		t.Fatal(r.mode(t), r.duty(t, 0))
	}
	// a config floor above 30 % is kept too (the protocol's 30 % is the lowest any config can go)
	c := fanCfg
	c.MinDuty = 40
	r2 := newRig(t, false, c)
	r2.call(t, `{"v":1,"verb":"fan_mode","mode":"full"}`)
	if resp := r2.call(t, `{"v":1,"verb":"fan_set","zone":0,"percent":35}`); resp.Status != 400 {
		t.Fatal(resp)
	}
	resp := r.call(t, `{"v":1,"verb":"fan_status"}`)
	var st map[string]any
	if resp.Status != 200 || json.Unmarshal(resp.Data, &st) != nil || st["mode"] != "full" {
		t.Fatal(resp)
	}
	if !strings.Contains(r.audit.String(), "verb=fan_set") || !strings.Contains(r.audit.String(), "client=test-client") {
		t.Fatal("changes are not in the audit log:", r.audit.String())
	}
}

func TestWatchdogAt80C(t *testing.T) {
	r := newRig(t, true, fanCfg)
	r.setManual(t, 35)
	r.fan.WatchdogOnce(context.Background())
	if r.duty(t, 0) != 35 {
		t.Fatal("watchdog acted at 45 °C")
	}
	r.bmc.SetRaw(0x01, 79)
	waitFor(t, func() bool { v, _, _ := agent.MaxCPUTemp(r.b.Readings(), nil); return v == 79 })
	r.fan.WatchdogOnce(context.Background())
	if r.duty(t, 0) != 35 {
		t.Fatal("watchdog acted at 79 °C")
	}
	r.bmc.SetRaw(0x01, 80)
	waitFor(t, func() bool { v, _, _ := agent.MaxCPUTemp(r.b.Readings(), nil); return v == 80 })
	r.fan.WatchdogOnce(context.Background())
	if r.duty(t, 0) != 100 || r.duty(t, 1) != 100 {
		t.Fatal("watchdog did not set 100 % at 80 °C", r.duty(t, 0), r.duty(t, 1))
	}
}

func TestWatchdogWithoutTemperatureFor30s(t *testing.T) {
	r := newRig(t, false, fanCfg) // no BMC readings, no Core Temp: no temperature at all
	r.setManual(t, 40)
	if agent.WatchdogInterval != 10*time.Second {
		t.Fatal("the watchdog checks every 10 s; 3 checks = 30 s")
	}
	r.fan.WatchdogOnce(context.Background()) // 10 s
	r.fan.WatchdogOnce(context.Background()) // 20 s
	if r.duty(t, 0) != 40 {
		t.Fatal("acted before 30 s")
	}
	r.fan.WatchdogOnce(context.Background()) // 30 s
	if r.duty(t, 0) != 100 || r.duty(t, 1) != 100 {
		t.Fatal("no 100 % after 30 s without a temperature")
	}
}

func TestWatchdogUsesCoreTemp(t *testing.T) {
	block := make([]byte, collect.CoreTempExSize)
	binary.LittleEndian.PutUint32(block[1024:], 100) // TjMax
	binary.LittleEndian.PutUint32(block[1536:], 1)   // cores
	binary.LittleEndian.PutUint32(block[1540:], 1)   // CPUs
	binary.LittleEndian.PutUint32(block[1544:], 0x42a00000)
	read := func() ([]byte, string, error) { return block, `Global\CoreTempMappingObjectEx`, nil }
	if ts := coreTemps(read); len(ts) != 1 || ts[0].Current != 80 {
		t.Fatal(ts)
	}
	if coreTemps(nil) != nil || coreTemps(func() ([]byte, string, error) { return nil, "", collect.ErrCoreTempAbsent }) != nil {
		t.Fatal("temperatures without Core Temp")
	}
}

func TestShutdownHandsFansBackToTheBMC(t *testing.T) {
	r := newRig(t, false, fanCfg)
	r.setManual(t, 50)
	r.srv.Shutdown(context.Background())
	if m := r.mode(t); m != "optimal" {
		t.Fatal("fans left in", m)
	}
	if !strings.Contains(r.audit.String(), "fans in BMC mode") {
		t.Fatal(r.audit.String())
	}
	// a board without "optimal": standard instead
	r2 := newRig(t, false, fanCfg)
	r2.bmc.RefuseMode(2, 0xCC)
	r2.setManual(t, 50)
	r2.srv.Shutdown(context.Background())
	if m := r2.mode(t); m != "standard" {
		t.Fatal("fans left in", m)
	}
	// a mode the owner chose (an automatic one) is left alone when stopping
	r3 := newRig(t, false, fanCfg)
	r3.call(t, `{"v":1,"verb":"fan_mode","mode":"heavyio"}`)
	r3.srv.Shutdown(context.Background())
	if m := r3.mode(t); m != "heavyio" {
		t.Fatal("changed an automatic mode:", m)
	}
	// fan_auto (the agent before /helper/stop) always goes to auto_mode
	resp := r3.call(t, `{"v":1,"verb":"fan_auto","by":"panel 100.64.0.2"}`)
	var d proto.AutoData
	if resp.Status != 200 || json.Unmarshal(resp.Data, &d) != nil || d.Mode != "optimal" || r3.mode(t) != "optimal" {
		t.Fatal(resp)
	}
}

func TestPower(t *testing.T) {
	r := newRig(t, false, fanCfg)
	if resp := r.call(t, `{"v":1,"verb":"power","action":"shutdown","delay_s":60,"by":"panel 100.64.0.2"}`); resp.Status != 200 {
		t.Fatal(resp)
	}
	if resp := r.call(t, `{"v":1,"verb":"power","action":"cancel"}`); resp.Status != 200 {
		t.Fatal(resp)
	}
	if len(r.power.Scheduled) != 1 || r.power.Scheduled[0] != "shutdown@1m0s" || r.power.Cancels != 1 {
		t.Fatal(r.power.Scheduled, r.power.Cancels)
	}
	r2 := newRig(t, false, fanCfg)
	r2.power.NoSleep = "only Modern Standby"
	resp := r2.call(t, `{"v":1,"verb":"power","action":"sleep","delay_s":30}`)
	if resp.Status != 409 || len(r2.power.Scheduled) != 0 {
		t.Fatal(resp)
	}
	resp = r2.call(t, `{"v":1,"verb":"status"}`)
	var st proto.StatusData
	if json.Unmarshal(resp.Data, &st) != nil || st.SleepOK || st.SleepNote != "only Modern Standby" || !st.Watchdog ||
		strings.Join(st.Features, ",") != "ipmi,fans,power" || st.Version != "0.5.0-test" {
		t.Fatal(st)
	}
}

// L34: the helper enforces power_control.min_delay_s itself. With 3600 configured, a request for 10 seconds
// (what a compromised agent process could send over the pipe) is refused before anything is scheduled.
func TestPowerMinDelay(t *testing.T) {
	cfg, err := agent.Parse([]byte("power_control: {enabled: true, min_delay_s: 3600}\n"), t.TempDir()+"/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, closer, err := FromConfig(cfg, "v", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if p.MinDelayS != 3600 {
		t.Fatalf("FromConfig: MinDelayS = %d, want 3600", p.MinDelayS)
	}
	audit := &syncBuf{}
	exec := &agenttest.PowerExec{}
	srv := New(Parts{Power: exec, MinDelayS: p.MinDelayS, Audit: slog.New(slog.NewTextHandler(audit, nil))})
	call := func(req string) proto.Response { return srv.Handle(context.Background(), "test-client", []byte(req)) }
	for _, action := range []string{"shutdown", "reboot", "sleep"} {
		for _, d := range []int{10, 60, 3599} {
			resp := call(`{"v":1,"verb":"power","action":"` + action + `","delay_s":` + itoa(d) + `,"by":"panel"}`)
			if resp.Status != 400 || resp.Code != proto.CodeBadRequest || !strings.Contains(resp.Error, "3600-86400") {
				t.Fatalf("%s in %d s with min_delay_s 3600: %+v", action, d, resp)
			}
		}
	}
	if len(exec.Scheduled) != 0 {
		t.Fatalf("scheduled below the minimum: %v", exec.Scheduled)
	}
	if !strings.Contains(audit.String(), "status=400") { // refused requests are in the audit log too
		t.Fatalf("audit log lacks the refusals:\n%s", audit.String())
	}
	for _, d := range []int{3600, 86400} {
		if resp := call(`{"v":1,"verb":"power","action":"shutdown","delay_s":` + itoa(d) + `}`); resp.Status != 200 {
			t.Fatalf("%d s: %+v", d, resp)
		}
	}
	if resp := call(`{"v":1,"verb":"power","action":"cancel"}`); resp.Status != 200 { // cancel has no delay
		t.Fatal(resp)
	}
	// no min_delay_s in config.yaml: the default (10) and the protocol's minimum are the same
	cfg, _ = agent.Parse([]byte("power_control: {enabled: true}\n"), t.TempDir()+"/config.yaml")
	p2, closer2, _ := FromConfig(cfg, "v", nil)
	defer closer2()
	srv2 := New(Parts{Power: &agenttest.PowerExec{}, MinDelayS: p2.MinDelayS, Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if resp := srv2.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"power","action":"reboot","delay_s":10}`)); resp.Status != 200 {
		t.Fatal(resp)
	}
	// a Parts without the setting (0) still has the protocol's floor
	if New(Parts{}).minDelay() != proto.MinDelayS {
		t.Fatal("no floor")
	}
}

func TestCoreTempRead(t *testing.T) {
	var err error
	block := []byte{1, 2, 3}
	srv := New(Parts{Audit: slog.New(slog.NewTextHandler(io.Discard, nil)),
		CoreTemp: func() ([]byte, string, error) { return block, `Global\CoreTempMappingObjectEx`, err }})
	resp := srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"coretemp_read"}`))
	var d proto.CoreTempData
	if resp.Status != 200 || json.Unmarshal(resp.Data, &d) != nil || !bytes.Equal(d.Block, block) || d.Name != `Global\CoreTempMappingObjectEx` {
		t.Fatal(resp)
	}
	err = collect.ErrCoreTempAbsent
	if resp := srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"coretemp_read"}`)); resp.Code != proto.CodeUnavailable {
		t.Fatal(resp)
	}
	err = collect.ErrCoreTempDenied
	if resp := srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"coretemp_read"}`)); resp.Code != proto.CodeDenied {
		t.Fatal(resp)
	}
	// L32: a session name that is not an administrator's is refused with the whole reason (object, owner, fix),
	// and no block is handed out
	err = fmt.Errorf(`%w: "Session\1\CoreTempMappingObjectEx" belongs to S-1-5-21-1111111111-2222222222-3333333333-1001, `+
		`not to Administrators or SYSTEM; not used. Switch on Core Temp's "Enable global shared memory (SNMP)"`, collect.ErrCoreTempUntrusted)
	resp = srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"coretemp_read"}`))
	if resp.Code != proto.CodeFailed || resp.Data != nil || !strings.Contains(resp.Error, "S-1-5-21-1111111111-2222222222-3333333333-1001") ||
		!strings.Contains(resp.Error, "global shared memory") {
		t.Fatal(resp)
	}
}

func TestRateLimits(t *testing.T) {
	now := time.Unix(5000, 0)
	r := newRig(t, false, fanCfg)
	r.srv.limit.Now = func() time.Time { return now }
	for i := 0; i < proto.ReadsPerMinute; i++ {
		if resp := r.call(t, `{"v":1,"verb":"ping"}`); resp.Status != 200 {
			t.Fatal(i, resp)
		}
	}
	if resp := r.call(t, `{"v":1,"verb":"ping"}`); resp.Status != 429 || resp.Code != proto.CodeRateLimited {
		t.Fatal(resp)
	}
	for i := 0; i < proto.ChangesPerMinute; i++ {
		if resp := r.call(t, `{"v":1,"verb":"fan_mode","mode":"standard"}`); resp.Status != 200 {
			t.Fatal(i, resp)
		}
	}
	if resp := r.call(t, `{"v":1,"verb":"fan_mode","mode":"full"}`); resp.Status != 429 {
		t.Fatal(resp)
	}
	now = now.Add(time.Minute)
	if resp := r.call(t, `{"v":1,"verb":"ping"}`); resp.Status != 200 {
		t.Fatal(resp)
	}
}

func TestServeConn(t *testing.T) {
	r := newRig(t, true, fanCfg)
	a, b := net.Pipe()
	done := make(chan struct{})
	go func() { r.srv.ServeConn(context.Background(), a, "pipe"); a.Close(); close(done) }()
	ask := func(req string) proto.Response {
		t.Helper()
		if err := proto.WriteFrame(b, []byte(req), proto.MaxRequest); err != nil {
			t.Fatal(err)
		}
		f, err := proto.ReadFrame(b, proto.MaxResponse)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := proto.DecodeResponse(f)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := ask(`{"v":1,"verb":"ping"}`); resp.Status != 200 {
		t.Fatal(resp)
	}
	resp := ask(`{"v":1,"verb":"ipmi_sensors"}`)
	var sd proto.SensorsData
	if resp.Status != 200 || json.Unmarshal(resp.Data, &sd) != nil || len(sd.Temps) != 2 || len(sd.Fans) != 2 || len(sd.Voltages) != 1 {
		t.Fatal(string(resp.Data))
	}
	// an oversized frame: answered with too_large, then the connection is closed
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], proto.MaxRequest+1)
	if _, err := b.Write(hdr[:]); err != nil {
		t.Fatal(err)
	}
	f, err := proto.ReadFrame(b, proto.MaxResponse)
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := proto.DecodeResponse(f); resp.Status != 413 || resp.Code != proto.CodeTooLarge {
		t.Fatal(resp)
	}
	<-done
	if _, err := proto.ReadFrame(b, proto.MaxResponse); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("connection still open:", err)
	}
}

func TestFeatureNames(t *testing.T) {
	srv := New(Parts{CoreTemp: collect.ReadCoreTemp, Power: &agenttest.PowerExec{},
		Updater: func(context.Context) error { return nil }, Audit: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if f := strings.Join(srv.Features(), ","); f != api.FeatureCoreTemp+","+api.FeaturePower+","+api.FeatureUpdate {
		t.Fatal(f)
	}
	if resp := srv.Handle(context.Background(), "c", []byte(`{"v":1,"verb":"apply_update","by":"self-update"}`)); resp.Status != 200 {
		t.Fatal(resp)
	}
}

func TestFromConfig(t *testing.T) {
	cfg, err := agent.Parse([]byte("power_control: {enabled: true}\nself_update: {enabled: true}\n"), t.TempDir()+"/config.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p, closer, err := FromConfig(cfg, "v", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer closer()
	if p.Power == nil || p.Updater == nil || p.CoreTemp != nil || p.BMC != nil || p.Fan != nil {
		t.Fatalf("%+v", p)
	}
}
