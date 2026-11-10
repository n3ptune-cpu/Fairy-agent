package agent

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/ipmi/fakebmc"
)

const (
	modeStandard, modeFull, modeOptimal, modeHeavyIO = 0, 1, 2, 4
)

// useFakeBMC makes Run and FansAuto talk to bmc instead of ipmitool. built counts the connections made.
func useFakeBMC(t *testing.T, bmc *fakebmc.BMC) (built *int) {
	t.Helper()
	old := ipmiTransport
	n := 0
	ipmiTransport = func(IPMIConfig) (ipmi.Transport, error) { n++; return bmc, nil }
	t.Cleanup(func() { ipmiTransport = old })
	return &n
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

// runAgent starts the real Run with fan control on a fake BMC and returns its address, a stop function that
// ends it the way SIGTERM does (and waits for it) and the log.
func runAgent(t *testing.T, bmc *fakebmc.BMC) (addr string, stop func()) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Run looks for the helper service on Windows")
	}
	useFakeBMC(t, bmc)
	t.Setenv("FAIRY_AGENT_TOKEN", readTok)
	t.Setenv("FAIRY_AGENT_CONTROL_TOKEN", ctlTok)
	addr = freeAddr(t)
	cfg := mustParse(t, "listen: "+addr+"\nipmi: {enabled: true}\nfan_control: {enabled: true}\n"+
		"gpu: {nvidia_smi: \"off\", amdgpu: \"off\"}\nprocesses: {enabled: false}\n")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg, Build{Version: "test"}) }()
	stopped := false
	stop = func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal("Run:", err)
			}
		case <-time.After(20 * time.Second):
			t.Fatal("Run did not stop")
		}
	}
	t.Cleanup(stop)
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return addr, stop
		}
		select {
		case err := <-done:
			t.Fatal("Run ended early:", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("agent not listening:", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func ctlPost(t *testing.T, addr, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://"+addr+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+ctlTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// M5: a clean stop of the real agent hands a manual fan speed back to the BMC.
func TestRunStopHandsFansBack(t *testing.T) {
	bmc := fakebmc.X11SCAF()
	addr, stop := runAgent(t, bmc)
	if st := ctlPost(t, addr, "/fan/mode", `{"mode":"full"}`); st != 200 {
		t.Fatal(st)
	}
	for _, z := range []string{"0", "1"} {
		// 409 until the BMC's sensors have been read once (a duty needs a temperature reading)
		for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			st := ctlPost(t, addr, "/fan/duty", `{"zone":`+z+`,"percent":30}`)
			if st == 200 {
				break
			}
			if st != 409 || time.Now().After(deadline) {
				t.Fatal(st)
			}
		}
	}
	if m, d := bmc.State(); m != modeFull || d != [2]byte{30, 30} {
		t.Fatal("manual 30 % expected", m, d)
	}
	stop()
	if m, d := bmc.State(); m != modeOptimal {
		t.Fatalf("after a clean stop the BMC is still in mode %d with duties %v", m, d)
	}
}

// A mode the owner chose (an automatic one, not "full") is left alone when the agent stops.
func TestRunStopKeepsChosenMode(t *testing.T) {
	bmc := fakebmc.X11SCAF()
	addr, stop := runAgent(t, bmc)
	if st := ctlPost(t, addr, "/fan/mode", `{"mode":"heavyio"}`); st != 200 {
		t.Fatal(st)
	}
	stop()
	if m, _ := bmc.State(); m != modeHeavyIO {
		t.Fatal("the owner's mode was changed to", m)
	}
}

// A fixed duty left by an agent that was killed (no hand-back ran) goes back to automatic when the next one
// starts: this is what the binary alone does, without the unit file's ExecStopPost.
func TestRunStartHandsBackLeftoverDuty(t *testing.T) {
	bmc := fakebmc.X11SCAF()
	bmc.Mode, bmc.Duty = modeFull, [2]byte{30, 30}
	runAgent(t, bmc)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if m, _ := bmc.State(); m == modeOptimal {
			return
		}
		if time.Now().After(deadline) {
			m, d := bmc.State()
			t.Fatal("the leftover duty is still set:", m, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A request that changed the fans before the start-up hand-back got its turn is not undone by it.
func TestFanRunKeepsARequestMadeMeanwhile(t *testing.T) {
	r := newRig(t, fanYAML)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Run: the hand-back at start, then the watchdog loop ends at once
	r.fan.SetMode(context.Background(), "full", "test")
	if st, b := r.fan.SetDuty(context.Background(), 0, 40, "test"); st != 200 {
		t.Fatal(st, b)
	}
	r.fan.Run(ctx)
	if m, d := r.bmc.State(); m != modeFull || d[0] != 40 {
		t.Fatal("the request was undone:", m, d)
	}
	// without such a request the leftover goes back (with a context that is still alive)
	r2 := newRig(t, fanYAML)
	r2.bmc.Mode, r2.bmc.Duty = modeFull, [2]byte{30, 30}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r2.fan.Run(ctx2); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if m, _ := r2.bmc.State(); m == modeOptimal {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("leftover duty still set")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel2()
	<-done
}

func fanConfig(t *testing.T, extra string) *Config {
	t.Helper()
	return mustParse(t, "ipmi: {enabled: true}\nfan_control: {enabled: true}\n"+extra)
}

// M5: `fairy-agent fans-auto` (ExecStopPost) after the agent was killed.
func TestFansAuto(t *testing.T) {
	ctx := context.Background()

	bmc := fakebmc.X11SCAF()
	bmc.Mode, bmc.Duty = modeFull, [2]byte{30, 35}
	useFakeBMC(t, bmc)
	mode, done, err := FansAuto(ctx, fanConfig(t, ""))
	if err != nil || !done || mode != "optimal" {
		t.Fatal(mode, done, err)
	}
	if m, _ := bmc.State(); m != modeOptimal {
		t.Fatal("still in mode", m)
	}
	// again (the agent stopped cleanly and handed back itself): nothing is changed
	calls := bmc.Calls
	if mode, done, err = FansAuto(ctx, fanConfig(t, "")); err != nil || !done || mode != "optimal" || bmc.Calls != calls+1 {
		t.Fatal("second run: one read, no change", mode, done, err, bmc.Calls-calls)
	}

	// a mode the owner chose is left alone
	for _, m := range []byte{modeStandard, modeHeavyIO} {
		bmc.Mode = m
		if _, _, err := FansAuto(ctx, fanConfig(t, "")); err != nil {
			t.Fatal(err)
		}
		if got, _ := bmc.State(); got != m {
			t.Fatalf("mode %d was changed to %d", m, got)
		}
	}

	// auto_mode from the config; a board without it gets "standard"
	bmc.Mode, bmc.Duty = modeFull, [2]byte{30, 30}
	heavy := mustParse(t, "ipmi: {enabled: true}\nfan_control: {enabled: true, auto_mode: heavyio}\n")
	if mode, _, err = FansAuto(ctx, heavy); err != nil || mode != "heavyio" {
		t.Fatal(mode, err)
	}
	bmc.Mode, bmc.Duty = modeFull, [2]byte{30, 30}
	bmc.RefuseMode(modeOptimal, 0xCC)
	if mode, _, err = FansAuto(ctx, fanConfig(t, "")); err != nil || mode != "standard" {
		t.Fatal(mode, err)
	}
	bmc.RefuseMode(modeOptimal, 0)

	// the BMC takes no automatic mode at all: both zones to 100 % rather than a low fixed duty, and an error
	bmc.Mode, bmc.Duty = modeFull, [2]byte{30, 30}
	bmc.RefuseMode(modeOptimal, 0xD5)
	if _, done, err = FansAuto(ctx, fanConfig(t, "")); err == nil || !done {
		t.Fatal("expected an error", err)
	}
	if m, d := bmc.State(); m != modeFull || d != [2]byte{100, 100} {
		t.Fatal("expected 100 % on both zones, got", m, d)
	}
	bmc.RefuseMode(modeOptimal, 0)

	// the mode cannot be read: the automatic mode is set anyway
	// (a BMC that answers nothing is an error, never a silent success)
	bmc.Fail = errors.New("BMC timeout")
	if _, done, err = FansAuto(ctx, fanConfig(t, "")); err == nil || !done {
		t.Fatal("expected an error from a BMC that does not answer", err)
	}
	bmc.Fail = nil
}

// fans-auto does nothing at all (no BMC connection) unless fan control is switched on.
func TestFansAutoOff(t *testing.T) {
	bmc := fakebmc.X11SCAF()
	bmc.Mode, bmc.Duty = modeFull, [2]byte{30, 30}
	built := useFakeBMC(t, bmc)
	for _, y := range []string{"", "ipmi: {enabled: true}\n", "ipmi: {enabled: true}\nfan_control: {enabled: false}\n"} {
		mode, done, err := FansAuto(context.Background(), mustParse(t, y))
		if err != nil || done || mode != "" {
			t.Fatalf("%q: %v %v %v", y, mode, done, err)
		}
	}
	if *built != 0 || bmc.Calls != 0 {
		t.Fatal("the BMC was contacted with fan control off:", *built, bmc.Calls)
	}
	// the BMC connection cannot be made (ipmitool missing): an error, not a silent success
	ipmiTransport = func(IPMIConfig) (ipmi.Transport, error) { return nil, errors.New("ipmitool not found") }
	if _, done, err := FansAuto(context.Background(), fanConfig(t, "")); err == nil || !done {
		t.Fatal(err)
	}
	// env_file is read first (it holds the BMC password for IPMI over LAN)
	missing := filepath.Join(t.TempDir(), "nope.env")
	if _, _, err := FansAuto(context.Background(), fanConfig(t, "env_file: "+missing+"\n")); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// Once the fans are handed back for a stop, the API changes nothing any more.
func TestFanShutdownRefusesChanges(t *testing.T) {
	r := newRig(t, fanYAML)
	ctx := context.Background()
	r.fan.SetMode(ctx, "full", "test")
	r.fan.SetDuty(ctx, 0, 40, "test")
	if mode, err := r.fan.Shutdown(ctx, "agent stopping"); err != nil || mode != "optimal" {
		t.Fatal(mode, err)
	}
	if st, b := r.do(t, "POST", "/fan/mode", ctlTok, map[string]any{"mode": "full"}); st != 503 || b["code"] != "stopping" {
		t.Fatal(st, b)
	}
	if st, b := r.do(t, "POST", "/fan/duty", ctlTok, map[string]any{"zone": 0, "percent": 40}); st != 503 || b["code"] != "stopping" {
		t.Fatal(st, b)
	}
	if m, _ := r.bmc.State(); m != modeOptimal {
		t.Fatal(m)
	}
}

// M4: the real Run serves behind the connection caps (here: this machine's own eight). A ninth connection from
// this machine is not answered while the eight are open, and it is not reset either (review N6, N2): it waits
// for a slot and is answered when one is free.
func TestRunLimitsConnections(t *testing.T) {
	addr, _ := runAgent(t, fakebmc.X11SCAF())
	var kept []net.Conn
	defer func() {
		for _, c := range kept {
			c.Close()
		}
	}()
	for i := 0; i < MaxConnsPerSender; i++ {
		c, held, err := halfOpen("127.0.0.1", addr, 100)
		if err != nil || !held {
			t.Fatal(i, held, err)
		}
		kept = append(kept, c)
	}
	// the ninth: a complete request. No slot until the agent drops an unfinished one (two seconds after it was
	// opened).
	start := time.Now()
	st, err := metricsFrom("127.0.0.1", addr)
	if err != nil || st != 200 {
		t.Fatalf("the ninth connection from this machine: HTTP %d, %v", st, err)
	}
	if took := time.Since(start); took < time.Second || took > ConnWait {
		t.Fatalf("the ninth connection was answered after %s: it should have waited for one of the eight slots", took)
	}
}
