package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/agenttest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval/approvaltest"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/plugs/hatest"
)

// The variables the plug tests keep the two made-up tokens in: the one the meters read with and the one of the
// home_assistant block. Not FAIRY_ names: those are refused.
const (
	plugReadEnv   = "AGT_PLUG_READ_TOKEN"
	plugSwitchEnv = "AGT_PLUG_SWITCH_TOKEN"
)

// plugRig is an agent as the panel sees it that reads the made-up plugs of agenttest.PlugConfig from a fake
// Home Assistant: the relay for the watts, pkg/plugs for the sockets, the agent's own approval gate on a trust
// file in its own folder, and the made-up Pocket ID. Power control is on too, with an executor that only
// records: a shutdown is the request these tests hold a socket switch against.
type plugRig struct {
	base  string
	ha    *hatest.Server
	cfg   *agent.Config
	relay *agent.Relay
	plugs *plugs.Plugs
	gate  *approval.Gate
	iss   *approvaltest.Issuer
	trust string // the trust file
	log   *logBuf
	clk   *plugClock
	power *agenttest.PowerExec // the machine's own shutdown, for the tests of what differs from it
}

// plugClock is the clock of the sockets' keeper in these tests: a wait moves it on and returns at once.
type plugClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *plugClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *plugClock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
func (c *plugClock) Pause(ctx context.Context, d time.Duration) bool {
	c.add(d)
	return true
}

type plugRigOpts struct {
	agenttest.PlugOptions
	off     bool   // home_assistant.switching: false
	trust   string // "" a trust file is set; "admin": set on the machine; "none": no trust file; "broken": one that cannot be used
	noGate  bool   // the agent was built without a gate
	quick   bool   // short timeouts for a Home Assistant that does not answer
	rate    int    // control_rate_per_min (0: 60)
	oneVar  bool   // one variable, and so one token, for the meters and for the block (plugSwitchEnv)
	helper  agent.HelperControl
	gateOpt func(*approval.Options)
}

func newPlugRig(t *testing.T, o plugRigOpts) *plugRig {
	t.Helper()
	r := &plugRig{ha: hatest.New(agenttest.PlugStates()), iss: approvaltest.New(), log: &logBuf{}, power: &agenttest.PowerExec{},
		trust: filepath.Join(t.TempDir(), approval.TrustFileName)}
	t.Cleanup(r.ha.Close)
	r.ha.SetSensor(agenttest.PlugBarSensor, "95.5", "W")
	r.ha.SetSensor(agenttest.PlugCornerSens, "410", "W")
	r.ha.SetSensor(agenttest.PlugOwnSensor, "61.2", "W")
	t.Setenv(plugReadEnv, hatest.ReadToken())
	t.Setenv(plugSwitchEnv, hatest.Token())
	if o.rate == 0 {
		o.rate = 60
	}
	o.ReadEnv, o.SwitchEnv, o.Switching = plugReadEnv, plugSwitchEnv, !o.off
	if o.oneVar {
		o.ReadEnv = plugSwitchEnv
		t.Setenv(plugReadEnv, "") // nothing can be read with a second token: there is none
	}
	cfg, err := agent.Parse([]byte("control_rate_per_min: "+strconv.Itoa(o.rate)+"\npower_control: {enabled: true}\n"+agenttest.PlugConfig(r.ha.URL, o.PlugOptions)),
		filepath.Join(t.TempDir(), "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	r.cfg = cfg
	if r.relay, err = cfg.NewRelay(); err != nil {
		t.Fatal(err)
	}
	// as Config.NewPlugs, with a clock of the test's: the waits of a switch (half a second, then a second, ten
	// seconds in all) move the clock on and take no time
	po, ok, err := cfg.PlugOptions(r.relay)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		r.clk = &plugClock{now: time.Unix(1794000000, 0)}
		po.Now, po.Pause = r.clk.Now, r.clk.Pause
		if o.quick {
			po.ReadTimeout, po.SwitchTimeout = 300*time.Millisecond, 300*time.Millisecond
		}
		r.plugs = plugs.New(po)
	}
	d := agent.Deps{Collector: agenttest.NewCollector(), Version: "test", Relay: r.relay, Plugs: r.plugs, Helper: o.helper,
		Power: agent.NewPower(r.power, cfg.PowerControl.MinDelayS)}
	if !o.noGate {
		gopts := approval.Options{Files: approval.Files{Path: r.trust}, EnforcedBy: api.EnforcedByAgent, Log: slog.New(slog.NewTextHandler(r.log, nil))}
		if o.gateOpt != nil {
			o.gateOpt(&gopts)
		}
		r.gate = approval.NewGate(gopts)
		switch o.trust {
		case "":
			in := r.iss.Init()
			c, ref := r.gate.Challenge(api.TrustSetRequest(in))
			if ref != nil {
				t.Fatal(ref)
			}
			if st, ref := r.gate.Init(r.iss.Prove(time.Now(), in, api.MachineEntry{MachineID: in.MachineID, Challenge: c.Challenge, Request: c.Request})); ref != nil || st.State != api.ApprovalRequired {
				t.Fatalf("first-time set: %+v, %v", st, ref)
			}
		case "admin": // written on the machine, as helper-trust set does (for a gate that only reads)
			tr, err := approval.FromInit(r.iss.Init(), time.Now(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := (approval.Files{Path: r.trust}).Replace(tr); err != nil {
				t.Fatal(err)
			}
		case "broken":
			r.breakTrust(t)
		}
		d.Approval = r.gate
	}
	r.poll()
	srv := httptest.NewServer(agent.New(cfg, agent.Tokens{Read: readTok, Control: ctlTok}, d).Handler())
	t.Cleanup(srv.Close)
	r.base = srv.URL
	return r
}

// breakTrust puts a trust file there that cannot be used.
func (r *plugRig) breakTrust(t *testing.T) {
	t.Helper()
	if err := os.WriteFile(r.trust, []byte("damaged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := r.gate.StatusNow(); st.State != api.ApprovalBroken {
		t.Fatalf("the damaged trust file counts as %s", st.State)
	}
}

// poll reads the meters and the sockets once, as the agent's loops do every few seconds.
func (r *plugRig) poll() {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	r.relay.PollOnce(ctx)
	r.plugs.PollOnce(ctx)
}

// metrics is GET /metrics, made anew (past the kept answer).
func (r *plugRig) metrics(t *testing.T) (map[string]any, string) {
	t.Helper()
	time.Sleep(260 * time.Millisecond)
	st, hdr, body := r.call(t, "GET", "/metrics", readTok, nil)
	if st != 200 {
		t.Fatalf("/metrics: %d %s", st, body)
	}
	_ = hdr
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	return m, body
}

// call sends one request and returns the status, the headers and the body as it came.
func (r *plugRig) call(t *testing.T, method, path, tok string, body any) (int, http.Header, string) {
	t.Helper()
	var rd io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case string:
		rd = bytes.NewReader([]byte(b))
	default:
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, r.base+path, rd)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, string(out)
}

// sockets are the "sockets" of the row of one power source in /metrics (nil: the row has none), and the row.
func socketsOf(t *testing.T, m map[string]any, source string) ([]map[string]any, map[string]any) {
	t.Helper()
	rows, _ := m["power_sources"].([]any)
	for _, raw := range rows {
		row, _ := raw.(map[string]any)
		if row["id"] != source {
			continue
		}
		list, has := row["sockets"].([]any)
		if !has {
			return nil, row
		}
		out := make([]map[string]any, 0, len(list))
		for _, s := range list {
			out = append(out, s.(map[string]any))
		}
		return out, row
	}
	t.Fatalf("/metrics has no power source %s", source)
	return nil, nil
}
