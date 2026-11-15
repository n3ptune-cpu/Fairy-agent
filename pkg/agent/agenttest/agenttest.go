// Package agenttest has fakes for the agent's tests and the panel contract test: a collector that describes the
// owner's Windows PC (Supermicro X11SCA-F, RTX 2080 SUPER), a GPU reader, a power executor and the Windows
// elevated helper.
package agenttest

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/api"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
)

const gib = 1 << 30

// Collector is a fixed machine whose network counters grow by NetStep per sample.
type Collector struct {
	mu      sync.Mutex
	NetStep int64
	net     collect.Net
	Procs   []collect.Process
	Total   int
	Temps   []collect.Temp
}

// NewCollector returns the fake PC.
func NewCollector() *Collector {
	return &Collector{NetStep: 1_000_000, net: collect.Net{BytesRecv: 5e9, BytesSent: 2e9}, Total: 212,
		Temps: []collect.Temp{{Sensor: "acpi", Label: collect.P("ACPI thermal zone TZ00"), Current: 27.8}},
		Procs: []collect.Process{
			{PID: 4120, Name: collect.P("obs64.exe"), Username: collect.P(`AGENT-1\user`), Status: collect.P("running"),
				CPUPercent: collect.P(9.5), RSS: collect.P(int64(620 << 20)), Cmdline: collect.P(`C:\Program Files\obs-studio\bin\64bit\obs64.exe`)},
			{PID: 5000, Name: collect.P("backup.exe"), Username: collect.P(`AGENT-1\user`), Status: collect.P("running"),
				CPUPercent: collect.P(3.0), RSS: collect.P(int64(80 << 20)), Cmdline: collect.P("backup.exe --password=hunter2 --target s3")},
			{PID: 6000, Name: collect.P("Ollama.exe"), Status: collect.P("running"), CPUPercent: collect.P(30.0),
				RSS: collect.P(int64(5200 << 20))},
			{PID: 7000, Name: collect.P("VALORANT-Win64-Shipping.exe"), Status: collect.P("running")}, // never opened
		}}
}

// Static describes the PC.
func (c *Collector) Static() collect.Static {
	return collect.Static{Hostname: "AGENT-1", Platform: collect.Platform{System: "Windows", Pretty: "Windows 11 Enterprise 24H2"},
		Logical: 16, Physical: collect.P(8),
		Hardware: &collect.Hardware{SystemVendor: collect.P("System manufacturer"), SystemModel: collect.P("System Product Name"),
			BoardVendor: collect.P("Supermicro"), BoardModel: collect.P("X11SCA-F"), BIOSVersion: collect.P("1.8"),
			CPUModel: collect.P("Intel(R) Xeon(R) E-2278G CPU @ 3.40GHz")}}
}

// Sample returns fixed values; the network counters grow.
func (c *Collector) Sample(context.Context) collect.Sample {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.net.BytesRecv += c.NetStep
	c.net.BytesSent += c.NetStep / 2
	return collect.Sample{CPUPercent: collect.P(23.5), Memory: collect.Memory{Total: 64 * gib, Used: 20 * gib},
		Disks: []collect.Disk{{Mount: `C:\`, FSType: "NTFS", Total: 1000 * gib, Used: 412 * gib},
			{Mount: `D:\`, FSType: "NTFS", Total: 4000 * gib, Used: 2710 * gib}},
		Net: c.net, UptimeS: collect.P(int64(86400 * 6)), Temps: c.Temps,
		Power: collect.Power{Sensors: []collect.PowerSensor{}, Source: []string{}}}
}

// Processes returns the fixed list (with the never_open program reduced to its name, as the real collector does).
func (c *Collector) Processes(_ context.Context, o collect.ProcOptions) ([]collect.Process, int, error) {
	out := make([]collect.Process, 0, len(c.Procs))
	for _, p := range c.Procs {
		if !o.Cmdline {
			p.Cmdline = nil
		}
		if p.RSS != nil && o.MemTotal > 0 {
			p.MemPercent = collect.P(collect.Round(float64(*p.RSS)/float64(o.MemTotal)*100, 2))
		}
		out = append(out, p)
	}
	return out, c.Total, nil
}

// GPU is one RTX 2080 SUPER; Ollama uses 5 GiB of it.
type GPU struct{}

// GPUs returns the card.
func (GPU) GPUs() []collect.GPU {
	return []collect.GPU{{Index: 0, UUID: "GPU-1", Name: "NVIDIA GeForce RTX 2080 SUPER", Vendor: "nvidia",
		UtilPercent: collect.P(37.0), VRAMUsed: collect.P(int64(3 * gib)), VRAMTotal: collect.P(int64(8 * gib)),
		TempC: collect.P(61.0), PowerW: collect.P(87.5)}}
}

// ComputeApps returns Ollama's VRAM.
func (GPU) ComputeApps(context.Context) map[int][]int64 { return map[int][]int64{6000: {5 * gib}} }

// PowerExec records scheduled and cancelled actions instead of shutting anything down.
type PowerExec struct {
	mu        sync.Mutex
	Scheduled []string
	Cancels   int
	NoSleep   string // CanSleep's reason when set (the machine cannot sleep)
}

// CanSleep is true unless NoSleep is set.
func (p *PowerExec) CanSleep() (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.NoSleep == "", p.NoSleep
}

// Schedule records the action.
func (p *PowerExec) Schedule(action string, delay time.Duration, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Scheduled = append(p.Scheduled, action+"@"+delay.String())
	return nil
}

// Cancel records the cancel.
func (p *PowerExec) Cancel() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.Cancels++
	return nil
}

// Helper is a fake Windows elevated helper (fairy-agent-helper) for the panel's contract test: it starts
// running; Stop and Start switch its state (NotInstalled makes both answer api.ErrHelperNotInstalled).
type Helper struct {
	mu           sync.Mutex
	State        string
	NotInstalled bool
	Stops        int
	Starts       int
}

// NewHelper returns a running fake helper serving Core Temp, IPMI, fans and power.
func NewHelper() *Helper { return &Helper{State: api.HelperRunning} }

// Status is the /metrics "helper" block.
func (h *Helper) Status(context.Context) api.HelperStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status()
}

func (h *Helper) status() api.HelperStatus {
	if h.NotInstalled {
		return api.HelperStatus{State: api.HelperNotInstalled, Needed: true, Since: "2026-11-09T12:00:00Z"}
	}
	st := api.HelperStatus{State: h.State, Needed: true, Since: "2026-11-09T12:00:00Z"}
	if h.State == api.HelperRunning {
		wd := true
		st.Version, st.Watchdog = "0.5.0", &wd
		st.Features = []string{api.FeatureCoreTemp, api.FeatureIPMI, api.FeatureFans, api.FeaturePower}
	}
	return st
}

// Stop stops the fake.
func (h *Helper) Stop(context.Context, string) (api.HelperStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.NotInstalled {
		return h.status(), api.ErrHelperNotInstalled
	}
	h.State = api.HelperStopped
	h.Stops++
	return h.status(), nil
}

// Start starts the fake.
func (h *Helper) Start(context.Context, string) (api.HelperStatus, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.NotInstalled {
		return h.status(), api.ErrHelperNotInstalled
	}
	h.State = api.HelperRunning
	h.Starts++
	return h.status(), nil
}

// The made-up plugs of PlugConfig: a powerbar with three sockets, the plug that feeds the whole corner the
// agent stands in, and the plug the agent's own machine hangs on. The ids of the sources and the sockets, and
// the entity ids a fake Home Assistant has to know (pkg/plugs/hatest).
const (
	PlugBar        = "desk-bar"                    // power source: "Monitor powerbar", sockets ch1, ch2, ch3
	PlugBarSensor  = "sensor.desk_bar_power"       //
	PlugBar1       = "switch.desk_bar_socket_1"    // ch1 "Left monitor"
	PlugBar2       = "switch.desk_bar_socket_2"    // ch2 (no name)
	PlugBar3       = "switch.desk_bar_socket_3"    // ch3 "Lamp": in no list
	PlugCorner     = "server-corner"               // power source, socket main "Server corner"
	PlugCornerSens = "sensor.server_corner_power"  //
	PlugCornerSw   = "switch.server_corner_socket" // the socket that must never be switched
	PlugOwn        = "own-plug"                    // power source with system_hint: self (PlugOptions.OwnHint), socket main "This machine"
	PlugOwnSensor  = "sensor.own_plug_power"       //
	PlugOwnSw      = "switch.own_plug"             //
)

// PlugOptions say how the home_assistant block of PlugConfig is written.
type PlugOptions struct {
	// ReadEnv and SwitchEnv name the variables of the two tokens: the one the meters read with and the one of
	// the block. The test sets them.
	ReadEnv, SwitchEnv string
	Switching          bool
	// Allow is switch_allow (nil: PlugBar1, PlugBar2 and PlugOwnSw). FeedsSelf is feeds_self (nil: PlugCornerSw).
	Allow, FeedsSelf []string
	MinGapS          int // 0: 5
	// NoBlock leaves the block and every socket out: the plugs are meters only, as before sockets.
	NoBlock bool
	// OwnHint is the system_hint of PlugOwn as it is written in the file ("": self).
	OwnHint string
}

// PlugConfig is the home_assistant block and the power_sources of an agent that reads the made-up plugs from
// the Home Assistant at haURL, as config.yaml text. A caller adds its own lines in front.
func PlugConfig(haURL string, o PlugOptions) string {
	if o.Allow == nil {
		o.Allow = []string{PlugBar1, PlugBar2, PlugOwnSw}
	}
	if o.FeedsSelf == nil {
		o.FeedsSelf = []string{PlugCornerSw}
	}
	if o.MinGapS == 0 {
		o.MinGapS = 5
	}
	if o.OwnHint == "" {
		o.OwnHint = "self"
	}
	meter := func(id, name, sensor, more string) string {
		return "  - id: " + id + "\n    type: homeassistant\n    name: \"" + name + "\"\n    url: \"" + haURL + "\"\n    token_env: " + o.ReadEnv +
			"\n    entity: " + sensor + "\n" + more
	}
	sockets := func(lines ...string) string {
		if o.NoBlock {
			return ""
		}
		return "    sockets:\n      - " + strings.Join(lines, "\n      - ") + "\n"
	}
	out := ""
	if !o.NoBlock {
		out = "home_assistant:\n  url: \"" + haURL + "\"\n  token_env: " + o.SwitchEnv + "\n  switching: " + strconv.FormatBool(o.Switching) +
			"\n  switch_allow: [" + strings.Join(o.Allow, ", ") + "]\n  feeds_self: [" + strings.Join(o.FeedsSelf, ", ") + "]\n  min_gap_s: " + strconv.Itoa(o.MinGapS) + "\n"
	}
	return out + "power_sources:\n" +
		meter(PlugBar, "Monitor powerbar", PlugBarSensor, sockets(
			"{id: ch1, name: \"Left monitor\", switch_entity: "+PlugBar1+"}",
			"{id: ch2, switch_entity: "+PlugBar2+"}",
			"{id: ch3, name: Lamp, switch_entity: "+PlugBar3+"}")) +
		meter(PlugCorner, "Server corner", PlugCornerSens, sockets("{id: main, name: \"Server corner\", switch_entity: "+PlugCornerSw+"}")) +
		meter(PlugOwn, "Own plug", PlugOwnSensor, "    system_hint: "+strconv.Quote(o.OwnHint)+"\n"+sockets("{id: main, name: \"This machine\", switch_entity: "+PlugOwnSw+"}"))
}

// PlugStates are the states a fake Home Assistant starts with for PlugConfig's switches: the first socket of
// the bar on, the second off, everything else on. (Its sensors are set with hatest's SetSensor.)
func PlugStates() map[string]string {
	return map[string]string{PlugBar1: "on", PlugBar2: "off", PlugBar3: "on", PlugCornerSw: "on", PlugOwnSw: "on"}
}
