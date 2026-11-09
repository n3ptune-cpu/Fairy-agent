// Package agenttest has fakes for the agent's tests and the panel contract test: a collector that describes the
// owner's Windows PC (Supermicro X11SCA-F, RTX 2080 SUPER), a GPU reader and a power executor.
package agenttest

import (
	"context"
	"sync"
	"time"

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
			{PID: 4120, Name: collect.P("obs64.exe"), Username: collect.P(`NSX-CYRENE\neptune`), Status: collect.P("running"),
				CPUPercent: collect.P(9.5), RSS: collect.P(int64(620 << 20)), Cmdline: collect.P(`C:\Program Files\obs-studio\bin\64bit\obs64.exe`)},
			{PID: 5000, Name: collect.P("backup.exe"), Username: collect.P(`NSX-CYRENE\neptune`), Status: collect.P("running"),
				CPUPercent: collect.P(3.0), RSS: collect.P(int64(80 << 20)), Cmdline: collect.P("backup.exe --password=hunter2 --target s3")},
			{PID: 6000, Name: collect.P("Ollama.exe"), Status: collect.P("running"), CPUPercent: collect.P(30.0),
				RSS: collect.P(int64(5200 << 20))},
			{PID: 7000, Name: collect.P("VALORANT-Win64-Shipping.exe"), Status: collect.P("running")}, // never opened
		}}
}

// Static describes the PC.
func (c *Collector) Static() collect.Static {
	return collect.Static{Hostname: "NSX-CYRENE", Platform: collect.Platform{System: "Windows", Pretty: "Windows 11 Enterprise 24H2"},
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
