// Package collect reads this machine's metrics for fairy-agent: CPU, memory, disks, network, sensors, GPUs,
// component power and processes. Every value comes from a documented, read-only user-mode interface (procfs and
// sysfs on Linux; Win32 APIs, the registry and PDH on Windows; nvidia-smi for NVIDIA GPUs; optionally the
// shared memory the Core Temp program publishes for other programs). Nothing here opens a driver of its own,
// reads another process's memory or changes anything on the machine.
//
// The JSON field names and units are the panel's agent contract (Fairy-dashboard's internal/normalise/agent.go):
// bytes, bytes per second counters, percent, degrees Celsius, RPM, volts, watts, Unix seconds.
package collect

import (
	"context"
	"time"
)

// Platform is the `platform` block: OS family and a human-readable OS name.
type Platform struct {
	System string `json:"system"` // Linux | Windows
	Pretty string `json:"pretty"` // e.g. "Ubuntu 24.04.1 LTS", "Windows 11 Pro 24H2"
}

// CPU is the `cpu` block. Percent is the whole-machine busy share since the previous sample.
type CPU struct {
	Percent  *float64 `json:"percent"`
	Logical  int      `json:"logical"`
	Physical *int     `json:"physical,omitempty"`
}

// Memory is the `memory` block (bytes). Used excludes caches the OS can drop (total - available).
type Memory struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
}

// Disk is one mounted filesystem (bytes).
type Disk struct {
	Mount  string `json:"mount"`
	FSType string `json:"fstype"`
	Total  int64  `json:"total"`
	Used   int64  `json:"used"`
}

// Net holds cumulative byte counters of the physical network interfaces; the panel turns them into rates.
type Net struct {
	BytesRecv int64 `json:"bytes_recv"`
	BytesSent int64 `json:"bytes_sent"`
}

// Temp is one temperature sensor (degrees Celsius).
type Temp struct {
	Sensor   string   `json:"sensor"`
	Label    *string  `json:"label"`
	Current  float64  `json:"current"`
	High     *float64 `json:"high,omitempty"`
	Critical *float64 `json:"critical,omitempty"`
}

// Fan is one fan speed sensor.
type Fan struct {
	Name string  `json:"name"`
	RPM  float64 `json:"rpm"`
}

// Voltage is one voltage sensor.
type Voltage struct {
	Name  string  `json:"name"`
	Volts float64 `json:"volts"`
}

// GPU is one graphics card.
type GPU struct {
	Index       int      `json:"-"`
	UUID        string   `json:"-"`
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor"` // nvidia | amd | intel | other
	UtilPercent *float64 `json:"util_percent"`
	VRAMUsed    *int64   `json:"vram_used"`
	VRAMTotal   *int64   `json:"vram_total"`
	TempC       *float64 `json:"temp_c"`
	PowerW      *float64 `json:"power_w"`
}

// PowerSensor is one named component power reading (e.g. "rapl package-0").
type PowerSensor struct {
	Name  string  `json:"name"`
	Watts float64 `json:"watts"`
}

// Power is the `power` block: component power (not wall power). Nil fields are unknown.
type Power struct {
	CPUPackageW  *float64      `json:"cpu_package_w"`
	GPUW         *float64      `json:"gpu_w"`
	BatteryW     *float64      `json:"battery_w"`
	BatteryState *string       `json:"battery_state"`
	BMCW         *float64      `json:"bmc_w"`
	BMCNote      *string       `json:"bmc_note,omitempty"`
	Sensors      []PowerSensor `json:"sensors"`
	Source       []string      `json:"source"`
}

// Empty reports whether the block carries no reading at all (then it is left out of /metrics).
func (p *Power) Empty() bool {
	return p == nil || (p.CPUPackageW == nil && p.GPUW == nil && p.BatteryW == nil && p.BatteryState == nil &&
		p.BMCW == nil && len(p.Sensors) == 0)
}

// Hardware is the `hardware` block (SMBIOS strings and the CPU model).
type Hardware struct {
	SystemVendor *string `json:"system_vendor"`
	SystemModel  *string `json:"system_model"`
	BoardVendor  *string `json:"board_vendor"`
	BoardModel   *string `json:"board_model"`
	BIOSVersion  *string `json:"bios_version"`
	CPUModel     *string `json:"cpu_model"`
}

// Static is what does not change while the agent runs (read once at start, refreshed rarely).
type Static struct {
	Hostname string
	Platform Platform
	Logical  int
	Physical *int
	Hardware *Hardware
}

// Sample is one reading of the changing values.
type Sample struct {
	CPUPercent *float64
	Memory     Memory
	Disks      []Disk
	Net        Net
	UptimeS    *int64
	LoadAvg    []float64 // nil where the OS has no load average (Windows)
	Temps      []Temp
	Fans       []Fan
	Voltages   []Voltage
	Power      Power          // CPU package (RAPL) and battery; GPU power is added from the GPU reader
	Battery    *BatteryStatus // nil without a system battery
}

// Process is one row of /processes. CPUPercent is of one CPU (a busy 4-thread process shows ~400).
type Process struct {
	PID         int      `json:"pid"`
	Name        *string  `json:"name"`
	Username    *string  `json:"username"`
	Status      *string  `json:"status"`
	CPUPercent  *float64 `json:"cpu_percent"`
	RSS         *int64   `json:"rss"`
	MemPercent  *float64 `json:"mem_percent"`
	GPUMem      *int64   `json:"gpu_mem"`
	GPUMemByGPU []int64  `json:"gpu_mem_by_gpu"`
	CreateTime  *float64 `json:"create_time"`
	Cmdline     *string  `json:"cmdline"`
}

// ProcOptions control a process listing.
type ProcOptions struct {
	Cmdline   bool                   // include the command line (Linux) / image path (Windows)
	NeverOpen map[string]bool        // Windows: lower-case image names the agent never opens a handle to
	MemTotal  int64                  // for mem_percent
	Interval  time.Duration          // CPU sampling interval when there is no recent previous sample
	GPUMem    func() map[int][]int64 // pid -> VRAM bytes per GPU index (nil = unknown)
}

// Collector reads this machine. Implementations are safe for concurrent use.
type Collector interface {
	Static() Static
	Sample(ctx context.Context) Sample
	// Processes returns every process the agent may look at (details of those it may not are skipped) and
	// the total number of processes on the machine.
	Processes(ctx context.Context, o ProcOptions) ([]Process, int, error)
}

// P returns a pointer to v.
func P[T any](v T) *T { return &v }
