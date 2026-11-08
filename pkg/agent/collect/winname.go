package collect

import (
	"strings"
	"time"
)

// WindowsPretty builds "Windows 11 Pro 24H2" from the registry's ProductName, DisplayVersion and build number.
// Windows 11 still says "Windows 10" in ProductName; build 22000 and later is Windows 11.
func WindowsPretty(product, displayVersion string, build int) string {
	p := strings.TrimSpace(product)
	if p == "" {
		p = "Windows"
	}
	if build >= 22000 && strings.Contains(p, "Windows 10") {
		p = strings.Replace(p, "Windows 10", "Windows 11", 1)
	}
	if v := strings.TrimSpace(displayVersion); v != "" {
		p += " " + v
	}
	return p
}

// filetimeEpochDelta is the number of 100 ns intervals between 1601-01-01 and 1970-01-01.
const filetimeEpochDelta = 116444736000000000

// FiletimeToUnix converts a Windows FILETIME (100 ns since 1601) to Unix seconds.
func FiletimeToUnix(ft uint64) float64 {
	if ft < filetimeEpochDelta {
		return 0
	}
	return float64(ft-filetimeEpochDelta) / 1e7
}

// KelvinToC converts the thermal-zone counter (Kelvin) to degrees Celsius; ok is false for readings that are
// clearly not a temperature (0 K or above 150 °C).
func KelvinToC(k float64) (float64, bool) {
	c := Round(k-273.15, 1)
	return c, k > 0 && c > -40 && c < 150
}

// CPUDelta is the busy share between two GetSystemTimes samples (kernel time includes idle time).
func CPUDelta(prevIdle, prevKernel, prevUser, idle, kernel, user uint64) *float64 {
	total := (kernel - prevKernel) + (user - prevUser)
	if kernel < prevKernel || user < prevUser || idle < prevIdle || total == 0 {
		return nil
	}
	busy := float64(total) - float64(idle-prevIdle)
	v := Round(max(0, min(100, busy/float64(total)*100)), 1)
	return &v
}

// ProcCPUPercent is the CPU use (percent of one CPU) of a process whose CPU time grew by d100ns (100 ns units)
// over the wall-clock interval dt.
func ProcCPUPercent(d100ns uint64, dt time.Duration) float64 {
	if dt <= 0 {
		return 0
	}
	return Round(float64(d100ns)/1e7/dt.Seconds()*100, 1)
}
