//go:build !windows

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// ApprovalFiles is the approval trust file of this machine. Not Windows: in the agent's state folder (Linux:
// /var/lib/fairy-agent, the only place the agent's user can write), because the agent itself writes it at the
// first-time set. The folder and the file must belong to root or to the agent's own user and be writable by
// nobody else (approval.UnixCheckDir, UnixCheckFile).
func ApprovalFiles(cfg *Config) approval.Files {
	return approval.UnixFiles(filepath.Join(filepath.Dir(PairingPath(cfg)), approval.TrustFileName))
}

// SystemUptime is the time since the system started (Linux: /proc/uptime, the same as "uptime_s" of /metrics).
// Unknown on other systems, where the shutdown-after-boot setting therefore never applies.
func SystemUptime() (time.Duration, error) {
	if runtime.GOOS != "linux" {
		return 0, errors.New("uptime is not known on " + runtime.GOOS)
	}
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	s := collect.ParseUptime(b)
	if s == nil || *s < 0 {
		return 0, errors.New("/proc/uptime: not a number")
	}
	return time.Duration(*s) * time.Second, nil
}
