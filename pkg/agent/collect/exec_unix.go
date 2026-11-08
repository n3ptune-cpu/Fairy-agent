//go:build !windows

package collect

import (
	"os"
	"os/exec"
	"syscall"
)

// lowPriority: on Linux the systemd unit already runs the agent (and its children) at low priority.
func lowPriority() *syscall.SysProcAttr { return nil }

// LowPriority is lowPriority for other packages.
func LowPriority() *syscall.SysProcAttr { return nil }

// FindNvidiaSMI returns the absolute path of nvidia-smi ("" if not installed).
func FindNvidiaSMI() string {
	for _, p := range []string{"/usr/bin/nvidia-smi", "/usr/local/bin/nvidia-smi"} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath("nvidia-smi"); err == nil {
		return p
	}
	return ""
}
