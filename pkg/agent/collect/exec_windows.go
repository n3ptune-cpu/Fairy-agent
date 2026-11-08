//go:build windows

package collect

import (
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// lowPriority starts helper processes without a console window and below normal priority.
func lowPriority() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{HideWindow: true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.BELOW_NORMAL_PRIORITY_CLASS}
}

// LowPriority is lowPriority for other packages.
func LowPriority() *syscall.SysProcAttr { return lowPriority() }

// FindNvidiaSMI returns the absolute path of nvidia-smi.exe ("" if not installed). Only the two places the
// NVIDIA driver installs it are tried; PATH is not searched.
func FindNvidiaSMI() string {
	sys, _ := windows.GetSystemDirectory()
	pf := os.Getenv("ProgramW6432")
	if pf == "" {
		pf = `C:\Program Files`
	}
	for _, p := range []string{filepath.Join(sys, "nvidia-smi.exe"), filepath.Join(pf, "NVIDIA Corporation", "NVSMI", "nvidia-smi.exe")} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
