//go:build windows

package agent

import (
	"path/filepath"
	"time"

	"golang.org/x/sys/windows"

	"github.com/n3ptune-cpu/Fairy-agent/pkg/agent/collect"
	"github.com/n3ptune-cpu/Fairy-agent/pkg/approval"
)

// ApprovalFiles is the approval trust file of this machine. Windows: in the helper's own folder
// (C:\ProgramData\fairy-agent\helper), which only Administrators and SYSTEM may change and the agent's account
// may only read; the folder and the file are checked like the helper's other files (collect.TrustedFolder,
// collect.TrustedFile) before the file counts.
func ApprovalFiles(cfg *Config) approval.Files {
	return approval.Files{Path: filepath.Join(cfg.Dir(), "helper", approval.TrustFileName),
		CheckDir: collect.TrustedFolder, CheckFile: collect.TrustedFile}
}

// SystemUptime is the time since Windows started (GetTickCount64, the same clock as "uptime_s" of /metrics).
func SystemUptime() (time.Duration, error) { return windows.DurationSinceBoot(), nil }

// SystemBootID: Windows has no id of its boot that a service can simply read, so there is none here and "the
// one shutdown after boot was used in this boot" is told from the time it was recorded and the uptime
// (approval.Gate.usedThisBoot).
func SystemBootID() (string, error) { return "", nil }

// ApprovalAdminFiles is ApprovalFiles for the administrator's command (fairy-agent helper-trust). A file
// created in the helper's folder inherits its permissions: Administrators and SYSTEM change it, the agent's
// account reads it.
func ApprovalAdminFiles(cfg *Config) approval.Files { return ApprovalFiles(cfg) }
