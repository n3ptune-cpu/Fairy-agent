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

// SystemBootID is the id of this boot as the agent reads it: the value the helper keeps in a volatile registry
// key (bootid.go). The agent's account only reads the key; before the helper has made it in this boot there is
// no id, and a record of the helper's is then not "of this boot" for the agent.
func SystemBootID() (string, error) { return bootIDFrom(winBootKey{}, nil, false) }

// SystemBootIDOwner is SystemBootID for whoever may make the key when it is not there: the helper (it runs
// as SYSTEM) and the administrator's command (fairy-agent helper-run).
func SystemBootIDOwner() (string, error) { return bootIDFrom(winBootKey{}, nil, true) }

// ApprovalAdminFiles is ApprovalFiles for the administrator's command (fairy-agent helper-trust). A file
// created in the helper's folder inherits its permissions: Administrators and SYSTEM change it, the agent's
// account reads it.
func ApprovalAdminFiles(cfg *Config) approval.Files { return ApprovalFiles(cfg) }
