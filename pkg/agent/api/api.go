// Package api holds the parts of the agent's HTTP contract that the panel (Fairy-dashboard) imports as types:
// the Windows elevated-helper block of GET /metrics, the "unavailable" list, and the /helper/stop and
// /helper/start endpoints. It has no dependencies, so the panel and the agent's test fakes can both use it.
package api

import "errors"

// Helper endpoints (POST, control token, rate limited and logged like every control action). Body: {}.
// 200 {"state": ...} with the helper's state afterwards; 409 {"error": "not_installed"} when the helper service
// is not installed (always on Linux).
const (
	PathHelperStop  = "/helper/stop"
	PathHelperStart = "/helper/start"
)

// Helper states (HelperStatus.State).
const (
	HelperRunning      = "running"       // the service runs and answered on its pipe
	HelperStopped      = "stopped"       // installed, not running (stopped by an admin or from the panel)
	HelperStarting     = "starting"      // the service manager is starting it
	HelperNotInstalled = "not_installed" // no fairy-agent-helper service on this PC
	HelperError        = "error"         // running but not answering, or the service manager could not be asked
)

// Helper feature names (HelperStatus.Features): what the helper does for the agent on this PC.
const (
	FeatureCoreTemp = "coretemp" // Core Temp's shared memory (CPU core temperatures and watts)
	FeatureIPMI     = "ipmi"     // BMC sensors through Windows' IPMI driver
	FeatureFans     = "fans"     // Supermicro fan control and the 80 °C / 30 s watchdog
	FeaturePower    = "power"    // shutdown, reboot, sleep
	FeatureUpdate   = "update"   // starting the signature-checking updater service
)

// HelperStatus is the "helper" block of GET /metrics (Windows only; Linux agents leave it out).
type HelperStatus struct {
	State string `json:"state"`
	// Needed: config.yaml switches on something that needs the helper (Core Temp, IPMI through Windows,
	// fan control or power control).
	Needed bool `json:"needed"`
	// Version of the running helper (state running only).
	Version string `json:"version,omitempty"`
	// Since: RFC 3339 time the helper started (running) or the agent first saw the current state.
	Since string `json:"since,omitempty"`
	// Watchdog: the helper's fan watchdog is active (fan control on and the helper running). Absent when the
	// helper is not running.
	Watchdog *bool `json:"watchdog,omitempty"`
	// Features the running helper serves (FeatureCoreTemp ...).
	Features []string `json:"features,omitempty"`
	// Error: what went wrong (state error only).
	Error string `json:"error,omitempty"`
}

// Running reports whether the helper answers.
func (s HelperStatus) Running() bool { return s.State == HelperRunning }

// Reasons a reading is unavailable (Unavailable.Reason, and "reason" in /fan/status and power_control).
const (
	ReasonHelperStopped = "helper_stopped" // the helper is stopped or starting: not an error
	ReasonHelperError   = "helper_error"   // the helper runs but does not answer
)

// Unavailable is one entry of the "unavailable" list of GET /metrics: a source the agent would normally read
// that is missing from this answer, and why. Only sources served by the Windows helper appear here; the list is
// left out when everything is available.
type Unavailable struct {
	Source string `json:"source"` // FeatureCoreTemp, FeatureIPMI, FeatureFans or FeaturePower
	Reason string `json:"reason"` // ReasonHelperStopped or ReasonHelperError
}

// Errors of helper-backed operations.
var (
	ErrHelperNotInstalled = errors.New("not_installed")
	ErrHelperStopped      = errors.New("helper stopped")
)
