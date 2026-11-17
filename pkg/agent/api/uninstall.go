package api

// PathUninstall is the panel's "Uninstall agent": POST with the control token, counted in the control budget and
// logged like every control action. It is open only while the machine's config.yaml says uninstall.enabled
// (404 CodeUninstallDisabled otherwise, and on a system where nothing can carry it out), and it is never
// carried out without a passkey approval (ApproveUninstall, a strict verb: 409 approval_off on a machine
// without a trust file, 403 approval_required / approval_refused as for every approved request).
//
// Body: UninstallRequest. Answers:
//
//	202 {"state": "uninstalling"}  the removal is under way; the agent goes offline within seconds and does not
//	                               answer again. Config, tokens and logs stay on the machine.
//	409 {"code": "uninstall_in_progress"}  one was already started by this process
//	409 {"code": "helper_required"}        Windows: the helper is not installed
//	409 {"code": "updater_busy"}           Windows: the updater service is installing an update
//	502 {"error": ...}             the removal could not be started (the approval was used up)
const PathUninstall = "/uninstall"

// UninstallRequest is the body of POST /uninstall. Nothing in it chooses what is removed: that is fixed on the
// machine.
type UninstallRequest struct {
	Approval    *Approval `json:"approval,omitempty"`
	RequestedBy string    `json:"requested_by,omitempty"` // who, for the machine's log (cleaned and cut there)
}

// UninstallStarted is the "state" of a 202 answer.
const UninstallStarted = "uninstalling"

// Codes of POST /uninstall's own refusals (the passkey check has its own: approval.go).
const (
	CodeUninstallDisabled = "uninstall_disabled"    // off in config.yaml, or nothing on this system can do it
	CodeUninstallBusy     = "uninstall_in_progress" // this process already started one
	// Windows: the helper checks the approval and carries the uninstall out, so without it there is none.
	CodeHelperRequired = "helper_required"
	// Windows: the updater service, which removes the services, is busy with an update.
	CodeUpdaterBusy = "updater_busy"
)
