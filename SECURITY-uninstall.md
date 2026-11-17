# Security test: "Uninstall agent" (0.11.0)

An attacker's pass over the feature as built in Fairy-agent `61bddc6..` and Fairy-dashboard `b1b303f..`, row by
row from the plan. Each row names the tests that hold it, or why it is out of scope. Tests run on Windows 11 (the
dev machine) and must run green on Linux CI too; the Windows-only rows are on the VM card (TEST-ON-WINDOWS.md,
section 17).

Fairy-agent test names are in `pkg/approval/uninstall_test.go` (gate), `pkg/agent/uninstall_route_test.go`
(route), `pkg/agent/uninstall_helper_test.go` (agent + real helper over a pipe), `pkg/agent/uninstall_marker_test.go`
(the Windows request file), `pkg/helper/uninstall_test.go` (helper), `pkg/helper/proto/*` (pipe protocol),
`pkg/agent/uninstall_linux_test.go` (Linux unit and polkit rule). Fairy-dashboard: `internal/web/uninstall_test.go`,
`internal/agentcontract/uninstall_test.go` (the panel against the real agent), and the route matrix tests.

## The attacks

| # | Attacker | Tries | Result | Held by |
|---|---|---|---|---|
| 1 | Anyone on the network | no token, the read token, a wrong control token (another, one character more, other case) | 401, before the passkey check is looked at; nothing started | `TestUninstallNeedsAnApproval`, `TestUninstallTokensAndBudget` |
| 2 | A program that squats port 9101 and so holds the control token | no approval | 403 `approval_required` | `TestUninstallNeedsAnApproval`, `TestE2EUninstallApproved`, `TestUninstallThroughAgentAndHelper` |
| 3 | same | replays a captured, used approval | 403 `approval_refused`; started once | `TestUninstallNeedsItsOwnApprovalEveryTime`, `TestUninstallNeedsAnApproval`, `TestE2EUninstallApproved`, `TestHelperUninstallNeedsItsApproval` |
| 4 | same | an approval made for a shutdown / update / fan change, or an uninstall approval used as a shutdown | refused both ways; the right request still works afterwards (nothing used up) | `TestUninstallApprovalIsForUninstallOnly`, `TestE2EUninstallApproved`, `TestHelperUninstallNeedsItsApproval` |
| 5 | same | an approval for another host (its challenge), or one made for machine B carrying machine A's challenge, or the entry rewritten to A's id | refused (`nonce`) | `TestUninstallIsBoundToTheMachine`, `TestE2EUninstallApproved` (pc-a's approval on pc-b) |
| 6 | same | an approval that also lists other machines or a shutdown ("one touch, everything") | refused (`one_entry`), nothing used up | `TestUninstallTakesAnApprovalOfOneEntryOnly` |
| 7 | same | its own approvals: another key under the same key id, another Pocket ID client, another issuer, the payload or signature changed, no signature, the entry's request rewritten | each refused, the challenge still open | `TestUninstallForgedApprovals` |
| 8 | same | an approval older than the challenge's 180 s | refused (`challenge_expired`) | `TestUninstallChallengeExpires` |
| 9 | same | the fan window, the shutdown after boot, or a confirmed run in place of an approval | refused: none stands in for it | `TestUninstallHasNoWindow` |
| 10 | same, machine without a trust file | uninstall, with or without a made-up approval; a challenge | 409 `approval_off` everywhere (agent, helper, nil gate, the agent's own gate never asked on Windows); never "needs none" | `TestUninstallIsRefusedWithoutATrustFile`, `TestUninstallRefusedWithoutTrust`, `TestHelperUninstallWithoutTrust`, `TestE2EUninstallNeedsTheCheck` |
| 11 | same, after `helper-trust clear` on the machine | a trust of its own and the uninstall in one passkey touch | the uninstall is refused (`one_entry`); without trust it is refused anyway; a first-time trust set needs its own proven approval (existing trust tests) | `TestUninstallNotInTheSameApprovalAsTheTrust` |
| 12 | same | many requests in a burst | 429 from the control budget; nothing started | `TestUninstallTokensAndBudget` |
| 13 | same | two good approvals at the same moment, or a second request after one was started | one removal; the second 409 `uninstall_in_progress` before its approval is used | `TestUninstallOnceUnderConcurrency`, `TestHelperUninstallNeedsItsApproval`, `TestUninstallThroughAgentAndHelper` |
| 14 | same (Windows) | uninstall while an update is installing | 409 `updater_busy`; the approval is not used up | `TestHelperUninstallWhileTheUpdaterRuns`, `TestHelperUninstallStartThatFails` |
| 15 | a process running as `NT SERVICE\fairy-agent` | writes the helper's request file | the folder is administrators / SYSTEM only (the trust file's folder); the updater checks folder and file owner and permissions before it reads, and refuses one that does not pass | `TestUninstallMarkerChecks`; **VM: U5 (`icacls`)** |
| 16 | same | writes a well-formed, fresh request into `update\stage\` (the one folder it may write) and starts the updater | ignored: the stage is never read for this | code: only `agent.WindowsUninstallMarker` (the helper's folder) is read; **VM: U5** |
| 17 | same | starts `fairy-agent-update` directly | the updater finds no request and does what it always did | `uninstallFromPanel` returns "not handled" on `ErrNoUninstallMarker`; **VM: U5** |
| 18 | same | puts a link / junction at the request's path | not followed, nothing acted on, the target left alone | `TestUninstallMarkerLinkIsNotFollowed`, `TestUninstallMarkerChecks` (a folder in its place) |
| 19 | same | an old request, one from the future, or a request that is not exactly the helper's | taken away, not acted on | `TestUninstallMarkerMustBeFresh`, `TestUninstallMarkerContent` |
| 20 | same | the agent as LocalSystem (not migrated yet) removing services itself | there is no such path: the only callers of `removeServices` are the administrator's `fairy-agent uninstall` and the updater after a verified request | code review (draft hole 3) |
| 21 | a local user without admin rights on Windows | opens the helper's pipe | refused by the pipe's ACL and the helper's identity check, unchanged by this feature | existing pipe tests (`pkg/helper/winpipe`) |
| 22 | a process already running as the `fairy-agent` user on Linux | `systemctl start fairy-agent-uninstall.service` | **succeeds: accepted limit** (as for the power and update rules); config and tokens stay | documented in AGENT.md; `TestUnitUninstallerStartsTheOneUnit` (Linux only: runs on CI) holds that the rule allows exactly `start` of exactly that unit for exactly that user |
| 23 | any other Linux user | starts the unit | polkit denies (the rule names only the `fairy-agent` user); the unit and rule exist only while `uninstall.enabled` is on | `TestUnitUninstallerStartsTheOneUnit` (rule text), install.sh |
| 24 | malformed input | unknown or duplicate members in the HTTP body; members the pipe verb does not take; a challenge with members | 400 / refused; the helper keeps running | `TestUninstallNeedsAnApproval` (unknown member), `TestUninstallRequest`, `FuzzUninstallFrames` (2.4 M inputs, 60 s, no finding) |
| 25 | the panel's side | a viewer, an API token, no CSRF header, the kill switch, a wrong typed name, an agent that does not offer it, a machine without the check | refused before Pocket ID is asked and before the machine is asked anything; every refusal audited | `TestUninstallRefusedByThePanel`, `TestUninstallWithoutTrust`, `TestAPITokensRefusedOnSignInOnlyActions`, `TestRouteAuthMatrix`, `TestE2EUninstallOffOnTheMachine` |
| 26 | a panel that was taken over, or a machine that lies | a machine answers "needs no approval" for uninstall | not believed, nothing sent | `TestUninstallNeverWithoutApproval` |
| 27 | the panel's record is a poll behind | the trust was cleared on the machine a moment ago | the machine's own answer refuses it; nothing sent | `TestUninstallWithoutTrust` (second half) |
| 28 | fans | uninstall while a fixed fan speed is set | Windows: the helper is stopped before it is deleted (its stop hands the fans to the BMC); Linux: the script stops the agent first, whose `ExecStopPost` runs `fans-auto`, before the program is removed | code; **VM: U8** |

## Holes of the draft, checked again

1. **No passkey approval**: closed. Uninstall is a strict verb (`pkg/approval/strict.go`); the panel never sends
   it without an approval and the machine never runs it without one (rows 2-11).
2. **The updater trusted a file in the stage folder**: closed. The request lives in the helper's administrators-only
   folder, is written only after the helper verified the approval, is checked like the trust file, taken away
   before anything is done, and only a fresh one is acted on (rows 15-19).
3. **The "do it myself" fallback**: closed. No route in the agent reaches `removeServices` (row 20).
4. **The updater's start type changed before its delete**: closed. Nothing changes a start type; the updater
   deletes itself last and is gone when its run ends; there is no boot-time self-cleanup.

## Logs and answers

No token in what the browser gets (`TestE2EUninstallApproved`: `noLeak`), in the gate's log
(`TestUninstallNeedsAnApproval`), or in the helper's audit log (`TestHelperUninstallNeedsItsApproval`). The agent
logs who asked (`requested_by`, the panel's name for the person) and the remote address; the helper's "by" is cut to
its allowed letters (`helperBy`). The panel's audit says `approval: sent`, never the approval.

## Accepted limits

* Row 22: on Linux a process that already runs as the `fairy-agent` user can start the removal unit without an
  approval. It could already shut the machine down through the power rule. Config and tokens stay.
* A removal that fails halfway (Windows: a service that will not stop; Linux: the script's own problems) leaves a
  half-removed agent; the log says what, and `deploy/uninstall-fairy-agent.ps1` / `.sh` finish it.
* A request file the updater refuses because its folder or file does not pass the checks stays where it is and
  stops that run of the updater (an update too) until an administrator looks: only an administrator could have
  made that folder fail the check.
* The program folder on Windows goes at the next reboot, not at once (the updater runs from it).

## Not run here

* `govulncheck`: not installed, and this machine cannot reach GitHub or the vulnerability database through its
  proxy. Run it in CI or on a machine with network: `go install golang.org/x/vuln/cmd/govulncheck@latest &&
  govulncheck ./...` in both repos.
* `staticcheck` / `gosec`: not installed. `go vet` is clean in both repos (agent: windows and linux).
* The Windows rows 15-17 and 28 need the VM (section 17, U5 and U8).
* About 108 agent and 17+11 panel tests fail on this machine with and without this feature (symbolic links without
  Developer Mode, file permissions, run records); none is new, compared test by test against the code before it.
