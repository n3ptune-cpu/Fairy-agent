# Testing 0.5.0 on Windows (agent + helper)

0.5.0 moves the Windows agent to its own low-rights account and adds the **fairy-agent-helper** service (see
AGENT.md, "Two services"). None of this has run on real Windows yet. Try it on **one** PC first, ideally one
with Core Temp or power control switched on so the helper gets installed. **Not on NSX-CYRENE** (its fans)
until this list has passed somewhere else.

Everything below is in **PowerShell as Administrator**. `$fa` is short for the program:

```powershell
$fa = "C:\Program Files\Fairy\fairy-agent.exe"
```

## 1. Install or update

Either re-pair from the panel (Re-pair on the host's page, run the command it shows: it uses the latest
release), or by hand with the release files in one folder:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-fairy-agent.ps1 -PanelAddress 100.88.109.47            # add -Helper if config.yaml has none of
                                                                 # Core Temp / IPMI / power control yet
& $fa version                                     # fairy-agent 11-xxxxxxx ... (build 11 or later = 0.5.0)
```

Expected: no red errors; the end shows `fairy-agent` (and, where needed, `fairy-agent-helper`) as Running.

## 2. The accounts

```powershell
sc.exe qc fairy-agent           # SERVICE_START_NAME : NT SERVICE\fairy-agent
sc.exe qprivs fairy-agent       # PRIVILEGES : SeChangeNotifyPrivilege   (only this one)
sc.exe qsidtype fairy-agent     # SERVICE_SID_TYPE: UNRESTRICTED
sc.exe qc fairy-agent-helper    # SERVICE_START_NAME : LocalSystem
sc.exe qprivs fairy-agent-helper  # SeChangeNotifyPrivilege, SeImpersonatePrivilege, SeShutdownPrivilege
& $fa helper-status             # both accounts, "helper: running", and its features
```

**whoami of the running agent** (there is no whoami for a service; this shows the account its process runs as):

```powershell
$p = (Get-CimInstance Win32_Service -Filter "Name='fairy-agent'").ProcessId
(Get-CimInstance Win32_Process -Filter "ProcessId=$p" | Invoke-CimMethod -MethodName GetOwner) | Select Domain, User
#   Domain: NT SERVICE   User: fairy-agent
$p = (Get-CimInstance Win32_Service -Filter "Name='fairy-agent-helper'").ProcessId
(Get-CimInstance Win32_Process -Filter "ProcessId=$p" | Invoke-CimMethod -MethodName GetOwner) | Select Domain, User
#   Domain: NT AUTHORITY   User: SYSTEM
```

Folder permissions (config readable by the agent, helper log admin-only):

```powershell
icacls C:\ProgramData\fairy-agent           # NT SERVICE\fairy-agent:(OI)(CI)(RX)
icacls C:\ProgramData\fairy-agent\logs      # NT SERVICE\fairy-agent:(OI)(CI)(M) or similar (write)
icacls C:\ProgramData\fairy-agent\helper    # NT SERVICE\fairy-agent:(OI)(CI)(RX), owner Administrators
Get-NetFirewallRule -DisplayName "Fairy agent helper (no network)" | Select Direction, Action   # Outbound/Inbound Block
```

## 3. Readings

In the panel, the host's page: CPU, memory, disks as before; with Core Temp: the "Core 0..." temperatures and
CPU watts; with a BMC: the IPMI sensors and the fan box. The Processes tab works, but programs of other
accounts (games, browser) show **name only** now (expected, see AGENT.md).

From the panel machine (or look at the panel's raw view): `curl -s -H "Authorization: Bearer <token>"
http://<pc>:9101/metrics` contains `"helper":{"state":"running", ... "features":[...]}` and no `"unavailable"`.

Logs: `Get-Content C:\ProgramData\fairy-agent\logs\agent.log -Tail 30` (no "access denied", no warning about
LocalSystem / LocalService) and `Get-Content C:\ProgramData\fairy-agent\helper\helper.log -Tail 30` ("helper
started" with the features).

## 4. Stop the helper

If a BMC is there: first set a fixed fan speed in the panel (mode Full, e.g. 50 %).

```powershell
Stop-Service fairy-agent-helper
```

Expected, within a few seconds:

* fans: back to the BMC's automatic mode (the panel's fan box, or the BMC's web page; helper.log says "helper
  stopping: fans in BMC mode");
* the panel still shows the host, without Core Temp / IPMI values; `/metrics` has `"helper":{"state":"stopped"}`
  and `"unavailable":[{"source":...,"reason":"helper_stopped"}]`; `/fan/status` says `"available":false,
  "reason":"helper_stopped"` (no error);
* agent.log says "fairy-agent-helper: stopped" (info, not an error) and "Core Temp readings: helper stopped".

## 5. Start it again

```powershell
Start-Service fairy-agent-helper
```

Readings come back within about 10 s; `/metrics` says `running` again; `& $fa helper-status` is happy.

## 6. Optional: power

With power control on: in the panel, Reboot (or Sleep, if the PC supports it) with a 60 s delay; Windows shows
its countdown; Cancel in the panel stops it. Then once for real if convenient. helper.log lists each request
with who asked.

## 7. Optional: watchdog

Only where safe: with a fixed speed set, `Stop-Service fairy-agent` (the agent, not the helper). The fans keep
their speed and the helper's watchdog keeps watching (helper.log). `Start-Service fairy-agent` afterwards.

## Rollback (back to build 10 / v0.4.4)

0.4.4 does not know the helper or the new account, so remove 0.5's services first. Config and tokens stay, the
panel needs nothing new.

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" uninstall        # stops both (fans back to the BMC), removes all three services
Get-NetFirewallRule -DisplayName "Fairy agent helper (no network)" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# then, in a folder with build 10's files (fairy-agent-windows-amd64.exe, SHA256SUMS and install-fairy-agent.ps1
# from https://github.com/n3ptune-cpu/Fairy-agent/releases/tag/v0.4.4):
Set-ExecutionPolicy -Scope Process Bypass
.\install-fairy-agent.ps1 -PanelAddress 100.88.109.47 -LocalSystem   # -LocalSystem only if this PC used Core Temp / fans
```

Report back: the output of section 2, the last 30 lines of both logs, and anything that differed.
