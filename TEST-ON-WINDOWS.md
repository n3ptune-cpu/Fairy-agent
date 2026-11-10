# Testing 0.5.x and 0.6.0 on Windows (agent + helper, self-migration, security fixes)

0.5.0 moves the Windows agent to its own low-rights account and adds the **fairy-agent-helper** service (see
AGENT.md, "Two services"). None of this has run on real Windows yet. Try it on **one** PC first, ideally one
with Core Temp or power control switched on so the helper gets installed. **Not on the PC whose fans Fairy
controls** until this list has passed somewhere else.

Everything below is in **PowerShell as Administrator**. `$fa` is short for the program:

```powershell
$fa = "C:\Program Files\Fairy\fairy-agent.exe"
```

## 1. Install or update

Either re-pair from the panel (Re-pair on the host's page, run the command it shows: it names the release the
panel has checked), or by hand with the files of one release in one folder (downloaded and checked as in
SETUP-UPDATES.md, 2.3):

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-fairy-agent.ps1 -PanelAddress 100.64.0.2    # EXAMPLE VALUE: the panel's Tailscale address.
                                                       # Add -Helper if config.yaml has none of
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

## 8. Self-migration (0.5.1): a LocalSystem PC moves itself when you press Update

Take **one** PC that runs build 7 (0.4.2) or build 10 (0.4.4) **as LocalSystem** (not the PC whose fans Fairy
controls first). LocalService PCs do **not** move themselves: for those only check the `needs_admin` part at
the end.

Before, in an Administrator PowerShell on the PC (keep the output):

```powershell
sc.exe qc fairy-agent | findstr SERVICE_START_NAME      # LocalSystem
sc.exe qprivs fairy-agent
Get-Service fairy-agent, fairy-agent-update, fairy-agent-helper -ErrorAction SilentlyContinue
```

If the PC has fan control: set a fixed speed in the panel first (mode Full, e.g. 50 %).

Then press **Update** for this host in the panel (self_update must be on). What should happen:

1. 0 - 1 min: the old installer swaps in 0.5.1 and checks it; the panel shows the new version.
   `/metrics` (panel raw view) has `"migration": {"state": "pending", "step": "waiting", "next_try": ...}`.
2. about 2 min later, within a minute: `agent.log` shows `migration: attempt 1 ...`, then `migration: step
   program_folder` ... `migration: step restart`; the fans go back to the BMC's automatic mode (step `fans`),
   then the helper starts (where Core Temp / IPMI / power control are on) and takes the watchdog.
3. the agent restarts once (the panel may show it offline for a few seconds). `installer.log` shows
   `migration: attempt 1: restarting fairy-agent under NT SERVICE\fairy-agent` and `migration: done`.
4. `/metrics`: `"migration": {"state": "done", "account": "NT SERVICE\\fairy-agent", ...}`; the panel's
   Update button works again (try it once more: "already up to date").

Check:

```powershell
Get-Content C:\ProgramData\fairy-agent\logs\agent.log -Tail 60 | Select-String migration
Get-Content C:\ProgramData\fairy-agent\update\installer.log -Tail 30
Get-Content C:\ProgramData\fairy-agent\migration\state.json        # "phase":"done"
icacls C:\ProgramData\fairy-agent\migration                          # SYSTEM, Administrators (F), NT SERVICE\fairy-agent (RX) only
sc.exe qc fairy-agent | findstr SERVICE_START_NAME                    # NT SERVICE\fairy-agent
sc.exe qprivs fairy-agent                                             # SeChangeNotifyPrivilege only
sc.exe qc fairy-agent-update | findstr START_TYPE                     # DEMAND_START again
Get-NetFirewallRule -DisplayName "Fairy agent helper (no network)" | Select Direction, Action   # where a helper exists
```

and then sections 2 and 3 above (accounts, whoami, folders, readings).

**Failure and rollback** (worth one try on a test PC): make the new account fail on purpose. Before pressing
Update: `secpol.msc` > Local Policies > User Rights Assignment > **Deny log on as a service** > Add User or
Group > `NT SERVICE\fairy-agent` (LocalSystem is not affected by that right; a file permission would not do,
the LocalSystem service carries the same service SID). Expected after step 2: `installer.log` says starting
the agent as NT SERVICE\fairy-agent failed (logon failure) and `rolling back to LocalSystem`; `sc.exe qc
fairy-agent` shows LocalSystem again; the agent runs and answers the panel as before; `/metrics` says
`"migration": {"state": "failed", "step": "restart", "rolled_back": true, "next_try": <in 1 hour>}`.
`Restart-Service fairy-agent` does **not** make it try sooner (agent.log: no new `migration: attempt` line). Undo
the test: remove the entry from "Deny log on as a service" again, then wait for next_try or run
`& $fa setup-self-update`.

**Interrupted**: during step 2 (the `migration: step ...` lines), `Restart-Service fairy-agent`. The next start
logs `resuming attempt 1 after an interruption` about two minutes later and finishes.

**LocalService PCs**: after Update to 0.5.1, `/metrics` says `"migration": {"state": "needs_admin", "account":
"LocalService", "command": "& \"C:\\Program Files\\Fairy\\fairy-agent.exe\" setup-self-update"}` and agent.log
says once that an administrator moves it. Nothing else changes. Run that command in an Administrator
PowerShell: `/metrics` then says `not_needed` and `sc.exe qc` shows `NT SERVICE\fairy-agent`.

**Rollback by hand** (if a PC is left in a bad state): `sc.exe config fairy-agent obj= LocalSystem` (no
password), `Start-Service fairy-agent`, and send `migration\state.json`, `agent.log` and `installer.log`. To keep
the agent from trying again for now, leave `state.json` as it is (it waits for `next_try`).

## 9. GPUs on a laptop with Intel and NVIDIA graphics (one Intel UHD, not two)

After updating to 0.5.1: the host's page shows **one** "Intel(R) UHD Graphics" (plus the NVIDIA card from
nvidia-smi), with a number for Util (0 % when idle, not "–") and VRAM like "40 MiB / 128 MiB". Compare with
Task Manager's Intel GPU page. agent.log at start lists every DXGI entry:

```powershell
Get-Content C:\ProgramData\fairy-agent\logs\agent.log | Select-String "DXGI adapter|counter"
```

Send those lines if there are still two: `pci=00:02.0` on both Intel lines is what merges them; `pci=unknown`
means Windows' kernel did not say (then the old rule applies). A line "counter not readable yet" means PDH was
not ready at start (it is tried again every minute, "counter readable now" follows).

## 10. Performance counters and leftover GPU entries (0.5.2, build 13)

On a PC that runs as `NT SERVICE\fairy-agent` on build 12: press **Update**. 0.5.1's
installer puts 0.5.2 in place (it does not know the group yet); about a minute later the new agent asks the
fairy-agent-update service, which adds the account to Performance Monitor Users and restarts the agent once
(the panel may show it offline for a few seconds). On a PC where the group was added by hand already,
nothing restarts. Check:

```powershell
net localgroup "Performance Monitor Users"                       # lists NT SERVICE\fairy-agent
Get-Content C:\ProgramData\fairy-agent\update\installer.log -Tail 10   # "added NT SERVICE\fairy-agent to Performance Monitor Users", restart
Get-Content C:\ProgramData\fairy-agent\logs\agent.log | Select-String "DXGI adapter|counter|Performance Monitor|ADL"
```

Expected: no `0xC0000BC8` / "performance counters not readable" line after the restart; GPU Util and VRAM in
use show numbers; Processes shows per-process GPU memory. The laptop of section 9: one Intel UHD (the leftover entry's line says
`pci=unknown` and is left out) plus the NVIDIA card; a PC with an RX 5600 XT: one RX 5600 XT (two `pci=unknown` lines left out),
and the `AMD GPU sensors (ADL)` line (send it: it says why there is no Radeon temperature yet).

LocalService PCs: `& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update` as
Administrator moves them and adds the group in one go. `uninstall` removes the membership again.

## 11. Radeon temperature through ADL (0.5.3, build 14)

On a PC with an RX 5600 XT (agent running as `NT SERVICE\fairy-agent`): press **Update**, then

```powershell
Get-Content C:\ProgramData\fairy-agent\logs\agent.log | Select-String "ADL"
```

Expected: `opened="atiadlxx.dll, ADL2_Main_Control_Create=0 (all adapters)"`, per adapter `vendor=1002` (0.5.2
said `03ea` and `skipped`), the first `2d:00.0` entry with `overdrive=8 temp=PMLog <n>C` (or `temp=OverdriveN`),
the others `same card`, `cards=1` and `temp_api="[2d:00.0 PMLog]"`. The panel shows the card "via AMD" with a
temperature (and watts with PMLog). If it says `temp=none (...)`, send the line: it holds each call's ADL error.

## 12. 0.6.0: the security fixes (data folder, installer, Cancel, update check)

**None of 0.6.0's Windows code and neither of its two PowerShell scripts has run on Windows.** The Go code was
compiled and its decisions tested on Linux; the scripts were written and re-read, not parsed. Do this list on
**one** PC first (again: not the PC whose fans Fairy controls), and send the output of any step that differs.

`N` below stands for the build number of the 0.6.0 release (the number in the tag `build-N` on the Releases
page). Type the real number in its place. Everything is one line at a time in **PowerShell as
Administrator**. Steps marked *read-only* change nothing.

### 12.1 Before updating (all read-only)

1. `$PSVersionTable.PSVersion.ToString()`
   Expected: starts with `5.1`.
2. Owners in the data folder:
   `(Get-Acl C:\ProgramData\fairy-agent).Owner; Get-ChildItem C:\ProgramData\fairy-agent -Recurse -Force | ForEach-Object { '{0}  {1}' -f (Get-Acl -LiteralPath $_.FullName).Owner, $_.FullName }`
   Expected: `BUILTIN\Administrators` or `NT AUTHORITY\SYSTEM` on every line; inside `logs\`, `state\` and
   `update\stage\` also `NT SERVICE\fairy-agent`. **Any other name outside those three folders: do not update
   this PC yet, send the output.** The new helper and updater would refuse that folder.
3. `(Get-Acl C:\ProgramData\fairy-agent).Sddl`
   Expected: `O:BA...D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-...)`.
4. `(Get-Acl C:\ProgramData\fairy-agent\config.yaml).Sddl; (Get-Acl C:\ProgramData\fairy-agent\token).Sddl`
   Expected, twice: `O:BA...D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-...)`, nothing else.
5. `(Get-Acl 'C:\Program Files\Fairy').Owner; (Get-Acl 'C:\Program Files\Fairy\fairy-agent.exe').Owner`
   Expected: `BUILTIN\Administrators`, `NT AUTHORITY\SYSTEM` or `NT SERVICE\TrustedInstaller` on both. Any
   other name: the installer will replace the program instead of keeping a newer one (safe, but report it).
6. Parse `install.ps1` of the new release without running it:
   `$b=(New-Object Net.WebClient).DownloadData('https://github.com/n3ptune-cpu/Fairy-agent/releases/download/build-N/install.ps1'); $e=$null; [void][Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString($b),[ref]$null,[ref]$e); "parse errors: $($e.Count)"; $e`
   Expected: `parse errors: 0`. If not, send the output and stop here.
7. The same line with `install-fairy-agent.ps1` in place of `install.ps1`.
   Expected: `parse errors: 0`.
8. Run `install.ps1` from memory up to its first check (needs step 6's `$b` in the same window; the join code
   and the address are made-up example values):
   `$env:FAIRY_JOIN_CODE='AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA'; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) -PanelAddress 100.64.0.10`
   Expected: one red error that starts `no release fingerprint (-SumsSha256)`. Nothing is downloaded.
   Then `Test-Path Env:FAIRY_JOIN_CODE`
   Expected: `False`.
9. The permission call the script makes, on a throwaway folder (creates and removes one empty folder):
   `$d=Join-Path $env:TEMP ('fairy-acltest-'+[guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $d | Out-Null; icacls $d /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /Q; (Get-Acl $d).Sddl; Remove-Item $d`
   Expected: `Successfully processed 1 files`, and an Sddl whose `D:` part starts with `P` and holds only
   `(A;OICI;FA;;;BA)` and `(A;OICI;FA;;;SY)` (either order). Send it if there is anything else in it.

### 12.2 After pressing Update (to build N) on the first PC

10. `& $fa version` shows build N, and the panel shows the host.
11. `Select-String -Path C:\ProgramData\fairy-agent\logs\agent.log -Pattern 'data folder'`
    Expected: no line with `data folder is not safe`.
12. `Select-String -Path C:\ProgramData\fairy-agent\logs\agent.log -Pattern 'exclusive use' | Select-Object -Last 2`
    Expected: no line. (A line means Windows refused to give the agent its port for exclusive use; the agent
    works, report it.)
13. Core Temp PCs:
    `Select-String -Path C:\ProgramData\fairy-agent\logs\agent.log -Pattern 'Core Temp' | Select-Object -Last 3`
    Expected: `Core Temp readings available` with `shared_memory=...`, and core temperatures in the panel. A
    line with `belongs to S-1-5-21...` means Core Temp's shared memory is not owned by Administrators on this
    PC: report it, and switch on Core Temp's "Enable global shared memory (SNMP)" (AGENT.md, "Core Temp").
14. `& $fa helper-status`
    Expected: `helper: running`.
    `Get-Content C:\ProgramData\fairy-agent\helper\helper.log -Tail 5`
    Expected: `helper started`, no line that starts with `pipe:`.
15. `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='fairy-agent','fairy-agent-helper'} -MaxEvents 10 -ErrorAction SilentlyContinue | Format-List TimeCreated, Message`
    Expected: no `did nothing` and no `not serving anything`.
16. `(Invoke-WebRequest -UseBasicParsing "http://$((Get-NetIPAddress -InterfaceAlias Tailscale -AddressFamily IPv4).IPAddress):9101/health?c=0123456789abcdef").Content`
    Expected: `{"proof":"` followed by 64 hex digits. No version, no token.

### 12.3 Re-pair with the panel's new line (this installs)

Only after the panel has been updated too, so that its line names build N.

17. On the host's page press **Re-pair** and run the line. Expected lines, in this order:
    `SHA256SUMS matches the hash the panel checked`,
    `verified (the panel's fingerprint, signature and hashes)`, `program checksum matches SHA256SUMS`,
    `pairing v2:`, `paired with the panel`. On a healthy PC there is **no** line that starts with `repaired:`
    or `IMPORTANT:` (if there is one, read AGENT.md, "Running the installer again", and send the output).
18. `Test-Path Env:FAIRY_JOIN_CODE`
    Expected: `False`.
    `(Get-ChildItem $env:TEMP -Filter 'fairy-install-*').Count`
    Expected: `0`.
    `& $fa pair-status`
    Expected: `paired with the panel (...)`.
19. Steps 2 to 4 again: the same expected output.

### 12.4 Cancel (changes state, harmless)

20. In the panel schedule a shutdown in 10 minutes. Then `Restart-Service fairy-agent`. The panel still shows
    the pending shutdown. `Test-Path C:\ProgramData\fairy-agent\helper\power-pending.json`
    Expected: `True`. Press **Cancel** in the panel: Windows shows that the shutdown was cancelled, the file
    is gone, the PC stays on.
21. The other half: `shutdown /s /t 600` typed by hand. The panel shows **nothing** pending. Then
    `shutdown /a`.

### 12.5 When the build after N exists

22. Press **Update**. `Get-Content C:\ProgramData\fairy-agent\update\installer.log -Tail 5`
    Expected: `apply-update: done`. `Test-Path C:\ProgramData\fairy-agent\update\last-apply`
    Expected: `True`. Press Update again: nothing is installed a second time (the agent answers "already up
    to date").
23. Later, on a PC whose agent is newer than the release the panel's line names, Re-pair: the output has
    `is NEWER than this installer's release`, and `& $fa version` is unchanged.

## Rollback (back to build 10 / v0.4.4)

0.4.4 does not know the helper or the new account, so remove 0.5's services first. Config and tokens stay, the
panel needs nothing new.

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" uninstall        # stops both (fans back to the BMC), removes all three services
Get-NetFirewallRule -DisplayName "Fairy agent helper (no network)" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
# then, in a folder with build 10's files (fairy-agent-windows-amd64.exe, SHA256SUMS and install-fairy-agent.ps1
# from https://github.com/n3ptune-cpu/Fairy-agent/releases/tag/v0.4.4):
Set-ExecutionPolicy -Scope Process Bypass
.\install-fairy-agent.ps1 -PanelAddress 100.64.0.2 -LocalSystem   # 100.64.0.2 is an EXAMPLE VALUE: the panel's Tailscale
                                                                   # address. -LocalSystem only if this PC used Core Temp / fans
```

Report back: the output of section 2, the last 30 lines of both logs (and for section 8 `installer.log` and
`migration\state.json`), and anything that differed. Before you send anything, look through it and remove
tokens and join codes if any show up (the logs are written not to contain them). Never send the release
signing key.
