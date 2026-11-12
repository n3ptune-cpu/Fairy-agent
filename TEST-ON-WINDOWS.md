# Testing 0.5.x, 0.6.0 and the passkey approval on Windows (agent + helper, self-migration, security fixes)

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

## 12. 0.6.0: the security fixes. One checklist for a real PC

**None of 0.6.0's Windows code and neither of its two PowerShell scripts has run on Windows.** The Go code was
compiled and its decisions tested on Linux; the scripts were written and re-read, not parsed. Do this list on
**one** PC first (again: not the PC whose fans Fairy controls), and send the output of any step that differs.

How to read it:

* One step is one line to type, in **Windows PowerShell as Administrator** unless the step says otherwise, and
  what a good answer looks like after the arrow (`->`).
* The steps are in the order to do them. Steps 1 to 21 **only read**. Steps 22 to 29 change a throwaway folder
  or something harmless. Steps 30 to 34 install.
* `N` is the build number of the 0.6.0 release (the number in the tag `build-N` on the Releases page). Type the
  real number in its place. `$fa` is the program, as at the top of this file.
* **[KEY]** marks the five steps that matter most. If time is short, do those five (2, 13, 16, 20 and, on the
  same visit, 9). Each one checks a guess the new code makes about real Windows; if a guess is wrong, that step
  shows it before anything breaks.

### A. Before updating (read-only; one PC is enough if all were installed the same way)

1. Which PowerShell this is.
   `$PSVersionTable.PSVersion.ToString()`
   -> starts with `5.1`.
2. **[KEY] Who owns the data folder and the program.** The new helper and updater refuse a folder that another
   account owns, and the installer would move it aside.
   `(Get-Acl C:\ProgramData\fairy-agent).Owner; Get-ChildItem C:\ProgramData\fairy-agent -Recurse -Force | ForEach-Object { '{0}  {1}' -f (Get-Acl -LiteralPath $_.FullName).Owner, $_.FullName }; (Get-Acl 'C:\Program Files\Fairy').Owner; (Get-Acl 'C:\Program Files\Fairy\fairy-agent.exe').Owner`
   -> `BUILTIN\Administrators` or `NT AUTHORITY\SYSTEM` on every line (`NT SERVICE\TrustedInstaller` also for
   the last two); inside `logs\`, `state\` and `update\stage\` also `NT SERVICE\fairy-agent`. **Any other name:
   do not update this PC yet, send the output.**
3. The permissions of the folder, of `config.yaml` and of `token`.
   `(Get-Acl C:\ProgramData\fairy-agent).Sddl; (Get-Acl C:\ProgramData\fairy-agent\config.yaml).Sddl; (Get-Acl C:\ProgramData\fairy-agent\token).Sddl`
   -> first `O:BA...D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;S-1-5-80-...)`, the other two
   `O:BA...D:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;S-1-5-80-...)`, nothing else.
4. The permissions of the agent's three folders. The installer moves one of them aside as a whole when it
   differs (AGENT.md, "The agent's three folders"), so it is good to know beforehand.
   `'logs','state','update\stage' | ForEach-Object { (Get-Acl "C:\ProgramData\fairy-agent\$_").Sddl }`
   -> three times `O:BA...D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;S-1-5-80-...)`. A line
   that starts `O:SY` with the same `D:` part is fine too and is left as it is (`update\stage` usually does:
   the agent made it while it ran as LocalSystem). A line that starts `O:S-1-5-80-` with the same `D:` part
   is fine as well: only the owner is corrected, with one `repaired:` line.
5. Who becomes the owner of what this window creates.
   `[Security.Principal.WindowsIdentity]::GetCurrent().Owner.Value`
   -> `S-1-5-32-544` (Administrators). Another value: send it; step 2 then decides.
6. Who became the owner of what the helper (LocalSystem) created.
   `(Get-Acl C:\ProgramData\fairy-agent\helper\helper.log).Owner`
   -> `BUILTIN\Administrators` (or `NT AUTHORITY\SYSTEM`).
7. The folders above the data folder.
   `(Get-Acl C:\ProgramData).Sddl; (Get-Acl C:\).Sddl`
   -> owner `O:SY`, `O:BA` or TrustedInstaller (`O:S-1-5-80-956008885-...`); for `BU` and `AU` no entry that
   applies to the folder itself (no `IO` in its second field) with `FA`, `SD`, `DT`, `WD` or `WO`.
8. The two temp folders. The install script now works in the second one.
   `icacls $env:TEMP; icacls $env:SystemRoot\Temp`
   -> the first shows your own account with `(OI)(CI)(F)`; the second shows `BUILTIN\Users:(CI)(S,WD,AD,X)`
   and no `(F)` or `(M)` for Users.
9. **[KEY] Who owns the helper's pipe** (works on 0.5.x too, while the helper runs).
   `(Get-Acl -LiteralPath '\\.\pipe\fairy-agent-helper').Sddl`
   -> starts with `O:BA` or `O:SY`, and holds `(D;;GA;;;NU)(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120183;;;S-1-5-80-`.
   If PowerShell cannot read a pipe this way (an error instead of a line), that is no finding: step 16 prints
   the same owner.
10. Does a failing check stop a PowerShell line? (This is why the panel's install line is being changed.)
    `if ((1/0) -ne 'x') { throw 'stop' }; 'ran'`
    -> an error line, then `ran`.
11. Can this PC compute SHA-256 the way the panel's install line does?
    `(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy).Enabled; [Security.Cryptography.SHA256]::Create().GetType().Name`
    -> `0`, then `SHA256Managed`. An error on the second part: send it, and do not use the panel's install
    line on this PC until the panel is updated.
12. Both scripts of the new release parse (nothing is run).
    `foreach ($n in 'install.ps1','install-fairy-agent.ps1') { $b=(New-Object Net.WebClient).DownloadData("https://github.com/n3ptune-cpu/Fairy-agent/releases/download/build-N/$n"); $e=$null; [void][Management.Automation.Language.Parser]::ParseInput([Text.Encoding]::UTF8.GetString($b),[ref]$null,[ref]$e); "$n parse errors: $($e.Count)"; $e }`
    -> `parse errors: 0`, twice. If not, stop here and send the output.
13. **[KEY] Run `install.ps1` in this PowerShell, up to its first check.** The script has no dry-run switch;
    this is the nearest thing: without the release fingerprint it stops before it downloads or changes
    anything. The join code and the address are made-up example values.
    `$b=(New-Object Net.WebClient).DownloadData('https://github.com/n3ptune-cpu/Fairy-agent/releases/download/build-N/install.ps1'); $env:FAIRY_JOIN_CODE='AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA'; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) -PanelAddress 100.64.0.10; Test-Path Env:FAIRY_JOIN_CODE`
    -> one red error that starts `no release fingerprint (-SumsSha256)`, then `False`.

### B. After pressing Update (to build N) on the first PC (read-only)

14. The new program runs.
    `& $fa version`
    -> shows build N; the panel shows the host.
15. The agent's own look at its data folder, and its port.
    `Select-String -Path C:\ProgramData\fairy-agent\logs\agent.log -Pattern 'data folder is not safe','exclusive use' | Select-Object -Last 3`
    -> no line.
16. **[KEY] The new helper starts, and its pipe belongs to Administrators or SYSTEM.**
    `& $fa helper-status; Get-Content C:\ProgramData\fairy-agent\helper\helper.log -Tail 5`
    -> `helper pipe owner: S-1-5-32-544 (...)` (or `S-1-5-18`), `helper: running, answers on ...`, and in the
    log `helper started` with no line that starts with `pipe:`. No line that starts with `note:`. **Another
    owner: send the output, and leave `require_helper_pipe_owner` off.**
17. The agent's own note about the pipe (it is written once when the owner is not the expected one).
    `Select-String -Path C:\ProgramData\fairy-agent\logs\agent.log -Pattern "helper's pipe" | Select-Object -Last 2`
    -> no line.
18. A typed command on a healthy PC.
    `& $fa update --check`
    -> the installed and the latest version; **no** `cannot be trusted`.
19. What the services told Windows.
    `Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='fairy-agent','fairy-agent-helper'} -MaxEvents 10 -ErrorAction SilentlyContinue | Format-List TimeCreated, Message`
    -> no `did nothing`, no `not serving anything`, no `cannot start`.
20. **[KEY] Core Temp PCs: who owns Core Temp's shared memory.**
    `Select-String -Path C:\ProgramData\fairy-agent\logs\agent.log, C:\ProgramData\fairy-agent\helper\helper.log -Pattern 'Core Temp' | Select-Object -Last 4`
    -> `Core Temp readings available` with `shared_memory=...`, and core temperatures in the panel. **A line
    with `belongs to S-1-5-21-...` means the guess "what Core Temp creates belongs to Administrators" is wrong
    on this PC: send it.** (With `It is used all the same` the readings still work; with `not used` they do
    not: switch on Core Temp's "Enable global shared memory (SNMP)", AGENT.md, "Core Temp".)
21. The health answer. `/health` answers only the update's own check on the PC itself, which first proves that
    it holds the read token; everybody else gets the answer of a path that does not exist.
    `try { (Invoke-WebRequest -UseBasicParsing "http://$((Get-NetIPAddress -InterfaceAlias Tailscale -AddressFamily IPv4).IPAddress):9101/health?c=0123456789abcdef").StatusCode } catch { [int]$_.Exception.Response.StatusCode }`
    -> `404` (the body is `{"error":"not found"}`). **Not** `200`, and nothing with `proof`, a version or a
    token in it.

### C. These change a throwaway folder or something harmless

22. The way the install script now makes its work folder (creates and removes one empty folder in
    `C:\Windows\Temp`).
    `$d=Join-Path $env:SystemRoot ('Temp\fairy-acltest-'+[guid]::NewGuid().ToString('N')); $s=New-Object System.Security.AccessControl.DirectorySecurity; $s.SetSecurityDescriptorSddlForm('O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)'); [System.IO.Directory]::CreateDirectory($d,$s) | Out-Null; (Get-Acl -LiteralPath $d).Sddl; Remove-Item -LiteralPath $d`
    -> one line that starts `O:BA`, whose `D:` part starts with `P` and holds only `(A;OICI;FA;;;BA)` and
    `(A;OICI;FA;;;SY)`. Anything else in it, or an error: send it (the script would stop with `did not get the
    permissions it was created with`).
23. Can an ordinary account make a junction? In a window that is **not** run as administrator:
    `cmd /c "mkdir %TEMP%\fj-a %TEMP%\fj-t & mklink /J %TEMP%\fj-a\j %TEMP%\fj-t & rmdir %TEMP%\fj-a\j & rmdir %TEMP%\fj-a %TEMP%\fj-t"`
    -> `Junction created for ...`. (That is what the rule "the installer changes nothing inside the agent's
    folders" guards against. `You do not have sufficient privilege`: send it; the rule stays.)
24. Do permissions set on a folder reach through a junction inside it? (For the record; since this release the
    installer does not depend on the answer.)
    `mkdir C:\fj\a, C:\fj\t | Out-Null; Set-Content C:\fj\t\f x; cmd /c mklink /J C:\fj\a\j C:\fj\t | Out-Null; $b=(Get-Acl C:\fj\t\f).Sddl; $acl=Get-Acl C:\fj\a; $acl.SetAccessRuleProtection($true,$false); $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule('Users','Modify','ContainerInherit,ObjectInherit','None','Allow'))); Set-Acl C:\fj\a $acl; $b -eq (Get-Acl C:\fj\t\f).Sddl; cmd /c rmdir C:\fj\a\j; cmd /c rd /s /q C:\fj`
    -> `True`. `False`: send it.
25. Fairy's own shutdown is remembered across a restart of both services. In the panel schedule a shutdown in
    10 minutes, then:
    `Restart-Service fairy-agent-helper; Restart-Service fairy-agent; Start-Sleep 5; Test-Path C:\ProgramData\fairy-agent\helper\power-pending.json`
    -> `True`, and the panel still shows the pending shutdown. Press **Cancel** in the panel: Windows shows that
    the shutdown was cancelled, `Test-Path` on the same file says `False`, the PC stays on.
26. The same across sleep. Schedule a shutdown in 30 minutes, put the PC to sleep for 2 minutes, wake it.
    `Test-Path C:\ProgramData\fairy-agent\helper\power-pending.json`
    -> `True` and the panel still shows it; Cancel works as in step 25.
27. The same across a correction of the clock (optional; it moves the PC's clock by five minutes and back).
    Schedule a shutdown in 30 minutes, then:
    `Set-Date (Get-Date).AddMinutes(5) | Out-Null; Start-Sleep 20; Test-Path C:\ProgramData\fairy-agent\helper\power-pending.json; w32tm /resync /force`
    -> `True`, the panel still shows the shutdown (now for a time five minutes later by the clock), and Cancel
    works as in step 25.
28. Fairy does not cancel what it did not start.
    `shutdown /s /t 600`
    -> the panel shows **nothing** pending. Then `shutdown /a`.
29. Optional: the helper waits for its pipe name. Stop the helper, hold the name from a second window with any
    program that creates `\\.\pipe\fairy-agent-helper`, start the helper.
    `Get-Content C:\ProgramData\fairy-agent\helper\helper.log -Tail 5`
    -> `pipe: another process holds the name` with that program's id, and `free again` within 30 seconds of
    closing it.

### D. These install

Only after the panel has been updated too, so that its line names build N.

30. On the host's page press **Re-pair** and run the line.
    -> these lines, in this order: `SHA256SUMS matches the hash the panel checked`,
    `verified (the panel's fingerprint, signature and hashes)`, `program checksum matches SHA256SUMS`,
    `pairing v2:`, `paired with the panel`; **no** line that starts with `repaired:` or `IMPORTANT:` on a
    healthy PC (if there is one, read AGENT.md, "Running the installer again", and send the output).
31. Nothing is left behind, and the PC is paired.
    `Test-Path Env:FAIRY_JOIN_CODE; (Get-ChildItem $env:SystemRoot\Temp -Filter 'fairy-install-*' -Force -ErrorAction SilentlyContinue).Count; (Get-ChildItem C:\ProgramData -Filter 'fairy-agent.*' -Force).Count; & $fa pair-status`
    -> `False`, `0`, `0`, `paired with the panel (...)`.
32. Steps 2, 3 and 4 again -> the same output as before. If a clean PC or VM is at hand: after **Add host**
    there, steps 2, 3 and 4 give the expected output too (the folders were created with their permissions).
33. When the build after N exists, press **Update**.
    `Get-Content C:\ProgramData\fairy-agent\update\installer.log -Tail 5; Test-Path C:\ProgramData\fairy-agent\update\last-apply`
    -> `apply-update: done`, `True`. Press Update again: nothing is installed a second time ("already up to
    date").
34. Later, on a PC whose agent is newer than the release the panel's line names, Re-pair.
    -> the output has `is NEWER than this installer's release`, and `& $fa version` is unchanged.

**If a step refuses with `the data folder cannot be trusted`:** the message ends with what to run
(`& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update`, as Administrator). AGENT.md, "Running the
installer again", says what that keeps and what it moves aside.

## 13. Passkey approval (next release): a self-built agent on the test VM

**What has run.** Steps 1 to 29 of the first version of this list were run on the test VM (NSX-TEST-VM,
Windows 11) on 2026-11-11 with the first version of the code, and all passed: the helper with the check,
`helper-trust`, the trust file's permissions, a damaged file, the file the helper wrote itself. **This is the
list for the second version** (after the security review). What is new or changed is marked **[NEW]**; none of
the new parts has run on Windows. The checking code was tested on Linux with a made-up Pocket ID. Do this on
the test VM, not on a PC you use.

What changed for you: the panel's first-time set (`POST /approval/trust`) is now accepted only with a passkey
approval that fits the proposed values. A plain POST, as step 26 used to send it, is **refused**; that refusal
is the test. The accepted path needs the panel (later). To get the VM to "required" for the other steps, the
trust is set on the VM itself with `helper-trust set`.

What you need on the VM, in `C:\fairy-selfbuilt\`:

* `fairy-agent-windows-amd64.exe`: built from the source of this change.
* `install-fairy-agent.ps1`: from `deploy\` of the same source.
* No `SHA256SUMS` and no `VERSION` file in that folder.

How to read it: one step is one line, in **Windows PowerShell as Administrator**; after `->` is what a good
answer looks like. Steps 1 to 5 install. Steps 6 to 12 only read or set the trust. From step 13 on, requests
are sent to the agent; every shutdown that is sent is cancelled in the next step.
**[KEY]** marks the steps whose output matters most. Keep the Administrator window open until the end: once a
trust is set, only that window can undo it. All control requests together are limited to 12 a minute
(`control_rate_per_min`); typed by hand you do not reach that, a script has to pace itself (answer `429`).

### A. Install the self-built agent over build 16

1. What is installed now.
   `& "C:\Program Files\Fairy\fairy-agent.exe" version`
   -> `fairy-agent 16-...`
2. Allow the script in this window, and read which address the firewall lets in.
   `Set-ExecutionPolicy -Scope Process Bypass`
   `(Get-NetFirewallRule -DisplayName "Fairy agent (Tailscale only)" | Get-NetFirewallAddressFilter).RemoteAddress`
   -> the panel's address as the VM was paired with (the test panel: `192.168.10.10`), or `100.64.0.0/10`.
3. Install. It stops both services, replaces the program, sets the services up again and starts them.
   **Give it the address of step 2** (`192.168.10.10` is an EXAMPLE VALUE: the test panel). The installer
   always writes the firewall rule anew; without `-PanelAddress` it writes `100.64.0.0/10` (Tailscale only),
   and a test panel on another network can no longer reach the VM until Re-pair.
   `& "C:\fairy-selfbuilt\install-fairy-agent.ps1" -Helper -Quiet -PanelAddress 192.168.10.10`
   -> a yellow warning `No SHA256SUMS next to this script` (expected: a self-built program has none), no red
   error, at the end `fairy-agent` and `fairy-agent-helper` Running. Step 2's second line again shows the same
   address as before.
4. The new program is in place.
   `& "C:\Program Files\Fairy\fairy-agent.exe" version`
   -> the version the program was built with (`16-selfbuilt`, or `dev`).
5. **[KEY]** The helper answers and knows approvals.
   `& "C:\Program Files\Fairy\fairy-agent.exe" helper-status`
   -> `helper: running, answers on \\.\pipe\fairy-agent-helper`, a JSON line with `"proto":2`, then
   `pipe protocol:   2` and a line that starts with `approval:        off (checked by the helper)`.

### B. Set the trust on the PC

Replace the three example values: Pocket ID's address, the client id of the client "Fairy PC actions" (any
text works for the steps below if that client does not exist yet), your user id in Pocket ID.

6. No trust yet.
   `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust show`
   -> a first line `trust file:       <path>`, then `approval:        off (no trust file ...)`
7. Set it. It fetches Pocket ID's signing key, shows it and asks; answer `yes`.
   `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust set --issuer https://id.example.org --client-id EXAMPLE-CLIENT-ID --user EXAMPLE-USER-ID`
   -> `to be written:`, the issuer, `pinned key:      kid ..., RS256, thumbprint ...`, `allowed users:   1`,
   `signing keys:    fetched just now from https://...`, then a line that starts with `written.`,
   **[NEW 3]** a line `In effect within 5 seconds: the running helper (pipe protocol 2) ...`,
   **[NEW]** and under it `NOT PROVEN: ...` (the command writes what it is given; only the panel's first-time
   set is checked against a real approval). **[NEW]** If a line `note: THE CLOCK: ...` shows: the VM's clock
   and Pocket ID's differ by more than 45 s; set the VM's clock (`w32tm /resync`) before going on.
   If it says `the issuer calls itself ...`: use exactly that spelling for `--issuer`.
8. **[KEY]** The helper sees it (wait 5 seconds first).
   `& "C:\Program Files\Fairy\fairy-agent.exe" helper-status`
   -> `approval:        required (checked by the helper)...`, `issuer:`, `client id:`, `pinned key:`,
   `allowed users:   1`, `fan window:      30 s ...`, `shutdown after boot: off ...`
9. Who may change the file.
   `icacls "C:\ProgramData\fairy-agent\helper\approval-trust.json"`
   -> `BUILTIN\Administrators:(I)(F)`, `NT AUTHORITY\SYSTEM:(I)(F)`, `NT SERVICE\fairy-agent:(I)(RX)`; no
   other account with `(F)`, `(M)` or `(W)`. (On a Windows in another language the first two names are
   translated; what counts is that only Administrators and SYSTEM have more than read.)

### C. Requests without an approval are refused

10. Where the agent listens.
    `Select-String -Path "C:\ProgramData\fairy-agent\logs\agent.log" -Pattern "fairy-agent listening" | Select-Object -Last 1`
    -> a line with `listen=<address>:9101`
11. Remember the address (type the one from step 10) and the two tokens. (The two files are where config.yaml
    says: `fairy-agent config get token_file` and `... control_token_file`; the lines below are the defaults.)
    `$base = "http://100.64.0.10:9101"`
    `$ctl = Get-Content "C:\ProgramData\fairy-agent\control-token"`
    `$read = Get-Content "C:\ProgramData\fairy-agent\token"`
12. The body of a shutdown request in 10 minutes, and of a cancel, as files.
    `Set-Content -Path "C:\fairy-selfbuilt\shutdown.json" -Value '{"action":"shutdown","delay_s":600}' -Encoding ASCII`
    `Set-Content -Path "C:\fairy-selfbuilt\cancel.json" -Value '{"action":"cancel"}' -Encoding ASCII`
    `Set-Content -Path "C:\fairy-selfbuilt\challenge.json" -Value '{"verb":"power","action":"shutdown","delay_s":600}' -Encoding ASCII`
13. **[KEY]** A shutdown without approval. (Needs `power_control: enabled: true` in config.yaml; if the answer
    has `"code":"power_control_disabled"`, switch it on first:
    `& "C:\Program Files\Fairy\fairy-agent.exe" config set power_control.enabled true`, then
    `Restart-Service fairy-agent-helper`, `Restart-Service fairy-agent`.)
    `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\shutdown.json" "$base/power"`
    -> `{"code":"approval_required","error":"this needs a passkey approval (Pocket ID) and the request carried none"} [403]`
    and Windows shows **no** shutdown notice.
14. Cancel needs none.
    `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\cancel.json" "$base/power"`
    -> `{"action":"cancel","pending":null} [200]`
15. **[KEY]** The helper wrote it down.
    `Get-Content "C:\ProgramData\fairy-agent\helper\helper.log" -Tail 6`
    -> a line with `approval: required, none sent` and `request="power action=shutdown delay_s=600"`.
16. A challenge.
    `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\challenge.json" "$base/approval/challenge"`
    -> `{"needed":true,"request":"power action=shutdown delay_s=600","challenge":"<43 characters>","expires_in_s":180,"issuer":...,"client_id":...} [200]`
17. What the panel will see.
    `(curl.exe -s -H "Authorization: Bearer $read" "$base/metrics" | ConvertFrom-Json).approval`
    -> `state : required`, `enforced_by : helper`, `proto : 1`, the issuer, the client id, `users : 1`.

### D. A damaged trust file refuses, it does not switch the check off

18. Keep a copy.
    `Copy-Item "C:\ProgramData\fairy-agent\helper\approval-trust.json" "C:\fairy-selfbuilt\trust-backup.json"`
19. Damage it.
    `Set-Content -Path "C:\ProgramData\fairy-agent\helper\approval-trust.json" -Value "damaged" -Encoding ASCII`
20. **[KEY]** After 5 seconds:
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-status`
    -> `approval:        broken (checked by the helper): fan, power and update requests are refused`
21. The shutdown request of step 13 again.
    -> `{"code":"approval_unavailable","error":"the approval trust file on this machine cannot be used ..."} [503]`
22. Repair it from the copy.
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust set --from "C:\fairy-selfbuilt\trust-backup.json" --yes`
    -> `written.`; step 8 again shows `required`.

### E. The first-time set from the panel needs a proof; the lock

23. Remove the trust on the PC.
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust clear --yes`
    -> `removed. Approval is off (in effect within 5 seconds); the panel can now set trust again (once).`
24. After 5 seconds the shutdown request of step 13 is accepted, as before this change. Cancel it at once
    (step 14).
    -> `{"action":"shutdown","pending":{...}} [200]`, Windows shows its shutdown notice; after step 14 it is gone.
25. What a panel without a proof would send as the first trust: the four values of the copy. (The route
    refuses any other member, so only these four. If your PowerShell's `ConvertTo-Json` writes them
    differently and step 26 answers `400`, send that answer.)
    `Get-Content "C:\fairy-selfbuilt\trust-backup.json" -Raw | ConvertFrom-Json | Select-Object issuer, client_id, keys, users | ConvertTo-Json -Depth 5 | Set-Content -Path "C:\fairy-selfbuilt\trust-init.json" -Encoding ASCII`
26. **[KEY] [NEW]** Send it as the panel would, WITHOUT the approval that proves it. It must be refused.
    `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\trust-init.json" "$base/approval/trust"`
    -> `{"code":"proof_required","error":"a first-time set of the trust needs a passkey approval that proves it works: ... Nothing was written"} [403]`
26b. **[NEW]** The helper gives a challenge for a first-time set (the hash here is 43 times `A`, a made-up one;
    the panel sends the hash of the values it proposes).
    `Set-Content -Path "C:\fairy-selfbuilt\challenge-trust.json" -Value '{"verb":"trust_set","trust_hash":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}' -Encoding ASCII`
    `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\challenge-trust.json" "$base/approval/challenge"`
    -> `{"needed":true,"request":"trust_set hash=AAAA...","challenge":"<43 characters>","expires_in_s":180} [200]`
    (no `issuer`, no `client_id`: the machine has none yet).
27. **[KEY] [NEW]** Nothing was written and nothing is locked.
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-status`
    -> `approval:        off (checked by the helper)...`
    `Get-ChildItem -Force "C:\ProgramData\fairy-agent\helper"`
    -> no `approval-trust.json` and no file whose name starts with `.approval-trust-`.
28. **[NEW]** Set the trust on the PC (from the copy), then try the panel's set again: locked.
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust set --from "C:\fairy-selfbuilt\trust-backup.json" --yes`
    -> `written.` and `NOT PROVEN: ...`. Wait 5 seconds, then step 26's line again:
    -> `{"code":"already_set","error":"this machine already has a trust file; ..."} [409]`
    and step 26b's line again -> `[409]` `already_set` (no challenge for a second set either).
29. Step 13 again -> `[403]` `approval_required`.

### E2. Three more checks **[NEW]** (the security review asked for them)

N1. The trust file has one name, and no temporary file was left behind.
    `fsutil hardlink list "C:\ProgramData\fairy-agent\helper\approval-trust.json"`
    -> exactly one line (`\ProgramData\fairy-agent\helper\approval-trust.json`).
    `Get-ChildItem -Force "C:\ProgramData\fairy-agent\helper" | Where-Object { $_.Name -like ".approval-*" }`
    -> nothing.
N2. **[KEY]** An update is refused while the helper cannot be asked. (Trust is set, from step 28. If the answer
    has `"code":"self_update_disabled"`, self-update is off on this VM and the step says nothing.)
    `Stop-Service fairy-agent-helper`
    `Restart-Service fairy-agent`
    wait until step 17's line answers again (some seconds), then:
    `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "{}" "$base/update"`
    -> `{"code":"approval_unavailable","error":"the update was not started: the helper, which checks the approval of an update on this machine, is not answering, and this machine has an approval trust file (start it: ...)"} [503]`
    The words after "is not answering" matter, please send the line: `and this machine has an approval trust
    file` = the agent's own account could read and check the helper's folder (good). `cannot be used` or
    `is not known` = it could not; the update is refused all the same, but then the agent's own check does
    not work on Windows yet.
    `Start-Service fairy-agent-helper`
    -> `helper-status` says `helper: running` again.
N3. The shutdown shortly after boot takes no long delay. (No restart needed: a delay of a day must be refused
    whatever the uptime is.)
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust set --boot-shutdown 900 --yes`
    wait 5 seconds, then:
    `Set-Content -Path "C:\fairy-selfbuilt\shutdown-day.json" -Value '{"action":"shutdown","delay_s":86400}' -Encoding ASCII`
    `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\shutdown-day.json" "$base/power"`
    -> `[403]` `approval_required`; then the cancel of step 14 (to be sure), and switch the setting off again:
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust set --boot-shutdown 0 --yes`

### F. Optional: one shutdown shortly after boot (for wake, update, shut down)

30. Allow one shutdown without approval in the first 15 minutes after Windows starts.
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust set --boot-shutdown 900 --yes`
31. Restart the VM (**Restart**, not shut down and power on), sign in, open PowerShell as Administrator, do
    step 11 again, then within 15 minutes of the start send the shutdown of step 13 (delay 600 s: the longest
    this exception takes).
    -> `[200]`; cancel it (step 14). `helper.log` has `UNAPPROVED shutdown accepted shortly after boot` with
    `uptime_s=`. Please send that line: the number shows whether Windows' clock counts as assumed.
32. The same request again -> `[403]` `approval_required` (only one).
32b. **[NEW]** One per boot, not one per start of the helper: `Restart-Service fairy-agent-helper`, wait until
    `helper-status` says running, the same request again -> still `[403]`. The record is
    `C:\ProgramData\fairy-agent\helper\approval-boot-shutdown.json`.
33. Switch it off again.
    `& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust set --boot-shutdown 0 --yes`

### G. After the fifth audit **[NEW 3]** (none of this has run on Windows)

These steps are for the code after the audit of 2026-11-12. They need the trust of section B to be set, unless
a step says otherwise. Nothing here has run on Windows; each step says what a good answer looks like.

**G1. The old helper is still running after an update (the audit's finding 01).** This is the one state in
which requests ran with no check at all. It needs the released build 16 installed and running first (both
services), so do it before section A, or after "Going back to build 16".

* G1.1 Replace the program while the **helper keeps running** (Windows lets a running program be renamed):
  `Stop-Service fairy-agent`
  `Rename-Item "C:\Program Files\Fairy\fairy-agent.exe" fairy-agent.exe.b16`
  `Copy-Item "C:\fairy-selfbuilt\fairy-agent-windows-amd64.exe" "C:\Program Files\Fairy\fairy-agent.exe"`
  `Start-Service fairy-agent`
  -> both services Running; the agent is the new program, the helper process is still build 16.
* G1.2 `& "C:\Program Files\Fairy\fairy-agent.exe" helper-status`
  -> **no** line `pipe protocol:   2`; instead `approval:        this helper is from before passkey approvals`.
* G1.3 No trust file yet: a shutdown far away is accepted as before (step 13's request, `delay_s` 86400)
  -> `[200]`; cancel it (step 14). `/metrics` (step 16) has **no** `approval` block.
* G1.4 **[KEY]** Set the trust (step 7's command, with `--yes`).
  -> `written.`, then **`NOT IN EFFECT IN THE HELPER YET: the fairy-agent-helper that is running is from before
  passkey approvals`** and `Restart it now: Restart-Service fairy-agent-helper`. It must NOT say `In effect
  within 5 seconds`.
* G1.5 **[KEY]** At once (no waiting), step 13's shutdown without approval
  -> **`[503]` with `approval_unavailable`**, text `the running fairy-agent-helper is older than this agent`.
  Before this fix: `[200]`, the PC would have shut down. The same for `reboot`, `sleep`, `POST /fan/mode`,
  `POST /fan/duty` (if fans are on) and `POST /update`: all `[503] approval_unavailable`.
* G1.6 `POST /power` with `cancel` -> `[200]`. `POST /approval/challenge` -> `[409] helper_too_old`.
* G1.7 **[KEY]** `/metrics` -> `"approval":{"state":"unknown","enforced_by":"helper","proto":1,"error":"the
  running fairy-agent-helper is older than this agent ..."}`. Before this fix it said `"state":"required",
  "enforced_by":"agent"`.
* G1.8 `Restart-Service fairy-agent-helper`, then `helper-status` -> `pipe protocol:   2`,
  `approval:        required (checked by the helper)`. Step 13's shutdown -> `[403] approval_required`.
* G1.9 Tidy up: `Remove-Item "C:\Program Files\Fairy\fairy-agent.exe.b16"`.

**G2. The fan window opens only after a fan change that was applied.** Needs a PC with fan control through the
helper (a Supermicro board; not the test VM) and a real approval, so the panel half: with the fan mode NOT
`full`, approve "zone 0 to 100 %" from the panel -> the panel shows the BMC's refusal (`409`, `fan mode is ...;
set mode 'full' first`). At once, without approval:
`POST /fan/mode {"mode":"full"}` -> **`[403] approval_required`** (before this fix: `[200]` for 30 s).
`helper.log` has no line `approval: fan window open` for the refused duty, and no `approval: accepted` for it
either: a request the helper refuses for a reason of its own does not use the approval up. (Then approve
"mode full" and send the first approval for "zone 0 to 100 %" again within its 3 minutes: `[200]`.)

**G3. A refused request costs neither the approval nor the shutdown after boot.** The helper now looks at an
approval (and records the shutdown after boot) only when a request has passed the helper's own checks. Through
the agent the VM shows little of this, because the agent's own checks came before the helper already. What
must still hold (nothing may have changed for requests without approval):

* G3.1 Steps 13 to 19 of section C answer exactly as before (`[403] approval_required`).
* G3.2 With section F's `--boot-shutdown 900`, inside the 15 minutes after a restart:
  `{"action":"shutdown","delay_s":5}` -> `[400]` (`delay_s must be between 10 and 86400`, the agent's own
  check); then step 13's shutdown with `delay_s` 600 -> `[200]`. Cancel it (step 14).
  `C:\ProgramData\fairy-agent\helper\approval-boot-shutdown.json` exists only after the `[200]`.

### What to send back

The output of steps 5, 8, 9, 13, 15, 20, 26, 26b, 27, 28, N1, N2 (and 31, 32b if done), of G1.2, G1.4, G1.5,
G1.7 and G1.8, and:
`Get-Content "C:\ProgramData\fairy-agent\helper\helper.log" -Tail 60`. If the helper did not start after
step 3: Event Viewer > Windows Logs > Application, source `fairy-agent-helper`.

Not testable yet: the first-time set that is accepted, and an approved request. Both need a real token from
Pocket ID, which only the panel half (next) obtains. When it exists: on a VM without trust, let the panel set
it (one passkey confirmation) and send the `trust set for the first time ... proven by a passkey approval`
line of `helper.log`; then press Shut down on the VM's page, confirm with the passkey, and send the
`approval: accepted` or `approval: refused` line.

Not testable on this VM: fan control that the agent carries out itself (`ipmi.transport: ipmitool`) next to
the helper. On a PC set up that way: with trust set, `POST /fan/mode` without approval must answer `403
approval_required`, and `/metrics` must show `"agent_checks":["fan_set","fan_mode"]` in the `approval` block.

### Going back to build 16

`& "C:\Program Files\Fairy\fairy-agent.exe" helper-trust clear --yes`, then **Re-pair** on the VM's page in
the test panel and run the line it shows. It puts released build 16 back: the installer replaces a program
whose build number is not higher, and `16-selfbuilt` (build number 16) is not higher than 16. A program built
without a version (`dev`) is replaced as well. `helper\approval-trust.json` and
`helper\approval-boot-shutdown.json` are the only new files; build 16 ignores them.

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
