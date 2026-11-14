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

With power control on: in the panel, Reboot or Shut down with a 60 s delay. Windows shows its own notice
(`Fairy: reboot requested by <your panel user> in 60 seconds.`) and counts down; Cancel in the panel aborts
it, and Windows says so. Then once for real if convenient. helper.log lists each request with who asked.

**Sleep is different: Windows shows nothing.** A pending Sleep is a timer inside the helper, not a countdown
of Windows. There is no notice on the PC when it is set, none while it waits and none when it is cancelled;
only the panel shows it. Cancel in the panel stops the timer, the PC stays on, and Windows says nothing. (A
shutdown or reboot uses Windows' own shutdown notice and can be aborted; a sleep cannot be shown that way.)

Sleep, wake, then shutdown and cancel, by hand. For a PC or VM that can sleep (the panel's Power menu offers
Sleep; if it does not, skip this). It checks that a sleep that was carried out does not swallow the Cancel of
the next shutdown, as it did before 0.7.0:

1. Panel: **Sleep**, delay 60 s. Expected: the panel shows the pending sleep; nothing appears on the PC.
2. Let the minute run out. Expected: at its time the PC goes to sleep (the screen goes black, a VM is
   suspended), and the panel shows the host as asleep, from the panel (`ASLEEP (FROM PANEL)`).
3. Wake the PC: a key or the power button, the panel's "Power on" (Wake-on-LAN), for a VM "Resume" in the
   hypervisor. Expected: the panel shows the host running again, with nothing pending.
4. Panel: **Shut down**, delay 60 s. Expected: Windows shows `Fairy: shutdown requested by <your panel user>
   in 60 seconds.` and the panel shows the pending shutdown.
5. Panel: **Cancel**, within that minute. Expected: a few seconds later Windows shows "Logoff is cancelled:
   The scheduled shutdown has been cancelled.", the panel shows nothing pending, and the PC stays on. Wait
   until the minute is over to be sure. If the PC shuts down although Cancel said it was cancelled, that is
   the fault this test looks for: note the time and keep helper.log.

On the owner's test VM (13 Nov 2026, build of 0.7.0) all five steps went as written, and a Sleep cancelled
before its time left the VM on without any notice.

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
**[NEW 3]** `POST /approval/challenge` and `POST /power` with `cancel` each have a budget of their own of the
same size (12 a minute each); a `429` for a challenge reads `too many approval challenge requests`, not `too
many control requests`.

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
   -> `helper: running, answers on \\.\pipe\fairy-agent-helper`, a JSON line with `"proto":3`, then
   `pipe protocol:   3` and a line that starts with `approval:        off (checked by the helper)`.
   **[NEW 4]** (It was 2 in the zip of 2026-11-11. `pipe protocol:   2 (the test build of 2026-11-11; this
   agent needs 3)` means the helper is still that build: run the installer of this build, section H.)

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
   **[NEW 4]** under `to be written:` a line `machine id:      <22 characters> (names this machine in every
   approval; ...` with two lines about a copied disk under it, and after `signing keys:` a line
   `the machine id:   new, made up just now`,
   **[NEW 3]** a line `In effect within 5 seconds: the running helper (pipe protocol 3) ...` and one that
   starts with `Until then what was in effect before still counts`,
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
  -> **no** line `pipe protocol:   3`; instead `approval:        this helper is from before passkey approvals`.
* G1.3 No trust file yet: a shutdown far away is accepted as before (step 13's request, `delay_s` 86400)
  -> `[200]`; cancel it (step 14). `/metrics` (step 16) has **no** `approval` block.
  (If this answers `[503] approval_unavailable` with a text that ends `..., and this machine's approval trust
  file cannot be used (restart the helper: ...`, although there is no trust file: the agent's account could
  not check the helper's folder, and a folder it cannot check counts as a trust file that cannot be used.
  That is the open question of step N2; please send the answer. It fails closed: nothing runs, and G1.8's
  restart of the helper ends it.)
* G1.4 **[KEY]** Set the trust (step 7's command, with `--yes`).
  -> `written.`, then **`NOT IN EFFECT IN THE HELPER YET: the fairy-agent-helper that is running is from before
  passkey approvals`** and `Restart it now: Restart-Service fairy-agent-helper`. It must NOT say `In effect
  within 5 seconds`.
* G1.5 **[KEY]** At once (no waiting), step 13's shutdown without approval
  -> **`[503]` with `approval_unavailable`**, text `the running fairy-agent-helper is older than this agent`.
  Before this fix: `[200]`, the PC would have shut down. The same for `reboot`, `sleep`, `POST /fan/mode`,
  `POST /fan/duty` (if fans are on) and `POST /update`: all `[503] approval_unavailable`.
* G1.6 `POST /power` with `cancel` -> `[200]`. `POST /approval/challenge` -> `[409] helper_too_old`.
* G1.7 **[KEY]** `/metrics` -> `"approval":{"state":"unknown","enforced_by":"helper","proto":2,"error":"the
  running fairy-agent-helper is older than this agent ..."}`. Before this fix it said `"state":"required",
  "enforced_by":"agent"`.
* G1.8 `Restart-Service fairy-agent-helper`, then `helper-status` -> `pipe protocol:   3`,
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

**G4. Challenges cannot keep a cancel out.** Wait a full minute first (so that all budgets are fresh). Then
13 times in a row (a loop; no pause) step 26b's challenge request, or any `POST /approval/challenge`:
-> twelve answers that are not `429`, the 13th **`[429]` `too many approval challenge requests`**. At once:
`POST /power` with `{"action":"cancel"}` -> **`[200]`** (before this fix: `[429] too many control requests`).
Step 13's shutdown -> `[403] approval_required`, not `429`: the control budget is untouched.

**G5. Sixteen open challenges, and the 17th.** Needs `control_rate_per_min: 60` for this step only
(`fairy-agent config set control_rate_per_min 60`, `Restart-Service fairy-agent`; put 12 back afterwards) and
the trust set. 17 times in a row: `POST /approval/challenge` with
`{"verb":"power","action":"shutdown","delay_s":60}`
-> 16 answers `[200]` with `"needed":true`, the 17th **`[429]` with `too_many_challenges`** and `Try again in
... s` (before this fix: `[200]`, and the first challenge was gone without a word). `helper.log` has
`approval: no challenge given, too many are open`. After 90 seconds the same request -> `[200]`, and
`helper.log` has `the oldest open challenge was dropped for a new one`.

**G6. Whose trust a machine has.** With the trust set (step 8): `helper-status` and `helper-trust show` now
also print `trust hash:      <43 characters> ...` and `set by:          admin, <time> (on this machine:
helper-trust set)`. `/metrics` (step 16) has `"trust_hash":"<the same 43 characters>"`, `"set_by":"admin"`
and `"set_at":"..."` in the `approval` block. `helper-trust clear` (step 23) prints, under `removed. Approval
is off ...`, two lines that start with `That first-time set is open to whoever holds the control token`.

### H. The machine id **[NEW 4]** (none of this has run on Windows)

Since 2026-11-12 an approval is for one machine: the trust file holds a machine id, `/metrics` shows it, and
the helper checks every approval with the id of **its** file. The pipe protocol is 3 and the `proto` of the
`approval` block is 2. The zip of 2026-11-11 (pipe protocol 2) and this build do not work together in any
mix: **install this build's program for both services** (the installer does both), never one of them alone.

* H1 **A VM that still has the zip of 2026-11-11 and its trust file.** Before installing:
  `Get-Content "C:\ProgramData\fairy-agent\helper\approval-trust.json"` -> no `"machine_id"`. Note the
  file's access list and its owner (icacls does not show the owner):
  `icacls "C:\ProgramData\fairy-agent\helper\approval-trust.json"`
  `(Get-Acl "C:\ProgramData\fairy-agent\helper\approval-trust.json").Owner`
  Install this build (section A). Then:
  * H1.1 **[KEY]** `Get-Content "C:\ProgramData\fairy-agent\helper\approval-trust.json"` -> the second line
    is `"machine_id": "<22 characters>",` and every other line is as before.
  * H1.2 **[KEY]** `icacls` on the file -> the same access list as before;
    `(Get-Acl "C:\ProgramData\fairy-agent\helper\approval-trust.json").Owner` -> the same owner as before
    (`BUILTIN\Administrators` or `NT AUTHORITY\SYSTEM`; the file is a new one, made by the helper and renamed
    over the old one, so this is what shows whether it came out as the old one was);
    `fsutil hardlink list` on it (step N1) -> one line;
    `Get-ChildItem "C:\ProgramData\fairy-agent\helper" -Force` -> no file whose name starts with
    `.approval-trust-`.
  * H1.3 `Get-Content "C:\ProgramData\fairy-agent\helper\helper.log" -Tail 20` -> one line `approval: the
    trust file had no machine id ... one was added, nothing else in it changed` with `machine_id=<the same 22
    characters>`. `Restart-Service fairy-agent-helper`, look again: no second such line, the same id in the file.
  * H1.4 `helper-status` -> `pipe protocol:   3`, `approval:        required (checked by the helper)` and
    `machine id:      <the same 22 characters> (names this machine in every approval; ...`.
* H2 **[KEY]** `/metrics` (step 16) -> the `approval` block has `"proto":2` and `"machine_id":"<the same 22
  characters>"`, next to `trust_hash`, `set_by`, `set_at`.
* H3 `helper-trust show` -> the `machine id:` line, and under it `A machine made from a copy of this disk has
  the SAME id ... until the copy's trust is set anew: fairy-agent helper-trust set --new-machine-id`.
* H4 `helper-trust set --fan-window 20 --yes` -> `the machine id:   kept as it was`; `/metrics` shows the same
  id (wait 5 seconds). `helper-trust set --new-machine-id --yes` -> `the machine id:   NEW, it was <old>. The
  panel has the old one on record ...`; `/metrics` shows another id. Put the fan window back (`--fan-window 30`).
* H5 A first-time set from the network cannot change it. Step 25's file with one more member, sent as in
  step 26:
  `Get-Content "C:\fairy-selfbuilt\trust-init.json" -Raw | ConvertFrom-Json | Add-Member -NotePropertyName machine_id -NotePropertyValue "aaaaaaaaaaaaaaaaaaaaaaaa" -PassThru | ConvertTo-Json -Depth 5 | Set-Content -Path "C:\fairy-selfbuilt\trust-init-id.json" -Encoding ASCII`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\trust-init-id.json" "$base/approval/trust"`
  -> `{"code":"already_set","error":"this machine already has a trust file; ..."} [409]`, and `/metrics`
  (step 16) still shows the id of H4.
* H6 (only if the old zip is still around; otherwise skip) **One service of each build.** The agent of this
  build in front of the helper of 2026-11-11, with a trust file: `helper-status` -> `pipe protocol:   2 (the
  test build of 2026-11-11; this agent needs 3)`; step 13's shutdown -> `[503] approval_unavailable` with
  `the running fairy-agent-helper is older than this agent`; `POST /approval/challenge` -> `[409]
  helper_too_old`. Nothing runs. Install this build for both and it ends.

Not testable without the panel half: that an approval for another machine is refused (`[403] approval_refused`
with `approval refused (nonce)`, and in `helper.log` an `approval: refused` line with `note="the entry with
this machine's challenge names another machine id than this machine's"`). The Linux tests do exactly this
with a made-up Pocket ID (`TestApprovalForOneMachineIsRefusedByAnother`,
`TestWindowsHelperChecksWithItsOwnMachineID`, the second through the helper's code on an in-memory pipe).

### I. After the second round of the fifth audit **[NEW 5]** (none of this has run on Windows)

Three changes of 2026-11-12 that a VM can show. They need the trust of section B to be set and both services
running. `Test-FairyApproval-3.ps1` does them as its steps I1 to I3.

* I1 **[KEY]** **A made-up approval for an update is refused before anything is downloaded.** The agent now
  looks at an update's approval itself (with its own read-only look at `helper\approval-trust.json`) before
  it downloads; the helper still checks it afterwards. Needs `self_update.enabled: true`.
  `Set-Content -Path "C:\fairy-selfbuilt\update-junk.json" -Value '{"approval":{"token":"x","entries":[]}}' -Encoding ASCII`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\update-junk.json" "$base/update"`
  -> `{"code":"approval_refused","error":"approval refused (entries): the list of entries is not well-formed, ..."} [403]`
  at once, and `/metrics` (step 16) does NOT show `"self_update":{"state":"downloading"...`. Before this
  change: `{"state":"downloading",...} [202]`, the release was fetched, and a minute later `self_update`
  said `failed` with `starting the installer: helper: approval refused (entries)`.
  If it still answers `[202]`: the agent could not read the helper's trust file itself (the open question of
  step N2) and went on as before; nothing is installed (the helper refuses). Please send the answer, and
  `"agent_error"` of the `approval` block in `/metrics`.
  If it answers `{"code":"self_update_unavailable","error":"..."} [503]`: the step says nothing here. The
  updater's own checks come before the look at the approval, and this program was built without the release
  key, or the updater is not set up on this VM (`fairy-agent setup-self-update`); the `error` text says
  which. Nothing was downloaded. The script reports this as INFO, not as FAIL.
* I2 **A request in which a member is there twice is refused.**
  `Set-Content -Path "C:\fairy-selfbuilt\twice.json" -Value '{"action":"shutdown","delay_s":600,"action":"cancel"}' -Encoding ASCII`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\twice.json" "$base/power"`
  -> `{"error":"invalid JSON body: a name is used twice in one object"} [400]`. Before this change: `[200]`
  with `"action":"cancel"` (the last of the two counted). The body is made so that an agent from before the
  change cancels, and schedules nothing.
* I3 **[KEY]** **Wrong tokens do not keep the right token out.** 21 requests with a wrong token, then the
  right ones (one line; it prints the 21 answers):
  `1..21 | ForEach-Object { curl.exe -s -o NUL -w "%{http_code} " -H "Authorization: Bearer wrong-wrong-wrong-wrong-wrong" "$base/metrics" }`
  -> `401` twenty times (or fewer, if something else failed in the same minute), then `429`.
  `curl.exe -s -o NUL -w "[%{http_code}]" -H "Authorization: Bearer $read" "$base/metrics"` -> **`[200]`**
  (before this change: `[429]`, for a minute). Step 14's cancel -> **`[200]`**. The wrong token once more
  -> `{"error":"too many failed requests"} [429]`. (`$read` is the read token of step 11.)

### What to send back

The output of steps 5, 8, 9, 13, 15, 20, 26, 26b, 27, 28, N1, N2 (and 31, 32b if done), of G1.2, G1.4, G1.5,
G1.7, G1.8, G4, G5 and G6, of H1.1 to H1.4, H2 and H4, of I1 and I3, and:
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

**[NEW 3]** That is the point of the `clear` above, and it holds without it too: build 16 ignores a trust
file, so on a PC that went back with the file still in place the check is simply OFF (no `approval` block in
`/metrics`, step 13's shutdown is accepted) until the new program is installed again, which then enforces
the same trust as before.

## 14. Runs (0.9.0): approvals inside "Update unpowered hosts" (none of this has run on Windows)

What it is: AGENT.md, "Runs". The checking code was tested on Linux with a made-up Pocket ID, the helper's
part on an in-memory pipe. On a real PC, before a panel knows runs, only the refusals, `helper-run` and "the
old approvals still work" can be shown (part A). An ACCEPTED ticket needs the panel (part B, later).

Needs: the trust of section 13 B set, both services running, `power_control.enabled: true` and
`self_update.enabled: true`, and `$ctl`, `$read`, `$base` as in section 13. One step is one line, in **Windows
PowerShell as Administrator**; after `->` is what a good answer looks like. Nothing here switches the PC off.

### A. Without a panel that knows runs

* J1 **[KEY]** **The block says what the machine can do, and nothing else changed in it.**
  `curl.exe -s -H "Authorization: Bearer $read" "$base/metrics" | Select-String -Pattern '"approval":\{[^}]*\}' | ForEach-Object { $_.Matches.Value }`
  -> `"approval":{"state":"required","enforced_by":"helper","proto":2, ... ,"runs":1}`: `"proto":2` as before,
  `"runs":1` new, no `"run"`.
* J2 **[KEY]** **A request alone arms nothing.**
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" -d "{}" "$base/run/arm"`
  -> `{"error":"a run ticket is an approval: the body needs \"approval\""} [400]`
  `Set-Content -Path "C:\fairy-selfbuilt\arm-junk.json" -Value '{"approval":{"token":"x","entries":[]}}' -Encoding ASCII`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\arm-junk.json" "$base/run/arm"`
  -> `{"code":"approval_refused","error":"approval refused (entries): the list of entries is not well-formed, ...","reason":"entries"} [403]`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $read" -d "{}" "$base/run/arm"` -> `{"error":"unauthorized"} [401]`
* J3 **The challenge for a confirmation is given, the confirmation without approval is refused.**
  `Set-Content -Path "C:\fairy-selfbuilt\go.json" -Value '{"verb":"run_go","run":"00000000000000aa","to":"-","shutdown_delay_s":60,"within_s":300}' -Encoding ASCII`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\go.json" "$base/approval/challenge"`
  -> `{"needed":true,"request":"run_go run=00000000000000aa to=- shutdown_delay_s=60 within_s=300","challenge":"...","expires_in_s":180,"issuer":"...","client_id":"..."} [200]`
  (`shutdown_delay_s` below the PC's `power_control.min_delay_s`: `{"code":"run_refused",...,"reason":"limits"} [409]`.)
  `Set-Content -Path "C:\fairy-selfbuilt\go2.json" -Value '{"run":"00000000000000aa","to":"-","shutdown_delay_s":60,"within_s":300}' -Encoding ASCII`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" --data-binary "@C:\fairy-selfbuilt\go2.json" "$base/run/go"`
  -> `{"code":"approval_required","error":"this needs a passkey approval (Pocket ID) and the request carried none"} [403]`
  A challenge for a ticket is never given:
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" -d '{\"verb\":\"run_arm\",\"run\":\"00000000000000aa\",\"valid_s\":420,\"wait_s\":960,\"notice_s\":120}' "$base/approval/challenge"`
  -> `{"error":"a run ticket (run_arm) answers no challenge: it is sent to POST /run/arm"} [400]`
* J4 **[KEY]** **A shutdown or an update that names a run nobody confirmed is refused like one without approval.**
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" -d '{\"action\":\"shutdown\",\"delay_s\":600,\"run\":\"00000000000000aa\"}' "$base/power"`
  -> `{"code":"approval_required","error":"this needs a passkey approval (Pocket ID) and the request carried none; the run it names does not cover it: no run is confirmed on this machine in this boot"} [403]`
  `curl.exe -s -w " [%{http_code}]" -H "Authorization: Bearer $ctl" -d '{\"run\":\"00000000000000aa\"}' "$base/update"`
  -> the same `[403]`; `/metrics` does NOT show `"self_update":{"state":"downloading"`.
  Then step 14 of section 13 (cancel) -> `[200]`, in case anything was scheduled after all.
* J5 **`helper-run` on the PC.**
  `& "C:\Program Files\Fairy\fairy-agent.exe" helper-run show` -> `run record:  C:\ProgramData\fairy-agent\helper\approval-run.json`,
  `run:  none is armed or confirmed`, a line `clock on record:` with a time of the last minutes, and `record made:` with the
  time the helper first started with the trust set.
  `& "C:\Program Files\Fairy\fairy-agent.exe" helper-run cancel` -> `no run is armed or confirmed on this machine (...): nothing changed`
  `Get-Content "C:\ProgramData\fairy-agent\helper\approval-run.json"` -> one line
  `{"version":1,"at":{"boot_id":"<32 hex>","wall":...,"up_ms":...},"arm":{...},"clock":...,"born":...}` and no `"run"`, `"used"`
  or `"last"` in it (the record is on every PC with trust; nothing above put anything of a run into it).
  `icacls "C:\ProgramData\fairy-agent\helper\approval-run.json"` -> the same lines as for `approval-trust.json` in that folder.
* J6 **The helper's log has the refusals and no token.**
  `Get-Content "C:\ProgramData\fairy-agent\helper\helper.log" -Tail 20`
  -> lines `approval: run ticket refused ... reason=entries` and `approval: required, none sent; the run named does not cover it`; `verb=run_arm` in the `request` line of J2; nowhere the `x` of the junk token as a value.
* J7 **[KEY]** **The old approvals still work.** With the panel you have (build 14): press Shut down on the VM's
  page, confirm with the passkey, then Cancel. -> as before: `approval: accepted` in `helper.log`, the Windows
  notice, the cancel.
* J8 **Without a trust file the two routes say so.** After `helper-trust clear --yes`:
  the second line of J2 -> `{"code":"approval_off","error":"approval is off on this machine: ..."} [409]`,
  and the first line of J4 with `"delay_s":600` -> `[200]` with `"pending"` (then cancel, step 14): `run` is
  ignored on a machine without the check. Set the trust again (section 13 B) afterwards.
* J9 **[KEY]** **Does the uptime start again after a wake?** The ticket arms only a PC that has been up for
  less than 10 minutes. Shut the VM / PC down from the Start menu, wake it, and within two minutes:
  `curl.exe -s -H "Authorization: Bearer $read" "$base/metrics" | Select-String -Pattern '"uptime_s":[0-9.]+' | ForEach-Object { $_.Matches.Value }`
  -> a number under 600. A number of hours or days: Fast Startup keeps Windows' uptime across a shutdown on
  this PC; such a PC is never armed by a ticket (`not_fresh`) and stays ON in a run. Please send the number.

* J10 **[KEY]** **The id of the boot (new; the helper makes it, Windows has none).**
  `reg query "HKLM\SOFTWARE\FairyAgentBoot"` -> one value: `id    REG_SZ    <32 hex characters>`, and no subkey.
  `(Get-Acl "HKLM:\SOFTWARE\FairyAgentBoot").Owner` -> `BUILTIN\Administrators` (or `NT AUTHORITY\SYSTEM`)
  `(Get-Acl "HKLM:\SOFTWARE\FairyAgentBoot").Access | Format-Table IdentityReference,RegistryRights,IsInherited`
  -> three lines, none inherited: `NT AUTHORITY\SYSTEM FullControl`, `BUILTIN\Administrators FullControl`,
  `NT AUTHORITY\Authenticated Users ReadKey`. Anything else, or `IsInherited True`: please send it.
  `Select-String -Path "C:\ProgramData\fairy-agent\helper\helper.log" -Pattern "cannot say which boot"` -> nothing.
  J1 again -> still `"runs":1` (the agent's own account can read the key: it shows the helper's block either way,
  so also do J4 again: its text must still be `... no run is confirmed on this machine in this boot`).
* J11 **[KEY]** **The id stays through a restart of the services and is another one after a restart of Windows.**
  Note the id of J10. `Restart-Service fairy-agent-helper; Restart-Service fairy-agent`, then `reg query` again -> the same id.
  `Restart-Computer`, then `reg query` again -> ANOTHER id (the key is in memory only). The same id after a
  restart would be a fault: please send both outputs.
* J12 **[KEY]** **Fast Startup, sleep, hibernation.** Three times: note the id and `uptime_s` (J9), then
  (a) Start menu > Sleep, wake it; (b) `shutdown /h` (hibernate), switch it on; (c) with Fast Startup ON (Control
  Panel > Power Options > "Choose what the power buttons do" > "Turn on fast startup"), Start menu > Shut down,
  switch it on. Each time `reg query` and `uptime_s` again.
  -> by Microsoft's documentation all three keep BOTH the id and the uptime (it goes on counting, also through the
  time the PC was off): for Windows this is the same boot. Such a PC is then not armed by a ticket (`not_fresh`)
  and stays ON in a run, which is the safe side. If (c) shows another id or an `uptime_s` near zero, please send
  it: then a wake after a Fast Startup shutdown is a new start for Fairy on this PC, and the notes in AGENT.md
  ("The boot") are too careful for it. `shutdown /s /t 0` with Fast Startup OFF (or `shutdown /s /f /t 0` and
  `powercfg /h off`) -> another id and an `uptime_s` under 600, as after J11's restart.
* J13 **The record can be written while somebody reads it.** In a second Administrator window:
  `$f = [System.IO.File]::Open("C:\ProgramData\fairy-agent\helper\approval-run.json","Open","Read","ReadWrite,Delete")`
  Wait two minutes, then in the first window `Restart-Service fairy-agent-helper` (it writes the clock into the
  record when it stops and starts), then `Select-String -Path "C:\ProgramData\fairy-agent\helper\helper.log" -Pattern "could not be written" | Select-Object -Last 2`
  -> no new line: the new record took the name although the file was open. `$f.Close()`.
  The same once more with `"ReadWrite"` in the place of `"ReadWrite,Delete"` (a program that does not share for
  delete) -> now a line `approval: the run record could not be written` is expected while the file is held;
  `$f.Close()`, `Restart-Service fairy-agent-helper` again -> written, and J1 still shows `"runs":1`. Please send
  what the first half showed: if the rename fails there too, Windows does not let a file take the name of one
  that is open even with sharing, and we need to know.
* J14 **A record that cannot be read is replaced, not removed.**
  `Stop-Service fairy-agent-helper`
  `Set-Content -Path "C:\ProgramData\fairy-agent\helper\approval-run.json" -Value "{broken" -Encoding ASCII`
  `& "C:\Program Files\Fairy\fairy-agent.exe" helper-run show` -> `run:  the record cannot be used: ...`
  `& "C:\Program Files\Fairy\fairy-agent.exe" helper-run cancel` -> `the run record could not be read (...) and was replaced by a new one. ...`
  `& "C:\Program Files\Fairy\fairy-agent.exe" helper-run show` -> `run:  none is armed or confirmed`, `record made:` with the time of now.
  `icacls "C:\ProgramData\fairy-agent\helper\approval-run.json"` -> the same lines as for `approval-trust.json`.
  `Start-Service fairy-agent-helper`, J1 -> `"runs":1`; `helper.log` has no `the run record cannot be used` after the start.
* J15 **The lock of the record's two writers.**
  `Get-Item "C:\ProgramData\fairy-agent\helper\approval-run.lock" | Format-List Length,CreationTime` -> `Length : 0`
  (the helper made it when it first wrote the record), and
  `icacls "C:\ProgramData\fairy-agent\helper\approval-run.lock"` -> the same lines as for `approval-trust.json`.
  Now hold it as a third program would:
  `$l = [System.IO.File]::Open("C:\ProgramData\fairy-agent\helper\approval-run.lock","Open","ReadWrite","ReadWrite"); $l.Lock(0,1)`
  `Restart-Service fairy-agent-helper`, wait ten seconds,
  `Select-String -Path "C:\ProgramData\fairy-agent\helper\helper.log" -Pattern "could not be written" | Select-Object -Last 1`
  -> a new line `approval: the run record could not be written error="the lock of the run record (approval-run.lock) cannot be taken: ..."`
  (the helper writes nothing while somebody else holds the lock).
  `Measure-Command { & "C:\Program Files\Fairy\fairy-agent.exe" helper-run cancel }` -> about 3 seconds, and no
  error (the command waits for the lock and then goes on without it).
  `$l.Unlock(0,1); $l.Close()`, `Restart-Service fairy-agent-helper` -> no new `could not be written` line after
  this start, and J1 still shows `"runs":1`. Please send the two `helper.log` lines and the measured time: if
  the FIRST start of the helper (before anything held the lock) already logged `the lock of the run record ...
  cannot be taken`, the lock does not work on Windows as written, the helper then keeps no runs, and we need
  the whole line.

### B. With a panel that knows runs (later)

Start a run for this PC only, confirm the start with the passkey, and do NOT confirm the second time.

* K1 **[KEY]** When the PC is up: `Get-Content "C:\ProgramData\fairy-agent\helper\helper.log" -Tail 10`
  -> `approval: run armed result=accepted run=<16 hex> sub=... kid=... wait_s=... notice_s=...`.
  `& "C:\Program Files\Fairy\fairy-agent.exe" helper-run show` -> `run:  <id>, armed: this machine switches itself off in <time> ...`
  `icacls "C:\ProgramData\fairy-agent\helper\approval-run.json"` -> the same lines as for `approval-trust.json`
  in that folder (SYSTEM and Administrators full, the agent's account read), and
  `Select-String -Path "C:\ProgramData\fairy-agent\helper\approval-run.json" -Pattern "eyJ"` -> nothing (no token in it).
* K2 **[KEY]** Wait for the time `helper-run show` named. -> Windows shows its own notice, with the whole text
  `Fairy: this PC was started for an update by <name> and nobody confirmed it. It shuts down in <n> seconds. To keep it on: press Cancel for this PC in the Fairy panel, or here press Windows+R and type: shutdown, a space, a slash and the letter a. (Administrators can also run: fairy-agent helper-run cancel)`.
  Please send a photo: whether the text is shown whole (it is about 310 characters), and whether the two
  hyphens of `fairy-agent helper-run` look like hyphens (they are the non-breaking kind, U+2011). `/metrics` shows `"pending":{"action":"shutdown",...,"requested_by":"run <id>"}`.
* K3 **[KEY]** `shutdown /a` -> the notice goes away and the PC stays on. Two minutes later:
  `helper-run show` -> `run:  none is armed or confirmed` and `last run:  <id>, cancelled`; `helper.log` has
  `approval: run cancelled ... why="the machine is still running after the countdown: ..."`.
* K4 Start the same run again from the panel (the PC is on now) -> the panel reports that it could not be
  armed; `helper.log`: `approval: run ticket refused ... reason=not_fresh` (or `already_armed`).
* K5 **[KEY]** A second run, and this time press Cancel in the panel while the PC waits. -> `helper.log`:
  `approval: run cancelled ... why="a cancel of the pending power action"`; the PC stays on past the time.
* K6 **[KEY]** A third run, confirmed the second time. -> `approval: run confirmed`, then the update (the
  helper restarts), `approval: run taken over from the record (this service was restarted)`, `approval:
  accepted, the one shutdown of the run`, the ordinary shutdown notice, the PC goes off. Please send the
  `helper.log` lines of the whole run. (If the update is refused with `... no run is confirmed on this machine
  in this boot` although `helper.log` says `run confirmed`: the agent's own account could not read the key of
  the boot id, J10. Please send the `Access` list of J10 then.)

* K7 **[KEY]** **The helper stopped over the end of the wait: the PC stays on.** A fourth run, not confirmed. While
  the PC waits (`helper-run show` names the time): `Stop-Service fairy-agent-helper`. Wait until three minutes
  after that time. `Start-Service fairy-agent-helper`. -> NO notice and no shutdown, now or later;
  `helper.log`: `approval: run cancelled ... why="the wait ended ... ago while nothing looked (...): no self-off now, the machine stays on"`;
  `helper-run show` -> `last run:  <id>, cancelled`.
* K8 **The panel's Cancel while the helper is stopped is not "cancelled".** A run, not confirmed; while the PC
  waits: `Stop-Service fairy-agent-helper`, then Cancel in the panel. -> the panel shows an error (the agent
  answers `503 helper_stopped`), not "cancelled". `Start-Service fairy-agent-helper`, Cancel again -> cancelled,
  `helper.log`: `approval: run cancelled ... why="a cancel of the pending power action"`.
* K9 **A second ticket in the same boot is refused after a clock change.** After K5 (cancelled, PC on): set
  the PC's clock forward by ten minutes (`Set-Date (Get-Date).AddMinutes(10)`), `Restart-Service
  fairy-agent-helper`, start a new run for it from the panel. -> not armed; `helper.log`:
  `approval: run ticket refused ... reason=not_fresh` or `reason=already_armed`. Set the clock right again
  (`w32tm /resync`). Then set it BACK by ten minutes and try once more -> `reason=clock_back` (or one of the
  two before); it stays on. Set it right again.

### What to send back

The output of J1, J2, J4, J5, J9 to J15 and the tail of `helper.log` (J6); later K1 to K9.

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
