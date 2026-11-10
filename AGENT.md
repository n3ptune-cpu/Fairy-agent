# fairy-agent

fairy-agent is a small program you install on each computer you want to see in the Fairy panel. It answers the
panel's questions ("how busy is the CPU, how full are the disks, which programs are running...") over your
Tailscale network. It is one file, needs nothing else installed, and uses very little: about 15 MB of memory and
well under 1 % of one CPU core while the panel watches it every second.

Out of the box it only **reads**. It can also restart or shut down the machine, control a Supermicro server's
fans, wake other computers on the network, or update itself when you press Update in the panel, but only if you
switch each of those on yourself.

The panel itself is [Fairy-dashboard](https://github.com/n3ptune-cpu/Fairy-dashboard). How to build fairy-agent
from source, and a map of the code, are in [README.md](README.md).

* [What it never touches (anti-cheat safety)](#what-it-never-touches-anti-cheat-safety)
* [Add a host from the panel (one command)](#add-a-host-from-the-panel-one-command): the easy way
* [Install on Windows](#install-on-windows)
  * [Two services: the agent and its helper](#two-services-the-agent-and-its-helper)
* [Install on Linux](#install-on-linux)
  * [Check your Linux agents: are the sandbox lines still on?](#check-your-linux-agents-are-the-sandbox-lines-still-on)
* [Point the panel at it](#point-the-panel-at-it)
* [Optional features](#optional-features): fan control, shutdown / reboot, Wake-on-LAN, plugs and UPSes
* [Updates (the panel's Update button)](#updates-the-panels-update-button)
* [What it can and cannot show](#what-it-can-and-cannot-show)
* [Core Temp (optional, Windows)](#core-temp-optional-windows): CPU core temperatures and watts on Windows
* [Settings (config.yaml)](#settings-configyaml)
* [Checking, logs, updating, removing](#checking-logs-updating-removing)
* [Security in short](#security-in-short)
* [Not yet tested on a real Windows PC](#not-yet-tested-on-a-real-windows-pc)

---

## What it never touches (anti-cheat safety)

fairy-agent was written so it can run on a gaming PC with kernel anti-cheat (Vanguard, EasyAntiCheat,
BattlEye, FACEIT...) without looking like a cheat:

* **No driver of any kind.** It does not install or load a driver: no WinRing0, no LibreHardwareMonitor or
  OpenHardwareMonitor, no inpout, nothing in the kernel. It only uses the normal, documented Windows functions
  that Task Manager and Performance Monitor use.
* **It never reads or writes another program's memory**, never injects anything into another program, never
  hooks anything, and never asks Windows for more than the weakest kind of access to another program
  ("query limited information": enough to ask how much CPU time and memory it used and where its .exe file
  is). If Windows says no, the agent quietly skips that program's details.
* You can tell it to **never even open** certain programs (for example your game's .exe): `never_open` in the
  settings. Or switch the Processes tab off completely (`processes: enabled: false`): then it does not look at
  other programs at all.
* **Not packed or obfuscated**: a plain Go program, built from the source in this repository.
* It runs at **below-normal priority** and starts helper programs (only `nvidia-smi`, and `powershell.exe` if
  you enable IPMI fan control) at below-normal priority without a window.
* On Windows the agent runs as its **own low-rights account** (`NT SERVICE\fairy-agent`). The few things that
  need more (Core Temp, the BMC, shutdown / sleep) are done by a second, small service, **fairy-agent-helper**,
  that has no network at all and only answers a fixed list of requests from the agent (see
  [Two services](#two-services-the-agent-and-its-helper)). Neither of them loads a driver.
* Graphics card numbers come from `nvidia-smi`, NVIDIA's own tool that comes with the driver, started once and
  left running in its "repeat every 2 seconds" mode.
* Temperatures on Windows come from the ACPI thermal zones that Windows itself publishes as performance
  counters, and, only if you switch it on, from the Core Temp program you already run (see
  [Core Temp](#core-temp-optional-windows)). Fan control talks to the server's management chip (BMC) through Windows' own built-in IPMI support.

What it does **not** do on Windows as a result: see [What it can and cannot show](#what-it-can-and-cannot-show).

## Add a host from the panel (one command)

Like adding a machine to Tailscale: no editor, no token copying.

1. In the panel (admins): **Add host** on the Overview page. Fill in the machine's **Tailscale name** (as in
   the Tailscale admin console, e.g. `agent-1`; the panel reaches it at `http://<name>:9101`, or give its
   100.x address), its site, Linux or Windows, and tick what the agent may do: shutdown / reboot,
   self-update, Wake-on-LAN relay, reading the UPS of a local NUT server, Core Temp (Windows), attaching it to
   a Proxmox node, and the MAC addresses to wake it with.
2. The panel asks you to confirm it's you (Pocket ID), then shows **one command** with a one-time code
   (valid 15 minutes, works once). Copy the whole command. Do not type it by hand and do not shorten it.
3. Run it on the machine:
   * **Linux**: as a user with sudo. On a Proxmox node, as root (the panel then leaves out `sudo`).
   * **Windows**: in PowerShell as Administrator, as one line.
4. The dialog goes from *waiting for the machine* to *paired* to *online*, and the host appears.

**Always use the command from the panel.** There is no "latest" install line any more. A line that downloads
whatever is newest and runs it cannot be checked by anybody. The panel's command names **one** release, and the
panel has already checked that release's signature with its own built-in release key.

**How to recognise the command.** The panel fills in every value. The words in capitals below are not for you to
replace; they only show where the panel's values are.

Linux:

```
f=$(mktemp) && curl -fsSL --proto '=https' -o "$f" BASE/install.sh && echo "SH_HASH  $f" | sha256sum -c - && printf '%s' 'CODE' | sudo env FAIRY_RELEASE_URL=BASE sh "$f" --sums-sha256 SUMS --join-stdin --pair-v2 --panel PANEL [options]
```

Windows:

```
$u='BASE'; $b=(New-Object Net.WebClient).DownloadData("$u/install.ps1"); if ((([Security.Cryptography.SHA256]::Create().ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) -join '') -ne 'PS1_HASH') { throw 'install.ps1 is not the release the panel checked: not run' }; $env:FAIRY_JOIN_CODE='CODE'; & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) -ReleaseUrl $u -SumsSha256 SUMS -PanelAddress PANEL -PairV2 [options]
```

| In the line | What the panel puts there |
| --- | --- |
| `BASE` | the address of one release, `https://github.com/n3ptune-cpu/Fairy-agent/releases/download/build-<number>`. Never `latest`. |
| `SH_HASH`, `PS1_HASH` | the SHA-256 of that release's `install.sh` / `install.ps1`. A script with any other content is not run. |
| `SUMS` | the SHA-256 of that release's `SHA256SUMS` file, which the panel checked with its own release key. |
| `CODE` | the one-time join code. |
| `PANEL` | the panel's Tailscale address (an IPv4 address such as `100.64.0.10`). Only this address may pair. |
| `[options]` | what you ticked. Linux: `--power-control`, `--self-update`, `--wol`, `--ipmi`, `--proxmox`, `--ups` or `--ups-name NAME`. Windows: `-PowerControl`, `-SelfUpdate`, `-Wol`, `-CoreTemp`, `-Ipmi`, `-Ups` or `-UpsName NAME`. |

**The join code is never an argument of a program.** Other users of the machine can read the arguments of a
running program. So:

* Linux: `printf` hands the code to the script on standard input (`--join-stdin`). The script hands it to
  `fairy-agent join --code-stdin` on standard input too.
* Windows: the line puts the code into the environment variable `FAIRY_JOIN_CODE` of that PowerShell window. The
  script reads it, removes the variable at once and hands the code to `fairy-agent join` through that
  program's environment.
* `install.sh` also takes the code from `FAIRY_JOIN_CODE` when `--join-stdin` is not given. `sudo` does not pass
  that variable on by default, which is why the panel's line uses standard input.
* The scripts and `fairy-agent join` never print the code.
* On Windows the line you pasted stays in PowerShell's history file, with the code in it. The code works once
  and for 15 minutes only.

**Lines from an older panel** look different: they carry the code as `--join CODE` (Linux) or `-Join CODE`
(Windows), have no `--pair-v2` / `-PairV2`, and on Windows save the script to a file first. The scripts still
accept them. On Linux the script then prints a note that the code was readable on the command line while it
ran. Update the panel to get the new line.

**Without the panel's fingerprint the scripts stop.** `install.sh` without `--sums-sha256` and `install.ps1`
without `-SumsSha256` end with `no release fingerprint` before they download anything. The options
`--unverified` (Linux) and `-Unverified` (Windows) go on anyway. Then, on a first install, nothing checks the
download but the downloaded program itself, and the script prints `NOT independently verified`. Do not use
them unless you checked the release yourself as in
[SETUP-UPDATES.md, part 2](SETUP-UPDATES.md#part-2-installing-or-updating-an-agent-by-hand).

**What the command does**, in order:

1. It downloads the install script of the named release and compares its SHA-256 with the one in the line. A
   different script is not run.
2. The script downloads the release's files. It refuses a `SHA256SUMS` whose SHA-256 is not the one the panel
   passed, before it trusts a line of it. It then checks every file against `SHA256SUMS`, and the signature of
   `SHA256SUMS` with the release key built into fairy-agent (on Linux the installed agent's key when there is
   one, otherwise the downloaded program's; on Windows always the downloaded program's).
3. **Never older.** When the installed fairy-agent is a newer build than the release in the line, the program
   stays (on Linux its service files too). The script says so (`is NEWER than this installer's release`) and
   goes on with the settings and the pairing. The cure is to update the panel, which then names a newer
   release. On Windows the installed program is asked for its version only when nobody but administrators
   could have changed it or its folder; otherwise it is replaced by the checked program without being run.
4. It installs as described in [Install on Windows](#install-on-windows) / [Install on Linux](#install-on-linux):
   user, program, service, polkit / tmpfiles rules when needed, a firewall rule for the panel only, and on
   Windows the elevated helper service when Core Temp, IPMI or shutdown / reboot is chosen.
5. It runs `fairy-agent join`. That makes the tokens on the machine, switches on the chosen features with the
   same checked edit as `fairy-agent config set`, and stores what the agent needs to recognise the panel, with
   its expiry and the panel's address. The code itself is never stored.
6. The panel asks the agent `POST /pair`. The agent answers **once**, only to the panel's address, with its
   tokens, and closes pairing for good (`fairy-agent pair-status` shows it).

The agent still never connects to the panel. The panel keeps the tokens in its own state folder, not in
`config.yaml`.

**Pairing v2** (`--pair-v2` / `-PairV2`, in the line when the panel speaks it): the panel must first prove that
it has the join code, and the agent's answer with the tokens is encrypted so that only a holder of the code
can open it. A program that only listens on the network learns nothing, and a program that answers in the
agent's place is not believed. The version is fixed by the command, never agreed over the network: an agent
that was given a v2 code refuses a v1 request (`400 wrong_version`) and the other way round. Without the option
(older panels) pairing works as before 0.6.0: the panel sends a proof of the code and the tokens come back
unencrypted inside Tailscale.

* **Lost the panel's copy of the tokens**, or the code expired before the machine ran it: **Re-pair** on the
  host's page makes a new code and the same command; running it again keeps the machine's settings but makes
  **new** read and control tokens (the old ones stop working at once, so whoever had them loses access) and
  hands those to the panel.
* **Remove host** (hosts added this way) forgets the host and its tokens in the panel. On the machine, remove
  the agent as in [Checking, logs, updating, removing](#checking-logs-updating-removing).
* Hosts written by hand into the panel's `config.yaml` keep working exactly as before.
* **A new Proxmox VE node** ("Is it a Proxmox node? Yes: a new node", panel and agent v0.4.2): the Linux
  command gets `--proxmox`, and `fairy-agent join` (as root on the node) also makes the panel a **read-only**
  API token, idempotently: `pveum user add fairy@pve --comment "Fairy panel, read-only"` (an existing user is
  fine), `pveum aclmod / --users fairy@pve --roles PVEAuditor`, and `pveum user token add fairy@pve
  panel-<node> --privsep 0 --output-format json` (a token of that same name is removed first; no other token is
  touched). The secret is read from pveum's JSON, never printed, and kept with the node's CA
  (`/etc/pve/pve-root-ca.pem`), its name and `https://<Tailscale name>:8006` in the pairing state (0600, only
  root and the agent), which hands it to the panel **once** with the agent's tokens and drops it at the same
  moment (also when the code expires). The panel then polls the node through the Proxmox API (verifying the
  certificate against that CA, for the node's name, which Proxmox's own certificate lists) and attaches the
  agent to it. If the node's certificate does not list its name, join warns: `pvecm updatecerts --force`, then
  `systemctl restart pveproxy`. With a custom (e.g. ACME) certificate the panel checks it against the public
  CAs. **Standalone nodes only**: in a cluster of more than one node join says so and skips the token (the agent
  still installs; add the cluster by hand under the panel's `proxmox:`). To withdraw the token later:
  `pveum user token remove fairy@pve panel-<node>` on the node.
* An agent *on* a Proxmox node the panel already polls: tick "attach to Proxmox node" (Yes: <that node>).

## Install on Windows

You need: Windows 10 or 11 (64-bit), Tailscale installed and signed in with **Run unattended** switched on
(Tailscale icon > Preferences > Run unattended, or `tailscale up --unattended`; without it Tailscale only
connects after someone signs in to Windows, so after a reboot or a Wake-on-LAN the panel shows the PC offline
until then; the installer warns when it is off), and the files
`fairy-agent-windows-amd64.exe` and `install-fairy-agent.ps1` of **one** release. Download and check them as in
[SETUP-UPDATES.md, 2.3](SETUP-UPDATES.md#23-by-hand-from-one-named-release-checked). The usual way is
[Add host](#add-a-host-from-the-panel-one-command); this section is for doing it by hand.

**The easy way.** Put both files in one folder, open **PowerShell as Administrator** (right-click the Start
button, "Terminal (Admin)"), go to that folder and run:

```powershell
cd $HOME\Downloads\fairy-agent        # wherever you put the two files
Set-ExecutionPolicy -Scope Process Bypass   # allows this one script, for this window only
.\install-fairy-agent.ps1 -PanelAddress 100.64.0.2   # the Tailscale address of the machine running the panel
```

Add `-Helper` on a PC where you want fan control, Core Temp or shutdown / reboot / sleep (the script also adds
it by itself when `config.yaml` already switches one of them on). `-LocalSystem` from older instructions still
works and means the same as `-Helper`.

**What the script does, step by step** (you can also type these yourself):

```powershell
# 1. copy the program to a folder only administrators can change
New-Item -ItemType Directory -Force "C:\Program Files\Fairy" | Out-Null
Copy-Item .\fairy-agent-windows-amd64.exe "C:\Program Files\Fairy\fairy-agent.exe"
Unblock-File "C:\Program Files\Fairy\fairy-agent.exe"

# 2. install the service (starts automatically with Windows, a little after boot, restarts itself on failure).
#    This also creates C:\ProgramData\fairy-agent with config.yaml, token and control-token, readable only by
#    administrators, SYSTEM and the service itself.
& "C:\Program Files\Fairy\fairy-agent.exe" install          # or: install --helper

# 3. let only the panel in: TCP 9101, only on the Tailscale adapter, only from Tailscale addresses
New-NetFirewallRule -DisplayName "Fairy agent (Tailscale only)" -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 9101 -RemoteAddress 100.64.0.0/10 -InterfaceAlias Tailscale `
  -Program "C:\Program Files\Fairy\fairy-agent.exe"
#    with the helper (install --helper): it never uses the network, so block all of its traffic
foreach ($d in 'Outbound', 'Inbound') { New-NetFirewallRule -DisplayName "Fairy agent helper (no network)" `
  -Direction $d -Action Block -Service fairy-agent-helper }

# 4. check the settings and start it
& "C:\Program Files\Fairy\fairy-agent.exe" check-config
Start-Service fairy-agent
```

See [Two services](#two-services-the-agent-and-its-helper) for the accounts and what each service may do.

By default the agent listens on this PC's Tailscale address, port 9101 (it finds it by itself). It never listens
on your home network or the internet unless you set `listen:` yourself. Until Tailscale is up the agent waits
(as long as it takes; the log says so once a minute) and then starts answering by itself.

### Two services: the agent and its helper

Since 0.5.0 (release build 11 or later) fairy-agent on Windows is two services that run the same program:

| | **fairy-agent** (the agent) | **fairy-agent-helper** (the helper) |
| --- | --- | --- |
| Account | `NT SERVICE\fairy-agent`, a "virtual account": no password, cannot sign in, a member of no admin group (only of "Performance Monitor Users", see below) | LocalSystem |
| Rights | only `SeChangeNotifyPrivilege` (needed to open folders); no shutdown, no impersonation, nothing else | only `SeChangeNotifyPrivilege`, `SeShutdownPrivilege`, `SeImpersonatePrivilege` (to see who connects); no driver loading, no debugging other programs, no taking over files |
| Network | listens on the Tailscale address for the panel; the tokens, `/metrics`, everything the panel sees | **none**: listens only on the local pipe `\\.\pipe\fairy-agent-helper`; a firewall rule blocks all its traffic in and out |
| Files | reads `C:\ProgramData\fairy-agent` (config, tokens), writes only `logs\`, `state\` and `update\stage\` | reads config.yaml, writes only its own log `C:\ProgramData\fairy-agent\helper\helper.log` (the agent can only read it) |
| Installed | always | only where something needs it: Core Temp, IPMI (BMC sensors, fans) or shutdown / reboot / sleep |

**What the helper does, and nothing else.** It answers ten fixed requests from the agent: `ping`, `status`,
`coretemp_read` (a copy of Core Temp's shared memory; the agent checks and converts it), `ipmi_sensors` (the
BMC's readings), `fan_status`, `fan_set` (zone 0 or 1, 30-100 %), `fan_mode` (standard, full, optimal or
heavyio), `fan_auto` (back to the BMC's automatic mode), `power` (shutdown, reboot or sleep after 10 s to 24 h,
or cancel) and `apply_update` (starts the signature-checking updater service, nothing else). No request takes a
path, a command or free text; anything else is refused, as are requests over 512 bytes, unknown fields and
values out of range. Each request is checked against what `config.yaml` switches on (with Core Temp off,
`coretemp_read` is refused too). Reads are limited to 300 a minute, changes to 30 a minute. Every change and
every refused request is written to `helper.log` with who asked.

**Who may talk to it.** The pipe's access list lets in only the agent's account, SYSTEM and Administrators,
refuses network logons, and the pipe refuses remote clients. On top of that the helper looks at every
client's identity and drops anyone else. The agent in turn checks that the pipe really belongs to the helper
service's process (so nothing can pretend to be the helper while it is stopped), and lets the helper only
identify it, not act as it.

**The fan watchdog lives in the helper**: while a fixed fan speed is set it checks the CPU temperature every
10 seconds (the BMC's sensors, and Core Temp's when that is on) and puts both zones to 100 % at 80 °C or after
30 seconds without any temperature. It keeps working if the agent stops or crashes. When the helper itself
stops (Stop-Service, the panel's Stop, an update, Windows shutting down) it first hands the fans back to the
BMC's automatic mode (`auto_mode`, or "standard" when the board refuses that), so fans never keep a fixed speed
without a watchdog. A mode you chose yourself (standard, optimal, heavy IO) is left as it is.

**Readings run by themselves**, without any prompt. Changes (fans, power) still need the panel's control
token and confirmation exactly as before; the agent only passes them on.

**Stopping the helper** (`Stop-Service fairy-agent-helper`, or the panel's Stop once the panel shows it): the
fans go back to the BMC's automatic mode, and Core Temp, BMC sensors, fan control and shutdown / sleep are
simply missing. The agent does not count that as an error: `/metrics` says `"helper": {"state": "stopped"}` and
lists them under `"unavailable"` with reason `helper_stopped`; `/fan/status` says `"available": false,
"reason": "helper_stopped"`; changes answer 503 `helper_stopped`. Everything else keeps working.
`Start-Service fairy-agent-helper` (or the panel's Start) brings them back within a few seconds. The helper
starts with Windows again after a reboot.

**What the panel sees** (for the panel's "Elevated helper" badge):

* `GET /metrics` has `"helper": {"state": "running" | "stopped" | "starting" | "not_installed" | "error",
  "needed": true/false, "version": "<the helper's build, like agent_version>", "since": "<RFC 3339>", "watchdog": true/false, "features":
  ["coretemp", "ipmi", "fans", "power", "update"], "error": "..."}` (fields that do not apply are left out;
  Linux agents have no `helper` block), and `"unavailable": [{"source": "ipmi", "reason": "helper_stopped"},
  ...]` while the helper is not running. `power_control` then also says `"available": false, "reason":
  "helper_stopped"`.
* `POST /helper/stop` and `POST /helper/start` (control token, body `{}`, rate limited and logged like the
  other control actions): 200 with the helper block afterwards, 409 `{"error": "not_installed"}` without a
  helper. Stop hands the fans to the BMC first. The agent's account may query, start and stop the helper
  service and nothing else (it cannot change or delete it).

**Fewer process details.** As a virtual account the agent opens other programs with the weakest access
there is (as always), and Windows refuses that for programs of other accounts and for elevated ones: those
(your games, your browser, services) are listed **by name only**, without CPU, memory, path or user, the same
as with LocalService before. For many people that is a feature. The helper is never used for the process list.

**Performance counters (0.5.2).** The agent reads GPU load, VRAM in use, per-process GPU memory and the ACPI
thermal zones from Windows' performance counters (PDH, as Task Manager does). PDH first reads the counters'
names from the Perflib registry key, which only Administrators, SYSTEM, INTERACTIVE, Performance Monitor Users
and Performance Log Users may read, so as a plain virtual account every counter failed with PDH status
`0xC0000BC8` (PDH_CANNOT_READ_NAME_STRINGS): Util and VRAM in use stayed "–" on 0.5.0 / 0.5.1. Since 0.5.2
`NT SERVICE\fairy-agent` is a member of the built-in group **Performance Monitor Users** (`S-1-5-32-558`,
found by its SID, so a localized Windows works too). That group grants read access to performance counter data
and nothing else: no administrator rights, no right to change any setting, service or file, no access to other
programs. `install`, `setup-self-update` (and so `install-fairy-agent.ps1`), the move off LocalSystem (step
`counters`) and the fairy-agent-update service (before it starts an updated agent) add it; `uninstall` removes
it. A group counts from the service's next start (a new token): `setup-self-update` restarts a running agent
when it had to add the group. An agent that runs as `NT SERVICE\fairy-agent` without the group in its token
(moved by 0.5.1, then updated to 0.5.2 by 0.5.1's updater, which does not know the group) starts the
fairy-agent-update service once, a minute or more after it starts and only while that service is stopped; with
nothing staged that service only adds the group and, if it really added it, restarts the agent (so this cannot
repeat). Check: `net localgroup "Performance Monitor Users"` (English Windows) lists `NT SERVICE\fairy-agent`.
If the counters still cannot be read, agent.log says so once: `performance counters not readable by this
account (PDH status 0xC0000BC8 ...)`, with the fix.

**Moving an existing install** (0.4.x ran as LocalService, or LocalSystem for Core Temp / fans): run
`install-fairy-agent.ps1` again, or, in an Administrator PowerShell,
`& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update`. Both are safe to run again. They switch the
service to `NT SERVICE\fairy-agent` (like `sc.exe config fairy-agent obj= "NT SERVICE\fairy-agent"`), give it
only `SeChangeNotifyPrivilege`, add it to Performance Monitor Users (above), set the folder permissions again (config and tokens readable by the agent's
account, the helper's folder writable only by administrators and SYSTEM), install the helper when `config.yaml`
uses Core Temp, IPMI or power control (`--helper` installs it anyway), and restart what was running. Config and
tokens stay, so the panel notices nothing but a restart. The folder permissions name the same account as
before (`NT SERVICE\fairy-agent` was already the service's own SID), so nothing has to be re-granted. Updating
to 0.5.0 through the panel did not move the account by itself; since 0.5.1 an agent that runs as
**LocalSystem** moves itself (next section). One that runs as **LocalService** cannot (that account may not
change services): it keeps working as before (with LocalService's rights), its log says so once at start, and
`/metrics` says `"migration": {"state": "needs_admin", "command": ...}` until an administrator runs one of the
two above.

#### Moving to the new account by itself (0.5.1, LocalSystem only)

When the agent starts as a service running as LocalSystem (installed by 0.4.x for Core Temp or fans, then
updated through the panel: on 0.4.2 by the old in-service updater, on build 10 by the fairy-agent-update
service), it does what `setup-self-update` does, by itself, once. Nothing to press besides **Update**.

It only does so as the signed release (built with the release key), installed as
`C:\Program Files\Fairy\fairy-agent.exe` (the service must start exactly that program), after checking that
only administrators can change it (the same check as for the updater). Otherwise `/metrics` says
`needs_admin` with the reason. It never takes a path or a command from `config.yaml` or the network; it adds
nothing that listens.

**When.** Two minutes after the agent listens, and only once the installer that just put it in place has
reported (it checks the new version for up to 90 s and must not see it restart), the updater service is not
running, no update is being downloaded and no shutdown / reboot / sleep is scheduled. The panel's Update
answers "unavailable" for the few minutes it takes.

**The steps** (each one is safe to run again; agent.log has a line before and after each, `migration: step ...`):

1. `program_folder`: the program folder administrators-only again (0.4.2 let the service write it);
2. `folders`: `C:\ProgramData\fairy-agent` (config and tokens readable by the new account, `logs\` writable);
3. `updater`: the fairy-agent-update service, `update\` and `state\`, as `setup-self-update`;
4. `fans`: when this agent controls the fans itself, back to the BMC's automatic mode (only from a fixed duty);
5. `helper`: the fairy-agent-helper service when `config.yaml` uses Core Temp, IPMI through Windows or power
   control (or one is installed already); it starts at once and its fan watchdog takes over;
6. `firewall`: the helper's two block rules (in and out, its service SID; `netsh advfirewall`, the same rules
   `install-fairy-agent.ps1` and `setup-self-update` make);
7. `counters` (0.5.2): `NT SERVICE\fairy-agent` into Performance Monitor Users (above); a failure here is
   logged and does not stop the move (only the counters would be missing);
8. `switch`: the service to `NT SERVICE\fairy-agent`, SID type unrestricted, only `SeChangeNotifyPrivilege`
   (effective at its next start), and the updater service to start with Windows until the switch is checked;
9. `restart`: the agent starts the **fairy-agent-update** service (LocalSystem, the installed program). Seeing
   the migration state, it installs nothing: it stops the agent, starts it (now as `NT SERVICE\fairy-agent`),
   and checks within two minutes that the service runs, that its process runs as `NT SERVICE\fairy-agent`,
   that the same process keeps running for 20 s, and that `/metrics` answers twice with this version. Then
   it writes `done` and sets itself back to manual start. Its log is
   `C:\ProgramData\fairy-agent\update\installer.log`.

The state is in `C:\ProgramData\fairy-agent\migration\state.json` (administrators and SYSTEM may write,
the agent's account only read; refused if anyone else could have written the folder).

**If something fails** the agent keeps running as before: before the switch it just stops; at or after the
switch the service is put back on LocalSystem with its old SID type and privileges (and, if the restart was
the problem, started again as LocalSystem). The other steps stay (they are the 0.5 setup and work with
LocalSystem too). `/metrics` says `failed` with the step, the error, `rolled_back` and `next_try`; the agent
tries again after 1 hour, then 6 hours, then once a day (restarting it does not try sooner), and
`setup-self-update` as Administrator does it at once. **Interrupted** (crash, reboot, Stop-Service): the next
start resumes at the step that was running; an attempt interrupted three times counts as failed. A reboot
after the switch: the updater service starts with Windows and finishes the check (the new agent starts it
too after three minutes, if needed). The SID type and privileges a rollback restores are read before the
switch; the account it restores is always LocalSystem, whatever the file says.

**What the panel sees**: `GET /metrics` has `"migration": {"state": "done" | "pending" | "failed" |
"not_needed" | "needs_admin", "account": "NT SERVICE\\fairy-agent" | "LocalSystem" | "LocalService" | ..., "step",
"error", "rolled_back", "attempts", "next_try", "since", "reason", "command"}` (Windows only; fields that do not
apply are left out). `pending` with step `waiting` before the first attempt (`next_try` says when, `reason`
what it waits for), then the current step; `command` is what an administrator runs instead.

**Commands** (Administrator PowerShell, `& "C:\Program Files\Fairy\fairy-agent.exe" ...`):
`helper-status` (both services' accounts, is the helper running, what it serves), `setup-self-update
[--helper]` (as above; also adds the helper's firewall rules), `remove-helper` (stop it, fans back to the BMC,
remove it and its firewall rules), `uninstall` (both services and the updater; takes `NT SERVICE\fairy-agent`
out of Performance Monitor Users).

**Troubleshooting**

* `sc.exe qc fairy-agent` should show `SERVICE_START_NAME : NT SERVICE\fairy-agent`, `sc.exe qc
  fairy-agent-helper` `LocalSystem`. `sc.exe qprivs fairy-agent` lists `SeChangeNotifyPrivilege` only.
* The agent's log says "fairy-agent-helper: error" or the panel shows the helper as "error": look at
  `C:\ProgramData\fairy-agent\helper\helper.log` and the Event Viewer (Windows Logs > Application, source
  fairy-agent-helper). `helper-status` asks the helper directly.
* The helper does not start: it refuses to run from a folder others can change (keep the program in
  `C:\Program Files\Fairy`) and needs the agent's service (it looks up its account). "not writing the helper
  log": the `helper` folder is not administrators-only; `setup-self-update` fixes it.
* Shutdown answers "helper stopped": start the helper. Shutdown answers that a privilege is missing: the
  helper is not installed (power control was switched on later); run `setup-self-update`.
* GPU Util / VRAM in use "–" and agent.log says `performance counters not readable by this account`: the
  account is not in Performance Monitor Users, or the agent was not restarted since. Run `setup-self-update`
  (it adds the group and restarts the agent), or by hand `net localgroup "Performance Monitor Users"
  "NT SERVICE\fairy-agent" /add` and `Restart-Service fairy-agent`.
* Something worked as LocalService / LocalSystem and not now: `sc.exe qprivs fairy-agent` and the agent's log;
  report it. Going back to build 10 is in TEST-ON-WINDOWS.md ("Rollback").

## Install on Linux

You need: Linux with systemd (Debian, Ubuntu, Proxmox VE, Fedora...), amd64 or arm64 (e.g. Raspberry Pi 4/5),
Tailscale signed in. The usual way is [Add host](#add-a-host-from-the-panel-one-command); this section is for
doing it by hand. Take the program, the two `.service` files, the polkit rules and the tmpfiles rule from
**one** release, downloaded and checked as in
[SETUP-UPDATES.md, 2.3](SETUP-UPDATES.md#23-by-hand-from-one-named-release-checked) (in a release they have no
`deploy/` in front). `fairy-agent.config.example.yaml` and `fairy-agent.udev.rules` are not part of a release:
they come from the `deploy/` folder of this repository. As root:

```sh
# 1. a user for the agent, the program, the settings folder
useradd --system --no-create-home --shell /usr/sbin/nologin fairy-agent
install -m 0755 fairy-agent-linux-amd64 /usr/local/bin/fairy-agent      # or fairy-agent-linux-arm64
install -d -m 0750 -o root -g fairy-agent /etc/fairy-agent
install -m 0640 -o root -g fairy-agent deploy/fairy-agent.config.example.yaml /etc/fairy-agent/config.yaml

# 2. the tokens (the panel needs the same ones, see below)
fairy-agent gen-token > /etc/fairy-agent/token
fairy-agent gen-token > /etc/fairy-agent/control-token   # only used if you enable fan / power / Wake-on-LAN
chown root:fairy-agent /etc/fairy-agent/token /etc/fairy-agent/control-token
chmod 0640 /etc/fairy-agent/token /etc/fairy-agent/control-token

# 3. the service
install -m 0644 deploy/fairy-agent.service /etc/systemd/system/fairy-agent.service
sudo -u fairy-agent fairy-agent check-config
systemctl daemon-reload && systemctl enable --now fairy-agent
systemctl status fairy-agent       # should say "fairy-agent listening" with your 100.x.y.z:9101
```

The service runs as the `fairy-agent` user with **no special rights** (no root, no capabilities) and is locked
down by systemd (read-only system, no new privileges, its own /tmp, only NVIDIA and IPMI devices visible).
Four optional extras need a small permission each, and only if you want them:

| You want | Install | Why |
| --- | --- | --- |
| CPU watts (Intel/AMD "RAPL") | `deploy/fairy-agent.tmpfiles.conf` as `/etc/tmpfiles.d/fairy-agent.conf`, then `systemd-tmpfiles --create /etc/tmpfiles.d/fairy-agent.conf` | the energy counters are root-only since 2020 (a side-channel fix); this lets the agent's group read them |
| Shutdown / reboot / sleep from the panel | `deploy/fairy-agent-power.polkit.rules` as `/etc/polkit-1/rules.d/49-fairy-agent-power.rules` | lets exactly this user power off / reboot / suspend through systemd, and nothing else |
| Self-update from the panel's Update button | `deploy/fairy-agent-update.polkit.rules` as `/etc/polkit-1/rules.d/49-fairy-agent-update.rules` (see [Updates](#updates-the-panels-update-button)) | lets exactly this user start the installer unit `fairy-agent-update.service`, and nothing else |
| BMC sensors / fan control in-band | `apt install ipmitool`, `deploy/fairy-agent.udev.rules` as `/etc/udev/rules.d/60-fairy-agent-ipmi.rules`, `modprobe ipmi_devintf ipmi_si`, `udevadm trigger` | lets the agent's group use /dev/ipmi0 |

**One polkit rule per feature.** Until 0.5.3 there was one combined rule file,
`/etc/polkit-1/rules.d/49-fairy-agent.rules`. It granted both rights (power and starting the installer) as soon
as one of the two features was chosen. Since 0.6.0 each feature has its own file, and the install script
installs a rule only for a feature that is on in `config.yaml`. It removes the rule of a feature that is off,
and it removes the old combined file. A machine installed before 0.6.0 keeps the combined file until the
install script runs there again: use **Re-pair** on the host's page in the panel and run the command it shows.
Check afterwards (read-only):

```sh
ls /etc/polkit-1/rules.d | grep fairy
```

Expected: only `49-fairy-agent-power.rules` and / or `49-fairy-agent-update.rules`, matching what is switched
on. No output means neither feature is on.

Temperatures, fans and voltages of the board come from `/sys/class/hwmon` and need nothing extra. So do AMD
graphics (built-in Radeon or a Radeon card): the agent reads the files the `amdgpu` kernel driver publishes under
`/sys/class/drm/card*/device/` (busy %, VRAM, and from the card's hwmon the temperature and watts). Nothing to
install; `gpu: amdgpu: off` switches it off. On a built-in Radeon "VRAM" is the small part of RAM the firmware
sets aside for graphics; what the GPU borrows on top is already in the memory figure. A second (discrete) GPU
that Linux has put to sleep is shown as idle and not woken up just to read it.

On Windows, AMD, Intel and other graphics (cards and built-in) come from what Windows itself reports, the
same numbers as Task Manager: the adapter's name and dedicated VRAM from DXGI, and its busy % and VRAM in use
from the "GPU Engine" and "GPU Adapter Memory" performance counters. Busy % is Task Manager's: the busiest
engine (3D, compute, video, copy...). The panel shows these cards "via Windows". NVIDIA cards stay with
nvidia-smi (they are not listed twice) and the Microsoft Basic Render Driver is left out. A card is listed once
even when DXGI reports it several times (some Windows 10 LTSC machines list one Radeon three times, with
leftover adapter ids): entries with the same PCI ids at the same PCI location (read from the adapter id through
D3DKMT) are one card, and the entry the GPU counters know is kept; two identical cards in two slots stay two.
A DXGI entry without a "GPU Adapter Memory" counter is left out when another entry of the same card model
(vendor, device and VRAM) has one: such leftovers still get "GPU Engine" counters from every program that draws
(e.g. dwm.exe), which made one Radeon or one Intel UHD show up twice. Two identical real cards both have memory
counters and both stay. Since 0.5.1, entries that Windows' kernel (D3DKMT) puts at the **same PCI bus /
device / function** with the same vendor and device id are one card whatever else DXGI says about them (a
laptop's Intel UHD had two LUIDs, both with memory and engine counters, with different subsystem ids: shown
twice). Such a card is shown once, named after its busiest entry, and the counters of all its entries are
added: busy % per engine summed over them (work sent through either reaches the same engine), then the
busiest engine; VRAM in use summed (each entry's allocations are its own). When D3DKMT gives no location the
rule above applies as before. Since 0.5.2 an entry whose location D3DKMT cannot give (it fails, or answers
`ffffffff:ffff.ffff`, logged as `pci=unknown`) is left out when another entry with the same PCI ids (vendor,
device, subsystem, revision) has a location: the leftover of a card after a driver reset (a laptop's Intel UHD
showed up twice; a Radeon three times). This needs no counter, so it works even when the counters cannot be
read; such an entry stays only if Windows still drives it (a "GPU Adapter Memory" counter). Software adapters
(Microsoft Basic Render Driver) are never listed. The counters are set up again once a minute when Windows did not offer them at
start (busy % and VRAM in use showed "–"), and the start-up log lists every DXGI entry with its LUID, PCI ids
and location. Nothing to install; `gpu: windows: off` switches it off.

Radeon temperature and watts on Windows come from AMD's own library, ADL (`atiadlxx.dll` in System32, installed
with the Adrenalin driver), read only: per card the temperature calls its Overdrive version suggests, the first
that answers is remembered: the PMLog sensors on Navi and newer (edge temperature, board or ASIC power: e.g.
RX 5600 XT), then OverdriveN / Overdrive 6; OverdriveN / Overdrive 6 / 5 calls on older cards; all of them
when `ADL2_Overdrive_Caps` does not answer. Only "Get" functions are called (no overclocking or fan settings
are touched), no driver of our own is loaded and nothing is read from other processes. ADL is opened for all
adapters, not only those driving a display: the agent runs as a service in session 0, where ADL reports the
Radeon `present=false` (it is still used when `exist=true`). ADL writes AMD's vendor id as decimal 1002
(0.5.2 logged it as `vendor=03ea` and skipped the card; fixed in 0.5.3). ADL lists one entry per display output
or logical adapter; they are grouped by PCI location, and the card is matched to the DXGI GPU by that location
(from D3DKMT; a GPU whose location Windows does not give gets the one ADL card left over, if it is the only
such GPU). The panel then shows it "via AMD". Without the DLL, or when no call answers, the card keeps load and
VRAM only. agent.log has one line at start, `AMD GPU sensors (ADL)`, with what ADL answered: the DLL and
`ADL2_Main_Control_Create`'s return code (or why no DLL could be used), the number of ADL adapters (or the
error code), per adapter its index, PCI location, vendor, present / exist, the Overdrive answer (version or ADL
error code) and which temperature call answered with what (`temp=PMLog 52.0C`, or `temp=none (...)` with each
call's error), "same card" for further entries of a card, the number of cards read and `temp_api` per card.
`gpu: amd_adl: off` switches it off. Untested on real AMD hardware so far.

If the firewall on the machine is on (nftables/ufw), allow TCP 9101 only on `tailscale0`, e.g.
`ufw allow in on tailscale0 to any port 9101 proto tcp`.

### Check your Linux agents: are the sandbox lines still on?

Do this once on every Linux agent. The check changes nothing.

**Why.** `fairy-agent.service` locks the agent down (the lines from `NoNewPrivileges=` to `DevicePolicy=`).
A note at the end of that file says that in an unprivileged LXC container without nesting some of these lines
can stop the service from starting, and that they can then be commented out. Without them a fault in the
agent reaches further. One known case: up to 0.5.3 the join step of Add host and Re-pair handed the pairing
file to the agent's account in a way that a program already running under that account could misuse: it
could become the owner of a file that belongs to root. With the sandbox lines on it could then read that file.
With them commented out it could also change it, which can lead to root. 0.6.0 closes this in
`fairy-agent join` itself. That takes effect once the panel's command installs 0.6.0 or later (an older
install command first puts its own older agent back).

1. As root on the agent:

   ```sh
   grep -nE '^[[:space:]]*#[[:space:]]*(NoNewPrivileges|CapabilityBoundingSet|AmbientCapabilities|Protect[A-Za-z]*|Private[A-Za-z]*|Restrict[A-Za-z]*|LockPersonality|MemoryDenyWriteExecute|SystemCall[A-Za-z]*|DevicePolicy)=' /etc/systemd/system/fairy-agent.service || echo "no sandbox line is commented out"
   ls /etc/systemd/system/fairy-agent.service.d 2>/dev/null
   ```

2. Read the result:
   * `no sandbox line is commented out` and nothing from `ls`: this agent is fine. Done.
   * Lines such as `54:#PrivateTmp=yes`: those sandbox lines are off on this machine. Go on with step 3.
   * `ls` lists files: someone added settings on top of the service file. Read them
     (`systemctl cat fairy-agent`) and remove what switches a sandbox line off.
3. Run the install script again: in the panel, open the host's page, press **Re-pair** and run the command it
   shows on the machine. The script puts the release's `fairy-agent.service` in place and keeps yours as
   `/etc/systemd/system/fairy-agent.service.bak`. (If the script says the installed agent `is NEWER than this
   installer's release`, it leaves the service file alone: update the panel first, or replace the file by hand
   as in [SETUP-UPDATES.md, 2.3](SETUP-UPDATES.md#23-by-hand-from-one-named-release-checked).)
4. Run the two commands of step 1 again, then `systemctl status fairy-agent --no-pager`.
5. If the agent no longer starts and the status shows `status=226/NAMESPACE`: this container cannot provide
   what some of the lines need. Comment out only the lines the note at the end of the service file names
   (`PrivateTmp`, the `Protect...` lines, `RestrictNamespaces`), leave every other line on, then
   `systemctl daemon-reload && systemctl restart fairy-agent`. Keep that agent on 0.6.0 or later.

## Point the panel at it

On the panel, two files change: `/etc/fairy/fairy.env` (the secrets) and `/etc/fairy/config.yaml`.

1. Copy the agent's token. Windows (PowerShell as Administrator): `Get-Content C:\ProgramData\fairy-agent\token`.
   Linux: `cat /etc/fairy-agent/token`.
2. On the panel, add it to `/etc/fairy/fairy.env` under a name of your choice, one per machine:

   ```sh
   AGENT_TOKEN_AGENT_1=paste-the-token-here
   # only if you enable fan control, shutdown/reboot or Wake-on-LAN on that machine:
   AGENT_CONTROL_TOKEN_AGENT_1=paste-the-control-token-here
   ```
3. Add the machine to `agents:` in `/etc/fairy/config.yaml` (the address is the machine's Tailscale address):

   ```yaml
   agents:
     - id: agent-1
       name: AGENT-1
       url: http://100.64.0.10:9101
       token_env: AGENT_TOKEN_AGENT_1
       group: Home
       site: Home
       # optional, each must also be switched on in the agent's config.yaml:
       # fan_control: {vendor: supermicro, control_token_env: AGENT_CONTROL_TOKEN_AGENT_1}
       # power_control: true
       # control_token_env: AGENT_CONTROL_TOKEN_AGENT_1   # (needed for power_control / wol_relay)
   ```
   For an agent on a Proxmox node, add `node: <node name>` so its details are shown on that node.
4. Restart the panel: `systemctl restart fairy`. The machine appears within a second or two.

The connection is plain HTTP inside Tailscale (which already encrypts everything between your machines). The
token travels in the `Authorization: Bearer` header.

## Optional features

Everything below is **off** until you switch it on in the agent's `config.yaml` **and** in the panel's
`agents:` entry. Each one uses the separate control token, is limited to 12 requests a minute, and is written
to the agent's log. Restart the agent after changing `config.yaml`. (Self-update has its own section:
[Updates](#updates-the-panels-update-button).)

### Fan control (Supermicro)

For Supermicro boards with a BMC (X9 to X12, e.g. the X11SCA-F): choose the BMC's fan mode (standard, full,
optimal, heavy IO) and, in "full" mode, a fixed speed per fan zone.

```yaml
ipmi:
  enabled: true
fan_control:
  enabled: true
  min_duty: 30          # never below 30 %
  max_temp_c: 80        # watchdog
  auto_mode: optimal    # the BMC's automatic mode on this board: optimal, standard or heavyio
```

Not every board has every mode. Some (e.g. the Enginetech EG320W-G20, a Supermicro OEM board) refuse "optimal"
with BMC completion code 0xCC. The agent remembers a mode its BMC refused, reports it in `/fan/status`
(`unsupported_modes`) and the panel greys that button out. If the refused mode is `auto_mode`, the log says so:
set `auto_mode` to a mode the board has, e.g.
`fairy-agent config set fan_control.auto_mode standard` (see [Settings](#settings-configyaml)), and restart.

Safety: the agent refuses any speed below 30 % (the panel does too). While you have set a fixed speed, it checks
the CPU temperature every 10 seconds; at 80 °C, or if it cannot read any temperature for 30 seconds, it sets
both zones back to 100 % and writes that in the fan log the panel shows.

On Windows this uses Windows' own IPMI support through one `powershell.exe` that the helper service starts
when needed (and stops after 5 idle minutes): Windows lets only administrators use it, so it runs in
[fairy-agent-helper](#two-services-the-agent-and-its-helper), together with the watchdog
(`install-fairy-agent.ps1 -Helper`). The first reading of the BMC's sensor list can take a minute. On Linux it uses `ipmitool` (see the table above).
`ipmi.enabled` alone (without `fan_control`) adds the BMC's temperatures, fan speeds and voltages to the panel.

### Shutdown, reboot and sleep

```yaml
power_control:
  enabled: true
```

Panel: `power_control: true` and `control_token_env:` in the agent's entry. On Windows the helper does the
actual shutdown, reboot or sleep (the agent's own account may not), so power control installs the helper. The panel asks you to type the
machine's name and sends a delay (default 60 s). On Windows, Windows itself shows its usual "you're about to be
signed out" warning and counts down (like `shutdown /s /t 60`; open programs are closed at the end); Cancel in
the panel aborts it. On Linux the agent waits and then runs `systemctl poweroff` / `reboot` (needs the polkit
rule above); if the agent is restarted in the meantime, the pending action is dropped.

**Sleep** (suspend to RAM, not hibernate) works the same way (delay, Cancel, one pending action at a time), but
the agent itself waits on Windows too and then calls `SetSuspendState` (powrprof.dll). The agent reports in
`/metrics` (`power_control.sleep`, and `sleep_note` with the reason when not) whether the machine can sleep, and
refuses with 409 `sleep_unavailable` otherwise: on Windows it needs S1-S3 in `GetPwrCapabilities` (a laptop with
only Modern Standby cannot be put to sleep by a service; `powercfg /a` shows what is available), on Linux
systemd-logind's `CanSuspend` must say `yes` (the power rule above covers `suspend`). Waking it is Wake-on-LAN (the panel's "Power on"), which from sleep needs the network
card's "Allow this device to wake the computer" / "Wake on Magic Packet" (Windows Device Manager) or
`ethtool -s <nic> wol g` (Linux).

### Wake-on-LAN

```yaml
wol:
  enabled: true
  allowed_macs: ["00:00:5e:00:53:01"]   # optional: only these machines
```

Panel: `wol_relay: true` and `control_token_env:` in this agent's entry, and `wol: {mac: ..., relay: <this
agent's id>}` under `systems:` for the machine to wake. The agent only sends to the LAN broadcast address or a
private (192.168.x.x / 10.x / 172.16-31.x) address, on port 7 or 9.

### BMC power-on relay

For a machine Wake-on-LAN cannot wake (e.g. a BMC sharing the LAN port, so the NIC is not listening for magic
packets), an always-on agent that can reach the BMC powers it on through the BMC: `POST /bmc/power
{"target": "<id>", "action": "on" | "status"}` with the control token (rate limited and logged like the other
control actions; `/metrics` lists the target ids and backends only, never addresses or accounts). Only private
BMC addresses are accepted. Two backends per target:

* `ipmitool` (default when `host:` is set): `ipmitool -I lanplus -H <host> -U <username> -E [-C <cipher_suite>]
  chassis power on` (and `chassis power status`), 15 s. The password travels only in the child process's
  `IPMI_PASSWORD` (that is what `-E` reads; never on the command line), and the child gets a minimal
  environment without the agent's tokens. ipmitool is taken from `C:\Program Files\ipmitool\` on Windows
  (never from PATH or another folder) and from `/usr/bin`, `/usr/sbin`, `/usr/local/bin` or PATH on Linux,
  unless `ipmitool_path` gives its full path. Either way the file and every folder above it must be changeable
  only by administrators / SYSTEM (Windows) or root (Linux), because the agent may run as LocalSystem: a
  program in `C:\ipmitool\` or a user's folder is refused (`ipmitool_untrusted`). `cipher_suite` (0-17) is ipmitool's `-C` for BMCs that need a
  particular one.
* `redfish` (default when `url:` is set): `GET /redfish/v1/Systems`, then `POST <first
  member>/Actions/ComputerSystem.Reset {"ResetType": "On"}`, basic auth, 10 s. The BMC's self-signed
  certificate is pinned by SHA-256: `tls_fingerprint` if given, else learned on the first successful call
  ("trust on first use", logged with the fingerprint) and kept in the agent's state folder (`bmc-pins.json`).

When ipmitool fails, the panel shows what went wrong (the `code` in the answer): `bmc_refused` (wrong user name
or password), `bmc_privilege` (the login worked but the BMC refused the ADMINISTRATOR privilege ipmitool asks
for, "invalid role": give the BMC user the Administrator role), `bmc_cipher` (the BMC does not offer that
`cipher_suite`), `bmc_busy` (no free session on the BMC), `bmc_session` (the session broke off) and
`bmc_unreachable` (no answer: is the relay cabled to it?). ipmitool's "IANA PEN registry open failed" warning is
left out of the message; it says nothing about the BMC.

```yaml
bmc_relay:
  enabled: true
  targets:
    - {id: server-bmc, backend: ipmitool, host: 192.168.1.5, username: fairy, password_env: BMC_SERVER_PASSWORD}
env_file: C:\ProgramData\fairy-agent\secrets.env    # BMC_SERVER_PASSWORD=... (written by `fairy-agent secret set`)
```

The password is never typed on a command line: `fairy-agent secret set NAME` asks for it (no echo) or reads one
line from stdin, writes it into `env_file` (setting `env_file` to `secrets.env` next to config.yaml if it was
not set) with tight permissions (Windows: SYSTEM and Administrators full control, the agent's service account
read-only, nobody else; Linux: 0640 root:fairy-agent). IPMI over LAN without ipmitool is not built in (future).

An example. `agent-2` is an always-on Windows PC, cabled to the BMC port of the server `agent-1` (the BMC has
the address 192.168.1.5, ipmitool is installed on `agent-2`). All names and the address are example values. On
`agent-2`, in an Administrator PowerShell:

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" bmc-relay add --id server-bmc --backend ipmitool --host 192.168.1.5 --username <BMC user> --password-env BMC_SERVER_PASSWORD
& "C:\Program Files\Fairy\fairy-agent.exe" secret set BMC_SERVER_PASSWORD
Restart-Service fairy-agent
```

(add `--cipher-suite <n>` to the first line if the BMC needs a particular cipher suite, and
`--ipmitool-path "C:\Program Files\<folder>\ipmitool.exe"` if it is not in `C:\Program Files\ipmitool\`).
Panel (`config.yaml`), on the machine to wake: `systems: [{id: agent-1, bmc_power: {relay: agent-2,
target: server-bmc}}]`; the relay agent's entry needs `control_token_env:`. The panel then offers "Power on (via
BMC, through AGENT-2)" while `agent-1` is offline and `agent-2` is online.

### Plugs and UPSes on this machine's network

When the panel cannot reach a smart plug or UPS itself (for example at a friend's place), the agent there can
read it and pass the readings on. The entries are the same as in the panel's `power_sources:` and `ups:`
(Shelly, Tasmota, Tuya, Redfish, NUT); passwords go into a separate file named by `env_file:` as
`NAME=value` lines and stay on that machine. `system_hint: self` links a plug to the agent's own machine, but
only for an agent that is a host of its own: for an agent merged into a Proxmox node (`node:` in the panel) it
does not work, because the panel shows that machine under the node's id. There, and whenever the panel should
decide, use `power_links:` in the panel's agent entry (`power_links: {<device id>: <system id>}`, e.g.
`{office-ups: node-office}`), plus `ups_powers:` / `ups_names:` for UPSes, as for any agent.

## Updates (the panel's Update button)

Nothing ever updates by itself. When an admin presses **Update** on the panel's Updates page (after confirming
with a fresh Pocket ID sign-in; it is written to the panel's audit log), the panel asks this agent to update
itself, and the agent:

1. asks GitHub for the latest release of Fairy-agent (made automatically for every change, see
   [SETUP-UPDATES.md](SETUP-UPDATES.md)) and checks its **signature** with the key built into this program.
   Releases are signed with the owner's private key; anything else is refused. An older release than the one
   running is refused too;
2. downloads only the file for its own system (e.g. `fairy-agent-linux-arm64`) and checks its fingerprint
   (SHA-256) against the signed list;
3. hands it to a small installer that checks everything **again**, keeps the old program as
   `fairy-agent.old` (Windows: `fairy-agent.exe.old`), puts the new one in place and restarts the service;
4. waits until the agent answers with the new version (about half a minute at most). If it does not, the
   installer puts the old program back and starts that again.

The panel shows each step (downloading, applying, the result) on the Updates page and next to the version on
the host's page. Programs you build yourself (without the release key) never update themselves and say so.

**On the machine itself** (like `tailscale update`), as root on Linux or in an Administrator PowerShell on
Windows; this works even without `self_update` switched on:

```sh
fairy-agent update --check   # installed vs latest release
fairy-agent update           # asks, then downloads, verifies, swaps (keeps .old), restarts, rolls back if needed
fairy-agent update --yes     # without the question
```

**Switch it on** in `config.yaml` (and `self_update: true` in the panel's agent entry, which needs the control
token like power control):

```yaml
self_update:
  enabled: true
```

* **Linux** also needs, once (all three files are in `deploy/`): the current `fairy-agent.service` (it gives
  the agent one folder it may write, `/var/lib/fairy-agent`, for the download), `fairy-agent-update.service`
  (the installer; it runs as root only when the agent starts it, and may only change `/usr/local/bin`), and the
  polkit rule `fairy-agent-update.polkit.rules` as `/etc/polkit-1/rules.d/49-fairy-agent-update.rules` (lets
  the agent's user start exactly that one unit; Debian/Proxmox: `apt install polkitd` if
  `/etc/polkit-1/rules.d` does not exist). Then `systemctl daemon-reload && systemctl restart fairy-agent`. On Fedora with SELinux the installer
  runs `restorecon` on the new program. The installer's messages: `journalctl -u fairy-agent-update`.
* **Windows**: run `install-fairy-agent.ps1` (again) as Administrator, or just
  `& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update` in an Administrator PowerShell. It installs
  a second service, **fairy-agent-update** (LocalSystem, started only on demand), which runs the *installed*
  `C:\Program Files\Fairy\fairy-agent.exe apply-update`: it checks the downloaded release again with its own
  built-in key, puts it into `C:\Program Files\Fairy`, restarts the agent and rolls back if needed, then stops.
  The agent's own account (`NT SERVICE\fairy-agent`) may only *start* that service and write the download
  folder `C:\ProgramData\fairy-agent\update\stage`; it can change nothing in `C:\Program Files\Fairy`, so
  even a compromised agent cannot plant a program that an administrator or SYSTEM later runs. The installer
  logs to `C:\ProgramData\fairy-agent\update\installer.log`. No driver, no other programs touched. When
  fairy-agent-helper runs, the installer stops it too (it runs the same program; the fans go back to the
  BMC's automatic mode meanwhile) and starts it again with the new version.
  Without the updater service the panel shows self-update as unavailable, with this command as the fix.
* **Coming from 0.4.2 or older on Windows**: those versions gave the agent's account write access to
  `C:\Program Files\Fairy` (so it could replace itself). After updating to 0.4.3, through the panel or by hand,
  run once in an Administrator PowerShell:
  `& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update`. It removes that access and sets up the
  updater service; until then the panel's Update button says so. (An agent running as LocalSystem removes the
  access by itself when it starts, and since 0.5.1 does all of `setup-self-update` by itself, see
  [Moving to the new account by itself](#moving-to-the-new-account-by-itself-051-localsystem-only);
  re-running `install.ps1` from the panel's Re-pair does all of it too.)
  Updates never go to an older release through the panel any more, not even with force: by hand only, with
  `fairy-agent update --force` as root / Administrator.

The very first program with self-update has to be installed by hand once per machine;
[SETUP-UPDATES.md](SETUP-UPDATES.md) has the exact commands. `self_update.repo` can point at a fork (its
releases must still carry the owner's signature).

**Undo by hand**: Linux `mv /usr/local/bin/fairy-agent.old /usr/local/bin/fairy-agent && systemctl restart
fairy-agent`; Windows `Stop-Service fairy-agent`, rename `fairy-agent.exe.old` back to `fairy-agent.exe`,
`Start-Service fairy-agent`.

## What it can and cannot show

| | Linux | Windows |
| --- | --- | --- |
| CPU %, memory, disks, network, uptime | yes | yes |
| Load average | yes | no (Windows has none) |
| CPU model, board / system model, BIOS | yes | yes |
| NVIDIA GPU (use, memory, temperature, watts) | yes (nvidia-smi) | yes (nvidia-smi) |
| AMD GPU (use, VRAM, temperature, watts) | yes (amdgpu driver's sysfs files, see below) | use and VRAM (Windows' GPU counters), no temperature or watts |
| Intel GPU | no | use and VRAM (Windows' GPU counters) |
| CPU temperature | yes (coretemp / k10temp) | only what the BIOS publishes as an ACPI thermal zone, often nothing or a fixed value; per core with [Core Temp](#core-temp-optional-windows) |
| Board fans and voltages | yes (hwmon chips) | only through the BMC (Supermicro, `ipmi:`) |
| CPU watts | yes (RAPL, see the table above) | only with [Core Temp](#core-temp-optional-windows) |
| Battery (laptops) | charge %, state, AC, draw in watts, time left, health | charge %, state, AC, Windows' own time-left estimate (no watts) |
| Processes | all, with command lines (passwords blanked) | all names; details for programs it may open; the program's path instead of its command line; per-program dedicated GPU memory for every card (Windows' "GPU Process Memory" counter, like Task Manager) |

**Not possible on Windows without a driver**, and therefore never done: CPU core temperatures, CPU package
watts, motherboard sensor chips (fans, voltages), and other programs' command-line arguments. Tools that show
these (HWiNFO, LibreHardwareMonitor, Afterburner) load a kernel driver, which is exactly what anti-cheat
software watches for. On a Supermicro board the BMC fills most of the gap (CPU temperature, fans, voltages).
The panel simply leaves out what the agent does not send.

**Laptop battery.** On a machine with a battery the panel shows a small *Battery* box on the host's page (charge,
state, time left, health) and the charge next to the host's name in the list. While the laptop runs on battery,
"Battery draw" is what the battery delivers, i.e. the whole laptop's consumption (not wall power). On Linux it
comes from `/sys/class/power_supply` and needs nothing extra; on Windows from GetSystemPowerStatus, which has no
watts. Desktops send nothing and the box does not appear.

## Core Temp (optional, Windows)

[Core Temp](https://www.alcpu.com/CoreTemp/) is a free Windows program that shows the temperature of every CPU
core and the CPU's power draw. It reads them with **its own** kernel driver, and it offers those readings to
other programs through a documented shared-memory block
([developer page](https://www.alcpu.com/CoreTemp/developers.html)). With `sensors: coretemp: true` fairy-agent
copies that block every couple of seconds and shows the cores as "Core 0", "Core 1"... (with Tj. Max as the
critical value) and the CPU package watts as "CPU watts", exactly where Linux machines show theirs. The fan
watchdog counts them as CPU temperatures.

**Anti-cheat:** fairy-agent itself still loads no driver and only opens the block read-only. The driver that
anti-cheat software can see is Core Temp's, the same situation as running Core Temp without fairy-agent. If a
game objects to Core Temp, close Core Temp before playing: the agent notices, writes one line in its log and
carries on without those readings (and picks them up again when Core Temp comes back).

**Set it up:**

1. Install Core Temp and start it. In *Options > Settings*: on *General* tick **Start Core Temp with Windows**
   (Core Temp does this with a scheduled task, as administrator) and on *Display* tick **Start Core Temp
   minimized** (and, if you like, *Close Core Temp to the notification area*).
2. Still in *Options > Settings*, on *Advanced*, tick **Enable global shared memory (SNMP)**. This is needed:
   without it Core Temp shares its readings only inside your own Windows sign-in session, and the fairy-agent
   service (like every service) runs outside it. In `CoreTemp.ini` this is `SnmpSharedMemory=1` under
   `[Advanced]`.
3. The helper service must be installed (`install-fairy-agent.ps1 -Helper`, or `setup-self-update` once
   `sensors.coretemp` is on; the same as for fan control). Core Temp runs as administrator and does not open its
   readings to other accounts, so the agent's own account is turned away; the helper (LocalSystem) copies the
   block for it, and the agent checks and converts it.
4. In `C:\ProgramData\fairy-agent\config.yaml`:

   ```yaml
   sensors:
     coretemp: true
   ```

   then `Restart-Service fairy-agent-helper, fairy-agent` (or run `setup-self-update`, which installs the helper if
needed). The log says "Core Temp readings available" once it has found them.

The agent looks for `Global\CoreTempMappingObjectEx` first, then the older `CoreTempMappingObject`, then the
same names in the signed-in user's session (the helper does the looking). Core Temp has no CPU package *temperature* in its shared block, so
only the cores are shown. Core Temp's Fahrenheit and "distance to Tj. Max" display options are converted back to
°C. Package watts appear only when Core Temp shows a "Power" value for your CPU.

## Settings (config.yaml)

The file is `C:\ProgramData\fairy-agent\config.yaml` (Windows) or `/etc/fairy-agent/config.yaml` (Linux).
`deploy/fairy-agent.config.example.yaml` lists every setting with an explanation. The important ones:

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | the Tailscale address, port 9101 | where the panel connects; `0.0.0.0` is refused unless `allow_all_interfaces: true` |
| `token_file`, `control_token_file` | `token`, `control-token` next to config.yaml | the tokens (at least 24 characters, different from each other). `FAIRY_AGENT_TOKEN` / `FAIRY_AGENT_CONTROL_TOKEN` in the environment win. Never on the command line. |
| `hide_host_details` | false | no hostname, no hardware model, just "Windows" / "Linux" |
| `processes.enabled` / `cmdline` / `never_open` | true / true / none | the Processes tab |
| `gpu.nvidia_smi` | auto | `off` or a full local path (only administrators / root may be able to change the file and its folders) |
| `gpu.amdgpu` | auto | Linux: AMD GPUs through the amdgpu driver's sysfs files; `off` to switch off |
| `gpu.windows` | auto | Windows: AMD / Intel / other GPUs from Windows' GPU counters; `off` to switch off |
| `gpu.amd_adl` | auto | Windows: Radeon temperature and watts from AMD's ADL (Adrenalin driver), read only; `off` to switch off |
| `sensors.coretemp` | false | Windows: CPU core temperatures and watts from Core Temp (see [Core Temp](#core-temp-optional-windows)) |
| `ipmi`, `fan_control`, `power_control`, `wol`, `bmc_relay` | off | see [Optional features](#optional-features) |
| `env_file` | none | `KEY=value` secrets (device and BMC passwords); `fairy-agent secret set NAME` writes it |
| `self_update.enabled`, `self_update.repo` | off, `n3ptune-cpu/Fairy-agent` | see [Updates](#updates-the-panels-update-button) |
| `control_rate_per_min` | 12 | all control requests together (fan, power, Wake-on-LAN, BMC relay, update) |
| `log_file` | Windows: `C:\ProgramData\fairy-agent\logs\agent.log` (5 MB, one old copy); Linux: the journal | |

Unknown settings are an error (so a typo does not silently do nothing). `fairy-agent check-config` checks the
file and the tokens without starting anything.

### Changing a setting from the command line

`fairy-agent config set <setting> <value>` changes one setting in config.yaml without an editor (handy in a
remote shell such as DWService): it keeps the file's comments and order, adds a missing setting under the
right section, checks the result exactly like `check-config` **before** writing, then replaces the file in one
step (keeping its owner and permissions, on Windows its access list). Run it as root / in an Administrator
PowerShell, then restart the agent.

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" config set fan_control.auto_mode standard
& "C:\Program Files\Fairy\fairy-agent.exe" config get fan_control.auto_mode
Restart-Service fairy-agent
```

```sh
sudo fairy-agent config set ipmi.enabled true
sudo fairy-agent config set wol.allowed_macs "aa:bb:cc:dd:ee:ff, 11:22:33:44:55:66"
sudo systemctl restart fairy-agent
```

Settings are written with dots (`fan_control.min_duty`). Values: `true`/`false`, numbers, text, and lists as
comma-separated values (`[]` for an empty list). `config get <setting>` prints the value the agent uses
(the default when the file does not set it); `config show` prints every setting. `power_sources` and `ups`
are lists of devices: edit those in the file.

## Checking, logs, updating, removing

* **Is it running?** Windows: `Get-Service fairy-agent, fairy-agent-helper` (the helper only where installed;
  `fairy-agent helper-status` says more). Linux: `systemctl status fairy-agent`.
* **Logs.** Windows: `Get-Content C:\ProgramData\fairy-agent\logs\agent.log -Tail 30` (start-up problems also go
  to the Event Viewer, Windows Logs > Application, source "fairy-agent"); the helper's:
  `C:\ProgramData\fairy-agent\helper\helper.log` (source "fairy-agent-helper"). Linux: `journalctl -u fairy-agent`.
  Logs never contain tokens or passwords.
* **Ask it directly** (from the panel machine):
  `curl -H "Authorization: Bearer <token>" http://100.64.0.10:9101/metrics`
* **Panel shows the machine offline**: check the firewall rule, that Tailscale is up on both sides, and that the
  token in the panel's `fairy.env` is exactly the one in the agent's `token` file. A wrong token shows up in the
  agent's log as "rejected request".
* **Update.** With self-update on: the panel's Update button (see [Updates](#updates-the-panels-update-button)).
  On the machine: `fairy-agent update` (it checks the release's signature itself). By hand, with files
  downloaded and checked as in [SETUP-UPDATES.md, 2.3](SETUP-UPDATES.md#23-by-hand-from-one-named-release-checked):
  Windows: run `install-fairy-agent.ps1` again with the new exe (or `Stop-Service fairy-agent`, copy
  the exe over, `Start-Service fairy-agent`). Linux: copy the new binary to `/usr/local/bin/fairy-agent`, then
  `systemctl restart fairy-agent`. Settings and tokens stay. `fairy-agent version` shows the version and
  whether the program carries the release key.
* **Pairing (Add host).** `fairy-agent pair-status` says whether the panel has paired, is still expected (and
  until when), or the code expired. The agent's log says "paired with panel" (with the panel's address, never a
  token). The state file is `/var/lib/fairy-agent/pairing.json` (Linux) or
  `C:\ProgramData\fairy-agent\state\pairing.json` (Windows); it never holds the code itself.
* **Remove.** Windows: `& "C:\Program Files\Fairy\fairy-agent.exe" uninstall` (removes all three services:
  agent, helper, updater; the fans go back to the BMC first), then
  `Remove-NetFirewallRule -DisplayName "Fairy agent (Tailscale only)", "Fairy agent helper (no network)"` and delete `C:\Program Files\Fairy` and
  `C:\ProgramData\fairy-agent`. Linux: `systemctl disable --now fairy-agent`, delete the units
  (`fairy-agent.service`, `fairy-agent-update.service`), the polkit rules (`rm -f
  /etc/polkit-1/rules.d/49-fairy-agent*.rules`), `/usr/local/bin/fairy-agent` (and `.old`), `/etc/fairy-agent`,
  `/var/lib/fairy-agent*`, and `userdel fairy-agent`.

## Security in short

* Listens only on the Tailscale address (or the address you set), never on every network by default.
* Every request needs a token, except `POST /pair`: it answers only while a one-time join code from the panel's
  Add host is waiting (15 minutes, the code stored only as a hash), only to the panel's address, 5 times a minute
  at most, hands out the tokens once and is closed for good after that (or after 10 wrong codes).
* Tokens are compared in a way that does not leak their length or content through
  timing. Reading uses one token, changing anything needs the second, separate one. Repeated wrong tokens
  block that address for a minute.
* Read-only unless you switch features on; each control action is rate limited and logged with who asked.
* Self-update installs only releases signed with the owner's key (checked twice: by the agent and by the
  installer, which never trusts the downloaded copy), only files fetched over HTTPS from GitHub, never an older
  version, and only when an admin asks for it.
* Command lines are cleaned of passwords and tokens before they leave the machine (and again by the panel).
* The BMC relay reaches private addresses only, passes the BMC password to ipmitool only through its
  environment, pins the Redfish certificate and never logs passwords.
* Time limits on every connection; requests are small and bounded. What a UPS server (NUT) sends is bounded too
  (4 KiB per line, 1 MiB per poll, 64 UPSes), so a broken or hostile upsd cannot exhaust memory.
* The log cannot fill the disk: the log file is rotated at 5 MB (one old file kept), and the same message is
  written at most 30 times a minute (the rest are counted: `suppressed=N` on the next one).
* Windows: the agent runs as its own virtual account with a single privilege; what needs more goes through the
  helper service, which has no network, admits only the agent's account on its local pipe (checked twice), and
  answers ten fixed requests with strict limits. Settings folder readable only by administrators, SYSTEM and the service; the program lives in
  `C:\Program Files` and only administrators / SYSTEM can change it (self-update goes through the separate
  LocalSystem updater service, which checks the signature itself). The install scripts check the program's
  SHA-256 against the signed SHA256SUMS before running it as Administrator. Helper programs (ipmitool,
  nvidia-smi) are only run from places only administrators can change. Linux: own user, no root, no capabilities, systemd sandbox.

## Not yet tested on a real Windows PC

The Windows parts compile and their pure logic is unit-tested, but were not yet run on real Windows. Check these
on the first install and report anything odd:

* the BMC power-on relay (ipmitool through `-E`, Redfish) against a real BMC, and `fairy-agent secret set`'s
  Windows ACL with the installed service;
* the service itself: install / start / stop / uninstall, the folder permissions, the log file, the Event Log
  entry on a failed start, automatic restart;
* CPU %, memory, disks, network counters, uptime, OS name and hardware strings (registry);
* ACPI thermal-zone temperatures (PDH);
* **0.5.1's self-migration** from LocalSystem (TEST-ON-WINDOWS.md, section 8): the state machine is
  unit-tested on Linux (every step failing, resume after a crash, rollback, the pauses), the Windows calls are
  not: the switch and the rollback (`ChangeServiceConfig` to LocalSystem with an empty password,
  `QueryServiceConfig2` for the old required privileges, the token's privileges as the fallback list), the
  updater service as the one that restarts the agent (and starting with Windows meanwhile), the account check
  of the new process (`OpenProcessToken` as SYSTEM), `netsh advfirewall ... service=fairy-agent-helper`, the
  migration folder's permissions and `TrustedFolder` on it, and the interplay with 0.4.2's in-service updater
  and build 10's updater service (the agent waits for their result before it restarts);
* **0.5.0's two services** (none of this has run on Windows yet; TEST-ON-WINDOWS.md is the checklist): creating
  the agent's service as `NT SERVICE\fairy-agent` and moving an existing one (`ChangeServiceConfig` with the
  virtual account and no password), the required-privileges lists of both services (`sc qprivs`), the helper
  service, its pipe (access list, `PIPE_REJECT_REMOTE_CLIENTS`, the first-instance flag, overlapped I/O with
  time limits), the client checks on both ends (impersonation at identification level, `CheckTokenMembership`,
  `GetNamedPipeServerProcessId` against the service's process id), the agent's query / start / stop right on
  the helper service, the helper's folder check (`helper\` owned by Administrators), the firewall block rule
  for the helper's service SID, Core Temp / WMI-IPMI / shutdown / sleep from a LocalSystem service with only
  three privileges, the fans going back to the BMC when the helper stops, the updater stopping and starting the
  helper around a swap, and Windows itself under a virtual account (PDH counters, DXGI, ADL, nvidia-smi,
  event log, the Tailscale address);
* Core Temp's shared memory: which name the helper finds (global setting on/off), the values against Core
  Temp's window (unit conversions, package watts);
* the process list (Toolhelp snapshot + limited handles) as `NT SERVICE\fairy-agent`;
* nvidia-smi on Windows (looping mode, path detection);
* shutdown / reboot / cancel (InitiateSystemShutdownEx / AbortSystemShutdown) from the helper;
* sleep (SetSuspendState after the agent's own countdown; GetPwrCapabilities for S1-S3 / Modern Standby) and
  `systemctl suspend` with the extended polkit rule (CanSuspend through busctl): untested on real machines;
* IPMI through `powershell.exe` and the Microsoft_IPMI WMI class: the reply format is taken from Microsoft's
  documentation and examples (first byte of the reply = completion code) and has not been seen on a real BMC
  yet. Try `ipmi: enabled: true` first (sensors only) and look at the panel and the log before enabling fan
  control;
* the install script's firewall rule;
* per-program GPU memory from the "GPU Process Memory" counter (compare with Task Manager's "Dedicated GPU
  memory" column), and its matching to the NVIDIA card through nvidia-smi's pci.bus_id;
* the permission check on helper programs (ipmitool, nvidia-smi) and on the agent itself (setup-self-update):
  reading owner and ACL entries of the file and its folders. 0.4.3 refused everything on a PC whose `C:\` gives
  Authenticated Users Modify on `C:\` itself (which holds DELETE, harmless on a drive's root): no nvidia-smi,
  no ipmitool, no self-update. 0.4.4 checks a folder further up only for what could replace the path below it
  (DELETE except on the root, FILE_DELETE_CHILD, WRITE_DAC, WRITE_OWNER), maps generic rights, and is unit-tested
  against stock Windows 10 / 11 permissions (`C:\`, `C:\Program Files`, `C:\Windows\System32`, an
  administrator's `C:\Program Files\ipmitool`) written as SDDL, but not yet run on a PC;
* leaving out leftover GPU entries ("GPU Adapter Memory" counter per adapter), checked against unit tests built
  from the RX 5600 XT and Intel UHD reports, not yet on those PCs; 0.5.1's merging of entries at one PCI
  location (D3DKMT `KMTQAITYPE_ADAPTERADDRESS`, then `..._RENDER`) and the added counters, tested with the adapter
  ids of one laptop only; the PDH counters set up again after a failure at start;
* self-update on Windows: `setup-self-update` (removing 0.4.2's program-folder entry, the update / stage folder
  permissions, creating the fairy-agent-update service and its start right for the agent), the updater service
  starting, stopping and starting the agent's service, renaming the running exe, rolling back, its log file,
  and the stage folder lock (no junction while it reads);
* `install.ps1` / `install-fairy-agent.ps1` on Windows with the new checks (parsed by PowerShell 7 on Linux
  only): the SHA256SUMS check of the program, `icacls /remove:g` before the copy, the check of the copy;

Self-update on Linux was tested with fakes (signature, download, swap, rollback) but not yet against a real
GitHub release, a real polkit rule or SELinux: watch `journalctl -u fairy-agent-update` the first time.
