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
  * [Running the installer again (0.6.0): what is kept, what is moved aside](#running-the-installer-again-060-what-is-kept-what-is-moved-aside)
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
$u='BASE'; $b=(New-Object Net.WebClient).DownloadData("$u/install.ps1"); if ((([Security.Cryptography.SHA256]::Create().ComputeHash($b) | ForEach-Object { $_.ToString('x2') }) -join '') -eq 'PS1_HASH') { $env:FAIRY_JOIN_CODE='CODE'; try { & ([scriptblock]::Create([Text.Encoding]::UTF8.GetString($b))) -ReleaseUrl $u -SumsSha256 SUMS -PanelAddress PANEL -PairV2 [options] } finally { Remove-Item Env:FAIRY_JOIN_CODE -ErrorAction SilentlyContinue } } else { throw 'install.ps1 is not the release the panel checked: not run' }
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
accept them. This old form is deprecated: `install.sh --join CODE`, `install.ps1 -Join CODE` and
`fairy-agent join --code CODE` each print one warning that says so (the warning never contains the code), and
the form will be removed in a later release. Update the panel to get the new line.

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

### Running the installer again (0.6.0): what is kept, what is moved aside

"The installer" here is `install-fairy-agent.ps1`, the panel's Add host / Re-pair command (which runs it),
`fairy-agent install` and `fairy-agent setup-self-update`. Since 0.6.0 they do not take the data folder
`C:\ProgramData\fairy-agent` on trust. The folder runs through a **trust check** first.

**Trusted means**, for the folder and for every file and folder in it:

1. it is a plain file or folder: no link, no junction, and a file has one name only;
2. its owner is Administrators, SYSTEM or TrustedInstaller;
3. nobody else can change it. (Inside `logs\`, `state\` and `update\stage\` the agent's own account may write;
   that is what those three folders are for.)

**A healthy PC passes, and nothing is written.** `config.yaml`, the tokens and the pairing stay exactly as
they are. One of Fairy's own folders that SYSTEM owns instead of Administrators is healthy too (`update\stage`
is, on a PC whose agent once ran as LocalSystem). If the agent's own account owns one of its three folders,
Administrators are made the owner of that folder, nothing inside it is touched, and one `repaired:` line says
so. Running `install-fairy-agent.ps1` again by hand does not unpair the PC. The output has no line that
starts with `repaired:` or `IMPORTANT:`.

(The panel's **Re-pair** always makes new tokens and hands them to the panel. That is what Re-pair is for, and
it is not a sign of a failed check.)

**When something fails the check**, the installer never keeps using it:

| What failed | What the installer does | What you see |
| --- | --- | --- |
| the data folder itself (someone else owns it or can change it) | renames the whole folder to `C:\ProgramData\fairy-agent.untrusted-<UTC date and time>`, makes a new one, writes a starter `config.yaml` with everything that can change the PC switched off, and new tokens | `repaired:` lines, then `IMPORTANT: config.yaml could not be trusted and was replaced by a starter ...` |
| a file or folder inside (someone else owns it or can change it) | moves it, as it is, into `C:\ProgramData\fairy-agent\untrusted-<UTC date and time>\` (a folder only administrators can change; what was moved keeps its old owner and permissions, so that account can still reach it until you delete it, step 4 below), and makes Fairy's own folders anew | a `repaired:` line for each |
| a link or junction inside | removes the link (not what it points to) | a `repaired:` line |
| a file that another account could read, but not change | writes it anew with the folder's permissions | a `repaired:` line |
| anything at all that does not belong in `logs\`, `state\` or `update\stage\` (a link, a file of another account, a file with a second name, folders nested more than 8 deep), or one of these three folders with other permissions | moves **that whole folder** into `untrusted-<UTC date and time>\` and makes a new, empty one. See "The agent's three folders" below | a `repaired:` line that names what was found and says what went with the folder |
| a token file that another account could read, or that went aside (the file `token_file` / `control_token_file` name in config.yaml, whether the path is written with `\` or `/`, in any letter case, with `.` parts or doubled separators; not if it is written with the file's short 8.3 name such as `CONTRO~1`: write the full name) | writes a new token | `IMPORTANT: the tokens are new. Pair this PC with the panel again (Re-pair in the panel).` |

If a rename fails (for example because a program holds a file in the folder open), the installer stops and
says so: stop the two services (`Stop-Service fairy-agent, fairy-agent-helper`) and run it again. The installer
only repairs a folder named `fairy-agent`. With another `--config` folder it reports what is wrong and moves
nothing in it.

**The agent's three folders.** `logs\`, `state\` and `update\stage\` are the folders the agent's own
low-rights account writes. The installer runs as Administrator, so it changes nothing inside them, ever: a
program running under the agent's account could swap a folder there for a link in the instant between the
installer's look at a name and its use of it, and the administrator's change would then land somewhere else
on the disk. The installer only looks. A healthy folder is left exactly as it is. When something in one of
the three is not as it should be, the whole folder is moved aside and a new, empty one is made. What that
costs you:

| Folder replaced | What went with it | What to do |
| --- | --- | --- |
| `logs\` | the old log files (they are in the moved folder) | nothing; the agent starts a new `agent.log` |
| `state\` | the pairing state: a join code that was waiting, and the panel's address | run the panel's Add host / Re-pair command once if a code was waiting or `only_from_panel` is on. The tokens are not affected: the PC stays paired |
| `update\stage\` | a downloaded update that was waiting to be installed | press Update in the panel again |

`config.yaml` and the tokens are never in these folders and are not touched by this.

For the same reason the installer sets a folder's permissions only while nothing below that folder can be
changed by another account (Windows passes a folder's new permissions on to everything inside). If the data
folder's own permissions have to be set, the three folders are moved next to it for that moment
(`C:\ProgramData\fairy-agent.parked-<time>-logs` and so on) and put back straight away, with everything in them.
If the installer is interrupted in that moment, it says where they are; move them back with `Move-Item`, then
run the installer again (`setup-self-update`): it checks the three folders.

**What "moved aside" means.** Nothing was deleted. The folder or file is still on the disk: the whole old data
folder as, for example, `C:\ProgramData\fairy-agent.untrusted-20261110-142530`, single things from inside it in
`C:\ProgramData\fairy-agent\untrusted-20261110-142530\`. Fairy never reads it again. It was moved
because Fairy could not tell who had prepared it: an untrusted `config.yaml` can name another token file or
switch features on, and the services that read it run with high rights. What to do:

1. Do what the `IMPORTANT:` line says: **Re-pair** the PC in the panel, from a panel that is already updated
   (Re-pair installs the agent release that panel was built for; an old panel puts an older agent back). If
   `config.yaml` was replaced, switch the features on again, in the panel or in the new `config.yaml`.
2. If you want to see your old settings, open the old `config.yaml` in Notepad and read it. Type what you need
   into the new file. Do not copy the old file back, and do not run anything from the old folder.
3. List what was moved aside (read-only), in PowerShell as Administrator:

   ```powershell
   Get-ChildItem C:\ProgramData -Force -Filter 'fairy-agent.untrusted-*'
   Get-ChildItem C:\ProgramData\fairy-agent -Force -Filter 'untrusted-*'
   ```

4. When you no longer need it, delete it. The names below are **examples**: use a name from step 3. Use
   `rd` as shown, not `Remove-Item -Recurse`: what was moved aside may hold links that another account made,
   and `rd /s` removes a link itself, never what the link points to.

   ```powershell
   cmd /c rd /s /q "C:\ProgramData\fairy-agent.untrusted-20261110-142530"
   cmd /c rd /s /q "C:\ProgramData\fairy-agent\untrusted-20261110-142530"
   ```

5. If you did not expect this on that PC, treat it as a finding: some other account or program had prepared or
   changed Fairy's data folder. Report it with the installer's output.

**After an update through the Update button only** (the installer has not run yet), the new program checks the
folder but repairs nothing:

* A healthy folder: nothing changes.
* An untrusted folder: `agent.log` has the warning `the agent's data folder is not safe: self-update and the
  helper will not work until it is repaired`. The helper refuses to work, `fairy-agent join` refuses, and the
  updater service does nothing: it writes `fairy-agent-update did nothing: ...` to the Windows Event Log
  (Windows Logs > Application, source fairy-agent) and ends with exit code 3. The cure is
  `& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update` in PowerShell as Administrator. (The panel's
  Re-pair runs the same repair, but it installs the agent release that panel was built for: use it only from a
  panel that is already updated, or it puts an older agent back.)

On Windows `fairy-agent join` also refuses a `config.yaml` that names a token file outside the data folder.

### Two services: the agent and its helper

Since 0.5.0 (release build 11 or later) fairy-agent on Windows is two services that run the same program:

| | **fairy-agent** (the agent) | **fairy-agent-helper** (the helper) |
| --- | --- | --- |
| Account | `NT SERVICE\fairy-agent`, a "virtual account": no password, cannot sign in, a member of no admin group (only of "Performance Monitor Users", see below) | LocalSystem |
| Rights | only `SeChangeNotifyPrivilege` (needed to open folders); no shutdown, no impersonation, nothing else | only `SeChangeNotifyPrivilege`, `SeShutdownPrivilege`, `SeImpersonatePrivilege` (to see who connects); no driver loading, no debugging other programs, no taking over files |
| Network | listens on the Tailscale address for the panel; the tokens, `/metrics`, everything the panel sees | **none**: listens only on the local pipe `\\.\pipe\fairy-agent-helper`; a firewall rule blocks all its traffic in and out |
| Files | reads `C:\ProgramData\fairy-agent` (config, tokens), writes only `logs\`, `state\` and `update\stage\` | reads config.yaml, writes only its own log `C:\ProgramData\fairy-agent\helper\helper.log` (the agent can only read it) |
| Installed | always | only where something needs it: Core Temp, IPMI (BMC sensors, fans) or shutdown / reboot / sleep |

**What the helper does, and nothing else.** It answers twelve fixed requests from the agent: `ping`, `status`,
`coretemp_read` (a copy of Core Temp's shared memory; the agent checks and converts it), `ipmi_sensors` (the
BMC's readings), `fan_status`, `fan_set` (zone 0 or 1, 30-100 %), `fan_mode` (standard, full, optimal or
heavyio), `fan_auto` (back to the BMC's automatic mode), `power` (shutdown, reboot or sleep after 10 s to 24 h,
or cancel), `apply_update` (starts the signature-checking updater service, nothing else), and for the passkey
approval `challenge` (a challenge for one exact fan, power or update request, or for the first-time set of
the trust) and `trust_init` (the first approval trust, accepted once and only with an approval that fits it;
see [Passkey approval](#passkey-approval-of-fan-power-and-update-requests-pocket-id)).
With a trust file in its folder the helper runs `fan_set`, `fan_mode`, `power` (other than cancel) and
`apply_update` only with an approval it has verified itself. No request takes a
path, a command or free text; anything else is refused, as are requests over 512 bytes (the two new requests
and a request with an approval: 32 KiB, in a frame marked as such), unknown fields and
values out of range. Each request is checked against what `config.yaml` switches on (with Core Temp off,
`coretemp_read` is refused too). Reads are limited to 300 a minute, changes to 30 a minute; requests for a
challenge (60 a minute) and the two requests that only make things safer (`power` cancel and `fan_auto`, 30 a
minute) are counted separately, so neither can be kept out by the others. Every change and
every refused request is written to `helper.log` with who asked.

**Who may talk to it.** The pipe's access list lets in only the agent's account, SYSTEM and Administrators,
refuses network logons, and the pipe refuses remote clients. On top of that the helper looks at every
client's identity and drops anyone else. The agent in turn uses the pipe only when the process that serves it
has the helper service's process id. A process id can be used again after the helper has ended, so the agent
also looks at who owns the pipe; in this release that look only writes a warning to `agent.log` unless
`require_helper_pipe_owner: true` is set (see [Settings](#settings-configyaml)). The agent lets the helper only
identify it, not act as it.

**The fan watchdog lives in the helper**: while a fixed fan speed is set it checks the CPU temperature every
10 seconds (the BMC's sensors, and Core Temp's when that is on) and puts both zones to 100 % at 80 °C or after
30 seconds without any temperature (see [Fan control](#fan-control-supermicro) for what counts as a
temperature and what happens when the BMC does not say its fan mode). It keeps working if the agent stops or
crashes. When the helper itself
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
  service and nothing else (it cannot change or delete it). **While the helper is stopped, `POST /power`
  with `cancel` answers `503 helper_stopped`** on a PC where the helper carries out power requests: a
  shutdown or reboot that was scheduled before keeps counting down in Windows (a pending sleep is a timer
  inside the helper and ends with it), and it cannot be cancelled from the panel until `POST /helper/start`
  has brought the helper back. Stopping the helper needs the control token and no passkey approval, so
  whoever holds that token can keep a cancel out in this way (he cannot start a shutdown with it while
  approvals are on). On the PC itself `shutdown /a` cancels a pending shutdown in any case.

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
`agents:` entry. Each one uses the separate control token, is limited to 12 requests a minute for all of them
together (`control_rate_per_min`; what counts in which budget is in the settings table below), and is written
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

Two details of that watchdog (0.6.0):

* **An old BMC temperature is no temperature.** A BMC temperature older than 60 seconds counts as no reading
  (with the default `ipmi.sensor_interval_s: 10` already after 30 seconds). Where a fixed fan speed is used on
  a machine without an OS temperature, keep `ipmi.sensor_interval_s` at 25 or less; with a longer interval
  the watchdog may find no fresh reading and set 100 %.
* **When the BMC does not say what fan mode it is in.** One failed answer changes nothing: the next check
  that gets an answer acts as always. After three checks in a row without an answer (20 seconds) the watchdog
  assumes a fixed speed may be set: at the temperature limit or without a reading it sets 100 %, and hands
  the fans back to the BMC's automatic mode only if the BMC refuses that. It never sets a lower speed. While
  the BMC stays silent it tries again every 30 seconds and writes what happened once, not with every try. As
  soon as the BMC says its mode again, the watchdog is back to its ordinary rule.

**When a lower speed is refused (0.6.0).** A fixed speed of 100 % is always accepted. A speed below 100 % is
refused with HTTP 409 in three cases. The answer carries a `code` and a sentence that the panel shows:

| `code` | When | What to do |
| --- | --- | --- |
| `fan_too_hot` | the hottest CPU reading is at or above `max_temp_c`, or a temperature sensor reports something that is not a number | wait until it is cooler; only 100 % is accepted until then |
| `fan_watchdog_hold` | the watchdog set the fans to 100 % less than 5 minutes ago | wait; the answer says how many seconds are left |
| `fan_no_temperature` | no temperature is known at all, neither from the BMC (a reading older than 60 seconds does not count) nor from the operating system | wait a moment and try again. This is normal right after the agent or the helper has started, until the BMC's first sensor reading is in. If it stays, look at the BMC sensors in the panel |

A 409 without a `code` means the BMC is not in mode "full" (a speed is ignored in the other modes): choose
"full" first.

**On Linux a fixed speed ends when the agent ends (0.6.0).** The watchdog lives in the agent, so a fixed speed
must not outlive it:

1. When the agent stops (stop, restart, update, reboot of the machine), it first hands the fans back to the
   BMC's automatic mode (`auto_mode`). If the BMC does not take that mode, both zones go to 100 %.
2. When the agent starts and finds mode "full" left over (after a crash or a power cut), it hands the fans back
   in the same way, right at its start.
3. `fairy-agent.service` has the line `ExecStopPost=-/usr/local/bin/fairy-agent fans-auto`. systemd runs it
   after the agent has ended for **any** reason, also when it was killed. `fairy-agent fans-auto` takes no
   options, reads `/etc/fairy-agent/config.yaml` and does nothing when fan control is off.

So after an agent restart or update the fans are in the BMC's automatic mode, and a fixed speed has to be set
again in the panel. A mode you chose yourself (standard, optimal, heavy IO) is left as it is. Mode "full"
counts as a fixed speed, also at 100 %.

Steps 1 and 2 come with the program (the Update button is enough). Step 3 is in the service file, which only
the install script replaces. Check (read-only):

```sh
grep -c 'ExecStopPost=-/usr/local/bin/fairy-agent fans-auto' /etc/systemd/system/fairy-agent.service
```

`1`: the line is there. `0`: run the panel's Re-pair command on that machine once
([SETUP-UPDATES.md, 2.2](SETUP-UPDATES.md#22-service-files-and-rules-of-a-newer-release-re-pair)). On Windows
the watchdog lives in the helper, which hands the fans back when it stops, see
[Two services](#two-services-the-agent-and-its-helper).

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

**Cancel on Windows cancels only Fairy's own shutdown (0.6.0).**

* The helper writes a shutdown or reboot that was asked for through the panel to
  `C:\ProgramData\fairy-agent\helper\power-pending.json` (administrators and SYSTEM only). So the panel still
  shows it, and Cancel still works, after the agent or the helper has restarted. Before 0.6.0 Cancel did
  nothing after an agent restart.
* Cancel aborts that shutdown and nothing else. A shutdown that Fairy did not start (for example
  `shutdown /s /t 600` typed by hand) is not shown as pending, and Cancel does not touch it.
* The record ends when the action's time has passed (plus one minute), on Cancel, and when Windows has been
  started again since.
* While one action is pending, a second one is refused with HTTP 409 (`a shutdown is already pending; cancel it
  first`).
* While the helper is stopped, Cancel answers 503 `helper_stopped` instead of "ok": the agent cannot tell
  whether a shutdown is pending. Start the helper, then cancel. This is the one way a request with the
  control token alone can keep a cancel out: `POST /helper/stop` needs no passkey approval. Windows goes on
  counting the shutdown down meanwhile; `shutdown /a` typed on the PC cancels it in any case.
* When the helper was handed a shutdown, reboot, sleep or cancel and did not answer in its time (5 s, counted
  from the moment the request is written to it), the agent answers 504, not "could not schedule": the helper
  may have carried the request out all the same. The agent then asks the helper again for what is pending,
  and Cancel reaches it. The same 504 answers a fan change, an approval question and "Turn on" when the
  helper has the request and is silent.
* Two limits. A Fairy shutdown that you abort by hand (`shutdown /a`) stays shown in the panel until its time
  or until you press Cancel, because Windows offers no way to ask. A pending **sleep** is a timer inside the
  helper: it is lost when the helper restarts.
* The helper enforces `power_control.min_delay_s` itself: a shorter delay is refused. It reads the setting when
  it starts, so after changing it run `Restart-Service fairy-agent-helper, fairy-agent`.

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
  member>/Actions/ComputerSystem.Reset {"ResetType": "On"}`, basic auth, 10 s. A BMC's certificate is
  self-signed, so the agent must be told which one is the BMC's: **`tls_fingerprint` is needed**, the SHA-256
  of the BMC's certificate (64 hex digits, colons allowed). The BMC's user name and password are sent only to
  that certificate. Without `tls_fingerprint` nothing is sent to the BMC: a request answers
  `bmc_fingerprint_missing` and names the fingerprint of the certificate the BMC's address shows at that moment.
  Compare it with the certificate in the BMC's own web interface (someone else on that network could be
  answering at the BMC's address), then put it into the target as `tls_fingerprint:` and restart the agent.
  `fairy-agent check-config` and the agent's log at start name every target that still lacks it. One exception,
  so that an update breaks nothing: a target whose certificate an earlier version learned on its first use
  (kept in the agent's state folder, `bmc-pins.json`) keeps working with that certificate. Nothing is learned
  any more; set `tls_fingerprint` for such a target too when you next edit the file. A different certificate
  than the named one answers `bmc_certificate_changed`, and nothing is sent to it; that answer shows the new
  certificate's fingerprint, and it must be compared in the same way before it is set. Both answers are short
  enough for the panel to show them whole; the agent's log has the same with the BMC's address.

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
(Shelly, Tasmota, Redfish, NUT); passwords go into a separate file named by `env_file:` as
`NAME=value` lines and stay on that machine. Tuya plugs are no longer supported. An entry with `type: tuya`
from an earlier version does not stop the agent: it is ignored, and the agent's log at start and
`fairy-agent check-config` name it in one line (`power source "desk-plug": tuya is no longer supported and is
ignored (remove the entry from config.yaml, and the line TUYA_KEY_DESK=... from the env file: the plug's key
is not used any more)`). That line names the variable the entry kept the plug's local key in (its
`local_key_env`), never the key. Remove both when you next edit the files: the entry from `config.yaml`, and
that variable's line from the `env_file` (the key is a secret of the plug and still works on your network).
Until you do, the agent leaves that line alone and does not load it: a secret that only an ignored entry names
is not put into the agent's environment. If something else in `config.yaml` names the same variable (a plug
or UPS that stays, the BMC's password, a BMC relay target), it is loaded as before, and the line for the
ignored entry says so instead: `(remove the entry from config.yaml; leave the line SHARED_PW=... in the env
file: it is still in use)`. Then remove only the entry. A Tasmota plug with a web password gets it the one way Tasmota
documents, in the address of the request (`/cm?user=...&password=...`), exactly as in earlier releases. That
address is never logged and never part of an error message. It crosses the local network unencrypted:
Tasmota speaks plain HTTP. One answer of a plug or a BMC is read up to 256 KiB of JSON with at most 8192 values,
nested at most 32 deep; a larger one is refused and the source shows "answer from device is too large", "has
too many values" or "is nested too deep" (a hostile or broken device could otherwise use up the agent's
memory with one answer). These limits are for one answer of one device: while an answer arrives, up to
256 KiB of it are held for each device, so a great many devices that all send the largest allowed answer at
the same moment (about 170 of them in an agent that may use 64 MiB) can still use the memory up. UPS servers
(NUT) are read in another way and have limits of their own (see "Security in short"). Plugs
send a few hundred bytes and a BMC's Power document 15 to 100 KiB, so this
should never show. If it does for a BMC (`type: redfish` or `ipmi`), point `power_path:` at a smaller document
of that BMC, for example `/redfish/v1/Chassis/<id>/EnvironmentMetrics`. `system_hint: self` links a plug to the agent's own machine, but
only for an agent that is a host of its own: for an agent merged into a Proxmox node (`node:` in the panel) it
does not work, because the panel shows that machine under the node's id. There, and whenever the panel should
decide, use `power_links:` in the panel's agent entry (`power_links: {<device id>: <system id>}`, e.g.
`{office-ups: node-office}`), plus `ups_powers:` / `ups_names:` for UPSes, as for any agent.

## Passkey approval of fan, power and update requests (Pocket ID)

A panel that was taken over, or a stolen control token, could until now shut a machine down, set its fans or
start an update. With an **approval trust** set on a machine, those requests run only with a fresh passkey
confirmation at Pocket ID, and the machine checks that confirmation **itself**, offline, against a key it has
pinned. The panel cannot skip the check, because the panel is not the one who checks.

**Who checks.**

| Machine | Who checks | Protects against | Does not protect against |
| --- | --- | --- | --- |
| Windows with the helper | `fairy-agent-helper` (LocalSystem, no network), for everything it carries out. The agent only passes things on and is not trusted | a taken-over panel, a stolen control token, a taken-over agent process | an administrator on the PC |
| Linux (and every system but Windows) | the agent process itself | a taken-over panel, a stolen control token | a taken-over agent process: it is the checker |
| Windows, what the agent carries out itself, without the helper: fans driven over the network (`ipmi.transport: ipmitool`); power, fans and update of an agent that was started before the helper was installed, or after it was removed | the agent process itself, with the helper's trust file (it reads it, it cannot change it) | a taken-over panel, a stolen control token | a taken-over agent process |
| Windows without the helper and without a trust file | nobody: nothing is checked, and there is no way to set a trust there | | |

The rule is the same everywhere: **while trust is set, each request that needs an approval is checked by the
program that carries it out.** `GET /metrics` says who that is: `"enforced_by"`, and on a Windows machine where
the agent carries some requests out itself also `"agent_checks": ["fan_set", "fan_mode"]` (those requests are
the agent's to check; the helper checks the rest). The panel does not have to know: it asks
`POST /approval/challenge`, and whoever will check answers.

**Which machine.** An approval is for one machine. Every machine with a trust file has a **machine id** in
that file: 22 characters made of 16 random bytes (or what the panel chose at the first-time set), made up when
the trust is set for the first time and kept as long as the file is. It is a name, not a secret, and
`GET /metrics` shows it (`"machine_id"`). Every approval names, for each request in it, the machine it is for,
and the machine that checks uses **its own** id from **its own** trust file, whatever the approval says. So
an approval you gave for one machine is refused by every other machine (`403 approval_refused`), also when
somebody who controls the first machine's answers handed the panel the other machine's challenge and then
passed the approved request on with a stolen control token. (That was possible before 2026-11-12: the
approval named the request and a challenge, and a challenge is 32 random bytes that could be any machine's.)

What this rests on, and what no machine can do for you: **the panel must know which id belongs to which
machine.** It takes each machine's id on record when it sets the trust (or when it first sees one), builds
every approval with the id on record, and treats two machines that show the same id, or a machine whose id
is suddenly another one, as an alarm. A machine sees no other machine, so it **cannot notice** that another
one has its id.

**One id, one machine: the panel has to check that, always.** At every look at its machines, not only when
it first takes an id on record, and also when it made every id up itself. The reason: a machine that answers
in another's name can hand the panel, when you turn approvals on for it, the challenge of a machine that has
no trust yet, and pass your proven set on to that one. The other machine then holds the id your panel
recorded for the first, and accepts what you later approve "for the first". The only place this shows is two
machines with one id. Until an administrator has found out which is which, neither of the two is protected
by its approvals: treat both as machines without the check.

It also happens in an ordinary way: **a machine made from a copy of another machine's disk**
(a cloned VM, a restored image) has the same trust file and so the same id, and the two then accept each
other's approvals. On the copy, as root / Administrator: `fairy-agent helper-trust set --new-machine-id`
(everything else in the file stays), or `helper-trust clear` and set the trust anew. `helper-trust show`
says the same next to the id. The panel then has to be told the new id (it still has the old one on record).

**What needs an approval** while trust is set:

| Request | Approval | |
| --- | --- | --- |
| `POST /fan/duty`, `POST /fan/mode` | yes | after one approved fan change that the machine applied, further fan changes need none for 30 s (the **fan window**; see settings) |
| `POST /power` with `shutdown`, `reboot`, `sleep` | yes, one each | never the fan window |
| `POST /update` | yes, one each | Windows: see "Updates on Windows" below |
| `POST /power` with `cancel` | no | it only stops something. Windows: answered `503 helper_stopped` while the helper is stopped (see the next row but one) |
| `POST /wol`, `POST /bmc/power` (`on`, `status`) | no | they wake machines; the relay has no "off" |
| `POST /helper/stop`, `/helper/start` | no | the service manager does this, not the helper; stop hands the fans back to the BMC. While the helper is stopped nothing that goes through it runs, and that includes the cancel of a shutdown (`503 helper_stopped`) until `/helper/start` |
| what the agent does by itself (fan watchdog, fans to automatic when it or the helper stops) | no | nobody is there to confirm |

**No trust set = exactly as before.** Without a trust file nothing is checked and every request works as it
always did. `GET /metrics` says `"approval": {"state": "off", ...}`.

### Setting the trust

The trust is four things: Pocket ID's address (issuer), the client id of the Pocket ID client "Fairy PC
actions", Pocket ID's signing key(s), and the users who may approve (their id in Pocket ID, the token's `sub`).
With the first trust the machine also gets its machine id ("Which machine" above): the panel's first-time set
may propose one (the approval that proves the set is made with it, so a proof for one id sets no other), and
when it proposes none, or the trust is set on the machine, the machine makes one up.

* **The first time, from the panel, with a proof that it works.** While a machine has no trust file, the panel
  can set the trust once (`POST /approval/trust`), and only together with a passkey approval that fits the
  very values it proposes: the panel asks the machine for a challenge for "set this trust" (bound to a hash of
  the proposed issuer, client, keys and users), you confirm once at Pocket ID as for any action, and the
  machine checks that token against the proposed values exactly as it will check every approval afterwards.
  Only then does it write the trust file. So a wrong spelling of the issuer, the wrong client id or user id,
  an old key, or a machine whose clock is off, is found out **before** the machine locks: the set is refused
  (`403 proof_refused`, the text says which check failed; without any approval `403 proof_required`), nothing
  is written, and the panel can try again. One confirmation can switch on many machines at once.
  **What this costs: whoever holds the control token first can lock you out.** Without trust, somebody with
  the control token can already send every control request, so the first-time set gives a thief no action
  he did not have. It does give him one thing "off" did not: a stolen control token (or a panel that is
  already taken over) can do the first-time set itself, on a machine that has no trust yet, with an issuer,
  a key or a user of its own. The proof does not stop that: it is checked against the proposed values, and
  the thief proves against his own. From then on **your** approvals are refused on that machine (`403
  approval_refused`) for fan, power and update, and his are accepted, until somebody repairs it **at the
  machine**. Changing the control token does not undo it. The same holds again after every `helper-trust
  clear`, for as long as the machine is left at "off". This was accepted (the owner's decision); it is a
  limit, not "never worse than off", which an earlier version of this guide said.

  The repair, as root / Administrator on the machine, in one sitting:
  `fairy-agent helper-trust set --issuer <yours> --client-id <yours> --user <your id> --fetch-keys --new-machine-id`
  (it replaces the foreign file with your values and the machine is locked to them; `helper-trust clear`
  alone would only open the race again). **`--new-machine-id` belongs to the repair.** Whoever did the
  first-time set also chose the machine id in that file, and `set` keeps the id it finds. He may have chosen
  the id of another machine of yours, and two machines with one id accept each other's approvals ("Which
  machine" above). With a new id that is over. (`helper-trust clear` followed at once by the full `set`
  line gives a new id too.) Your panel still has the old id on record: it must be told to accept the new
  one, and until it has, approvals it builds for this machine are refused here (`403 approval_refused`,
  `nonce`). Then replace the control token, because it was stolen: **Re-pair** in the panel.

  How to notice. `GET /metrics` shows, in the `approval` block, what the machine trusts: `issuer`,
  `client_id`, each key's `thumbprint`, `users` (how many), `trust_hash` (one hash over issuer, client id,
  keys and the user ids themselves: it equals the hash your panel computes for the values it would set, and
  differs if anything differs, also if only the user list does), `set_by` (`panel`: over the network;
  `admin`: on the machine) and `set_at`. A panel compares these with its own. On the machine:
  `helper-status` / `helper-trust show` print the same and the user ids. Look at them after the first set.

  How to avoid the window altogether: set the trust on the machine yourself right after installing (the last
  line of the block below), before the panel's first contact, and never leave a machine at "off" after a
  `clear`.
* **After that, only on the machine.** Once a trust file exists (usable or damaged), every attempt to set,
  change or remove it from the network is refused (`409 already_set`), always, also with a valid approval.
  Another signing key after a key rotation at Pocket ID, other users, the two settings below, switching the
  check off: root / an Administrator on the machine, with `fairy-agent helper-trust`:

```
fairy-agent helper-trust show                         # the trust file and whether it can be used
fairy-agent helper-trust set --fetch-keys             # after a key rotation at Pocket ID: fetch the new key(s)
fairy-agent helper-trust set --fetch-keys --keep-old-keys   # keep the old key pinned next to the new one
fairy-agent helper-trust set --user <id> --user <id>  # who may approve (replaces the list)
fairy-agent helper-trust set --fan-window 0           # no fan window: every fan change needs an approval
fairy-agent helper-trust set --boot-shutdown 600      # see "Settings" below
fairy-agent helper-trust set --new-machine-id         # on a machine made from a copy of another one's disk
fairy-agent helper-trust clear                        # remove it: approval off; the panel can set it again
# everything at once, e.g. right after installing, without the panel:
fairy-agent helper-trust set --issuer https://id.example.org --client-id <client id> --user <id>
```

  `set` starts from the existing file and changes what you give. The machine id stays as it is: `set` makes
  one up only when the file has none, or when you ask (`--new-machine-id`), and never takes one from a file
  given with `--from`. It prints what it will write, with each key's
  thumbprint, and asks before writing (`--yes` does not ask). With `--fetch-keys`, or when there is no key yet,
  it reads the issuer's keys itself over https (`<issuer>/.well-known/openid-configuration`, then the
  `jwks_uri` named there, which must be on the same host; redirects are not followed). `--jwks FILE` takes
  them from a file instead. Compare the thumbprint with Pocket ID's before you answer yes. Whoever checks
  (the helper, the agent) reads the file again every 5 seconds, so a change is in effect within 5 seconds and
  nothing has to be restarted, with one exception that `set` tells you about in its last lines: a helper from
  before passkey approvals that is still running reads no trust file at all (`NOT IN EFFECT IN THE HELPER
  YET`; see "Mixed versions" below).

  **"Within 5 seconds" means: until then the old state still counts**, in both directions. For up to 5
  seconds after the very first `set`, a request without approval still runs. For up to 5 seconds after you
  took a user or a key out of the file, an approval by that user, or signed with that key, is still accepted.
  And for up to 5 seconds after `clear`, requests are still refused. If you are removing somebody because he
  must not approve any more, wait those 5 seconds before you rely on it (or restart the service that checks:
  it reads the file when it starts). When the file's content changes, every open challenge and an open fan
  window are dropped at that moment.

  **`set` on the machine proves nothing.** Unlike the panel's first-time set it needs no approval (you are at
  the machine), so it writes what it is given, and says so (`NOT PROVEN`). If the issuer, the client id or a
  user id is wrong, or the clock is off, the first approval is refused. So approve one action from the panel
  right after a `set`, while you are still at the machine; `helper-trust clear` undoes it. When `set` fetches
  the keys itself it also compares the machine's clock with Pocket ID's and warns when they are more than
  45 s apart.
* **At install time.** The installers take no trust parameters yet. Until they do, a new machine is covered by
  the panel's first-time set at first contact, or by the last line of the block above right after installing.

**The trust file.** `approval-trust.json`. It holds no secret. Windows: `C:\ProgramData\fairy-agent\helper\`
(the helper's folder: only Administrators and SYSTEM change it, the agent's account can read it). The folder
and the file are checked like the helper's other files (owner and access list) every time before the file
counts. The machine id is in this file (`"machine_id"`) and nowhere else, because this is the one file that
only the side that checks can write: on Windows the agent's service cannot change it, and it has no way to
tell the helper another id (the helper reads the file, and takes no id over the pipe).

**A trust file from before machine ids** (written by the test build of 2026-11-11; no release ever wrote
one) has no `"machine_id"`. Nothing is ever checked with such a file. The service that owns the file adds an
id the first time it looks at such a file: `fairy-agent-helper` on Windows, `fairy-agent` elsewhere. That is
when it starts, and also later: a running service looks at the file whenever it is asked something (the
panel's poll, a request), at most every 5 seconds, so a file like that which appears under a running service
(put back from a backup, say) gets its id within seconds as well. It adds that one member and
changes nothing else, the file keeps its owner and mode, and the log says so once (`the trust file had no
machine id ... one was added`). Where it cannot (Linux: the file is root's and the agent does not run as
root; Windows: the helper that runs is not this version), the file stays as it was and the state is `broken`
with the reason: fan, power and update requests are refused until `fairy-agent helper-trust set` is run on
the machine (it keeps the file's values and writes it with an id) or the right service starts.
`helper-trust show` only looks: it never adds the id itself.

On Linux "cannot" is decided by looking, not by trying. The agent compares the file's owner and group with
its own before it writes anything. Its own file (the one it wrote at the panel's first-time set) gets the id.
A file of another owner or group (root's, after `helper-trust set` as root) is left alone: no temporary file
is made, and the agent does not ask the system to change an owner, because under the unit's system call
filter (`SystemCallFilter=~@privileged` in `fairy-agent.service`) that request would not be answered with
"no": it would end the agent, at every start. The reason then reads `the trust file belongs to user 0,
group N, but this service is user N, group N: only root can keep the owner`.

**Linux: whose file it is.** `/var/lib/fairy-agent/approval-trust.json`, in the agent's state folder, because
the agent itself writes it at the first-time set. That folder belongs to the agent's service user
(`fairy-agent`, mode 0700; `root` when the agent runs as root), and whoever owns a folder can replace any file
in it. So on Linux the trust file is the service user's, whatever its own owner says, and that is honest: the
agent process is the checker there anyway. What is checked before the file counts: the folder and the file
belong to root or to the agent's own user, nobody else can write them, and the file is a plain file with one
name. A folder that fails this (group-writable, another owner) is `broken` even with no trust file in it,
and fan, power and update requests are then refused until the folder is put right
(`chown fairy-agent:fairy-agent /var/lib/fairy-agent; chmod 0700 /var/lib/fairy-agent`). A set from the panel
is refused in that state like on every machine that is not "off" (`409 already_set`); its text then says
`this machine has no trust file, and none can be set from the network: the folder of the trust file is not
safe: ...`, not that there is a file. (Without the folder at all the state is "off": there is no file. A set
from the panel then fails with `the folder of the trust file does not exist`; a standard install has the
folder.)
`fairy-agent helper-trust` is root's command (`sudo`). In the agent's folder it does its file work as the
agent's user, not as root: `show` tells you what the running agent sees (and says `checked as: uid N`),
`set` and `clear` work on the file the panel's first-time set left there, and the file `set` writes is again
the service user's, mode 0600. A local user who is neither root nor `fairy-agent` can neither read nor change
anything (the folder is 0700).

**A damaged trust file never means "off".** If the file is there but cannot be used (not valid, wrong owner
or permissions, a link, a folder others can write), the state is `broken` and every request that would need an
approval is refused (`503 approval_unavailable`) until an administrator repairs it (`helper-trust show` says
what is wrong; `helper-trust set` or `clear` fixes it). Only removing the file switches the check off, and
only root / Administrators (Linux: or the agent's own user) can remove it.

### Settings (in the trust file, changed only on the machine)

* `fan_window_s` (default 30, 0 = off, at most 60): after one approved fan change **that was applied**, the
  machine accepts further fan changes without a new approval for this many seconds, by its own clock, counted
  from the moment it accepted that approval. An approved fan request that the machine then refuses (a duty
  below the minimum, a mode the board does not have) or that changes nothing (a duty while the mode is not
  `full`, a duty below 100 % while the CPU is too hot) opens no window: the next fan request needs an approval
  again. Fan requests inside the window do not make it longer. Power and update never use it.
* `boot_shutdown_s` (default 0 = off, at most 900): the machine accepts **one** shutdown (not reboot, not
  sleep) without approval while it has been up for less than this many seconds. For machines that are switched
  on only to be updated and switched off again. Each use is written to the log as
  `UNAPPROVED shutdown accepted shortly after boot`. The request may ask for a delay of at most 600 s (it is
  for "switch off again now", not for a shutdown that happens a day later). "One" is one per boot: the use is
  recorded next to the trust file (`approval-boot-shutdown.json`), so restarting the helper / agent inside the
  window gives no second one. It is recorded when the shutdown is really scheduled: a request that the machine
  refuses (a delay under `min_delay_s`, another action already pending) does not use it up. Linux tells boots apart by the kernel's boot id. In an LXC container that id is the host's while the uptime is the container's, so there (read from the code, not run in a container) the one shutdown is one per boot of the HOST, not per start of the container: after the first, a restarted container gets none until the host reboots. It fails closed. Windows has none; there the
  record counts for the current boot unless it was made clearly before Windows started, by the clock (after a
  clock that jumped forward by more than the uptime, or sleep inside the window, one more could be accepted).
  If the record cannot be read or written, no shutdown is accepted without approval. Windows: "up" is the time
  since Windows started (GetTickCount64); after a shutdown with Fast Startup that clock does not start at
  zero, so the setting then does not apply (every shutdown needs an approval). Only what the helper carries
  out can use it on Windows.

### How one approval works

1. The panel asks the machine for a **challenge** for one exact request (`POST /approval/challenge`, e.g.
   shutdown in 60 s). The machine answers with 32 random bytes and remembers them with that request: single
   use, 180 s (an update: 900 s, on every system: on Windows the download lies between the approval and
   the helper's check, and everywhere a panel that updates several machines with one confirmation needs the
   time), at most 16 open at a time. When 16 are open and one more is asked for: if
   the oldest is at least 90 s old it is dropped for the new one (the log names it); if not, the new request
   is refused (`429 too_many_challenges`; the `Retry-After` header, `"retry_after_s"` and the text say in how
   many seconds to ask again). So a challenge
   that somebody is confirming at Pocket ID cannot be pushed out for its first 90 s by a burst of requests
   for others, and one burst cannot keep the list shut for longer than 90 s. A panel asks for
   one challenge per machine and action and uses it within seconds; it does not meet this. (What whoever
   holds the control token can still do, for as long as he keeps asking: sixteen challenge requests every
   90 s keep the list full, and one more request than the budget allows in every minute keeps the budget
   used up, so nobody else gets a challenge while he goes on. Once he stops, the list has room again after
   at most 90 s and the budget after at most 60 s. On Windows he can also drop the challenge of an update
   whose download takes longer than 90 s. All of this stops approvals; none of it lets anything through.)
2. The panel sends the browser to Pocket ID once, as the client "Fairy PC actions", with a nonce made from the
   challenge, the request and the id of the machine it is for (the id the panel has on record for the machine
   you chose, not one that came with the challenge). Pocket ID asks for the passkey and signs an ID token with
   that nonce.
3. The panel sends the request with the token attached. The machine first runs the request's own checks: is
   the delay allowed, is another action pending, can this machine sleep, are the fans in a mode that takes a
   duty, can an update be started. A request that fails one of them is refused for that reason and **costs
   nothing**: the approval is not looked at and stays good for the rest of its 180 s. (For an update on
   Linux, "can an update be started" is all that is known at that point: the approval is used up before the
   agent has asked the release server, so an update that then ends with "already up to date", inside the
   pause after the last one, or with a failed download has cost its approval. On Windows the helper uses it
   up after the download.) Then, immediately before
   it acts, the machine checks: the token's signature with the pinned key (RS256), issuer, that it was issued
   for this client only, the user is one of the allowed ones, it is not expired, the passkey check
   (`auth_time`) is not older than the challenge, it was a passkey sign-in, the nonce fits (the machine makes
   it from its own open challenge, the request it is about to run and its own machine id), and its own
   remembered request equals the request it is about to run. Then it uses the challenge up and runs the
   request. From that moment the approval is spent, also when the action then fails (the BMC does not answer,
   the system refuses the shutdown). A second use, another action, another machine: refused.

   Whoever checks answers a request that carries no approval at all (and needs one) with
   `403 approval_required` before any of those checks, and a broken trust file with
   `503 approval_unavailable`, as before. So nothing changed for a request without approval.

   Who does this on Windows: the agent runs its own checks (delay against `min_delay_s`, an action already
   pending, the fan duty's range) and passes the request with its approval on. The **helper** answers a
   request without approval `403 approval_required`, runs its checks (its own `min_delay_s`, sleep, the fan
   mode, the temperature), and only then verifies the token and uses the challenge up, immediately before the
   system call or the BMC command. The agent never uses anything up for what the helper carries out. For an
   update the helper does it when it is asked to start the installer, after the download.

One token can cover several machines and requests (one entry each, with that machine's id); every machine
finds its own entry. The exact formats are in `pkg/agent/api/approval.go`.

**Clock.** The machine's clock must be within 60 s of Pocket ID's. If it is further off, approvals are refused
(the answer says `clock` or `auth_time`); nothing is ever accepted because of a wrong clock. Fix:
`w32tm /resync` (Windows), `timedatectl` (Linux). The panel's first-time set finds a wrong clock before the
machine locks (its proof is refused with `clock`).

**What "fresh passkey check" means exactly.** The machine checks that your last authentication at Pocket ID
(`auth_time`) is not more than 60 s older than the moment it gave the challenge. The 60 s are there because
the two times come from two clocks. This shows that you authenticated around the time of the request; it does
not show that the passkey was touched *for* this request. That part is Pocket ID's: keep **Requires
Re-Authentication** switched ON for the client "Fairy PC actions". With it on, Pocket ID asks for the passkey
at every approval. If it were off, a taken-over panel could get a token without any click right after you
signed in to anything at Pocket ID. The machine cannot see that switch.

**The log.** Every accepted and every refused approval is one line: the request, accepted or refused and why,
the user (`sub`), the key id and the first 8 characters of the challenge. Never the token. Windows:
`C:\ProgramData\fairy-agent\helper\helper.log`. Linux: the agent's log (`journalctl -u fairy-agent`).

**What the panel sees.** `GET /metrics` has `"approval": {"state": "off" | "required" | "broken" | "unknown",
"enforced_by": "helper" | "agent", "proto": 2, "machine_id": ..., "issuer": ..., "client_id": ..., "keys": [{"kid", "alg",
"thumbprint"}], "users": <how many>, "trust_hash": ..., "set_by": "panel" | "admin", "set_at": ...,
"fan_window_s": ..., "boot_shutdown_s": ..., "error": ...}`. No user ids
and no keys, only how many users, each key's thumbprint, and `trust_hash`: the hash of issuer, client id, keys
and users that the panel computes for a first-time set (`pkg/agent/api`: `TrustHash`), so a panel can tell
whether a machine trusts exactly what it would set, without the user ids being sent. `machine_id`: this
machine's id ("Which machine" above); the panel keeps it on record and uses the one on record. `proto` is 2
since approvals name the machine (1 was the test build of 2026-11-11, whose approvals this version refuses).
`unknown`: the Windows helper is not answering, or
the helper that is running is from before passkey approvals while this machine has a trust file ("Mixed
versions" below); either way nothing that would go through the helper and need an approval runs.
`"agent_checks": [...]` (Windows): the requests the agent carries out and checks itself; `"agent_error"`: why
it cannot (those are then refused; only while the helper answers and says there is no trust file do they run
as they do without trust). No `approval` block: an agent from before this, or Windows without the
helper and without a trust file. Refusals: `403 approval_required` (none sent), `403 approval_refused` (sent,
not accepted; the text says why), `503 approval_unavailable` (broken trust file, or nothing that could check
is reachable), `429 too_many_challenges` (for a challenge: 16 are open and none is 90 s old yet). For the
first-time set: `403 proof_required`, `403 proof_refused`, `409 already_set`.

**Updates on Windows.** The Windows agent starts the updater service with its own right, which the helper
never sees. So while the helper's check is on, the agent refuses `POST /update` without an approval itself,
and with one it lets the **helper** start the installer, which checks the approval then (after the download;
that is why an update's challenge lives 900 s). A refusal at that point shows as a failed update
(`starting the installer: helper: approval refused ...`), and what was downloaded for it is removed again.
Before it downloads anything, the agent looks at the approval itself, with its own read-only look at the
helper's trust file, and uses nothing up: the list of entries, an entry for the update, the token's
signature against the pinned keys, issuer, client, user, passkey, the times, and the nonce with this
machine's id. An approval that fails this is refused at once with `403 approval_refused` and the reason, as on
Linux, and nothing is downloaded; so a request with a made-up `approval` no longer makes the machine fetch
the release, and no longer stands in the way of yours (`409`) while it does. What the agent cannot see is the
challenge (the helper gave it): an approval that was real and is used up or too old for its challenge passes
the look, is downloaded for and is then refused by the helper as before. Where the agent's account cannot
read the trust file, there is no look and everything is as before. The helper alone accepts an approval.
The agent finds the state out when the request arrives: it asks the helper at that moment, and when the
helper does not answer (stopped, starting, the PC has just booted) it looks at the trust file itself. Only
"there is no trust file" lets an update through without approval. A helper that cannot be reached while a
trust file exists means `503 approval_unavailable` and nothing is downloaded: start the helper first. This is
the agent keeping to the rule: an agent process that was taken over can still start the updater service
directly. That service installs only a newer release signed with the release key, nothing else.

**The Windows repair and the trust file.** `install` / `setup-self-update` move anything in the data folder
that somebody else could have written out of the way (`untrusted-<time>\`). If that is the trust file, approval
is off afterwards; the repair says so in capital letters (`ATTENTION`) and names the command that switches it
back on. For a trust file that is merely damaged, use `helper-trust set` or `clear`, not the repair.

**Not solved by this.** Pocket ID's page shows the name "Fairy PC actions", not the action. A taken-over panel
can ask you to approve one action while it shows another. What the machine guarantees is: the action it runs
is the one the challenge was issued for, approved once, by an allowed user, with a fresh passkey check. Look at
which machine and action you started before you touch the passkey for an unexpected Pocket ID page.

**Mixed versions.** An agent or helper from before this ignores an approval and checks nothing, as before. A
new helper with trust set refuses the four kinds of request from an older agent (nothing runs unapproved).

**An old helper behind a new agent** (Windows: the helper that is *running* is still the program from before
passkey approvals, because an update did not restart it; `fairy-agent helper-status` then shows no
`pipe protocol:   3`). That helper reads no trust file and would carry out whatever it is sent. So the agent
looks at the trust file itself, at the moment a request arrives:

* **No trust file:** nothing is checked and nothing asks for it, as before. No `approval` block; the two
  approval routes answer `409 helper_too_old`; fan, power and update requests work as they always did.
* **A trust file (or a broken one, or the agent cannot tell):** the agent refuses every fan, power and update
  request that would go through that helper, with or without an approval: `503 approval_unavailable`, and the
  text names the repair. Nothing reaches the old helper. `GET /metrics` says
  `"approval": {"state": "unknown", "enforced_by": "helper", "error": "the running fairy-agent-helper is older
  than this agent ..."}`: it does **not** say `required`, because nothing can enforce it at that moment.
  `POST /power` with `cancel`, wake and the BMC power-on relay work as always; what the agent carries out
  itself (`agent_checks`) it goes on checking itself. The two approval routes answer `409 helper_too_old`.
  Repair: restart the helper (`Restart-Service fairy-agent-helper`, or from the panel: stop the helper, then
  start it). What starts is the new program, and it checks.
* `fairy-agent helper-trust set` typed in this state says so (`NOT IN EFFECT IN THE HELPER YET`) instead of
  "in effect within 5 seconds".

The same refusal holds while no helper has answered at all since the agent started and a trust file exists:
the agent does not hand a request that needs an approval to a helper it has not seen yet.

**The test build of 2026-11-11** (pipe protocol 2, never released) counts as "from before" in every respect.
Its helper checks approvals without a machine id, so an agent of this version does not rely on it and hands
it nothing that needs an approval (`503 approval_unavailable`, `409 helper_too_old`, the block `unknown`,
exactly as above); `helper-status` says `pipe protocol:   2 (the test build of 2026-11-11; this agent needs
3)`. The other way round, this version's helper refuses that build's agent (its requests are marked
protocol 2). Restarting does not help there, because the installed program is the old one: **install this
version of both services** (the installer replaces and restarts both). The trust file that build left gets
its machine id when this version's helper starts ("A trust file from before machine ids" above), and the
panel then takes the id on record.

**Going back to an older agent switches the check OFF.** A release from before passkey approvals does not know
the trust file: put back on a machine that has one (`fairy-agent update --force` to an older release, an old
installer run by hand, a restored backup of the program), it starts as always, leaves
`approval-trust.json` where it is, sends no `approval` block, answers the two approval routes `404 not
found`, and carries out fan, power and update requests with the control token alone, as it did before. Nothing
on the machine warns about it. Upgrade again and the check is back exactly as it was, with the same trust.
On Windows this is so when both services run the old program (the installer replaces and restarts both); an
old agent in front of a **new** helper is still refused by that helper. Who can do this: only root / an
Administrator on the machine. The panel's Update button never installs an older release, and a failed update
goes back to the program that was running before it, which is this one or a newer one once the trust was
set with it. What to do: do not go back on a machine with a trust file unless you mean to switch the check
off; and a panel should treat a machine whose `approval` block was there and is gone as an alarm, not as
"an agent without the feature".

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

**The rules of an update (0.6.0).**

* **Versions carry a build number.** A release's version is `<build number>-<short commit>`, for example
  `42-1a2b3c4`. `fairy-agent version` shows it. "Newer" and "older" are decided by the build number alone. A release whose version does not start with a build number (or has one
  of more than nine digits) cannot be compared, so it is refused: by the agent before it downloads anything,
  and again by the installer.
* **Never older, never the same again.** A request from the panel never installs an older release and never
  reinstalls the running one: the agent answers "already up to date" or refuses. A `force` in the request is
  ignored. Only root / an administrator at the machine can do either: `fairy-agent update --force`.
* **Ten minutes between two updates.** After an installer run that replaced the program, another run asked
  for through the panel is refused for 10 minutes. The panel shows that run as failed with the reason ("an
  update was installed on this machine less than 10 minutes ago; refused, try again in ..."). Without this,
  whoever holds the control token could keep a machine restarting. The installer keeps the time itself, in a
  file the agent's account cannot write: `/var/lib/fairy-agent-update/last-apply` (Linux),
  `C:\ProgramData\fairy-agent\update\last-apply` (Windows). `fairy-agent update` typed at the machine is not
  held back. The pause starts with the first update that 0.6.0's own installer runs: the update *to* 0.6.0 is
  still run by the old installer.
* **The check after the swap sends no token.** The installer asks the agent's new `GET /health` with a random
  value and its own proof. The answer proves that the agent on that port holds this machine's read token and
  runs the new version, without the token or the version going over the wire. A program that only sits on the
  agent's port cannot pass. `/health` answers only the update's own check on the machine itself, which first
  proves that it holds the read token. Every other request gets `404 {"error":"not found"}`, like any unknown
  path. (The update *to* 0.6.0 is checked the old way, by the old installer.)
* **A port held by another program.** If another program is listening on the agent's port, the agent no
  longer waits silently: after five tries it ends with `another program is listening on the agent's port`,
  and the service manager shows the failure and starts it again later.
* **What a failed update reports.** When the new version does not come up, the installer puts the old
  program back, starts it and checks that it answers. The report then ends with `rolled back to the previous
  version`: the machine runs the old version and is fine. Only when the old version does not come up either
  does it say `rolling back FAILED too`: then look at the machine. There is a third ending, `the previous
  version was put back and started again, but ...`: the old program was restored and started, but its check
  could not be completed. Look at the machine; it is very likely running the old version. (Up to 0.5.3 a
  clean rollback was reported as a failed one.)

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
  Updates never go to an older release through the panel, not even with force: by hand only, with
  `fairy-agent update --force` as root / Administrator (see "The rules of an update" above). Going back by
  hand to a release from before passkey approvals switches the approval check off on that machine, trust
  file or not (see "Mixed versions" in the passkey section).

The very first program with self-update has to be installed by hand once per machine;
[SETUP-UPDATES.md](SETUP-UPDATES.md) has the exact commands. `self_update.repo` can point at a fork (its
releases must still carry the owner's signature).

**Undo by hand**: Linux `mv /usr/local/bin/fairy-agent.old /usr/local/bin/fairy-agent && systemctl restart
fairy-agent`; Windows `Stop-Service fairy-agent, fairy-agent-helper` (the helper only if it is installed: it
runs the same program), rename the current `fairy-agent.exe` away, rename `fairy-agent.exe.old` to
`fairy-agent.exe`, `Start-Service fairy-agent-helper, fairy-agent`.

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
| Processes | all; command lines only with `processes.cmdline: true` (a filter blanks the secrets it recognises: best effort). With command lines off, the name is not taken from the command line at all: it is the name of the program's file where the agent may see it, otherwise the 15 characters the kernel keeps of it (as `top` shows it). With command lines on, a name longer than 15 characters is completed from the program's title, and a title of an unusual shape can leave argument text in it (see [Security in short](#security-in-short)) | all names; details for programs it may open; the program's path instead of its command line; per-program dedicated GPU memory for every card (Windows' "GPU Process Memory" counter, like Task Manager) |

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
same names in the signed-in user's session (the helper does the looking). Since 0.6.0 a session name is used
only when its shared-memory object belongs to Administrators or SYSTEM. If it belongs to another account, the
readings are not used, and `agent.log` names the object, its owner and the fix: switch on **Enable global
shared memory (SNMP)** (step 2 above). With that option on, nothing changes for you. Core Temp has no CPU package *temperature* in its shared block, so
only the cores are shown. Core Temp's Fahrenheit and "distance to Tj. Max" display options are converted back to
°C. Package watts appear only when Core Temp shows a "Power" value for your CPU.

## Settings (config.yaml)

The file is `C:\ProgramData\fairy-agent\config.yaml` (Windows) or `/etc/fairy-agent/config.yaml` (Linux).
`deploy/fairy-agent.config.example.yaml` lists every setting with an explanation. The important ones:

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | the Tailscale address, port 9101 | where the panel connects; `0.0.0.0` is refused unless `allow_all_interfaces: true` |
| `only_from_panel` | false | `true`: connections are accepted only from the panel that added this machine (Add host) and from this machine itself. Your own `curl` from another machine then gets no answer, and a new panel address needs a new Add host / Re-pair. An agent with no panel on record (never added with Add host, or its last join code expired) then refuses every other machine, until the Add host / Re-pair command has run on it; the log says so once a minute |
| `require_helper_pipe_owner` | false | Windows only. The agent knows its helper service by the helper's process id. It also looks at who owns the helper's pipe: a pipe the helper made belongs to Administrators or SYSTEM. In this release another owner is only reported, once, as a warning in `agent.log` (the pipe is still used); `true` makes the agent refuse such a pipe. Leave it off until the check in TEST-ON-WINDOWS.md (section 12, step 16) has shown `S-1-5-32-544` or `S-1-5-18` on your PCs: with a wrong owner and `true` the agent could not reach its helper (no fan control, Core Temp or power actions). Restart the agent after a change |
| `token_file`, `control_token_file` | `token`, `control-token` next to config.yaml | the tokens (at least 24 characters, different from each other). A token you write yourself must be **long and random**: `fairy-agent gen-token` prints one (32 random bytes). The agent checks only the length, so it also takes 24 times the letter `a`; and nothing slows down somebody who tries tokens (a wrong one is refused at once and the right one is served, from any address, however many wrong ones came before), so a token that can be guessed will be. At its start the agent writes one warning into its log when a token has fewer than 10 different characters. `FAIRY_AGENT_TOKEN` / `FAIRY_AGENT_CONTROL_TOKEN` in the environment win. Never on the command line. |
| `hide_host_details` | false | no hostname, no hardware model, just "Windows" / "Linux". It does not shorten the `approval` block of `/metrics`: whoever holds the read token still sees the Pocket ID address (`issuer`), the client id, this machine's `machine_id`, each key's id and thumbprint, how many users, `trust_hash`, `set_by` / `set_at`, `fan_window_s` and `boot_shutdown_s`, and for a broken trust file the reason with the file's path. The panel needs those to check whose trust a machine has; none of them is a secret, and none lets a request through |
| `processes.enabled` / `cmdline` / `never_open` | true / true / none | the Processes tab. `cmdline` sends command lines (Linux) or program paths (Windows). A config file without the line means `true`. Since 0.6.0 a new Linux install writes `cmdline: false`; an existing `config.yaml` keeps what it says |
| `gpu.nvidia_smi` | auto | `off` or a full local path (only administrators / root may be able to change the file and its folders) |
| `gpu.amdgpu` | auto | Linux: AMD GPUs through the amdgpu driver's sysfs files; `off` to switch off |
| `gpu.windows` | auto | Windows: AMD / Intel / other GPUs from Windows' GPU counters; `off` to switch off |
| `gpu.amd_adl` | auto | Windows: Radeon temperature and watts from AMD's ADL (Adrenalin driver), read only; `off` to switch off |
| `sensors.coretemp` | false | Windows: CPU core temperatures and watts from Core Temp (see [Core Temp](#core-temp-optional-windows)) |
| `ipmi`, `fan_control`, `power_control`, `wol`, `bmc_relay` | off | see [Optional features](#optional-features) |
| `env_file` | none | `KEY=value` secrets (device and BMC passwords); `fairy-agent secret set NAME` writes it |
| `self_update.enabled`, `self_update.repo` | off, `n3ptune-cpu/Fairy-agent` | see [Updates](#updates-the-panels-update-button) |
| `control_rate_per_min` | 12 | requests a minute, for everybody together, in each of three budgets that cannot use each other up: **control requests** (fan, power other than cancel, Wake-on-LAN, BMC relay, update, helper stop / start, the first-time set of the approval trust), all together; **approval challenges** (`POST /approval/challenge`), so an approved action costs one control request and one challenge, not two control requests; and **`POST /power` with `cancel`**, so that neither a burst of challenges nor a row of refused requests can keep a cancel out (only other cancels with the control token can, and on Windows a `POST /helper/stop`, which also needs the control token: a cancel is answered `503 helper_stopped` until the helper is started again; requests with a wrong token or none count against nobody but themselves, see [Security in short](#security-in-short)). One more is answered `429` (`Retry-After: 60`); the text says which budget |
| `log_file` | Windows: `C:\ProgramData\fairy-agent\logs\agent.log` (5 MB, one old copy); Linux: the journal | |

Unknown settings are an error (so a typo does not silently do nothing). `fairy-agent check-config` checks the
file and the tokens without starting anything. The one thing from an earlier version that is ignored instead, with
a line in the log and in `check-config`, is a `power_sources` entry with `type: tuya`
(see [Plugs and UPSes on this machine's network](#plugs-and-upses-on-this-machines-network)).

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
* Every request needs a token, with two exceptions that give nothing away:
  * `POST /pair` answers only while a one-time join code from the panel's Add host is waiting (15 minutes; the
    code itself is never stored), only to the panel's address and only to a JSON request. It hands out the
    tokens once and is closed for good after that, or after 10 wrong codes. The panel's address has its own
    budget of 5 requests a minute. Requests from other addresses are refused, are counted separately (5 a
    minute each, 20 a minute together) and cannot use up the panel's budget or the 10 tries. With pairing v2
    the panel must prove it has the code, and the answer is encrypted
    (see [Add a host](#add-a-host-from-the-panel-one-command)).
  * `GET /health` is what the update installer asks after a swap. It answers only the update's own check on
    the machine itself, which first proves that it holds the read token. Every other request gets
    `404 {"error":"not found"}`, like any unknown path. The answer contains neither the token nor the version,
    and another machine gets nothing to test a guessed token against. A program on the machine itself can try
    guesses of the read token there, because only the right one is answered. Each try costs it a slow
    computation, and a token made by `fairy-agent join` or `gen-token` cannot be guessed; a token you chose
    yourself should be long and random. A wrong try is written to the agent's log (at most one line a minute).
    Wrong tries are logged but not limited: the update's own check comes the same way and cannot always be
    told from another local program's tries, so a limit would let any program on the machine make updates
    fail with a few wrong tries.
* The join code is never an argument of a program: the install scripts and `fairy-agent join` take it from
  standard input or from the environment, and never print it. The old form with the code as an argument
  (`--join CODE`, `-Join CODE`, `fairy-agent join --code CODE`) is still accepted, prints a deprecation line
  without the code, and will be removed in a later release.
* Tokens are compared in a way that does not leak their length or content through
  timing. Reading uses one token, changing anything needs the second, separate one (the read token on a
  control route is a wrong token, and the other way round).
* After 20 requests with a wrong token or none from one address within a minute, further such requests from
  that address are answered `429 too many failed requests` until the minute is over. A request with the
  right token is always served, from that address too, and never counted. So somebody who shares the panel's
  address (another user or a container on the panel's host, a machine behind the same NAT) cannot keep the
  panel out with wrong tokens: its polls, its challenges and the cancel of a shutdown get through. (Until
  this version the 429 was for every request of the address, the panel's included.) What this does not do
  is slow down guessing: a wrong token is told from a right one at any rate. What keeps a token from being
  guessed is its length alone. The tokens the agent makes (`fairy-agent join`, the installers) are 32 random bytes (43 characters,
  256 bits); one you set by hand must have at least 24 characters, and must be as random as those.
* **A limit: a program on the machine can take the agent's port while the agent is not running, and is then
  sent the tokens.** The agent listens on an ordinary port (9101) that any local user may open. While the
  agent is down (a restart, the moment an update swaps the program, a crash, the time at boot before it is
  up) another program on the same machine can listen on that address and port. The panel cannot tell who
  answers: its next poll carries the read token and its next control request the control token, in the
  `Authorization` header, to that program. And while that program holds the port the agent cannot start
  (`another program is listening on the agent's port`, see [Updates](#updates-the-panels-update-button)).
  Nothing in this version prevents it; only the update's own health check was made safe against it (it sends
  no token). So a user account on a machine with an agent is, for this purpose, somebody who can get that
  machine's tokens. With the control token he can send every control request to a machine that has no
  approval trust (shut it down, set its fans, start an update). With a trust set he can send what needs no
  approval: cancel, Wake-on-LAN, the BMC relay's power-on, stopping and starting the helper, fan changes
  while a fan window is open, and the first-time set of the trust after a `helper-trust clear`. If the agent's log shows that line, or a machine is "offline" in
  the panel while it is up, look at what holds the port (`ss -ltnp`, on Windows `netstat -abno`), and
  replace both tokens (**Re-pair**) after such a program was found. Windows opens the port for exclusive
  use, which helps only while the agent runs.
* Read-only unless you switch features on; each control action is rate limited and logged with who asked.
* With an approval trust set, fan changes, shutdown / reboot / sleep and updates run only with a fresh passkey
  confirmation at Pocket ID that the machine verifies itself, offline (Windows: the helper; Linux: the agent).
  The trust can be set once from the panel and is changed only on the machine afterwards. See
  [Passkey approval](#passkey-approval-of-fan-power-and-update-requests-pocket-id).
* Self-update installs only releases signed with the owner's key (checked twice: by the agent and by the
  installer, which never trusts the downloaded copy), only files fetched over HTTPS from GitHub, never an older
  version, and only when an admin asks for it.
* Command lines (Linux) are sent only with `processes.cmdline: true`, which new installs switch off. When
  they are sent, a filter blanks the passwords and tokens it recognises before they leave the machine (and
  again in the panel). The filter is best effort: it cannot know every way a program takes a secret.
  Command lines are off only for installs made with this release or later; an existing agent keeps sending
  them, filtered, until `fairy-agent config set processes.cmdline false` and a restart. With them off, the
  agent does not open any process's command line, so no argument of any process is sent. A process's name
  then comes from two things the kernel keeps: its own name of the process (the program's file name, cut at
  15 characters; a program can give itself another one of that length) and, where the agent may read it, the
  link to the program's file, from which a name that was cut is completed. The agent may read that link for
  processes of its own user only, so most programs with a long name show the first 15 characters, as `top`
  does. (Until this version a long name was completed from the program's title, also with command lines
  off, and a title of an unusual shape, such as `some-long-program-name--token=...` with nothing between
  name and argument, was sent whole as the name.) With command lines **on**, the name is still completed
  from the title, up to the first space, tab or line end. Argument text that follows the name without one of
  those (no separator at all, a no-break space, or a name that first appears inside an argument) then stays
  in the name, where the secret filter does not look. That takes a program name of 15 characters or more and
  such a title; if it matters to you, switch command lines off.
* The BMC relay reaches private addresses only, passes the BMC password to ipmitool only through its
  environment, sends a Redfish login only to the certificate named in `tls_fingerprint`, and never logs
  passwords.
* At most 64 connections are open at a time. A stranger's address gets 8. The panel's address gets 32, and
  when those are busy up to 128 more of its connections wait up to 3 seconds for a free one instead of being
  reset. 16 of the 64 are kept for the panel and this machine, 4 of those for this machine alone. So a flood
  from another device cannot lock the panel out or exhaust the agent's memory. Programs on the machine itself
  share 8 connections, and any of them can fill those. So on Linux the update's health check, which root runs,
  connects from a port below 1024 (one of 512 to 1023 that no well-known service listens on), and connections
  from this machine that come from such a port have 4 more slots of their own. Only root, or a program that
  was given the right to use such ports (`CAP_NET_BIND_SERVICE`), can connect from one. So a program on the
  machine without that right can no longer use the agent's own connection limits to keep the check out, which
  a few open connections used to do. This does not make the check safe from every local program. What is left:
  * Before a connection reaches the agent it waits in the system's queue for the port, and that queue is one
    for all senders. A program that opens connections as fast as the machine allows (hundreds of thousands a
    second, every processor core busy for as long as the update runs) can keep the queue full, and then the
    check fails whatever port it comes from.
  * A program that has the right to use ports below 1024 can fill the 4 slots.
  * Where root itself cannot use those ports (a container without `CAP_NET_BIND_SERVICE`, a firewall that
    drops packets from them), the check comes from an ordinary port and shares the 8 connections as before.
  * There are no such slots on a machine where `net.ipv4.ip_unprivileged_port_start` was lowered below 1024,
    and none on Windows, which has no ports reserved for administrators: there a local program that keeps
    opening connections to the agent can make the check fail as before.
  * The first update to this version is still checked by the old installer, from an ordinary port.

  In each of these cases the update is rolled back, the version that ran before keeps running, and nothing
  else is harmed. An agent set up by hand (tokens written into the files, never added through Add
  host) has no panel address on record. There an address that has shown a valid token counts as the panel for
  an hour after its last request. Until the panel's first request with the token got through (after the agent
  was restarted, or after an hour without a request from the panel) the panel is a stranger there like any
  other device, and devices that hold all 48 connections strangers may have with unfinished requests (six
  addresses are enough) can keep it out for as long as they do so. An agent added through Add host has the
  panel's address on record and is not affected. The process list is read at most once
  a second however many ask. When more than 16 requests are waiting for it the agent answers `503` with code
  `busy` and `Retry-After: 1`. A request's header must arrive within 2 seconds and may have about 8 KiB at
  most: the limit the agent sets is 4096 bytes, and the HTTP server it is built on allows 4096 more for its
  own reading (measured: a request whose header has 8192 bytes in all is answered, one with 8200 gets
  `431`). The panel's is a few hundred bytes. With
  `only_from_panel: true` nobody but the panel and this machine gets a connection at all.
* A response header from a device, a BMC, an agent or the release server may be at most 64 KiB.
* Time limits on every connection; requests are small and bounded. What a UPS server (NUT) sends is bounded too
  (4 KiB per line, 1 MiB per poll, 64 UPSes), so one broken or hostile upsd cannot exhaust memory. (One such
  answer can cost the agent about 15 MiB for a moment, so about ten hostile upsd entries at once still can.
  The limits of plug and BMC answers, 256 KiB each, do not apply to NUT.)
* The log cannot fill the disk: the log file is rotated at 5 MB (one old file kept), and the same message is
  written at most 30 times a minute (the rest are counted: `suppressed=N` on the next one).
* Windows: the agent runs as its own virtual account with a single privilege; what needs more goes through the
  helper service, which has no network, admits only the agent's account on its local pipe (checked twice), and
  answers twelve fixed requests with strict limits. Settings folder readable only by administrators, SYSTEM and the service; the program lives in
  `C:\Program Files` and only administrators / SYSTEM can change it (self-update goes through the separate
  LocalSystem updater service, which checks the signature itself). The install scripts check the program's
  SHA-256 against the signed SHA256SUMS before running it as Administrator. Helper programs (ipmitool,
  nvidia-smi) are only run from places only administrators can change. Since 0.6.0 the installer, the
  helper and the updater service first check that the data folder can be changed by administrators and SYSTEM
  only, and refuse it otherwise (see
  [Running the installer again](#running-the-installer-again-060-what-is-kept-what-is-moved-aside)).
* Linux: own user, no root, no capabilities, systemd sandbox (check that it is still on:
  [Check your Linux agents](#check-your-linux-agents-are-the-sandbox-lines-still-on)). One polkit rule per
  feature. With fan control, a fixed fan speed never outlives the agent.

## Not yet tested on a real Windows PC

The Windows parts compile and their pure logic is unit-tested, but were not yet run on real Windows. Check these
on the first install and report anything odd:

* the BMC power-on relay (ipmitool through `-E`, Redfish) against a real BMC, and `fairy-agent secret set`'s
  Windows ACL with the installed service;
* the service itself: install / start / stop / uninstall, the folder permissions, the log file, the Event Log
  entry on a failed start, automatic restart;
* CPU %, memory, disks, network counters, uptime, OS name and hardware strings (registry);
* ACPI thermal-zone temperatures (PDH);
* **the passkey approval** (TEST-ON-WINDOWS.md, section 13). Run on a Windows 11 test VM on 2026-11-11 with
  the first version of this code, and found to work then: the helper with the check, the pipe as it was then
  (version 2 frames), `helper-trust set / show / clear` as Administrator with keys fetched from a real
  Pocket ID, the trust file's permissions, the file the helper wrote itself (hard link, inherited
  permissions) passing the helper's own check, a damaged file refusing, `helper-status`. **Not yet run on
  Windows:** everything that changed after that run.
  * From the first review: the first-time set that needs a proof (the refusal without one is step 26 of
    section 13; the accepted path needs the panel), the agent's own check next to the helper (fans over
    `ipmitool`; the agent's account reading and checking `helper\`), `POST /update` while the helper is
    stopped, the record of the shutdown after boot.
  * From the fifth audit (section 13, G): an agent of this version in front of a running helper from before
    approvals (`503 approval_unavailable`, `helper-trust set` saying `NOT IN EFFECT IN THE HELPER YET`), the
    fan window opening only after a change that was applied, an approval used up only when the request is
    carried out, the three request budgets, the 17th open challenge, and the `trust hash` / `set by` lines.
  * The machine id (section 13, H): **pipe protocol 3** on the real pipe (the version 2 that ran is refused
    now, by both sides); the `machine_id` in the trust file, in `/metrics`, `helper-status` and
    `helper-trust show`; the helper adding an id to a trust file from the run of 2026-11-11 (a temporary file
    in `helper\`, then a rename over the trust file: whether the new file gets the same owner and access
    list by inheritance, and whether the rename works while the agent has the file open);
    `helper-trust set --new-machine-id`; one service of each build refusing to work together.
  * From the second round of that audit: the agent's own look at an update's approval before it downloads
    (it needs the agent's account to read `helper\approval-trust.json`; where it cannot, there is no look).
  * And still: a real Pocket ID token checked by a machine (its size and header, the clock difference on
    real PCs), and whether GetTickCount64 behaves as described for `boot_shutdown_s`;
* **0.6.0's security fixes** (TEST-ON-WINDOWS.md, section 12, is the checklist; none of this has run on
  Windows): the trust check and repair of the data folder (owners and access lists read from the objects
  themselves, the rename to `*.untrusted-<time>`, folders created with their final permissions), the updater
  and the helper refusing an untrusted folder, the helper remembering its own pending shutdown
  (`power-pending.json`) and Cancel aborting only that, the owner check on Core Temp's session object, the
  helper retrying while its pipe name is held, the agent's port opened for exclusive use, and both install
  scripts in their 0.6.0 form (`install.ps1` run from memory with the join code in `FAIRY_JOIN_CODE`, its
  work folder restricted with `icacls`, the "never older" check in `install-fairy-agent.ps1`): written and
  re-read, not parsed or run;
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
