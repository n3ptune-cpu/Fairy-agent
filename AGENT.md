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
* [Install on Linux](#install-on-linux)
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
* Graphics card numbers come from `nvidia-smi`, NVIDIA's own tool that comes with the driver, started once and
  left running in its "repeat every 2 seconds" mode.
* Temperatures on Windows come from the ACPI thermal zones that Windows itself publishes as performance
  counters, and, only if you switch it on, from the Core Temp program you already run (see
  [Core Temp](#core-temp-optional-windows)). Fan control talks to the server's management chip (BMC) through Windows' own built-in IPMI support.

What it does **not** do on Windows as a result: see [What it can and cannot show](#what-it-can-and-cannot-show).

## Add a host from the panel (one command)

Like adding a machine to Tailscale: no editor, no token copying.

1. In the panel (admins): **Add host** on the Overview page. Fill in the machine's **Tailscale name** (as in
   the Tailscale admin console, e.g. `nsx-furina`; the panel reaches it at `http://<name>:9101`, or give its
   100.x address), its site, Linux or Windows, and tick what the agent may do: shutdown / reboot,
   self-update, Wake-on-LAN relay, reading the UPS of a local NUT server, Core Temp (Windows), attaching it to
   a Proxmox node, and the MAC addresses to wake it with.
2. The panel asks you to confirm it's you (Pocket ID), then shows **one command** with a one-time code
   (valid 15 minutes, works once). Copy it.
3. Run it on the machine:
   * **Linux** (as a user with sudo; on a Proxmox node, as root, the panel leaves out `sudo`):
     `curl -fsSL https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download/install.sh | sudo sh -s -- --join CODE --panel 100.88.109.47 ...`
   * **Windows** (PowerShell as Administrator, one line):
     `iwr https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download/install.ps1 -OutFile $env:TEMP\fairy-install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\fairy-install.ps1 -Join CODE -PanelAddress 100.88.109.47 ...`
4. The dialog goes from *waiting for the machine* to *paired* to *online*, and the host appears.

What the command does: it downloads the latest release, checks every file against the signed `SHA256SUMS`
(with the release key built into fairy-agent: the installed agent's on a re-run), installs exactly as described
in [Install on Windows](#install-on-windows) / [Install on Linux](#install-on-linux) (user, program, service,
polkit / tmpfiles rules when needed, firewall rule for the panel only, LocalSystem on Windows when Core Temp or
IPMI is chosen), then runs `fairy-agent join`: it makes the tokens on the machine, switches on the chosen
features with the same checked edit as `fairy-agent config set`, and stores the code (only a hash of it) with its
expiry and the panel's address. The panel then asks the agent `POST /pair` with proof of the code; the agent
answers **once**, only to the panel's address, with its tokens, and closes pairing for good (`fairy-agent
pair-status` shows it). The agent still never connects to the panel; the panel keeps the tokens in its own state
folder, not in `config.yaml`.

* **Lost the panel's copy of the tokens**, or the code expired before the machine ran it: **Re-pair** on the
  host's page makes a new code and the same command; running it again keeps the machine's tokens and settings.
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
until then; the installer warns when it is off), and the file
`fairy-agent-windows-amd64.exe` (plus `install-fairy-agent.ps1` from the `deploy` folder).

**The easy way.** Put both files in one folder, open **PowerShell as Administrator** (right-click the Start
button, "Terminal (Admin)"), go to that folder and run:

```powershell
cd $HOME\Downloads\fairy-agent        # wherever you put the two files
Set-ExecutionPolicy -Scope Process Bypass   # allows this one script, for this window only
.\install-fairy-agent.ps1 -PanelAddress 100.64.0.2   # the Tailscale address of the machine running the panel
```

Add `-LocalSystem` on a PC where you want fan control (see [Fan control](#fan-control-supermicro)).

**What the script does, step by step** (you can also type these yourself):

```powershell
# 1. copy the program to a folder only administrators can change
New-Item -ItemType Directory -Force "C:\Program Files\Fairy" | Out-Null
Copy-Item .\fairy-agent-windows-amd64.exe "C:\Program Files\Fairy\fairy-agent.exe"
Unblock-File "C:\Program Files\Fairy\fairy-agent.exe"

# 2. install the service (starts automatically with Windows, a little after boot, restarts itself on failure).
#    This also creates C:\ProgramData\fairy-agent with config.yaml, token and control-token, readable only by
#    administrators, SYSTEM and the service itself.
& "C:\Program Files\Fairy\fairy-agent.exe" install          # or: install --account LocalSystem

# 3. let only the panel in: TCP 9101, only on the Tailscale adapter, only from Tailscale addresses
New-NetFirewallRule -DisplayName "Fairy agent (Tailscale only)" -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 9101 -RemoteAddress 100.64.0.0/10 -InterfaceAlias Tailscale `
  -Program "C:\Program Files\Fairy\fairy-agent.exe"

# 4. check the settings and start it
& "C:\Program Files\Fairy\fairy-agent.exe" check-config
Start-Service fairy-agent
```

The service runs as **LocalService**, a built-in Windows account with very few rights. That is enough for
everything except two things, which need **LocalSystem** (`install --account LocalSystem`):

* fan control and BMC sensors through Windows' IPMI support (Windows only lets administrators use it), and
* full details for programs of other accounts in the Processes tab. As LocalService the agent can open only
  programs running under its own account; everything else (your games, your browser) is listed **by name only**,
  without CPU, memory or user. For many people that is a feature.

Shutdown / reboot and Wake-on-LAN work as LocalService.

By default the agent listens on this PC's Tailscale address, port 9101 (it finds it by itself). It never listens
on your home network or the internet unless you set `listen:` yourself. Until Tailscale is up the agent waits
(as long as it takes; the log says so once a minute) and then starts answering by itself.

## Install on Linux

You need: Linux with systemd (Debian, Ubuntu, Proxmox VE, Fedora...), amd64 or arm64 (e.g. Raspberry Pi 4/5),
Tailscale signed in. As root:

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
Three optional extras need a small permission each, and only if you want them:

| You want | Install | Why |
| --- | --- | --- |
| CPU watts (Intel/AMD "RAPL") | `deploy/fairy-agent.tmpfiles.conf` as `/etc/tmpfiles.d/fairy-agent.conf`, then `systemd-tmpfiles --create /etc/tmpfiles.d/fairy-agent.conf` | the energy counters are root-only since 2020 (a side-channel fix); this lets the agent's group read them |
| Shutdown / reboot / sleep from the panel | `deploy/fairy-agent.polkit.rules` as `/etc/polkit-1/rules.d/49-fairy-agent.rules` | lets exactly this user power off / reboot / suspend through systemd |
| BMC sensors / fan control in-band | `apt install ipmitool`, `deploy/fairy-agent.udev.rules` as `/etc/udev/rules.d/60-fairy-agent-ipmi.rules`, `modprobe ipmi_devintf ipmi_si`, `udevadm trigger` | lets the agent's group use /dev/ipmi0 |

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
counters and both stay. Nothing to install; `gpu: windows: off` switches it off.

Radeon temperature and watts on Windows come from AMD's own library, ADL (`atiadlxx.dll` in System32, installed
with the Adrenalin driver), read only: per card by its Overdrive version, the PMLog sensors on Navi and newer
(edge temperature, board or ASIC power: e.g. RX 5600 XT), OverdriveN / Overdrive 6 / 5 calls on older cards.
Only "Get" functions are called (no overclocking or fan settings are touched), no driver of our own is loaded
and nothing is read from other processes. Cards are matched to the DXGI list by PCI location; the panel then
shows them "via AMD". Without the DLL, or when a call fails, the card keeps load and VRAM only (logged once at
debug level). `gpu: amd_adl: off` switches it off. Untested on real AMD hardware so far.

If the firewall on the machine is on (nftables/ufw), allow TCP 9101 only on `tailscale0`, e.g.
`ufw allow in on tailscale0 to any port 9101 proto tcp`.

## Point the panel at it

On the panel, two files change: `/etc/fairy/fairy.env` (the secrets) and `/etc/fairy/config.yaml`.

1. Copy the agent's token. Windows (PowerShell as Administrator): `Get-Content C:\ProgramData\fairy-agent\token`.
   Linux: `cat /etc/fairy-agent/token`.
2. On the panel, add it to `/etc/fairy/fairy.env` under a name of your choice, one per machine:

   ```sh
   AGENT_TOKEN_NSX_CYRENE=paste-the-token-here
   # only if you enable fan control, shutdown/reboot or Wake-on-LAN on that machine:
   AGENT_CONTROL_TOKEN_NSX_CYRENE=paste-the-control-token-here
   ```
3. Add the machine to `agents:` in `/etc/fairy/config.yaml` (the address is the machine's Tailscale address):

   ```yaml
   agents:
     - id: nsx-cyrene
       name: NSX-CYRENE
       url: http://100.64.0.10:9101
       token_env: AGENT_TOKEN_NSX_CYRENE
       group: Neptune
       site: Neptune
       # optional, each must also be switched on in the agent's config.yaml:
       # fan_control: {vendor: supermicro, control_token_env: AGENT_CONTROL_TOKEN_NSX_CYRENE}
       # power_control: true
       # control_token_env: AGENT_CONTROL_TOKEN_NSX_CYRENE   # (needed for power_control / wol_relay)
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

On Windows this uses Windows' own IPMI support through one `powershell.exe` the agent starts when needed (and
stops after 5 idle minutes), so the service must run as LocalSystem (`install --account LocalSystem`). The first
reading of the BMC's sensor list can take a minute. On Linux it uses `ipmitool` (see the table above).
`ipmi.enabled` alone (without `fan_control`) adds the BMC's temperatures, fan speeds and voltages to the panel.

### Shutdown, reboot and sleep

```yaml
power_control:
  enabled: true
```

Panel: `power_control: true` and `control_token_env:` in the agent's entry. The panel asks you to type the
machine's name and sends a delay (default 60 s). On Windows, Windows itself shows its usual "you're about to be
signed out" warning and counts down (like `shutdown /s /t 60`; open programs are closed at the end); Cancel in
the panel aborts it. On Linux the agent waits and then runs `systemctl poweroff` / `reboot` (needs the polkit
rule above); if the agent is restarted in the meantime, the pending action is dropped.

**Sleep** (suspend to RAM, not hibernate) works the same way (delay, Cancel, one pending action at a time), but
the agent itself waits on Windows too and then calls `SetSuspendState` (powrprof.dll). The agent reports in
`/metrics` (`power_control.sleep`, and `sleep_note` with the reason when not) whether the machine can sleep, and
refuses with 409 `sleep_unavailable` otherwise: on Windows it needs S1-S3 in `GetPwrCapabilities` (a laptop with
only Modern Standby cannot be put to sleep by a service; `powercfg /a` shows what is available), on Linux
systemd-logind's `CanSuspend` must say `yes` (the polkit rule above covers `suspend` since v0.4.2: copy the new
file over the old one). Waking it is Wake-on-LAN (the panel's "Power on"), which from sleep needs the network
card's "Allow this device to wake the computer" / "Wake on Magic Packet" (Windows Device Manager) or
`ethtool -s <nic> wol g` (Linux).

### Wake-on-LAN

```yaml
wol:
  enabled: true
  allowed_macs: ["3c:ec:ef:00:11:22"]   # optional: only these machines
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
  environment without the agent's tokens. ipmitool is found in PATH, `C:\Program Files\ipmitool\` or
  `/usr/bin` unless `ipmitool_path` says where. `cipher_suite` (0-17) is ipmitool's `-C` for BMCs that need a
  particular one.
* `redfish` (default when `url:` is set): `GET /redfish/v1/Systems`, then `POST <first
  member>/Actions/ComputerSystem.Reset {"ResetType": "On"}`, basic auth, 10 s. The BMC's self-signed
  certificate is pinned by SHA-256: `tls_fingerprint` if given, else learned on the first successful call
  ("trust on first use", logged with the fingerprint) and kept in the agent's state folder (`bmc-pins.json`).

```yaml
bmc_relay:
  enabled: true
  targets:
    - {id: cyrene-bmc, backend: ipmitool, host: 192.168.254.254, username: fairy, password_env: BMC_CYRENE_PASSWORD}
env_file: C:\ProgramData\fairy-agent\secrets.env    # BMC_CYRENE_PASSWORD=... (written by `fairy-agent secret set`)
```

The password is never typed on a command line: `fairy-agent secret set NAME` asks for it (no echo) or reads one
line from stdin, writes it into `env_file` (setting `env_file` to `secrets.env` next to config.yaml if it was
not set) with tight permissions (Windows: SYSTEM and Administrators full control, the agent's service account
read-only, nobody else; Linux: 0640 root:fairy-agent). IPMI over LAN without ipmitool is not built in (future).

Neptune's NSX-FURINA (cabled to NSX-CYRENE's BMC port, BMC at 192.168.254.254, ipmitool installed), in an
Administrator PowerShell:

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" bmc-relay add --id cyrene-bmc --backend ipmitool --host 192.168.254.254 --username <BMC user> --password-env BMC_CYRENE_PASSWORD
& "C:\Program Files\Fairy\fairy-agent.exe" secret set BMC_CYRENE_PASSWORD
Restart-Service fairy-agent
```

(add `--cipher-suite <n>` to the first line if the BMC needs a particular cipher suite, and
`--ipmitool-path "C:\path\to\ipmitool.exe"` if it is not in PATH or `C:\Program Files\ipmitool\`).
Panel (`config.yaml`), on the machine to wake: `systems: [{id: nsx-cyrene, bmc_power: {relay: nsx-furina-agent,
target: cyrene-bmc}}]`; the relay agent's entry needs `control_token_env:`. The panel then offers "Power on (via
BMC, through NSX-FURINA)" while NSX-CYRENE is offline and NSX-FURINA is online.

### Plugs and UPSes on this machine's network

When the panel cannot reach a smart plug or UPS itself (for example at a friend's place), the agent there can
read it and pass the readings on. The entries are the same as in the panel's `power_sources:` and `ups:`
(Shelly, Tasmota, Tuya, Redfish, NUT); passwords go into a separate file named by `env_file:` as
`NAME=value` lines and stay on that machine. `system_hint: self` links a plug to the agent's own machine, but
only for an agent that is a host of its own: for an agent merged into a Proxmox node (`node:` in the panel) it
does not work, because the panel shows that machine under the node's id. There, and whenever the panel should
decide, use `power_links:` in the panel's agent entry (`power_links: {<device id>: <system id>}`, e.g.
`{asus-i7-ups: straw-node-asus-i7}`), plus `ups_powers:` / `ups_names:` for UPSes, as for any agent.

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
  polkit rule `fairy-agent.polkit.rules` as `/etc/polkit-1/rules.d/49-fairy-agent.rules` (lets the agent's user
  start exactly that one unit; Debian/Proxmox: `apt install polkitd` if `/etc/polkit-1/rules.d` does not
  exist). Then `systemctl daemon-reload && systemctl restart fairy-agent`. On Fedora with SELinux the installer
  runs `restorecon` on the new program. The installer's messages: `journalctl -u fairy-agent-update`.
* **Windows**: run `install-fairy-agent.ps1` (again) as Administrator. It gives the service's own account
  (`NT SERVICE\fairy-agent`, nothing else) the right to replace files in `C:\Program Files\Fairy`, to write
  `C:\ProgramData\fairy-agent\update` and to stop and start its own service. The installer is
  `fairy-agent.exe apply-update`, started by the service; it writes to the agent's log file. No driver, no
  other programs touched.

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
3. The fairy-agent service must run as **LocalSystem** (`install-fairy-agent.ps1 -LocalSystem`, or
   `install --account LocalSystem`; the same as for fan control). Core Temp runs as administrator and does not
   open its readings to other accounts, so the default LocalService account is turned away ("access denied" in
   the agent's log).
4. In `C:\ProgramData\fairy-agent\config.yaml`:

   ```yaml
   sensors:
     coretemp: true
   ```

   then `Restart-Service fairy-agent`. The log says "Core Temp readings available" once it has found them.

The agent looks for `Global\CoreTempMappingObjectEx` first, then the older `CoreTempMappingObject`, then the
same names in the signed-in user's session. Core Temp has no CPU package *temperature* in its shared block, so
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
| `gpu.nvidia_smi` | auto | `off` or a full path |
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

* **Is it running?** Windows: `Get-Service fairy-agent`. Linux: `systemctl status fairy-agent`.
* **Logs.** Windows: `Get-Content C:\ProgramData\fairy-agent\logs\agent.log -Tail 30` (start-up problems also go
  to the Event Viewer, Windows Logs > Application, source "fairy-agent"). Linux: `journalctl -u fairy-agent`.
  Logs never contain tokens or passwords.
* **Ask it directly** (from the panel machine):
  `curl -H "Authorization: Bearer <token>" http://100.64.0.10:9101/metrics`
* **Panel shows the machine offline**: check the firewall rule, that Tailscale is up on both sides, and that the
  token in the panel's `fairy.env` is exactly the one in the agent's `token` file. A wrong token shows up in the
  agent's log as "rejected request".
* **Update.** With self-update on: the panel's Update button (see [Updates](#updates-the-panels-update-button)).
  By hand: Windows: run `install-fairy-agent.ps1` again with the new exe (or `Stop-Service fairy-agent`, copy
  the exe over, `Start-Service fairy-agent`). Linux: copy the new binary to `/usr/local/bin/fairy-agent`, then
  `systemctl restart fairy-agent`. Settings and tokens stay. `fairy-agent version` shows the version and
  whether the program carries the release key.
* **Pairing (Add host).** `fairy-agent pair-status` says whether the panel has paired, is still expected (and
  until when), or the code expired. The agent's log says "paired with panel" (with the panel's address, never a
  token). The state file is `/var/lib/fairy-agent/pairing.json` (Linux) or
  `C:\ProgramData\fairy-agent\state\pairing.json` (Windows); it never holds the code itself.
* **Remove.** Windows: `& "C:\Program Files\Fairy\fairy-agent.exe" uninstall`, then
  `Remove-NetFirewallRule -DisplayName "Fairy agent (Tailscale only)"` and delete `C:\Program Files\Fairy` and
  `C:\ProgramData\fairy-agent`. Linux: `systemctl disable --now fairy-agent`, delete the units
  (`fairy-agent.service`, `fairy-agent-update.service`), `/etc/polkit-1/rules.d/49-fairy-agent.rules`,
  `/usr/local/bin/fairy-agent` (and `.old`), `/etc/fairy-agent`, `/var/lib/fairy-agent*`, and `userdel fairy-agent`.

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
* Time limits on every connection; requests are small and bounded.
* Windows: settings folder readable only by administrators, SYSTEM and the service; the program lives in
  `C:\Program Files`. Linux: own user, no root, no capabilities, systemd sandbox.

## Not yet tested on a real Windows PC

The Windows parts compile and their pure logic is unit-tested, but were not yet run on real Windows. Check these
on the first install and report anything odd:

* the BMC power-on relay (ipmitool through `-E`, Redfish) against a real BMC, and `fairy-agent secret set`'s
  Windows ACL with the installed service;
* the service itself: install / start / stop / uninstall, the folder permissions, the log file, the Event Log
  entry on a failed start, automatic restart;
* CPU %, memory, disks, network counters, uptime, OS name and hardware strings (registry);
* ACPI thermal-zone temperatures (PDH);
* Core Temp's shared memory: which name the service finds (global setting on/off), LocalService vs LocalSystem,
  the values against Core Temp's window (unit conversions, package watts);
* the process list (Toolhelp snapshot + limited handles), LocalService vs LocalSystem;
* nvidia-smi on Windows (looping mode, path detection);
* shutdown / reboot / cancel (InitiateSystemShutdownEx / AbortSystemShutdown) as LocalService;
* sleep (SetSuspendState after the agent's own countdown; GetPwrCapabilities for S1-S3 / Modern Standby) and
  `systemctl suspend` with the extended polkit rule (CanSuspend through busctl): untested on real machines;
* IPMI through `powershell.exe` and the Microsoft_IPMI WMI class: the reply format is taken from Microsoft's
  documentation and examples (first byte of the reply = completion code) and has not been seen on a real BMC
  yet. Try `ipmi: enabled: true` first (sensors only) and look at the panel and the log before enabling fan
  control;
* the install script's firewall rule;
* per-program GPU memory from the "GPU Process Memory" counter (compare with Task Manager's "Dedicated GPU
  memory" column), and its matching to the NVIDIA card through nvidia-smi's pci.bus_id;
* leaving out leftover GPU entries ("GPU Adapter Memory" counter per adapter), checked against unit tests built
  from the RX 5600 XT and Intel UHD reports, not yet on those PCs;
* self-update on Windows: the permissions `setup-self-update` sets (program folder, update folder, the
  service's own start/stop right), the detached installer (`apply-update`) stopping and starting the service,
  renaming the running exe, and rolling back.

Self-update on Linux was tested with fakes (signature, download, swap, rollback) but not yet against a real
GitHub release, a real polkit rule or SELinux: watch `journalctl -u fairy-agent-update` the first time.
