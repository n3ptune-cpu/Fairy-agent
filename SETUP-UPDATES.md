# Setting up Fairy updates

After this setup:

* every push to `main` in **Fairy-agent** and **Fairy-dashboard** makes a signed release on GitHub by itself;
* the panel tells admins when there is something new (a banner at the top, an arrow next to the version of
  each host that is behind, a dot on the Updates menu entry);
* agents update when an admin presses **Start update** (on the host's page), **Update** or **Update all** (on
  the **Updates** page), or when you run `fairy-agent update` on the machine. Each agent downloads the release,
  checks its signature, installs it, restarts and goes back to the old version if the new one does not come up;
* the panel updates when you run `fairy update` on its host.

Nothing ever installs on its own. You do the steps below **once**. Part 1 is on your Windows PC (PowerShell),
part 2 is on each machine, part 3 on the panel.

| Machine | System | Release file |
| --- | --- | --- |
| Linux machines with an Intel or AMD processor | Proxmox VE, Debian, Fedora (SELinux) ..., amd64 | `fairy-agent-linux-amd64` |
| Linux machines with an ARM processor | Proxmox VE, Debian ..., arm64 | `fairy-agent-linux-arm64` |
| Windows PCs | Windows 10/11 | `fairy-agent-windows-amd64.exe` |
| The panel host | Debian (machine or container), amd64 | `fairy-linux-amd64` (the panel) |

---

## Part 1: the signing key and the first releases (Windows PC)

### 1.1 Bring in the new commits

You get two zips, `fairy-agent-repo-v2.zip` and `fairy-dashboard-repo-v2.zip`. They contain your repositories
with the new commits on top of what you already pushed (plain fast-forwards). Unpack them next to your
repositories and pull from them (this keeps your GitHub settings):

```powershell
Expand-Archive "$HOME\Downloads\fairy-agent-repo-v2.zip"     -DestinationPath E:\Projects\v2
Expand-Archive "$HOME\Downloads\fairy-dashboard-repo-v2.zip" -DestinationPath E:\Projects\v2

cd E:\Projects\Fairy-agent
git pull --ff-only E:\Projects\v2\Fairy-agent main
git fetch E:\Projects\v2\Fairy-agent refs/tags/v0.2.0:refs/tags/v0.2.0
git log --oneline -6                       # newest first; the old 5e2d90c is further down
git rev-parse "v0.2.0^{commit}"            # must be the same as: git rev-parse HEAD

cd E:\Projects\Fairy-dashboard
git pull --ff-only E:\Projects\v2\Fairy-dashboard main
git log --oneline -6                       # ee94dde further down
```

If `git pull --ff-only` refuses, stop and ask (something was committed in between). If git says "detected
dubious ownership", run the `git config --global --add safe.directory ...` line it suggests.

**Do not change or re-make the tag `v0.2.0`.** The dashboard's `go.sum` has a fingerprint of exactly that tag.

### 1.2 Make the key

Go must be installed on the PC (`go version` shows 1.27.3 or newer).

```powershell
cd E:\Projects\Fairy-agent
go run ./cmd/fairy-release-key gen
```

This writes two files:

* `C:\Users\<you>\fairy-release-key.txt`: the **private key**, one line. Whoever has it can sign a release
  that every agent and the panel will install. It belongs in exactly two places: the GitHub Environment
  `release` of both repositories (next step), and your own offline copy. See
  [1.6 Rules for the private key](#16-rules-for-the-private-key).
* `E:\Projects\Fairy-agent\release\signing.pub`: the **public key**. It is committed in both repositories and
  built into every release; agents and the panel accept only releases signed with the matching private key.

Copy the public key into the dashboard too:

```powershell
New-Item -ItemType Directory -Force E:\Projects\Fairy-dashboard\release | Out-Null
Copy-Item E:\Projects\Fairy-agent\release\signing.pub E:\Projects\Fairy-dashboard\release\signing.pub
```

### 1.3 Put the private key into GitHub (both repositories)

Copy the key to the clipboard:

```powershell
Get-Content "$HOME\fairy-release-key.txt" | Set-Clipboard
```

Then in your browser, do the steps below for **Fairy-agent**, and then the same steps again for
**Fairy-dashboard**. Both release jobs read the key only from the GitHub Environment `release`, so every
release waits for your approval before the job can read the key.

1. Open the repository on github.com and click **Settings** (top right of the repository, not your account
   settings).
2. In the left menu: **Environments** > **New environment**; Name: `release`; **Configure environment**.
3. Tick **Required reviewers**, type your own GitHub name, pick yourself; **Save protection rules**. Leave
   "Prevent self-review" off: you are the only reviewer.
4. On the same page: **Deployment branches and tags** > **Selected branches and tags** > **Add deployment branch
   or tag rule** > `main`. This step is required, not optional. It limits the environment, and so the key, to
   the `main` branch.
5. On the same page under **Environment secrets**: **Add environment secret**; Name: `FAIRY_RELEASE_KEY`; Value:
   paste (Ctrl+V); **Add secret**.
6. In the left menu: **Secrets and variables** > **Actions**. Under **Repository secrets** there must be **no**
   `FAIRY_RELEASE_KEY`. If there is one (setups from before 0.4.3, and older versions of this guide for
   Fairy-dashboard), delete it with the trash icon. A repository secret can be read by a workflow on any
   branch, without your approval. The environment is the only place on GitHub that holds the key.

Check these three things in **both** repositories before the first release, and again whenever you change
the settings:

| Where | Must be |
| --- | --- |
| **Settings** > **Secrets and variables** > **Actions** > **Repository secrets** | no `FAIRY_RELEASE_KEY` |
| **Settings** > **Environments** > `release` > **Deployment branches and tags** | **Selected branches and tags**, one rule: `main` |
| **Settings** > **Environments** > `release` > **Required reviewers** | ticked, with you as reviewer |

Afterwards clear the clipboard (copy something else). Then take `fairy-release-key.txt` off this PC's
everyday folders: keep it as your own offline copy, or delete it. Where you keep it is for you alone to know.
Do not write it down in a repository, an issue or a chat.

If the key is ever **lost**, make a new key (1.2 to 1.4 again); machines then need one more update by hand
(part 2), because they only trust the old key. If the key may have **leaked**, see
[1.7](#17-if-the-private-key-may-have-leaked).

### 1.4 Commit the public key and push

Fairy-agent first (with the tag: the dashboard needs it to build):

```powershell
cd E:\Projects\Fairy-agent
git add release/signing.pub
git commit -m "Release signing key"
git push origin main
git push origin v0.2.0

cd E:\Projects\Fairy-dashboard
git add release/signing.pub
git commit -m "Release signing key"
git push origin main
```

### 1.5 Wait for the first releases

On GitHub open each repository's **Actions** tab. Fairy-agent's "release" run first shows **Waiting** (review
required): open it, **Review deployments**, tick `release`, **Approve and deploy**. Then it takes a few minutes. When it is green, the
repository's **Releases** (right side of the repository page) shows `build-1` (or a higher number) marked
**Latest**, with the binaries, `VERSION`, `SHA256SUMS` and `SHA256SUMS.sig`.

If a run is red:

* "The FAIRY_RELEASE_KEY secret is missing": step 1.3 for that repository (the secret must be in the
  environment `release`, and the environment must be named exactly `release`).
* "release/signing.pub is missing": step 1.4.
* "the private key does not belong to release/signing.pub": the secret and the committed file come from
  different `gen` runs; paste the right key again (1.3).
* the dashboard cannot download `github.com/n3ptune-cpu/Fairy-agent v0.2.0`: the tag was not pushed (1.4), or
  wait a minute and press **Re-run jobs**.
* "Resource not accessible by integration" when publishing: repository **Settings** > **Actions** > **General**
  > **Workflow permissions** > **Read and write permissions** > Save, then re-run.

Optional check of the signature on the PC (download `SHA256SUMS` and `SHA256SUMS.sig` from the release into
the Fairy-agent folder first):

```powershell
go run ./cmd/fairy-release-key verify --pub release\signing.pub SHA256SUMS
```

Expected: `OK: signature of SHA256SUMS is good`.

### 1.6 Rules for the private key

1. The key is in two places only: the GitHub Environment `release` of Fairy-agent and of Fairy-dashboard, and
   your own offline copy.
2. Never paste the key into a chat, an issue, a pull request, a log, a screenshot or a support request. Never
   send it to anyone. Nobody who helps you with Fairy needs it: only the release job on GitHub signs.
3. Never commit it. `release/signing.pub` is the public half and is the only key file in the repositories.
4. Never store it as a repository secret (1.3, step 6), and never add it to another workflow.
5. A release is published only after you approve its run (**Review deployments**, 1.5). Before you approve,
   look at which commit the run is for. Reject a run you did not expect.
6. Whoever can sign in to your GitHub account can approve a run. Protect that account with two-factor
   sign-in.

### 1.7 If the private key may have leaked

Treat the key as leaked if it was pasted or sent anywhere outside the two places above, or if a PC that held
`fairy-release-key.txt` was compromised. A leaked key lets someone else sign a release. Agents and the panel
download releases only from GitHub over HTTPS, so that person would also have to control what the download
returns. Do not wait to find out: change the key.

1. On GitHub, in the **Actions** tab of both repositories: do not approve any waiting release run.
2. In both repositories: **Settings** > **Environments** > `release` > **Environment secrets**: delete
   `FAIRY_RELEASE_KEY`.
3. Make a new key pair on your PC. `gen` never overwrites a key file, so move the old ones away first:

   ```powershell
   cd E:\Projects\Fairy-agent
   Remove-Item release\signing.pub
   Remove-Item "$HOME\fairy-release-key.txt" -ErrorAction SilentlyContinue
   go run ./cmd/fairy-release-key gen
   Copy-Item release\signing.pub E:\Projects\Fairy-dashboard\release\signing.pub
   ```

4. Put the new private key into the environment `release` of both repositories (1.3), then commit and push
   the new `release/signing.pub` in both (1.4, without the tag line). Approve the two release runs (1.5).
   These releases are signed with the new key.
5. Every agent and the panel that are already installed still carry the **old** public key. They refuse the
   new releases (the Update button and `fairy-agent update` fail with "the release signature does not match
   this build's release key"), and they would still accept a release signed with the leaked key. So install
   the new program by hand once on **every** machine: agents as in [2.3](#23-by-hand-from-one-named-release-checked),
   the panel as in [3.1](#31-install-the-release-build-of-the-panel-once). `fairy-agent version` and
   `fairy version` then show the new build.
6. Only when every machine runs a build with the new key is the leaked key trusted nowhere. Until then keep
   the list of machines that are still on an old build, and finish it.

On a Linux machine the panel's Re-pair command cannot do step 5: with an agent installed, `install.sh` checks
the release with the **installed** agent's key and stops with "the release signature does not match the
installed fairy-agent's release key". Use 2.3 there.

---

## Part 2: installing or updating an agent by hand

Nothing in this part downloads "latest" and runs it. Every way below either names one release, or lets an
installed release build check the signature itself. Pick the row that fits the machine:

| The machine | Do this |
| --- | --- |
| has no agent yet | **Add host** in the panel and run the command it shows ([AGENT.md](AGENT.md#add-a-host-from-the-panel-one-command)). Nothing by hand. |
| runs a release build (`fairy-agent version` says `signed-release key: built in`) and only needs a newer program | [2.1](#21-a-machine-that-runs-a-release-build-fairy-agent-update): `fairy-agent update` |
| needs the service files or rules of a newer release | [2.2](#22-service-files-and-rules-of-a-newer-release-re-pair): **Re-pair** in the panel |
| can use none of these (no panel yet, a build without the release key, or after a key change, 1.7) | [2.3](#23-by-hand-from-one-named-release-checked): by hand from one named release |

Self-update from the panel's Update button is switched on per machine in [2.4](#24-switch-self-update-on).

### 2.1 A machine that runs a release build: `fairy-agent update`

Linux, as root:

```sh
fairy-agent version          # must say: signed-release key: built in
fairy-agent update --check   # installed vs latest release
fairy-agent update           # asks, then downloads, checks the signature with its built-in key, swaps, restarts
```

Windows, PowerShell as Administrator:

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" version
& "C:\Program Files\Fairy\fairy-agent.exe" update --check
& "C:\Program Files\Fairy\fairy-agent.exe" update
```

This works even where `self_update` is off (it is you at the machine, not the panel). It replaces the program
only. If the new program does not come up, the old one is put back.

### 2.2 Service files and rules of a newer release: Re-pair

An update (2.1, or the panel's Update button) replaces the program and nothing else. Some things only the
install script delivers:

* Linux: the current `fairy-agent.service` (since 0.6.0 it hands the fans back to the BMC when the agent has
  ended, `ExecStopPost`), `fairy-agent-update.service`, and one polkit rule per feature that is on.
* Windows: the service setup and the check of the data folder (AGENT.md, "Running the installer again").

To run the install script again:

1. In the panel, open the host's page and press **Re-pair**.
2. Run the command it shows on the machine (Linux: a user with sudo, or root on a Proxmox node; Windows:
   PowerShell as Administrator).

The machine's settings stay. It gets new tokens, which the panel picks up by itself. If the script says the
installed fairy-agent `is NEWER than this installer's release`, it leaves the program alone (on Linux the
existing service files too): update the panel first, then Re-pair again.

### 2.3 By hand from one named release, checked

Use this only when 2.1 and 2.2 do not fit. The machine must already have the agent's user, folders and tokens
(for a machine without any, follow [AGENT.md, "Install on Linux"](AGENT.md#install-on-linux) or
["Install on Windows"](AGENT.md#install-on-windows) with the files you download and check here).

#### Linux, as root

1. Download one named release. `BUILD` below is an **example value**: put in the tag of the release you want,
   as shown on <https://github.com/n3ptune-cpu/Fairy-agent/releases>. The file names are those of 0.6.0 and
   later releases.

   ```sh
   BUILD=build-20      # EXAMPLE VALUE: the release tag you chose
   ARCH=amd64          # or arm64 (uname -m says x86_64 or aarch64)
   mkdir -p /root/fairy-update && cd /root/fairy-update && rm -f ./*
   REL=https://github.com/n3ptune-cpu/Fairy-agent/releases/download/$BUILD
   for f in "fairy-agent-linux-$ARCH" SHA256SUMS SHA256SUMS.sig VERSION fairy-agent.service \
            fairy-agent-update.service fairy-agent-power.polkit.rules fairy-agent-update.polkit.rules; do
     curl -fsSL --proto '=https' -O "$REL/$f" || { echo "download of $f failed: stop here"; break; }
   done
   cat VERSION                                   # e.g. fairy-agent 20-1a2b3c4
   ```

2. Check the signature and the files. Use way A if you can.

   **Way A**: a release build of fairy-agent is installed on this machine, and the release key was not
   changed since:

   ```sh
   fairy-agent verify-release /root/fairy-update
   ```

   Expected: one line that starts `release 20-1a2b3c4: signature OK, checked` and lists the downloaded files.
   Anything else: stop.

   **Way B**: no release build is installed, or the key was changed (1.7). Check the signature on your PC,
   which has Go and the Fairy-agent repository with the public key:

   1. On the PC, download `SHA256SUMS` and `SHA256SUMS.sig` of the **same** release from its page on GitHub
      into the Fairy-agent folder. Then, in PowerShell in that folder:

      ```powershell
      go run ./cmd/fairy-release-key verify --pub release\signing.pub SHA256SUMS
      (Get-FileHash SHA256SUMS -Algorithm SHA256).Hash.ToLower()
      ```

      Expected: `OK: signature of SHA256SUMS is good`, then 64 hex digits.
   2. On the machine:

      ```sh
      sha256sum SHA256SUMS                          # the same 64 hex digits as on the PC, else stop
      sha256sum -c --ignore-missing SHA256SUMS      # every line must say OK, else stop
      ```

3. Install the program and the two units. This replaces `/etc/systemd/system/fairy-agent.service`. If you
   changed that file yourself, save a copy first:
   `cp -p /etc/systemd/system/fairy-agent.service /root/fairy-agent.service.mine`.

   ```sh
   install -m 0755 "fairy-agent-linux-$ARCH" /usr/local/bin/fairy-agent.new
   mv /usr/local/bin/fairy-agent.new /usr/local/bin/fairy-agent
   command -v restorecon >/dev/null && restorecon -v /usr/local/bin/fairy-agent    # Fedora (SELinux)
   install -m 0644 fairy-agent.service /etc/systemd/system/fairy-agent.service
   install -m 0644 fairy-agent-update.service /etc/systemd/system/fairy-agent-update.service
   fairy-agent version                           # must say: signed-release key: built in
   ```

4. Install one polkit rule per feature that is on, and remove the combined rule of installs before 0.6.0
   (it granted both rights for either feature):

   ```sh
   [ -d /etc/polkit-1/rules.d ] || apt-get install -y polkitd                   # Debian / Proxmox without polkit
   R=/etc/polkit-1/rules.d
   if [ "$(fairy-agent config get self_update.enabled)" = true ]; then
     install -m 0644 fairy-agent-update.polkit.rules "$R/49-fairy-agent-update.rules"
   else
     rm -f "$R/49-fairy-agent-update.rules"
   fi
   if [ "$(fairy-agent config get power_control.enabled)" = true ]; then
     install -m 0644 fairy-agent-power.polkit.rules "$R/49-fairy-agent-power.rules"
   else
     rm -f "$R/49-fairy-agent-power.rules"
   fi
   rm -f "$R/49-fairy-agent.rules"
   ls "$R" | grep fairy                            # only the rule(s) of what is switched on
   ```

   The block can be pasted as a whole: it asks `config.yaml` which features are on. If you switch self-update
   on in 2.4, run it again afterwards.

5. Restart and look:

   ```sh
   systemctl daemon-reload && systemctl restart fairy-agent
   systemctl status fairy-agent --no-pager       # "fairy-agent listening ..."
   ```

`/root/fairy-update` can be deleted afterwards.

#### Windows, PowerShell as Administrator

1. Download one named release into a new folder. `$build` is an **example value**, as above.

   ```powershell
   $ProgressPreference = 'SilentlyContinue'
   $build = 'build-20'      # EXAMPLE VALUE: the release tag you chose
   $d = Join-Path $env:TEMP ('fairy-update-' + [guid]::NewGuid().ToString('N'))
   New-Item -ItemType Directory -Path $d | Out-Null; cd $d
   $rel = "https://github.com/n3ptune-cpu/Fairy-agent/releases/download/$build"
   foreach ($f in 'fairy-agent-windows-amd64.exe', 'SHA256SUMS', 'SHA256SUMS.sig', 'VERSION', 'install-fairy-agent.ps1') { Invoke-WebRequest -UseBasicParsing "$rel/$f" -OutFile $f }
   Get-Content VERSION
   ```

2. Check the signature and the files. Use way A if you can.

   **Way A**: a release build from 0.4.3 or later is installed on this PC, and the release key was not changed
   since:

   ```powershell
   & "C:\Program Files\Fairy\fairy-agent.exe" verify-release $d
   ```

   Expected: one line that starts `release` and says `signature OK, checked`, with
   `fairy-agent-windows-amd64.exe` and `install-fairy-agent.ps1` in the list. Anything else: stop.

   **Way B**: otherwise. On the PC that has Go and the Fairy-agent repository (it can be this PC), in the
   Fairy-agent folder:

   ```powershell
   go run ./cmd/fairy-release-key verify --pub release\signing.pub "$d\SHA256SUMS"
   ```

   Expected: a line that starts `OK: signature of`. Then, back in the download folder (`cd $d`):

   ```powershell
   $want = ((Select-String -Path SHA256SUMS -Pattern 'fairy-agent-windows-amd64.exe$').Line -split '\s+')[0]
   $got = (Get-FileHash fairy-agent-windows-amd64.exe -Algorithm SHA256).Hash.ToLower()
   if ($got -eq $want) { 'OK: program matches' } else { 'MISMATCH: stop here' }
   $want = ((Select-String -Path SHA256SUMS -Pattern 'install-fairy-agent.ps1$').Line -split '\s+')[0]
   $got = (Get-FileHash install-fairy-agent.ps1 -Algorithm SHA256).Hash.ToLower()
   if ($got -eq $want) { 'OK: script matches' } else { 'MISMATCH: stop here' }
   ```

3. Only if every check said OK:

   ```powershell
   Set-ExecutionPolicy -Scope Process Bypass
   .\install-fairy-agent.ps1 -PanelAddress 100.64.0.2     # EXAMPLE VALUE: the panel's Tailscale address; add
                                                        # -Helper on a new install that needs fan control,
                                                        # Core Temp or power
   & "C:\Program Files\Fairy\fairy-agent.exe" version   # must say: signed-release key: built in
   ```

   The install script also sets up what self-update needs (safe to run again): the **fairy-agent-update**
   service (LocalSystem, started on demand) that installs signed releases, and the download folder
   `C:\ProgramData\fairy-agent\update\stage`. The agent itself cannot change `C:\Program Files\Fairy`.

### 2.4 Switch self-update on

Self-update needs the control token.

#### Linux, as root

Check that the control token file exists:

```sh
ls -l /etc/fairy-agent/control-token || {
  fairy-agent gen-token > /etc/fairy-agent/control-token
  chown root:fairy-agent /etc/fairy-agent/control-token && chmod 0640 /etc/fairy-agent/control-token
  echo "NEW control token: add it to the panel's fairy.env (part 3)"; }
nano /etc/fairy-agent/config.yaml
```

Add at the end of `config.yaml` (or change the block if it is already there):

```yaml
self_update:
  enabled: true
```

Self-update on Linux also needs `fairy-agent-update.service` and the rule
`/etc/polkit-1/rules.d/49-fairy-agent-update.rules`. The install script puts both in place when self-update
is ticked in the panel (2.2); by hand they are steps 3 and 4 of 2.3.

Check and restart:

```sh
runuser -u fairy-agent -- fairy-agent check-config
systemctl daemon-reload && systemctl restart fairy-agent
systemctl status fairy-agent --no-pager       # "fairy-agent listening ... features=...self_update..."
```

#### Windows, PowerShell as Administrator

```powershell
notepad C:\ProgramData\fairy-agent\config.yaml
```

Add at the end of `config.yaml`:

```yaml
self_update:
  enabled: true
```

then `Restart-Service fairy-agent`. On a PC that ran 0.4.2 or older, run this once after it is on 0.4.3
(through the panel or by hand), in PowerShell as Administrator; it sets up the updater service and takes back
the write access 0.4.2 gave the agent:

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update
```

**Coming from 0.4.x (0.5.0 and later).** Since 0.5.0 the agent runs as its own low-rights account
`NT SERVICE\fairy-agent`, and Core Temp, IPMI / fans and shutdown / sleep go through the separate
**fairy-agent-helper** service (see AGENT.md, "Install on Windows"). An update through the panel only swaps the
program. Since 0.5.1 a service that runs as **LocalSystem** then moves itself (the agent does what the command
above does, restarts once through the updater service, rolls back if the new account does not come up; see
AGENT.md, "Moving to the new account by itself"). One that runs as **LocalService** keeps that account and keeps
working as before, its log and `/metrics` (`"migration": {"state": "needs_admin"}`) say it should be moved:
move it once, as Administrator, with the same command as above (or by running `install-fairy-agent.ps1`
again); it keeps config and tokens and installs the helper where config.yaml needs it. When the helper runs, the updater stops it during an update (fans go back to the BMC's automatic mode for
those seconds) and starts it again with the new program.

The control token is in `C:\ProgramData\fairy-agent\control-token`.

---

## Part 3: the panel (on the panel host, as root)

### 3.1 Install the release build of the panel once

A panel that already runs a release build (`fairy version` says `release key: built in`) updates itself with
`fairy update` (see [The panel: `fairy update`](#the-panel-fairy-update) below): go on with 3.2. Do the steps
here only for the first release build, or after a key change (1.7).

1. Download one named release. `BUILD` is an **example value**: put in the tag of the release you want, as
   shown on <https://github.com/n3ptune-cpu/Fairy-dashboard/releases>.

   ```sh
   BUILD=build-10      # EXAMPLE VALUE: the release tag you chose
   mkdir -p /root/fairy-update && cd /root/fairy-update && rm -f ./*
   REL=https://github.com/n3ptune-cpu/Fairy-dashboard/releases/download/$BUILD
   curl -fsSL --proto '=https' -O "$REL/fairy-linux-amd64" -O "$REL/SHA256SUMS" -O "$REL/SHA256SUMS.sig" -O "$REL/VERSION"
   sha256sum SHA256SUMS                          # 64 hex digits, needed in step 2
   ```

2. Check the signature on your PC, as in way B of 2.3: download `SHA256SUMS` and `SHA256SUMS.sig` of the
   **same** Fairy-dashboard release into the Fairy-agent folder (the same key signs both programs), then

   ```powershell
   go run ./cmd/fairy-release-key verify --pub release\signing.pub SHA256SUMS
   (Get-FileHash SHA256SUMS -Algorithm SHA256).Hash.ToLower()
   ```

   Expected: `OK: signature of SHA256SUMS is good`, and the same 64 hex digits as in step 1. If not, stop.

3. Install:

   ```sh
   sha256sum -c --ignore-missing SHA256SUMS      # both lines must say OK, else stop
   install -m 0755 fairy-linux-amd64 /usr/local/bin/fairy.new && mv /usr/local/bin/fairy.new /usr/local/bin/fairy
   printf '%s\n' '#!/bin/sh' 'exec /usr/local/bin/fairy update "$@"' > /usr/local/sbin/fairy-update
   chmod 0755 /usr/local/sbin/fairy-update
   systemctl restart fairy && fairy version      # must say: release key: built in
   ```

   The third line writes the small wrapper `fairy-update` (it only runs `fairy update`).

### 3.2 Tell the panel which agents may update

In `/etc/fairy/fairy.env`, each agent with self-update needs its control token (you may already have it for
power control):

```sh
AGENT_CONTROL_TOKEN_AGENT_1=paste-the-control-token-here
```

In `/etc/fairy/config.yaml`, add to each such agent entry:

```yaml
  - id: agent-1
    # ...as before...
    control_token_env: AGENT_CONTROL_TOKEN_AGENT_1
    self_update: true
```

The panel looks up the newest Fairy-agent release on GitHub (at most every 10 minutes, only while the Updates
page is open). If the panel host has no internet access, add `updates: {check_latest: false}`; the page then shows no
"latest" but Update still works (the agents download themselves). Then:

```sh
runuser -u fairy -- fairy admin config check
systemctl restart fairy
```

---

## Using it

### What admins see

* A banner at the top when a newer Fairy-agent or Fairy-dashboard release exists ("Update available: 3 agents,
  panel", with **Open Updates**). **Dismiss** hides it until the next release.
* Next to a host's agent version (host list and the host's page) a small arrow in a circle when it is behind.
  Click it (or Tab to it and press Enter): "Update available. Release ... is available.", a **Release notes**
  link (the GitHub release lists the changes since the previous one) and **Start update**. For a host that
  cannot update itself the box says what to switch on, or to run `fairy-agent update` on the machine.
* A dot on **Updates** in the menu while anything is behind.

Viewers see none of this.

### Agents: the Updates page

Menu (top right) > **Updates** (admins only). Each agent shows its version (`build 3 (1a2b3c4)`), whether it is
behind the latest release, and its self-update state. **Update** on one row or **Update all**: the panel asks
you to confirm with Pocket ID (like power actions), writes it to the Audit log, and the agents do the rest:
*downloading*, *applying* (offline for a few seconds), then the new version with "last update OK". If the new
version did not come up, the agent is back on the old one and shows why ("rolled back").

Since 0.6.0: after an update was installed, another one asked for through the panel within 10 minutes is
refused and shown as failed with the reason. Wait, or run `fairy-agent update` on the machine. A release whose
version does not start with a build number is refused. Details: AGENT.md, "The rules of an update".

Linux details: `journalctl -u fairy-agent-update` (installer), `journalctl -u fairy-agent` (agent). Windows:
`C:\ProgramData\fairy-agent\update\installer.log` (installer), `C:\ProgramData\fairy-agent\logs\agent.log`
(agent), `C:\ProgramData\fairy-agent\helper\helper.log` (helper). The panel's own version is on the same page, with "Panel update
available: run `fairy update` on the panel's host" when it is behind (the panel never updates itself from the
web page).

### Agents: on the machine (`fairy-agent update`)

Like `tailscale update`. Linux as root, Windows in PowerShell as Administrator:

```sh
fairy-agent update --check   # installed vs latest
fairy-agent update           # asks, then the same download, check, swap, restart and rollback
fairy-agent update --yes     # no question
```

This works even where `self_update` is off (it is you at the machine, not the panel).

### The panel: `fairy update`

On the panel host, as root:

```sh
fairy update --check     # installed vs latest
fairy update             # asks, then installs, restarts fairy.service, checks it, rolls back if needed
fairy-update             # the same (the small wrapper from 3.1)
```

### Going back by hand

* Linux agent: `mv /usr/local/bin/fairy-agent.old /usr/local/bin/fairy-agent && systemctl restart fairy-agent`
* Windows agent: `Stop-Service fairy-agent, fairy-agent-helper` (the helper only if installed), rename
  `C:\Program Files\Fairy\fairy-agent.exe.old` to `fairy-agent.exe` (rename the current one away first),
  `Start-Service fairy-agent-helper, fairy-agent`. Going back from 0.5 to 0.4.x: see TEST-ON-WINDOWS.md,
  "Rollback" (0.4.x does not know the helper or the new account)
* Panel: `mv /usr/local/bin/fairy.old /usr/local/bin/fairy && systemctl restart fairy`

Agents never install a release older than the one they run; the panel only with `fairy update --force`.
