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

| Machine | System | Agent file |
| --- | --- | --- |
| NSX-KACHINA | Proxmox VE (Debian), amd64 | `fairy-agent-linux-amd64` |
| NSX-FONTAINE, NSX-SNEZHNAYA | Proxmox VE (Debian), arm64 | `fairy-agent-linux-arm64` |
| NSX-PERLICA | Fedora (SELinux), amd64 | `fairy-agent-linux-amd64` |
| Windows PCs | Windows 10/11 | `fairy-agent-windows-amd64.exe` |
| Panel, CT 124 | Debian container, amd64 | `fairy-linux-amd64` (the panel) |

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

* `C:\Users\<you>\fairy-release-key.txt`: the **private key**, one line. It goes into GitHub as a secret (next
  step) and nowhere else. Never commit it, never paste it into chat.
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

Then in your browser, for **Fairy-agent** (its release job reads the key only from the GitHub Environment
`release`, so every release waits for your approval):

1. open the repository on github.com, click **Settings** (top right of the repository, not your account
   settings);
2. in the left menu: **Environments** > **New environment**; Name: `release`; **Configure environment**;
3. tick **Required reviewers**, type your own GitHub name, pick yourself; **Save protection rules**. (Optional,
   same page: **Deployment branches and tags** > **Selected branches and tags** > **Add deployment branch or
   tag rule** > `main`.) Leave "Prevent self-review" off: you are the only reviewer;
4. on the same page under **Environment secrets**: **Add environment secret**; Name: `FAIRY_RELEASE_KEY`; Value:
   paste (Ctrl+V); **Add secret**;
5. if the key was already a repository secret (before 0.4.3): **Secrets and variables** > **Actions**, and under
   **Repository secrets** delete `FAIRY_RELEASE_KEY` (the trash icon), so only the environment has it.

For **Fairy-dashboard** (until its release workflow uses the environment too): **Settings** > **Secrets and
variables** > **Actions** > **New repository secret**; Name: `FAIRY_RELEASE_KEY`; Secret: paste; **Add secret**.

Afterwards you can clear the clipboard (copy something else) and move `fairy-release-key.txt` to a USB stick or
your password manager, or delete it. If it is ever lost, make a new key (1.2 to 1.4 again); machines then need
one more update by hand (part 2), because they only trust the old key.

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

* "The FAIRY_RELEASE_KEY secret is missing": step 1.3 for that repository (Fairy-agent: the secret must be in
  the environment `release`, and the environment must be named exactly `release`).
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

---

## Part 2: one last update by hand on each machine

The agents running now cannot update themselves yet. Install the release build once; after that the panel's
Update button does it.

### 2.1 Linux machines (Proxmox nodes, Fedora), as root

Set `ARCH` to `amd64` (NSX-KACHINA, NSX-PERLICA) or `arm64` (NSX-FONTAINE, NSX-SNEZHNAYA), then paste the rest:

```sh
ARCH=amd64
mkdir -p /root/fairy-update && cd /root/fairy-update && rm -f ./*
REL=https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download
RAW=https://raw.githubusercontent.com/n3ptune-cpu/Fairy-agent/main/deploy
curl -fsSL -O "$REL/fairy-agent-linux-$ARCH" -O "$REL/SHA256SUMS" -O "$REL/VERSION"
sha256sum -c --ignore-missing SHA256SUMS      # both lines must say OK; if not, stop
curl -fsSL -O "$RAW/fairy-agent.service" -O "$RAW/fairy-agent-update.service" -O "$RAW/fairy-agent.polkit.rules"
cat VERSION                                   # e.g. fairy-agent 3-1a2b3c4
```

Install the program, the two units and the polkit rule:

```sh
install -m 0755 "fairy-agent-linux-$ARCH" /usr/local/bin/fairy-agent.new
mv /usr/local/bin/fairy-agent.new /usr/local/bin/fairy-agent
command -v restorecon >/dev/null && restorecon -v /usr/local/bin/fairy-agent    # Fedora (SELinux)
install -m 0644 fairy-agent.service /etc/systemd/system/fairy-agent.service
install -m 0644 fairy-agent-update.service /etc/systemd/system/fairy-agent-update.service
[ -d /etc/polkit-1/rules.d ] || apt-get install -y polkitd                   # Debian / Proxmox without polkit
install -m 0644 fairy-agent.polkit.rules /etc/polkit-1/rules.d/49-fairy-agent.rules
fairy-agent version                           # must say: signed-release key: built in
```

(If you had changed your own `fairy-agent.service`, keep yours and only add these two lines under
`[Service]`: `StateDirectory=fairy-agent` and `StateDirectoryMode=0700`.)

Switch self-update on. It needs the control token; check that the file exists:

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

Check and restart:

```sh
runuser -u fairy-agent -- fairy-agent check-config
systemctl daemon-reload && systemctl restart fairy-agent
systemctl status fairy-agent --no-pager       # "fairy-agent listening ... features=...self_update..."
```

`/root/fairy-update` can be deleted afterwards.

### 2.2 Windows PCs, PowerShell as Administrator

```powershell
$ProgressPreference = 'SilentlyContinue'
$d = "$env:TEMP\fairy-update"; New-Item -ItemType Directory -Force $d | Out-Null; cd $d
$rel = 'https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download'
foreach ($f in 'fairy-agent-windows-amd64.exe', 'SHA256SUMS', 'VERSION') { Invoke-WebRequest "$rel/$f" -OutFile $f }
Invoke-WebRequest 'https://raw.githubusercontent.com/n3ptune-cpu/Fairy-agent/main/deploy/install-fairy-agent.ps1' -OutFile install-fairy-agent.ps1
$want = ((Select-String -Path SHA256SUMS -Pattern 'fairy-agent-windows-amd64.exe$').Line -split '\s+')[0]
$got = (Get-FileHash fairy-agent-windows-amd64.exe -Algorithm SHA256).Hash.ToLower()
if ($got -eq $want) { 'OK: checksum matches' } else { 'MISMATCH: stop here' }
```

Only if it said OK:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install-fairy-agent.ps1 -PanelAddress 100.64.0.2     # the panel's Tailscale address; add -LocalSystem on a
                                                     # new install that needs fan control or Core Temp
notepad C:\ProgramData\fairy-agent\config.yaml
```

Add at the end of `config.yaml`:

```yaml
self_update:
  enabled: true
```

then `Restart-Service fairy-agent`. The install script also sets up what self-update needs (safe to run again):
the **fairy-agent-update** service (LocalSystem, started on demand) that installs signed releases, and the
download folder `C:\ProgramData\fairy-agent\update\stage`. The agent itself cannot change
`C:\Program Files\Fairy`. On a PC that ran 0.4.2 or older, run this once after it is on 0.4.3 (through the
panel or by hand), in PowerShell as Administrator; it also takes back the write access 0.4.2 gave the agent:

```powershell
& "C:\Program Files\Fairy\fairy-agent.exe" setup-self-update
```

The control token is in `C:\ProgramData\fairy-agent\control-token`.

---

## Part 3: the panel (CT 124, as root)

### 3.1 Install the release build of the panel once

```sh
mkdir -p /root/fairy-update && cd /root/fairy-update && rm -f ./*
REL=https://github.com/n3ptune-cpu/Fairy-dashboard/releases/latest/download
curl -fsSL -O "$REL/fairy-linux-amd64" -O "$REL/SHA256SUMS" -O "$REL/VERSION"
sha256sum -c --ignore-missing SHA256SUMS      # both OK, else stop
install -m 0755 fairy-linux-amd64 /usr/local/bin/fairy.new && mv /usr/local/bin/fairy.new /usr/local/bin/fairy
curl -fsSL https://raw.githubusercontent.com/n3ptune-cpu/Fairy-dashboard/main/deploy/fairy-update -o /usr/local/sbin/fairy-update
chmod 0755 /usr/local/sbin/fairy-update
systemctl restart fairy && fairy version      # must say: release key: built in
```

### 3.2 Tell the panel which agents may update

In `/etc/fairy/fairy.env`, each agent with self-update needs its control token (you may already have it for
power control):

```sh
AGENT_CONTROL_TOKEN_KACHINA=paste-the-agent's-control-token
```

In `/etc/fairy/config.yaml`, add to each such agent entry:

```yaml
  - id: kachina-agent
    # ...as before...
    control_token_env: AGENT_CONTROL_TOKEN_KACHINA
    self_update: true
```

The panel looks up the newest Fairy-agent release on GitHub (at most every 10 minutes, only while the Updates
page is open). If CT 124 has no internet access, add `updates: {check_latest: false}`; the page then shows no
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

Linux details: `journalctl -u fairy-agent-update` (installer), `journalctl -u fairy-agent` (agent). Windows:
`C:\ProgramData\fairy-agent\update\installer.log` (installer), `C:\ProgramData\fairy-agent\logs\agent.log`
(agent). The panel's own version is on the same page, with "Panel update
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

On CT 124, as root:

```sh
fairy update --check     # installed vs latest
fairy update             # asks, then installs, restarts fairy.service, checks it, rolls back if needed
fairy-update             # the same (the small wrapper from 3.1)
```

### Going back by hand

* Linux agent: `mv /usr/local/bin/fairy-agent.old /usr/local/bin/fairy-agent && systemctl restart fairy-agent`
* Windows agent: `Stop-Service fairy-agent`, rename `C:\Program Files\Fairy\fairy-agent.exe.old` to
  `fairy-agent.exe` (rename the current one away first), `Start-Service fairy-agent`
* Panel: `mv /usr/local/bin/fairy.old /usr/local/bin/fairy && systemctl restart fairy`

Agents never install a release older than the one they run; the panel only with `fairy update --force`.
