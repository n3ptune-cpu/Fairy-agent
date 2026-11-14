# Fairy-agent

> [!WARNING]
> Heads up: this whole thing was written by AI. We're not programmers,
> so we can't help you set it up or fix your install. If you want a
> feature or found a bug, open an issue and we'll have the AI look at it.
> It might not work on your hardware.
>
> It's MIT, so no warranty, use it at your own risk. Nobody has
> professionally security-tested it. It can shut down and reboot PCs
> and change fan speeds if you turn those on, and on Windows part of
> it runs as SYSTEM. Only connect to the agents over Tailscale, never
> straight from the internet, and only install from our Releases page.

`fairy-agent` is the small metrics agent for the Fairy homelab panel
([Fairy-dashboard](https://github.com/n3ptune-cpu/Fairy-dashboard)). It runs on each watched Windows or Linux
machine and answers the panel over Tailscale: `/metrics`, `/processes`, and, only when the machine's owner turns
them on, fan control, shutdown / reboot, Wake-on-LAN and self-update from the panel's Update button. It never
installs a driver and never touches other programs' memory, so it is safe next to kernel anti-cheat.

**Installing and configuring it: see [AGENT.md](AGENT.md).**

This repository also holds the Go packages the agent and the panel share (`pkg/`): the panel imports them from
here (`github.com/n3ptune-cpu/Fairy-agent/pkg/...`), so there is one copy of the device code.

## Build

Go 1.27.4 or newer. Releases are built with Go 1.27.4: the workflows take the Go version from the `go` line
in `go.mod`. One static binary per platform, no runtime dependencies:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o fairy-agent-windows-amd64.exe ./cmd/fairy-agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o fairy-agent-linux-amd64 ./cmd/fairy-agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o fairy-agent-linux-arm64 ./cmd/fairy-agent
go test ./... && go vet ./...
```

Builds like these carry no release key (`-X main.releaseKey=...`), so they never update themselves. The
binaries that agents install come from the release workflow below.

The tests run on Windows too: `go test ./...` in a normal cmd window (not "Run as administrator"), on a PC
with or without the agent. They install nothing, need no service and work in their own temporary folders.
Where a test needs a link it makes a junction, which every user may create. A few tests skip themselves on
Windows and say why (`go test -v ./... | findstr SKIP`): the ones that need administrator rights, the four
that start the whole agent (it looks for the helper service), and the one that would ask the PC's own BMC.

`go.mod` also has the line `godebug multipathtcp=0`: the programs built from this module do not use Multipath
TCP, which Go otherwise switches on for listeners on Linux. `go version -m fairy-agent-linux-amd64` shows
`DefaultGODEBUG=multipathtcp=0`. The line does not reach programs that only import the packages:
Fairy-dashboard needs the same line in its own `go.mod`.

**For maintainers: the next Go patch release.** When Go 1.27.5 is published:

1. Check that it can be downloaded: `GOTOOLCHAIN=go1.27.5 go version` prints `go version go1.27.5 ...`. While
   it is not published, the command ends with `toolchain not available`.
2. Set `go 1.27.5` in this repository's `go.mod` first. Fairy-dashboard depends on this module, so its own
   `go.mod` must then say at least the same.
3. Run the checks: `go build ./... && go vet ./... && GOOS=windows go vet ./... && go test ./... -race`, and
   the two cross-builds `GOOS=windows GOARCH=amd64 go build ./...` and `GOOS=linux GOARCH=arm64 go build ./...`.
4. Release again (below), then do the same in Fairy-dashboard.

## Releases and self-update

Every push to `main` that changes more than Markdown files (`*.md`) runs `.github/workflows/release.yml`. The
run waits for the owner's approval, because the signing key is a secret of the GitHub Environment `release`
(see [SETUP-UPDATES.md](SETUP-UPDATES.md#13-put-the-private-key-into-github-both-repositories)). Then: vet,
test, build the three binaries with the version
`<run number>-<short commit>` and the public key from `release/signing.pub`, write `SHA256SUMS` and `VERSION`,
add the Add host installers (`install.sh`, `install.ps1`) and the files they install, sign `SHA256SUMS` (which
lists all of them) with the `FAIRY_RELEASE_KEY` secret and publish the GitHub release `build-<run number>` as
"latest". (Release tags are never `vX.Y.Z`: those are Go module versions, below.) Pull requests run
`ci.yml` (tests only). Nothing is installed anywhere until an admin presses Update in the panel; see
[SETUP-UPDATES.md](SETUP-UPDATES.md) for the one-time key setup and [AGENT.md](AGENT.md#updates-the-panels-update-button)
for how an agent updates itself.

`go run ./cmd/fairy-release-key gen` makes the key pair (once, on the owner's PC), `sign` / `verify` are used by
the workflow. The same key signs Fairy-dashboard's releases (`fairy update` on the panel host).

The panel <-> agent contract test lives in Fairy-dashboard (`internal/agentcontract`): it runs the panel's real
poller and web API against this repository's agent handler.

## Versions

Fairy-dashboard pins a tagged version of this module in its `go.mod` (and the hashes in its `go.sum`). A change
to `pkg/` reaches the panel like this: commit and tag here (`git tag -a vX.Y.Z -m vX.Y.Z` with the new version's
number, push the commit and the tag), then in Fairy-dashboard run
`go get github.com/n3ptune-cpu/Fairy-agent@vX.Y.Z && go mod tidy`. Never move or
re-create a tag that was pushed: Go's checksum database remembers the first contents it saw for each version.

## Map of the code

Each folder is one Go package; inside a package, files are named after what they contain.

| Folder | What it does |
| --- | --- |
| `cmd/fairy-agent` | The `fairy-agent` program: `main.go` (run, check-config, gen-token, update, apply-update, fans-auto, version), `config_cmd.go` (`config get/set/show`), `join.go` (`join`, `pair-status`, `verify-release`: the machine side of the panel's Add host), `service_windows.go` (the Windows services: install as `NT SERVICE\fairy-agent`, uninstall, setup-self-update with the LocalSystem updater service, run under the service manager), `helper_windows.go` (the fairy-agent-helper service: setup with its rights, `helper-status`, `remove-helper`, the account migration), `trust_cmd.go` (`helper-trust set / show / clear`: the approval trust, changed on the machine; `trust_unix.go`: as whom root works in the agent's state folder on Linux), `run_cmd.go` (`helper-run show / cancel`: the run this machine is in, looked at and called off on the machine), `migrate_windows.go` (a LocalSystem agent moving itself to `NT SERVICE\fairy-agent`, and the updater service finishing it). |
| `cmd/fairy-release-key` | The release signing key: `gen` (owner, once), `sign` and `verify` (release workflow). |
| `pkg/agent` | The agent's HTTP server and the panel contract (`server.go`), settings and tokens (`config.go`), BMC sensors (`bmc.go`), Supermicro fan control and its watchdog (`fan.go`), shutdown / reboot (`power*.go`), Wake-on-LAN (`wol.go`), plugs and UPSes it relays (`relay.go`), self-update and its installer (`update*.go`), Tailscale address (`listen.go`), start-up (`run.go`), log file (`logfile.go`), the one-time `POST /pair` of Add host (`pairing.go`), the Windows helper's client and `/helper/stop`, `/helper/start` (`helper*.go`), the update installer's health check `GET /health` (`health.go`), the process's logger with the guard in front of Go's standard logger (`stdlog.go`: `SetLog`, which every program here uses instead of `slog.SetDefault`). |
| `pkg/agent/api` | Contract types the panel imports: the `/metrics` "helper" and "migration" blocks, the "unavailable" list, the helper endpoints. `approval.go`: the passkey approval as the panel sees it (the two routes, the "approval" field and block, the canonical request text, the nonce, the hash of a proposed trust, codes and limits), and runs (0.9.0: the ticket and the confirmation of a wake / update / shutdown run, their two request texts and limits, `POST /run/arm` and `/run/go`, `"runs"` and `"run"` of the block, the reasons of a refusal). |
| `pkg/approval` | The passkey approval check itself, standard library only: the trust file (`trust.go`, `files.go`), the offline check of the ID token (`token.go`), challenges, fan window, shutdown-after-boot and the first-time set with its proof (`gate.go`: `Precheck` when a request arrives, which uses nothing up; `Admit` when it is about to be carried out, which uses the approval up; `Pass.Applied` when a fan change was applied, which opens the fan window). Used by the Windows helper and by every agent for what it carries out itself (`pkg/agent/approval.go` decides who checks which request). Runs (AGENT.md, "Runs"): `run.go` (`Arm`: the ticket and the rules that stand in for the challenge; `Go`: the confirmation; `RunCovers` / `AdmitRun`: the run's one update and one shutdown; `DisarmRun`), `runfile.go` (the run record `approval-run.json`, with the trust file's checks), `runwatch.go` (the wait on the uptime, the vetoes, the self-off, the cancel). `approvaltest/`: a made-up issuer for tests. |
| `pkg/agent/migrate` | The Windows self-migration from LocalSystem as a state machine (steps, state file, rollback, pauses, the restart check), platform-independent and tested on Linux. |
| `pkg/helper` | fairy-agent-helper, the Windows LocalSystem helper: its verbs, rate limits, audit log and fan watchdog (`helper.go`), the service and pipe glue (`serve_windows.go`). `proto/`: the pipe protocol (frames, the fixed verbs and their schema; platform-independent). `winpipe/`: the named pipe (overlapped I/O, client identity checks; Windows only). |
| `pkg/enroll` | Add host's join codes, shared with the panel: the code, the proof the panel sends, the verifier the agent stores, the pairing state file, and pairing v2 (`v2.go`: the panel proves it has the code, the agent's answer is encrypted). |
| `pkg/release` | Signed releases, shared with the panel's `fairy update`: signature and SHA256SUMS checks, the GitHub download (fixed hosts, size and time limits), and the swap / restart / health check / rollback installer; `releasetest/` is a fake GitHub for tests. |
| `pkg/agent/collect` | What the agent measures: Linux `/proc` and `/sys` (`procfs.go`, `linux.go`), Windows APIs, registry and PDH (`windows.go`, `pdh_windows.go`), NVIDIA GPUs via nvidia-smi (`nvidia.go`), AMD GPUs via amdgpu sysfs (`amdgpu.go`), laptop batteries (`battery.go`), Core Temp's shared memory on Windows (`coretemp*.go`). |
| `pkg/agent/ipmi` | Raw IPMI to the BMC: sensor list and readings (`sdr.go`), Supermicro fan commands (`ipmi.go`), through ipmitool or Windows' IPMI WMI class (`ipmitool.go`, `wmi_windows.go`); `fakebmc/` for tests. |
| `pkg/agent/configedit` | `fairy-agent config set`: changes one setting's text in config.yaml (comments, order and layout stay), checks the result, and replaces the file in one step keeping its owner, permissions and Windows access list. |
| `pkg/agent/agenttest` | Fakes for tests (here and in the panel's contract test): a collector, a GPU, a power executor, the Windows helper. |
| `pkg/devices` | Device protocols shared with the panel: Shelly/Tasmota/Redfish parsing, Home Assistant state objects, NUT client, HTTP helpers (basic, digest and bearer auth), and `Describe` (errors as short messages without secrets). |
| `pkg/power` | One power source per device type (`shelly.go`, `tasmota.go`, `nut.go`, `redfish.go`, `homeassistant.go`, `agentpower.go`), built from a `power_sources:` entry (`build.go`; an entry of the removed type `tuya` is taken out with a warning, `DropRemoved`). The agent relays them; the panel adds backoff, totals and history. |
| `pkg/ups` | NUT UPS sources built from an `ups:` entry, and which systems each UPS powers. |
| `pkg/redact` | Removes passwords/tokens from process command lines (in the agent, and again in the panel). |
| `pkg/configutil` | The id rule (`ValidID`) and secrets referenced by environment variable name (`EnvSecret`). |
| `deploy/` | `install.sh` / `install.ps1` (the one-line Add host installers, published with every release), `fairy-agent.service` (systemd), `fairy-agent-update.service` (the self-update installer), `fairy-agent.config.example.yaml`, `install-fairy-agent.ps1` (Windows), and the optional rules: polkit (`fairy-agent-power.polkit.rules` for shutdown / reboot, `fairy-agent-update.polkit.rules` for self-update: one file per feature), tmpfiles, udev. |
| `.github/workflows` | `release.yml` (signed release on every push to main that changes more than `*.md` files), `ci.yml` (tests on pull requests). |

## Licence

MIT, see [LICENSE](LICENSE).
