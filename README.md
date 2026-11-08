# Fairy-agent

`fairy-agent` is the small metrics agent for the Fairy homelab panel
([Fairy-dashboard](https://github.com/n3ptune-cpu/Fairy-dashboard)). It runs on each watched Windows or Linux
machine and answers the panel over Tailscale: `/metrics`, `/processes`, and, only when the machine's owner turns
them on, fan control, shutdown / reboot and Wake-on-LAN. It never installs a driver and never touches other
programs' memory, so it is safe next to kernel anti-cheat.

**Installing and configuring it: see [AGENT.md](AGENT.md).**

This repository also holds the Go packages the agent and the panel share (`pkg/`): the panel imports them from
here (`github.com/n3ptune-cpu/Fairy-agent/pkg/...`), so there is one copy of the device code.

## Build

Go 1.27.3 or newer. One static binary per platform, no runtime dependencies:

```sh
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o fairy-agent-windows-amd64.exe ./cmd/fairy-agent
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o fairy-agent-linux-amd64 ./cmd/fairy-agent
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.version=$(git describe --always)" -o fairy-agent-linux-arm64 ./cmd/fairy-agent
go test ./... && go vet ./...
```

The panel <-> agent contract test lives in Fairy-dashboard (`internal/agentcontract`): it runs the panel's real
poller and web API against this repository's agent handler.

## Versions

Fairy-dashboard pins a tagged version of this module in its `go.mod` (and the hashes in its `go.sum`). A change
to `pkg/` reaches the panel like this: commit and tag here (`git tag -a v0.1.1 -m v0.1.1`, push the commit and the
tag), then in Fairy-dashboard run `go get github.com/n3ptune-cpu/Fairy-agent@v0.1.1 && go mod tidy`. Never move or
re-create a tag that was pushed: Go's checksum database remembers the first contents it saw for each version.

## Map of the code

Each folder is one Go package; inside a package, files are named after what they contain.

| Folder | What it does |
| --- | --- |
| `cmd/fairy-agent` | The `fairy-agent` program: `main.go` (run, check-config, gen-token, version), `service_windows.go` (the Windows service: install, uninstall, run under the service manager). |
| `pkg/agent` | The agent's HTTP server and the panel contract (`server.go`), settings and tokens (`config.go`), BMC sensors (`bmc.go`), Supermicro fan control and its watchdog (`fan.go`), shutdown / reboot (`power*.go`), Wake-on-LAN (`wol.go`), plugs and UPSes it relays (`relay.go`), Tailscale address (`listen.go`), start-up (`run.go`), log file (`logfile.go`). |
| `pkg/agent/collect` | What the agent measures: Linux `/proc` and `/sys` (`procfs.go`, `linux.go`), Windows APIs, registry and PDH (`windows.go`, `pdh_windows.go`), NVIDIA GPUs via nvidia-smi (`nvidia.go`), AMD GPUs via amdgpu sysfs (`amdgpu.go`), laptop batteries (`battery.go`), Core Temp's shared memory on Windows (`coretemp*.go`). |
| `pkg/agent/ipmi` | Raw IPMI to the BMC: sensor list and readings (`sdr.go`), Supermicro fan commands (`ipmi.go`), through ipmitool or Windows' IPMI WMI class (`ipmitool.go`, `wmi_windows.go`); `fakebmc/` for tests. |
| `pkg/agent/agenttest` | A fake collector for tests (here and in the panel's contract test). |
| `pkg/devices` | Device protocols shared with the panel: Shelly/Tasmota/Redfish/Tuya parsing, NUT client, HTTP helpers, digest auth, and `Describe` (errors as short messages without secrets). |
| `pkg/power` | One power source per device type (`shelly.go`, `tasmota.go`, `tuya.go`, `nut.go`, `redfish.go`, `agentpower.go`), built from a `power_sources:` entry (`build.go`). The agent relays them; the panel adds backoff, totals and history. |
| `pkg/ups` | NUT UPS sources built from an `ups:` entry, and which systems each UPS powers. |
| `pkg/tuya` | The Tuya 3.3/3.4/3.5 local protocol (encryption, frames, one persistent connection per plug). |
| `pkg/redact` | Removes passwords/tokens from process command lines (in the agent, and again in the panel). |
| `pkg/configutil` | The id rule (`ValidID`) and secrets referenced by environment variable name (`EnvSecret`). |
| `deploy/` | `fairy-agent.service` (systemd), `fairy-agent.config.example.yaml`, `install-fairy-agent.ps1` (Windows), and the optional polkit / tmpfiles / udev rules. |

## Licence

MIT, see [LICENSE](LICENSE).
