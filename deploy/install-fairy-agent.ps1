#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs (or updates) fairy-agent on this Windows PC.

.DESCRIPTION
  1. checks fairy-agent-windows-amd64.exe (next to this script) against SHA256SUMS when that file is next to it
     (install.ps1 has checked its signature), takes back the write access to C:\Program Files\Fairy that
     fairy-agent 0.4.2 and older gave the service, copies the program to C:\Program Files\Fairy\fairy-agent.exe
     and checks the copy before running it
  2. installs the "fairy-agent" Windows service (first time only; creates C:\ProgramData\fairy-agent with
     config.yaml, token and control-token, readable only by administrators, SYSTEM and the service). The service
     runs as its own virtual account NT SERVICE\fairy-agent (no password, cannot sign in, almost no rights).
     An existing installation that runs as LocalService or LocalSystem (fairy-agent 0.4.x) is moved to that
     account; config and tokens are kept
  2b. when Core Temp, IPMI / fan control or power control is switched on in config.yaml (or with -Helper):
     the "fairy-agent-helper" service (LocalSystem, no network, a local pipe only the agent's account may use,
     a fixed list of requests) that reads Core Temp and the BMC, sets fans and shuts down / reboots / sleeps
     for the agent, plus two firewall rules (in and out) that block all network traffic of that service
  3. allows the panel in through Windows Firewall: TCP port 9101, only on the Tailscale network adapter and only
     from Tailscale addresses (100.64.0.0/10, or just the panel's address with -PanelAddress)
  4. sets up what the panel's Update button needs (only used when self_update is enabled in config.yaml): the
     "fairy-agent-update" service (LocalSystem, started on demand, installs only releases signed with the key
     built into the installed program) which the agent's own account (NT SERVICE\fairy-agent) may start, and
     C:\ProgramData\fairy-agent\update\stage for the download. The agent's account cannot change anything in
     C:\Program Files\Fairy. Safe to run again.
  5. checks the configuration and starts the service

  Run it again with a newer fairy-agent-windows-amd64.exe to update by hand; config and tokens are kept.

.PARAMETER Helper
  Also install the elevated helper service (fairy-agent-helper), even if config.yaml does not switch on Core
  Temp, IPMI, fan or power control yet (install.ps1 passes it when you chose one of those in the panel).

.PARAMETER LocalSystem
  Deprecated: the agent no longer runs as LocalSystem. Means the same as -Helper.

.PARAMETER PanelAddress
  The Tailscale address of the Fairy panel, e.g. 100.64.0.2. Default: any Tailscale address (100.64.0.0/10).

.PARAMETER Quiet
  Leave out the "next steps" at the end (install.ps1, the panel's Add host, pairs the tokens by itself).

.EXAMPLE
  .\install-fairy-agent.ps1 -PanelAddress 100.64.0.2
#>
param(
    [switch]$Helper,
    [switch]$LocalSystem,
    [string]$PanelAddress = '100.64.0.0/10',
    [int]$Port = 9101,
    [switch]$Quiet
)
$ErrorActionPreference = 'Stop'
if ($LocalSystem) {
    Write-Warning '-LocalSystem is deprecated: the agent now runs as NT SERVICE\fairy-agent and the elevated helper service is installed instead (same as -Helper).'
    $Helper = $true
}

$src = Join-Path $PSScriptRoot 'fairy-agent-windows-amd64.exe'
if (-not (Test-Path -LiteralPath $src)) { $src = Join-Path $PSScriptRoot 'fairy-agent.exe' }
if (-not (Test-Path -LiteralPath $src)) { throw "fairy-agent-windows-amd64.exe not found next to this script" }

function Get-Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLower() }

# The program must match the release's SHA256SUMS (signature checked by install.ps1) when that file is here.
$srcHash = Get-Sha256 $src
$sumsFile = Join-Path $PSScriptRoot 'SHA256SUMS'
if (Test-Path -LiteralPath $sumsFile) {
    $want = $null
    foreach ($line in Get-Content -LiteralPath $sumsFile) {
        $p = $line -split '\s+', 2
        if ($p.Count -eq 2 -and $p[1].TrimStart('*') -eq 'fairy-agent-windows-amd64.exe') { $want = $p[0].ToLower() }
    }
    if (-not $want) { throw 'fairy-agent-windows-amd64.exe is not listed in SHA256SUMS' }
    if ($srcHash -ne $want) { throw "$src does not match SHA256SUMS (corrupted or tampered download)" }
    Write-Host 'fairy: program checksum matches SHA256SUMS'
} else {
    Write-Warning 'No SHA256SUMS next to this script: the program''s checksum was not checked (AGENT.md shows how to check it by hand).'
}

$sys = Join-Path $env:SystemRoot 'System32'
$dir = Join-Path $env:ProgramFiles 'Fairy'
$exe = Join-Path $dir 'fairy-agent.exe'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$svc = Get-Service -Name 'fairy-agent' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name 'fairy-agent' }
# the helper runs the same program: stop it too (it hands the fans back to the BMC's automatic mode first)
$helperSvc = Get-Service -Name 'fairy-agent-helper' -ErrorAction SilentlyContinue
if ($helperSvc -and $helperSvc.Status -ne 'Stopped') { Stop-Service -Name 'fairy-agent-helper' }
if ($svc) {
    # fairy-agent 0.4.2 and older let the service's own account change this folder (for self-update). Take that
    # back BEFORE copying, so nothing can swap the program between the copy and the check below.
    & (Join-Path $sys 'icacls.exe') $dir /remove:g 'NT SERVICE\fairy-agent' /T /C /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "could not remove the service's write access to $dir (icacls exit code $LASTEXITCODE)" }
}
# a new file, so it is owned by Administrators (0.4.2's in-service updater left one owned by the service account)
if (Test-Path -LiteralPath $exe) { Remove-Item -LiteralPath $exe -Force }
Copy-Item -LiteralPath $src -Destination $exe -Force
Unblock-File -LiteralPath $exe
# Run the installed program (as Administrator) only if it is exactly the checked one.
if ((Get-Sha256 $exe) -ne $srcHash) { throw "$exe is not the program that was checked: not running it" }
& $exe version

$helperArg = @()
if ($Helper) { $helperArg = @('--helper') }
if (-not $svc) {
    & $exe install @helperArg
    if ($LASTEXITCODE -ne 0) { throw 'fairy-agent install failed' }
} else {
    # existing installs: move to NT SERVICE\fairy-agent, permissions, updater, helper (idempotent)
    & $exe setup-self-update @helperArg
    if ($LASTEXITCODE -ne 0) { throw 'fairy-agent setup-self-update failed' }
}

$ruleName = 'Fairy agent (Tailscale only)'
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
$rule = @{ DisplayName = $ruleName; Direction = 'Inbound'; Action = 'Allow'; Protocol = 'TCP'; LocalPort = $Port;
           RemoteAddress = $PanelAddress; Program = $exe; Profile = 'Any' }
if (Get-NetAdapter -Name 'Tailscale' -ErrorAction SilentlyContinue) {
    $rule.InterfaceAlias = 'Tailscale'
} else {
    Write-Warning 'No network adapter named "Tailscale" found: the firewall rule is limited by address only.'
}
New-NetFirewallRule @rule | Out-Null

# The helper never uses the network: block everything in and out for its service (and anything it starts).
# install / setup-self-update above already add these two rules (the agent adds them too when it moves itself
# off LocalSystem); this only makes sure both directions exist, the same rules either way.
$helperRule = 'Fairy agent helper (no network)'
if (Get-Service -Name 'fairy-agent-helper' -ErrorAction SilentlyContinue) {
    $have = @(Get-NetFirewallRule -DisplayName $helperRule -ErrorAction SilentlyContinue |
              Where-Object { $_.Action -eq 'Block' } | ForEach-Object { $_.Direction.ToString() })
    try {
        foreach ($d in 'Outbound', 'Inbound') {
            if ($have -notcontains $d) {
                New-NetFirewallRule -DisplayName $helperRule -Direction $d -Action Block -Service 'fairy-agent-helper' -Profile Any | Out-Null
            }
        }
    } catch { Write-Warning "could not add the firewall rule '$helperRule': $_" }
} else {
    Get-NetFirewallRule -DisplayName $helperRule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

& $exe check-config
if ($LASTEXITCODE -ne 0) { throw 'fix C:\ProgramData\fairy-agent\config.yaml, then: Start-Service fairy-agent' }
if ((Get-Service -Name 'fairy-agent-helper' -ErrorAction SilentlyContinue) -and (Get-Service -Name 'fairy-agent-helper').Status -ne 'Running') {
    Start-Service -Name 'fairy-agent-helper'
}
Start-Service -Name 'fairy-agent'
Get-Service -Name 'fairy-agent', 'fairy-agent-helper' -ErrorAction SilentlyContinue | Format-Table -AutoSize Name, Status, StartType

if ($Quiet) { return }
Write-Host ''
Write-Host 'Done. Next: put this PC''s token into the panel (see AGENT.md, "Point the panel at it"):'
Write-Host '  Get-Content C:\ProgramData\fairy-agent\token'
Write-Host 'Log file: C:\ProgramData\fairy-agent\logs\agent.log'
