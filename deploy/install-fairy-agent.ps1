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
     config.yaml, token and control-token, readable only by administrators, SYSTEM and the service)
  3. allows the panel in through Windows Firewall: TCP port 9101, only on the Tailscale network adapter and only
     from Tailscale addresses (100.64.0.0/10, or just the panel's address with -PanelAddress)
  4. sets up what the panel's Update button needs (only used when self_update is enabled in config.yaml): the
     "fairy-agent-update" service (LocalSystem, started on demand, installs only releases signed with the key
     built into the installed program) which the agent's own account (NT SERVICE\fairy-agent) may start, and
     C:\ProgramData\fairy-agent\update\stage for the download. The agent's account cannot change anything in
     C:\Program Files\Fairy. Safe to run again.
  5. checks the configuration and starts the service

  Run it again with a newer fairy-agent-windows-amd64.exe to update by hand; config and tokens are kept.

.PARAMETER LocalSystem
  Run the service as LocalSystem instead of LocalService. Only needed for IPMI / fan control on a Supermicro
  board (Windows' IPMI driver is for administrators) and to see the details of every program in the Processes
  tab. Has no effect when the service already exists (uninstall first to change the account).

.PARAMETER PanelAddress
  The Tailscale address of the Fairy panel, e.g. 100.64.0.2. Default: any Tailscale address (100.64.0.0/10).

.PARAMETER Quiet
  Leave out the "next steps" at the end (install.ps1, the panel's Add host, pairs the tokens by itself).

.EXAMPLE
  .\install-fairy-agent.ps1 -PanelAddress 100.64.0.2
#>
param(
    [switch]$LocalSystem,
    [string]$PanelAddress = '100.64.0.0/10',
    [int]$Port = 9101,
    [switch]$Quiet
)
$ErrorActionPreference = 'Stop'

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

if (-not $svc) {
    $account = if ($LocalSystem) { 'LocalSystem' } else { 'LocalService' }
    & $exe install --account $account
    if ($LASTEXITCODE -ne 0) { throw 'fairy-agent install failed' }
} else {
    & $exe setup-self-update   # existing installs: the updater service and permissions (idempotent)
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

& $exe check-config
if ($LASTEXITCODE -ne 0) { throw 'fix C:\ProgramData\fairy-agent\config.yaml, then: Start-Service fairy-agent' }
Start-Service -Name 'fairy-agent'
Get-Service -Name 'fairy-agent' | Format-Table -AutoSize Name, Status, StartType

if ($Quiet) { return }
Write-Host ''
Write-Host 'Done. Next: put this PC''s token into the panel (see AGENT.md, "Point the panel at it"):'
Write-Host '  Get-Content C:\ProgramData\fairy-agent\token'
Write-Host 'Log file: C:\ProgramData\fairy-agent\logs\agent.log'
