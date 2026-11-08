#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Installs (or updates) fairy-agent on this Windows PC.

.DESCRIPTION
  1. copies fairy-agent-windows-amd64.exe (next to this script) to C:\Program Files\Fairy\fairy-agent.exe
  2. installs the "fairy-agent" Windows service (first time only; creates C:\ProgramData\fairy-agent with
     config.yaml, token and control-token, readable only by administrators, SYSTEM and the service)
  3. allows the panel in through Windows Firewall: TCP port 9101, only on the Tailscale network adapter and only
     from Tailscale addresses (100.64.0.0/10, or just the panel's address with -PanelAddress)
  4. gives the service what the panel's Update button needs (only used when self_update is enabled in
     config.yaml): its own account (NT SERVICE\fairy-agent) may replace files in C:\Program Files\Fairy, write
     C:\ProgramData\fairy-agent\update and stop / start its own service. Safe to run again.
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
if (-not (Test-Path $src)) { $src = Join-Path $PSScriptRoot 'fairy-agent.exe' }
if (-not (Test-Path $src)) { throw "fairy-agent-windows-amd64.exe not found next to this script" }

$dir = Join-Path $env:ProgramFiles 'Fairy'
$exe = Join-Path $dir 'fairy-agent.exe'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$svc = Get-Service -Name 'fairy-agent' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne 'Stopped') { Stop-Service -Name 'fairy-agent' }
Copy-Item -Path $src -Destination $exe -Force
Unblock-File -Path $exe
& $exe version

if (-not $svc) {
    $account = if ($LocalSystem) { 'LocalSystem' } else { 'LocalService' }
    & $exe install --account $account
    if ($LASTEXITCODE -ne 0) { throw 'fairy-agent install failed' }
} else {
    & $exe setup-self-update   # existing installs: add the self-update permissions (idempotent)
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
