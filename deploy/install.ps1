#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Fairy agent installer for Windows, the machine side of the panel's "Add host". One line in an
  Administrator PowerShell (the panel shows it with the code filled in):

  iwr https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download/install.ps1 -OutFile $env:TEMP\fairy-install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\fairy-install.ps1 -Join CODE -PanelAddress 100.x.y.z [-PowerControl] [-SelfUpdate] [-Wol] [-Ups] [-UpsName NAME] [-CoreTemp] [-Ipmi]

.DESCRIPTION
  1. downloads the latest release: fairy-agent-windows-amd64.exe, SHA256SUMS (+ signature), VERSION and
     install-fairy-agent.ps1, and checks each file's SHA-256 against SHA256SUMS and SHA256SUMS' signature with
     fairy-agent's built-in release key (the installed agent's key on a re-run);
  2. runs install-fairy-agent.ps1: program in C:\Program Files\Fairy, the service (LocalSystem when Core Temp
     or IPMI is chosen, else LocalService), folder permissions, the firewall rule for the panel only;
  3. runs `fairy-agent join`: tokens, the chosen settings and the one-time join code (nothing secret is shown);
  4. restarts the service and waits until the panel has picked up the tokens.

  Safe to run again (e.g. with a new code from the panel's Re-pair): tokens and settings are kept. No driver,
  no other program touched.
#>
param(
    [Parameter(Mandatory = $true)][string]$Join,
    [Parameter(Mandatory = $true)][string]$PanelAddress,
    [switch]$PowerControl,
    [switch]$SelfUpdate,
    [switch]$Wol,
    [switch]$Ups,
    [string]$UpsName = '',
    [switch]$CoreTemp,
    [switch]$Ipmi,
    [string]$ReleaseUrl = 'https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($PanelAddress -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "-PanelAddress must be the panel's Tailscale IPv4 address, e.g. 100.88.109.47" }

# Runs a native program without letting Windows PowerShell 5.1 turn its stderr into a terminating error.
function Invoke-Quiet([string]$cmd, [string[]]$cmdArgs) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $cmd @cmdArgs 2>&1 | Out-String } finally { $ErrorActionPreference = $old }
    return @{ Code = $LASTEXITCODE; Text = $out.Trim() }
}

$dir = Join-Path $env:TEMP ('fairy-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $dir | Out-Null
try {
    Write-Host "fairy: downloading the latest release from $ReleaseUrl"
    $files = 'fairy-agent-windows-amd64.exe', 'SHA256SUMS', 'SHA256SUMS.sig', 'VERSION', 'install-fairy-agent.ps1'
    foreach ($f in $files) { Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseUrl/$f" -OutFile (Join-Path $dir $f) }

    # 1. every file must be listed in SHA256SUMS with the same SHA-256
    $sums = @{}
    foreach ($line in Get-Content (Join-Path $dir 'SHA256SUMS')) {
        $p = $line -split '\s+', 2
        if ($p.Count -eq 2) { $sums[$p[1].TrimStart('*')] = $p[0].ToLower() }
    }
    foreach ($f in $files) {
        if ($f -like 'SHA256SUMS*') { continue }
        if (-not $sums.ContainsKey($f)) { throw "$f is not listed in SHA256SUMS" }
        $got = (Get-FileHash -Algorithm SHA256 (Join-Path $dir $f)).Hash.ToLower()
        if ($got -ne $sums[$f]) { throw "$f does not match SHA256SUMS (corrupted or tampered download)" }
    }

    # 2. the signature, with the release key built into fairy-agent (the installed one's on a re-run)
    $exe = Join-Path $env:ProgramFiles 'Fairy\fairy-agent.exe'
    $new = Join-Path $dir 'fairy-agent-windows-amd64.exe'
    Unblock-File $new
    $rc = 2
    if (Test-Path $exe) {
        $rc = (Invoke-Quiet $exe @('verify-release', $dir)).Code
        if ($rc -eq 1) { throw "the release signature does not match the installed fairy-agent's release key" }
    }
    if ($rc -ne 0) { $rc = (Invoke-Quiet $new @('verify-release', $dir)).Code }
    if ($rc -eq 0) { Write-Host ("fairy: release " + (Get-Content (Join-Path $dir 'VERSION')) + " verified (signature and hashes)") }
    elseif ($rc -eq 3) { Write-Warning 'this build has no release key: the signature was not checked (hashes only)' }
    else { throw 'the release signature check failed' }

    # 3. program, service, permissions, firewall (the existing installer script)
    $system = $CoreTemp -or $Ipmi
    $svc = Get-CimInstance Win32_Service -Filter "Name='fairy-agent'" -ErrorAction SilentlyContinue
    if ($svc -and $system -and $svc.StartName -ne 'LocalSystem') {
        Write-Host 'fairy: switching the service to LocalSystem (needed for Core Temp / IPMI)'
        Stop-Service fairy-agent -ErrorAction SilentlyContinue
        & sc.exe config fairy-agent obj= LocalSystem | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'sc.exe config fairy-agent obj= LocalSystem failed' }
    }
    $inst = @{ PanelAddress = $PanelAddress; Quiet = $true }
    if ($system) { $inst.LocalSystem = $true }
    & (Join-Path $dir 'install-fairy-agent.ps1') @inst

    # 4. tokens, settings and the join code (prints no secret)
    $joinArgs = @('join', '--code', $Join, '--panel', $PanelAddress)
    if ($PowerControl) { $joinArgs += '--power-control' }
    if ($SelfUpdate) { $joinArgs += '--self-update' }
    if ($Wol) { $joinArgs += '--wol' }
    if ($CoreTemp) { $joinArgs += '--coretemp' }
    if ($Ipmi) { $joinArgs += '--ipmi' }
    if ($UpsName) { $joinArgs += @('--ups-name', $UpsName) } elseif ($Ups) { $joinArgs += '--ups' }
    & $exe @joinArgs
    if ($LASTEXITCODE -ne 0) { throw 'fairy-agent join failed (see above)' }
    Restart-Service fairy-agent
    Write-Host 'fairy: started; waiting for the panel to pair (keep the Add host dialog open) ...'

    # 5. wait (up to 2 minutes) until the panel has picked up the tokens
    for ($i = 0; $i -lt 60; $i++) {
        if ((Invoke-Quiet $exe @('pair-status')).Code -eq 0) { Write-Host 'fairy: paired with the panel. The host appears there within a few seconds. Done.'; return }
        if ((Get-Service fairy-agent).Status -ne 'Running') {
            Get-Content (Join-Path $env:ProgramData 'fairy-agent\logs\agent.log') -Tail 15 -ErrorAction SilentlyContinue
            throw 'fairy-agent is not running (see above)'
        }
        Start-Sleep -Seconds 2
    }
    Write-Host ('fairy: not paired yet: ' + (Invoke-Quiet $exe @('pair-status')).Text)
    Write-Host 'fairy: the panel keeps trying while the code is valid; log: C:\ProgramData\fairy-agent\logs\agent.log'
} finally {
    Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
}
