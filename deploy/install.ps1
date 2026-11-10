#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Fairy agent installer for Windows, the machine side of the panel's "Add host".

  Use the one line from the panel's Add host (or Re-pair) dialog, in an Administrator PowerShell. It names one
  checked release, refuses to run this script unless its SHA-256 is the one the panel verified, and passes
  the release's fingerprint (-SumsSha256). There is no "latest" one-liner any more: nobody can check a line
  that downloads whatever is newest and runs it.

  install.ps1 -ReleaseUrl URL -SumsSha256 HASH -Join CODE -PanelAddress 100.x.y.z
              [-PowerControl] [-SelfUpdate] [-Wol] [-Ups] [-UpsName NAME] [-CoreTemp] [-Ipmi]

.DESCRIPTION
  1. downloads the release: fairy-agent-windows-amd64.exe, SHA256SUMS (+ signature), VERSION and
     install-fairy-agent.ps1, and checks each file's SHA-256 against SHA256SUMS and SHA256SUMS' signature with
     the release key built into the downloaded fairy-agent. An already installed fairy-agent.exe is never run
     before it has been replaced by the checked one (fairy-agent 0.4.2 and older let the service's own account
     change it);
  2. runs install-fairy-agent.ps1: program in C:\Program Files\Fairy, the service (as its own low-rights
     account NT SERVICE\fairy-agent; an older install running as LocalService or LocalSystem is moved to it),
     the elevated helper service fairy-agent-helper when Core Temp, IPMI or power control is chosen, folder
     permissions, the firewall rule for the panel only;
  3. runs `fairy-agent join`: tokens, the chosen settings and the one-time join code (nothing secret is shown);
  4. restarts the service and waits until the panel has picked up the tokens.

  -SumsSha256 <sha256 of SHA256SUMS>: the panel checks the release's signature with its own built-in key and
  passes this hash; the script then refuses a SHA256SUMS with any other hash before trusting a line of it (so
  even a first install does not rest on the downloaded program's own key). Without it the script does not
  run, unless -Unverified is given: then the downloaded program checks its own download, and the script says
  "NOT independently verified".

  Safe to run again (e.g. with a new code from the panel's Re-pair): settings are kept, the tokens are
  replaced by new ones (the panel gets them by pairing). No driver,
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
    [string]$SumsSha256 = '',
    [switch]$Unverified,
    [string]$ReleaseUrl = 'https://github.com/n3ptune-cpu/Fairy-agent/releases/latest/download'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

if ($PanelAddress -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "-PanelAddress must be the panel's Tailscale IPv4 address, e.g. 100.88.109.47" }
if ($SumsSha256 -and $SumsSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw '-SumsSha256 must be 64 hex digits (the SHA-256 of SHA256SUMS)' }
# The release's fingerprint from the panel. Without it nothing vouches for the download but the download itself.
if (-not $SumsSha256 -and -not $Unverified) {
    throw "no release fingerprint (-SumsSha256). Use the line from the panel's Add host dialog: it carries the fingerprint of the release the panel checked. To install without it, at your own risk, add -Unverified."
}

# Runs a native program without letting Windows PowerShell 5.1 turn its stderr into a terminating error.
function Invoke-Quiet([string]$cmd, [string[]]$cmdArgs) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $cmd @cmdArgs 2>&1 | Out-String } finally { $ErrorActionPreference = $old }
    return @{ Code = $LASTEXITCODE; Text = $out.Trim() }
}

$dir = Join-Path $env:TEMP ('fairy-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $dir | Out-Null
try {
    Write-Host "fairy: downloading the release from $ReleaseUrl"
    $files = 'fairy-agent-windows-amd64.exe', 'SHA256SUMS', 'SHA256SUMS.sig', 'VERSION', 'install-fairy-agent.ps1'
    foreach ($f in $files) { Invoke-WebRequest -UseBasicParsing -Uri "$ReleaseUrl/$f" -OutFile (Join-Path $dir $f) }

    # 0. SHA256SUMS itself must be the one the panel vouched for (when it passed its hash)
    if ($SumsSha256) {
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dir 'SHA256SUMS')).Hash.ToLower()
        if ($got -ne $SumsSha256.ToLower()) { throw "SHA256SUMS is not the release the panel checked (SHA-256 $got, expected $($SumsSha256.ToLower()))" }
        Write-Host 'fairy: SHA256SUMS matches the hash the panel checked'
    }

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

    # 2. the signature, with the release key built into the downloaded fairy-agent (its hash was checked above).
    #    The installed C:\Program Files\Fairy\fairy-agent.exe is NOT run here: until install-fairy-agent.ps1 has
    #    replaced it with the checked program, it may have been changed by the service's own account (0.4.2).
    $exe = Join-Path $env:ProgramFiles 'Fairy\fairy-agent.exe'
    $new = Join-Path $dir 'fairy-agent-windows-amd64.exe'
    Unblock-File $new
    $rc = (Invoke-Quiet $new @('verify-release', $dir)).Code
    $relName = "" + (Get-Content -LiteralPath (Join-Path $dir 'VERSION') -TotalCount 1)
    if ($rc -eq 0 -and $SumsSha256) { Write-Host "fairy: release $relName verified (the panel's fingerprint, signature and hashes)" }
    elseif ($rc -eq 0) {
        Write-Warning "release $relName is NOT independently verified: no fingerprint from the panel (-Unverified)."
        Write-Warning 'Its signature was checked only with the key built into the downloaded program, which came with the same download.'
    }
    elseif ($rc -eq 3 -and $SumsSha256) { Write-Warning "this build has no release key: the signature was not checked (the panel's fingerprint and hashes only)" }
    elseif ($rc -eq 3) { throw 'this build has no release key and no fingerprint from the panel was given: nothing vouches for it' }
    else { throw 'the release signature check failed' }

    # Tailscale must be up without anyone signed in, or the panel cannot reach this PC after a reboot or a
    # Wake-on-LAN until someone logs on ("Run unattended" = ForceDaemon in Tailscale's prefs).
    $ts = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
    if (Test-Path $ts) {
        $prefs = Invoke-Quiet $ts @('debug', 'prefs')
        if ($prefs.Code -eq 0 -and $prefs.Text -match '"ForceDaemon":\s*false') {
            Write-Warning 'Tailscale "Run unattended" is off: after a reboot or Wake-on-LAN the panel cannot reach this PC until someone signs in. Turn it on: Tailscale icon > Preferences > Run unattended (or: tailscale up --unattended).'
        }
    } else { Write-Warning 'Tailscale was not found in C:\Program Files\Tailscale: the panel reaches the agent only over Tailscale.' }

    # 3. program, services, permissions, firewall (the existing installer script). The agent runs as
    #    NT SERVICE\fairy-agent; Core Temp, IPMI (fans) and power control go through the elevated helper.
    #    It runs in a Windows PowerShell of its own: a script file needs an execution policy that allows it,
    #    which the window this was started from may not have.
    $kept = Join-Path $dir 'kept-newer.txt'
    $ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $instArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $dir 'install-fairy-agent.ps1'),
                  '-PanelAddress', $PanelAddress, '-Quiet', '-KeptMarker', $kept)
    if ($CoreTemp -or $Ipmi -or $PowerControl) { $instArgs += '-Helper' }
    & $ps @instArgs
    if ($LASTEXITCODE -ne 0) { throw 'install-fairy-agent.ps1 failed (see above); nothing was paired' }

    if (Test-Path -LiteralPath $kept) {
        # never older: a newer fairy-agent is installed and was kept, so it is not the downloaded program
        Write-Host ('fairy: pairing with the installed fairy-agent ' + (Get-Content -LiteralPath $kept -TotalCount 1))
    } else {
        # the program now installed must be the checked one before it runs again as Administrator
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash.ToLower()
        if ($got -ne $sums['fairy-agent-windows-amd64.exe']) { throw "$exe does not match the signed SHA256SUMS: not running it" }
    }

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
    # the helper reads config.yaml when it starts: restart it so it serves what join just switched on
    if (Get-Service fairy-agent-helper -ErrorAction SilentlyContinue) { Restart-Service fairy-agent-helper }
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
