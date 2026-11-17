#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Removes fairy-agent from this Windows PC.

.DESCRIPTION
  Undoes what install-fairy-agent.ps1 / the panel's "Add host" command set up:

   1. Runs the program's own `uninstall` (only when the program and its folder can be changed by
      administrators only). It stops the agent, the helper (the fans go back to the BMC's automatic mode first)
      and the updater, deletes the three services, takes NT SERVICE\fairy-agent out of "Performance Monitor
      Users", and removes the event-log sources and the helper's two firewall rules.
   2. Cleans up whatever is still there by hand (services that are left, leftover processes, the group
      membership), so the script also works on a half-installed or half-removed agent.
   3. Removes the firewall rule "Fairy agent (Tailscale only)" (and the helper's, if one is left).
   4. Deletes C:\Program Files\Fairy.
   5. Deletes C:\ProgramData\fairy-agent (config, tokens, pairing, logs) and any
      C:\ProgramData\fairy-agent.untrusted-* / fairy-agent.parked-* folders the installer moved aside,
      unless -KeepData is given.

  Folders are deleted with `rd /s /q`, which removes a link or junction itself and never what it points to
  (a program running as the agent's account could have put one into its own folders).

  It never touches Tailscale, the panel, or anything outside the paths above. It does NOT remove the host in
  the panel: do that in the panel (Remove host).

.PARAMETER Yes
  Do not ask for confirmation (alias: -Force).

.PARAMETER KeepData
  Keep C:\ProgramData\fairy-agent (config.yaml, tokens, logs). Everything else is removed.

.EXAMPLE
  Set-ExecutionPolicy -Scope Process Bypass
  .\uninstall-fairy-agent.ps1

.EXAMPLE
  .\uninstall-fairy-agent.ps1 -Yes -KeepData

.NOTES
  Exit code 0: everything is gone (or there was nothing to remove). 1: something could not be removed; the
  list at the end says what and what to do.
#>
[CmdletBinding()]
param(
    [Alias('Force')][switch]$Yes,
    [switch]$KeepData
)
$ErrorActionPreference = 'Stop'

$agentSvc  = 'fairy-agent'
$helperSvc = 'fairy-agent-helper'
$updateSvc = 'fairy-agent-update'
$progDir   = Join-Path $env:ProgramFiles 'Fairy'
$dataDir   = Join-Path $env:ProgramData 'fairy-agent'
$ruleNames = @('Fairy agent (Tailscale only)', 'Fairy agent helper (no network)')
$sys       = Join-Path $env:SystemRoot 'System32'

$problems = New-Object 'System.Collections.Generic.List[string]'
$done     = New-Object 'System.Collections.Generic.List[string]'

function Say([string]$m)  { Write-Host "fairy: $m" }
function Fail([string]$m) { Write-Warning $m; $script:problems.Add($m) }

# Runs a native program without letting Windows PowerShell 5.1 turn its stderr into a terminating error.
function Invoke-Native([string]$File, [string[]]$Arguments) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $File @Arguments 2>&1 | Out-String } finally { $ErrorActionPreference = $old }
    return @{ Code = $LASTEXITCODE; Text = $out.Trim() }
}

# True when only Administrators, SYSTEM and TrustedInstaller own $path and may change it. Anything unexpected,
# also an error while looking, counts as "no". (Same test as install-fairy-agent.ps1.)
function Test-AdminOnly([string]$path) {
    try {
        $trusted = 'S-1-5-32-544', 'S-1-5-18', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        $sid = [Security.Principal.SecurityIdentifier]
        $acl = Get-Acl -LiteralPath $path
        if ($trusted -notcontains $acl.GetOwner($sid).Value) { return $false }
        $change = 0x000D0156 -bor 0x40000000 -bor 0x10000000
        foreach ($ace in $acl.GetAccessRules($true, $true, $sid)) {
            if ($ace.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { continue }
            $who = $ace.IdentityReference.Value
            if (($trusted -contains $who) -or ($who -eq 'S-1-3-0')) { continue }   # S-1-3-0: CREATOR OWNER
            if (([int]$ace.FileSystemRights -band $change) -ne 0) { return $false }
        }
        return $true
    } catch { return $false }
}

function Test-ServiceExists([string]$name) {
    return [bool](Get-Service -Name $name -ErrorAction SilentlyContinue)
}

# The program a service starts, from its registered command line (quoted or not).
function Get-ServiceExe([string]$name) {
    try {
        $s = Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'" -ErrorAction Stop
        if ($s -and $s.PathName) {
            if ($s.PathName -match '^\s*"([^"]+)"') { return $Matches[1] }
            return ($s.PathName -split '\s+')[0]
        }
    } catch { }
    return $null
}

function Stop-FairyService([string]$name, [int]$timeoutSec) {
    $s = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $s -or $s.Status -eq 'Stopped') { return }
    Say "stopping $name ..."
    try { Stop-Service -Name $name -Force -ErrorAction Stop } catch { }
    try { $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($timeoutSec)) } catch { }
    $s.Refresh()
    if ($s.Status -ne 'Stopped') {
        Say "$name did not stop in $timeoutSec s: ending its process"
        $procId = $null
        try { $procId = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$name'").ProcessId } catch { }
        if ($procId) { Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue }
    }
}

function Wait-ServiceGone([string]$name, [int]$sec) {
    $end = (Get-Date).AddSeconds($sec)
    while ((Get-Date) -lt $end) {
        if (-not (Test-ServiceExists $name)) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return (-not (Test-ServiceExists $name))
}

function Remove-FairyService([string]$name, [int]$stopTimeout) {
    if (-not (Test-ServiceExists $name)) { return }
    Stop-FairyService $name $stopTimeout
    $r = Invoke-Native (Join-Path $sys 'sc.exe') @('delete', $name)
    if ($r.Code -ne 0 -and $r.Code -ne 1072 -and $r.Code -ne 1060) {
        Fail "could not delete the service $name (sc.exe exit code $($r.Code)): $($r.Text)"
        return
    }
    if (Wait-ServiceGone $name 10) {
        Say "removed service $name"
        $script:done.Add("service $name")
    } else {
        Fail "the service $name is marked for deletion but still listed: close Services / Event Viewer / Task Manager windows, or reboot, and it goes away"
    }
}

# The agent's virtual account is a member of "Performance Monitor Users" (S-1-5-32-558). Its SID only
# resolves while the service exists, so this must run before the service is deleted.
function Remove-CounterGroupMember {
    try {
        $r = Invoke-Native (Join-Path $sys 'sc.exe') @('showsid', $agentSvc)
        $m = [regex]::Match($r.Text, 'S-1-5-80(?:-\d+)+')
        if (-not $m.Success) { return }
        $g = Get-LocalGroup -SID 'S-1-5-32-558' -ErrorAction Stop
        Remove-LocalGroupMember -Group $g -Member $m.Value -ErrorAction Stop
        Say 'removed NT SERVICE\fairy-agent from "Performance Monitor Users"'
    } catch { }   # not a member, or already gone: nothing to undo
}

# Deletes a folder with rd /s /q: a link or junction inside is removed itself, never followed.
function Remove-Tree([string]$path) {
    $leaf = Split-Path -Leaf $path
    if (-not $path -or $leaf -notmatch '^(Fairy|fairy-agent)') {
        throw "refusing to delete '$path': not one of Fairy's own folders"
    }
    if (-not (Test-Path -LiteralPath $path)) { return $true }
    $cmd = Join-Path $sys 'cmd.exe'
    for ($i = 0; $i -lt 4; $i++) {
        Start-Process -FilePath $cmd -ArgumentList ('/c rd /s /q "{0}"' -f $path) -Wait -WindowStyle Hidden
        if (-not (Test-Path -LiteralPath $path)) { return $true }
        Start-Sleep -Seconds 2   # a program may still hold a file open
    }
    return $false
}

function Get-ExtraDataDirs {
    return @(Get-ChildItem -LiteralPath $env:ProgramData -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.PSIsContainer -and ($_.Name -like 'fairy-agent.untrusted-*' -or $_.Name -like 'fairy-agent.parked-*') } |
        ForEach-Object { $_.FullName })
}

# Files config.yaml points at outside the data folder (a secrets file, a certificate): they are not ours to
# delete, but they may hold secrets, so they are listed at the end.
function Get-OutsideFiles {
    $cfg = Join-Path $dataDir 'config.yaml'
    if (-not (Test-Path -LiteralPath $cfg -PathType Leaf)) { return @() }
    $found = @()
    foreach ($line in @(Get-Content -LiteralPath $cfg -ErrorAction SilentlyContinue)) {
        if ($line -match '^\s*(env_file|token_file|control_token_file|ca_file)\s*:\s*(.+?)\s*$') {
            $v = ($Matches[2] -replace '\s+#.*$', '').Trim().Trim('"').Trim("'")
            if ($v -match '^[A-Za-z]:[\\/]' -and -not ($v -like "$dataDir*") -and (Test-Path -LiteralPath $v)) { $found += $v }
        }
    }
    return @($found | Select-Object -Unique)
}

# --- what is there? ----------------------------------------------------------------------------------------

# A shell sitting inside a folder we are about to delete would keep it locked.
$here = (Get-Location).ProviderPath
if ($here -like "$progDir*" -or $here -like "$env:ProgramData\fairy-agent*") { Set-Location -LiteralPath $env:SystemRoot }

$svcFound  = @($agentSvc, $helperSvc, $updateSvc | Where-Object { Test-ServiceExists $_ })
$ruleFound = @($ruleNames | Where-Object { Get-NetFirewallRule -DisplayName $_ -ErrorAction SilentlyContinue })
$hasProg   = Test-Path -LiteralPath $progDir
$hasData   = Test-Path -LiteralPath $dataDir
$extraDirs = @(Get-ExtraDataDirs)
$outside   = @(Get-OutsideFiles)

$svcExe = Get-ServiceExe $agentSvc
$otherProg = $null
if ($svcExe -and ((Split-Path -Parent $svcExe) -ne $progDir) -and (Test-Path -LiteralPath $svcExe)) { $otherProg = $svcExe }

if (-not $svcFound -and -not $ruleFound -and -not $hasProg -and -not $hasData -and -not $extraDirs) {
    Say 'fairy-agent is not installed on this PC (no services, firewall rules or folders found). Nothing to do.'
    exit 0
}

Write-Host ''
Write-Host 'This will remove fairy-agent from this PC:'
if ($svcFound)  { Write-Host ('  services:       ' + ($svcFound -join ', ')) }
if ($ruleFound) { Write-Host ('  firewall rules: ' + ($ruleFound -join ', ')) }
if ($hasProg)   { Write-Host "  program folder: $progDir" }
if ($KeepData) {
    if ($hasData) { Write-Host "  data folder:    $dataDir  (KEPT: -KeepData)" }
} else {
    if ($hasData)   { Write-Host "  data folder:    $dataDir  (config.yaml, tokens, pairing, logs)" }
    foreach ($d in $extraDirs) { Write-Host "  moved aside:    $d" }
}
Write-Host ''
if (Test-Path -LiteralPath (Join-Path $dataDir 'helper\power-pending.json')) {
    Write-Warning 'A shutdown / reboot started through Fairy may still be pending. This script does not cancel it; run "shutdown /a" if you do not want it.'
}

if (-not $Yes) {
    $answer = Read-Host 'Type YES to continue'
    if ($answer -ne 'YES') { Say 'cancelled, nothing was changed'; exit 0 }
}

# --- 1. the program's own uninstall ------------------------------------------------------------------------

$usedOfficial = $false
if (Test-ServiceExists $agentSvc) {
    $exe = $null
    foreach ($c in @((Join-Path $progDir 'fairy-agent.exe'), $svcExe)) {
        if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { $exe = $c; break }
    }
    if (-not $exe) {
        Say 'the program file is missing: removing the services by hand'
    } elseif (-not ((Test-AdminOnly $exe) -and (Test-AdminOnly (Split-Path -Parent $exe)))) {
        Say "$exe or its folder can be changed by a non-administrator account: not running it. Removing the services by hand"
    } else {
        Say 'running the built-in uninstall (this can take up to a minute: the helper hands the fans back to the BMC first) ...'
        $r = Invoke-Native $exe @('uninstall')
        if ($r.Text) { $r.Text -split "`r?`n" | ForEach-Object { Say "  $_" } }
        if ($r.Code -eq 0) { $usedOfficial = $true; $done.Add('services (built-in uninstall)') }
        else { Say "the built-in uninstall ended with exit code $($r.Code): finishing by hand" }
    }
}

# --- 2. whatever is left, by hand ----------------------------------------------------------------------------

if (-not $usedOfficial -and (Test-ServiceExists $agentSvc)) { Remove-CounterGroupMember }
Remove-FairyService $updateSvc 20
Remove-FairyService $agentSvc 25
Remove-FairyService $helperSvc 40   # stopping it hands the fans back to the BMC's automatic mode

# programs that are still running from the program folder (a helper's powershell.exe is not one of them)
foreach ($p in @(Get-Process -Name 'fairy-agent' -ErrorAction SilentlyContinue)) {
    $path = $null
    try { $path = $p.Path } catch { }
    if ($path -and $path -like "$progDir\*") {
        Say "ending leftover process fairy-agent (id $($p.Id))"
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
}

# event-log sources (the built-in uninstall does this too; harmless to repeat)
foreach ($src in @($agentSvc, $helperSvc)) {
    try { if ([System.Diagnostics.EventLog]::SourceExists($src)) { [System.Diagnostics.EventLog]::DeleteEventSource($src) } } catch { }
}

# --- 3. firewall ----------------------------------------------------------------------------------------------

foreach ($rn in $ruleNames) {
    $rule = @(Get-NetFirewallRule -DisplayName $rn -ErrorAction SilentlyContinue)
    if ($rule.Count -gt 0) {
        try {
            $rule | Remove-NetFirewallRule -ErrorAction Stop
            Say "removed firewall rule '$rn'"
            $done.Add("firewall rule '$rn'")
        } catch { Fail "could not remove the firewall rule '$rn': $_" }
    }
}

# --- 4. program folder ----------------------------------------------------------------------------------------

if (Test-Path -LiteralPath $progDir) {
    if (Remove-Tree $progDir) { Say "deleted $progDir"; $done.Add($progDir) }
    else { Fail "could not delete $progDir (something still holds a file in it). Close it, then: cmd /c rd /s /q `"$progDir`"" }
}
if ($otherProg) {
    Write-Host ''
    Write-Warning "The service was registered with a program outside the usual folder: $otherProg. It was not deleted; remove it yourself if you do not need it."
}

# --- 5. data folder -------------------------------------------------------------------------------------------

if ($KeepData) {
    if ($hasData) { Say "kept $dataDir (-KeepData)" }
} else {
    foreach ($d in @($dataDir) + $extraDirs) {
        if (Test-Path -LiteralPath $d) {
            if (Remove-Tree $d) { Say "deleted $d"; $done.Add($d) }
            else { Fail "could not delete $d. Stop whatever holds it open, then: cmd /c rd /s /q `"$d`"  (use rd, not Remove-Item -Recurse: it never follows links)" }
        }
    }
}

# --- summary --------------------------------------------------------------------------------------------------

Write-Host ''
$left = @($agentSvc, $helperSvc, $updateSvc | Where-Object { Test-ServiceExists $_ })
if ($left) { Fail ('still listed as services: ' + ($left -join ', ')) }

if ($problems.Count -eq 0) {
    Say 'fairy-agent has been removed from this PC.'
} else {
    Say ("finished with {0} problem(s), listed above." -f $problems.Count)
}
Write-Host ''
Write-Host 'Still to do, by hand:'
Write-Host '  - In the panel: open this host and press "Remove host" (the panel keeps its own copy of the tokens).'
if ($outside) {
    Write-Host '  - config.yaml pointed at files outside the data folder; they were not touched and may hold secrets:'
    $outside | ForEach-Object { Write-Host "      $_" }
}
if ($KeepData -and $hasData) {
    Write-Host "  - $dataDir was kept; it holds this PC's tokens. Delete it when you no longer need it."
}
Write-Host '  - If the agent read a Home Assistant plug: delete the long-lived token it used in Home Assistant (profile > Security).'

if ($problems.Count -gt 0) { exit 1 }
exit 0
