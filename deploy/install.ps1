<#
.SYNOPSIS
  Fairy agent installer for Windows, the machine side of the panel's "Add host".

  Use the one line from the panel's Add host (or Re-pair) dialog, in an Administrator PowerShell. It names one
  checked release, refuses to run this script unless its SHA-256 is the one the panel verified, and passes
  the release's fingerprint (-SumsSha256). There is no "latest" one-liner any more: nobody can check a line
  that downloads whatever is newest and runs it.

  install.ps1 -ReleaseUrl URL -SumsSha256 HASH -PanelAddress 100.x.y.z [-PairV2]
              [-PowerControl] [-SelfUpdate] [-Wol] [-Ups] [-UpsName NAME] [-CoreTemp] [-Ipmi]

  The one-time join code comes from the environment variable FAIRY_JOIN_CODE, which the panel's line sets
  just before ($env:FAIRY_JOIN_CODE='CODE'). It is then on no program's command line, where every user of
  the PC could read it while the installer runs. The script removes the variable again, never shows the
  code and hands it to `fairy-agent join` through that program's environment. -Join CODE (lines of older
  panels) still works, with a warning; it is deprecated and will be removed in a later release.

  -PairV2 (the panel's line says so when the panel speaks it): the agent answers the panel encrypted, and
  only a panel that proves it has this join code.

  The panel's line downloads this script into memory, checks the SHA-256 of exactly those bytes and runs
  them, with no file in between that another program could swap after the check. The script therefore has
  no "#Requires" line (it checks for an Administrator window itself) and works both run from memory and
  as a file (powershell -ExecutionPolicy Bypass -File install.ps1 ..., lines of older panels).

.DESCRIPTION
  1. downloads the release into a new folder in C:\Windows\Temp that only Administrators and SYSTEM can reach:
     fairy-agent-windows-amd64.exe, SHA256SUMS (+ signature), VERSION and install-fairy-agent.ps1, and checks each file's SHA-256 against SHA256SUMS and SHA256SUMS' signature with
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
    [string]$Join = '',
    [Parameter(Mandatory = $true)][string]$PanelAddress,
    [switch]$PairV2,
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

# The join code: from the environment (the panel's line), or -Join (older panels). Never shown. The variable
# is removed at once, also from the window this runs in, so that nothing started later inherits it.
$code = $Join
$Join = ''
# -Join CODE is the old form. One warning, a fixed text in single quotes: the code is in no message.
if ($code) { Write-Warning '-Join CODE is deprecated and will stop working in a later release: the code stays in the PowerShell history, and where it is part of a command line other users of this PC can read it while this runs. Use the line the panel shows now (it sets FAIRY_JOIN_CODE).' }
if (-not $code) { $code = $env:FAIRY_JOIN_CODE }
Remove-Item Env:FAIRY_JOIN_CODE -ErrorAction SilentlyContinue
if (-not $code) { throw "no join code: use the line from the panel's Add host dialog (it sets FAIRY_JOIN_CODE), or -Join CODE" }
if ($code -notmatch '^[A-Za-z2-7 -]+$') { throw 'that is not a Fairy join code (letters A-Z and digits 2-7, in groups of four)' }
if ($PanelAddress -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { throw "-PanelAddress must be the panel's Tailscale IPv4 address, e.g. 100.64.0.10" }
if ($UpsName -and $UpsName -notmatch '^[A-Za-z0-9_.-]{1,64}$') { throw '-UpsName: letters, digits, _ . - only' }
if ($SumsSha256 -and $SumsSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw '-SumsSha256 must be 64 hex digits (the SHA-256 of SHA256SUMS)' }
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'this must run in an Administrator PowerShell (right-click Windows PowerShell, "Run as administrator")'
}
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

# The work folder. What is downloaded is checked and then run from here as Administrator, so nobody else may
# be able to swap a file, or the whole folder, between the check and the run:
#   - It is in C:\Windows\Temp, not in $env:TEMP. For an elevated administrator $env:TEMP is the user's own temp
#     folder, where every program of that user, also one that is not elevated, may rename or delete what is
#     inside whatever permissions the work folder has, and so swap the whole folder. In C:\Windows\Temp other
#     accounts may add files, but not rename or delete what they did not make.
#   - It is new, with a random name, and created together with its permissions (Administrators and SYSTEM
#     only, owner Administrators, nothing inherited): there is no moment in which it has the permissions it
#     would inherit. What the create call made is then looked at, and nothing is downloaded unless it is right.
$dir = Join-Path (Join-Path $env:SystemRoot 'Temp') ('fairy-install-' + [guid]::NewGuid().ToString('N'))
if (Test-Path -LiteralPath $dir) { throw "the work folder $dir exists already; nothing was downloaded. Run the line again." }
$admins = 'S-1-5-32-544', 'S-1-5-18'   # Administrators, SYSTEM
$sec = New-Object System.Security.AccessControl.DirectorySecurity
$sec.SetSecurityDescriptorSddlForm('O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)')
if ($PSVersionTable.PSEdition -eq 'Core') { [System.IO.FileSystemAclExtensions]::Create((New-Object System.IO.DirectoryInfo($dir)), $sec) }
else { [System.IO.Directory]::CreateDirectory($dir, $sec) | Out-Null }
try {
    $sid = [Security.Principal.SecurityIdentifier]
    $acl = Get-Acl -LiteralPath $dir
    $rules = @($acl.GetAccessRules($true, $true, $sid))
    $bad = @($rules | Where-Object { $admins -notcontains $_.IdentityReference.Value })
    if (($admins -notcontains $acl.GetOwner($sid).Value) -or (-not $acl.AreAccessRulesProtected) -or $rules.Count -eq 0 -or $bad.Count -ne 0) {
        throw "the work folder $dir did not get the permissions it was created with (owner $($acl.GetOwner($sid).Value), $($acl.Sddl)); nothing was downloaded"
    }
    if (@(Get-ChildItem -LiteralPath $dir -Force).Count -ne 0) { throw "the new work folder $dir is not empty: something else wrote to it; nothing was downloaded" }
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
    foreach ($line in Get-Content -LiteralPath (Join-Path $dir 'SHA256SUMS')) {
        $p = $line -split '\s+', 2
        if ($p.Count -eq 2) { $sums[$p[1].TrimStart('*')] = $p[0].ToLower() }
    }
    foreach ($f in $files) {
        if ($f -like 'SHA256SUMS*') { continue }
        if (-not $sums.ContainsKey($f)) { throw "$f is not listed in SHA256SUMS" }
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dir $f)).Hash.ToLower()
        if ($got -ne $sums[$f]) { throw "$f does not match SHA256SUMS (corrupted or tampered download)" }
    }
    # A file from the work folder is hashed once more in the moment before it is run (the folder is one nobody
    # else can write; this is the second lock on the same door).
    function Assert-Checked([string]$f) {
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $dir $f)).Hash.ToLower()
        if ($got -ne $sums[$f]) { throw "$f changed after it was checked: not running it" }
    }

    # 2. the signature, with the release key built into the downloaded fairy-agent (its hash was checked above).
    #    The installed C:\Program Files\Fairy\fairy-agent.exe is NOT run here: until install-fairy-agent.ps1 has
    #    replaced it with the checked program, it may have been changed by the service's own account (0.4.2).
    $exe = Join-Path $env:ProgramFiles 'Fairy\fairy-agent.exe'
    $new = Join-Path $dir 'fairy-agent-windows-amd64.exe'
    Unblock-File -LiteralPath $new
    Assert-Checked 'fairy-agent-windows-amd64.exe'
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
    Assert-Checked 'install-fairy-agent.ps1'
    Assert-Checked 'fairy-agent-windows-amd64.exe'   # the script copies it to C:\Program Files\Fairy
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

    # 4. tokens, settings and the join code (prints no secret). The code is not on the command line: join
    #    takes it from its own environment and removes it there.
    $joinArgs = @('join', '--panel', $PanelAddress)
    if ($PairV2) { $joinArgs += '--pair-v2' }
    if ($PowerControl) { $joinArgs += '--power-control' }
    if ($SelfUpdate) { $joinArgs += '--self-update' }
    if ($Wol) { $joinArgs += '--wol' }
    if ($CoreTemp) { $joinArgs += '--coretemp' }
    if ($Ipmi) { $joinArgs += '--ipmi' }
    if ($UpsName) { $joinArgs += @('--ups-name', $UpsName) } elseif ($Ups) { $joinArgs += '--ups' }
    $env:FAIRY_JOIN_CODE = $code
    try { & $exe @joinArgs } finally { Remove-Item Env:FAIRY_JOIN_CODE -ErrorAction SilentlyContinue; $code = '' }
    if ($LASTEXITCODE -ne 0) { throw 'fairy-agent join failed (see above)' }
    # the helper reads config.yaml when it starts: restart it so it serves what join just switched on
    if (Get-Service fairy-agent-helper -ErrorAction SilentlyContinue) { Restart-Service fairy-agent-helper }
    Restart-Service fairy-agent
    Write-Host 'fairy: started; waiting for the panel to pair (keep the Add host dialog open) ...'

    # 5. wait (up to 2 minutes) until the panel has picked up the tokens
    for ($i = 0; $i -lt 60; $i++) {
        if ((Invoke-Quiet $exe @('pair-status')).Code -eq 0) { Write-Host 'fairy: paired with the panel. The host appears there within a few seconds. Done.'; return }
        if ((Get-Service fairy-agent).Status -ne 'Running') {
            # The log folder is written by the agent's own account: a link there would put lines of another
            # file on the administrator's screen. Shown only when folder and file are no links.
            $logDir = Join-Path $env:ProgramData 'fairy-agent\logs'
            $log = Join-Path $logDir 'agent.log'
            $plain = $true
            foreach ($p in @($logDir, $log)) {
                $it = Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
                if (-not $it -or ($it.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $plain = $false }
            }
            if ($plain) { Get-Content -LiteralPath $log -Tail 15 -ErrorAction SilentlyContinue }
            else { Write-Host 'fairy: the agent log is missing or is a link: not shown' }
            throw 'fairy-agent is not running (see above; log: C:\ProgramData\fairy-agent\logs\agent.log)'
        }
        Start-Sleep -Seconds 2
    }
    Write-Host ('fairy: not paired yet: ' + (Invoke-Quiet $exe @('pair-status')).Text)
    Write-Host 'fairy: the panel keeps trying while the code is valid; log: C:\ProgramData\fairy-agent\logs\agent.log'
} finally {
    Remove-Item -Recurse -Force -LiteralPath $dir -ErrorAction SilentlyContinue
}
