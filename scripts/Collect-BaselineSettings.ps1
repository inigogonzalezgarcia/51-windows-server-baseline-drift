<#
.SYNOPSIS
    Read-only collection of the Windows Server security baseline settings that baselinedrift reviews: the actual value of every
    baseline setting on every server (settings.csv) and the Group Policy results per server (gpo-results.csv).

.DESCRIPTION
    Only read operations. Nothing is set, enabled, disabled, linked or restarted, and no credential is written to disk: the remote
    sessions use the current Windows session or a credential from Get-Credential that stays in memory.

    It reads baseline.csv and, for each server in servers.csv (or -ComputerName), opens one PowerShell remoting session
    (Invoke-Command over WinRM) and reads each setting according to its Type:

      registry   Get-ItemProperty -Path <Path> -Name <ValueName>                 (Path as HKLM\..., read through the HKLM: drive)
      auditpol   auditpol /get /category:* /r, the "Inclusion Setting" of the subcategory in Path (English subcategory names)
      service    Get-Service -Name <Path>: the property in ValueName (StartType or Status)
      firewall   Get-NetFirewallProfile -Name <Path> -PolicyStore ActiveStore: the property in ValueName (Enabled, LogBlocked...)
      smb        Get-SmbServerConfiguration: the property in ValueName (EnableSMB1Protocol...)
      defender   Get-MpComputerStatus, or Get-MpPreference when the property is not there (RealTimeProtectionEnabled,
                 AntivirusSignatureAge, IsTamperProtected...)
      asr        Get-MpPreference: the action of the ASR rule whose GUID is in ValueName (AttackSurfaceReductionRules_Ids and
                 _Actions: 0 off, 1 block, 2 audit, 5 not configured, 6 warn)
      userright  secedit /export /areas USER_RIGHTS to a temporary file on the server, which is read and deleted; the SIDs of the
                 privilege in ValueName (SeDebugPrivilege...). secedit only exports the effective local policy; nothing is changed.
      laps       Get-ADComputer -Properties <ValueName> from the admin workstation (ActiveDirectory module): Present when the
                 attribute has a value (msLAPS-PasswordExpirationTime for Windows LAPS, ms-Mcs-AdmPwdExpirationTime for legacy
                 LAPS). Only the expiration time is read, never the password.

    Group Policy results: Get-GPResultantSetOfPolicy -Computer <server> -ReportType Xml (GroupPolicy module, RSoP logging data) is
    written to a temporary file on the admin workstation and parsed: a GPO is applied when it is listed with IsValid, FilterAllowed
    and not AccessDenied; denied by security filtering when AccessDenied; filtered out by WMI when FilterAllowed is false. A GPO
    named in baseline.csv that is not in the RSoP at all is reported as "Not in RSoP (not linked to the server's OU, link disabled
    or GPO disabled)": check the links in GPMC.

    Source of each value (a hint, which baselinedrift uses for the root cause):
      Missing   the value does not exist (registry value absent, auditpol "No Auditing" counts as a value).
      GPO       a registry value under ...\Policies\ that one of the applied GPOs configures (Get-GPRegistryValue on each applied GPO;
                the one applied last wins and is written in GpoName); for the other types, a value that meets the baseline while
                the baseline GPO applies.
      Local     any other value: set on the server, by a tool, or the Windows default while the baseline GPO does not apply.

    Modules: ActiveDirectory and GroupPolicy (RSAT) on the admin workstation; the Defender, SMB and NetSecurity modules on the
    servers (built into Windows Server 2016 and later). Rights: local administrator on the servers for remoting, auditpol and
    secedit; read access in AD; RSoP logging data needs administrator rights on the target too.

.PARAMETER Baseline
    The approved baseline (default .\data\baseline.csv).

.PARAMETER Servers
    The server inventory with a Server column (default .\data\servers.csv). Ignored when -ComputerName is given.

.PARAMETER ComputerName
    Collect only these servers.

.PARAMETER OutputFolder
    Where settings.csv and gpo-results.csv are written (default .\data). Rename last month's settings.csv to previous.csv first.

.PARAMETER Credential
    A credential for the remote sessions (Get-Credential); by default the current Windows session is used.

.PARAMETER SkipGpo
    Do not collect the Group Policy results.

.EXAMPLE
    Move-Item .\data\settings.csv .\data\previous.csv -Force
    .\scripts\Collect-BaselineSettings.ps1 -Baseline .\data\baseline.csv -Servers .\data\servers.csv -OutputFolder .\data

.EXAMPLE
    .\scripts\Collect-BaselineSettings.ps1 -ComputerName FAB-GET-FS01, FAB-SVQ-FS01 -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [string] $Baseline = '.\data\baseline.csv',
    [string] $Servers = '.\data\servers.csv',
    [string[]] $ComputerName,
    [string] $OutputFolder = '.\data',
    [pscredential] $Credential,
    [switch] $SkipGpo
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputFolder | Out-Null
$rules = @(Import-Csv $Baseline | Where-Object { $_.SettingId })
if (-not $ComputerName) { $ComputerName = @(Import-Csv $Servers | ForEach-Object { $_.Server } | Where-Object { $_ }) }
$now = (Get-Date).ToString('yyyy-MM-dd HH:mm')
$baselineGpos = @($rules | ForEach-Object { $_.Gpo } | Where-Object { $_ } | Sort-Object -Unique)

# Runs on each server: returns one object per rule with the raw value ('' when absent). Read-only.
$remote = {
    param($Rules)
    $out = @{}
    $audit = $null; $rights = $null; $mpStatus = $null; $mpPref = $null; $smb = $null
    foreach ($r in $Rules) {
        $v = ''
        try {
            switch ($r.Type) {
                'registry' {
                    $p = $r.Path -replace '^HKLM\\', 'HKLM:\' -replace '^HKEY_LOCAL_MACHINE\\', 'HKLM:\'
                    $item = Get-ItemProperty -Path $p -Name $r.ValueName -ErrorAction SilentlyContinue
                    if ($null -ne $item) { $v = [string] $item.($r.ValueName) }
                }
                'auditpol' {
                    if (-not $audit) { $audit = auditpol /get /category:* /r | ConvertFrom-Csv }
                    $row = $audit | Where-Object { $_.Subcategory -eq $r.Path } | Select-Object -First 1
                    if ($row) { $v = $row.'Inclusion Setting' }
                }
                'service' {
                    $svc = Get-Service -Name $r.Path -ErrorAction SilentlyContinue
                    if ($svc) { $v = [string] $svc.($r.ValueName) }
                }
                'firewall' {
                    $v = [string] (Get-NetFirewallProfile -Name $r.Path -PolicyStore ActiveStore).($r.ValueName)
                }
                'smb' {
                    if (-not $smb) { $smb = Get-SmbServerConfiguration }
                    $v = [string] $smb.($r.ValueName)
                }
                'defender' {
                    if (-not $mpStatus) { $mpStatus = Get-MpComputerStatus; $mpPref = Get-MpPreference }
                    if ($mpStatus.PSObject.Properties.Name -contains $r.ValueName) { $v = [string] $mpStatus.($r.ValueName) }
                    else { $v = [string] $mpPref.($r.ValueName) }
                }
                'asr' {
                    if (-not $mpPref) { $mpStatus = Get-MpComputerStatus; $mpPref = Get-MpPreference }
                    $ids = @($mpPref.AttackSurfaceReductionRules_Ids)
                    for ($i = 0; $i -lt $ids.Count; $i++) {
                        if ($ids[$i] -eq $r.ValueName) { $v = [string] [int] @($mpPref.AttackSurfaceReductionRules_Actions)[$i] }
                    }
                }
                'userright' {
                    if (-not $rights) {
                        $tmp = Join-Path $env:TEMP ("ur-{0}.inf" -f [guid]::NewGuid())
                        secedit /export /areas USER_RIGHTS /cfg $tmp /quiet | Out-Null
                        $rights = @{}
                        foreach ($line in Get-Content $tmp) {
                            if ($line -match '^(Se\w+)\s*=\s*(.*)$') { $rights[$Matches[1]] = $Matches[2].Trim() }
                        }
                        Remove-Item $tmp -Force
                    }
                    if ($rights.ContainsKey($r.ValueName)) { $v = $rights[$r.ValueName] }
                }
            }
        } catch { $v = '' }
        $out[$r.SettingId] = $v
    }
    $out
}

function Test-Meets($Rule, [string] $Actual) {
    # A simple version of baselinedrift's comparison, only to label the source; the review does the real comparison.
    if ($Actual -eq '') { return $false }
    $opts = $Rule.Expected -split '[|;]'
    switch ($Rule.Comparison) {
        'min' { return ([double] $Actual) -ge ([double] $Rule.Expected) }
        'max' { return ([double] $Actual) -le ([double] $Rule.Expected) }
        'in' { return $opts -contains $Actual }
        'not_in' { return -not ($opts -contains $Actual) }
        'contains' { return @($opts | Where-Object { ($Actual -split ',') -notcontains $_ }).Count -eq 0 }
        default { return $Actual -eq $Rule.Expected }
    }
}

$gpoRows = New-Object System.Collections.Generic.List[object]
$settingRows = New-Object System.Collections.Generic.List[object]
$gpCache = @{}
$sessionArgs = @{}
if ($Credential) { $sessionArgs.Credential = $Credential }

foreach ($server in $ComputerName) {
    Write-Host "-> $server"
    # Group Policy results (RSoP), read from the admin workstation
    $applied = @()                                  # GPO names applied, in the order they were applied
    $gpoState = @{}
    if (-not $SkipGpo) {
        $xmlPath = Join-Path $env:TEMP ("rsop-{0}.xml" -f [guid]::NewGuid())
        try {
            Get-GPResultantSetOfPolicy -Computer $server -ReportType Xml -Path $xmlPath | Out-Null
            [xml] $rsop = Get-Content $xmlPath -Raw
            $readTime = [string] $rsop.Rsop.ReadTime
            foreach ($g in @($rsop.Rsop.ComputerResults.GPO)) {
                $name = [string] $g.Name
                $ok = ($g.IsValid -eq 'true') -and ($g.FilterAllowed -eq 'true') -and ($g.AccessDenied -ne 'true') -and ($g.Enabled -eq 'true')
                $reason = if ($g.AccessDenied -eq 'true') { 'Denied by security filtering' }
                          elseif ($g.FilterAllowed -ne 'true') { 'Filtered out by the WMI filter' }
                          elseif ($g.Enabled -ne 'true') { 'GPO computer settings disabled' } else { '' }
                $order = @($g.Link | ForEach-Object { [int] $_.AppliedOrder } | Measure-Object -Maximum).Maximum
                $gpoState[$name] = $ok
                if ($ok) { $applied += [pscustomobject]@{ Name = $name; Order = $order } }
                if ($baselineGpos -contains $name -or -not $ok) {
                    $gpoRows.Add([pscustomobject]@{ Server = $server; Gpo = $name; Applied = if ($ok) { 'Yes' } else { 'No' };
                                                    Reason = $reason; LastRefresh = $readTime })
                }
            }
            foreach ($b in $baselineGpos) {
                if (-not $gpoState.ContainsKey($b)) {
                    $gpoRows.Add([pscustomobject]@{ Server = $server; Gpo = $b; Applied = 'No'; LastRefresh = $readTime
                                                    Reason = "Not in RSoP (not linked to the server's OU, link disabled or GPO disabled)" })
                }
            }
        } catch {
            Write-Warning "$server : no RSoP ($($_.Exception.Message))"
        } finally {
            if (Test-Path $xmlPath) { Remove-Item $xmlPath -Force }
        }
        $applied = @($applied | Sort-Object Order | ForEach-Object { $_.Name })
    }

    try {
        $values = Invoke-Command -ComputerName $server -ScriptBlock $remote -ArgumentList (, $rules) @sessionArgs
    } catch {
        Write-Warning "$server : not reachable ($($_.Exception.Message))"
        continue
    }
    $short = $server.Split('.')[0]
    foreach ($r in $rules) {
        $actual = [string] $values[$r.SettingId]
        if ($r.Type -eq 'laps') {
            $comp = Get-ADComputer -Identity $short -Properties $r.ValueName
            $actual = if ($comp.($r.ValueName)) { 'Present' } else { '' }
        }
        $sourceName = 'Missing'; $gpoName = ''
        if ($actual -ne '') {
            $sourceName = 'Local'
            if ($r.Type -eq 'registry' -or $r.Type -eq 'asr') {
                $key = $r.Path -replace '^HKLM:\\', 'HKLM\'
                if ($key -match '\\Policies\\') {
                    foreach ($g in $applied) {                   # the GPO applied last wins
                        $ck = "$g|$key|$($r.ValueName)"
                        if (-not $gpCache.ContainsKey($ck)) {
                            $gpCache[$ck] = $null -ne (Get-GPRegistryValue -Name $g -Key $key -ValueName $r.ValueName -ErrorAction SilentlyContinue)
                        }
                        if ($gpCache[$ck]) { $sourceName = 'GPO'; $gpoName = $g }
                    }
                }
            }
            if ($sourceName -eq 'Local' -and $r.Gpo -and $gpoState[$r.Gpo] -and (Test-Meets $r $actual)) {
                $sourceName = 'GPO'; $gpoName = $r.Gpo
            }
        }
        $settingRows.Add([pscustomobject]@{ Server = $short; SettingId = $r.SettingId; Actual = $actual; Source = $sourceName
                                            GpoName = $gpoName; CollectedAt = $now })
    }
}

$settingRows | Export-Csv -Path (Join-Path $OutputFolder 'settings.csv') -NoTypeInformation -Encoding utf8
Write-Host ("{0,7} settings -> settings.csv" -f $settingRows.Count)
if (-not $SkipGpo) {
    $gpoRows | ForEach-Object { $_.Server = $_.Server.Split('.')[0]; $_ } |
        Select-Object Server, Gpo, Applied, Reason, LastRefresh |
        Export-Csv -Path (Join-Path $OutputFolder 'gpo-results.csv') -NoTypeInformation -Encoding utf8
    Write-Host ("{0,7} GPO results -> gpo-results.csv" -f $gpoRows.Count)
}
