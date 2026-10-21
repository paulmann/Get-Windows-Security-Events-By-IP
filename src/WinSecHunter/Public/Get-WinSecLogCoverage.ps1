#Requires -Version 7.6
function Get-WinSecLogCoverage {
    <#
    .SYNOPSIS
        Reports event log completeness: is each channel enabled, how far back
        does it reach, and is it about to wrap?

    .DESCRIPTION
        "No events found" only means something when the logs CAN prove it.
        This cmdlet answers the evidence-completeness questions before you
        write that line into an incident report:

          * Is the channel enabled and accessible?
          * Oldest/newest record (UTC) — does retention actually cover the
            investigation window (-CoveringFrom)?
          * Size vs. maximum, retention mode, and wrap risk rating.

        Works live (local/remote via WinRM, parallel) and offline against
        acquired EVTX files (-Path). Channels that are not installed
        (Sysmon absent, RDP logs on a DC) are reported with Risk=Informational
        instead of erroring.

    .PARAMETER CoveringFrom
        Investigation window start (UTC-converted). If a log's oldest record
        is NEWER than this, the log cannot prove absence before that point →
        High risk warning.

    .PARAMETER LogName
        Channels to inspect. Default: all catalog-supported channels.

    .EXAMPLE
        Get-WinSecLogCoverage -CoveringFrom (Get-Date).AddDays(-7)

    .EXAMPLE
        Get-WinSecLogCoverage -ComputerName DC01, VPN01 -Credential $cred -LogName Security

    .EXAMPLE
        Get-WinSecLogCoverage -Path C:\Cases\*.evtx

    .OUTPUTS
        WinSecLogCoverage
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    [OutputType('WinSecLogCoverage')]
    param(
        [Parameter(ParameterSetName = 'Remote')]
        [ValidateNotNullOrEmpty()]
        [string[]] $ComputerName,

        [Parameter(ParameterSetName = 'Remote')]
        [pscredential] $Credential,

        [Parameter(ParameterSetName = 'Remote')]
        [ValidateRange(1, 64)] [int] $ThrottleLimit = 8,

        [Parameter(ParameterSetName = 'File', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Path,

        [string[]] $LogName,
        [datetime] $CoveringFrom
    )

    if (-not $IsWindows -and $PSCmdlet.ParameterSetName -ne 'File') {
        throw [System.PlatformNotSupportedException]::new('Get-WinSecLogCoverage (live mode) requires Windows. Use -Path to inspect acquired EVTX files.')
    }

    $res = Get-WinSecResource
    $logs = $LogName
    if (-not $logs) {
        $logs = @($res.Logs)
        # Sysmon is optional infrastructure — inspect it but never hard-fail.
    }
    else {
        $expanded = foreach ($l in $logs) {
            if ($res.Aliases.ContainsKey($l)) { $res.Aliases[$l] } else { $l }
        }
        $logs = @($expanded | Select-Object -Unique)
    }

    $coveringUtc = $PSBoundParameters.ContainsKey('CoveringFrom') ? $CoveringFrom.ToUniversalTime() : $null

    # ----- per-log collector executed locally or remotely -------------------
    $collector = {
        param([string[]]$Logs)
        $out = [System.Collections.Generic.List[hashtable]]::new()
        foreach ($log in $Logs) {
            $h = @{ LogName = $log; Computer = $env:COMPUTERNAME; IsEnabled = $false; IsAccessible = $false;
                    RecordCount = 0L; FileSizeBytes = 0L; MaxSizeBytes = 0L; UsedPercent = 0.0;
                    RetentionSetting = ''; OldestRecordUtc = $null; NewestRecordUtc = $null; FilePath = ''; Warning = '' }
            try {
                $cfg = Get-WinEvent -ListLog $log -ErrorAction Stop
                $h.IsAccessible = $true
                $h.IsEnabled    = $cfg.IsEnabled
                $h.RecordCount  = $cfg.RecordCount
                $h.FileSizeBytes= $cfg.FileSize
                $h.MaxSizeBytes = $cfg.MaximumSizeInBytes
                $h.UsedPercent  = $cfg.MaximumSizeInBytes -gt 0 ? [Math]::Round(100.0 * $cfg.FileSize / $cfg.MaximumSizeInBytes, 1) : 0.0
                $h.RetentionSetting = [string]$cfg.LogMode
                $h.FilePath = $cfg.LogFilePath
                if ($cfg.RecordCount -gt 0) {
                    try { $h.OldestRecordUtc = (Get-WinEvent -LogName $log -Oldest -MaxEvents 1 -ErrorAction Stop).TimeCreated.ToUniversalTime() } catch { Write-Verbose "Oldest record unavailable for ${log}: $($_.Exception.Message)" }
                    try { $h.NewestRecordUtc = (Get-WinEvent -LogName $log -MaxEvents 1 -ErrorAction Stop).TimeCreated.ToUniversalTime() } catch { Write-Verbose "Newest record unavailable for ${log}: $($_.Exception.Message)" }
                }
            }
            catch {
                $ex = $_.Exception
                while ($ex.InnerException) { $ex = $ex.InnerException }
                $win32 = $ex.HResult -band 0xFFFF
                $h.Warning = if ($win32 -eq 5 -or $ex -is [System.UnauthorizedAccessException]) { 'Access denied — elevation required.' }
                             elseif ($win32 -in 2, 3, 15007 -or $ex.Message -match 'does not exist|was not found|cannot find') { 'Channel not installed on this system.' }
                             else { $ex.Message }
            }
            $out.Add($h)
        }
        $out.ToArray()
    }

    $allRows = [System.Collections.Generic.List[hashtable]]::new()

    switch ($PSCmdlet.ParameterSetName) {
        'File' {
            foreach ($file in $Path) {
                $resolved = Get-ChildItem -Path $file -File -ErrorAction SilentlyContinue
                if (-not $resolved) { Write-Warning "EVTX not found: $file"; continue }
                foreach ($f in $resolved) {
                    $h = @{ LogName = $f.Name; Computer = $f.Name; IsEnabled = $true; IsAccessible = $true;
                            RecordCount = 0L; FileSizeBytes = $f.Length; MaxSizeBytes = 0L; UsedPercent = 0.0;
                            RetentionSetting = 'OfflineFile'; OldestRecordUtc = $null; NewestRecordUtc = $null;
                            FilePath = $f.FullName; Warning = '' }
                    try {
                        $first = Get-WinEvent -Path $f.FullName -Oldest -MaxEvents 1 -ErrorAction Stop
                        $h.OldestRecordUtc = $first.TimeCreated.ToUniversalTime()
                        $h.LogName = $first.LogName ? $first.LogName : $f.Name
                        $h.Computer = $first.MachineName ? $first.MachineName : $f.Name
                        $last = Get-WinEvent -Path $f.FullName -MaxEvents 1 -ErrorAction SilentlyContinue
                        if ($last) { $h.NewestRecordUtc = $last.TimeCreated.ToUniversalTime() }
                        if ($first -and $last) { $h.RecordCount = [Math]::Max($last.RecordId - $first.RecordId + 1, 1) }
                    }
                    catch {
                        if ($_.Exception.Message -match 'No events') { $h.Warning = 'File contains no events.' }
                        else { $h.Warning = $_.Exception.Message }
                    }
                    $allRows.Add($h)
                }
            }
        }
        'Remote' {
            # Scriptblocks cannot travel through $using: into ForEach-Object
            # -Parallel; pass the text and rebuild it in the runspace.
            $collectorText = $collector.ToString()
            $rows = $ComputerName | ForEach-Object -Parallel {
                $target = $_
                $inner = [scriptblock]::Create($using:collectorText)
                $icp = @{ ScriptBlock = $inner; ArgumentList = , $using:logs; ErrorAction = 'Stop' }
                if ($using:Credential) { $icp.Credential = $using:Credential }
                try {
                    $r = Invoke-Command -ComputerName $target @icp
                }
                catch {
                    $errText = $_.Exception.Message
                    $r = @(foreach ($log in $using:logs) {
                        @{ LogName = $log; Computer = $target; IsEnabled = $false; IsAccessible = $false; RecordCount = 0L;
                           FileSizeBytes = 0L; MaxSizeBytes = 0L; UsedPercent = 0.0; RetentionSetting = '';
                           OldestRecordUtc = $null; NewestRecordUtc = $null; FilePath = '';
                           Warning = "Host unreachable: $errText" } })
                }
                $r
            } -ThrottleLimit $ThrottleLimit
            foreach ($r in @($rows)) { $allRows.Add($r) }
        }
        'Local' {
            foreach ($r in @(& $collector $logs)) { $allRows.Add($r) }
        }
    }

    # ----- risk rating (uniform, local) ---------------------------------------
    foreach ($h in $allRows) {
        $c = [WinSecLogCoverage]::new()
        $c.Computer = $h.Computer; $c.LogName = $h.LogName; $c.FilePath = $h.FilePath
        $c.IsEnabled = [bool]$h.IsEnabled; $c.IsAccessible = [bool]$h.IsAccessible
        $c.RecordCount = [long]$h.RecordCount; $c.FileSizeBytes = [long]$h.FileSizeBytes
        $c.MaxSizeBytes = [long]$h.MaxSizeBytes; $c.UsedPercent = [double]$h.UsedPercent
        $c.RetentionSetting = $h.RetentionSetting
        if ($h.OldestRecordUtc) { $c.OldestRecordUtc = [datetime]$h.OldestRecordUtc }
        if ($h.NewestRecordUtc) { $c.NewestRecordUtc = [datetime]$h.NewestRecordUtc }
        if ($c.OldestRecordUtc -and $c.NewestRecordUtc) { $c.Span = $c.NewestRecordUtc - $c.OldestRecordUtc }

        $risk = [WinSecSeverity]::Low
        $warn = [string]$h.Warning
        if (-not $c.IsAccessible) {
            $risk = if ($warn -match 'not installed') { [WinSecSeverity]::Informational } else { [WinSecSeverity]::High }
        }
        elseif (-not $c.IsEnabled) {
            $risk = [WinSecSeverity]::Critical
            $warn = 'CHANNEL DISABLED — no evidence is being recorded right now.'
        }
        else {
            if ($coveringUtc -and $c.OldestRecordUtc -and $c.OldestRecordUtc -gt $coveringUtc) {
                $risk = [WinSecSeverity]::High
                $warn = ("Retention gap: log starts {0:u} but investigation window starts {1:u} — activity in between may have been overwritten or never audited." -f $c.OldestRecordUtc, $coveringUtc)
            }
            elseif ($c.UsedPercent -ge 95 -and $c.RetentionSetting -match 'Overwrite|Circular') {
                $risk = [WinSecSeverity]::High
                $warn = ('Log {0:N0}% full and overwriting oldest events — preserve (wevtutil epl / Export in Event Viewer) immediately.' -f $c.UsedPercent)
            }
            elseif ($c.UsedPercent -ge 80) {
                $risk = [WinSecSeverity]::Medium
                $warn = ('Log {0:N0}% full — wrap risk within the investigation horizon.' -f $c.UsedPercent)
            }
            if ($c.RecordCount -eq 0 -and $c.IsEnabled) {
                $risk = [WinSecSeverity]::Medium
                $warn = 'Channel is enabled but empty — recently cleared? Check 1102/104 and coverage of other hosts.'
            }
        }
        $c.Risk = $risk
        $c.Warning = $warn
        $c
    }
}
