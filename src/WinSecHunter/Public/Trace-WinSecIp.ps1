#Requires -Version 7.6
function Trace-WinSecIp {
    <#
    .SYNOPSIS
        Near-real-time tail of Windows event logs for a specific IP — live
        monitoring during an ongoing incident.

    .DESCRIPTION
        Polls the selected channels every -IntervalSeconds using a per-log
        RecordId bookmark with a small time overlap, so nothing is missed
        between cycles and nothing is duplicated in the output. Each matching
        WinSecEvent is emitted to the pipeline as it appears (works with
        Out-GridView, Tee-Object, SIEM forwarders, etc.).

        Deliberately polling-based: no ETW consumer dependency, works from an
        elevated shell on any Windows host, and degrades gracefully. Ctrl+C
        stops the trace cleanly (bookmarks are reported on exit).

        Runs against the LOCAL machine by design — for remote live monitoring,
        run WinSecHunter inside a remote session (Enter-PSSession) or schedule
        repeated Get-WinSecEventByIp sweeps.

    .PARAMETER Duration
        Stop after this timespan (default: run until Ctrl+C).

    .PARAMETER StartTime
        Begin scanning from this point instead of "now" (e.g. catch the last
        hour while you set up).

    .EXAMPLE
        Trace-WinSecIp -IpAddress 203.0.113.7 -IntervalSeconds 5

    .EXAMPLE
        Trace-WinSecIp 203.0.113.7 -Profile Rdp -Duration ([timespan]::FromHours(2)) |
            Tee-Object -FilePath .\live-rdp.jsonl -Append |
            ForEach-Object { Write-Information ("{0:HH:mm:ss} {1} {2}" -f $_.TimeCreated, $_.EventId, $_.TargetAccount) -InformationAction Continue }

    .OUTPUTS
        WinSecEvent (streaming)
    #>
    [CmdletBinding()]
    [OutputType('WinSecEvent')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]] $IpAddress,

        [string[]] $Profile,
        [string[]] $Category,
        [int[]] $EventId,
        [string[]] $LogName,

        [ValidateRange(1, 3600)] [int] $IntervalSeconds,
        [timespan] $Duration,
        [datetime] $StartTime,
        [switch] $DeepScan,
        [switch] $IncludeMessage
    )

    if (-not $IsWindows) {
        throw [System.PlatformNotSupportedException]::new('Trace-WinSecIp requires Windows (Get-WinEvent).')
    }

    $config = Get-WinSecConfig
    if (-not $PSBoundParameters.ContainsKey('IntervalSeconds')) { $IntervalSeconds = [int]$config.TraceIntervalSeconds }
    if (-not $Profile -and -not $Category -and -not $EventId) { $Profile = @([string]$config.DefaultProfile) }

    foreach ($ip in $IpAddress) {
        if (-not (Test-WinSecIpAddress -Value $ip -AllowCidr)) {
            throw [ArgumentException]::new("Invalid IP address or CIDR range: '$ip'.")
        }
    }
    $ipSpecs = @(foreach ($ip in $IpAddress) {
        $canonical = ConvertTo-WinSecCanonicalIp -Value $ip
        [pscustomobject]@{
            Input = $ip
            Canonical = $ip.Contains('/') ? ($canonical + '/' + ($ip -split '/')[1]) : $canonical
            IsCidr = $ip.Contains('/')
            Regex = Get-WinSecIpMatchRegex -IpAddress $canonical
        }
    })

    $scope = Get-WinSecEventIdsByScope -Profile $Profile -Category $Category -EventId $EventId -LogName $LogName
    if ($scope.LogEventIds.Count -eq 0) {
        throw [ArgumentException]::new('No events selected — check profile/category/log filters.')
    }

    $variants = ($ipSpecs.Count -eq 1 -and -not $ipSpecs[0].IsCidr -and -not $DeepScan) ?
        @(Get-WinSecIpVariant -IpAddress $ipSpecs[0].Canonical) : $null

    # Bookmarks: per channel → last seen (TimeUtc, RecordId).
    $bookmarks = @{}
    $anchor = $PSBoundParameters.ContainsKey('StartTime') ? $StartTime.ToUniversalTime() : [datetime]::UtcNow
    foreach ($log in $scope.LogEventIds.Keys) {
        $bookmarks[$log] = [pscustomobject]@{ TimeUtc = $anchor; RecordId = [long]::MaxValue }
    }

    Write-Verbose ("Tracing {0} across {1} channel(s), every {2}s. Ctrl+C to stop." -f
        (($ipSpecs | ForEach-Object Input) -join ', '), $scope.LogEventIds.Count, $IntervalSeconds)

    $seenKeys = [System.Collections.Generic.HashSet[string]]::new()
    $cycles = 0
    try {
        while ($true) {
            $cycles++
            $globalStart = ($bookmarks.Values | Measure-Object -Property TimeUtc -Minimum).Minimum.AddSeconds(-5)
            $query = New-WinSecEventQuery -LogEventIds $scope.LogEventIds -StartTimeUtc $globalStart -EndTimeUtc ([datetime]::UtcNow.AddSeconds(1)) -IpExactVariants $variants
            $result = Invoke-WinSecEventQuery -Query $query -MaxEvents 0 -IncludeMessage:$IncludeMessage

            foreach ($hr in $result.HostResults) {
                if ($hr.Status -eq 'Failed' -and $hr.ErrorMessage -notmatch 'No events') {
                    Write-Verbose ("Trace cycle {0}: {1}" -f $cycles, $hr.ErrorMessage)
                }
            }

            $batch = [System.Collections.Generic.List[WinSecEvent]]::new()
            foreach ($payload in $result.Raw) {
                $xmlText = [string]$payload.Xml
                $matched = $null
                foreach ($spec in $ipSpecs) {
                    if ($spec.IsCidr) { continue }
                    if ($spec.Regex.IsMatch($xmlText)) { $matched = $spec; break }
                }
                if (-not $matched -and -not ($ipSpecs | Where-Object IsCidr)) { continue }

                $e = $null
                try { $e = ConvertTo-WinSecEvent -Record $payload -IncludeMessage:$IncludeMessage } catch { continue }

                if ($matched) { $e.MatchedIp = $matched.Canonical; $e.MatchedOn = 'Xml' }
                else {
                    foreach ($spec in ($ipSpecs | Where-Object IsCidr)) {
                        if (($e.SourceIp -and (Test-WinSecIpInCidr -IpAddress $e.SourceIp -Cidr $spec.Canonical)) -or
                            ($e.DestinationIp -and (Test-WinSecIpInCidr -IpAddress $e.DestinationIp -Cidr $spec.Canonical))) {
                            $e.MatchedIp = $spec.Canonical; $e.MatchedOn = 'EventData'; break
                        }
                    }
                    if (-not $e.MatchedIp) { continue }
                }

                # Bookmark filter: only newer-than-bookmark records per channel.
                $bm = $bookmarks[$e.LogName]
                if ($bm -and ($e.TimeUtc -lt $bm.TimeUtc -or ($e.TimeUtc -eq $bm.TimeUtc -and $e.RecordId -le $bm.RecordId))) {
                    if ($bm.RecordId -ne [long]::MaxValue) { continue }
                }
                if (-not $seenKeys.Add($e.GetDedupKey() + '|' + $e.MatchedIp)) { continue }
                $batch.Add($e)
            }

            foreach ($e in ($batch | Sort-Object TimeUtc, RecordId)) { $e }

            # Advance bookmarks
            foreach ($log in $scope.LogEventIds.Keys) {
                $newOnes = @($batch | Where-Object LogName -eq $log)
                if ($newOnes.Count -gt 0) {
                    $maxTime = ($newOnes | Measure-Object TimeUtc -Maximum).Maximum
                    $maxRec  = ($newOnes | Measure-Object RecordId -Maximum).Maximum
                    $bookmarks[$log] = [pscustomobject]@{ TimeUtc = $maxTime; RecordId = [long]$maxRec }
                }
                elseif ($bookmarks[$log].RecordId -eq [long]::MaxValue) {
                    $bookmarks[$log] = [pscustomobject]@{ TimeUtc = [datetime]::UtcNow; RecordId = [long]::MaxValue }
                }
            }

            if ($Duration -and ($Duration -gt [timespan]::Zero)) {
                if (([datetime]::UtcNow - $anchor) -ge $Duration) { break }
            }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
    finally {
        Write-Verbose ("Trace stopped after {0} cycle(s). Bookmarks: {1}" -f $cycles,
            (($bookmarks.GetEnumerator() | ForEach-Object { '{0}→{1:u}/#{2}' -f $_.Key, $_.Value.TimeUtc, ($_.Value.RecordId -eq [long]::MaxValue ? 'init' : $_.Value.RecordId) }) -join '; '))
    }
}
