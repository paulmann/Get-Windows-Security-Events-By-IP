#Requires -Version 7.6
function Get-WinSecIpTimeline {
    <#
    .SYNOPSIS
        Builds a chronological activity timeline with volume buckets, ASCII
        histogram and attacker-behavior summaries for collected events.

    .DESCRIPTION
        Answers the first questions of any IP investigation: when did the
        activity start/stop, how intense was it, which accounts and hosts were
        touched in each window, and did failures turn into successes?

        Buckets are emitted as WinSecTimelineBucket objects (pipeline-friendly,
        consumed by Export-WinSecInvestigation for the HTML histogram). With
        -AsciiChart the same data is rendered as console-safe strings —
        no host output, fully testable and redirectable.

        A leading summary object (PSTypeName WinSecTimelineSummary) carries
        totals, first/last seen (UTC), per-host/per-account/per-event breakdowns
        and the success-after-failure indicator.

    .PARAMETER Event
        WinSecEvent objects, typically piped from Get-WinSecEventByIp.

    .PARAMETER BucketSize
        Bucket granularity. Default: automatic — 1h for spans ≤ 48h, 6h for
        ≤ 14 days, 1 day beyond.

    .PARAMETER MaxBarWidth
        Width of the longest ASCII bar (default 50).

    .PARAMETER Top
        How many entries per breakdown table (default 10).

    .EXAMPLE
        Get-WinSecEventByIp 203.0.113.7 | Get-WinSecIpTimeline -AsciiChart

    .EXAMPLE
        $timeline = $events | Get-WinSecIpTimeline -BucketSize ([timespan]::FromMinutes(15))
        $timeline | Where-Object PSTypeName -eq 'WinSecTimelineBucket'

    .OUTPUTS
        WinSecTimelineSummary (first object), then WinSecTimelineBucket objects.
    #>
    [CmdletBinding()]
    [OutputType('WinSecTimelineBucket')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSecEvent[]] $Event,

        [timespan] $BucketSize,
        [ValidateRange(5, 200)] [int] $MaxBarWidth = 50,
        [ValidateRange(1, 100)] [int] $Top = 10,
        [switch] $AsciiChart
    )

    begin {
        $all = [System.Collections.Generic.List[WinSecEvent]]::new()
    }
    process { foreach ($e in $Event) { $all.Add($e) } }
    end {
        if ($all.Count -eq 0) {
            Write-Warning 'Get-WinSecIpTimeline received no events.'
            return
        }

        $sorted = @($all | Sort-Object TimeUtc)
        $firstUtc = $sorted[0].TimeUtc
        $lastUtc  = $sorted[-1].TimeUtc
        $span = [Math]::Max(($lastUtc - $firstUtc).TotalSeconds, 1)

        if (-not $BucketSize -or $BucketSize -eq [timespan]::Zero) {
            $BucketSize = if ($span -le 48 * 3600) { [timespan]::FromHours(1) }
                          elseif ($span -le 14 * 86400) { [timespan]::FromHours(6) }
                          else { [timespan]::FromDays(1) }
        }

        # Success-after-failure indicator (per account+host): compromise smell.
        $safPairs = @()
        foreach ($grp in ($sorted | Where-Object { $_.TargetAccount } | Group-Object { "$($_.Computer)|$($_.TargetAccount)" })) {
            $fails = @($grp.Group | Where-Object Outcome -eq 'Failure' | Sort-Object TimeUtc)
            if ($fails.Count -eq 0) { continue }
            $lastFail = $fails[-1].TimeUtc
            $laterSuccess = $grp.Group | Where-Object { $_.Outcome -eq 'Success' -and $_.TimeUtc -ge $fails[0].TimeUtc -and $_.TimeUtc -le $lastFail.AddHours(1) } |
                            Select-Object -First 1
            if ($laterSuccess) {
                $safPairs += [pscustomobject]@{
                    Computer = ($grp.Name -split '\|')[0]
                    Account  = $grp.Group[0].TargetAccount
                    FirstFailureUtc = $fails[0].TimeUtc
                    SuccessUtc = $laterSuccess.TimeUtc
                    SuccessEventId = $laterSuccess.EventId
                    FailuresBefore = @($fails | Where-Object { $_.TimeUtc -le $laterSuccess.TimeUtc }).Count
                }
            }
        }

        $summary = [pscustomobject][ordered]@{
            TotalEvents       = $all.Count
            FirstSeenUtc      = $firstUtc
            LastSeenUtc       = $lastUtc
            SpanHours         = [Math]::Round($span / 3600, 2)
            BucketSize        = $BucketSize
            FailureCount      = @($all | Where-Object Outcome -eq 'Failure').Count
            SuccessCount      = @($all | Where-Object Outcome -eq 'Success').Count
            Hosts             = @($all | ForEach-Object Computer | Sort-Object -Unique)
            Accounts          = @($all | ForEach-Object TargetAccount | Where-Object { $_ } | Sort-Object -Unique)
            SourceIps         = @($all | ForEach-Object { $_.SourceIp, $_.MatchedIp } | Where-Object { $_ } | Sort-Object -Unique)
            LogonTypes        = @($all | Where-Object { [int]$_.LogonType -gt 0 } | Group-Object { [int]$_.LogonType } | Sort-Object Count -Descending |
                                     ForEach-Object { [pscustomobject]@{ LogonType = [int]$_.Name; Count = $_.Count; Meaning = (Get-WinSecLogonTypeName -LogonType ([int]$_.Name)) } })
            EventBreakdown    = @($all | Group-Object EventId | Sort-Object Count -Descending | Select-Object -First $Top |
                                     ForEach-Object { [pscustomobject]@{ EventId = [int]$_.Name; Name = $_.Group[0].EventName; Count = $_.Count } })
            TopAccounts       = @($all | Where-Object TargetAccount | Group-Object TargetAccount | Sort-Object Count -Descending | Select-Object -First $Top |
                                     ForEach-Object { [pscustomobject]@{ Account = $_.Name; Count = $_.Count; Failures = @($_.Group | Where-Object Outcome -eq 'Failure').Count } })
            TopHosts          = @($all | Group-Object Computer | Sort-Object Count -Descending | Select-Object -First $Top |
                                     ForEach-Object { [pscustomobject]@{ Computer = $_.Name; Count = $_.Count } })
            AttackIds         = @($all | ForEach-Object AttackIds | Where-Object { $_ } | Sort-Object -Unique)
            SuccessAfterFailure = $safPairs
        }
        $summary.PSObject.TypeNames.Insert(0, 'WinSecTimelineSummary')

        # ---- Buckets ----------------------------------------------------------
        $epoch = [datetime]::new($firstUtc.Ticks - ($firstUtc.Ticks % $BucketSize.Ticks), [System.DateTimeKind]::Utc)
        $bucketCount = [int][Math]::Ceiling((($lastUtc - $epoch).TotalSeconds + 1) / $BucketSize.TotalSeconds)
        $bucketCount = [Math]::Min([Math]::Max($bucketCount, 1), 100000)

        $byBucket = @{}
        foreach ($e in $sorted) {
            $idx = [int][Math]::Floor(($e.TimeUtc - $epoch).TotalSeconds / $BucketSize.TotalSeconds)
            if (-not $byBucket.ContainsKey($idx)) { $byBucket[$idx] = [System.Collections.Generic.List[WinSecEvent]]::new() }
            $byBucket[$idx].Add($e)
        }

        $maxInBucket = 1
        foreach ($k in $byBucket.Keys) { if ($byBucket[$k].Count -gt $maxInBucket) { $maxInBucket = $byBucket[$k].Count } }

        $buckets = [System.Collections.Generic.List[WinSecTimelineBucket]]::new()
        for ($i = 0; $i -lt $bucketCount; $i++) {
            $items = $byBucket.ContainsKey($i) ? $byBucket[$i] : $null
            $b = [WinSecTimelineBucket]::new()
            $b.BucketStartUtc = $epoch.Add($BucketSize * $i)
            if ($items) {
                $b.Count           = $items.Count
                $b.SuccessCount    = @($items | Where-Object Outcome -eq 'Success').Count
                $b.FailureCount    = @($items | Where-Object Outcome -eq 'Failure').Count
                $b.DistinctAccounts= @($items | ForEach-Object TargetAccount | Where-Object { $_ } | Sort-Object -Unique).Count
                $b.DistinctHosts   = @($items | ForEach-Object Computer | Sort-Object -Unique).Count
                $b.TopEventIds     = (($items | Group-Object EventId | Sort-Object Count -Descending | Select-Object -First 3 |
                                        ForEach-Object { '{0}x{1}' -f $_.Name, $_.Count }) -join ', ')
                $b.BarWidth        = [int][Math]::Ceiling($items.Count / $maxInBucket * $MaxBarWidth)
            }
            else { $b.BarWidth = 0 }
            $b.Bar = '█' * [Math]::Max($b.BarWidth, ($items -and $items.Count -gt 0 ? 1 : 0))
            $buckets.Add($b)
        }

        # ---- Output -------------------------------------------------------------
        if ($AsciiChart) {
            $lines = [System.Collections.Generic.List[string]]::new()
            $lines.Add(('WinSecHunter timeline — {0} events, {1:u} → {2:u} (UTC), bucket {3}' -f $all.Count, $firstUtc, $lastUtc, $BucketSize.ToString()))
            foreach ($b in $buckets) {
                $lines.Add(('{0:MM-dd HH:mm} | {1,-50} {2,6}  {3}' -f $b.BucketStartUtc, $b.Bar, $b.Count, $b.TopEventIds))
            }
            if ($safPairs) {
                $lines.Add('')
                $lines.Add('!! SUCCESS AFTER FAILURE (possible compromise):')
                foreach ($p in $safPairs) {
                    $lines.Add(('   {0}\{1} on {2}: {3} failure(s) from {4:u}, then event {5} at {6:u}' -f
                        $p.Account, '', $p.Computer, $p.FailuresBefore, $p.FirstFailureUtc, $p.SuccessEventId, $p.SuccessUtc))
                }
            }
            $summary | Add-Member -NotePropertyName AsciiChart -NotePropertyValue $lines.ToArray() -Force
        }

        $summary
        $buckets
    }
}
