#Requires -Version 7.6
function Test-WinSecBruteForce {
    <#
    .SYNOPSIS
        Detects brute-force, password-spraying, credential-stuffing and
        lockout-storm patterns in collected events and rates their severity.

    .DESCRIPTION
        Detection logic (all UTC, all thresholds configurable):

        * BruteForce — ≥ FailureThreshold failed authentications from ONE
          source IP against ONE account inside WindowMinutes.
        * PasswordSpraying — ONE source IP touching ≥ SprayAccountThreshold
          DISTINCT accounts with failures inside WindowMinutes (typically
          few attempts per account — defeats per-account thresholds).
        * CredentialStuffing — ONE account hit from ≥ 3 distinct source IPs
          with failures inside WindowMinutes (distributed attack).
        * BruteForceWithSuccess — any of the above followed by a SUCCESS for
          the same source/account within SuccessWindowMinutes → treat as
          possible compromise (Critical). Successes include 4624, RDP 1149/21/25,
          Kerberos 0x0 results and NTLM 4776 with status 0x0.
        * LockoutStorm — ≥ LockoutThreshold account lockouts (4740) in scope.

        Failure sources: 4625, 4771, 4776 (non-zero status), RCM 1148, wireless
        5632/5633. Findings carry an evidence list (capped at 1000 events) and
        MITRE ATT&CK IDs (T1110 family).

    .PARAMETER Event
        WinSecEvent objects (pipe from Get-WinSecEventByIp).

    .EXAMPLE
        Get-WinSecEventByIp 203.0.113.7 -LastDays 1 | Test-WinSecBruteForce

    .EXAMPLE
        $findings = $events | Test-WinSecBruteForce -FailureThreshold 10 -WindowMinutes 5
        $findings | Where-Object SucceededAfterFailures   # compromise candidates

    .OUTPUTS
        WinSecBruteForceFinding
    #>
    [CmdletBinding()]
    [OutputType('WinSecBruteForceFinding')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSecEvent[]] $Event,

        [ValidateRange(2, 10000)] [int] $FailureThreshold,
        [ValidateRange(1, 1440)]  [int] $WindowMinutes,
        [ValidateRange(2, 1000)]  [int] $SprayAccountThreshold,
        [ValidateRange(1, 1440)]  [int] $SuccessWindowMinutes = 30,
        [ValidateRange(1, 1000)]  [int] $LockoutThreshold = 3,
        [ValidateRange(10, 100000)] [int] $MaxEvidencePerFinding = 1000
    )

    begin {
        $all = [System.Collections.Generic.List[WinSecEvent]]::new()
        $config = Get-WinSecConfig
    }
    process { foreach ($e in $Event) { $all.Add($e) } }
    end {
        if ($all.Count -eq 0) { Write-Warning 'Test-WinSecBruteForce received no events.'; return }
        if (-not $PSBoundParameters.ContainsKey('FailureThreshold'))     { $FailureThreshold      = [int]$config.BruteForceFailureThreshold }
        if (-not $PSBoundParameters.ContainsKey('WindowMinutes'))        { $WindowMinutes         = [int]$config.BruteForceWindowMinutes }
        if (-not $PSBoundParameters.ContainsKey('SprayAccountThreshold')){ $SprayAccountThreshold = [int]$config.BruteForceSprayAccountThreshold }

        $window = [timespan]::FromMinutes($WindowMinutes)
        $successWindow = [timespan]::FromMinutes($SuccessWindowMinutes)

        $failures = @($all | Where-Object { $_.Outcome -eq 'Failure' -and $_.EventId -in 4625, 4771, 4776, 1148, 5632, 5633, 4649 })
        $successes = @($all | Where-Object { $_.Outcome -eq 'Success' -and $_.EventId -in 4624, 1149, 21, 25, 4768, 4769, 4776 })
        $lockouts = @($all | Where-Object EventId -eq 4740)

        $findings = [System.Collections.Generic.List[WinSecBruteForceFinding]]::new()

        # Helper: sliding-window maximum burst inside a chronologically sorted list.
        $burst = {
            param([object[]]$SortedEvents, [timespan]$Win)
            if ($SortedEvents.Count -eq 0) { return $null }
            $best = [System.Collections.Generic.List[object]]::new()
            $i = 0
            for ($j = 0; $j -lt $SortedEvents.Count; $j++) {
                while (($SortedEvents[$j].TimeUtc - $SortedEvents[$i].TimeUtc) -gt $Win) { $i++ }
                if (($j - $i + 1) -gt $best.Count) {
                    $best = [System.Collections.Generic.List[object]]::new()
                    $best.AddRange([object[]]$SortedEvents[$i..$j])
                }
            }
            return $best
        }

        $newFinding = {
            param($Pattern, $Severity, $Source, $Account, $Events2, $Extra)
            $f = [WinSecBruteForceFinding]::new()
            $f.Pattern = $Pattern
            $f.Severity = $Severity
            $f.SourceIp = $Source ?? '*'
            $f.TargetAccount = $Account ?? '*'
            $sorted = @($Events2 | Sort-Object TimeUtc)
            $f.FailureCount = @($sorted | Where-Object Outcome -eq 'Failure').Count
            $f.SuccessCount = @($sorted | Where-Object Outcome -eq 'Success').Count
            $f.DistinctAccounts = @($sorted | ForEach-Object TargetAccount | Where-Object { $_ } | Sort-Object -Unique).Count
            $f.DistinctSources  = @($sorted | ForEach-Object { $_.SourceIp, $_.MatchedIp } | Where-Object { $_ } | Sort-Object -Unique).Count
            $f.SourceHosts = @($sorted | ForEach-Object Computer | Sort-Object -Unique)
            $f.FirstSeenUtc = $sorted[0].TimeUtc
            $f.LastSeenUtc  = $sorted[-1].TimeUtc
            $minutes = [Math]::Max(($f.LastSeenUtc - $f.FirstSeenUtc).TotalMinutes, 1.0 / 60)
            $f.AttemptsPerMinute = [Math]::Round($sorted.Count / $minutes, 2)
            $f.AttackIds = @('T1110', 'T1110.001', 'T1110.003', 'T1078') | Sort-Object -Unique
            foreach ($kv in $Extra.GetEnumerator()) { $f.($kv.Key) = $kv.Value }
            foreach ($ev in ($sorted | Select-Object -First $MaxEvidencePerFinding)) { $f.Evidence.Add($ev) }
            return $f
        }

        # ---- 1) Classic brute force: (source IP, account) ---------------------
        foreach ($grp in ($failures | Where-Object { $_.TargetAccount -and ($_.SourceIp -or $_.MatchedIp) } |
                          Group-Object { "$($_.SourceIp ?? $_.MatchedIp)|$($_.TargetAccount)" })) {
            $sortedG = @($grp.Group | Sort-Object TimeUtc)
            if ($sortedG.Count -lt $FailureThreshold) { continue }
            $b = & $burst $sortedG $window
            if ($b.Count -lt $FailureThreshold) { continue }
            $parts = $grp.Name -split '\|', 2
            $ev = @($sortedG | Where-Object { $_.TimeUtc -ge $b[0].TimeUtc -and $_.TimeUtc -le $b[-1].TimeUtc })
            $successAfter = $successes | Where-Object {
                $_.TargetAccount -eq $parts[1] -and ($_.SourceIp ?? $_.MatchedIp) -eq $parts[0] -and
                $_.TimeUtc -ge $b[0].TimeUtc -and $_.TimeUtc -le $b[-1].TimeUtc.Add($successWindow)
            }
            $f = & $newFinding ([WinSecVerdict]::BruteForce) ([WinSecSeverity]::High) $parts[0] $parts[1] $ev @{
                Description = ('{0} failed logons from {1} against {2} within {3} min ({4:N1}/min).' -f $b.Count, $parts[0], $parts[1], $WindowMinutes, ($b.Count / [Math]::Max($window.TotalMinutes, 0.01)))
            }
            if ($successAfter) {
                $f.Pattern = [WinSecVerdict]::BruteForceWithSuccess
                $f.Severity = [WinSecSeverity]::Critical
                $f.SucceededAfterFailures = $true
                $f.SuccessCount = @($successAfter).Count
                foreach ($s in ($successAfter | Select-Object -First 50)) { $f.Evidence.Add($s) }
                $f.Description += (' SUCCESS observed after failures ({0} event {1} at {2:u}) — assume compromise: isolate host, reset credentials, review sessions.' -f
                    $successAfter[0].Computer, $successAfter[0].EventId, $successAfter[0].TimeUtc)
            }
            $findings.Add($f)
        }

        # ---- 2) Password spraying: one source, many accounts -------------------
        foreach ($grp in ($failures | Where-Object { $_.SourceIp -or $_.MatchedIp } |
                          Group-Object { $_.SourceIp ?? $_.MatchedIp })) {
            $sortedG = @($grp.Group | Sort-Object TimeUtc)
            $accounts = @($sortedG | ForEach-Object TargetAccount | Where-Object { $_ } | Sort-Object -Unique)
            if ($accounts.Count -lt $SprayAccountThreshold) { continue }
            $b = & $burst $sortedG $window
            $bAccounts = @($b | ForEach-Object TargetAccount | Where-Object { $_ } | Sort-Object -Unique)
            if ($bAccounts.Count -lt $SprayAccountThreshold) { continue }
            $ev = @($sortedG | Where-Object { $_.TimeUtc -ge $b[0].TimeUtc -and $_.TimeUtc -le $b[-1].TimeUtc })
            $successAfter = $successes | Where-Object {
                ($_.SourceIp ?? $_.MatchedIp) -eq $grp.Name -and $_.TargetAccount -in $bAccounts -and
                $_.TimeUtc -ge $b[0].TimeUtc -and $_.TimeUtc -le $b[-1].TimeUtc.Add($successWindow)
            }
            $f = & $newFinding ([WinSecVerdict]::PasswordSpraying) ([WinSecSeverity]::High) $grp.Name $null $ev @{
                Description = ('Password spraying: {0} distinct accounts targeted from {1} within {2} min ({3} failures).' -f $bAccounts.Count, $grp.Name, $WindowMinutes, $b.Count)
            }
            if ($successAfter) {
                $f.Pattern = [WinSecVerdict]::BruteForceWithSuccess
                $f.Severity = [WinSecSeverity]::Critical
                $f.SucceededAfterFailures = $true
                $f.SuccessCount = @($successAfter).Count
                foreach ($s in ($successAfter | Select-Object -First 50)) { $f.Evidence.Add($s) }
                $f.Description += (' SUCCESS for {0} after spraying — assume compromise.' -f ($successAfter[0].TargetAccount))
            }
            $findings.Add($f)
        }

        # ---- 3) Credential stuffing: one account, many sources -----------------
        foreach ($grp in ($failures | Where-Object { $_.TargetAccount -and ($_.SourceIp -or $_.MatchedIp) } |
                          Group-Object TargetAccount)) {
            $sources = @($grp.Group | ForEach-Object { $_.SourceIp ?? $_.MatchedIp } | Sort-Object -Unique)
            if ($sources.Count -lt 3) { continue }
            $sortedG = @($grp.Group | Sort-Object TimeUtc)
            $b = & $burst $sortedG $window
            $bSources = @($b | ForEach-Object { $_.SourceIp ?? $_.MatchedIp } | Sort-Object -Unique)
            if ($bSources.Count -lt 3) { continue }
            $ev = @($sortedG | Where-Object { $_.TimeUtc -ge $b[0].TimeUtc -and $_.TimeUtc -le $b[-1].TimeUtc })
            $f = & $newFinding ([WinSecVerdict]::CredentialStuffing) ([WinSecSeverity]::High) $null $grp.Name $ev @{
                Description = ('Distributed attack: account {0} hit from {1} distinct sources within {2} min ({3} failures). Sources: {4}' -f
                    $grp.Name, $bSources.Count, $WindowMinutes, $b.Count, (($bSources | Select-Object -First 8) -join ', '))
            }
            $findings.Add($f)
        }

        # ---- 4) Lockout storm ---------------------------------------------------
        if ($lockouts.Count -ge $LockoutThreshold) {
            $f = & $newFinding ([WinSecVerdict]::LockoutStorm) ([WinSecSeverity]::Medium) $null $null $lockouts @{
                Description = ('{0} account lockouts (4740) in scope — sustained credential attack or misconfigured service causing lockouts.' -f $lockouts.Count)
                AttackIds = @('T1110')
            }
            $findings.Add($f)
        }

        if ($findings.Count -eq 0) {
            Write-Verbose ('No brute-force patterns above thresholds (failures={0}, threshold={1}/{2}min, spray>={3} accounts).' -f
                $failures.Count, $FailureThreshold, $WindowMinutes, $SprayAccountThreshold)
        }
        $findings | Sort-Object @{ Expression = { [int]$_.Severity }; Descending = $true }, FirstSeenUtc
    }
}
