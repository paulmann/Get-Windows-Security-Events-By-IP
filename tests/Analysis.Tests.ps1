#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-10 10:00:00', [System.DateTimeKind]::Utc)
}

Describe 'Brute-force detection (Test-WinSecBruteForce)' {
    It 'Detects classic brute force against one account' {
        $events = 1..8 | ForEach-Object { New-TestEvent -EventId 4625 -TimeUtc $script:T0.AddSeconds($_ * 5) -RecordId $_ }
        $f = @($events | Test-WinSecBruteForce -FailureThreshold 5 -WindowMinutes 10)
        $bf = @($f | Where-Object { "$($_.Pattern)" -eq 'BruteForce' })
        $bf.Count | Should -BeGreaterOrEqual 1
        $bf[0].FailureCount | Should -Be 8
        "$($bf[0].Severity)" | Should -Be 'High'
        $bf[0].SourceIp | Should -Be '203.0.113.7'
        $bf[0].TargetAccount | Should -Be 'CORP\alice'
        $bf[0].AttackIds | Should -Contain 'T1110'
        $bf[0].Evidence.Count | Should -Be 8
    }

    It 'Escalates to BruteForceWithSuccess (Critical) when a success follows' {
        $events = @(1..8 | ForEach-Object { New-TestEvent -EventId 4625 -TimeUtc $script:T0.AddSeconds($_ * 5) -RecordId $_ })
        $events += New-TestEvent -EventId 4624 -Outcome Success -TimeUtc $script:T0.AddSeconds(120) -RecordId 99
        $f = @($events | Test-WinSecBruteForce -FailureThreshold 5 -WindowMinutes 10)
        $hit = @($f | Where-Object { "$($_.Pattern)" -eq 'BruteForceWithSuccess' })
        $hit.Count | Should -BeGreaterOrEqual 1
        "$($hit[0].Severity)" | Should -Be 'Critical'
        $hit[0].SucceededAfterFailures | Should -BeTrue
        $hit[0].SuccessCount | Should -BeGreaterOrEqual 1
    }

    It 'Detects password spraying (one source, many accounts, few tries each)' {
        $events = @()
        $rid = 1
        foreach ($u in 1..6) {
            foreach ($t in 1..2) {
                $events += New-TestEvent -EventId 4625 -TargetAccount "CORP\u$u" -TimeUtc $script:T0.AddSeconds($rid * 3) -RecordId $rid
                $rid++
            }
        }
        $f = @($events | Test-WinSecBruteForce -FailureThreshold 5 -WindowMinutes 10 -SprayAccountThreshold 5)
        $spray = @($f | Where-Object { "$($_.Pattern)" -eq 'PasswordSpraying' })
        $spray.Count | Should -BeGreaterOrEqual 1
        $spray[0].DistinctAccounts | Should -BeGreaterOrEqual 6
        @($f | Where-Object { "$($_.Pattern)" -eq 'BruteForce' }).Count | Should -Be 0
    }

    It 'Detects credential stuffing (one account, many sources)' {
        $events = @()
        $rid = 1
        foreach ($s in 1..3) {
            foreach ($t in 1..2) {
                $events += New-TestEvent -EventId 4625 -SourceIp "198.51.100.$s" -MatchedIp "198.51.100.$s" -TimeUtc $script:T0.AddSeconds($rid * 4) -RecordId $rid
                $rid++
            }
        }
        $f = @($events | Test-WinSecBruteForce -FailureThreshold 5 -WindowMinutes 10)
        $stuff = @($f | Where-Object { "$($_.Pattern)" -eq 'CredentialStuffing' })
        $stuff.Count | Should -BeGreaterOrEqual 1
        $stuff[0].DistinctSources | Should -BeGreaterOrEqual 3
    }

    It 'Detects lockout storms (4740)' {
        $events = 1..3 | ForEach-Object { New-TestEvent -EventId 4740 -Outcome Informational -TimeUtc $script:T0.AddMinutes($_) -RecordId $_ }
        $f = @($events | Test-WinSecBruteForce -LockoutThreshold 3)
        @($f | Where-Object { "$($_.Pattern)" -eq 'LockoutStorm' }).Count | Should -Be 1
    }

    It 'Stays silent below thresholds' {
        $events = 1..2 | ForEach-Object { New-TestEvent -EventId 4625 -TimeUtc $script:T0.AddSeconds($_) -RecordId $_ }
        $f = @($events | Test-WinSecBruteForce -FailureThreshold 5)
        @($f | Where-Object { "$($_.Pattern)" -ne 'None' }).Count | Should -Be 0
    }
}

Describe 'Timeline (Get-WinSecIpTimeline)' {
    BeforeAll {
        $script:TlEvents = @(1..10 | ForEach-Object { New-TestEvent -EventId 4625 -TimeUtc $script:T0.AddMinutes(30 * $_) -RecordId $_ })
        $script:TlEvents += New-TestEvent -EventId 4624 -Outcome Success -TimeUtc $script:T0.AddMinutes(30 * 10 + 1) -RecordId 999
    }

    It 'Emits a summary object first, then typed buckets' {
        $out = @($script:TlEvents | Get-WinSecIpTimeline -BucketSize ([timespan]::FromHours(1)) -AsciiChart)
        $out[0].PSObject.TypeNames[0] | Should -Be 'WinSecTimelineSummary'
        $out[0].TotalEvents | Should -Be 11
        $out[0].FailureCount | Should -Be 10
        $out[0].SuccessCount | Should -Be 1
        $buckets = @($out | Where-Object { $_.GetType().Name -eq 'WinSecTimelineBucket' })
        $buckets.Count | Should -BeGreaterOrEqual 5
        ($buckets | Measure-Object -Property Count -Sum).Sum | Should -Be 11
    }

    It 'Flags success-after-failure as a compromise indicator' {
        $out = @($script:TlEvents | Get-WinSecIpTimeline -BucketSize ([timespan]::FromHours(1)))
        $out[0].SuccessAfterFailure.Count | Should -BeGreaterOrEqual 1
        $out[0].SuccessAfterFailure[0].Account | Should -Be 'CORP\alice'
    }

    It 'Renders an ASCII chart without touching the host' {
        $out = @($script:TlEvents | Get-WinSecIpTimeline -BucketSize ([timespan]::FromHours(1)) -AsciiChart)
        $chart = $out[0].AsciiChart
        $chart.Count | Should -BeGreaterThan 5
        ($chart -join "`n") | Should -Match ([char]0x2588)   # block char present
        ($chart -join "`n") | Should -Match 'SUCCESS AFTER FAILURE'
    }

    It 'Auto-selects bucket size and keeps UTC ordering' {
        $out = @($script:TlEvents | Get-WinSecIpTimeline)
        $buckets = @($out | Where-Object { $_.GetType().Name -eq 'WinSecTimelineBucket' })
        $times = $buckets | ForEach-Object BucketStartUtc
        ($times | Sort-Object) | Should -Be $times
    }
}

Describe 'Session reconstruction (Get-WinSecLogonSession)' {
    BeforeAll {
        $script:S4624 = New-TestEvent -EventId 4624 -Outcome Success -LogonId '0xABC' -TimeUtc $script:T0 -RecordId 1
        $script:S4672 = New-TestEvent -EventId 4672 -Outcome Informational -LogonId '0xabc' -TimeUtc $script:T0.AddSeconds(1) -RecordId 2
        $script:S4648 = New-TestEvent -EventId 4648 -Outcome Success -LogonId '0xdef' -TimeUtc $script:T0.AddMinutes(5) -RecordId 3
        $script:S4648.Data['SubjectLogonId'] = '0xABC'
        $script:S4648.Data['TargetLogonId']  = '0xdef'
        $script:S4634 = New-TestEvent -EventId 4634 -Outcome Informational -LogonId '0xABC' -TimeUtc $script:T0.AddMinutes(30) -RecordId 4
    }

    It 'Chains logon → privilege → explicit-creds → logoff into one session' {
        $sessions = @($script:S4624, $script:S4672, $script:S4648, $script:S4634 | Get-WinSecLogonSession)
        $sessions.Count | Should -Be 1
        $s = $sessions[0]
        $s.LogonId | Should -Be 'abc'
        $s.IsAdmin | Should -BeTrue
        $s.Ended | Should -BeTrue
        $s.ChildLogonIds | Should -Contain 'def'
        [Math]::Round($s.GetDuration().TotalMinutes) | Should -Be 30
        $s.Events.Count | Should -BeGreaterOrEqual 3
    }

    It '-ActiveOnly returns only unterminated sessions' {
        $open = @($script:S4624, $script:S4672 | Get-WinSecLogonSession -ActiveOnly)
        $open.Count | Should -Be 1
        $open[0].EndUtc | Should -Be ([datetime]::MaxValue)
        $closed = @($script:S4624, $script:S4672, $script:S4634 | Get-WinSecLogonSession -ActiveOnly)
        $closed.Count | Should -Be 0
    }

    It 'Ignores events without a 4624 anchor' {
        $orphan = @((New-TestEvent -EventId 4672 -LogonId '0x999' -RecordId 7) | Get-WinSecLogonSession)
        $orphan.Count | Should -Be 0
    }
}
