#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
    $script:T0 = [datetime]::SpecifyKind([datetime]'2026-10-10 10:00:00', [System.DateTimeKind]::Utc)

    $script:Ev = @(1..6 | ForEach-Object { New-TestEvent -EventId 4625 -TimeUtc $script:T0.AddSeconds($_ * 5) -RecordId $_ })
    $script:Ev += New-TestEvent -EventId 4624 -Outcome Success -TimeUtc $script:T0.AddSeconds(200) -RecordId 900
    $script:Ev += New-TestEvent -EventId 4672 -Outcome Informational -LogonId '0xabc' -TimeUtc $script:T0.AddSeconds(201) -RecordId 901

    $script:Findings = @($script:Ev | Test-WinSecBruteForce -FailureThreshold 5)
    $script:Sessions = @($script:Ev | Get-WinSecLogonSession)
    $script:Timeline = @($script:Ev | Get-WinSecIpTimeline -BucketSize ([timespan]::FromMinutes(5)))

    $script:Cov = & (Get-Module WinSecHunter) {
        $c = [WinSecLogCoverage]::new()
        $c.Computer = 'SRV01'; $c.LogName = 'Security'; $c.IsEnabled = $true; $c.IsAccessible = $true
        $c.RecordCount = 1234567; $c.FileSizeBytes = 100MB; $c.MaxSizeBytes = 200MB
        $c.UsedPercent = 50; $c.RetentionSetting = 'OverwriteOlder'
        $c.OldestRecordUtc = [datetime]::UtcNow.AddDays(-30); $c.NewestRecordUtc = [datetime]::UtcNow
        $c.Risk = [WinSecSeverity]::Low; $c.Warning = ''
        $c
    }
    $script:Attr = & (Get-Module WinSecHunter) {
        $a = [WinSecIpAttribution]::new()
        $a.IpAddress = '203.0.113.7'; $a.Version = 4; $a.IsPrivate = $false
        $a.PtrHostname = 'bad.example'; $a.PtrResolved = $true
        $a.Provider = 'AbuseIPDB'; $a.QueriedUtc = [datetime]::UtcNow
        $a.Country = 'Netherlands'; $a.CountryCode = 'NL'
        $a.AbuseConfidenceScore = 99; $a.TotalReports = 150
        $a.Categories = @('brute-force'); $a.Verdict = 'Known abusive internet source (test)'
        $a.Raw = @{}
        $a
    }
    $script:Case = New-WinSecCase -SubjectIps '203.0.113.7' -Title 'Pester integration case'
}

Describe 'Investigation export (Export-WinSecInvestigation)' {
    BeforeAll {
        $script:OutDir = Join-Path $TestDrive 'bundle'
        $script:ReturnedCase = Export-WinSecInvestigation -Case $script:Case -Event $script:Ev -Finding $script:Findings `
            -Session $script:Sessions -Coverage @($script:Cov) -Attribution @($script:Attr) -Timeline $script:Timeline `
            -Format All -OutputDirectory $script:OutDir -PassThru -Confirm:$false
        $script:CaseDir = Join-Path $script:OutDir $script:Case.CaseId
    }

    It 'Writes every artifact of the bundle' {
        foreach ($f in 'events.csv', 'events.json', 'events.clixml', 'findings.json', 'sessions.csv',
                       'coverage.csv', 'attribution.json', 'timeline.csv', 'report.html', 'report.md',
                       'case.json', 'manifest.json') {
            (Join-Path $script:CaseDir $f) | Should -Exist -Because "$f missing"
        }
    }

    It 'manifest.json hashes verify against every artifact (chain of custody)' {
        $manifest = Get-Content -Raw (Join-Path $script:CaseDir 'manifest.json') | ConvertFrom-Json
        $manifest.caseId | Should -Be $script:Case.CaseId
        $manifest.hashAlgorithm | Should -Be 'SHA256'
        $count = 0
        foreach ($p in $manifest.artifacts.PSObject.Properties) {
            $leaf = Split-Path $p.Name -Leaf
            $full = Join-Path $script:CaseDir $leaf
            $full | Should -Exist
            (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash | Should -Be $p.Value.Sha256
            $p.Value.Bytes | Should -Be (Get-Item -LiteralPath $full).Length
            $count++
        }
        $count | Should -BeGreaterOrEqual 11
    }

    It 'HTML report is self-contained (no scripts, links or external refs)' {
        $html = Get-Content -Raw (Join-Path $script:CaseDir 'report.html')
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match '<link'
        $html | Should -Not -Match 'src="http'
        $html | Should -Match $script:Case.CaseId
        $html | Should -Match 'Known abusive internet source'
        $html | Should -Match '4625'
    }

    It 'CSV/JSON round-trip preserves core fields' {
        $csv = Import-Csv (Join-Path $script:CaseDir 'events.csv')
        $csv.Count | Should -Be $script:Ev.Count
        ($csv | ForEach-Object EventId | Select-Object -Unique) | Should -Contain '4625'
        ($csv[0].SourceIp) | Should -Be '203.0.113.7'
        $json = Get-Content -Raw (Join-Path $script:CaseDir 'events.json') | ConvertFrom-Json
        @($json).Count | Should -Be $script:Ev.Count
    }

    It 'CLIXML rehydrates event objects' {
        $back = Import-Clixml (Join-Path $script:CaseDir 'events.clixml')
        @($back).Count | Should -Be $script:Ev.Count
        @($back | ForEach-Object EventId) | Should -Contain 4625
    }

    It 'Markdown report contains findings and coverage' {
        $md = Get-Content -Raw (Join-Path $script:CaseDir 'report.md')
        $md | Should -Match '## Findings'
        $md | Should -Match 'BruteForce'
        $md | Should -Match '## Log coverage'
        $md | Should -Match 'manifest.json'
    }

    It 'PassThru returns the case with populated evidence registry' {
        $script:ReturnedCase.CaseId | Should -Be $script:Case.CaseId
        $script:ReturnedCase.Evidence.Count | Should -BeGreaterOrEqual 11
    }

    It 'Creates an ad-hoc case when none is supplied' {
        $out2 = Join-Path $TestDrive 'adhoc'
        Export-WinSecInvestigation -Event $script:Ev -Format Csv -OutputDirectory $out2 -Confirm:$false
        $dirs = @(Get-ChildItem $out2 -Directory)
        $dirs.Count | Should -Be 1
        $dirs[0].Name | Should -Match '^WSC-\d{8}-'
        (Join-Path $dirs[0].FullName 'events.csv') | Should -Exist
        (Join-Path $dirs[0].FullName 'manifest.json') | Should -Exist
    }

    It 'Supports WhatIf without writing' {
        $out3 = Join-Path $TestDrive 'whatif'
        Export-WinSecInvestigation -Event $script:Ev -OutputDirectory $out3 -WhatIf
        (Test-Path $out3) | Should -BeFalse
    }
}
