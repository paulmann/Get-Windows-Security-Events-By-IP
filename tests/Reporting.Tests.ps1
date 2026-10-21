#Requires -Version 7.6
#Requires -PSEdition Core
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Tests for the 2.1.0 reporting surface: unified help, incident reports,
    abuse reports, IOC export, evidence verification and case re-import.
    All tests are pure (no Windows APIs, no network).
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule

    $script:base = [datetime]::UtcNow.AddHours(-4)
    $script:events = @()
    for ($i = 0; $i -lt 12; $i++) {
        $script:events += New-TestEvent -EventId 4625 -TimeUtc $script:base.AddMinutes($i * 3) `
            -TargetAccount 'CORP\alice' -SourceIp '203.0.113.7' -Outcome Failure -LogonType 10
    }
    $script:events += New-TestEvent -EventId 4624 -TimeUtc $script:base.AddMinutes(50) `
        -TargetAccount 'CORP\alice' -SourceIp '203.0.113.7' -Outcome Success -LogonType 10
    $script:events += New-TestEvent -EventId 4672 -TimeUtc $script:base.AddMinutes(51) `
        -TargetAccount 'CORP\alice' -SourceIp '203.0.113.7' -Outcome Informational

    $script:case = New-WinSecCase -SubjectIps '203.0.113.7' -Title 'Unit-test case' -ScopeHosts 'SRV01'
    $script:findings = @($script:events | Test-WinSecBruteForce -WindowMinutes 60 -FailureThreshold 5)
    $script:sessions = @($script:events | Get-WinSecLogonSession)
    $script:coverage = @(
        [pscustomobject]@{ Computer = 'SRV01'; LogName = 'Security'; IsEnabled = $true; IsAccessible = $true
            RecordCount = 1000; FileSizeBytes = 1MB; MaxSizeBytes = 10MB; UsedPercent = 10.0
            RetentionSetting = 'OverwriteOlder'; OldestRecordUtc = $script:base.AddDays(-3)
            NewestRecordUtc = $script:base; Risk = 'Low'; Warning = '' }
    )
    $script:attribution = @(
        [pscustomobject]@{ IpAddress = '203.0.113.7'; Asn = 64500; AsnOrganization = 'Hetzner Online GmbH'
            Country = 'Germany'; CountryCode = 'DE'; PtrHostname = 'host.example.net'; PtrResolved = $true
            Provider = 'None'; AbuseConfidenceScore = 70; TotalReports = 5; Categories = @('brute-force'); Verdict = 'scanner' }
    )
}

AfterAll {
    Remove-Module WinSecHunter -Force -ErrorAction SilentlyContinue
}

Describe 'Show-WinSecHunterHelp' {
    It 'lists every exported cmdlet in the overview' {
        $text = Show-WinSecHunterHelp -PassThru
        foreach ($name in (Get-Module WinSecHunter).ExportedFunctions.Keys) {
            $text | Should -Match ([regex]::Escape($name))
        }
    }

    It 'renders a single cmdlet reference with parameters and examples' {
        $text = Show-WinSecHunterHelp -Cmdlet Get-WinSecEventByIp -PassThru
        $text | Should -Match 'Get-WinSecEventByIp'
        $text | Should -Match 'IpAddress'
        $text | Should -Match 'EXAMPLES'
    }

    It 'produces Markdown on demand' {
        $md = Show-WinSecHunterHelp -Markdown
        $md | Should -Match '^# WinSecHunter'
    }

    It 'rejects an unknown cmdlet with a helpful message' {
        { Show-WinSecHunterHelp -Cmdlet 'Get-Nope' -PassThru } | Should -Throw '*Unknown WinSecHunter cmdlet*'
    }
}

Describe 'New-WinSecIncidentReport' {
    BeforeAll {
        $script:reportDir = Join-Path $TestDrive 'reports'
        $script:report = New-WinSecIncidentReport -Case $script:case -Event $script:events -Finding $script:findings `
            -Session $script:sessions -Coverage $script:coverage -Attribution $script:attribution `
            -Template Full -Format Both -OutputDirectory $script:reportDir -PassThru
    }

    It 'writes Markdown and HTML with hashes' {
        @($script:report.Files).Count | Should -Be 2
        foreach ($f in $script:report.Files) {
            Test-Path -LiteralPath $f.Path | Should -BeTrue
            $f.Sha256 | Should -Match '^[0-9A-F]{64}$'
        }
    }

    It 'states the verdict and the key sections' {
        $md = Get-Content -Raw -LiteralPath ($script:report.Files | Where-Object Format -eq 'Markdown').Path
        $md | Should -Match 'Executive summary'
        $md | Should -Match 'Credential compromise'
        $md | Should -Match 'Indicators of compromise'
        $md | Should -Match 'Recommendations'
        $md | Should -Match 'chain of custody'
    }

    It 'produces a self-contained HTML document' {
        $html = Get-Content -Raw -LiteralPath ($script:report.Files | Where-Object Format -eq 'Html').Path
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Not -Match '<script'
        $html | Should -Not -Match 'https?://'
    }

    It 'supports -WhatIf without writing files' {
        $dir = Join-Path $TestDrive 'whatif'
        $null = New-WinSecIncidentReport -Case $script:case -Event $script:events -OutputDirectory $dir -Format Markdown -WhatIf
        Test-Path -LiteralPath $dir | Should -BeFalse
    }
}

Describe 'New-WinSecAbuseReport' {
    BeforeAll {
        $script:abuseDir = Join-Path $TestDrive 'abuse'
        $script:abuse = New-WinSecAbuseReport -Case $script:case -Event $script:events -Finding $script:findings `
            -Attribution $script:attribution -ReporterEmail 'soc@contoso.example' -ReporterOrg 'Contoso SOC' `
            -Format All -OutputDirectory $script:abuseDir -PassThru
    }

    It 'resolves the abuse desk from the ASN' {
        $script:abuse.Provider | Should -Be 'Hetzner'
        $script:abuse.Recipient | Should -Be 'abuse@hetzner.com'
        $script:abuse.NeedsContact | Should -BeFalse
    }

    It 'writes a valid-looking RFC 5322 message' {
        $eml = Get-Content -Raw -LiteralPath ($script:abuse.Files | Where-Object Format -eq 'Eml').Path
        $eml | Should -Match 'MIME-Version: 1\.0'
        $eml | Should -Match 'Content-Type: multipart/mixed; boundary='
        ($eml -split "`r?`n" | Where-Object { $_ -match '^Message-ID:' } | Select-Object -First 1) | Should -Match '@contoso\.example>$'
        $eml | Should -Match 'Content-Transfer-Encoding: base64'
    }

    It 'embeds the evidence as base64 attachments' {
        $eml = Get-Content -Raw -LiteralPath ($script:abuse.Files | Where-Object Format -eq 'Eml').Path
        $eml | Should -Match 'filename="events\.csv"'
        $eml | Should -Match 'filename="evidence\.json"'
    }

    It 'returns a structured JSON payload with the source facts' {
        $json = Get-Content -Raw -LiteralPath ($script:abuse.Files | Where-Object Format -eq 'Json').Path | ConvertFrom-Json
        $json.source.ip | Should -Be '203.0.113.7'
        $json.summary.failures | Should -BeGreaterThan 5
        $json.reporter.email | Should -Be 'soc@contoso.example'
    }

    It 'asks for a contact when the network is unknown' {
        $r = New-WinSecAbuseReport -Event $script:events -TargetIp '203.0.113.7' -Provider Generic `
            -ReporterEmail 'soc@contoso.example' -Format Json -OutputDirectory $TestDrive -WarningAction SilentlyContinue -PassThru
        $r.NeedsContact | Should -BeTrue
    }

    It 'pseudonymises account names on request' {
        $r = New-WinSecAbuseReport -Case $script:case -Event $script:events -Provider Hetzner `
            -ReporterEmail 'soc@contoso.example' -RedactAccounts -Format Json `
            -OutputDirectory (Join-Path $TestDrive 'redacted') -PassThru
        $json = Get-Content -Raw -LiteralPath ($r.Files | Where-Object Format -eq 'Json').Path
        $json | Should -Not -Match 'CORP\\\\alice'
        $json | Should -Match 'acct-[0-9a-f]{6}'
    }
}

Describe 'Export-WinSecIocList' {
    It 'writes CSV rows for every indicator type' {
        $r = Export-WinSecIocList -Case $script:case -Event $script:events -Format Csv -OutputDirectory $TestDrive -PassThru
        $rows = @(Import-Csv -LiteralPath $r.Path)
        $rows.Count | Should -BeGreaterThan 2
        $rows[0].PSObject.Properties.Name | Should -Contain 'Type'
        ($rows | Where-Object Type -eq 'SourceIp').Value | Should -Contain '203.0.113.7'
    }

    It 'writes a STIX 2.1 bundle with indicators' {
        $r = Export-WinSecIocList -Case $script:case -Event $script:events -Format Stix21 -OutputDirectory $TestDrive -PassThru
        $doc = Get-Content -Raw -LiteralPath $r.Path | ConvertFrom-Json
        $doc.type | Should -Be 'bundle'
        $doc.spec_version | Should -Be '2.1'
        @($doc.objects).Count | Should -BeGreaterThan 0
        $doc.objects[0].pattern_type | Should -Be 'stix'
    }

    It 'writes a grep-friendly text list' {
        $r = Export-WinSecIocList -Case $script:case -Event $script:events -Format Txt -OutputDirectory $TestDrive -PassThru
        $lines = @(Get-Content -LiteralPath $r.Path | Where-Object { $_ -notmatch '^#' })
        $lines.Count | Should -BeGreaterThan 2
        $lines[0] | Should -Match "`t"
    }
}

Describe 'Evidence integrity and case re-import' {
    BeforeAll {
        $script:bundleRoot = Join-Path $TestDrive 'bundle'
        $script:caseObj = Export-WinSecInvestigation -Case $script:case -Event $script:events -Finding $script:findings `
            -Session $script:sessions -Coverage $script:coverage -Format All -OutputDirectory $script:bundleRoot -PassThru
        $script:bundleDir = Join-Path $script:bundleRoot $script:caseObj.CaseId
    }

    It 'includes the indicator artifacts in the bundle' {
        Test-Path -LiteralPath (Join-Path $script:bundleDir 'iocs.csv') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:bundleDir 'iocs.json') | Should -BeTrue
    }

    It 'verifies a pristine bundle' {
        $s = Test-WinSecEvidenceIntegrity -Path $script:bundleDir -Summary
        $s.IsIntact | Should -BeTrue
        $s.Problems | Should -Be 0
    }

    It 'detects a modified artifact' {
        $copy = Join-Path $TestDrive 'tamper-mod'
        Copy-Item -LiteralPath $script:bundleDir -Destination $copy -Recurse
        Add-Content -LiteralPath (Join-Path $copy 'events.csv') -Value 'tampered'
        $s = Test-WinSecEvidenceIntegrity -Path $copy -Summary
        $s.Modified | Should -BeGreaterThan 0
        $s.IsIntact | Should -BeFalse
    }

    It 'detects an added file and a missing file' {
        $copy = Join-Path $TestDrive 'tamper-add'
        Copy-Item -LiteralPath $script:bundleDir -Destination $copy -Recurse
        Set-Content -LiteralPath (Join-Path $copy 'extra.txt') -Value 'added' -Encoding utf8NoBOM
        Remove-Item -LiteralPath (Join-Path $copy 'report.md') -Force
        $s = Test-WinSecEvidenceIntegrity -Path $copy -Summary
        $s.Extra | Should -Be 1
        $s.Missing | Should -Be 1
    }

    It 'rehydrates the case and its events' {
        $b = Import-WinSecCase -Path $script:bundleDir
        $b.Case.CaseId | Should -Be $script:case.CaseId
        $b.Events.Count | Should -Be $script:events.Count
        $b.Events[0].GetType().Name | Should -Be 'WinSecEvent'
        $b.Events[0].TimeUtc | Should -BeOfType [datetime]
        @($b.Coverage).Count | Should -Be 1
        @($b.Attribution).Count | Should -Be 1
    }
}
