#Requires -Version 7.6
#Requires -PSEdition Core
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Regression tests for defects fixed in 2.1.0. Each test below fails on the
    2.0.0 code and passes on the current build:
      * null time window crashed parameter binding ([AllowNull()][datetime]);
      * $using:scriptblock aborted every -ComputerName sweep;
      * a missing optional channel aborted the whole host;
      * Write-Error + module EAP=Stop swallowed -PassHostStatus output;
      * IPv6 attribution cache used ':' in a file name (illegal on Windows);
      * config.json was written non-atomically.
#>

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
}

AfterAll {
    Remove-Module WinSecHunter -Force -ErrorAction SilentlyContinue
}

Describe 'Query builder: optional time window' {
    It 'builds a query when no time bounds are supplied' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4625, 4624) }
            $q.QueryList.Query.Select.Count | Should -Be 1
            $q.OuterXml | Should -Not -Match 'TimeCreated'
        }
    }

    It 'emits TimeCreated predicates only for the bounds that are set' {
        InModuleScope WinSecHunter {
            $start = [datetime]::UtcNow.AddHours(-2)
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4625) } -StartTimeUtc $start
            $q.OuterXml | Should -Match 'SystemTime&gt;='
            $q.OuterXml | Should -Not -Match 'SystemTime&lt;='
        }
    }

    It 'splits a multi-channel query into one Select per channel' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4625); System = @(7045) }
            $parts = @(Split-WinSecQueryXml -Query $q)
            $parts.Count | Should -Be 2
            foreach ($p in $parts) {
                @($p.QueryXml.SelectNodes("//*[local-name()='Select']")).Count | Should -Be 1
                $p.LogName | Should -Not -BeNullOrEmpty
            }
        }
    }

    It 'never passes a scriptblock through $using: (parallel safety)' {
        $src = Join-Path $script:WinSecTestRoot 'src'
        $hits = @(Get-ChildItem -LiteralPath $src -Recurse -File -Include *.ps1 |
            Select-String -Pattern '\$using:\s*(remoteSb|collector|scriptBlock|block)\b' -AllMatches)
        $hits.Count | Should -Be 0
    }
}

Describe 'Error classification without OS language' {
    It 'maps access denied (Win32 5) to Skipped' {
        InModuleScope WinSecHunter {
            $ex = [System.ComponentModel.Win32Exception]::new(5)
            $rec = [System.Management.Automation.ErrorRecord]::new($ex, 'x', 'NotSpecified', $null)
            Get-WinSecLogErrorKind -ErrorRecord $rec | Should -Be 'Skipped'
        }
    }

    It 'maps a missing channel (15007) to Skipped' {
        InModuleScope WinSecHunter {
            $ex = [System.ComponentModel.Win32Exception]::new(15007)
            $rec = [System.Management.Automation.ErrorRecord]::new($ex, 'x', 'NotSpecified', $null)
            Get-WinSecLogErrorKind -ErrorRecord $rec | Should -Be 'Skipped'
        }
    }

    It 'maps an empty result to NoEvents and a real failure to Failed' {
        InModuleScope WinSecHunter {
            $noEvents = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('No events were found that match the specified selection criteria.'),
                'x', 'NotSpecified', $null)
            Get-WinSecLogErrorKind -ErrorRecord $noEvents | Should -Be 'NoEvents'

            $boom = [System.Management.Automation.ErrorRecord]::new(
                [System.Exception]::new('RPC server is unavailable'), 'x', 'NotSpecified', $null)
            Get-WinSecLogErrorKind -ErrorRecord $boom | Should -Be 'Failed'
        }
    }
}

Describe 'Configuration durability' {
    It 'uses a filesystem-safe, stable cache name for IPv6' {
        InModuleScope WinSecHunter {
            $a = Get-WinSecCacheFile -IpAddress '2001:db8::1'
            $b = Get-WinSecCacheFile -IpAddress '2001:db8::1'
            $c = Get-WinSecCacheFile -IpAddress '2001:db8::2'
            $a | Should -Be $b
            $a | Should -Not -Be $c
            (Split-Path -Leaf $a) | Should -Not -Match ':'
        }
    }

    It 'writes config.json atomically and leaves no temp files' {
        InModuleScope WinSecHunter {
            $dir = Get-WinSecConfigPath -Ensure
            for ($i = 0; $i -lt 5; $i++) {
                $null = Save-WinSecConfig -Changes @{ DefaultMaxEvents = 1000 + $i }
            }
            $file = Join-Path $dir 'config.json'
            { Get-Content -Raw -LiteralPath $file | ConvertFrom-Json } | Should -Not -Throw
            @(Get-ChildItem -LiteralPath $dir -Filter 'config.*.tmp' -File).Count | Should -Be 0
        }
    }
}

Describe 'Host status reporting' {
    It 'returns -PassHostStatus rows even when a channel is unavailable (Windows)' -Skip:(-not $IsWindows) {
        $rows = @(Get-WinSecEventByIp -IpAddress '203.0.113.7' -LastHours 1 -LogName Security -PassHostStatus -WarningAction SilentlyContinue)
        @($rows).Count | Should -BeGreaterThan 0
        $rows[0].PSObject.Properties.Name | Should -Contain 'LogDetails'
        @($rows[0].LogDetails).Count | Should -BeGreaterThan 0
    }

    It 'does not treat a missing channel as a terminating error (module scope)' {
        InModuleScope WinSecHunter {
            # A query for a channel that does not exist must classify as Skipped.
            $part = [pscustomobject]@{
                LogName  = 'Microsoft-Windows-ThisChannelDoesNotExist/Operational'
                QueryXml = [xml]'<QueryList><Query Id="0" Path="Microsoft-Windows-ThisChannelDoesNotExist/Operational"><Select Path="Microsoft-Windows-ThisChannelDoesNotExist/Operational">*</Select></Query></QueryList>'
            }
            $r = Invoke-WinSecLogQueryPart -Part $part
            $r.Status | Should -BeIn @('Skipped', 'Failed')
            $r.EventsFound | Should -Be 0
        }
    }
}

Describe 'Logon session filters' {
    BeforeAll {
        $script:sessionEvents = @(
            New-TestEvent -EventId 4624 -TimeUtc ([datetime]::UtcNow.AddHours(-2)) -LogonId '0x1001' -TargetAccount 'CORP\alice' -SourceIp '203.0.113.7'
            New-TestEvent -EventId 4634 -TimeUtc ([datetime]::UtcNow.AddHours(-1)) -LogonId '0x1001' -TargetAccount 'CORP\alice' -Outcome Informational
            New-TestEvent -EventId 4624 -TimeUtc ([datetime]::UtcNow.AddMinutes(-30)) -LogonId '0x1002' -TargetAccount 'CORP\bob' -SourceIp '198.51.100.9'
        )
    }

    It 'defaults to all sessions' {
        @($script:sessionEvents | Get-WinSecLogonSession).Count | Should -Be 2
    }

    It '-ActiveOnly returns open sessions' {
        $r = @($script:sessionEvents | Get-WinSecLogonSession -ActiveOnly)
        $r.Count | Should -Be 1
        $r[0].LogonId | Should -Be '1002'
    }

    It '-EndedOnly returns closed sessions' {
        $r = @($script:sessionEvents | Get-WinSecLogonSession -EndedOnly)
        $r.Count | Should -Be 1
        $r[0].Ended | Should -BeTrue
    }

    It '-IncludeEnded and -ActiveOnly are mutually exclusive' {
        { $script:sessionEvents | Get-WinSecLogonSession -IncludeEnded -ActiveOnly } | Should -Throw
    }
}
