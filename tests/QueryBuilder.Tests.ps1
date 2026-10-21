#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
}

Describe 'XPath query builder (New-WinSecEventQuery)' {
    It 'Pushes event IDs and UTC time window into the Select' {
        InModuleScope WinSecHunter {
            $start = [datetime]::SpecifyKind([datetime]'2026-10-01 00:00:00', [System.DateTimeKind]::Utc)
            $end   = [datetime]::SpecifyKind([datetime]'2026-10-02 00:00:00', [System.DateTimeKind]::Utc)
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4625) } -StartTimeUtc $start -EndTimeUtc $end
            $x = $q.OuterXml
            $x | Should -Match 'EventID=4625'
            $x | Should -Match "SystemTime(&gt;|>)='2026-10-01T00:00:00\.000Z'"
            $x | Should -Match "SystemTime(&lt;|<)='2026-10-02T00:00:00\.000Z'"
            $q | Should -BeOfType [xml]
        }
    }

    It 'Gates IP-bearing events on exact Data equality incl. mapped variants and UserData' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4625) } -IpExactVariants @('203.0.113.7', '::ffff:203.0.113.7')
            $x = $q.OuterXml
            $x | Should -Match "Data='203\.0\.113\.7'"
            $x | Should -Match "Data='::ffff:203\.0\.113\.7'"
            $x | Should -Match "Address='203\.0\.113\.7'"   # UserData/EventXML clause for RDP logs
        }
    }

    It 'Passes through IDs without IP fields (contextual evidence stays visible)' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4740) } -IpExactVariants @('203.0.113.7')
            $x = $q.OuterXml
            $x | Should -Match 'EventID=4740'
            $x | Should -Not -Match "Data='203"
        }
    }

    It 'Splits gated and pass-through IDs inside one Select' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4625, 4740) } -IpExactVariants @('203.0.113.7')
            $x = $q.OuterXml
            $x | Should -Match '\(EventID=4625\)'
            $x | Should -Match '\(EventID=4740\)'
            ($x | Select-String -Pattern ' and \(\*\[EventData' -AllMatches).Matches.Count | Should -Be 1
        }
    }

    It 'Omits the IP gate entirely for deep scans / CIDR sweeps' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{ Security = @(4625) }
            $q.OuterXml | Should -Not -Match "Data='"
        }
    }

    It 'Emits one Select per log, QueryList Path = first (sorted) log' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{
                'Security' = @(4625)
                'System'   = @(7045)
            }
            $x = $q.OuterXml
            ($x | Select-String -Pattern '<Select' -AllMatches).Matches.Count | Should -Be 2
            $q.QueryList.Query.Path | Should -Be 'Security'
            $x | Should -Match 'Path="System"'
        }
    }

    It 'Supports EVTX file mode via -PathOverride' {
        InModuleScope WinSecHunter {
            $q = New-WinSecEventQuery -LogEventIds @{ 'Security' = @(4625) } -PathOverride 'C:\cases\dc01-security.evtx'
            $x = $q.OuterXml
            $x | Should -Match 'Path="C:\\cases\\dc01-security\.evtx"'
        }
    }

    It 'Throws on empty scope' {
        InModuleScope WinSecHunter {
            { New-WinSecEventQuery -LogEventIds @{} } | Should -Throw
        }
    }
}

Describe 'Scope resolution (Get-WinSecEventIdsByScope)' {
    It 'Defaults to the IncidentResponse profile' {
        InModuleScope WinSecHunter {
            $s = Get-WinSecEventIdsByScope
            $s.Profiles | Should -Contain 'IncidentResponse'
            $s.LogEventIds.Keys | Should -Contain 'Security'
            $s.LogEventIds['Security'] | Should -Contain 4625
        }
    }
    It 'Expands explicit profiles and unions them' {
        InModuleScope WinSecHunter {
            $s = Get-WinSecEventIdsByScope -Profile FailedAuth, Rdp
            $s.LogEventIds['Security'] | Should -Contain 4625
            $s.LogEventIds['Security'] | Should -Contain 4778
            $s.LogEventIds.Keys | Should -Contain 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational'
        }
    }
    It 'Unions categories and explicit ids' {
        InModuleScope WinSecHunter {
            $s = Get-WinSecEventIdsByScope -Category Kerberos -EventId 7045
            $s.LogEventIds['Security'] | Should -Contain 4771
            $s.LogEventIds['System'] | Should -Contain 7045
        }
    }
    It 'Honors log aliases (RDP → RCM + LSM)' {
        InModuleScope WinSecHunter {
            $s = Get-WinSecEventIdsByScope -Profile All -LogName RDP
            $s.LogEventIds.Keys.Count | Should -Be 2
            $s.LogEventIds.Keys | Should -Not -Contain 'Security'
        }
    }
    It 'Rejects unknown profiles with actionable message' {
        InModuleScope WinSecHunter {
            { Get-WinSecEventIdsByScope -Profile 'NoSuchProfile' } | Should -Throw '*Available*'
        }
    }
    It 'Places unknown event ids into Security (or the requested log)' {
        InModuleScope WinSecHunter {
            $s = Get-WinSecEventIdsByScope -EventId 13371
            $s.LogEventIds['Security'] | Should -Contain 13371
            $s2 = Get-WinSecEventIdsByScope -EventId 13371 -LogName System
            $s2.LogEventIds['System'] | Should -Contain 13371
        }
    }
}
