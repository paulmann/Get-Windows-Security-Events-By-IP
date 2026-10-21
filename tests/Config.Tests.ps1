#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
}

Describe 'Configuration (Set/Get-WinSecHunterOption)' {
    It 'Reads defaults before anything is set' {
        Get-WinSecHunterOption -Name DefaultProfile | Should -Be 'IncidentResponse'
        Get-WinSecHunterOption -Name DefaultMaxEvents | Should -Be 5000
    }

    It 'Round-trips single options and persists to config.json' {
        Set-WinSecHunterOption -Name DefaultProfile -Value 'BruteForce' -Confirm:$false
        Get-WinSecHunterOption -Name DefaultProfile | Should -Be 'BruteForce'
        (Join-Path $env:WINSECHUNTER_CONFIG_DIR 'config.json') | Should -Exist
    }

    It 'Survives module reload' {
        Import-Module $script:WinSecManifestPath -Force
        Get-WinSecHunterOption -Name DefaultProfile | Should -Be 'BruteForce'
    }

    It 'Bulk-sets with type coercion' {
        Set-WinSecHunterOption -Options @{ DefaultMaxEvents = '12345'; IncludeMessage = 'true' } -Confirm:$false
        $v = Get-WinSecHunterOption -Name DefaultMaxEvents
        $v | Should -Be 12345
        $v.GetType().Name | Should -Be 'Int32'
        Get-WinSecHunterOption -Name IncludeMessage | Should -BeTrue
    }

    It 'Rejects unknown options with the valid list' {
        { Set-WinSecHunterOption -Options @{ Bogus = 1 } -Confirm:$false } | Should -Throw '*Valid options*'
        { Set-WinSecHunterOption -Name DefaultProfile -Value 1 -Confirm:$false } | Should -Not -Throw
    }

    It 'Validates the threat-intel provider' {
        { Set-WinSecHunterOption -Name ThreatIntelProvider -Value 'VirusTotal' -Confirm:$false } |
            Should -Throw '*must be one of*'
        { Set-WinSecHunterOption -Name ThreatIntelProvider -Value 'AbuseIPDB' -Confirm:$false } |
            Should -Not -Throw
    }

    It 'Resets to defaults' {
        Set-WinSecHunterOption -Reset -Confirm:$false
        Get-WinSecHunterOption -Name DefaultProfile | Should -Be 'IncidentResponse'
        Get-WinSecHunterOption -Name DefaultMaxEvents | Should -Be 5000
    }

    It 'ShowResolved exposes key PRESENCE, never key VALUES' {
        $env:ABUSEIPDB_KEY = 'super-secret-test-key'
        try {
            $r = Get-WinSecHunterOption -ShowResolved
            $r.AbuseIpDbKeyPresent | Should -BeTrue
            ($r | Out-String -Width 500) | Should -Not -Match 'super-secret-test-key'
            $r.ModuleVersion | Should -Be (Import-PowerShellDataFile $script:WinSecManifestPath).ModuleVersion
            $r.CatalogVersion | Should -Not -BeNullOrEmpty
        }
        finally { Remove-Item Env:ABUSEIPDB_KEY -ErrorAction SilentlyContinue }
    }

    It 'Supports WhatIf' {
        (Get-Command Set-WinSecHunterOption).Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }
}

Describe 'Attribution offline path (Resolve-WinSecIpAttribution)' {
    It 'Classifies private IPs without any network calls' {
        $a = Resolve-WinSecIpAttribution -IpAddress '192.168.1.10' -Provider None -NoCache
        $a.IpAddress | Should -Be '192.168.1.10'
        $a.IsPrivate | Should -BeTrue
        $a.Version | Should -Be 4
        $a.Verdict | Should -Match 'private'
        $a.Provider | Should -BeNullOrEmpty
    }

    It 'Normalizes IPv6 and detects loopback' {
        $a = Resolve-WinSecIpAttribution -IpAddress '2001:0DB8:0000:0000:0000:0000:0000:0001' -Provider None -NoCache
        $a.IpAddress | Should -Be '2001:db8::1'
        ($a2 = Resolve-WinSecIpAttribution '::1' -Provider None -NoCache).IsLoopback | Should -BeTrue
        $a2.Verdict | Should -Match 'Loopback'
    }

    It 'Caches results and rehydrates from cache' {
        $a1 = Resolve-WinSecIpAttribution -IpAddress '203.0.113.99' -Provider None
        $a1.FromCache | Should -BeFalse
        $a2 = Resolve-WinSecIpAttribution -IpAddress '203.0.113.99' -Provider None
        $a2.FromCache | Should -BeTrue
        $a2.IpAddress | Should -Be '203.0.113.99'
        $a2.Version | Should -Be 4
    }

    It 'Rejects invalid input via the pipeline' {
        # Invalid values are reported as warnings so one bad address cannot abort
        # a batch; -WarningAction Stop turns that warning into a terminating error.
        { 'not-an-ip' | Resolve-WinSecIpAttribution -Provider None -WarningAction Stop } | Should -Throw
    }
}
