#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
}

Describe 'IP validation (Test-WinSecIpAddress)' {
    It 'Accepts well-formed IPv4: <Ip>' -TestCases @(
        @{ Ip = '203.0.113.7' }, @{ Ip = '10.0.0.1' }, @{ Ip = '255.255.255.255' }, @{ Ip = '0.0.0.0' }
    ) {
        InModuleScope WinSecHunter -Parameters @{ Ip = $Ip } { param($Ip)
            Test-WinSecIpAddress -Value $Ip | Should -BeTrue }
    }
    It 'Accepts well-formed IPv6: <Ip>' -TestCases @(
        @{ Ip = '2001:db8::1' }, @{ Ip = '::1' }, @{ Ip = 'fe80::abcd:1234' },
        @{ Ip = '2001:0db8:0000:0000:0000:ff00:0042:8329' }, @{ Ip = '::ffff:203.0.113.7' }
    ) {
        InModuleScope WinSecHunter -Parameters @{ Ip = $Ip } { param($Ip)
            Test-WinSecIpAddress -Value $Ip | Should -BeTrue }
    }
    It 'Rejects malformed input: <Bad>' -TestCases @(
        @{ Bad = 'abc' }, @{ Bad = '1.2.3' }, @{ Bad = '1.2.3.4.5' }, @{ Bad = '1.2.3.999' },
        @{ Bad = '1' }, @{ Bad = '01.02.03.04' }, @{ Bad = '' }, @{ Bad = 'fe80::1%eth0' },
        @{ Bad = '[::1]' }, @{ Bad = '2001:db8::1/129' }, @{ Bad = '10.0.0.0/33' },
        @{ Bad = 'dead::beef::1' }, @{ Bad = '192.168.1.1/24/8' }
    ) {
        InModuleScope WinSecHunter -Parameters @{ Bad = $Bad } { param($Bad)
            Test-WinSecIpAddress -Value $Bad -AllowCidr | Should -BeFalse }
    }
    It 'Accepts CIDR only with -AllowCidr' {
        InModuleScope WinSecHunter {
            Test-WinSecIpAddress -Value '10.0.0.0/24' | Should -BeFalse
            Test-WinSecIpAddress -Value '10.0.0.0/24' -AllowCidr | Should -BeTrue
            Test-WinSecIpAddress -Value '2001:db8::/64' -AllowCidr | Should -BeTrue
        }
    }
}

Describe 'Canonicalization (ConvertTo-WinSecCanonicalIp)' {
    It 'Collapses IPv4-mapped IPv6 to dotted quad' {
        InModuleScope WinSecHunter {
            ConvertTo-WinSecCanonicalIp '::ffff:203.0.113.7' | Should -Be '203.0.113.7'
            ConvertTo-WinSecCanonicalIp '::ffff:cb00:7107' | Should -Be '203.0.113.7'
        }
    }
    It 'Compresses and lowercases IPv6' {
        InModuleScope WinSecHunter {
            ConvertTo-WinSecCanonicalIp '2001:0DB8:0000:0000:0000:0000:0000:0001' | Should -Be '2001:db8::1'
        }
    }
    It 'Strips CIDR suffix from base address' {
        InModuleScope WinSecHunter {
            ConvertTo-WinSecCanonicalIp '192.168.0.0/16' | Should -Be '192.168.0.0'
        }
    }
    It 'Throws on garbage' {
        InModuleScope WinSecHunter {
            { ConvertTo-WinSecCanonicalIp 'not-an-ip' } | Should -Throw
        }
    }
}

Describe 'Match regex (Get-WinSecIpMatchRegex)' {
    It 'Matches the exact address in event-like text' {
        InModuleScope WinSecHunter {
            $rx = Get-WinSecIpMatchRegex '203.0.113.7'
            $rx.IsMatch('<Data Name="IpAddress">203.0.113.7</Data>') | Should -BeTrue
            $rx.IsMatch('::ffff:203.0.113.7') | Should -BeTrue
            $rx.IsMatch('from 203.0.113.7:55123 to 10.0.0.5:445') | Should -BeTrue
        }
    }
    It 'Respects boundaries — no substring false positives' {
        InModuleScope WinSecHunter {
            $rx = Get-WinSecIpMatchRegex '203.0.113.7'
            $rx.IsMatch('203.0.113.70') | Should -BeFalse
            $rx.IsMatch('1203.0.113.7') | Should -BeFalse
            $rx.IsMatch('203.0.113.7.8') | Should -BeFalse
        }
    }
    It 'Handles IPv6 compressed and expanded renderings' {
        InModuleScope WinSecHunter {
            $rx = Get-WinSecIpMatchRegex '2001:db8::1'
            $rx.IsMatch('Address=2001:db8::1;') | Should -BeTrue
            $rx.IsMatch('2001:0db8:0000:0000:0000:0000:0000:0001') | Should -BeTrue
            $rx.IsMatch('2001:db8::11') | Should -BeFalse
        }
    }
}

Describe 'CIDR membership (Test-WinSecIpInCidr)' {
    It 'Matches members and rejects non-members' {
        InModuleScope WinSecHunter {
            Test-WinSecIpInCidr '10.0.0.5' '10.0.0.0/24' | Should -BeTrue
            Test-WinSecIpInCidr '10.0.1.5' '10.0.0.0/24' | Should -BeFalse
            Test-WinSecIpInCidr '172.16.5.4' '172.16.0.0/12' | Should -BeTrue
            Test-WinSecIpInCidr '172.32.0.1' '172.16.0.0/12' | Should -BeFalse
        }
    }
    It 'Works for IPv6 and mapped forms' {
        InModuleScope WinSecHunter {
            Test-WinSecIpInCidr '2001:db8::dead:beef' '2001:db8::/64' | Should -BeTrue
            Test-WinSecIpInCidr '2001:db9::1' '2001:db8::/64' | Should -BeFalse
            Test-WinSecIpInCidr '::ffff:10.0.0.9' '10.0.0.0/24' | Should -BeTrue
        }
    }
    It 'Never throws on invalid input' {
        InModuleScope WinSecHunter {
            Test-WinSecIpInCidr 'garbage' '10.0.0.0/24' | Should -BeFalse
            Test-WinSecIpInCidr '10.0.0.1' 'also-garbage' | Should -BeFalse
        }
    }
}

Describe 'Classification (Get-WinSecIpClassification)' {
    It 'Classifies address classes correctly' {
        InModuleScope WinSecHunter {
            (Get-WinSecIpClassification '10.1.2.3').IsPrivate | Should -BeTrue
            (Get-WinSecIpClassification '172.16.0.1').IsPrivate | Should -BeTrue
            (Get-WinSecIpClassification '172.32.0.1').IsPrivate | Should -BeFalse
            (Get-WinSecIpClassification '192.168.1.1').IsPrivate | Should -BeTrue
            (Get-WinSecIpClassification '100.64.0.1').IsPrivate | Should -BeTrue
            (Get-WinSecIpClassification '169.254.1.1').IsLinkLocal | Should -BeTrue
            (Get-WinSecIpClassification '::1').IsLoopback | Should -BeTrue
            (Get-WinSecIpClassification '8.8.8.8').IsPrivate | Should -BeFalse
            (Get-WinSecIpClassification '8.8.8.8').Version | Should -Be 4
            (Get-WinSecIpClassification '2001:db8::1').Version | Should -Be 6
            (Get-WinSecIpClassification 'fc00::1').IsPrivate | Should -BeTrue
        }
    }
}

Describe 'Range expansion (Expand-WinSecIpRange)' {
    It 'Expands /30 excluding network and broadcast by default' {
        $r = Expand-WinSecIpRange '203.0.113.0/30'
        $r | Should -Be @('203.0.113.1', '203.0.113.2')
    }
    It 'Includes network/broadcast on request' {
        $r = Expand-WinSecIpRange '203.0.113.0/30' -IncludeNetworkAddress -IncludeBroadcast
        $r | Should -Be @('203.0.113.0', '203.0.113.1', '203.0.113.2', '203.0.113.3')
    }
    It 'Expands dash ranges both directions' {
        (Expand-WinSecIpRange '10.0.0.5-10.0.0.7') | Should -Be @('10.0.0.5', '10.0.0.6', '10.0.0.7')
        (Expand-WinSecIpRange '10.0.0.7-10.0.0.5') | Should -Be @('10.0.0.5', '10.0.0.6', '10.0.0.7')
    }
    It 'Expands small IPv6 ranges' {
        (Expand-WinSecIpRange '2001:db8::/126' -IncludeNetworkAddress -IncludeBroadcast) |
            Should -Be @('2001:db8::', '2001:db8::1', '2001:db8::2', '2001:db8::3')
    }
    It 'Refuses ranges above the safety cap' {
        { Expand-WinSecIpRange '10.0.0.0/8' } | Should -Throw '*MaxAddresses*'
        { Expand-WinSecIpRange '2001:db8::/64' } | Should -Throw '*MaxAddresses*'
    }
    It 'Rejects invalid input' {
        { Expand-WinSecIpRange 'nonsense' } | Should -Throw
        { Expand-WinSecIpRange '10.0.0.1-2001:db8::1' } | Should -Throw
    }
}
