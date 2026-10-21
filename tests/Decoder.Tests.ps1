#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
}

Describe 'NTSTATUS decoding' {
    It 'Decodes common logon failure codes' {
        InModuleScope WinSecHunter {
            Get-WinSecStatusDescription '0xC000006A' | Should -Match 'Incorrect password'
            Get-WinSecStatusDescription '0xc000006a' | Should -Match 'Incorrect password'
            Get-WinSecStatusDescription '0xC0000064' | Should -Match 'does not exist'
            Get-WinSecStatusDescription '0xC0000234' | Should -Match 'locked out'
            Get-WinSecStatusDescription '0xC0000072' | Should -Match 'disabled'
            Get-WinSecStatusDescription '0xC0000071' | Should -Match 'Password expired'
            Get-WinSecStatusDescription '0xC0000224' | Should -Match 'must change password'
            Get-WinSecStatusDescription '0xC000015B' | Should -Match 'logon type'
        }
    }
    It 'Accepts decimal (signed) representations' {
        InModuleScope WinSecHunter {
            # 0xC000006A == -1073741718 (signed int32)
            Get-WinSecStatusDescription '-1073741718' | Should -Match 'Incorrect password'
        }
    }
    It 'Returns null for empty/unknown codes' {
        InModuleScope WinSecHunter {
            Get-WinSecStatusDescription '' | Should -BeNullOrEmpty
            Get-WinSecStatusDescription '-' | Should -BeNullOrEmpty
            Get-WinSecStatusDescription '0xC0099999' | Should -BeNullOrEmpty
        }
    }
}

Describe 'Kerberos decoding' {
    It 'Decodes pre-auth failure codes for 4771' {
        InModuleScope WinSecHunter {
            Get-WinSecStatusDescription '0x18' -EventId 4771 | Should -Match 'Pre-authentication.*invalid'
            Get-WinSecStatusDescription '0x12' -EventId 4771 | Should -Match 'revoked'
            Get-WinSecStatusDescription '0x17' -EventId 4771 | Should -Match 'expired'
            Get-WinSecStatusDescription '0x25' -EventId 4771 | Should -Match 'Clock skew'
            Get-WinSecStatusDescription '0x6'  -EventId 4771 | Should -Match 'Client not found'
            Get-WinSecStatusDescription '0x2C' -EventId 4771 | Should -Match 'version of key'
        }
    }
    It 'Distinguishes short Kerberos codes from NTSTATUS by context' {
        InModuleScope WinSecHunter {
            # 0x12 without event context would be NTSTATUS space; with 4768 it is Kerberos
            Get-WinSecStatusDescription '0x0' -EventId 4768 | Should -Match 'No error'
        }
    }
}

Describe 'FailureReason (%%) decoding' {
    It 'Uses the Microsoft-documented %% string table' {
        InModuleScope WinSecHunter {
            Get-WinSecStatusDescription '%%2313' | Should -Match 'Unknown user name or bad password'
            Get-WinSecStatusDescription '%%2305' | Should -Match 'user account has expired'
            Get-WinSecStatusDescription '%%2309' | Should -Match "password has expired"
            Get-WinSecStatusDescription '%%2310' | Should -Match 'disabled'
            Get-WinSecStatusDescription '%%2312' | Should -Match 'not allowed to log on'
            Get-WinSecStatusDescription '%%2304' | Should -Match 'error occurred during logon'
        }
    }
    It 'Corrects the legacy script mapping (2305 was mislabeled "Account does not exist")' {
        InModuleScope WinSecHunter {
            Get-WinSecStatusDescription '%%2305' | Should -Not -Match 'does not exist'
        }
    }
}

Describe 'Logon type names' {
    It 'Maps the standard logon types' {
        InModuleScope WinSecHunter {
            Get-WinSecLogonTypeName 10 | Should -Match 'RDP'
            Get-WinSecLogonTypeName 3  | Should -Match 'Network'
            Get-WinSecLogonTypeName 2  | Should -Match 'Interactive'
            Get-WinSecLogonTypeName 9  | Should -Match 'netonly'
            Get-WinSecLogonTypeName 0  | Should -BeNullOrEmpty
            Get-WinSecLogonTypeName 99 | Should -Be '99'
        }
    }
}

Describe 'Network constants' {
    It 'Decodes WFP direction %% codes' {
        InModuleScope WinSecHunter {
            Get-WinSecNetworkConstant '%%14592' -Type Direction | Should -Be 'Inbound'
            Get-WinSecNetworkConstant '%%14593' -Type Direction | Should -Be 'Outbound'
        }
    }
    It 'Decodes IANA protocol numbers and passes names through' {
        InModuleScope WinSecHunter {
            Get-WinSecNetworkConstant '6' -Type Protocol | Should -Be 'TCP'
            Get-WinSecNetworkConstant '17' -Type Protocol | Should -Be 'UDP'
            Get-WinSecNetworkConstant 'tcp' -Type Protocol | Should -Be 'TCP'
            Get-WinSecNetworkConstant '253' -Type Protocol | Should -Be 'proto:253'
        }
    }
}
