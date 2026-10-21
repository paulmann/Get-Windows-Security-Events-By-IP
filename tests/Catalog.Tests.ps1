#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
    $script:CatalogPath = Join-Path $script:WinSecTestRoot 'src/WinSecHunter/Resources/EventCatalog.json'
    $script:Catalog = Get-Content -Raw $script:CatalogPath | ConvertFrom-Json -AsHashtable
}

Describe 'Event catalog integrity' {
    It 'Contains a substantial, deduplicated event set' {
        $script:Catalog.events.Count | Should -BeGreaterOrEqual 140
        $keys = $script:Catalog.events | ForEach-Object { '{0}|{1}' -f $_['Log'], $_['Id'] }
        ($keys | Select-Object -Unique).Count | Should -Be $keys.Count
    }
    It 'Every entry has valid Category, Importance and well-formed ATT&CK IDs' {
        $cats = InModuleScope WinSecHunter { [enum]::GetNames([WinSecEventCategory]) }
        $imps = InModuleScope WinSecHunter { [enum]::GetNames([WinSecSeverity]) }
        $bad = @()
        foreach ($e in $script:Catalog.events) {
            if ($e['Category'] -notin $cats) { $bad += "$($e['Id']): category $($e['Category'])" }
            if ($e['Importance'] -notin $imps) { $bad += "$($e['Id']): importance $($e['Importance'])" }
            foreach ($a in @($e['Attack'])) {
                if ($a -and $a -notmatch '^T\d{4}(\.\d{3})?$') { $bad += "$($e['Id']): attack '$a'" }
            }
            if (-not $e['Name']) { $bad += "$($e['Id']): missing name" }
        }
        $bad | Should -Be @() -Because ($bad -join '; ')
    }
    It 'Every entry references a declared log' {
        $logs = @($script:Catalog.logs.Values)
        $bad = @($script:Catalog.events | Where-Object { $_['Log'] -notin $logs })
        $bad.Count | Should -Be 0
    }
    It 'Profile categories and event ids resolve' {
        $cats = InModuleScope WinSecHunter { [enum]::GetNames([WinSecEventCategory]) }
        $ids  = @($script:Catalog.events | ForEach-Object { [int]$_['Id'] } | Select-Object -Unique)
        $bad = @()
        foreach ($p in $script:Catalog.profiles.GetEnumerator()) {
            foreach ($c in @($p.Value['categories'])) { if ($c -and $c -notin $cats) { $bad += "$($p.Key): $c" } }
            foreach ($i in @($p.Value['eventIds'])) { if ($null -ne $i -and [int]$i -notin $ids) { $bad += "$($p.Key): id $i" } }
        }
        $bad | Should -Be @() -Because ($bad -join '; ')
    }
    It 'Critical IR anchors are present and correctly shaped' {
        $e4625 = $script:Catalog.events | Where-Object { $_['Id'] -eq 4625 -and $_['Log'] -eq 'Security' }
        $e4625['IpFields'] | Should -Contain 'IpAddress'
        $e4625['Importance'] | Should -Be 'Critical'
        ($script:Catalog.events | Where-Object { $_['Id'] -eq 1149 })['IpFields'] | Should -Contain 'Address'
        $s3 = $script:Catalog.events | Where-Object { $_['Id'] -eq 3 -and $_['Log'] -like '*Sysmon*' }
        $s3['IpFields'] | Should -Contain 'SourceIp'
        $s3['IpFields'] | Should -Contain 'DestinationIp'
        $e1102 = $script:Catalog.events | Where-Object { $_['Id'] -eq 1102 }
        $e1102['Importance'] | Should -Be 'Critical'
        $e1102['Attack'] | Should -Contain 'T1070.001'
    }
}

Describe 'Catalog browsing (Get-WinSecEventCatalog)' {
    It 'Lists all profiles' {
        $p = @(Get-WinSecEventCatalog -ListProfiles)
        $p.Count | Should -Be 14
        ($p | Where-Object Profile -eq 'IncidentResponse').Description | Should -Match 'DEFAULT'
    }
    It '-IpMatchable returns only events carrying IP fields' {
        $m = @(Get-WinSecEventCatalog -IpMatchable)
        $m.Count | Should -BeGreaterThan 10
        $m | ForEach-Object { $_.IpFields | Should -Not -BeNullOrEmpty }
    }
    It 'Filters by ATT&CK technique' {
        $r = @(Get-WinSecEventCatalog -AttackId 'T1021.001')
        $ids = $r | ForEach-Object EventId
        $ids | Should -Contain 4778
        $ids | Should -Contain 1149
        $ids | Should -Contain 21
    }
    It 'Filters by profile, category and importance simultaneously' {
        $r = @(Get-WinSecEventCatalog -Profile BruteForce)
        ($r | ForEach-Object EventId) | Should -Contain 4625
        $k = @(Get-WinSecEventCatalog -Category Kerberos)
        ($k | ForEach-Object EventId) | Should -Contain 4771
        $c = @(Get-WinSecEventCatalog -Importance Critical)
        ($c | ForEach-Object Importance | Select-Object -Unique) | Should -Be @('Critical')
    }
    It 'Resolves log aliases' {
        $r = @(Get-WinSecEventCatalog -LogName RDP)
        ($r | ForEach-Object Log | Select-Object -Unique).Count | Should -Be 2
    }
}
