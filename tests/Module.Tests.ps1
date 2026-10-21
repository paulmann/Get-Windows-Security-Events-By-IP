#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Initialize-WinSecTestModule
}

Describe 'Module integrity' {
    Context 'Manifest' {
        It 'Has a valid manifest' {
            { Test-ModuleManifest -Path $script:WinSecManifestPath -ErrorAction Stop } | Should -Not -Throw
        }
        It 'Requires PowerShell 7.6+ and Core edition' {
            $mf = Test-ModuleManifest -Path $script:WinSecManifestPath
            $mf.PowerShellVersion.ToString() | Should -BeGreaterOrEqual '7.6'
            $mf.CompatiblePSEditions | Should -Contain 'Core'
        }
        It 'Exports exactly the documented public API (20 functions)' {
            $mf = Test-ModuleManifest -Path $script:WinSecManifestPath
            @($mf.ExportedFunctions.Keys).Count | Should -Be 20
            foreach ($name in 'Get-WinSecEventByIp', 'Export-WinSecInvestigation', 'Show-WinSecHunterHelp',
                'New-WinSecIncidentReport', 'New-WinSecAbuseReport', 'Export-WinSecIocList',
                'Test-WinSecEvidenceIntegrity', 'Import-WinSecCase') {
                $mf.ExportedFunctions.Keys | Should -Contain $name
            }
            @($mf.ExportedAliases.Keys).Count | Should -Be 0
            @($mf.ExportedCmdlets.Keys).Count | Should -Be 0
        }
        It 'Carries PolyForm Noncommercial license metadata and attribution' {
            $mf = Test-ModuleManifest -Path $script:WinSecManifestPath
            $mf.PrivateData.PSData.LicenseUri | Should -Match 'polyform'
            $mf.Copyright | Should -Match 'Deynekin'
        }
    }

    Context 'Import & help' {
        It 'Imports cleanly on the current platform' {
            (Get-Module WinSecHunter) | Should -Not -BeNullOrEmpty
        }
        It 'Every exported function has synopsis and >= 2 examples' {
            $bad = @()
            foreach ($cmd in (Get-Command -Module WinSecHunter)) {
                $h = Get-Help $cmd.Name
                $examples = @($h.examples.example)
                if (-not $h.Synopsis -or $h.Synopsis -eq $cmd.Name -or $examples.Count -lt 2) { $bad += $cmd.Name }
            }
            $bad | Should -Be @() -Because ($bad -join ', ')
        }
        It 'Every exported function declares OutputType' {
            $bad = @()
            foreach ($cmd in (Get-Command -Module WinSecHunter)) {
                if (-not $cmd.OutputType) { $bad += $cmd.Name }
            }
            $bad | Should -Be @() -Because ($bad -join ', ')
        }
        It 'Every exported function supports common parameters (CmdletBinding)' {
            $bad = @()
            foreach ($cmd in (Get-Command -Module WinSecHunter)) {
                if (-not $cmd.Parameters.ContainsKey('Verbose')) { $bad += $cmd.Name }
            }
            $bad | Should -Be @() -Because ($bad -join ', ')
        }
        It 'Mutating functions support ShouldProcess' {
            (Get-Command Set-WinSecHunterOption).Parameters.ContainsKey('WhatIf') | Should -BeTrue
            (Get-Command Export-WinSecInvestigation).Parameters.ContainsKey('WhatIf') | Should -BeTrue
        }
    }

    Context 'Code quality gates' {
        It 'No Write-Host / exit in module source (library hygiene)' {
            $offenders = @()
            Get-ChildItem (Join-Path $script:WinSecTestRoot 'src') -Recurse -Filter *.ps1 | ForEach-Object {
                $content = Get-Content -Raw $_.FullName
                if ($content -match '(?m)^\s*Write-Host\b' -or $content -match '(?m)^\s*exit\s') { $offenders += $_.Name }
            }
            $offenders | Should -Be @() -Because ($offenders -join ', ')
        }
        It 'All source files parse without errors' {
            $errs = @()
            # Class files reference module-scoped enums; they are validated by the
            # import test above (isolated ParseFile cannot see session types).
            Get-ChildItem (Join-Path $script:WinSecTestRoot 'src') -Recurse -Filter *.ps1 |
                Where-Object { $_.DirectoryName -notmatch 'Classes$' } |
                ForEach-Object {
                    $tokens = $null; $parseErrors = $null
                    [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$parseErrors)
                    if ($parseErrors) { $errs += "$($_.Name): $($parseErrors[0].Message)" }
                }
            $errs | Should -Be @() -Because ($errs -join '; ')
        }
        It 'Format file is valid XML' {
            $fmt = Join-Path $script:WinSecTestRoot 'src/WinSecHunter/WinSecHunter.Format.ps1xml'
            { [xml](Get-Content -Raw $fmt) } | Should -Not -Throw
        }
        It 'Windows-only cmdlets guard non-Windows platforms' -Skip:$IsWindows {
            { Get-WinSecEventByIp -IpAddress '203.0.113.7' -ErrorAction Stop } |
                Should -Throw -ErrorId '*WinSecNotWindows*'
        }
    }
}
