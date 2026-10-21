#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — root module loader
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
#
# Dot-sources the module in dependency order:
#   Enums → Classes → Private → Public
# and exports an explicit allow-list of public functions (mirrored in the
# manifest). Classes live in module scope; consumers who need the type names
# in their own session use `using module WinSecHunter`.
# ---------------------------------------------------------------------------

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

# Public API surface — single source of truth for Export-ModuleMember.
$script:WinSecPublicFunctions = @(
    'Get-WinSecEventByIp'
    'Get-WinSecIpTimeline'
    'Get-WinSecLogonSession'
    'Test-WinSecBruteForce'
    'Get-WinSecLogCoverage'
    'Test-WinSecAuditPolicy'
    'Resolve-WinSecIpAttribution'
    'Export-WinSecInvestigation'
    'New-WinSecCase'
    'Trace-WinSecIp'
    'Expand-WinSecIpRange'
    'Get-WinSecEventCatalog'
    'Set-WinSecHunterOption'
    'Get-WinSecHunterOption'
    'Show-WinSecHunterHelp'
    'New-WinSecIncidentReport'
    'New-WinSecAbuseReport'
    'Export-WinSecIocList'
    'Test-WinSecEvidenceIntegrity'
    'Import-WinSecCase'
)

$manifestPath = Join-Path $PSScriptRoot 'WinSecHunter.psd1'
$script:WinSecModuleVersion = (Import-PowerShellDataFile -LiteralPath $manifestPath).ModuleVersion

# Order matters: enums before classes (type references), everything before Public.
foreach ($folder in 'Enums', 'Classes', 'Private', 'Public') {
    $dir = Join-Path $PSScriptRoot $folder
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    Get-ChildItem -LiteralPath $dir -Filter '*.ps1' -File | Sort-Object Name | ForEach-Object {
        try {
            . $_.FullName
        }
        catch {
            throw [System.Management.Automation.RuntimeException]::new(
                "WinSecHunter: failed to load '$($_.FullName)': $($_.Exception.Message)", $_.Exception)
        }
    }
}

Export-ModuleMember -Function $script:WinSecPublicFunctions

