@{
    # ----- Module identity --------------------------------------------------
    RootModule           = 'WinSecHunter.psm1'
    ModuleVersion        = '2.1.0'
    GUID                 = 'f3c9a1d2-8b47-4e6a-9c25-7d1e0b6a4f38'
    CompatiblePSEditions = @('Core')
    PowerShellVersion    = '7.6'

    Author               = 'WinSecHunter contributors'
    CompanyName          = 'WinSecHunter Project'
    Copyright            = '(c) Mikhail Deynekin. Licensed under the PolyForm Noncommercial License 1.0.0. Derivative of Get-Windows-Security-Events-By-IP (mid1977@gmail.com, https://deynekin.com).'
    Description          = 'Incident-response toolkit for Windows security events. Collects, normalizes, decodes and correlates Windows event log evidence about an attacker IP address (IPv4/IPv6/CIDR) across local hosts, remote systems (WinRM) and offline EVTX files. Includes brute-force/spray detection, RDP and logon-session reconstruction, audit-policy gap analysis, log-coverage completeness checks, threat-intel attribution, incident reports, abuse reports (RFC 5322 .eml), IOC export (CSV/STIX 2.1), tamper-evident evidence export (SHA-256 manifest) and an in-module command reference.'

    # ----- Exports ------------------------------------------------------------
    FunctionsToExport    = @(
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
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()

    # ----- Resources -----------------------------------------------------------
    FormatsToProcess     = @('WinSecHunter.Format.ps1xml')

    # ----- Gallery metadata ------------------------------------------------------
    PrivateData          = @{
        PSData = @{
            Tags         = @('Security', 'Forensics', 'DFIR', 'IncidentResponse', 'WindowsEvent', 'EventLog', 'BlueTeam', 'MITRE', 'ATTCK', 'BruteForce', 'RDP', 'Audit', 'SIEM', 'IR', 'AbuseReport', 'STIX', 'IncidentReport')
            LicenseUri   = 'https://polyformproject.org/licenses/noncommercial/1.0.0'
            ProjectUri   = 'https://github.com/paulmann/Get-Windows-Security-Events-By-IP'
            ReleaseNotes = 'https://github.com/paulmann/Get-Windows-Security-Events-By-IP/blob/main/CHANGELOG.md'
            Prerelease   = ''
        }
    }
}

