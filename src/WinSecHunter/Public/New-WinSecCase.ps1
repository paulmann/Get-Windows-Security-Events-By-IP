#Requires -Version 7.6
function New-WinSecCase {
    <#
    .SYNOPSIS
        Creates an investigation case that binds evidence, findings and notes
        to a tamper-evident export bundle.

    .DESCRIPTION
        A WinSecCase is the unit of work for an incident responder. It carries
        the case id, operator, subject IP(s), scope hosts, free-form notes and
        findings. Export-WinSecInvestigation writes every artifact into a case
        folder and records SHA-256 hashes in manifest.json (chain of custody).

    .PARAMETER SubjectIps
        Attacker IP address(es)/CIDR(s) under investigation. Validated with the
        same strict parser as Get-WinSecEventByIp.

    .EXAMPLE
        $case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'Brute force vs VPN concentrator'

    .EXAMPLE
        $case = New-WinSecCase -SubjectIps 203.0.113.0/24 -ScopeHosts DC01, VPN01 -Operator 'soc@contoso.com'
        $case.AddNote('Customer reported lockouts 02:00-03:00 UTC.')

    .OUTPUTS
        WinSecCase
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory case object; modifies no system state.')]
    [CmdletBinding()]
    [OutputType('WinSecCase')]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]] $SubjectIps,

        [string] $Title,
        [string] $Description,
        [string[]] $ScopeHosts,
        [string] $Operator
    )

    $normalized = foreach ($ip in $SubjectIps) {
        if (-not (Test-WinSecIpAddress -Value $ip -AllowCidr)) {
            throw [ArgumentException]::new("Invalid subject IP/CIDR: '$ip'.")
        }
        $isCidr = $ip.Contains('/')
        $canonical = ConvertTo-WinSecCanonicalIp -Value $ip
        if ($isCidr) { $canonical = $canonical + '/' + ($ip -split '/')[1] }
        $canonical
    }

    $case = [WinSecCase]::new()
    $case.SubjectIps = [string[]]@($normalized | Select-Object -Unique)
    $case.Title       = [string]::IsNullOrEmpty($Title) ? ("Investigation of {0}" -f ($case.SubjectIps -join ', ')) : $Title
    $case.Description = $Description
    $case.ScopeHosts  = $ScopeHosts ?? [string[]]@()
    if ($Operator) { $case.Operator = $Operator }
    $case.AddNote("Case opened. Subject IP(s): $($case.SubjectIps -join ', '). Scope: $(($case.ScopeHosts.Count -gt 0) ? ($case.ScopeHosts -join ', ') : 'local machine').")
    return $case
}
