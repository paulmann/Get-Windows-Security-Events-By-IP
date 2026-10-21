#Requires -Version 7.6
function Get-WinSecEventCatalog {
    <#
    .SYNOPSIS
        Browses the built-in WinSecHunter event catalog: IDs, logs, categories,
        MITRE ATT&CK mappings, importance and IP-bearing fields.

    .DESCRIPTION
        The catalog is the knowledge base behind profiles, classification and
        the audit-policy requirement matrix. Use this cmdlet to discover what
        a profile collects, which events carry IP addresses natively, and how
        they map to ATT&CK techniques — e.g. when tuning a sweep or writing
        detection documentation.

        -ListProfiles shows all available hunt profiles with descriptions.

    .EXAMPLE
        Get-WinSecEventCatalog -ListProfiles

    .EXAMPLE
        Get-WinSecEventCatalog -IpMatchable | Format-Table EventId, Log, Name -AutoSize

    .EXAMPLE
        Get-WinSecEventCatalog -AttackId T1021.001

    .EXAMPLE
        Get-WinSecEventCatalog -Profile BruteForce | Sort-Object EventId

    .EXAMPLE
        Get-WinSecEventCatalog -Category Kerberos -Importance Critical

    .OUTPUTS
        PSCustomObject (catalog entries) or profile overview with -ListProfiles
    #>
    [CmdletBinding(DefaultParameterSetName = 'Filter')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Profiles')]
        [switch] $ListProfiles,

        [Parameter(ParameterSetName = 'Filter')]
        [string[]] $Category,

        [Parameter(ParameterSetName = 'Filter')]
        [string[]] $LogName,

        [Parameter(ParameterSetName = 'Filter')]
        [string[]] $Profile,

        [Parameter(ParameterSetName = 'Filter')]
        [int[]] $EventId,

        [Parameter(ParameterSetName = 'Filter')]
        [ValidateSet('Informational', 'Low', 'Medium', 'High', 'Critical')]
        [string] $Importance,

        [Parameter(ParameterSetName = 'Filter')]
        [string] $AttackId,

        [Parameter(ParameterSetName = 'Filter')]
        [switch] $IpMatchable
    )

    $res = Get-WinSecResource

    if ($ListProfiles) {
        foreach ($name in ($res.Profiles.Keys | Sort-Object)) {
            $p = $res.Profiles[$name]
            $scope = Get-WinSecEventIdsByScope -Profile $name
            [pscustomobject]@{
                Profile     = $name
                Description = $p['description']
                LogCount    = $scope.LogEventIds.Count
                EventIds    = (($scope.LogEventIds.Values | ForEach-Object { $_ }) | Sort-Object -Unique) -join ', '
            }
        }
        return
    }

    $entries = $res.Catalog.events

    if ($Profile) {
        $scope = Get-WinSecEventIdsByScope -Profile $Profile
        $keys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($log in $scope.LogEventIds.Keys) {
            foreach ($id in $scope.LogEventIds[$log]) { [void]$keys.Add(('{0}|{1}' -f $log, $id)) }
        }
        $entries = $entries | Where-Object { $keys.Contains(('{0}|{1}' -f $_['Log'], $_['Id'])) }
    }
    if ($Category) {
        $entries = $entries | Where-Object { $_['Category'] -in $Category }
    }
    if ($LogName) {
        $expanded = foreach ($l in $LogName) { if ($res.Aliases.ContainsKey($l)) { $res.Aliases[$l] } else { $l } }
        $entries = $entries | Where-Object { $_['Log'] -in $expanded -or ($expanded -contains 'Security' -and $_['Log'] -eq 'Security') }
    }
    if ($EventId) {
        $entries = $entries | Where-Object { [int]$_['Id'] -in $EventId }
    }
    if ($Importance) {
        $entries = $entries | Where-Object { $_['Importance'] -eq $Importance }
    }
    if ($AttackId) {
        $entries = $entries | Where-Object { $_['Attack'] -and (@($_['Attack']) | Where-Object { $_ -like "*$AttackId*" }) }
    }
    if ($IpMatchable) {
        $entries = $entries | Where-Object { $_['IpFields'] -and @($_['IpFields']).Count -gt 0 }
    }

    foreach ($e in ($entries | Sort-Object { $_['Log'] }, { [int]$_['Id'] })) {
        [pscustomobject]@{
            EventId    = [int]$e['Id']
            Log        = $e['Log']
            Name       = $e['Name']
            Category   = $e['Category']
            Importance = $e['Importance']
            Attack     = (@($e['Attack']) -join ', ')
            IpFields   = (@($e['IpFields']) -join ', ')
            Notes      = $e['Notes']
        }
    }
}
