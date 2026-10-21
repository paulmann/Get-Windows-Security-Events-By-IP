#Requires -Version 7.6
function Get-WinSecHunterOption {
    <#
    .SYNOPSIS
        Shows the effective WinSecHunter configuration.

    .DESCRIPTION
        Returns the merged configuration (built-in defaults overlaid by the
        persisted config.json). Pass -Name to read a single option, or
        -ShowResolved to also display where threat-intel keys are sourced from
        and whether they are currently set (values are never printed).

    .EXAMPLE
        Get-WinSecHunterOption

    .EXAMPLE
        Get-WinSecHunterOption -Name DefaultProfile

    .EXAMPLE
        Get-WinSecHunterOption -ShowResolved

    .OUTPUTS
        Hashtable / PSCustomObject
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType([hashtable], [object])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single', Position = 0)]
        [string] $Name,

        [Parameter(ParameterSetName = 'All')]
        [switch] $ShowResolved
    )

    $config = Get-WinSecConfig

    if ($PSCmdlet.ParameterSetName -eq 'Single') {
        if (-not $config.ContainsKey($Name)) {
            throw [ArgumentException]::new("Unknown option '$Name'. Valid: $(($config.Keys | Sort-Object) -join ', ')")
        }
        return $config[$Name]
    }

    if (-not $ShowResolved) { return $config }

    $abuseVar = [string]$config.AbuseIpDbKeyEnvVar
    $otxVar   = [string]$config.OtxKeyEnvVar
    [pscustomobject]@{
        Config                = $config
        ConfigDirectory       = Get-WinSecConfigPath
        AbuseIpDbKeySource    = "env:$abuseVar"
        AbuseIpDbKeyPresent   = [bool](Get-Item "env:$abuseVar" -ErrorAction SilentlyContinue)
        OtxKeySource          = "env:$otxVar"
        OtxKeyPresent         = [bool](Get-Item "env:$otxVar" -ErrorAction SilentlyContinue)
        ModuleVersion         = $script:WinSecModuleVersion
        CatalogVersion        = (Get-WinSecResource).Version
    }
}
