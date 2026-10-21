#Requires -Version 7.6
function Set-WinSecHunterOption {
    <#
    .SYNOPSIS
        Persists WinSecHunter configuration options.

    .DESCRIPTION
        Writes options to config.json under the WinSecHunter configuration
        directory (%LOCALAPPDATA%\WinSecHunter on Windows,
        ~/.config/WinSecHunter elsewhere; override with
        $env:WINSECHUNTER_CONFIG_DIR — handy for portable IR kits).

        Threat-intel API keys are NEVER stored as options directly; store the
        NAME of the environment variable that holds the key
        (AbuseIpDbKeyEnvVar / OtxKeyEnvVar defaults: ABUSEIPDB_KEY / OTX_API_KEY).

    .EXAMPLE
        Set-WinSecHunterOption -Options @{ DefaultProfile = 'BruteForce'; DefaultMaxEvents = 20000 }

    .EXAMPLE
        Set-WinSecHunterOption -Name ThreatIntelProvider -Value AbuseIPDB
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Single', Position = 0)]
        [ValidateSet('DefaultProfile', 'DefaultMaxEvents', 'DefaultThrottleLimit', 'DefaultOutputDirectory',
                     'IncludeMessage', 'DeepScan', 'TraceIntervalSeconds', 'ThreatIntelProvider',
                     'AbuseIpDbKeyEnvVar', 'OtxKeyEnvVar', 'IpApiContactEmail', 'AttributionCacheHours',
                     'BruteForceFailureThreshold', 'BruteForceWindowMinutes', 'BruteForceSprayAccountThreshold')]
        [string] $Name,

        [Parameter(Mandatory, ParameterSetName = 'Single', Position = 1)]
        [object] $Value,

        [Parameter(Mandatory, ParameterSetName = 'Bulk')]
        [hashtable] $Options,

        [Parameter(ParameterSetName = 'Reset')]
        [switch] $Reset
    )

    if ($Reset) {
        if ($PSCmdlet.ShouldProcess('WinSecHunter configuration', 'Reset to defaults')) {
            $file = Join-Path (Get-WinSecConfigPath) 'config.json'
            if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
            $script:WinSecConfigCache = $null
            return Get-WinSecConfig
        }
        return
    }

    $changes = $PSCmdlet.ParameterSetName -eq 'Single' ? @{ $Name = $Value } : $Options

    if ($changes.ContainsKey('ThreatIntelProvider')) {
        $valid = 'None', 'AbuseIPDB', 'OTX', 'IpApi'
        if ($changes.ThreatIntelProvider -notin $valid) {
            throw [ArgumentException]::new("ThreatIntelProvider must be one of: $($valid -join ', ').")
        }
    }

    if ($PSCmdlet.ShouldProcess((($changes.Keys | ForEach-Object { "$_=$($changes[$_])" }) -join '; '), 'Set WinSecHunter option')) {
        return Save-WinSecConfig -Changes $changes
    }
}
