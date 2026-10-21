#Requires -Version 7.6
#Requires -PSEdition Core
# ---------------------------------------------------------------------------
# WinSecHunter — Private: help rendering helpers
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

<#
    .SYNOPSIS
        Short human description for a configuration key (used by the reference).
#>
function Get-WinSecOptionDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Name)

    $map = @{
        DefaultProfile                 = 'Profile used when no -Profile/-Category/-EventId is supplied.'
        DefaultMaxEvents               = 'Per-channel record cap for collection (0 = unlimited).'
        DefaultThrottleLimit           = 'Parallel host fan-out for remote collection.'
        DefaultOutputDirectory         = 'Default parent folder for evidence bundles and reports.'
        IncludeMessage                 = 'Collect the rendered message text (slower, larger).'
        DeepScan                       = 'Regex the IP anywhere in the record, including messages.'
        TraceIntervalSeconds           = 'Polling interval for Trace-WinSecIp.'
        ThreatIntelProvider            = 'Optional enrichment provider: None, AbuseIPDB, OTX, IpApi.'
        AbuseIpDbKeyEnvVar             = 'Environment variable holding the AbuseIPDB API key.'
        OtxKeyEnvVar                   = 'Environment variable holding the AlienVault OTX key.'
        IpApiContactEmail              = 'Contact e-mail required by the ip-api free tier.'
        AttributionCacheHours          = 'How long attribution results stay cached.'
        BruteForceFailureThreshold     = 'Failures per account before a brute-force finding.'
        BruteForceWindowMinutes        = 'Sliding window for brute-force counting.'
        BruteForceSprayAccountThreshold= 'Distinct accounts that turns failures into spraying.'
    }
    return $map[$Name] ?? ''
}

<#
    .SYNOPSIS
        Renders one cmdlet as text or Markdown from live help metadata.
#>
function Get-WinSecCmdletReference {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $Name,
        [switch] $Markdown
    )

    $cmd = Get-Command $Name -ErrorAction Stop
    $help = Get-Help $Name -Full
    # Get-Help's Syntax is a formatted object whose string form is unstable; the
    # command's own syntax rendering is deterministic across hosts and OSes.
    $syntaxText = (@(Get-Command $Name -Syntax) -join "`n").Trim()
    $sb = [System.Text.StringBuilder]::new()
    $line = { param([string]$s = '') $null = $sb.AppendLine($s) }
    # Help objects are DynamicObjects: absent properties throw under StrictMode.
    $prop = { param($o, $n) if ($null -eq $o) { return $null }; $p = $o.PSObject.Properties[$n]; if ($p) { return $p.Value } return $null }
    $descOf = { param($ph) $d = & $prop $ph 'Description'; if (-not $d) { return '' }; ([string]($d.Text -join ' ')).Trim() }

    if ($Markdown) {
        & $line "### ``$Name``"
        & $line
        & $line ([string]$help.Synopsis).Trim()
        & $line
        & $line '```text'
        & $line $syntaxText
        & $line '```'
        & $line
        if (& $prop $help 'Description') { & $line ([string]($help.Description.Text -join ' ')).Trim(); & $line }
        & $line '| Parameter | Type | Required | Description |'
        & $line '|---|---|---|---|'
        foreach ($p in @($cmd.Parameters.Values | Where-Object { $_.Name -notin [System.Management.Automation.PSCmdlet]::CommonParameters } | Sort-Object Name)) {
            $h = @($help.Parameters.Parameter | Where-Object Name -eq $p.Name)
            $desc = $h.Count ? (& $descOf $h[0]) : ''
            $req = ($h.Count -and (& $prop $h[0] 'Required') -eq 'true') ? 'yes' : 'no'
            & $line ('| `-{0}` | `{1}` | {2} | {3} |' -f $p.Name, $p.ParameterType.Name, $req, ($desc -replace '\|', '\|'))
        }
        & $line
        if ($help.Examples -and $help.Examples.Example) {
            & $line '**Examples**'
            & $line
            foreach ($ex in @($help.Examples.Example)) {
                & $line '```powershell'
                & $line (([string](& $prop $ex 'Code')).Trim())
                & $line '```'
                if (& $prop $ex 'Remarks') { & $line ([string](& $prop $ex 'Remarks')).Trim() }
                & $line
            }
        }
        return $sb.ToString().TrimEnd()
    }

    & $line ("{0}" -f $Name)
    & $line ('-' * 78)
    & $line ([string]$help.Synopsis).Trim()
    & $line
    & $line 'SYNTAX'
    foreach ($s in @($syntaxText -split "`n")) { & $line ('  ' + $s.Trim()) }
    & $line
    if (& $prop $help 'Description') {
        & $line 'DESCRIPTION'
        & $line ('  ' + (([string]($help.Description.Text -join ' ')).Trim() -replace "`n", "`n  "))
        & $line
    }
    & $line 'PARAMETERS'
    foreach ($p in @($cmd.Parameters.Values | Where-Object { $_.Name -notin [System.Management.Automation.PSCmdlet]::CommonParameters } | Sort-Object Name)) {
        $h = @($help.Parameters.Parameter | Where-Object Name -eq $p.Name)
        $desc = $h.Count ? (& $descOf $h[0]) : ''
        $req = ($h.Count -and (& $prop $h[0] 'Required') -eq 'true') ? 'required' : 'optional'
        & $line ('  -{0} <{1}> [{2}]' -f $p.Name, $p.ParameterType.Name, $req)
        if ($desc) { & $line ('      ' + ($desc -replace "`n", "`n      ")) }
    }
    if ($help.Examples -and $help.Examples.Example) {
        & $line
        & $line 'EXAMPLES'
        foreach ($ex in @($help.Examples.Example)) {
            & $line '  ' + (([string](& $prop $ex 'Code')).Trim() -replace "`n", "`n  ")
            & $line
        }
    }
    return $sb.ToString().TrimEnd()
}


