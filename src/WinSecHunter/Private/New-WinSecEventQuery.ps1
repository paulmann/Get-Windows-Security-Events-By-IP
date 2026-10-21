#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: Event Log XPath query builder
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Event Log XPath 1.0 subset: no contains()/string functions — IP equality
# only. CIDR & deep matching happen client-side by design.
# ---------------------------------------------------------------------------

<#
    .SYNOPSIS
        Builds a QueryList XML for Get-WinEvent -FilterXml.
    .DESCRIPTION
        Server-side pushdown: log channels, event IDs and a UTC time window.
        When -IpExactVariants is supplied, IDs that carry IP fields (per the
        event catalog) are additionally gated on exact Data equality —
        including IPv4-mapped IPv6 renderings and the UserData/EventXML/
        Address layout used by the RDP operational logs. IDs without IP
        fields (e.g. 4740 lockouts, 7045 service installs) pass through
        unfiltered because they are contextual evidence even though the IP
        never appears in them.
    .OUTPUTS
        [xml] ready for Get-WinEvent -FilterXml.
#>
function New-WinSecEventQuery {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure in-memory query builder; modifies no system state.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = 'Returns [xml]; analyzer misreads the here-string cast.')]
    [CmdletBinding()]
    [OutputType([xml])]
    param(
        # canonical log name -> event ids
        [Parameter(Mandatory)]
        [hashtable] $LogEventIds,

        # [datetime] with an explicit "not set" sentinel. PowerShell unboxes
        # Nullable<T> back to T during parameter binding, so HasValue is not
        # reliable here; $null cannot bind to a value type at all.
        [datetime] $StartTimeUtc = [datetime]::MinValue,
        [datetime] $EndTimeUtc   = [datetime]::MinValue,

        # exact-match textual variants of the investigated IP (empty = no server-side IP filter)
        [AllowNull()][string[]] $IpExactVariants,

        # EVTX file mode: every Select targets this file path instead of live channels
        [AllowEmptyString()][string] $PathOverride = ''
    )

    if (-not $LogEventIds -or $LogEventIds.Count -eq 0) {
        throw [ArgumentException]::new('No logs/event ids to query.')
    }

    $timeCond = ''
    $hasStart = $StartTimeUtc -ne [datetime]::MinValue
    $hasEnd   = $EndTimeUtc   -ne [datetime]::MinValue
    if ($hasStart -or $hasEnd) {
        $parts = @()
        if ($hasStart) {
            $parts += ("@SystemTime&gt;='{0}'" -f $StartTimeUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture))
        }
        if ($hasEnd) {
            $parts += ("@SystemTime&lt;='{0}'" -f $EndTimeUtc.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [System.Globalization.CultureInfo]::InvariantCulture))
        }
        $timeCond = ' and TimeCreated[' + ($parts -join ' and ') + ']'
    }

    $ipCond = $null
    if ($IpExactVariants -and $IpExactVariants.Count -gt 0) {
        $dataClauses    = @($IpExactVariants | ForEach-Object { "Data='$_'" }) -join ' or '
        $addressClauses = @($IpExactVariants | ForEach-Object { "Address='$_'" }) -join ' or '
        $ipCond = "(*[EventData[$dataClauses]] or *[UserData[EventXML[$addressClauses]]])"
    }

    $selects = [System.Collections.Generic.List[string]]::new()
    $firstPath = $null
    foreach ($log in ($LogEventIds.Keys | Sort-Object)) {
        $ids = @($LogEventIds[$log] | Sort-Object -Unique)
        if ($ids.Count -eq 0) { continue }

        # Split ids: catalog says the event carries IP fields → gate on IP.
        $gated = [System.Collections.Generic.List[int]]::new()
        $pass  = [System.Collections.Generic.List[int]]::new()
        foreach ($id in $ids) {
            $info = Get-WinSecEventInfo -EventId $id -LogName $log
            if ($ipCond -and $info -and $info['IpFields'] -and @($info['IpFields']).Count -gt 0) { $gated.Add($id) }
            else { $pass.Add($id) }
        }

        $exprParts = [System.Collections.Generic.List[string]]::new()
        if ($gated.Count -gt 0) {
            $idCond = 'EventID=' + ($gated -join ' or EventID=')
            $exprParts.Add("*[System[($idCond)$timeCond]] and $ipCond")
        }
        if ($pass.Count -gt 0) {
            $idCond = 'EventID=' + ($pass -join ' or EventID=')
            $exprParts.Add("*[System[($idCond)$timeCond]]")
        }
        if ($exprParts.Count -eq 0) { continue }

        $selectPath = $PathOverride ? $PathOverride : $log
        $firstPath ??= $selectPath
        $escapedPath = [System.Security.SecurityElement]::Escape($selectPath)
        $selects.Add("<Select Path=`"$escapedPath`">" + ($exprParts -join ' or ') + '</Select>')
    }

    if ($selects.Count -eq 0) {
        throw [ArgumentException]::new('Query produced no Select statements — check log/event id filters.')
    }

    $queryListPath = [System.Security.SecurityElement]::Escape($firstPath)
    [xml]$query = @"
<QueryList>
  <Query Id="0" Path="$queryListPath">
$($selects -join "`n")
  </Query>
</QueryList>
"@
    return $query
}

