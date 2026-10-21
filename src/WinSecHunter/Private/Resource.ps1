#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: event catalog resources
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

$script:WinSecResource = $null

<#
    .SYNOPSIS
        Lazy-loads and indexes Resources/EventCatalog.json.
    .DESCRIPTION
        Parsed once per session into $script:WinSecResource. The index maps
        'Log|Id' → entry and 'Id' → entries (an ID can exist in several logs,
        e.g. Security 104 vs System 104). -Reload forces a re-read (used by
        tests after catalog edits).
#>
function Get-WinSecResource {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([switch]$Reload)

    if ($script:WinSecResource -and -not $Reload) { return $script:WinSecResource }

    $catalogPath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'Resources' -AdditionalChildPath 'EventCatalog.json'
    if (-not (Test-Path -LiteralPath $catalogPath)) {
        throw [System.IO.FileNotFoundException]::new('WinSecHunter event catalog is missing.', $catalogPath)
    }

    $catalog = Get-Content -Raw -LiteralPath $catalogPath | ConvertFrom-Json -AsHashtable
    if (-not $catalog -or -not $catalog.events) {
        throw [System.IO.InvalidDataException]::new("Catalog '$catalogPath' has no 'events' array.")
    }

    $byKey = @{}
    $byId  = @{}
    foreach ($e in $catalog.events) {
        $key = '{0}|{1}' -f $e['Log'], $e['Id']
        if ($byKey.ContainsKey($key)) {
            throw [System.IO.InvalidDataException]::new("Duplicate catalog entry for $key.")
        }
        $byKey[$key] = $e
        $idKey = [string]$e['Id']
        if (-not $byId.ContainsKey($idKey)) { $byId[$idKey] = [System.Collections.Generic.List[hashtable]]::new() }
        $byId[$idKey].Add($e)
    }

    $script:WinSecResource = @{
        Catalog = $catalog
        ByKey   = $byKey
        ById    = $byId
        Logs    = @($catalog.events | ForEach-Object { $_.Log } | Select-Object -Unique)
        Aliases = $catalog.logAliases
        Profiles= $catalog.profiles
        Version = $catalog.version
    }
    return $script:WinSecResource
}

<#
    .SYNOPSIS
        Catalog entry for an event id, preferring an exact Log|Id match.
#>
function Get-WinSecEventInfo {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)][int]$EventId,
        [AllowEmptyString()][string]$LogName = ''
    )

    $res = Get-WinSecResource
    if ($LogName) {
        $key = '{0}|{1}' -f $LogName, $EventId
        if ($res.ByKey.ContainsKey($key)) { return $res.ByKey[$key] }
    }
    $idKey = [string]$EventId
    if ($res.ById.ContainsKey($idKey)) {
        $entries = $res.ById[$idKey]
        if ($entries.Count -eq 1) { return $entries[0] }
        # Ambiguous id across logs — return Security-log entry when present.
        return ($entries | Where-Object { $_.Log -eq 'Security' } | Select-Object -First 1) ?? $entries[0]
    }
    return $null
}

<#
    .SYNOPSIS
        Resolves profiles/categories/event ids/log filters into a concrete
        per-log event-id map for the query engine.
    .OUTPUTS
        PSCustomObject with .LogEventIds ([hashtable] canonical-log -> int[])
        and .Entries (selected catalog entries).
#>
function Get-WinSecEventIdsByScope {
    [CmdletBinding()]
    param(
        [string[]]$Profile,
        [string[]]$Category,
        [int[]]$EventId,
        [string[]]$LogName
    )

    $res = Get-WinSecResource
    $selected = [System.Collections.Generic.HashSet[string]]::new()  # 'Log|Id' keys

    $addEntry = {
        param($entry)
        [void]$selected.Add(('{0}|{1}' -f $entry.Log, $entry.Id))
    }

    # --- Profiles -----------------------------------------------------------
    $effectiveProfiles = $Profile
    if (-not $effectiveProfiles -and -not $Category -and -not $EventId) {
        $effectiveProfiles = @('IncidentResponse')
    }
    foreach ($p in $effectiveProfiles) {
        if (-not $res.Profiles.ContainsKey($p)) {
            throw [ArgumentException]::new(
                "Unknown profile '$p'. Available: $($res.Profiles.Keys -join ', ')")
        }
        $def = $res.Profiles[$p]
        if ($def['categories']) {
            foreach ($e in $res.Catalog.events) {
                if ($e['Category'] -in $def['categories']) { & $addEntry $e }
            }
        }
        if ($def['eventIds']) {
            foreach ($id in $def['eventIds']) {
                $idKey = [string]$id
                if ($res.ById.ContainsKey($idKey)) { foreach ($e in $res.ById[$idKey]) { & $addEntry $e } }
                else {
                    # Id outside the catalog: still query it (assume Security unless restricted)
                    [void]$selected.Add(('(unknown)|{0}' -f $id))
                }
            }
        }
        if ($def['importance']) {
            foreach ($e in $res.Catalog.events) {
                if ($e['Importance'] -eq $def['importance']) { & $addEntry $e }
            }
        }
    }

    # --- Explicit categories -------------------------------------------------
    foreach ($c in $Category) {
        $parsed = $null
        if (-not [enum]::TryParse([WinSecEventCategory], $c, $true, [ref]$parsed) -or $parsed -eq [WinSecEventCategory]::Unknown) {
            throw [ArgumentException]::new(
                "Unknown category '$c'. Available: $(([enum]::GetNames([WinSecEventCategory]) | Where-Object { $_ -ne 'Unknown' }) -join ', ')")
        }
        foreach ($e in $res.Catalog.events) {
            if ($e['Category'] -eq $parsed.ToString()) { & $addEntry $e }
        }
    }

    # --- Explicit event ids ---------------------------------------------------
    foreach ($id in $EventId) {
        $idKey = [string]$id
        if ($res.ById.ContainsKey($idKey)) {
            foreach ($e in $res.ById[$idKey]) { & $addEntry $e }
        }
        else {
            [void]$selected.Add(('(unknown)|{0}' -f $id))
        }
    }

    # --- Resolve unknown-id placeholders against log restrictions ------------
    $allowedLogs = [System.Collections.Generic.HashSet[string]]::new([string[]]$res.Logs)
    if ($LogName) {
        $expanded = [System.Collections.Generic.List[string]]::new()
        foreach ($l in $LogName) {
            if ($res.Aliases -and $res.Aliases.ContainsKey($l)) { $res.Aliases[$l] | ForEach-Object { $expanded.Add($_) } }
            else { $expanded.Add($l) }
        }
        # Case-insensitive match against canonical logs
        $allowedLogs = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($expanded | ForEach-Object { $n = $_; ($res.Logs | Where-Object { $_ -ieq $n } | Select-Object -First 1) ?? $n }))
    }

    $logEventIds = @{}
    $entries = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($key in $selected) {
        $log, $idStr = $key -split '\|', 2
        $id = [int]$idStr
        if ($log -eq '(unknown)') {
            # Not in catalog: attach to explicitly requested logs, else Security.
            $targetLogs = $LogName ? @($allowedLogs) : @('Security')
            foreach ($tl in $targetLogs) {
                if (-not $logEventIds.ContainsKey($tl)) { $logEventIds[$tl] = [System.Collections.Generic.HashSet[int]]::new() }
                [void]$logEventIds[$tl].Add($id)
            }
            continue
        }
        if (-not $allowedLogs.Contains($log)) { continue }
        if (-not $logEventIds.ContainsKey($log)) { $logEventIds[$log] = [System.Collections.Generic.HashSet[int]]::new() }
        [void]$logEventIds[$log].Add($id)
        $info = $res.ByKey[$key]
        if ($info) { $entries.Add($info) }
    }

    # Prune logs that ended up empty, produce sorted arrays
    $final = @{}
    foreach ($log in @($logEventIds.Keys)) {
        if ($logEventIds[$log].Count -gt 0) {
            $final[$log] = @($logEventIds[$log] | Sort-Object)
        }
    }

    return [pscustomobject]@{
        LogEventIds = $final
        Entries     = $entries
        Profiles    = @($effectiveProfiles)
    }
}

