#Requires -Version 7.6
function Get-WinSecLogonSession {
    <#
    .SYNOPSIS
        Reconstructs logon sessions from collected events by chaining LogonId
        references (4624 → 4672/4648 → 4634/4647).

    .DESCRIPTION
        Turns a flat event list into attacker sessions: who logged on, from
        where, with what logon type, whether the session held administrative
        privileges (4672), which child sessions it spawned with explicit
        credentials (4648 SubjectLogonId → new TargetLogonId), and how long it
        lasted (4634/4647 close). Sessions that never closed are flagged —
        on a live incident that is your "attacker may still be inside" list.

    .PARAMETER Event
        WinSecEvent objects (pipe from Get-WinSecEventByIp). Include the
        BruteForce or IncidentResponse profile so 4624/4634/4647/4672/4648
        are present.

    .PARAMETER IncludeEnded
        Explicitly return both open and closed sessions. This is the default
        behaviour when no filter switch is given; the switch exists to make the
        intent readable in scripts and to document that ended sessions are in
        scope. Cannot be combined with -ActiveOnly or -EndedOnly.

    .PARAMETER ActiveOnly
        Return only sessions without a matching logoff — potential live
        attacker footholds.

    .PARAMETER EndedOnly
        Return only sessions with a recorded 4634/4647 logoff — useful to
        compute dwell time and to exclude still-open footholds from statistics.

    .EXAMPLE
        $sessions = Get-WinSecEventByIp 203.0.113.7 -LastDays 2 | Get-WinSecLogonSession
        $sessions | Where-Object IsAdmin | Sort-Object StartUtc

    .EXAMPLE
        Get-WinSecEventByIp 203.0.113.7 | Get-WinSecLogonSession -ActiveOnly

    .OUTPUTS
        WinSecSession
    #>
    [CmdletBinding(DefaultParameterSetName = 'All')]
    [OutputType('WinSecSession')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [WinSecEvent[]] $Event,

        [Parameter(ParameterSetName = 'All')]
        [switch] $IncludeEnded,

        [Parameter(ParameterSetName = 'Active')]
        [switch] $ActiveOnly,

        [Parameter(ParameterSetName = 'Ended')]
        [switch] $EndedOnly
    )

    begin { $all = [System.Collections.Generic.List[WinSecEvent]]::new() }
    process { foreach ($e in $Event) { $all.Add($e) } }
    end {
        if ($all.Count -eq 0) { Write-Warning 'Get-WinSecLogonSession received no events.'; return }

        $norm = {
            param([string]$id)
            if (-not $id) { return $null }
            $x = $id.Trim()
            if ($x -match '^(?:0x)?0*([0-9A-Fa-f]+)$') { return $Matches[1].ToLowerInvariant() }
            return $x.ToLowerInvariant()
        }

        $sessions = @{}          # 'computer|logonId' -> WinSecSession
        $childMap = @{}           # 'computer|parentLogonId' -> set of child logonIds

        foreach ($e in ($all | Sort-Object TimeUtc)) {
            if ($e.EventId -eq 4624) {
                $lid = & $norm $e.LogonId
                if (-not $lid -or -not $e.LogonId) { continue }
                $key = "$($e.Computer)|$lid"
                if ($sessions.ContainsKey($key)) { continue }   # duplicate 4624 (re-audit) — keep first
                $s = [WinSecSession]::new()
                $s.LogonId    = $lid
                $s.Computer   = $e.Computer
                $s.Account    = $e.TargetAccount
                $s.LogonType  = $e.LogonType
                $s.SourceIp   = $e.SourceIp
                $s.AuthPackage= $e.AuthPackage
                $s.LogonProcess = $e.LogonProcess
                $s.StartUtc   = $e.TimeUtc
                $s.AttackIds  = $e.AttackIds
                $s.Events.Add($e)
                $sessions[$key] = $s
                continue
            }

            $lid = & $norm ($e.LogonId)
            if (-not $lid) { continue }
            $key = "$($e.Computer)|$lid"

            switch ($e.EventId) {
                4672 {
                    if ($sessions.ContainsKey($key)) {
                        $sessions[$key].IsAdmin = $true
                        $sessions[$key].Events.Add($e)
                        $sessions[$key].AttackIds = @($sessions[$key].AttackIds + $e.AttackIds | Sort-Object -Unique)
                    }
                }
                { $_ -in 4634, 4647 } {
                    if ($sessions.ContainsKey($key)) {
                        $sessions[$key].EndUtc = $e.TimeUtc
                        $sessions[$key].Ended  = $true
                        $sessions[$key].Events.Add($e)
                    }
                }
                4648 {
                    # SubjectLogonId = parent session; TargetLogonId (new logon) often absent
                    # in 4648 itself — the spawned 4624 carries it. Link by subject here;
                    # the child 4624 (same computer, later time) is linked when its
                    # SubjectLogonId matches — recorded via childMap on the fly below.
                    $subjLid = & $norm ($e.Data['SubjectLogonId'] ?? $lid)
                    $childLid = & $norm ($e.Data['TargetLogonId'])
                    $parentKey = "$($e.Computer)|$subjLid"
                    if ($sessions.ContainsKey($parentKey)) {
                        $sessions[$parentKey].Events.Add($e)
                        if ($childLid) {
                            if (-not $childMap.ContainsKey($parentKey)) { $childMap[$parentKey] = [System.Collections.Generic.HashSet[string]]::new() }
                            [void]$childMap[$parentKey].Add($childLid)
                        }
                    }
                }
                default {
                    # Any other event that carries the same LogonId enriches the session.
                    if ($sessions.ContainsKey($key)) { $sessions[$key].Events.Add($e) }
                }
            }
        }

        foreach ($key in $childMap.Keys) {
            $sessions[$key].ChildLogonIds = @($childMap[$key] | Sort-Object)
        }

        $result = $sessions.Values | Sort-Object StartUtc
        if ($ActiveOnly) { $result = $result | Where-Object { -not $_.Ended } }
        elseif ($EndedOnly) { $result = $result | Where-Object { $_.Ended } }
        if (-not $result) {
            Write-Warning 'No logon sessions (event 4624) found in the supplied events. Include an authentication profile (e.g. -Profile IncidentResponse or BruteForce) when collecting.'
        }
        $result
    }
}
