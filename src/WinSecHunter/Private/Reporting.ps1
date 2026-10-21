#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: reporting, IOC extraction and abuse-report helpers
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

<#
    .SYNOPSIS
        Formats a timestamp for reports (UTC, invariant) or an em dash.
#>
function Format-WinSecUtc {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [object] $Value,
        [string] $Format = 'yyyy-MM-dd HH:mm:ss'
    )
    if ($null -eq $Value) { return [char]0x2014 }
    try { $dt = [datetime]$Value } catch { return [string]$Value }
    if ($dt -eq [datetime]::MinValue -or $dt -eq [datetime]::MaxValue) { return [char]0x2014 }
    return $dt.ToUniversalTime().ToString($Format, [System.Globalization.CultureInfo]::InvariantCulture)
}

<#
    .SYNOPSIS
        Writes a UTF-8 (no BOM) file atomically: temp file in the same folder,
        then replace. Prevents half-written evidence and reports.
#>
function Write-WinSecFileAtomic {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Content,
        [switch] $Crlf
    )

    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -ItemType Directory -Path $dir -Force }
    $text = $Crlf ? ($Content -replace "`r?`n", "`r`n") : ($Content -replace "`r`n", "`n")
    $tmp  = Join-Path $dir ('.{0}.{1}.tmp' -f (Split-Path -Leaf $Path), [guid]::NewGuid().ToString('n'))
    [System.IO.File]::WriteAllText($tmp, $text, [System.Text.UTF8Encoding]::new($false))
    if (Test-Path -LiteralPath $Path) { [System.IO.File]::Replace($tmp, $Path, $null) }
    else { [System.IO.File]::Move($tmp, $Path) }
    return $Path
}

<#
    .SYNOPSIS
        Extracts deduplicated indicators of compromise from events and findings.
    .DESCRIPTION
        One row per value and type: TargetIp (case subjects), SourceIp,
        DestinationIp, Account, Host, Process, Service, Task, Path. Each row
        carries count and first/last UTC sighting so a report can rank them.
#>
function Get-WinSecIocSet {
    [CmdletBinding()]
    param(
        [WinSecCase] $Case,
        [object[]] $Event,
        [object[]] $Finding
    )

    $bucket = @{}   # 'Type|lowervalue' -> row

    $add = {
        param([string]$Type, [object]$Value, [object]$When)
        $v = ([string]$Value).Trim()
        if (-not $v -or $v -in '-', 'N/A', 'unknown', '(none)', '::', '0.0.0.0') { return }
        $stamp = if ($null -ne $When) { try { [datetime]$When } catch { [datetime]::MinValue } } else { [datetime]::MinValue }
        $key = '{0}|{1}' -f $Type, $v.ToLowerInvariant()
        if (-not $bucket.ContainsKey($key)) {
            $bucket[$key] = [pscustomobject]@{
                Type = $Type; Value = $v; Count = 0
                FirstUtc = $stamp; LastUtc = $stamp
            }
        }
        $row = $bucket[$key]
        $row.Count++
        if ($stamp -and $stamp -ne [datetime]::MinValue) {
            if ($row.FirstUtc -eq [datetime]::MinValue -or $stamp -lt $row.FirstUtc) { $row.FirstUtc = $stamp }
            if ($stamp -gt $row.LastUtc) { $row.LastUtc = $stamp }
        }
    }

    foreach ($ip in @($Case.SubjectIps)) { if ($ip) { & $add 'TargetIp' $ip ([datetime]::MinValue) } }

    foreach ($e in @($Event)) {
        if (-not $e) { continue }
        $when = $e.TimeUtc
        & $add 'SourceIp' $e.SourceIp $when
        & $add 'DestinationIp' $e.DestinationIp $when
        & $add 'Account' $e.TargetAccount $when
        & $add 'Account' $e.SubjectAccount $when
        & $add 'Host' $e.Computer $when
        & $add 'Process' $e.ProcessName $when
        & $add 'Service' $e.ServiceName $when
        & $add 'Task' $e.TaskName $when
        & $add 'Path' $e.ObjectName $when
    }

    foreach ($f in @($Finding)) {
        if (-not $f) { continue }
        & $add 'SourceIp' $f.SourceIp $f.FirstSeenUtc
        & $add 'Account' $f.TargetAccount $f.FirstSeenUtc
        foreach ($h in @($f.SourceHosts)) { & $add 'Host' $h $f.FirstSeenUtc }
    }

    $order = @('TargetIp', 'SourceIp', 'DestinationIp', 'Account', 'Host', 'Process', 'Service', 'Task', 'Path')
    $rows = @($bucket.Values | Sort-Object @{ Expression = { $order.IndexOf($_.Type) } }, @{ Expression = 'Count'; Descending = $true }, Value)

    [pscustomobject]@{
        Rows        = $rows
        IpAddresses = @($rows | Where-Object { $_.Type -in 'TargetIp', 'SourceIp', 'DestinationIp' })
        Accounts    = @($rows | Where-Object Type -eq 'Account')
        Hosts       = @($rows | Where-Object Type -eq 'Host')
        Processes   = @($rows | Where-Object Type -eq 'Process')
        Services    = @($rows | Where-Object Type -eq 'Service')
        Tasks       = @($rows | Where-Object Type -eq 'Task')
        Paths       = @($rows | Where-Object Type -eq 'Path')
    }
}

<#
    .SYNOPSIS
        Normalizes investigation inputs into one reporting context: counts,
        verdict, severity, confidence, IOCs, limitations and recommendations.
    .DESCRIPTION
        Single source of truth for New-WinSecIncidentReport, New-WinSecAbuseReport
        and the Markdown section of Export-WinSecInvestigation. Pure function:
        it only derives values, it never touches disk or network.
#>
function Get-WinSecCaseContext {
    [CmdletBinding()]
    param(
        [WinSecCase] $Case,
        [object[]] $Event,
        [object[]] $Finding,
        [object[]] $Session,
        [object[]] $Coverage,
        [object[]] $Attribution,
        [object[]] $Timeline,
        [hashtable] $Summary
    )

    $events   = @($Event   | Where-Object { $_ })
    $findings = @($Finding | Where-Object { $_ })
    $sessions = @($Session | Where-Object { $_ })
    $coverage = @($Coverage | Where-Object { $_ })
    $attrib   = @($Attribution | Where-Object { $_ })
    $buckets  = @($Timeline | Where-Object { $_ -and $_.PSObject.Properties['BucketStartUtc'] })

    if (-not $Case) {
        $Case = [WinSecCase]::new()
        $ips = @($events | ForEach-Object { $_.MatchedIp, $_.SourceIp } | Where-Object { $_ } | Sort-Object -Unique)
        $Case.SubjectIps = $ips.Count -gt 0 ? [string[]]$ips : [string[]]@('(none)')
        $Case.Title = "Ad-hoc investigation of $($Case.SubjectIps -join ', ')"
        $Case.AddNote('Ad-hoc case created while rendering a report (no New-WinSecCase supplied).')
    }

    $failure = @($events | Where-Object { [string]$_.Outcome -eq 'Failure' }).Count
    $success = @($events | Where-Object { [string]$_.Outcome -eq 'Success' }).Count
    $accounts = @($events | ForEach-Object { $_.TargetAccount, $_.SubjectAccount } | Where-Object { $_ } | Sort-Object -Unique)
    $hosts    = @($events | ForEach-Object { $_.Computer } | Where-Object { $_ } | Sort-Object -Unique)
    $attack   = @($events | ForEach-Object { $_.AttackIds } | Where-Object { $_ } | Sort-Object -Unique)

    $times = @($events | ForEach-Object { $_.TimeUtc } | Where-Object { $_ -and $_ -ne [datetime]::MinValue } | Sort-Object)
    $first = $times.Count ? $times[0] : $null
    $last  = $times.Count ? $times[-1] : $null
    $spanHours = ($first -and $last) ? [Math]::Round(($last - $first).TotalHours, 2) : 0

    $severityRank = @{ Informational = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
    $maxRank = 0
    $maxSev = 'Informational'
    foreach ($f in $findings) {
        $s = [string]$f.Severity
        if ($severityRank.ContainsKey($s) -and $severityRank[$s] -gt $maxRank) { $maxRank = $severityRank[$s]; $maxSev = $s }
    }
    if (-not $findings) {
        foreach ($e in $events) {
            $s = [string]$e.Importance
            if ($severityRank.ContainsKey($s) -and $severityRank[$s] -gt $maxRank) { $maxRank = $severityRank[$s]; $maxSev = $s }
        }
    }

    $verdict = 'No matching activity in the collected window'

    # Success from the same source after a sustained failure run is the single
    # most important signal an IR report can carry — check it FIRST.
    $compromise = $false
    if ($failure -gt 0 -and $success -gt 0) {
        $failByIp = @{}
        foreach ($e in $events) {
            if ([string]$e.Outcome -eq 'Failure' -and $e.SourceIp) {
                $k = [string]$e.SourceIp
                $failByIp[$k] = 1 + ($failByIp.ContainsKey($k) ? $failByIp[$k] : 0)
            }
        }
        foreach ($e in $events) {
            if ([string]$e.Outcome -ne 'Success' -or -not $e.SourceIp) { continue }
            $k = [string]$e.SourceIp
            if ($failByIp.ContainsKey($k) -and $failByIp[$k] -ge 5) { $compromise = $true; break }
        }
    }

    if ($compromise) { $verdict = 'Credential compromise — success observed after failures' }
    elseif (@($findings | Where-Object { $_.Pattern -eq 'BruteForceWithSuccess' -or $_.SucceededAfterFailures }).Count -gt 0) {
        $verdict = 'Credential compromise — success observed after failures'
    }
    elseif (@($findings | Where-Object Pattern -eq 'BruteForce').Count -gt 0) { $verdict = 'Brute-force attack' }
    elseif (@($findings | Where-Object Pattern -eq 'PasswordSpraying').Count -gt 0) { $verdict = 'Password spraying' }
    elseif (@($findings | Where-Object Pattern -eq 'CredentialStuffing').Count -gt 0) { $verdict = 'Credential stuffing' }
    elseif (@($findings | Where-Object Pattern -eq 'LockoutStorm').Count -gt 0) { $verdict = 'Account lockout storm' }
    elseif ($events.Count -gt 0) { $verdict = 'Suspicious authentication activity' }

    # ---- limitations & confidence -------------------------------------------
    $limits = [System.Collections.Generic.List[string]]::new()
    if ($events.Count -eq 0) { $limits.Add('No events matched the query. Absence of evidence is not evidence of absence — confirm log coverage and audit policy first.') }
    $risky = @($coverage | Where-Object { [string]$_.Risk -in 'High', 'Critical' -or -not $_.IsAccessible })
    if ($risky.Count -gt 0) { $limits.Add(('Log coverage gaps on {0} channel(s): {1}.' -f $risky.Count, (($risky | ForEach-Object { '{0}/{1}' -f $_.Computer, $_.LogName }) -join ', '))) }
    $skipped = @($coverage | Where-Object { -not $_.IsEnabled -and $_.IsAccessible })
    if ($skipped.Count -gt 0) { $limits.Add(('Disabled channel(s): {0}.' -f (($skipped | ForEach-Object { $_.LogName }) -join ', '))) }
    if (-not $attrib) { $limits.Add('No threat-intelligence attribution was supplied; ownership of the source IP is unconfirmed.') }
    if (-not $first) { $limits.Add('The observed time window is unknown (no events).') }
    $limits.Add('Findings are derived from Windows event records; clocks on evidence sources may drift from the analyst workstation.')

    $confidence = 'High'
    if ($events.Count -eq 0 -or $risky.Count -gt 0) { $confidence = 'Low' }
    elseif ($coverage.Count -eq 0 -or $limits.Count -gt 3) { $confidence = 'Medium' }

    # ---- recommendations -----------------------------------------------------
    $recs = [System.Collections.Generic.List[string]]::new()
    if ($verdict -like 'Credential compromise*') {
        $recs.Add('Treat the targeted account(s) as compromised: reset credentials, revoke refresh/kerberos tickets and terminate active sessions.')
        $recs.Add('Isolate or triage the affected host(s) and collect volatile evidence before remediation.')
        $recs.Add('Hunt for lateral movement from the source IP and from the compromised account across all domain-joined hosts.')
        $recs.Add('Review mailbox, VPN and SaaS sign-ins for the same account in the same window.')
    }
    elseif ($findings.Count -gt 0) {
        $recs.Add('Block or rate-limit the source address at the network edge and on exposed services (VPN, RDP, SMTP, SSH).')
        $recs.Add('Enforce account lockout thresholds, MFA and geo/ASN restrictions on internet-facing authentication.')
        $recs.Add('Verify whether any attempt succeeded; if yes, escalate to the compromise playbook.')
    }
    else {
        $recs.Add('Confirm audit policy and log retention before concluding that no activity occurred.')
        $recs.Add('Widen the time window, add profiles or rerun with -DeepScan to catch message-embedded addresses.')
    }
    if ($risky.Count -gt 0) { $recs.Add('Increase Security log size / enable forwarding so the retention window covers a realistic dwell time.') }
    $recs.Add('File an abuse report with the source network operator and attach this bundle (New-WinSecAbuseReport).')
    $recs.Add('Preserve the evidence bundle unmodified; verify hashes with Test-WinSecEvidenceIntegrity before sharing.')

    # ---- narrative ------------------------------------------------------------
    $subject = ($Case.SubjectIps -join ', ')
    $narrative = if ($events.Count -gt 0) {
        '{0}. Across {1} host(s) the collection returned {2} event(s) in {3} → {4} UTC ({5} h): {6} failure(s), {7} success(es), {8} account(s). Highest severity: {9}.' -f
            $verdict, $hosts.Count, $events.Count, (Format-WinSecUtc $first), (Format-WinSecUtc $last), $spanHours,
            $failure, $success, $accounts.Count, $maxSev
    }
    else {
        '{0}: no events referencing {1} were found. This report documents the scope, method and evidence limitations rather than an intrusion.' -f
            $verdict, $subject
    }

    [pscustomobject]@{
        Case          = $Case
        Events        = $events
        Findings      = $findings
        Sessions      = $sessions
        Coverage      = $coverage
        Attribution   = $attrib
        Timeline      = $buckets
        Summary       = $Summary
        EventCount    = $events.Count
        FailureCount  = $failure
        SuccessCount  = $success
        AccountCount  = $accounts.Count
        HostCount     = $hosts.Count
        FirstUtc      = $first
        LastUtc       = $last
        SpanHours     = $spanHours
        Severity      = $maxSev
        Verdict       = $verdict
        Confidence    = $confidence
        AttackIds     = $attack
        Limitations   = @($limits)
        Recommendations = @($recs)
        Narrative     = $narrative
        Iocs          = (Get-WinSecIocSet -Case $Case -Event $events -Finding $findings)
    }
}

<#
    .SYNOPSIS
        Builds a renderer-agnostic section model for incident reports.
    .DESCRIPTION
        Every section is a hashtable: Type = heading | paragraph | bullets |
        keyvalue | table. Markdown and HTML renderers consume the same model, so
        both formats always carry identical facts.
#>
function Get-WinSecReportSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Context,
        [ValidateSet('Executive', 'Technical', 'Full')]
        [string] $Template = 'Technical'
    )

    $sections = [System.Collections.Generic.List[hashtable]]::new()
    $h = { param($t) $sections.Add(@{ Type = 'heading'; Level = 2; Text = $t }) }
    $p = { param($t) $sections.Add(@{ Type = 'paragraph'; Text = $t }) }
    $b = { param($items) $sections.Add(@{ Type = 'bullets'; Items = @($items) }) }
    $kv = { param($pairs) $sections.Add(@{ Type = 'keyvalue'; Pairs = $pairs }) }
    $tbl = { param($headers, $rows) $sections.Add(@{ Type = 'table'; Headers = @($headers); Rows = @($rows) }) }

    # ---- 1. Executive summary -------------------------------------------------
    & $h 'Executive summary'
    & $kv ([ordered]@{
        'Case'       = $Context.Case.CaseId
        'Title'      = $Context.Case.Title
        'Verdict'    = $Context.Verdict
        'Severity'   = $Context.Severity
        'Confidence' = $Context.Confidence
        'Subject IP' = ($Context.Case.SubjectIps -join ', ')
        'Operator'   = $Context.Case.Operator
        'Generated'  = ('{0} UTC' -f (Format-WinSecUtc ([datetime]::UtcNow)))
    })
    & $p $Context.Narrative
    $facts = @(
        ('{0} event(s) from {1} channel-query(ies) on {2} host(s)' -f $Context.EventCount, @($Context.Coverage).Count, $Context.HostCount)
        ('{0} failure(s) / {1} success(es) across {2} account(s)' -f $Context.FailureCount, $Context.SuccessCount, $Context.AccountCount)
        ('Observed window: {0} → {1} UTC ({2} h)' -f (Format-WinSecUtc $Context.FirstUtc), (Format-WinSecUtc $Context.LastUtc), $Context.SpanHours)
    )
    if ($Context.Findings.Count -gt 0) { $facts += ('{0} detection finding(s); ATT&CK: {1}' -f $Context.Findings.Count, (($Context.AttackIds) -join ', ')) }
    & $b $facts
    if ($Template -eq 'Executive') {
        & $h 'Recommended immediate actions'
        & $b (@($Context.Recommendations | Select-Object -First 4))
        & $h 'Indicators (top)'
        $top = @($Context.Iocs.Rows | Where-Object { $_.Type -ne 'TargetIp' } | Select-Object -First 10)
        if ($top.Count) { & $tbl @('Type', 'Value', 'Count') @($top | ForEach-Object { , @($_.Type, $_.Value, [string]$_.Count) }) }
        return $sections
    }

    # ---- 2. Scope and method --------------------------------------------------
    & $h 'Scope and method'
    & $p ('Collection targeted Windows event channels selected by the WinSecHunter catalog. ' +
          'Each channel is queried independently, so a missing optional channel (for example Sysmon) reduces coverage without aborting the sweep. ' +
          'Server-side XPath pushes the time window, event IDs and exact IP variants; every record is re-verified client-side before it is reported.')
    & $kv ([ordered]@{
        'Scope hosts'    = (($Context.Case.ScopeHosts | Where-Object { $_ }) -join ', ') ?? '(local machine)'
        'Subject IP(s)'  = ($Context.Case.SubjectIps -join ', ')
        'Channels'       = (($Context.Coverage | ForEach-Object { $_.LogName } | Sort-Object -Unique) -join ', ')
        'Events in scope'= [string]$Context.EventCount
        'Tool'           = ('WinSecHunter {0}' -f $script:WinSecModuleVersion)
    })
    if ($Context.Limitations.Count) { & $b $Context.Limitations }

    # ---- 3. Timeline ----------------------------------------------------------
    & $h 'Activity timeline'
    if ($Context.Timeline.Count -gt 0) {
        $rows = @($Context.Timeline | Select-Object -First 72 | ForEach-Object {
            , @((Format-WinSecUtc $_.BucketStartUtc), [string]$_.Count, [string]$_.FailureCount, [string]$_.SuccessCount,
                [string]$_.DistinctAccounts, [string]$_.DistinctHosts, [string]$_.TopEventIds)
        })
        & $tbl @('Bucket start (UTC)', 'Events', 'Failures', 'Successes', 'Accounts', 'Hosts', 'Top event IDs') $rows
    }
    elseif ($Context.Events.Count -gt 0) {
        $rows = @($Context.Events | Group-Object EventId | Sort-Object Count -Descending | Select-Object -First 25 | ForEach-Object {
            , @([string]$_.Name, $_.Group[0].EventName, [string]$_.Count,
                (Format-WinSecUtc (($_.Group | Measure-Object TimeUtc -Minimum).Minimum)),
                (Format-WinSecUtc (($_.Group | Measure-Object TimeUtc -Maximum).Maximum)))
        })
        & $tbl @('Event ID', 'Name', 'Count', 'First (UTC)', 'Last (UTC)') $rows
    }
    else { & $p 'No activity was observed in the collected window.' }

    # ---- 4. Findings ----------------------------------------------------------
    & $h 'Detection findings'
    if ($Context.Findings.Count -gt 0) {
        $rows = @($Context.Findings | ForEach-Object {
            , @([string]$_.Pattern, [string]$_.Severity, $_.TargetAccount, $_.SourceIp,
                [string]$_.FailureCount, [string]$_.SuccessCount, ('{0:N1}' -f $_.AttemptsPerMinute),
                ('{0} → {1}' -f (Format-WinSecUtc $_.FirstSeenUtc), (Format-WinSecUtc $_.LastSeenUtc)))
        })
        & $tbl @('Pattern', 'Severity', 'Target', 'Source', 'Failures', 'Successes', 'Attempts/min', 'Window (UTC)') $rows
        foreach ($f in $Context.Findings) {
            if ($f.Description) { & $p ('**{0} / {1}:** {2}' -f $f.Pattern, $f.TargetAccount, $f.Description) }
        }
    }
    else { & $p 'No brute-force, spraying, stuffing or lockout pattern exceeded its threshold.' }

    # ---- 5. Indicators --------------------------------------------------------
    & $h 'Indicators of compromise'
    if ($Context.Iocs.Rows.Count -gt 0) {
        foreach ($type in @('TargetIp', 'SourceIp', 'DestinationIp', 'Account', 'Host', 'Process', 'Service', 'Task', 'Path')) {
            $rows = @($Context.Iocs.Rows | Where-Object Type -eq $type)
            if ($rows.Count -eq 0) { continue }
            & $p ("**$type**")
            & $tbl @('Value', 'Count', 'First seen (UTC)', 'Last seen (UTC)') @($rows | Select-Object -First 50 | ForEach-Object {
                , @($_.Value, [string]$_.Count, (Format-WinSecUtc $_.FirstUtc), (Format-WinSecUtc $_.LastUtc))
            })
        }
    }
    else { & $p 'No indicators were extracted.' }

    # ---- 6. Sessions ----------------------------------------------------------
    if ($Context.Sessions.Count -gt 0) {
        & $h 'Logon sessions'
        $rows = @($Context.Sessions | Select-Object -First 100 | ForEach-Object {
            $dur = $_.Ended ? ('{0:N0}s' -f $_.GetDuration().TotalSeconds) : 'open'
            , @($_.Account, $_.Computer, [string]$_.LogonType, ($_.SourceIp ?? '-'),
                (Format-WinSecUtc $_.StartUtc), ($_.Ended ? (Format-WinSecUtc $_.EndUtc) : '—'),
                $dur, ($_.IsAdmin ? 'yes' : 'no'))
        })
        & $tbl @('Account', 'Host', 'Logon type', 'Source', 'Start (UTC)', 'End (UTC)', 'Duration', 'Admin') $rows
    }

    # ---- 7. Evidence quality --------------------------------------------------
    & $h 'Evidence quality'
    if ($Context.Coverage.Count -gt 0) {
        $rows = @($Context.Coverage | ForEach-Object {
            , @($_.Computer, $_.LogName, ($_.IsEnabled ? 'enabled' : 'disabled'), ($_.IsAccessible ? 'readable' : 'denied'),
                [string]$_.RecordCount, ('{0:N1}%' -f $_.UsedPercent), (Format-WinSecUtc $_.OldestRecordUtc),
                [string]$_.Risk, ($_.Warning ?? ''))
        })
        & $tbl @('Host', 'Channel', 'State', 'Access', 'Records', 'Used', 'Oldest (UTC)', 'Risk', 'Note') $rows
    }
    else { & $p 'No coverage snapshot was supplied — retention and audit gaps are unknown for this report.' }

    # ---- 8. Attribution -------------------------------------------------------
    if ($Context.Attribution.Count -gt 0) {
        & $h 'Source attribution'
        $rows = @($Context.Attribution | ForEach-Object {
            , @($_.IpAddress, ($_.PtrHostname ?? '—'), [string]$_.Country, [string]$_.AsnOrganization,
                [string]$_.AbuseConfidenceScore, [string]$_.TotalReports, [string]$_.Verdict)
        })
        & $tbl @('IP', 'PTR', 'Country', 'ASN organisation', 'Abuse score', 'Reports', 'Verdict') $rows
    }

    # ---- 9. Recommendations ---------------------------------------------------
    & $h 'Recommendations'
    & $b $Context.Recommendations

    # ---- 10. Evidence and custody --------------------------------------------
    & $h 'Evidence and chain of custody'
    $evidenceCount = @($Context.Case.Evidence.Keys).Count
    & $p ('The exported bundle contains {0} hashed artifact(s). manifest.json records SHA-256, byte size and UTC write time for every file; the manifest itself is written last and is intentionally not self-hashed.' -f $evidenceCount)
    & $b @(
        'Verify integrity with: Test-WinSecEvidenceIntegrity -Path <bundle>'
        'Share the bundle read-only; any modification changes the hashes and invalidates the manifest.'
        'Keep the original media image or EVTX copy alongside the bundle when available.'
    )

    if ($Template -eq 'Full') {
        & $h 'Appendix A — events by ID'
        if ($Context.Events.Count -gt 0) {
            $rows = @($Context.Events | Group-Object EventId | Sort-Object Count -Descending | ForEach-Object {
                , @([string]$_.Name, $_.Group[0].EventName, [string]$_.Count, (($_.Group[0].AttackIds) -join ', '))
            })
            & $tbl @('Event ID', 'Name', 'Count', 'ATT&CK') $rows
        }
        & $h 'Appendix B — MITRE ATT&CK coverage'
        if ($Context.AttackIds.Count -gt 0) {
            $rows = @($Context.AttackIds | ForEach-Object {
                $id = $_
                $count = @($Context.Events | Where-Object { $_.AttackIds -contains $id }).Count
                , @($id, [string]$count)
            })
            & $tbl @('Technique', 'Events') $rows
        }
        else { & $p 'No ATT&CK techniques were mapped.' }
    }

    return $sections
}

<#
    .SYNOPSIS
        Renders a section model as Markdown.
#>
function ConvertTo-WinSecReportMarkdown {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object[]] $Section,
        [Parameter(Mandatory)][string] $Title,
        [string] $Subtitle
    )

    $esc = { param($s) ([string]$s) -replace '\|', '\|' -replace "`r?`n", ' ' }
    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# $Title")
    $null = $md.AppendLine()
    if ($Subtitle) { $null = $md.AppendLine("_${Subtitle}_"); $null = $md.AppendLine() }

    foreach ($s in $Section) {
        switch ($s.Type) {
            'heading' {
                $null = $md.AppendLine()
                $null = $md.AppendLine(('{0} {1}' -f ('#' * [Math]::Max(2, [int]$s.Level)), $s.Text))
                $null = $md.AppendLine()
            }
            'paragraph' { $null = $md.AppendLine([string]$s.Text); $null = $md.AppendLine() }
            'bullets' {
                foreach ($i in @($s.Items)) { $null = $md.AppendLine("- $i") }
                $null = $md.AppendLine()
            }
            'keyvalue' {
                $null = $md.AppendLine('| Field | Value |')
                $null = $md.AppendLine('|---|---|')
                foreach ($k in $s.Pairs.Keys) { $null = $md.AppendLine(('| {0} | {1} |' -f (& $esc $k), (& $esc $s.Pairs[$k]))) }
                $null = $md.AppendLine()
            }
            'table' {
                if (-not $s.Rows -or @($s.Rows).Count -eq 0) { $null = $md.AppendLine('_No rows._'); $null = $md.AppendLine(); break }
                $null = $md.AppendLine('| ' + ((@($s.Headers) | ForEach-Object { & $esc $_ }) -join ' | ') + ' |')
                $null = $md.AppendLine('|' + ((@($s.Headers) | ForEach-Object { '---' }) -join '|') + '|')
                foreach ($row in $s.Rows) {
                    $cells = @($row) | ForEach-Object { & $esc $_ }
                    $null = $md.AppendLine('| ' + ($cells -join ' | ') + ' |')
                }
                $null = $md.AppendLine()
            }
        }
    }
    return $md.ToString()
}

<#
    .SYNOPSIS
        Renders a section model as a self-contained HTML document
        (inline CSS, no scripts, no external requests).
#>
function ConvertTo-WinSecReportHtml {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][object[]] $Section,
        [Parameter(Mandatory)][string] $Title,
        [string] $Subtitle
    )

    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('<!DOCTYPE html>')
    $null = $sb.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
    $null = $sb.AppendLine(('<title>{0}</title>' -f (& $enc $Title)))
    $null = $sb.AppendLine(@'
<style>
:root{--bg:#0f1419;--card:#171d25;--ink:#e6edf3;--muted:#9aa7b4;--line:#2a3441;--accent:#4aa8ff;--warn:#f0b429;--bad:#ef5350;--ok:#3fb950}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 24px 64px}
h1{font-size:28px;margin:0 0 6px;letter-spacing:-.02em}
h2{font-size:19px;margin:34px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:16px;margin:20px 0 8px;color:var(--accent)}
.sub{color:var(--muted);margin:0 0 24px}
p{margin:0 0 12px}
ul{margin:0 0 14px 20px;padding:0}
li{margin:4px 0}
table{width:100%;border-collapse:collapse;margin:6px 0 18px;font-size:13.5px;background:var(--card)}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:11.5px;letter-spacing:.05em}
tr:last-child td{border-bottom:none}
td:first-child{white-space:nowrap}
.kv td:first-child{color:var(--muted);width:180px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line);color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:12px}
@media print{body{background:#fff;color:#111}table{background:#fff}th,td{border-color:#ddd}h2{border-color:#ddd}}
</style>
</head><body><main>
'@)
    $null = $sb.AppendLine(('<h1>{0}</h1>' -f (& $enc $Title)))
    if ($Subtitle) { $null = $sb.AppendLine(('<p class="sub">{0}</p>' -f (& $enc $Subtitle))) }

    foreach ($s in $Section) {
        switch ($s.Type) {
            'heading' {
                $lvl = [Math]::Max(2, [Math]::Min(3, [int]$s.Level))
                $null = $sb.AppendLine(('<h{0}>{1}</h{0}>' -f $lvl, (& $enc $s.Text)))
            }
            'paragraph' { $null = $sb.AppendLine(('<p>{0}</p>' -f (& $enc $s.Text))) }
            'bullets' {
                $null = $sb.AppendLine('<ul>')
                foreach ($i in @($s.Items)) { $null = $sb.AppendLine(('<li>{0}</li>' -f (& $enc $i))) }
                $null = $sb.AppendLine('</ul>')
            }
            'keyvalue' {
                $null = $sb.AppendLine('<table class="kv"><tbody>')
                foreach ($k in $s.Pairs.Keys) {
                    $null = $sb.AppendLine(('<tr><td>{0}</td><td>{1}</td></tr>' -f (& $enc $k), (& $enc $s.Pairs[$k])))
                }
                $null = $sb.AppendLine('</tbody></table>')
            }
            'table' {
                if (-not $s.Rows -or @($s.Rows).Count -eq 0) { $null = $sb.AppendLine('<p class="sub">No rows.</p>'); break }
                $null = $sb.AppendLine('<table><thead><tr>')
                foreach ($hcell in @($s.Headers)) { $null = $sb.AppendLine(('<th>{0}</th>' -f (& $enc $hcell))) }
                $null = $sb.AppendLine('</tr></thead><tbody>')
                foreach ($row in $s.Rows) {
                    $null = $sb.AppendLine('<tr>')
                    foreach ($cell in @($row)) { $null = $sb.AppendLine(('<td>{0}</td>' -f (& $enc $cell))) }
                    $null = $sb.AppendLine('</tr>')
                }
                $null = $sb.AppendLine('</tbody></table>')
            }
        }
    }

    $null = $sb.AppendLine(('<footer>Generated by WinSecHunter {0} at {1} UTC. Self-contained document — no external requests.</footer>' -f
        (& $enc $script:WinSecModuleVersion), (Format-WinSecUtc ([datetime]::UtcNow))))
    $null = $sb.AppendLine('</main></body></html>')
    return $sb.ToString()
}

<#
    .SYNOPSIS
        Resolves the abuse mailbox and display name for a source network.
    .DESCRIPTION
        Explicit -Provider wins. 'Auto' inspects the ASN organisation, PTR and
        country from attribution data. Unknown networks get an empty mailbox so
        the operator must supply -ContactEmail — the tool never invents an
        address.
#>
function Get-WinSecAbuseContact {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $Provider,
        [object] $Attribution,
        [string] $ContactEmail
    )

    $map = [ordered]@{
        AWS          = @{ Mailbox = 'abuse@amazonaws.com';        Name = 'Amazon Web Services' }
        Azure        = @{ Mailbox = 'abuse@microsoft.com';        Name = 'Microsoft Azure' }
        GCP          = @{ Mailbox = 'network-abuse@google.com';   Name = 'Google Cloud' }
        DigitalOcean = @{ Mailbox = 'abuse@digitalocean.com';     Name = 'DigitalOcean' }
        Hetzner      = @{ Mailbox = 'abuse@hetzner.com';          Name = 'Hetzner Online' }
        OVH          = @{ Mailbox = 'abuse@ovh.net';              Name = 'OVHcloud' }
        Cloudflare   = @{ Mailbox = 'abuse@cloudflare.com';       Name = 'Cloudflare' }
        Contabo      = @{ Mailbox = 'abuse@contabo.com';          Name = 'Contabo' }
        Linode       = @{ Mailbox = 'abuse@linode.com';           Name = 'Akamai / Linode' }
        Vultr        = @{ Mailbox = 'abuse@vultr.com';            Name = 'Vultr' }
        Oracle       = @{ Mailbox = 'abuse@oracle.com';           Name = 'Oracle Cloud' }
        Alibaba      = @{ Mailbox = 'abuse@alibabacloud.com';     Name = 'Alibaba Cloud' }
        Tencent      = @{ Mailbox = 'abuse@tencent.com';          Name = 'Tencent Cloud' }
        Generic      = @{ Mailbox = '';                            Name = 'Network operator' }
    }

    $resolved = $Provider
    if ($Provider -eq 'Auto') {
        $hay = @()
        if ($Attribution) {
            $hay += [string]$Attribution.AsnOrganization
            $hay += [string]$Attribution.PtrHostname
        }
        $hay = ($hay -join ' ').ToLowerInvariant()
        $resolved = 'Generic'
        foreach ($k in @('AWS', 'Azure', 'GCP', 'DigitalOcean', 'Hetzner', 'OVH', 'Cloudflare', 'Contabo', 'Linode', 'Vultr', 'Oracle', 'Alibaba', 'Tencent')) {
            $needle = switch ($k) {
                'AWS'     { 'amazon|aws' }
                'Azure'   { 'microsoft|azure' }
                'GCP'     { 'google' }
                'Linode'  { 'linode|akamai' }
                default   { $k.ToLowerInvariant() }
            }
            if ($hay -match $needle) { $resolved = $k; break }
        }
    }

    if (-not $map.Contains($resolved)) { $resolved = 'Generic' }
    $entry = $map[$resolved]
    $mailbox = $ContactEmail ? $ContactEmail : $entry.Mailbox
    $display = $entry.Name
    if ($Attribution -and $Attribution.AsnOrganization) { $display = [string]$Attribution.AsnOrganization }

    [pscustomobject]@{
        Provider = $resolved
        Mailbox  = $mailbox
        Display  = $display
        NeedsContact = [string]::IsNullOrWhiteSpace($mailbox)
    }
}

<#
    .SYNOPSIS
        Builds an RFC 5322 message (EML) with optional base64 attachments.
    .DESCRIPTION
        Headers use CRLF line endings as required by RFC 5322. Attachments are
        base64 with 76-character lines. The result is a plain string; the caller
        writes it with Write-WinSecFileAtomic -Crlf.
#>
function New-WinSecEmlMessage {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Pure string builder: composes an RFC 5322 message in memory, writes nothing.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $From,
        [Parameter(Mandatory)][string] $To,
        [Parameter(Mandatory)][string] $Subject,
        [Parameter(Mandatory)][AllowEmptyString()][string] $Body,
        [hashtable[]] $Attachment = @(),
        [string] $ReplyTo
    )

    $domain = 'localhost'
    if ($From -match '@([^>\s]+)') { $domain = $Matches[1] }
    $boundary = '=_WinSecHunter_{0}' -f [guid]::NewGuid().ToString('n')
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("From: $From")
    if ($ReplyTo) { $null = $sb.AppendLine("Reply-To: $ReplyTo") }
    $null = $sb.AppendLine("To: $To")
    $null = $sb.AppendLine("Subject: $Subject")
    $null = $sb.AppendLine(('Date: {0}' -f [datetime]::UtcNow.ToString('ddd, dd MMM yyyy HH:mm:ss +0000', [System.Globalization.CultureInfo]::InvariantCulture)))
    $null = $sb.AppendLine(('Message-ID: <{0}@{1}>' -f [guid]::NewGuid().ToString('n'), $domain))
    $null = $sb.AppendLine('MIME-Version: 1.0')
    $null = $sb.AppendLine(('Content-Type: multipart/mixed; boundary="{0}"' -f $boundary))
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("--$boundary")
    $null = $sb.AppendLine('Content-Type: text/plain; charset=utf-8')
    $null = $sb.AppendLine('Content-Transfer-Encoding: 8bit')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine($Body)

    foreach ($att in @($Attachment)) {
        if (-not $att -or -not $att['Name']) { continue }
        $bytes = if ($att.ContainsKey('Bytes') -and $att['Bytes']) { [byte[]]$att['Bytes'] }
                 else { [System.Text.Encoding]::UTF8.GetBytes([string]$att['Content']) }
        $b64 = [Convert]::ToBase64String($bytes)
        $ctype = $att.ContainsKey('ContentType') && $att['ContentType'] ? $att['ContentType'] : 'application/octet-stream'
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("--$boundary")
        $null = $sb.AppendLine(('Content-Type: {0}; name="{1}"' -f $ctype, $att['Name']))
        $null = $sb.AppendLine('Content-Transfer-Encoding: base64')
        $null = $sb.AppendLine(('Content-Disposition: attachment; filename="{0}"' -f $att['Name']))
        $null = $sb.AppendLine()
        for ($i = 0; $i -lt $b64.Length; $i += 76) {
            $null = $sb.AppendLine($b64.Substring($i, [Math]::Min(76, $b64.Length - $i)))
        }
    }

    $null = $sb.AppendLine()
    $null = $sb.AppendLine("--$boundary--")
    return $sb.ToString()
}

