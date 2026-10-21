#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: self-contained HTML investigation report
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Zero external dependencies: inline CSS + SVG only, safe for air-gapped
# review and e-mailing as evidence. All dynamic values are HTML-encoded.
# ---------------------------------------------------------------------------

function ConvertTo-WinSecHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] $Case,                 # WinSecCase
        [AllowNull()][object[]] $Events,     # WinSecEvent[]
        [AllowNull()][object[]] $Findings,   # WinSecBruteForceFinding[]
        [AllowNull()][object[]] $Sessions,   # WinSecSession[]
        [AllowNull()][object[]] $Coverage,   # WinSecLogCoverage[]
        [AllowNull()][object[]] $Attribution,# WinSecIpAttribution[]
        [AllowNull()][object[]] $Buckets,    # WinSecTimelineBucket[]
        [AllowNull()][hashtable] $Summary,
        [string] $Title = 'WinSecHunter Investigation Report',
        [int] $MaxEventRows = 1000
    )

    function Enc([AllowNull()]$Value) { [System.Net.WebUtility]::HtmlEncode([string]$Value) }
    function FmtUtc($Value) {
        if ($null -eq $Value) { return '—' }
        try { $dt = [datetime]$Value } catch { return '—' }
        ($dt -ne [datetime]::MaxValue -and $dt -ne [datetime]::MinValue) ? $dt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') : '—'
    }

    $sb = [System.Text.StringBuilder]::new()
    $now = [datetime]::UtcNow
    $modVersion = $script:WinSecModuleVersion ?? '2.0.0'

    # ---- summary (compute when not supplied) --------------------------------
    if (-not $Summary) {
        $Summary = @{}
        if ($Events) {
            $Summary.TotalEvents   = @($Events).Count
            $Summary.FirstSeenUtc  = ($Events | Measure-Object -Property TimeUtc -Minimum).Minimum
            $Summary.LastSeenUtc   = ($Events | Measure-Object -Property TimeUtc -Maximum).Maximum
            $Summary.FailureCount  = @($Events | Where-Object Outcome -eq 'Failure').Count
            $Summary.SuccessCount  = @($Events | Where-Object Outcome -eq 'Success').Count
            $Summary.Hosts         = @($Events | ForEach-Object { $_.Computer } | Sort-Object -Unique)
            $Summary.Accounts      = @($Events | ForEach-Object { $_.TargetAccount } | Where-Object { $_ } | Sort-Object -Unique)
        }
        else { $Summary.TotalEvents = 0 }
    }

    $verdictText = 'No attack patterns detected in the collected evidence.'
    $verdictClass = 'ok'
    if ($Findings -and @($Findings).Count -gt 0) {
        $order = @{ 'BruteForceWithSuccess' = 5; 'LockoutStorm' = 4; 'CredentialStuffing' = 4; 'PasswordSpraying' = 3; 'BruteForce' = 3; 'SuspiciousVolume' = 2; 'None' = 1 }
        $worst = $Findings | Sort-Object { $order[[string]$_.Pattern] ?? 0 } -Descending | Select-Object -First 1
        $verdictText  = '{0} — {1}' -f $worst.Pattern, $worst.Description
        $verdictClass = ($worst.SucceededAfterFailures -or $worst.Pattern -eq 'BruteForceWithSuccess') ? 'crit' : 'warn'
    }

    $caseId    = $Case ? $Case.CaseId : ('ad-hoc-{0:yyyyMMddHHmmss}' -f $now)
    $operator  = $Case ? $Case.Operator : ($env:USERNAME ?? $env:USER ?? 'unknown')
    $subjectIp = $Case ? ($Case.SubjectIps -join ', ') : ($Summary['SubjectIps'] -join ', ')

    # ---- head & style --------------------------------------------------------
    $null = $sb.Append(@"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>$(Enc $Title)</title>
<style>
:root{--bg:#0f1420;--card:#1a2233;--fg:#dbe4f3;--mut:#8ea0bd;--acc:#4da3ff;--crit:#ff5d5d;--warn:#ffb347;--ok:#41d99b;--line:#2a3550}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 'Segoe UI',Roboto,Arial,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px;color:var(--acc)}
.meta{color:var(--mut);font-size:12px;margin-bottom:16px}
.banner{padding:12px 16px;border-radius:8px;font-weight:600;margin:12px 0}
.banner.crit{background:rgba(255,93,93,.15);border:1px solid var(--crit);color:var(--crit)}
.banner.warn{background:rgba(255,179,71,.12);border:1px solid var(--warn);color:var(--warn)}
.banner.ok{background:rgba(65,217,155,.12);border:1px solid var(--ok);color:var(--ok)}
.cards{display:flex;flex-wrap:wrap;gap:12px;margin:14px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px;min-width:150px;flex:1}
.card .k{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:20px;font-weight:700;margin-top:2px;word-break:break-all}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden;font-size:13px}
th{background:#212b42;text-align:left;padding:8px 10px;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.05em}
td{padding:7px 10px;border-top:1px solid var(--line);vertical-align:top;word-break:break-word}
tr:hover td{background:rgba(77,163,255,.05)}
.chip{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700;border:1px solid}
.chip.Critical{color:var(--crit);border-color:var(--crit)}.chip.High{color:#ff8f6b;border-color:#ff8f6b}
.chip.Medium{color:var(--warn);border-color:var(--warn)}.chip.Low{color:var(--mut);border-color:var(--mut)}
.chip.Informational{color:var(--acc);border-color:var(--acc)}
.chip.Failure{color:var(--crit);border-color:var(--crit)}.chip.Success{color:var(--ok);border-color:var(--ok)}
.small{font-size:12px;color:var(--mut)}footer{margin:30px 0 10px;color:var(--mut);font-size:12px;border-top:1px solid var(--line);padding-top:10px}
code{background:#11182a;padding:1px 5px;border-radius:4px}
svg text{fill:var(--mut);font-size:10px}
</style>
</head>
<body><div class="wrap">
<h1>$(Enc $Title)</h1>
<div class="meta">Case <code>$(Enc $caseId)</code> · Operator <b>$(Enc $operator)</b> · Subject IP(s): <b>$(Enc $subjectIp)</b> · Generated $(FmtUtc $now) UTC · WinSecHunter $(Enc $modVersion)</div>
<div class="banner $verdictClass">$(Enc $verdictText)</div>
"@)

    # ---- summary cards --------------------------------------------------------
    $null = $sb.Append('<h2>Summary</h2><div class="cards">')
    $cardDefs = @(
        @{ k = 'Events';        v = "$($Summary['TotalEvents'])" },
        @{ k = 'Failures';      v = "$($Summary['FailureCount'])" },
        @{ k = 'Successes';     v = "$($Summary['SuccessCount'])" },
        @{ k = 'Hosts touched'; v = "$(@($Summary['Hosts']).Count)" },
        @{ k = 'Accounts hit';  v = "$(@($Summary['Accounts']).Count)" },
        @{ k = 'First seen (UTC)'; v = (FmtUtc $Summary['FirstSeenUtc']) },
        @{ k = 'Last seen (UTC)';  v = (FmtUtc $Summary['LastSeenUtc']) }
    )
    foreach ($c in $cardDefs) {
        $null = $sb.Append("<div class=`"card`"><div class=`"k`">$(Enc $c.k)</div><div class=`"v`">$(Enc $c.v)</div></div>")
    }
    $null = $sb.Append('</div>')

    # ---- timeline histogram (inline SVG) ---------------------------------------
    if ($Buckets -and @($Buckets).Count -gt 0) {
        $null = $sb.Append('<h2>Activity timeline (UTC)</h2>')
        $n = @($Buckets).Count
        $w = 960.0; $h = 170.0; $pad = 24.0
        $maxCount = (@($Buckets | Measure-Object -Property Count -Maximum).Maximum) ?? 1
        if ($maxCount -lt 1) { $maxCount = 1 }
        $barW = [Math]::Max(1.0, ($w - $pad) / $n - 1)
        $null = $sb.Append("<svg width=`"100%`" viewBox=`"0 0 $w $($h + 30)`" xmlns=`"http://www.w3.org/2000/svg`" role=`"img`" aria-label=`"Event volume histogram`">")
        $i = 0
        foreach ($b in $Buckets) {
            $bh = ([double]$b.Count / $maxCount) * ($h - 10)
            $x = $pad + $i * (($w - $pad) / $n)
            $y = $h - $bh
            $fill = $b.FailureCount -gt $b.SuccessCount ? '#ff5d5d' : ($b.Count -gt 0 ? '#4da3ff' : '#2a3550')
            $tip = Enc ("{0:yyyy-MM-dd HH:mm} UTC — {1} events ({2} fail / {3} ok)" -f $b.BucketStartUtc, $b.Count, $b.FailureCount, $b.SuccessCount)
            $null = $sb.Append("<rect x=`"$([Math]::Round($x,1))`" y=`"$([Math]::Round($y,1))`" width=`"$([Math]::Round($barW,1))`" height=`"$([Math]::Round($bh,1))`" fill=`"$fill`"><title>$tip</title></rect>")
            $labelEvery = [Math]::Ceiling($n / 8)
            if ($i % $labelEvery -eq 0) {
                $lbl = Enc ("{0:MM-dd HH:mm}" -f $b.BucketStartUtc)
                $null = $sb.Append("<text x=`"$([Math]::Round($x,1))`" y=`"$($h + 16)`">$lbl</text>")
            }
            $i++
        }
        $null = $sb.Append("<text x=`"0`" y=`"12`">peak: $maxCount</text></svg>")
    }

    # ---- table helper ---------------------------------------------------------
    $table = {
        param([string]$Heading, [object[]]$Rows, [scriptblock[]]$Cols, [string]$EmptyNote)
        $null = $sb.Append("<h2>$Heading</h2>")
        if (-not $Rows -or @($Rows).Count -eq 0) {
            $null = $sb.Append("<p class=`"small`">$(Enc ($EmptyNote ?? 'No data.'))</p>")
            return
        }
        $null = $sb.Append('<table><thead><tr>')
        foreach ($c in $Cols) { $null = $sb.Append("<th>$(Enc (& $c 'header'))</th>") }
        $null = $sb.Append('</tr></thead><tbody>')
        foreach ($r in $Rows) {
            $null = $sb.Append('<tr>')
            foreach ($c in $Cols) { $null = $sb.Append("<td>$(& $c $r)</td>") }
            $null = $sb.Append('</tr>')
        }
        $null = $sb.Append('</tbody></table>')
    }
    $chip = { param($v) "<span class=`"chip $(Enc $v)`">$(Enc $v)</span>" }

    # ---- findings ---------------------------------------------------------------
    if ($Findings) {
        & $table 'Detection findings' @($Findings) @(
            { param($x) if ($x -eq 'header') { 'Pattern' } else { Enc $x.Pattern } },
            { param($x) if ($x -eq 'header') { 'Severity' } else { & $chip ([string]$x.Severity) } },
            { param($x) if ($x -eq 'header') { 'Target' } else { Enc $x.TargetAccount } },
            { param($x) if ($x -eq 'header') { 'Source IP' } else { "<code>$(Enc $x.SourceIp)</code>" } },
            { param($x) if ($x -eq 'header') { 'Fail / OK' } else { "$($x.FailureCount) / $($x.SuccessCount)" } },
            { param($x) if ($x -eq 'header') { 'Per min' } else { '{0:N1}' -f $x.AttemptsPerMinute } },
            { param($x) if ($x -eq 'header') { 'Window (UTC)' } else { "$(FmtUtc $x.FirstSeenUtc) → $(FmtUtc $x.LastSeenUtc)" } },
            { param($x) if ($x -eq 'header') { 'ATT&CK' } else { Enc ($x.AttackIds -join ', ') } },
            { param($x) if ($x -eq 'header') { 'Detail' } else { Enc $x.Description } }
        ) $null
    }

    # ---- event breakdown ----------------------------------------------------------
    if ($Events) {
        $byId = $Events | Group-Object EventId | ForEach-Object {
            $g = $_.Group
            $first = ($g | Measure-Object TimeUtc -Minimum).Minimum
            $last  = ($g | Measure-Object TimeUtc -Maximum).Maximum
            [pscustomobject]@{
                EventId = $_.Name; Name = $g[0].EventName; Log = ($g[0].LogName -split '/')[-1]
                Count = $_.Count
                Fail  = @($g | Where-Object Outcome -eq 'Failure').Count
                Ok    = @($g | Where-Object Outcome -eq 'Success').Count
                First = $first; Last = $last
                Attack = ($g[0].AttackIds -join ', ')
                Imp = $g[0].Importance
            }
        } | Sort-Object Count -Descending
        & $table 'Events by ID' @($byId) @(
            { param($x) if ($x -eq 'header') { 'ID' } else { Enc $x.EventId } },
            { param($x) if ($x -eq 'header') { 'Name' } else { Enc $x.Name } },
            { param($x) if ($x -eq 'header') { 'Log' } else { Enc $x.Log } },
            { param($x) if ($x -eq 'header') { 'Importance' } else { & $chip ([string]$x.Imp) } },
            { param($x) if ($x -eq 'header') { 'Count' } else { $x.Count } },
            { param($x) if ($x -eq 'header') { 'Fail' } else { $x.Fail } },
            { param($x) if ($x -eq 'header') { 'OK' } else { $x.Ok } },
            { param($x) if ($x -eq 'header') { 'First (UTC)' } else { FmtUtc $x.First } },
            { param($x) if ($x -eq 'header') { 'Last (UTC)' } else { FmtUtc $x.Last } },
            { param($x) if ($x -eq 'header') { 'ATT&CK' } else { Enc $x.Attack } }
        ) $null

        # accounts + hosts
        $accts = $Events | Where-Object TargetAccount | Group-Object TargetAccount | Sort-Object Count -Descending | Select-Object -First 15
        & $table 'Top targeted accounts' @($accts) @(
            { param($x) if ($x -eq 'header') { 'Account' } else { Enc $x.Name } },
            { param($x) if ($x -eq 'header') { 'Events' } else { $x.Count } },
            { param($x) if ($x -eq 'header') { 'Failures' } else { @($x.Group | Where-Object Outcome -eq 'Failure').Count } },
            { param($x) if ($x -eq 'header') { 'Successes' } else { @($x.Group | Where-Object Outcome -eq 'Success').Count } },
            { param($x) if ($x -eq 'header') { 'Hosts' } else { Enc ((($x.Group | ForEach-Object { $_.Computer } | Sort-Object -Unique) -join ', ')) } }
        ) $null

        $hostsT = $Events | Group-Object Computer | Sort-Object Count -Descending
        & $table 'Affected hosts' @($hostsT) @(
            { param($x) if ($x -eq 'header') { 'Host' } else { Enc $x.Name } },
            { param($x) if ($x -eq 'header') { 'Events' } else { $x.Count } },
            { param($x) if ($x -eq 'header') { 'Failures' } else { @($x.Group | Where-Object Outcome -eq 'Failure').Count } },
            { param($x) if ($x -eq 'header') { 'First (UTC)' } else { FmtUtc (($x.Group | Measure-Object TimeUtc -Minimum).Minimum) } },
            { param($x) if ($x -eq 'header') { 'Last (UTC)' } else { FmtUtc (($x.Group | Measure-Object TimeUtc -Maximum).Maximum) } }
        ) $null
    }

    # ---- sessions ------------------------------------------------------------------
    if ($Sessions) {
        & $table 'Reconstructed logon sessions (top 50)' @($Sessions | Select-Object -First 50) @(
            { param($x) if ($x -eq 'header') { 'LogonId' } else { Enc $x.LogonId } },
            { param($x) if ($x -eq 'header') { 'Account' } else { Enc $x.Account } },
            { param($x) if ($x -eq 'header') { 'Computer' } else { Enc $x.Computer } },
            { param($x) if ($x -eq 'header') { 'LogonType' } else { Enc $x.LogonType } },
            { param($x) if ($x -eq 'header') { 'Source IP' } else { "<code>$(Enc $x.SourceIp)</code>" } },
            { param($x) if ($x -eq 'header') { 'Start (UTC)' } else { FmtUtc $x.StartUtc } },
            { param($x) if ($x -eq 'header') { 'Duration' } else { if ($x.EndUtc -eq [datetime]::MaxValue) { 'open' } else { Enc $x.GetDuration().ToString() } } },
            { param($x) if ($x -eq 'header') { 'Admin' } else { $x.IsAdmin ? '⚠ yes' : 'no' } }
        ) $null
    }

    # ---- attribution ------------------------------------------------------------------
    if ($Attribution) {
        & $table 'IP attribution' @($Attribution) @(
            { param($x) if ($x -eq 'header') { 'IP' } else { "<code>$(Enc $x.IpAddress)</code>" } },
            { param($x) if ($x -eq 'header') { 'Class' } else { $x.IsPrivate ? 'private' : 'public' } },
            { param($x) if ($x -eq 'header') { 'PTR' } else { Enc ($x.PtrHostname ?? '—') } },
            { param($x) if ($x -eq 'header') { 'Geo' } else { Enc (('{0} {1}' -f $x.CountryCode, $x.City).Trim()) } },
            { param($x) if ($x -eq 'header') { 'ASN' } else { Enc $x.AsnOrganization } },
            { param($x) if ($x -eq 'header') { 'Abuse score' } else { $x.Provider ? (Enc $x.AbuseConfidenceScore) : '—' } },
            { param($x) if ($x -eq 'header') { 'Verdict' } else { Enc $x.Verdict } }
        ) $null
    }

    # ---- coverage ------------------------------------------------------------------------
    if ($Coverage) {
        & $table 'Log coverage & completeness' @($Coverage) @(
            { param($x) if ($x -eq 'header') { 'Host' } else { Enc $x.Computer } },
            { param($x) if ($x -eq 'header') { 'Log' } else { Enc (($x.LogName -split '/')[-1]) } },
            { param($x) if ($x -eq 'header') { 'Enabled' } else { $x.IsEnabled ? 'yes' : '<b style="color:#ff5d5d">NO</b>' } },
            { param($x) if ($x -eq 'header') { 'Records' } else { $x.RecordCount } },
            { param($x) if ($x -eq 'header') { 'Oldest (UTC)' } else { FmtUtc $x.OldestRecordUtc } },
            { param($x) if ($x -eq 'header') { 'Newest (UTC)' } else { FmtUtc $x.NewestRecordUtc } },
            { param($x) if ($x -eq 'header') { 'Used' } else { '{0:N0}%' -f $x.UsedPercent } },
            { param($x) if ($x -eq 'header') { 'Risk' } else { & $chip ([string]$x.Risk) } },
            { param($x) if ($x -eq 'header') { 'Warning' } else { Enc $x.Warning } }
        ) 'No coverage data collected.'
    }

    # ---- raw events ---------------------------------------------------------------------
    if ($Events) {
        $rows = @($Events | Sort-Object TimeUtc | Select-Object -First $MaxEventRows)
        $note = @($Events).Count -gt $MaxEventRows ? "Showing first $MaxEventRows of $(@($Events).Count) events — full data in events.csv / events.json." : $null
        & $table 'Event detail (chronological)' $rows @(
            { param($x) if ($x -eq 'header') { 'Time (UTC)' } else { FmtUtc $x.TimeUtc } },
            { param($x) if ($x -eq 'header') { 'Host' } else { Enc $x.Computer } },
            { param($x) if ($x -eq 'header') { 'ID' } else { Enc $x.EventId } },
            { param($x) if ($x -eq 'header') { 'Category' } else { Enc $x.Category } },
            { param($x) if ($x -eq 'header') { 'Outcome' } else { & $chip ([string]$x.Outcome) } },
            { param($x) if ($x -eq 'header') { 'Source IP' } else { "<code>$(Enc ($x.SourceIp ?? $x.MatchedIp))</code>" } },
            { param($x) if ($x -eq 'header') { 'Target' } else { Enc $x.TargetAccount } },
            { param($x) if ($x -eq 'header') { 'LogonType' } else { [int]$x.LogonType -gt 0 ? (Enc ([string][int]$x.LogonType)) : '—' } },
            { param($x) if ($x -eq 'header') { 'Status' } else { Enc ($x.StatusCode ?? '—') } },
            { param($x) if ($x -eq 'header') { 'Match' } else { Enc ($x.MatchedOn ?? '') } }
        ) $note
    }

    # ---- notes & footer ------------------------------------------------------------------
    if ($Case -and $Case.Notes -and $Case.Notes.Count -gt 0) {
        $null = $sb.Append('<h2>Investigator notes</h2><ul>')
        foreach ($n in $Case.Notes) { $null = $sb.Append("<li>$(Enc $n)</li>") }
        $null = $sb.Append('</ul>')
    }
    $null = $sb.Append(@"
<footer>Generated by WinSecHunter v$(Enc $modVersion) on $(Enc $env:COMPUTERNAME) at $(FmtUtc $now) UTC.
Evidence bundle integrity: see <code>manifest.json</code> (SHA-256 per artifact).
WinSecHunter is a derivative of Get-Windows-Security-Events-By-IP (Mikhail Deynekin), licensed under the PolyForm Noncommercial License 1.0.0.</footer>
</div></body></html>
"@)
    return $sb.ToString()
}


