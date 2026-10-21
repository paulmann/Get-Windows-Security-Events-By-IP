#Requires -Version 7.6
#Requires -PSEdition Core
function New-WinSecIncidentReport {
    <#
    .SYNOPSIS
        Produces a narrative incident report (Markdown and/or HTML) from
        collected events, detections, sessions, coverage and attribution.

    .DESCRIPTION
        Turns raw telemetry into the document a responder actually hands over:
        executive summary with verdict, severity and confidence; scope and
        method; timeline; detection findings; indicators of compromise; logon
        sessions; evidence-quality assessment; source attribution;
        recommendations; and the chain-of-custody statement.

        Two templates are available:
          Executive — one page for management: verdict, key facts, top
                      indicators, immediate actions, custody.
          Technical — the full report for the case file.
          Full      — Technical plus appendices (events by ID, ATT&CK coverage).

        Markdown is review-friendly (pull requests, tickets); HTML is a
        self-contained dark-theme document with inline CSS, no scripts and no
        external requests — safe to attach to an e-mail or open offline.

    .PARAMETER Case
        WinSecCase from New-WinSecCase. When omitted an ad-hoc case is derived
        from the supplied events.

    .PARAMETER Event
        WinSecEvent objects from Get-WinSecEventByIp (or Import-WinSecCase).

    .PARAMETER Finding
        Findings from Test-WinSecBruteForce.

    .PARAMETER Session
        Sessions from Get-WinSecLogonSession.

    .PARAMETER Coverage
        Coverage rows from Get-WinSecLogCoverage — they drive the confidence
        rating and the evidence-quality section.

    .PARAMETER Attribution
        Results from Resolve-WinSecIpAttribution.

    .PARAMETER Timeline
        Buckets from Get-WinSecIpTimeline. Without them the report falls back to
        an events-by-ID summary.

    .PARAMETER Summary
        Optional free-form facts merged into the report context.

    .PARAMETER Template
        Executive, Technical (default) or Full.

    .PARAMETER Format
        Markdown, Html or Both (default).

    .PARAMETER OutputDirectory
        Parent folder. Defaults to the DefaultOutputDirectory option, else the
        current directory.

    .PARAMETER FileName
        Base file name without extension. Defaults to
        <CaseId>-incident-report.

    .PARAMETER PassThru
        Emit the descriptor object (paths, SHA-256, verdict, counts).

    .EXAMPLE
        $events = Get-WinSecEventByIp 203.0.113.7 -LastDays 2 -PassHostStatus
        $case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force vs VPN tier'
        $events | Export-WinSecInvestigation -Case $case -Format All -PassThru
        New-WinSecIncidentReport -Case $case -Event $events -Template Full -PassThru

    .EXAMPLE
        Import-WinSecCase .\WSC-20261011-AB12CD34 |
            ForEach-Object { New-WinSecIncidentReport -Case $_.Case -Event $_.Events -Coverage $_.Coverage -Format Html }

    .OUTPUTS
        PSCustomObject describing written files with -PassThru; otherwise the
        paths are written to the information stream.

    .NOTES
        Every file is written atomically (temp file + replace) and hashed, so
        the same report can be registered in an evidence manifest.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [WinSecCase] $Case,
        [object[]] $Event,
        [object[]] $Finding,
        [object[]] $Session,
        [object[]] $Coverage,
        [object[]] $Attribution,
        [object[]] $Timeline,
        [hashtable] $Summary,

        [ValidateSet('Executive', 'Technical', 'Full')]
        [string] $Template = 'Technical',

        [ValidateSet('Markdown', 'Html', 'Both')]
        [string] $Format = 'Both',

        [string] $OutputDirectory,
        [string] $FileName,
        [switch] $PassThru
    )

    $config = Get-WinSecConfig
    if (-not $OutputDirectory) { $OutputDirectory = [string]$config.DefaultOutputDirectory }
    if (-not $OutputDirectory) { $OutputDirectory = (Get-Location).Path }

    $ctx = Get-WinSecCaseContext -Case $Case -Event $Event -Finding $Finding -Session $Session `
        -Coverage $Coverage -Attribution $Attribution -Timeline $Timeline -Summary $Summary

    $sections = Get-WinSecReportSection -Context $ctx -Template $Template
    $title = "Incident report — $($ctx.Case.Title)"
    $subtitle = 'Case {0} · {1} · severity {2} · confidence {3} · generated {4} UTC' -f
        $ctx.Case.CaseId, $ctx.Verdict, $ctx.Severity, $ctx.Confidence, (Format-WinSecUtc ([datetime]::UtcNow))

    $base = if ($FileName) { [System.IO.Path]::GetFileNameWithoutExtension($FileName) } else { "$($ctx.Case.CaseId)-incident-report" }
    $caseDir = Join-Path $OutputDirectory ($ctx.Case.CaseId + '-reports')

    $formats = switch ($Format) {
        'Markdown' { @('Markdown') }
        'Html'     { @('Html') }
        default    { @('Markdown', 'Html') }
    }

    $written = [System.Collections.Generic.List[object]]::new()
    foreach ($fmt in $formats) {
        $ext  = $fmt -eq 'Markdown' ? 'md' : 'html'
        $path = Join-Path $caseDir ("{0}.{1}" -f $base, $ext)
        if (-not $PSCmdlet.ShouldProcess($path, "Write $fmt incident report")) { continue }

        $content = if ($fmt -eq 'Markdown') {
            ConvertTo-WinSecReportMarkdown -Section $sections -Title $title -Subtitle $subtitle
        }
        else {
            ConvertTo-WinSecReportHtml -Section $sections -Title $title -Subtitle $subtitle
        }
        $null = Write-WinSecFileAtomic -Path $path -Content $content
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $bytes = (Get-Item -LiteralPath $path).Length
        $written.Add([pscustomobject]@{ Format = $fmt; Path = $path; Sha256 = $hash; Bytes = $bytes })
        Write-Information ("Incident report ({0}) written to {1} [{2} bytes]" -f $fmt, $path, $bytes) -InformationAction Continue
    }

    $result = [pscustomobject]@{
        CaseId     = $ctx.Case.CaseId
        Title      = $ctx.Case.Title
        Template   = $Template
        Verdict    = $ctx.Verdict
        Severity   = $ctx.Severity
        Confidence = $ctx.Confidence
        EventCount = $ctx.EventCount
        Files      = @($written)
        GeneratedUtc = [datetime]::UtcNow.ToString('o')
    }

    if ($PassThru -or $written.Count -eq 0) { return $result }
}


