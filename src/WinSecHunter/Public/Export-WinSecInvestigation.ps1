#Requires -Version 7.6
function Export-WinSecInvestigation {
    <#
    .SYNOPSIS
        Writes a complete, tamper-evident investigation bundle: events,
        findings, sessions, coverage, attribution, timeline and a
        self-contained HTML report — hashed into manifest.json.

    .DESCRIPTION
        Production evidence export for an IP investigation. Creates (or reuses)
        a case folder, writes each selected artifact, then computes SHA-256 for
        every file and records it in manifest.json together with tool version,
        operator, host and timestamps — the chain-of-custody anchor you can
        hand to a responder, auditor or court.

        Artifacts (written when the corresponding input is supplied):
          events.csv / events.json / events.clixml   — normalized events
          findings.json                              — brute-force/spray detections
          sessions.csv                               — reconstructed logon sessions
          coverage.csv                               — log completeness snapshot
          attribution.json                           — IP enrichment results
          timeline.csv                               — activity buckets
          report.html                                — self-contained HTML report
          report.md                                  — Markdown summary
          case.json                                  — case metadata + notes
          manifest.json                              — SHA-256 manifest (written last)

        CLIXML preserves WinSecEvent objects for re-analysis with
        Import-Clixml; JSON/CSV are SIEM/spreadsheet-friendly. The HTML report
        has zero external dependencies (inline CSS/SVG) and renders anywhere.

    .PARAMETER Case
        WinSecCase from New-WinSecCase. When omitted, an ad-hoc case is
        created from the event data (subject IPs = distinct MatchedIp).

    .PARAMETER OutputDirectory
        Parent directory; the case folder is created inside it. Defaults to
        the DefaultOutputDirectory configuration option, else the current
        directory.

    .PARAMETER Format
        Artifact set: Csv, Json, Html, Markdown, CliXml or All. Events are
        written in each requested tabular/structured format; report.html and
        report.md follow Html/Markdown respectively.

    .PARAMETER PassThru
        Return the WinSecCase with Evidence (path → SHA-256) populated.

    .EXAMPLE
        $events = Get-WinSecEventByIp 203.0.113.7 -ComputerName SRV1, SRV2 -LastDays 2 -IncludeRawXml
        $case   = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force vs SRV tier'
        $events | Test-WinSecBruteForce | Set-Variable findings
        Export-WinSecInvestigation -Case $case -Event $events -Finding $findings -Format All -PassThru

    .EXAMPLE
        Get-WinSecEventByIp 10.0.0.0/24 -Path C:\Cases\*.evtx |
            Export-WinSecInvestigation -Format Csv, Html -OutputDirectory D:\IR

    .OUTPUTS
        WinSecCase with -PassThru; otherwise the bundle directory (as string,
        via Write-Information) and nothing to the success stream.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType('WinSecCase')]
    param(
        [WinSecCase] $Case,

        [WinSecEvent[]] $Event,
        [object[]] $Finding,
        [object[]] $Session,
        [object[]] $Coverage,
        [object[]] $Attribution,
        [object[]] $Timeline,
        [hashtable] $Summary,

        [string] $OutputDirectory,
        [WinSecExportFormat[]] $Format = @([WinSecExportFormat]::Csv, [WinSecExportFormat]::Json, [WinSecExportFormat]::Html),
        [ValidateRange(10, 100000)] [int] $MaxHtmlEventRows = 1000,
        [switch] $PassThru
    )

    $config = Get-WinSecConfig
    if (-not $OutputDirectory) { $OutputDirectory = [string]$config.DefaultOutputDirectory }
    if (-not $OutputDirectory) { $OutputDirectory = (Get-Location).Path }

    # ---- Case bootstrap ------------------------------------------------------
    if (-not $Case) {
        $Case = [WinSecCase]::new()
        $ips = @($Event | ForEach-Object { $_.MatchedIp, $_.SourceIp } | Where-Object { $_ } | Sort-Object -Unique)
        $Case.SubjectIps = $ips.Count -gt 0 ? [string[]]$ips : [string[]]@('(none)')
        $Case.Title = "Ad-hoc investigation of $($Case.SubjectIps -join ', ')"
        $Case.AddNote('Ad-hoc case created by Export-WinSecInvestigation (no New-WinSecCase supplied).')
    }
    foreach ($f in @($Finding)) { if ($f) { $Case.AddFinding($f) } }
    if ($Event) {
        $Case.AddNote(('Exported {0} event(s); {1} failure(s), {2} success(es); hosts: {3}.' -f
            @($Event).Count,
            @($Event | Where-Object Outcome -eq 'Failure').Count,
            @($Event | Where-Object Outcome -eq 'Success').Count,
            ((@($Event | ForEach-Object { $_.Computer } | Sort-Object -Unique)) -join ', ')))
    }

    $caseDir = Join-Path $OutputDirectory $Case.CaseId
    if ($PSCmdlet.ShouldProcess($caseDir, 'Create case directory')) {
        if (-not (Test-Path -LiteralPath $caseDir)) { $null = New-Item -ItemType Directory -Path $caseDir -Force }
    }

    $want = { param($f) $Format -contains [WinSecExportFormat]::All -or $Format -contains $f }

    $written = [System.Collections.Generic.List[string]]::new()
    $writeArtifact = {
        param([string]$FileName, [scriptblock]$Writer, [string]$Source)
        $path = Join-Path $caseDir $FileName
        if ($PSCmdlet.ShouldProcess($path, "Write $Source")) {
            & $Writer $path
            $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
            $bytes = (Get-Item -LiteralPath $path).Length
            $rel = '{0}/{1}' -f $Case.CaseId, $FileName
            $Case.RegisterEvidence($rel, $hash, $bytes, $Source)
            $written.Add($path)
        }
    }

    # ---- events ----------------------------------------------------------------
    if ($Event -and @($Event).Count -gt 0) {
        $flat = @($Event | Sort-Object TimeUtc | ForEach-Object { [pscustomobject]$_.ToHashtable($false) })
        if (& $want 'Csv') {
            & $writeArtifact 'events.csv' { param($p) $flat | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding utf8NoBOM } 'Get-WinSecEventByIp events (flattened)'
        }
        if (& $want 'Json') {
            & $writeArtifact 'events.json' { param($p) $flat | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $p -Encoding utf8NoBOM } 'Get-WinSecEventByIp events (flattened)'
        }
        if (& $want 'CliXml') {
            & $writeArtifact 'events.clixml' { param($p) $Event | Export-Clixml -LiteralPath $p -Depth 4 } 'Get-WinSecEventByIp events (objects)'
        }
    }

    # ---- findings ---------------------------------------------------------------
    if ($Finding -and @($Finding).Count -gt 0 -and (& $want 'Json')) {
        $fFlat = @($Finding | ForEach-Object {
            [pscustomobject]@{
                Pattern = [string]$_.Pattern; Severity = [string]$_.Severity
                TargetAccount = $_.TargetAccount; SourceIp = $_.SourceIp
                SourceHosts = ($_.SourceHosts -join ', ')
                FailureCount = $_.FailureCount; SuccessCount = $_.SuccessCount
                DistinctAccounts = $_.DistinctAccounts; DistinctSources = $_.DistinctSources
                FirstSeenUtc = $_.FirstSeenUtc.ToString('o'); LastSeenUtc = $_.LastSeenUtc.ToString('o')
                AttemptsPerMinute = $_.AttemptsPerMinute
                SucceededAfterFailures = $_.SucceededAfterFailures
                AttackIds = ($_.AttackIds -join ', '); Description = $_.Description
                EvidenceRecordCount = @($_.Evidence).Count
            }
        })
        & $writeArtifact 'findings.json' { param($p) $fFlat | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $p -Encoding utf8NoBOM } 'Test-WinSecBruteForce findings'
    }

    # ---- sessions ----------------------------------------------------------------
    if ($Session -and @($Session).Count -gt 0 -and (& $want 'Csv')) {
        $sFlat = @($Session | ForEach-Object {
            [pscustomobject]@{
                LogonId = $_.LogonId; Computer = $_.Computer; Account = $_.Account
                LogonType = [string]$_.LogonType; SourceIp = $_.SourceIp
                AuthPackage = $_.AuthPackage
                StartUtc = $_.StartUtc.ToString('o')
                EndUtc = ($_.Ended ? $_.EndUtc.ToString('o') : '')
                DurationSeconds = ($_.Ended ? [Math]::Round($_.GetDuration().TotalSeconds, 1) : '')
                IsAdmin = $_.IsAdmin; Ended = $_.Ended
                ChildLogonIds = ($_.ChildLogonIds -join ', ')
                EventCount = @($_.Events).Count
            }
        })
        & $writeArtifact 'sessions.csv' { param($p) $sFlat | Export-Csv -LiteralPath $p -NoTypeInformation -Encoding utf8NoBOM } 'Get-WinSecLogonSession output'
    }

    # ---- coverage ------------------------------------------------------------------
    if ($Coverage -and @($Coverage).Count -gt 0 -and (& $want 'Csv')) {
        & $writeArtifact 'coverage.csv' { param($p)
            $Coverage | ForEach-Object { [pscustomobject]@{
                Computer = $_.Computer; LogName = $_.LogName; IsEnabled = $_.IsEnabled
                IsAccessible = $_.IsAccessible; RecordCount = $_.RecordCount
                FileSizeBytes = $_.FileSizeBytes; MaxSizeBytes = $_.MaxSizeBytes
                UsedPercent = $_.UsedPercent; RetentionSetting = $_.RetentionSetting
                OldestRecordUtc = ($_.OldestRecordUtc ? $_.OldestRecordUtc.ToString('o') : '')
                NewestRecordUtc = ($_.NewestRecordUtc ? $_.NewestRecordUtc.ToString('o') : '')
                Risk = [string]$_.Risk; Warning = $_.Warning } } |
            Export-Csv -LiteralPath $p -NoTypeInformation -Encoding utf8NoBOM } 'Get-WinSecLogCoverage output'
    }

    # ---- attribution ------------------------------------------------------------------
    if ($Attribution -and @($Attribution).Count -gt 0 -and (& $want 'Json')) {
        & $writeArtifact 'attribution.json' { param($p)
            @($Attribution | ForEach-Object { $_ | Select-Object IpAddress, Version, IsPrivate, IsLoopback, IsLinkLocal,
                PtrHostname, PtrResolved, Provider, QueriedUtc, Country, CountryCode, Region, City, Asn,
                AsnOrganization, AbuseConfidenceScore, TotalReports, Categories, Verdict }) |
            ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $p -Encoding utf8NoBOM } 'Resolve-WinSecIpAttribution output'
    }

    # ---- timeline ------------------------------------------------------------------------
    if ($Timeline -and @($Timeline).Count -gt 0 -and (& $want 'Csv')) {
        $buckets = @($Timeline | Where-Object { $_ -is [WinSecTimelineBucket] })
        if ($buckets.Count -gt 0) {
            & $writeArtifact 'timeline.csv' { param($p)
                $buckets | ForEach-Object { [pscustomobject]@{
                    BucketStartUtc = $_.BucketStartUtc.ToString('o'); Count = $_.Count
                    FailureCount = $_.FailureCount; SuccessCount = $_.SuccessCount
                    DistinctAccounts = $_.DistinctAccounts; DistinctHosts = $_.DistinctHosts
                    TopEventIds = $_.TopEventIds } } |
                Export-Csv -LiteralPath $p -NoTypeInformation -Encoding utf8NoBOM } 'Get-WinSecIpTimeline buckets'
        }
    }

    # ---- indicators ------------------------------------------------------------
    $iocSet = Get-WinSecIocSet -Case $Case -Event $Event -Finding $Finding
    if ($iocSet.Rows.Count -gt 0) {
        if (& $want 'Csv') {
            & $writeArtifact 'iocs.csv' { param($p)
                $iocSet.Rows | ForEach-Object { [pscustomobject]@{
                    Type = $_.Type; Value = $_.Value; Count = $_.Count
                    FirstUtc = (Format-WinSecUtc $_.FirstUtc); LastUtc = (Format-WinSecUtc $_.LastUtc) } } |
                Export-Csv -LiteralPath $p -NoTypeInformation -Encoding utf8NoBOM } 'Indicators of compromise'
        }
        if (& $want 'Json') {
            & $writeArtifact 'iocs.json' { param($p)
                @($iocSet.Rows | ForEach-Object { [pscustomobject]@{
                    Type = $_.Type; Value = $_.Value; Count = $_.Count
                    FirstUtc = (Format-WinSecUtc $_.FirstUtc); LastUtc = (Format-WinSecUtc $_.LastUtc) } }) |
                ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $p -Encoding utf8NoBOM } 'Indicators of compromise'
        }
    }

    # ---- HTML report ------------------------------------------------------------------------
    if (& $want 'Html') {
        $timelineBuckets = @($Timeline | Where-Object { $_ -is [WinSecTimelineBucket] })
        $html = ConvertTo-WinSecHtmlReport -Case $Case -Events $Event -Findings $Finding -Sessions $Session `
            -Coverage $Coverage -Attribution $Attribution -Buckets $timelineBuckets -Summary $Summary `
            -Title "Investigation: $($Case.Title)" -MaxEventRows $MaxHtmlEventRows
        & $writeArtifact 'report.html' { param($p) Set-Content -LiteralPath $p -Value $html -Encoding utf8NoBOM } 'Rendered investigation report'
    }

    # ---- Markdown report -----------------------------------------------------------------------
    if (& $want 'Markdown') {
        $md = [System.Text.StringBuilder]::new()
        $fmt = { param($d) ($d -and $d -ne [datetime]::MaxValue) ? ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') : '—' }
        $null = $md.AppendLine("# Investigation: $($Case.Title)")
        $null = $md.AppendLine()
        $null = $md.AppendLine("- **Case:** ``$($Case.CaseId)``")
        $null = $md.AppendLine("- **Subject IP(s):** $($Case.SubjectIps -join ', ')")
        $null = $md.AppendLine("- **Operator:** $($Case.Operator)")
        $null = $md.AppendLine("- **Generated:** $(& $fmt ([datetime]::UtcNow)) UTC (WinSecHunter $($script:WinSecModuleVersion))")
        $null = $md.AppendLine()
        if ($Finding -and @($Finding).Count) {
            $null = $md.AppendLine('## Findings')
            $null = $md.AppendLine('| Pattern | Severity | Target | Source | Fail | OK | /min | Window (UTC) |')
            $null = $md.AppendLine('|---|---|---|---|---|---|---|---|')
            foreach ($f in $Finding) {
                $null = $md.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} | {6:N1} | {7} → {8} |' -f
                    $f.Pattern, $f.Severity, $f.TargetAccount, $f.SourceIp, $f.FailureCount, $f.SuccessCount,
                    $f.AttemptsPerMinute, (& $fmt $f.FirstSeenUtc), (& $fmt $f.LastSeenUtc)))
            }
            $null = $md.AppendLine()
        }
        if ($Event -and @($Event).Count) {
            $null = $md.AppendLine('## Events by ID')
            $null = $md.AppendLine('| ID | Name | Count | First (UTC) | Last (UTC) |')
            $null = $md.AppendLine('|---|---|---|---|---|')
            foreach ($g in ($Event | Group-Object EventId | Sort-Object Count -Descending)) {
                $null = $md.AppendLine(('| {0} | {1} | {2} | {3} | {4} |' -f $g.Name, $g.Group[0].EventName, $g.Count,
                    (& $fmt ($g.Group | Measure-Object TimeUtc -Minimum).Minimum),
                    (& $fmt ($g.Group | Measure-Object TimeUtc -Maximum).Maximum)))
            }
            $null = $md.AppendLine()
            $null = $md.AppendLine("Total events: **$(@($Event).Count)** — full detail in ``events.csv`` / ``events.json``.")
            $null = $md.AppendLine()
        }
        if ($Coverage -and @($Coverage).Count) {
            $null = $md.AppendLine('## Log coverage')
            foreach ($c in $Coverage) {
                $null = $md.AppendLine(('- ``{0}`` @ {1}: enabled={2}, oldest={3}, newest={4}, used={5:N0}%, risk={6}{7}' -f
                    $c.LogName, $c.Computer, $c.IsEnabled, (& $fmt $c.OldestRecordUtc), (& $fmt $c.NewestRecordUtc),
                    $c.UsedPercent, $c.Risk, ($c.Warning ? " — $($c.Warning)" : '')))
            }
            $null = $md.AppendLine()
        }
        if ($Case.Notes.Count) {
            $null = $md.AppendLine('## Notes')
            foreach ($n in $Case.Notes) { $null = $md.AppendLine("- $n") }
            $null = $md.AppendLine()
        }
        $null = $md.AppendLine('## Evidence integrity')
        $null = $md.AppendLine('Every artifact in this bundle is SHA-256-hashed in `manifest.json`.')
        $null = $md.AppendLine('Verify with: `Get-FileHash <file> -Algorithm SHA256`.')
        $mdText = $md.ToString()
        & $writeArtifact 'report.md' { param($p) Set-Content -LiteralPath $p -Value $mdText -Encoding utf8NoBOM } 'Markdown investigation summary'
    }

    # ---- case metadata + manifest (manifest LAST: hashes everything above) -----------
    $caseObj = [pscustomobject]@{
        CaseId = $Case.CaseId; Title = $Case.Title; Description = $Case.Description
        Operator = $Case.Operator; CreatedUtc = $Case.CreatedUtc.ToString('o')
        SubjectIps = $Case.SubjectIps; ScopeHosts = $Case.ScopeHosts
        Notes = @($Case.Notes)
    }
    & $writeArtifact 'case.json' { param($p) $caseObj | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $p -Encoding utf8NoBOM } 'Case metadata'

    if ($PSCmdlet.ShouldProcess((Join-Path $caseDir 'manifest.json'), 'Write evidence manifest')) {
        $manifest = [ordered]@{
            caseId       = $Case.CaseId
            title        = $Case.Title
            operator     = $Case.Operator
            subjectIps   = $Case.SubjectIps
            generatedUtc = [datetime]::UtcNow.ToString('o')
            collector    = [ordered]@{
                host           = $env:COMPUTERNAME ?? (hostname)
                user           = $env:USERNAME ?? $env:USER
                tool           = 'WinSecHunter'
                toolVersion    = $script:WinSecModuleVersion
                catalogVersion = (Get-WinSecResource).Version
                psVersion      = $PSVersionTable.PSVersion.ToString()
                os             = $IsWindows ? [System.Environment]::OSVersion.VersionString : 'non-Windows (analysis only)'
            }
            hashAlgorithm = 'SHA256'
            artifacts     = [ordered]@{}
        }
        foreach ($rel in ($Case.Evidence.Keys | Sort-Object)) {
            if ($rel -like '*/manifest.json') { continue }
            $manifest.artifacts[$rel] = $Case.Evidence[$rel]
        }
        $manifestPath = Join-Path $caseDir 'manifest.json'
        $manifest | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
        $written.Add($manifestPath)
    }

    Write-Information ("WinSecHunter bundle written to {0} ({1} files, manifest: {2})" -f
        $caseDir, $written.Count, (Join-Path $caseDir 'manifest.json')) -InformationAction Continue

    if ($PassThru) { return $Case }
}
