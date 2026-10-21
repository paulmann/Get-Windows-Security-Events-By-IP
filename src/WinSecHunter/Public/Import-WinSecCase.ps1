#Requires -Version 7.6
#Requires -PSEdition Core
function Import-WinSecCase {
    <#
    .SYNOPSIS
        Reopens an exported investigation bundle so analysis and reporting can
        continue in a new session, on another workstation, or after a reboot.

    .DESCRIPTION
        Reads manifest.json, case.json and every artifact present in the bundle
        and rebuilds the objects:

          Events       rehydrated WinSecEvent instances from events.json (or
                       events.clixml when JSON is absent)
          Findings     Test-WinSecBruteForce findings
          Sessions     logon sessions (string-typed CSV rows)
          Coverage     log coverage rows
          Attribution  enrichment results
          Timeline     activity buckets

        The case object is restored with its id, title, operator, notes and the
        evidence table from the manifest, so a follow-up report references the
        same chain of custody instead of inventing a new case.

        Nothing is written; the cmdlet is read-only and safe on evidence media.

    .PARAMETER Path
        Bundle directory (containing manifest.json) or the manifest path itself.

    .PARAMETER SkipEvents
        Skip event rehydration for very large bundles; other artifacts are still
        loaded.

    .EXAMPLE
        $b = Import-WinSecCase .\WSC-20261011-AB12CD34
        $b.Events | Test-WinSecBruteForce -WindowMinutes 30
        New-WinSecIncidentReport -Case $b.Case -Event $b.Events -Coverage $b.Coverage -PassThru

    .EXAMPLE
        $b = Import-WinSecCase .\bundle\manifest.json -SkipEvents
        Test-WinSecEvidenceIntegrity -Path $b.BundlePath -Summary

    .OUTPUTS
        PSCustomObject: BundlePath, ManifestPath, Case, Events, Findings,
        Sessions, Coverage, Attribution, Timeline, Manifest.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [switch] $SkipEvents
    )

    process {
        $manifestPath = if (Test-Path -LiteralPath $Path -PathType Container) { Join-Path $Path 'manifest.json' }
                        elseif ((Split-Path -Leaf $Path) -eq 'manifest.json') { $Path }
                        else { throw [ArgumentException]::new("Path must be a bundle directory or manifest.json: '$Path'.") }

        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new("Evidence manifest not found: '$manifestPath'.", $manifestPath)
        }

        $caseDir = Split-Path -Parent $manifestPath
        $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -AsHashtable

        $readJson = {
            param([string]$Name)
            $p = Join-Path $caseDir $Name
            if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return $null }
            try { Get-Content -Raw -LiteralPath $p | ConvertFrom-Json } catch { Write-Warning "Cannot parse ${Name}: $($_.Exception.Message)"; return $null }
        }
        $readCsv = {
            param([string]$Name)
            $p = Join-Path $caseDir $Name
            if (-not (Test-Path -LiteralPath $p -PathType Leaf)) { return @() }
            try { return @(Import-Csv -LiteralPath $p) } catch { Write-Warning "Cannot parse ${Name}: $($_.Exception.Message)"; return @() }
        }

        $meta = & $readJson 'case.json'

        # ---- case object ------------------------------------------------------
        $case = [WinSecCase]::new()
        if ($meta) {
            if ($meta.CaseId)   { $case.CaseId = [string]$meta.CaseId }
            if ($meta.Title)    { $case.Title = [string]$meta.Title }
            if ($meta.Description) { $case.Description = [string]$meta.Description }
            if ($meta.Operator) { $case.Operator = [string]$meta.Operator }
            if ($meta.CreatedUtc) {
                try { $case.CreatedUtc = [datetime]::Parse([string]$meta.CreatedUtc, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) } catch { Write-Verbose ("case.json: unparsable CreatedUtc '{0}': {1}" -f $meta.CreatedUtc, $_.Exception.Message) }
            }
            if ($meta.SubjectIps) { $case.SubjectIps = [string[]]@($meta.SubjectIps) }
            if ($meta.ScopeHosts) { $case.ScopeHosts = [string[]]@($meta.ScopeHosts) }
            foreach ($n in @($meta.Notes)) { if ($n) { $case.Notes.Add([string]$n) } }
        }
        elseif ($manifest['caseId']) { $case.CaseId = [string]$manifest['caseId']; $case.Title = [string]$manifest['title'] }

        if ($manifest['artifacts']) {
            foreach ($rel in @($manifest['artifacts'].Keys)) { $case.RegisterEvidence([string]$rel, [string]$manifest['artifacts'][$rel]['Sha256'], [long]$manifest['artifacts'][$rel]['Bytes'], 'imported') }
        }

        # ---- events -----------------------------------------------------------
        $events = [System.Collections.Generic.List[WinSecEvent]]::new()
        if (-not $SkipEvents) {
            $rawEvents = & $readJson 'events.json'
            if (-not $rawEvents) {
                $clixml = Join-Path $caseDir 'events.clixml'
                if (Test-Path -LiteralPath $clixml) {
                    try { $rawEvents = @(Import-Clixml -LiteralPath $clixml) } catch { Write-Warning "Cannot read events.clixml: $($_.Exception.Message)" }
                }
            }
            foreach ($r in @($rawEvents)) {
                if (-not $r) { continue }
                $has = { param($o, $n) $null -ne $o.PSObject.Properties[$n] }
                $e = [WinSecEvent]::new()
                foreach ($prop in 'Computer', 'LogName', 'ProviderName', 'MatchedIp', 'MatchedOn', 'EventName', 'Description',
                    'TargetAccount', 'SubjectAccount', 'LogonId', 'AuthPackage', 'LogonProcess', 'Workstation',
                    'Status', 'SubStatus', 'StatusCode', 'FailureReason', 'ProcessName', 'ServiceName', 'TaskName',
                    'ObjectName', 'Protocol', 'SourceIp', 'DestinationIp', 'Message', 'Xml') {
                    if ((& $has $r $prop) -and $null -ne $r.$prop) { $e.$prop = [string]$r.$prop }
                }
                foreach ($num in 'RecordId', 'EventId', 'SourcePort', 'DestinationPort') {
                    if ((& $has $r $num) -and $null -ne $r.$num -and "$($r.$num)" -ne '') { $e.$num = [int]$r.$num }
                }
                foreach ($dt in 'TimeCreated', 'TimeUtc') {
                    if ((& $has $r $dt) -and $r.$dt) {
                        try { $e.$dt = [datetime]::Parse([string]$r.$dt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind) } catch { Write-Verbose ("events.json: unparsable {0} '{1}': {2}" -f $dt, $r.$dt, $_.Exception.Message) }
                    }
                }
                foreach ($en in @(
                    @{ Name = 'Category'; Type = [WinSecEventCategory] }
                    @{ Name = 'Outcome'; Type = [WinSecOutcome] }
                    @{ Name = 'Importance'; Type = [WinSecSeverity] }
                    @{ Name = 'Direction'; Type = [WinSecDirection] }
                )) {
                    if (-not (& $has $r $en.Name)) { continue }
                    $val = $r.($en.Name)
                    if ($null -ne $val -and "$val" -ne '') {
                        try { $e.($en.Name) = [System.Enum]::Parse($en.Type, [string]$val, $true) } catch { Write-Verbose ("events.json: unknown {0} value '{1}'" -f $en.Name, $val) }
                    }
                }
                if ((& $has $r 'LogonType') -and $null -ne $r.LogonType -and "$($r.LogonType)" -ne '') {
                    try { $e.LogonType = [WinSecLogonType][int]$r.LogonType } catch { Write-Verbose ("events.json: unknown LogonType '{0}'" -f $r.LogonType) }
                }
                if ((& $has $r 'AttackIds') -and $r.AttackIds) {
                    $e.AttackIds = [string[]]@(([string]$r.AttackIds) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                }
                $e.Data = @{}
                $events.Add($e)
            }
        }

        $findings = @(& $readJson 'findings.json')
        $attribution = @(& $readJson 'attribution.json')
        $sessions = @(& $readCsv 'sessions.csv')
        $coverage = @(& $readCsv 'coverage.csv')
        $timeline = @(& $readCsv 'timeline.csv')

        [pscustomobject]@{
            BundlePath   = $caseDir
            ManifestPath = $manifestPath
            Case         = $case
            Events       = $events.ToArray()
            Findings     = $findings
            Sessions     = $sessions
            Coverage     = $coverage
            Attribution  = $attribution
            Timeline     = $timeline
            Manifest     = $manifest
        }
    }
}

