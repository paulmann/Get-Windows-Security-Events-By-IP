#Requires -Version 7.6
function Get-WinSecEventByIp {
    <#
    .SYNOPSIS
        Collects Windows security events that reference an attacker IP address
        (IPv4/IPv6/CIDR) from local logs, remote hosts or offline EVTX files.

    .DESCRIPTION
        The core evidence-collection cmdlet of WinSecHunter, built for incident
        responders answering "everything this IP did to us".

        Data sources (per target): Security log, System log, RDP operational
        logs (RemoteConnectionManager + LocalSessionManager), Windows Firewall
        operational log and — when present — Sysmon. The event set is driven by
        a built-in catalog with MITRE ATT&CK mapping, selected via -Profile,
        -Category or explicit -EventId.

        Query strategy (three layers):
          1. Server-side pushdown — an Event Log XPath QueryList restricts by
             channel, event IDs and a UTC time window; for a single exact IP
             the query is additionally gated on IP equality (including
             IPv4-mapped IPv6 renderings and the UserData/EventXML/Address
             layout of the RDP logs) for maximum speed on huge logs.
          2. Client-side verification — every returned record is matched with
             a boundary-aware regex so mapped/compressed IPv6 variants and
             message-embedded addresses are never missed.
          3. -DeepScan — disables the server-side IP gate entirely, sweeping
             every cataloged event in the time window and matching the IP
             anywhere in the record XML (finds IPs inside command lines, UNC
             paths, task XML, etc. at the cost of throughput).

        Remote execution uses WinRM (Invoke-Command) with parallel fan-out and
        per-host retry; -CimSession is honored for pre-built sessions. EVTX
        files are analyzed offline via -Path. Results are normalized, decoded
        (NTSTATUS/Kerberos/%% codes), classified, deduplicated and sorted by
        UTC time.

        Every result carries BOTH timestamps: TimeCreated (source-local) and
        TimeUtc (authoritative). Analysis functions sort on TimeUtc so
        multi-timezone estates correlate correctly.

    .PARAMETER IpAddress
        One or more IPv4/IPv6 addresses or CIDR ranges (e.g. '203.0.113.7',
        '2001:db8::/64', '10.0.0.0/24'). CIDR members are matched client-side.

    .PARAMETER ComputerName
        Remote hosts to sweep over WinRM. Requires WinRM connectivity and
        (normally) administrator credentials on the target.

    .PARAMETER Credential
        PSCredential for remote targets.

    .PARAMETER CimSession
        Pre-built CIM sessions (New-CimSession) as an alternative transport.

    .PARAMETER Path
        Offline EVTX files to analyze. Wildcards allowed.

    .PARAMETER StartTime
        Start of the investigation window (interpreted in the COLLECTING
        machine's local time zone, converted to UTC for the query).

    .PARAMETER EndTime
        End of the investigation window. Defaults to now.

    .PARAMETER LastHours
        Convenience window: last N hours (mutually exclusive with StartTime).

    .PARAMETER LastDays
        Convenience window: last N days.

    .PARAMETER Profile
        Catalog profile(s) selecting which events to hunt:
        IncidentResponse (default), FailedAuth, BruteForce, Rdp, Lateral,
        AccountManagement, Kerberos, Firewall, DefenseEvasion, Persistence,
        Sysmon, ObjectAccess, Critical, All. See Get-WinSecEventCatalog.

    .PARAMETER Category
        Additional WinSecEventCategory values to include (union with profiles).

    .PARAMETER EventId
        Explicit event IDs to include (union). Unknown IDs default to the
        Security log unless -LogName restricts otherwise.

    .PARAMETER LogName
        Restrict the sweep to these channels. Aliases: RDP, TerminalServices,
        Firewall, Sysmon.

    .PARAMETER MaxEvents
        Per-log record cap passed to each channel query (default from
        configuration, 5000). Client-side filtering may yield fewer matches.
        Because channels are queried independently, the total can reach
        MaxEvents × number of channels. 0 means unlimited.

    .PARAMETER DeepScan
        Drop the server-side IP gate and regex-match the IP anywhere in every
        cataloged event of the window. Slower; catches IPs embedded in command
        lines, UNC paths, firewall rule XML, scheduled task definitions, etc.

    .PARAMETER NoServerSideIpFilter
        Keep catalog IDs/time pushdown but skip only the exact-IP gate (middle
        ground between default and -DeepScan; required semantics for CIDR are
        applied automatically).

    .PARAMETER IncludeMessage
        Populate the Message property (renders event messages on the source;
        slower remotely). Default can be set via Set-WinSecHunterOption.

    .PARAMETER IncludeRawXml
        Populate the Xml property with the raw event XML (useful for evidence
        exports; increases memory).

    .PARAMETER ThrottleLimit
        Maximum parallel remote hosts (default from configuration, 8).

    .PARAMETER PassHostStatus
        Also emit WinSecHostResult objects (one per target: status, event
        count, duration, error) at the start of the output stream so sweeps
        over many hosts explain every machine — including unreachable ones
        and channels that are simply not installed (status Skipped).

    .PARAMETER RetryCount
        Per-host retry attempts on transport failure (default 1).

    .EXAMPLE
        Get-WinSecEventByIp -IpAddress 203.0.113.7

        Full incident-response sweep of the local machine for the last
        (default) window using the IncidentResponse profile.

    .EXAMPLE
        Get-WinSecEventByIp 203.0.113.7 -ComputerName SRV1, SRV2, DC01 -Credential $cred -LastDays 3 -PassHostStatus

        Parallel 3-day sweep of three hosts with per-host status reporting.

    .EXAMPLE
        Get-WinSecEventByIp '10.10.0.0/24' -Path 'C:\Cases\DC01-Security.evtx' -DeepScan -IncludeRawXml

        Offline deep sweep of an acquired EVTX for an entire internal range.

    .EXAMPLE
        Get-WinSecEventByIp 203.0.113.7 -Profile BruteForce,Rdp -LastHours 12 |
            Test-WinSecBruteForce

        Focused 12-hour brute-force/RDP hunt piped straight into detection.

    .OUTPUTS
        WinSecEvent. With -PassHostStatus, WinSecHostResult objects first.

    .NOTES
        Windows-only (Get-WinEvent / WinRM). Reading the Security log normally
        requires elevation; run Test-WinSecAuditPolicy and Get-WinSecLogCoverage
        to understand what the logs CAN prove before concluding "no activity".
    #>
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    [OutputType('WinSecEvent')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [Alias('Ip', 'Cidr')]
        [ValidateNotNullOrEmpty()]
        [string[]] $IpAddress,

        [Parameter(ParameterSetName = 'Remote')]
        [ValidateNotNullOrEmpty()]
        [string[]] $ComputerName,

        [Parameter(ParameterSetName = 'Remote')]
        [object[]] $CimSession,

        [Parameter(ParameterSetName = 'Remote')]
        [pscredential] $Credential,

        [Parameter(ParameterSetName = 'Remote')]
        [ValidateSet('Basic', 'Credssp', 'Default', 'Digest', 'Negotiate', 'NegotiateWithImplicitCredential')]
        [string] $Authentication = 'Default',

        [Parameter(ParameterSetName = 'Remote')]
        [object] $SessionOption,

        [Parameter(ParameterSetName = 'Remote')]
        [ValidateRange(1, 256)]
        [int] $ThrottleLimit,

        [Parameter(ParameterSetName = 'File', Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]] $Path,

        [datetime] $StartTime,
        [datetime] $EndTime,
        [ValidateRange(1, 878400)] [int] $LastHours,
        [ValidateRange(1, 36600)]  [int] $LastDays,

        [ValidateNotNullOrEmpty()]
        [string[]] $Profile,

        [string[]] $Category,
        [int[]] $EventId,
        [string[]] $LogName,

        [ValidateRange(0, [int]::MaxValue)]
        [int] $MaxEvents,

        [switch] $DeepScan,
        [switch] $NoServerSideIpFilter,
        [switch] $IncludeMessage,
        [switch] $IncludeRawXml,
        [switch] $PassHostStatus,

        [ValidateRange(0, 5)]
        [int] $RetryCount = 1
    )

    begin {
        $config = Get-WinSecConfig
        $collectedIps = [System.Collections.Generic.List[string]]::new()
    }

    process {
        $collectedIps.AddRange([string[]]$IpAddress)
    }

    end {
        if (-not $IsWindows) {
            $err = [System.PlatformNotSupportedException]::new(
                'Get-WinSecEventByIp requires Windows (Get-WinEvent / WinRM). Analyze acquired EVTX files on a Windows host, or use the pure analysis cmdlets (Get-WinSecIpTimeline, Test-WinSecBruteForce, ...) on exported data anywhere.')
            $PSCmdlet.ThrowTerminatingError((New-Object System.Management.Automation.ErrorRecord(
                $err, 'WinSecNotWindows', [System.Management.Automation.ErrorCategory]::NotImplemented, $null)))
        }

        # ---- Resolve effective options ---------------------------------------
        if (-not $PSBoundParameters.ContainsKey('MaxEvents'))    { $MaxEvents    = [int]$config.DefaultMaxEvents }
        if (-not $PSBoundParameters.ContainsKey('ThrottleLimit')) { $ThrottleLimit = [int]$config.DefaultThrottleLimit }
        if ($config.DeepScan -and -not $DeepScan)                 { $DeepScan = [switch]::new($true) }
        if ($config.IncludeMessage -and -not $IncludeMessage)     { $IncludeMessage = [switch]::new($true) }
        if (-not $Profile -and -not $Category -and -not $EventId)  { $Profile = @([string]$config.DefaultProfile) }

        # ---- Validate & normalize every IP/CIDR -------------------------------
        $ipSpecs = foreach ($raw in ($collectedIps | Select-Object -Unique)) {
            $value = $raw.Trim()
            if (-not (Test-WinSecIpAddress -Value $value -AllowCidr)) {
                throw [ArgumentException]::new(
                    "Invalid IP address or CIDR range: '$value'. Expected forms: 203.0.113.7, 2001:db8::42, 10.0.0.0/24, 2001:db8::/64.")
            }
            $isCidr = $value.Contains('/')
            $canonical = ConvertTo-WinSecCanonicalIp -Value $value
            [pscustomobject]@{
                Input     = $value
                Canonical = $isCidr ? ($canonical + '/' + ($value -split '/')[1]) : $canonical
                IsCidr    = $isCidr
                Regex     = $isCidr ? $null : (Get-WinSecIpMatchRegex -IpAddress $canonical)
                Variants  = $isCidr ? $null : @(Get-WinSecIpVariant -IpAddress $canonical)
            }
        }
        $ipSpecs = @($ipSpecs)

        # ---- Time window -------------------------------------------------------
        if (($LastHours -or $LastDays) -and ($PSBoundParameters.ContainsKey('StartTime') -or $PSBoundParameters.ContainsKey('EndTime'))) {
            throw [ArgumentException]::new('-LastHours/-LastDays cannot be combined with -StartTime/-EndTime.')
        }
        $nowUtc = [datetime]::UtcNow
        $startUtc = $null; $endUtc = $null
        if ($LastDays)       { $startUtc = $nowUtc.AddDays(-$LastDays) }
        elseif ($LastHours)  { $startUtc = $nowUtc.AddHours(-$LastHours) }
        elseif ($PSBoundParameters.ContainsKey('StartTime')) { $startUtc = $StartTime.ToUniversalTime() }
        if ($PSBoundParameters.ContainsKey('EndTime')) { $endUtc = $EndTime.ToUniversalTime() }
        if ($startUtc -and $endUtc -and $endUtc -le $startUtc) {
            throw [ArgumentException]::new('-EndTime must be after -StartTime.')
        }

        # ---- Event scope ---------------------------------------------------------
        $scope = Get-WinSecEventIdsByScope -Profile $Profile -Category $Category -EventId $EventId -LogName $LogName
        if ($scope.LogEventIds.Count -eq 0) {
            throw [ArgumentException]::new('The selected profile/category/log combination matched no events. Check Get-WinSecEventCatalog -ListProfiles.')
        }
        Write-Verbose ("WinSecHunter scope: {0} log(s), {1} event id(s); window {2} → {3}; IPs: {4}" -f
            $scope.LogEventIds.Count,
            (($scope.LogEventIds.Values | ForEach-Object { $_.Count }) | Measure-Object -Sum).Sum,
            ($startUtc ? $startUtc.ToString('u') : '(log start)'),
            ($endUtc ? $endUtc.ToString('u') : 'now'),
            (($ipSpecs | ForEach-Object Canonical) -join ', '))

        # ---- Server-side IP gate: only for a single exact IP ---------------------
        $ipVariants = $null
        $singleExact = ($ipSpecs.Count -eq 1 -and -not $ipSpecs[0].IsCidr)
        if ($singleExact -and -not $DeepScan -and -not $NoServerSideIpFilter) {
            $ipVariants = $ipSpecs[0].Variants
        }
        $query = New-WinSecEventQuery -LogEventIds $scope.LogEventIds -StartTimeUtc ($startUtc ?? [datetime]::MinValue) -EndTimeUtc ($endUtc ?? [datetime]::MinValue) -IpExactVariants $ipVariants

        # ---- Execute ------------------------------------------------------------
        $invokeParams = @{
            Query          = $query
            MaxEvents      = $MaxEvents
            IncludeMessage = $IncludeMessage
            RetryCount     = $RetryCount
        }
        switch ($PSCmdlet.ParameterSetName) {
            'Remote' {
                $invokeParams.ComputerName  = $ComputerName
                $invokeParams.CimSession    = $CimSession
                $invokeParams.Credential    = $Credential
                $invokeParams.Authentication= $Authentication
                $invokeParams.SessionOption = $SessionOption
                $invokeParams.ThrottleLimit = $ThrottleLimit
            }
            'File' {
                $invokeParams.Path          = $Path
                $invokeParams.LogEventIds   = $scope.LogEventIds
                $invokeParams.StartTimeUtc  = $startUtc ?? [datetime]::MinValue
                $invokeParams.EndTimeUtc    = $endUtc ?? [datetime]::MinValue
                $invokeParams.IpExactVariants = $ipVariants
            }
        }
        $result = Invoke-WinSecEventQuery @invokeParams

        # ---- Host status reporting ----------------------------------------------
        # Statuses are emitted BEFORE any diagnostics: -PassHostStatus is the
        # documented way to learn what happened to every target, so it must
        # never be lost behind an error record. Channel-level problems are
        # warnings, not terminating errors (the module sets EAP=Stop).
        if ($PassHostStatus) { $result.HostResults }

        $failed = @($result.HostResults | Where-Object Status -eq 'Failed')
        foreach ($hr in $failed) {
            Write-Warning ("Target '{0}' failed: {1}" -f $hr.Computer, $hr.ErrorMessage)
        }
        $skippedLogs = @($result.HostResults | ForEach-Object { $_.LogDetails } | Where-Object { $_ -and $_.Status -eq 'Skipped' })
        if ($skippedLogs.Count -gt 0) {
            Write-Verbose ("Unavailable channel(s): {0}" -f (($skippedLogs | ForEach-Object { $_.LogName } | Sort-Object -Unique) -join ', '))
        }

        # ---- Parse + match + dedup -----------------------------------------------
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        $events = [System.Collections.Generic.List[WinSecEvent]]::new()

        foreach ($payload in $result.Raw) {
            $xmlText = [string]$payload.Xml

            # Cheap pre-filter: does ANY investigated IP appear in this record?
            $matched = $null; $matchedOn = ''
            foreach ($spec in $ipSpecs) {
                if ($spec.IsCidr) {
                    # CIDR membership is decided structurally after parsing.
                    continue
                }
                if ($spec.Regex.IsMatch($xmlText)) { $matched = $spec; $matchedOn = 'Xml'; break }
            }
            $needsCidrCheck = ($null -eq $matched) -and @($ipSpecs | Where-Object IsCidr).Count -gt 0

            if (-not $matched -and -not $needsCidrCheck) { continue }

            try {
                $e = ConvertTo-WinSecEvent -Record $payload -MatchedIp ($matched ? $matched.Canonical : '') -MatchedOn $matchedOn -IncludeMessage:$IncludeMessage -IncludeRawXml:$IncludeRawXml
            }
            catch {
                Write-Warning ("Skipping unparseable record (EventId {0}): {1}" -f $payload.Xml.Substring(0, [Math]::Min(80, $payload.Xml.Length)), $_.Exception.Message)
                continue
            }

            if ($needsCidrCheck) {
                foreach ($spec in ($ipSpecs | Where-Object IsCidr)) {
                    $candidates = @($e.SourceIp, $e.DestinationIp) + @($e.Data.Values | Where-Object { $_ -and $_ -match ':' -or $_ -match '^\d+\.\d+\.\d+\.\d+$' })
                    foreach ($cand in $candidates) {
                        if ($cand -and (Test-WinSecIpInCidr -IpAddress $cand -Cidr $spec.Canonical)) {
                            $matched = $spec; $e.MatchedIp = $spec.Canonical; $e.MatchedOn = 'EventData'; break
                        }
                    }
                    if ($matched) { break }
                }
                if (-not $matched) { continue }
            }
            elseif ($matchedOn -eq 'Xml') {
                # Refine where the match actually came from.
                $structured = @($e.SourceIp, $e.DestinationIp)
                if ($structured -contains $matched.Canonical -or
                    ($structured | Where-Object { $_ } | ForEach-Object { ConvertTo-WinSecCanonicalIp -Value $_ -ErrorAction SilentlyContinue }) -contains $matched.Canonical) {
                    $e.MatchedOn = $e.Data.Count -gt 0 ? 'EventData' : 'Xml'
                }
                elseif ($IncludeMessage -and $e.Message -and $matched.Regex.IsMatch($e.Message)) {
                    $e.MatchedOn = 'Message'
                }
                $e.MatchedIp = $matched.Canonical
            }

            $key = $e.GetDedupKey() + '|' + $e.MatchedIp
            if ($seen.Add($key)) { $events.Add($e) }
        }

        # ---- Diagnostics -----------------------------------------------------------
        if ($events.Count -eq 0) {
            $windowHint = $startUtc ? "since $($startUtc.ToString('u'))" : 'across the entire retained log'
            Write-Warning ("No events referencing {0} found {1} on {2} target(s). Before concluding 'no activity': (1) widen -LastDays/-Profile or try -DeepScan; (2) run Get-WinSecLogCoverage to confirm the window is actually retained; (3) run Test-WinSecAuditPolicy to confirm the events would even be audited." -f
                (($ipSpecs | ForEach-Object Input) -join ', '), $windowHint, @($result.HostResults).Count)
        }
        else {
            Write-Verbose ("WinSecHunter: {0} matched event(s) after client-side verification and dedup." -f $events.Count)
        }

        $events | Sort-Object TimeUtc
    }
}
