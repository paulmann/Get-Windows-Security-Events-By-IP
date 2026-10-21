#Requires -Version 7.6
function Resolve-WinSecIpAttribution {
    <#
    .SYNOPSIS
        Enriches attacker IPs: reverse DNS, RFC classification, optional
        threat-intel lookups (AbuseIPDB / AlienVault OTX / ip-api) with caching.

    .DESCRIPTION
        Offline-first by design: PTR resolution and private/loopback/link-local
        classification never touch third-party services. Threat intelligence
        is opt-in via -Provider (or the ThreatIntelProvider configuration
        option) because sending internal IPs to public services can leak
        investigation context.

        API keys are read from ENVIRONMENT VARIABLES only (names configurable:
        AbuseIpDbKeyEnvVar → ABUSEIPDB_KEY, OtxKeyEnvVar → OTX_API_KEY) — never
        from parameters, so they cannot leak into shell history, transcripts or
        logs. Results are cached per IP for AttributionCacheHours (default 72)
        under the WinSecHunter config directory; -NoCache bypasses the cache.

        ip-api.com free tier is HTTP-only — it is offered for lab use and
        clearly marked in the Verdict.

    .EXAMPLE
        Resolve-WinSecIpAttribution -IpAddress 203.0.113.7

    .EXAMPLE
        $env:ABUSEIPDB_KEY = '...'
        '203.0.113.7', '198.51.100.23' | Resolve-WinSecIpAttribution -Provider AbuseIPDB

    .EXAMPLE
        Get-WinSecEventByIp 203.0.113.7 | Select-Object -Expand SourceIp -Unique |
            Resolve-WinSecIpAttribution -Provider OTX

    .OUTPUTS
        WinSecIpAttribution
    #>
    [CmdletBinding()]
    [OutputType('WinSecIpAttribution')]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string[]] $IpAddress,

        [ValidateSet('None', 'AbuseIPDB', 'OTX', 'IpApi', 'Config')]
        [string] $Provider = 'Config',

        [switch] $NoCache,
        [ValidateRange(0, 8760)] [int] $CacheHours
    )

    begin {
        $config = Get-WinSecConfig
        if ($Provider -eq 'Config') { $Provider = [string]$config.ThreatIntelProvider }
        if (-not $PSBoundParameters.ContainsKey('CacheHours')) { $CacheHours = [int]$config.AttributionCacheHours }
        $warnedKey = $false
    }

    process {
        foreach ($raw in $IpAddress) {
            if (-not (Test-WinSecIpAddress -Value $raw)) {
                Write-Warning "Not a valid IP address: '$raw'"
                continue
            }
            $canonical = ConvertTo-WinSecCanonicalIp -Value $raw

            # ---- cache ---------------------------------------------------------
            $cacheFile = Get-WinSecCacheFile -IpAddress $canonical
            if (-not $NoCache -and $CacheHours -gt 0 -and (Test-Path -LiteralPath $cacheFile)) {
                $age = [datetime]::UtcNow - (Get-Item -LiteralPath $cacheFile).LastWriteTimeUtc
                if ($age.TotalHours -lt $CacheHours) {
                    try {
                        $cached = Get-Content -Raw -LiteralPath $cacheFile | ConvertFrom-Json
                        $a = [WinSecIpAttribution]::new()
                        foreach ($p in $a.PSObject.Properties) {
                            if ($null -ne $cached.PSObject.Properties[$p.Name]) {
                                $v = $cached.($p.Name)
                                if ($null -ne $v) {
                                    try { $p.Value = $v } catch { Write-Verbose "Cache field '$($p.Name)' skipped: $($_.Exception.Message)" }
                                }
                            }
                        }
                        $a.FromCache = $true
                        $a
                        continue
                    }
                    catch { Write-Verbose "Attribution cache corrupt for ${canonical}: $($_.Exception.Message)" }
                }
            }

            # ---- base attribution (always offline-safe) -------------------------
            $a = [WinSecIpAttribution]::new()
            $a.IpAddress  = $canonical
            $a.QueriedUtc = [datetime]::UtcNow
            $cls = Get-WinSecIpClassification -IpAddress $canonical
            $a.Version     = $cls.Version
            $a.IsPrivate   = $cls.IsPrivate
            $a.IsLoopback  = $cls.IsLoopback
            $a.IsLinkLocal = $cls.IsLinkLocal
            $a.Categories  = @()
            $a.Raw         = @{}

            # PTR (bounded, cross-platform)
            try {
                $cts = [System.Threading.CancellationTokenSource]::new([timespan]::FromSeconds(4))
                $task = [System.Net.Dns]::GetHostEntryAsync([System.Net.IPAddress]::Parse($canonical))
                if ($task.Wait($cts.Token)) {
                    $a.PtrHostname = $task.Result.HostName
                    $a.PtrResolved = $true
                }
            }
            catch { $a.PtrResolved = $false }

            # ---- provider lookups ------------------------------------------------
            if ($Provider -ne 'None' -and -not $cls.IsPrivate) {
                $headers = @{ 'User-Agent' = "WinSecHunter/2.0 (incident-response)" }
                try {
                    switch ($Provider) {
                        'AbuseIPDB' {
                            $key = (Get-Item "env:$($config.AbuseIpDbKeyEnvVar)" -ErrorAction SilentlyContinue).Value
                            if (-not $key) {
                                if (-not $warnedKey) { Write-Warning "AbuseIPDB key not found in env:$($config.AbuseIpDbKeyEnvVar). Skipping provider lookups."; $warnedKey = $true }
                            }
                            else {
                                $headers['Key'] = $key
                                $headers['Accept'] = 'application/json'
                                $resp = Invoke-RestMethod -Method Get -TimeoutSec 15 -Headers $headers `
                                    -Uri "https://api.abuseipdb.com/api/v2/check?ipAddress=$([uri]::EscapeDataString($canonical))&maxAgeInDays=90"
                                $d = $resp.PSObject.Properties['data'] ? $resp.data : $null
                                if (-not $d) { throw [System.InvalidOperationException]::new('AbuseIPDB response has no data node (invalid key?).') }
                                $a.Provider = 'AbuseIPDB'
                                $a.Country = $d.countryName; $a.CountryCode = $d.countryCode
                                $a.AsnOrganization = ($d.isp, $d.domain | Where-Object { $_ }) -join ' / '
                                $a.AbuseConfidenceScore = [int]$d.abuseConfidenceScore
                                $a.TotalReports = [int]$d.totalReports
                                $a.Categories = @($d.reports | ForEach-Object { $_.categories } | Select-Object -Unique | Select-Object -First 10)
                                $a.Raw = @{ check = $d }
                            }
                        }
                        'OTX' {
                            $key = (Get-Item "env:$($config.OtxKeyEnvVar)" -ErrorAction SilentlyContinue).Value
                            if (-not $key) {
                                if (-not $warnedKey) { Write-Warning "OTX key not found in env:$($config.OtxKeyEnvVar). Skipping provider lookups."; $warnedKey = $true }
                            }
                            else {
                                $headers['X-OTX-API-KEY'] = $key
                                $kind = ($cls.Version -eq 4) ? 'IPv4' : 'IPv6'
                                $resp = Invoke-RestMethod -Method Get -TimeoutSec 15 -Headers $headers `
                                    -Uri "https://otx.alienvault.com/api/v1/indicators/$kind/$([uri]::EscapeDataString($canonical))/general"
                                $a.Provider = 'OTX'
                                $a.Country = $resp.PSObject.Properties['country_name'] ? [string]$resp.country_name : $null
                                $a.CountryCode = $resp.PSObject.Properties['country_code'] ? [string]$resp.country_code : $null
                                $a.Region = $resp.PSObject.Properties['region'] ? [string]$resp.region : $null
                                $a.City = $resp.PSObject.Properties['city'] ? [string]$resp.city : $null
                                $asnRaw = $resp.PSObject.Properties['asn'] ? [string]$resp.asn : ''
                                if ($asnRaw -match '(\d+)') { $a.Asn = [int]$Matches[1] }
                                $a.AsnOrganization = $asnRaw
                                $pulses = $resp.PSObject.Properties['pulse_info'] ? $resp.pulse_info : $null
                                $a.TotalReports = ($pulses -and $pulses.PSObject.Properties['count']) ? [int]$pulses.count : 0
                                $a.Categories = @($pulses -and $pulses.PSObject.Properties['pulses'] ? ($pulses.pulses | ForEach-Object { $_.name } | Select-Object -First 10) : @())
                                $a.Raw = @{ general = $resp }
                            }
                        }
                        'IpApi' {
                            $a.Provider = 'IpApi'
                            $fields = 'status,country,countryCode,regionName,city,as,asn,isp,org,hosting,proxy,query'
                            $resp = Invoke-RestMethod -Method Get -TimeoutSec 15 `
                                -Uri "http://ip-api.com/json/$([uri]::EscapeDataString($canonical))?fields=$fields"
                            if ($resp.status -eq 'success') {
                                $a.Country = $resp.country; $a.CountryCode = $resp.countryCode
                                $a.Region = $resp.regionName; $a.City = $resp.city
                                if ($resp.asn) { $a.Asn = [int]$resp.asn }
                                $a.AsnOrganization = ($resp.isp, $resp.org | Where-Object { $_ } | Select-Object -Unique) -join ' / '
                                if ($resp.hosting) { $a.Categories += 'hosting-provider' }
                                if ($resp.proxy)   { $a.Categories += 'public-proxy' }
                                $a.Raw = @{ ipapi = $resp }
                            }
                        }
                    }
                }
                catch {
                    Write-Warning ("Threat-intel lookup ({0}) failed for {1}: {2}" -f $Provider, $canonical, $_.Exception.Message)
                }
            }
            elseif ($Provider -ne 'None' -and $cls.IsPrivate) {
                Write-Verbose "$canonical is private — public threat intel skipped by design."
            }

            # ---- verdict synthesis -------------------------------------------------
            $a.Verdict = if ($a.IsLoopback) { 'Loopback address — local-only traffic.' }
            elseif ($a.IsLinkLocal) { 'Link-local address (APIPA/169.254 or fe80::) — check DHCP health.' }
            elseif ($a.IsPrivate) { 'RFC1918/private source — internal actor, compromised internal host, or NAT/pivot; correlate with asset inventory and upstream NAT logs.' }
            elseif ($a.Provider -eq 'AbuseIPDB' -and $a.AbuseConfidenceScore -ge 75) { 'Known abusive internet source (AbuseIPDB confidence {0}%, {1} reports) — treat as hostile.' -f $a.AbuseConfidenceScore, $a.TotalReports }
            elseif ($a.Provider -eq 'AbuseIPDB' -and $a.AbuseConfidenceScore -ge 25) { 'Reported abusive (AbuseIPDB confidence {0}%) — corroborate with internal evidence.' -f $a.AbuseConfidenceScore }
            elseif ($a.Provider -eq 'OTX' -and $a.TotalReports -gt 0) { 'Present in {0} OTX pulse(s) — corroborate before blocking.' -f $a.TotalReports }
            elseif ($a.Provider -eq 'IpApi' -and $a.Categories -contains 'public-proxy') { 'Public proxy — attribution beyond the proxy requires provider logs.' }
            elseif ($a.Provider -ne 'None' -and $a.Provider) { 'Public internet source, no abuse reports on file at query time (absence of reports ≠ benign).' }
            else { 'No external enrichment performed (offline-first). Use -Provider for threat intel.' }

            if (-not $NoCache -and $CacheHours -gt 0) {
                try {
                    $payload = $a | Select-Object IpAddress, Version, IsPrivate, IsLoopback, IsLinkLocal, PtrHostname, PtrResolved,
                        Provider, QueriedUtc, Country, CountryCode, Region, City, Asn, AsnOrganization,
                        AbuseConfidenceScore, TotalReports, Categories, Verdict
                    $payload | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $cacheFile -Encoding utf8NoBOM
                }
                catch { Write-Verbose "Could not write attribution cache: $($_.Exception.Message)" }
            }

            $a
        }
    }
}
