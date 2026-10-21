#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: persistent configuration
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

<#
    .SYNOPSIS
        Configuration directory (created on demand).
    .DESCRIPTION
        Override with $env:WINSECHUNTER_CONFIG_DIR (used by tests and by
        responders who want portable config on a USB IR kit).
        Defaults: Windows → %LOCALAPPDATA%\WinSecHunter, *nix → ~/.config/WinSecHunter.
#>
function Get-WinSecConfigPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([switch]$Ensure)

    $dir = $env:WINSECHUNTER_CONFIG_DIR
    if (-not $dir) {
        # Do not rely on $env:LOCALAPPDATA/$env:HOME: they are absent in hardened
        # service accounts, scheduled tasks and the AutoClaw exec session.
        $dir = if ($IsWindows) {
            Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'WinSecHunter'
        }
        else {
            $xdg = $env:XDG_CONFIG_HOME
            if ($xdg) { Join-Path $xdg 'WinSecHunter' }
            else { Join-Path ([Environment]::GetFolderPath('UserProfile')) '.config/WinSecHunter' }
        }
    }
    if ($Ensure) {
        if (-not (Test-Path -LiteralPath $dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force
        }
        $cacheDir = Join-Path $dir 'cache'
        if (-not (Test-Path -LiteralPath $cacheDir)) {
            $null = New-Item -ItemType Directory -Path $cacheDir -Force
        }
    }
    return $dir
}

$script:WinSecConfigCache = $null

$script:WinSecConfigDefaults = @{
    DefaultProfile          = 'IncidentResponse'
    DefaultMaxEvents        = 5000
    DefaultThrottleLimit    = 8
    DefaultOutputDirectory  = ''            # '' = current directory
    IncludeMessage          = $false
    DeepScan                = $false
    TraceIntervalSeconds    = 5
    ThreatIntelProvider     = 'None'        # None | AbuseIPDB | OTX | IpApi
    AbuseIpDbKeyEnvVar      = 'ABUSEIPDB_KEY'
    OtxKeyEnvVar            = 'OTX_API_KEY'
    IpApiContactEmail       = ''
    AttributionCacheHours   = 72
    BruteForceFailureThreshold     = 5
    BruteForceWindowMinutes        = 10
    BruteForceSprayAccountThreshold= 5
}

<#
    .SYNOPSIS
        Effective configuration: defaults overlaid by persisted config.json.
#>
function Get-WinSecConfig {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([switch]$Reload)

    if ($script:WinSecConfigCache -and -not $Reload) { return $script:WinSecConfigCache }

    $merged = @{}
    foreach ($k in $script:WinSecConfigDefaults.Keys) { $merged[$k] = $script:WinSecConfigDefaults[$k] }

    $file = Join-Path (Get-WinSecConfigPath) 'config.json'
    if (Test-Path -LiteralPath $file) {
        try {
            $stored = Get-Content -Raw -LiteralPath $file | ConvertFrom-Json -AsHashtable
            foreach ($k in @($stored.Keys)) {
                if (-not $merged.ContainsKey($k)) {
                    Write-Warning "WinSecHunter config: ignoring unknown option '$k'."
                    continue
                }
                # Normalize to the default's type so JSON round-trips stay stable
                # (ConvertFrom-Json may widen Int32 → Int64, etc.).
                $def = $script:WinSecConfigDefaults[$k]
                $val = $stored[$k]
                if ($null -ne $def -and $null -ne $val) {
                    try {
                        if ($def -is [int] -and $val -isnot [int]) { $val = [int]$val }
                        elseif ($def -is [bool] -and $val -isnot [bool]) { $val = [bool]::Parse([string]$val) }
                        elseif ($def -is [string] -and $val -isnot [string]) { $val = [string]$val }
                    }
                    catch { Write-Warning "WinSecHunter config: option '$k' has invalid value '$val'; keeping default." ; continue }
                }
                $merged[$k] = $val
            }
        }
        catch {
            Write-Warning "WinSecHunter config '$file' is corrupt and was ignored: $($_.Exception.Message)"
        }
    }
    $script:WinSecConfigCache = $merged
    return $merged
}

<#
    .SYNOPSIS
        Validates and persists configuration changes.
#>
function Save-WinSecConfig {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Changes)

    $current = Get-WinSecConfig
    foreach ($k in @($Changes.Keys)) {
        if (-not $current.ContainsKey($k)) {
            throw [ArgumentException]::new(
                "Unknown WinSecHunter option '$k'. Valid options: $((@($current.Keys) | Sort-Object) -join ', ')")
        }
        $expected = $current[$k]
        if ($null -ne $expected -and $expected -isnot [string]) {
            # Type-coerce to the default's type so JSON round-trips stay stable.
            try { $Changes[$k] = $Changes[$k] -as $expected.GetType() } catch { Write-Verbose "Option '$k': keeping raw value ($($_.Exception.Message))." }
            if ($null -ne $Changes[$k] -and $Changes[$k].GetType() -ne $expected.GetType()) {
                throw [ArgumentException]::new(
                    "Option '$k' expects $($expected.GetType().Name), got '$($Changes[$k])'.")
            }
        }
        $current[$k] = $Changes[$k]
    }

    $dir  = Get-WinSecConfigPath -Ensure
    $file = Join-Path $dir 'config.json'

    # Atomic write: a crash or a concurrent Set-WinSecHunterOption must never
    # leave a truncated config.json behind. Write a temp file in the same
    # directory, flush, then replace. Retry briefly on sharing violations.
    $json = $current | ConvertTo-Json -Depth 4
    $tmp  = Join-Path $dir ('config.{0}.tmp' -f [guid]::NewGuid().ToString('n'))
    $attempt = 0
    while ($true) {
        try {
            [System.IO.File]::WriteAllText($tmp, $json, [System.Text.UTF8Encoding]::new($false))
            # Move with overwrite is atomic on the same volume and, unlike
            # File.Replace, does not require a backup path.
            [System.IO.File]::Move($tmp, $file, $true)
            break
        }
        catch {
            $attempt++
            if ($attempt -ge 5) {
                if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
                throw [System.IO.IOException]::new("Cannot persist WinSecHunter config '$file': $($_.Exception.Message)", $_.Exception)
            }
            Start-Sleep -Milliseconds (100 * $attempt)
        }
    }

    $script:WinSecConfigCache = $current
    return $current
}

<#
    .SYNOPSIS
        Path to the attribution cache file for an IP.
#>
function Get-WinSecCacheFile {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string]$IpAddress)

    $safe = $IpAddress -replace '[^0-9A-Za-z._-]', '_'
    # IPv6 contains ':' which is illegal in a Windows file name; a hash is
    # stable, filesystem-safe and does not leak the address into directory
    # listings. Keep a readable prefix for support.
    $hashInput = [System.Text.Encoding]::UTF8.GetBytes($IpAddress.ToLowerInvariant())
    $hash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($hashInput)).Substring(0, 16).ToLowerInvariant()
    $prefix = $safe.Substring(0, [Math]::Min(24, $safe.Length))
    return Join-Path (Get-WinSecConfigPath -Ensure) ("cache/attr-{0}-{1}.json" -f $prefix, $hash)
}

