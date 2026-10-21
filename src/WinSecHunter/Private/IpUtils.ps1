#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: IP address utilities
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Pure functions; fully unit-testable on any platform.
# ---------------------------------------------------------------------------

<#
    .SYNOPSIS
        Validates an IPv4/IPv6 literal, optionally with CIDR suffix.
    .DESCRIPTION
        Strict validation for incident-response input: rejects hostnames,
        zone IDs ('%'), partial forms that .NET would silently coerce
        ('1' → 0.0.0.1), leading-zero octets and out-of-range prefixes.
#>
function Test-WinSecIpAddress {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Value,

        [switch] $AllowCidr
    )

    process {
        $s = ($Value ?? '').Trim()
        if ([string]::IsNullOrEmpty($s)) { return $false }
        if ($s.Contains('%')) { return $false }                    # zone/scope IDs never appear in event data
        if ($s.Contains('[')) { return $false }                    # bracket form is URI syntax, not log data

        $ipPart = $s
        $prefixPart = $null
        if ($s -match '^(.+)/(\d{1,3})$') {
            if (-not $AllowCidr) { return $false }
            $ipPart     = $Matches[1]
            $prefixPart = [int]$Matches[2]
        }

        if ($ipPart -notmatch '^[0-9A-Fa-f:.]+$') { return $false }

        $isV4Style = $ipPart.Contains('.') -and -not $ipPart.Contains(':')
        if ($isV4Style) {
            if ([regex]::Matches($ipPart, '\.').Count -ne 3) { return $false }
            if ($ipPart -match '(^|\.)0\d') { return $false }   # leading-zero octets are ambiguous (octal heritage)
        }
        elseif ([regex]::Matches($ipPart, ':').Count -lt 2) {
            return $false
        }

        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($ipPart, [ref]$parsed)) { return $false }
        if ($null -eq $parsed) { return $false }

        if ($null -ne $prefixPart) {
            $max = ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) ? 32 : 128
            if ($prefixPart -gt $max) { return $false }
        }
        return $true
    }
}

<#
    .SYNOPSIS
        Normalizes an IP (or CIDR base) to its canonical text form.
    .DESCRIPTION
        IPv4-mapped IPv6 ('::ffff:10.0.0.1') collapses to dotted-quad;
        IPv6 is compressed lowercase, exactly as Windows event logs
        normally render it. Strips an optional CIDR suffix.
#>
function ConvertTo-WinSecCanonicalIp {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory, ValueFromPipeline)][string]$Value)

    process {
        $clean = $Value.Trim()
        if ($clean -match '^(.+)/\d{1,3}$') { $clean = $Matches[1] }
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse($clean, [ref]$parsed) -or $null -eq $parsed) {
            throw [ArgumentException]::new("Not a valid IP address: '$Value'")
        }
        if ($parsed.IsIPv4MappedToIPv6) { $parsed = $parsed.MapToIPv4() }
        return $parsed.ToString()
    }
}

<#
    .SYNOPSIS
        All textual variants of an IP that may legitimately appear in logs.
    .DESCRIPTION
        Windows stacks render the same address differently by component:
        SChannel/RDP may log IPv4-mapped IPv6 ('::ffff:1.2.3.4' or hex
        '::ffff:102:304'), event XML may carry expanded IPv6. Matching any
        variant prevents false negatives during a sweep.
#>
function Get-WinSecIpVariant {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][string]$IpAddress)

    $canonical = ConvertTo-WinSecCanonicalIp -Value $IpAddress
    $parsed = [System.Net.IPAddress]::Parse($canonical)
    $variants = [System.Collections.Generic.List[string]]::new()
    $variants.Add($canonical)

    if ($parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        # IPv4: add mapped-IPv6 renderings
        $variants.Add("::ffff:$canonical")
        $b = $parsed.GetAddressBytes()
        $variants.Add(('::ffff:{0:x}:{1:x}' -f (($b[0] -shl 8) -bor $b[1]), (($b[2] -shl 8) -bor $b[3])))
    }
    else {
        # IPv6: expanded form (8 x 4 hex digits)
        $b = $parsed.GetAddressBytes()
        $groups = for ($i = 0; $i -lt 16; $i += 2) { '{0:x2}{1:x2}' -f $b[$i], $b[$i + 1] }
        $variants.Add(($groups -join ':'))
        if ($parsed.IsIPv4MappedToIPv6) {
            $v4 = $parsed.MapToIPv4().ToString()
            $variants.Add($v4)
            $variants.Add("::ffff:$v4")
        }
    }
    return [string[]]@($variants | Select-Object -Unique)
}

<#
    .SYNOPSIS
        Compiled regex matching an IP inside arbitrary event text/XML.
    .DESCRIPTION
        Boundary rules:
        - IPv4 variants: not preceded by digit/dot, not followed by digit
          (so '1.2.3.4' never matches inside '11.2.3.4' or '1.2.3.44',
          but DOES match inside '::ffff:1.2.3.4' and '1.2.3.4:55123').
        - IPv6 variants: word/colon boundaries, case-insensitive.
#>
function Get-WinSecIpMatchRegex {
    [CmdletBinding()]
    [OutputType([regex])]
    param([Parameter(Mandatory)][string]$IpAddress)

    $parts = foreach ($v in (Get-WinSecIpVariant -IpAddress $IpAddress)) {
        $esc = [regex]::Escape($v)
        if ($v.Contains(':') -and -not $v.Contains('.')) {
            "(?<![\w:])$esc(?![\w:])"          # pure IPv6
        }
        else {
            "(?<![\d.])$esc(?![\d.])"          # IPv4 (incl. mapped forms)
        }
    }
    return [regex]::new(($parts -join '|'), [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Compiled)
}

<#
    .SYNOPSIS
        True when the candidate IP falls inside the CIDR network.
#>
function Test-WinSecIpInCidr {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$IpAddress,
        [Parameter(Mandatory)][string]$Cidr
    )

    try {
        if ($Cidr -notmatch '^(.+)/(\d{1,3})$') { return $false }
        $network = ConvertTo-WinSecCanonicalIp -Value $Matches[1]
        $prefix  = [int]$Matches[2]
        $candidate = ConvertTo-WinSecCanonicalIp -Value $IpAddress
    }
    catch { return $false }

    $netParsed = [System.Net.IPAddress]::Parse($network)
    $candParsed = [System.Net.IPAddress]::Parse($candidate)
    if ($netParsed.AddressFamily -ne $candParsed.AddressFamily) { return $false }

    $netBytes  = $netParsed.GetAddressBytes()
    $candBytes = $candParsed.GetAddressBytes()

    $fullBytes = [int][Math]::Floor($prefix / 8)
    for ($i = 0; $i -lt $fullBytes; $i++) {
        if ($netBytes[$i] -ne $candBytes[$i]) { return $false }
    }
    $remBits = $prefix % 8
    if ($remBits -gt 0 -and $fullBytes -lt $netBytes.Length) {
        $mask = (0xFF -shl (8 - $remBits)) -band 0xFF
        if (($netBytes[$fullBytes] -band $mask) -ne ($candBytes[$fullBytes] -band $mask)) { return $false }
    }
    return $true
}

<#
    .SYNOPSIS
        Classifies an IP: private/loopback/link-local/public + version.
    .OUTPUTS
        Hashtable with Version, IsPrivate, IsLoopback, IsLinkLocal, IsMulticast.
#>
function Get-WinSecIpClassification {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)][string]$IpAddress)

    $parsed = [System.Net.IPAddress]::Parse((ConvertTo-WinSecCanonicalIp -Value $IpAddress))
    $isV4 = $parsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork
    $isPrivate = $false
    if ($isV4) {
        $b = $parsed.GetAddressBytes()
        $isPrivate = ($b[0] -eq 10) -or
                     ($b[0] -eq 172 -and ($b[1] -band 0xF0) -eq 16) -or
                     ($b[0] -eq 192 -and $b[1] -eq 168) -or
                     ($b[0] -eq 100 -and ($b[1] -band 0xC0) -eq 64)   # CGNAT 100.64.0.0/10
    }
    else {
        $b = $parsed.GetAddressBytes()
        $isPrivate = ($b[0] -band 0xFE) -eq 0xFC   # fc00::/7 ULA
    }
    return @{
        Version      = $isV4 ? 4 : 6
        IsPrivate    = $isPrivate -or [System.Net.IPAddress]::IsLoopback($parsed) -or $parsed.IsIPv6LinkLocal
        IsLoopback   = [System.Net.IPAddress]::IsLoopback($parsed)
        IsLinkLocal  = ($isV4 -and $parsed.GetAddressBytes()[0] -eq 169 -and $parsed.GetAddressBytes()[1] -eq 254) -or $parsed.IsIPv6LinkLocal
        IsMulticast  = $isV4 ? ($parsed.GetAddressBytes()[0] -ge 224 -and $parsed.GetAddressBytes()[0] -le 239) : ($parsed.GetAddressBytes()[0] -eq 0xFF)
    }
}

