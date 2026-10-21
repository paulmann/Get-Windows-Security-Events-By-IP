#Requires -Version 7.6
function Expand-WinSecIpRange {
    <#
    .SYNOPSIS
        Enumerates the individual addresses of an IPv4/IPv6 CIDR or dash range.

    .DESCRIPTION
        Utility for allow/deny-list building and sweep planning: expands
        '203.0.113.0/24', '10.0.0.5-10.0.0.9' or '2001:db8::/126' into
        canonical address strings. Guarded by -MaxAddresses (default 4096)
        because enumerating wide ranges is a memory hazard, not a feature.
        Network and broadcast addresses of IPv4 ranges are excluded unless
        requested — they never appear as authentication sources.

    .EXAMPLE
        Expand-WinSecIpRange 203.0.113.0/30

    .EXAMPLE
        Expand-WinSecIpRange '10.0.0.5-10.0.0.9'

    .EXAMPLE
        Expand-WinSecIpRange '2001:db8::/126' -IncludeNetworkAddress

    .OUTPUTS
        System.String (canonical IP addresses)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $Range,

        [ValidateRange(1, 1048576)]
        [int] $MaxAddresses = 4096,

        [switch] $IncludeNetworkAddress,
        [switch] $IncludeBroadcast
    )

    process {
        $r = $Range.Trim()

        [System.Net.IPAddress]$first = $null
        [System.Net.IPAddress]$last  = $null
        $prefix = $null

        if ($r -match '^(.+)/(\d{1,3})$') {
            if (-not (Test-WinSecIpAddress -Value $r -AllowCidr)) {
                throw [ArgumentException]::new("Invalid CIDR range: '$r'.")
            }
            $prefix = [int]$Matches[2]
            $base = [System.Net.IPAddress]::Parse((ConvertTo-WinSecCanonicalIp -Value $Matches[1]))
            $bits = ($base.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) ? 32 : 128
            $bytes = $base.GetAddressBytes()

            # network = base & mask; last = network | ~mask
            $netBytes = [byte[]]::new($bytes.Length)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bitPos = $i * 8
                $maskByte = if ($bitPos + 8 -le $prefix) { 0xFF }
                            elseif ($bitPos -ge $prefix) { 0x00 }
                            else { (0xFF -shl (8 - ($prefix - $bitPos))) -band 0xFF }
                $netBytes[$i] = $bytes[$i] -band $maskByte
            }
            # last address: host bits all 1
            $lastBytes = [byte[]]::new($bytes.Length)
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                $bitPos = $i * 8
                $hostBits = if ($bitPos + 8 -le $prefix) { 0 } elseif ($bitPos -ge $prefix) { 8 } else { 8 - ($prefix - $bitPos) }
                $maskByte = if ($hostBits -eq 0) { 0 } elseif ($hostBits -ge 8) { 0xFF } else { (0xFF -shr (8 - $hostBits)) }
                $lastBytes[$i] = [byte](($netBytes[$i] -bor $maskByte) -band 0xFF)
            }
            $first = [System.Net.IPAddress]::new($netBytes)
            $last  = [System.Net.IPAddress]::new($lastBytes)

            # IPv4 semantics: exclude network/broadcast for prefixes ≤ /30
            if ($first.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork -and $prefix -le 30) {
                if (-not $IncludeNetworkAddress) { $first = Get-ShiftedIp -Address $first -Offset 1 }
                if (-not $IncludeBroadcast)    { $last  = Get-ShiftedIp -Address $last -Offset -1 }
            }
        }
        elseif ($r -match '^(.+)-(.+)$') {
            $a = $Matches[1].Trim(); $b = $Matches[2].Trim()
            if (-not (Test-WinSecIpAddress -Value $a) -or -not (Test-WinSecIpAddress -Value $b)) {
                throw [ArgumentException]::new("Invalid dash range: '$r'. Both sides must be IP addresses.")
            }
            $first = [System.Net.IPAddress]::Parse((ConvertTo-WinSecCanonicalIp -Value $a))
            $last  = [System.Net.IPAddress]::Parse((ConvertTo-WinSecCanonicalIp -Value $b))
            if ($first.AddressFamily -ne $last.AddressFamily) {
                throw [ArgumentException]::new("Dash range mixes address families: '$r'.")
            }
            if ((ConvertTo-BigInteger $first) -gt (ConvertTo-BigInteger $last)) {
                $tmp = $first; $first = $last; $last = $tmp
            }
        }
        else {
            throw [ArgumentException]::new("Expected CIDR ('10.0.0.0/24', '2001:db8::/126') or dash range ('10.0.0.5-10.0.0.9'), got '$r'.")
        }

        $startInt = ConvertTo-BigInteger $first
        $endInt   = ConvertTo-BigInteger $last
        $count = $endInt - $startInt + 1
        if ($count -gt $MaxAddresses) {
            throw [ArgumentException]::new(
                ("Range '{0}' contains {1} addresses, above -MaxAddresses ({2}). Narrow the range or raise the cap deliberately." -f $r, $count, $MaxAddresses))
        }

        $i = [bigint]0
        while ($i -lt $count) {
            (ConvertFrom-BigInteger ($startInt + $i) $first.AddressFamily).ToString()
            $i = $i + [bigint]1
        }
    }
}

# --- BigInteger helpers (module-private, not exported) -----------------------
function ConvertTo-BigInteger {
    param([System.Net.IPAddress]$Address)
    $bytes = $Address.GetAddressBytes()
    [array]::Reverse($bytes)                       # little-endian for BigInteger
    $unsigned = [byte[]]::new($bytes.Length + 1)   # leading zero → positive
    [array]::Copy($bytes, $unsigned, $bytes.Length)
    return [System.Numerics.BigInteger]::new($unsigned)
}

function ConvertFrom-BigInteger {
    param([System.Numerics.BigInteger]$Value, [System.Net.Sockets.AddressFamily]$Family)
    $len = ($Family -eq [System.Net.Sockets.AddressFamily]::InterNetwork) ? 4 : 16
    $bytes = $Value.ToByteArray()
    $out = [byte[]]::new($len)
    for ($i = 0; $i -lt [Math]::Min($bytes.Length, $len); $i++) { $out[$i] = $bytes[$i] }
    [array]::Reverse($out)                         # back to network order
    return [System.Net.IPAddress]::new($out)
}

function Get-ShiftedIp {
    param([System.Net.IPAddress]$Address, [bigint]$Offset)
    return ConvertFrom-BigInteger ((ConvertTo-BigInteger $Address) + $Offset) $Address.AddressFamily
}
