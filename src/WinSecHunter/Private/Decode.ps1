#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: status code decoders
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Tables aligned with Microsoft auditing documentation (learn.microsoft.com
# event 4625/4771/4776 references). Keys are stored lowercase without '0x'.
# ---------------------------------------------------------------------------

$script:WinSecNtStatusMap = @{
    '0'        = 'Success'
    'c0000064' = 'Account does not exist'
    'c000006a' = 'Incorrect password'
    'c000006d' = 'Generic logon failure'
    'c000006e' = 'Account restriction (e.g. logon hours, workstation limit)'
    'c000006f' = 'Logon time restriction violation — user cannot log on at this time'
    'c0000070' = 'Workstation restriction violation — user cannot log on from this computer'
    'c0000071' = 'Password expired'
    'c0000072' = 'Account disabled'
    'c000009a' = 'Insufficient system resources'
    'c0000133' = 'Clocks out of sync between client and server'
    'c000015b' = 'The user has not been granted the requested logon type at this machine'
    'c0000193' = 'Account expired'
    'c0000224' = 'User must change password at next logon'
    'c0000225' = 'A non-retryable error occurred during logon'
    'c0000234' = 'Account locked out'
    'c00002ee' = 'An error occurred during logon'
    'c0000413' = 'Authentication firewall prohibits logon (silos)'
}

$script:WinSecKerberosMap = @{
    '0'   = 'No error'
    '1'   = "Client's entry in the Kerberos database has expired"
    '2'   = "Server's entry in the Kerberos database has expired"
    '3'   = 'Requested protocol version not supported'
    '4'   = "Client's key encrypted in old master key"
    '5'   = "Server's key encrypted in old master key"
    '6'   = 'Client not found in Kerberos database (bad user name, or account not yet replicated)'
    '7'   = 'Server not found in Kerberos database (new computer account not yet replicated)'
    '8'   = 'Multiple principal entries in the Kerberos database'
    '9'   = 'The client or server has a null key (administrator should reset the password)'
    'a'   = 'Ticket not eligible for postdating'
    'b'   = 'Requested start time is later than end time'
    'c'   = 'KDC policy rejects the request (e.g. workstation restriction)'
    'd'   = 'KDC cannot accommodate the requested option'
    'e'   = 'KDC has no support for encryption type'
    'f'   = 'KDC has no support for checksum type'
    '10'  = 'KDC has no support for padata type'
    '11'  = 'KDC has no support for transited type'
    '12'  = 'Client credentials revoked (account disabled, expired, locked out, or logon hours violation)'
    '13'  = 'Credentials for server revoked'
    '14'  = 'TGT revoked'
    '15'  = 'Client not yet valid — try again later'
    '16'  = 'Server not yet valid — try again later'
    '17'  = 'Password has expired'
    '18'  = 'Pre-authentication information was invalid (usually means bad password)'
    '19'  = 'Additional pre-authentication required'
    '1f'  = 'Integrity check on decrypted field failed'
    '20'  = 'Ticket expired (frequently logged by computer accounts)'
    '21'  = 'Ticket not yet valid'
    '22'  = 'Request is a replay'
    '23'  = "The ticket isn't for us"
    '24'  = "Ticket and authenticator don't match"
    '25'  = 'Clock skew too great'
    '26'  = 'Incorrect net address (IP address changed mid-session?)'
    '27'  = 'Protocol version mismatch'
    '28'  = 'Invalid message type'
    '29'  = 'Message stream modified'
    '2a'  = 'Message out of order'
    '2c'  = 'Specified version of key is not available'
    '2d'  = 'Service key not available'
    '2e'  = 'Mutual authentication failed (possible memory allocation failure)'
    '2f'  = 'Incorrect message direction'
    '30'  = 'Alternative authentication method required'
    '31'  = 'Incorrect sequence number in message'
    '32'  = 'Inappropriate type of checksum in message'
    '3c'  = 'Generic error (description in e-text)'
    '3d'  = 'Field is too long for this implementation'
}

$script:WinSecFailureReasonMap = @{
    '2304' = 'An error occurred during logon'
    '2305' = 'The specified user account has expired'
    '2308' = 'The user has not been granted the requested logon type at this machine'
    '2309' = "The specified account's password has expired"
    '2310' = 'Account currently disabled'
    '2311' = 'Account logon time restriction violation'
    '2312' = 'User not allowed to log on at this computer'
    '2313' = 'Unknown user name or bad password'
}

$script:WinSecLogonTypeNames = @{
    2  = 'Interactive (physical console)'
    3  = 'Network (SMB, remote registry, IIS)'
    4  = 'Batch (scheduled task)'
    5  = 'Service (service control manager)'
    6  = 'Proxy'
    7  = 'Unlock (workstation unlock)'
    8  = 'NetworkCleartext (plaintext network logon)'
    9  = 'NewCredentials (runas /netonly)'
    10 = 'RemoteInteractive (RDP)'
    11 = 'CachedInteractive (cached domain credentials)'
    12 = 'CachedRemoteInteractive'
    13 = 'CachedUnlock'
}

<#
    .SYNOPSIS
        Decodes Windows authentication status codes into human-readable text.
    .DESCRIPTION
        Handles NTSTATUS codes (4625 Status/SubStatus, 4776 ErrorCode),
        Kerberos result codes (4768/4769/4770/4771/4777) and %%-encoded
        FailureReason values (4625). Accepts hex ('0xC000006A', '0x18'),
        bare hex ('C000006A') and decimal representations.
    .OUTPUTS
        System.String — description, or $null when the code is empty/unknown.
#>
function Get-WinSecStatusDescription {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Code,

        [ValidateSet('Auto', 'NtStatus', 'Kerberos', 'LogonFailureReason')]
        [string] $Kind = 'Auto',

        # EventId improves Auto-detection (Kerberos events use short codes).
        [int] $EventId = 0
    )

    if ([string]::IsNullOrWhiteSpace($Code) -or $Code.Trim() -eq '-') { return $null }
    $c = $Code.Trim()

    # %%-encoded string IDs (FailureReason)
    if ($c -match '^%%(\d+)$') {
        $key = $Matches[1]
        return $script:WinSecFailureReasonMap.ContainsKey($key) ? "%%$key — $($script:WinSecFailureReasonMap[$key])" : $null
    }

    # Normalize to bare lowercase hex
    $hex = $c
    if ($hex -match '^(?:0x)?([0-9A-Fa-f]+)$') {
        $hex = $Matches[1].ToLowerInvariant().TrimStart('0')
        if ([string]::IsNullOrEmpty($hex)) { $hex = '0' }
    }
    else {
        # decimal integer form (some providers emit signed decimals)
        $asLong = 0L
        if ([long]::TryParse($c, [ref]$asLong)) {
            $hex = ([uint32]($asLong -band 0xFFFFFFFFL)).ToString('x').TrimStart('0')
            if ([string]::IsNullOrEmpty($hex)) { $hex = '0' }
        }
        else { return $null }
    }

    if ($Kind -eq 'Auto') {
        $Kind = if ($EventId -in 4768, 4769, 4770, 4771, 4777) { 'Kerberos' }
                elseif ($hex.Length -le 2 -and $EventId -eq 0) { 'Kerberos' }
                else { 'NtStatus' }
    }

    switch ($Kind) {
        'Kerberos' {
            if ($script:WinSecKerberosMap.ContainsKey($hex)) {
                return "0x$($hex.ToUpperInvariant()) — $($script:WinSecKerberosMap[$hex])"
            }
        }
        default {
            if ($script:WinSecNtStatusMap.ContainsKey($hex)) {
                $display = ('0x{0:X8}' -f [Convert]::ToUInt32($hex, 16))
                return "$display — $($script:WinSecNtStatusMap[$hex])"
            }
        }
    }
    return $null
}

<#
    .SYNOPSIS
        Friendly name for a Windows logon type number.
#>
function Get-WinSecLogonTypeName {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowNull()][int]$LogonType)

    if ($LogonType -le 0) { return $null }
    return $script:WinSecLogonTypeNames.ContainsKey($LogonType) ?
        "$LogonType — $($script:WinSecLogonTypeNames[$LogonType])" : "$LogonType"
}

<#
    .SYNOPSIS
        Decodes WFP/firewall %% direction and protocol constants.
#>
function Get-WinSecNetworkConstant {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Value, [ValidateSet('Direction', 'Protocol')][string]$Type)

    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    if ($Type -eq 'Direction') {
        $dir = switch ($Value.Trim()) {
            '%%14592' { 'Inbound' }
            '%%14593' { 'Outbound' }
            '%%14594' { 'Loopback' }
            default { $Value }
        }
        return $dir
    }
    # Protocol: firewall events carry IANA numbers, Sysmon carries names
    $v = $Value.Trim()
    if ($v -notmatch '^\d+$') { return $v.ToUpperInvariant() }
    $proto = switch ([int]$v) {
        1  { 'ICMP' }
        6  { 'TCP' }
        17 { 'UDP' }
        58 { 'ICMPv6' }
        default { "proto:$v" }
    }
    return $proto
}

