#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: event parser (raw record/XML → WinSecEvent)
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Accepts EventLogRecord, [xml], XML string or the remote payload hashtable,
# which keeps it unit-testable on any platform.
# ---------------------------------------------------------------------------

$script:WinSecIndexFieldMaps = @{
    # Providers whose EventData carries unnamed positional values.
    '7045' = @('ServiceName', 'ImagePath', 'ServiceType', 'StartType', 'AccountName')
    '6008' = @('ShutdownDate', 'ShutdownTime')
    '104'  = @('LogFileCleared', 'SubjectUserName', 'SubjectDomainName')
}

$script:WinSecOutcomeSuccessIds = @(4624, 4648, 4778, 1149, 21, 22, 25)
$script:WinSecOutcomeFailureIds = @(4625, 4649, 4771, 1147, 1148, 5632, 5633, 4766)
$script:WinSecOutcomeStatusIds  = @(4768, 4769, 4770, 4776)

<#
    .SYNOPSIS
        Converts a raw Windows event into a normalized WinSecEvent.
#>
function ConvertTo-WinSecEvent {
    [CmdletBinding()]
    [OutputType([WinSecEvent])]
    param(
        # EventLogRecord | [xml] | XML string | remote payload hashtable
        [Parameter(Mandatory)] $Record,

        [AllowEmptyString()][string] $MatchedIp = '',
        [ValidateSet('', 'EventData', 'UserData', 'Message', 'Xml')]
        [AllowEmptyString()][string] $MatchedOn = '',

        [switch] $IncludeMessage,
        [switch] $IncludeRawXml,

        # UTC computed on the SOURCE machine (authoritative for remote queries).
        [datetime] $AuthoritativeUtc = [datetime]::MinValue
    )

    # ---- Normalize input ----------------------------------------------------
    [xml]$xml = $null
    [string]$computerOverride = $null
    [string]$messageOverride  = $null
    [datetime]$utcOverride    = $AuthoritativeUtc

    if ($Record -is [hashtable]) {
        if ($Record.Xml -is [xml]) { $xml = $Record.Xml } else { $xml = [xml][string]$Record.Xml }
        $computerOverride = $Record.Computer
        $messageOverride  = $Record['Message']
        if ($Record.TimeUtc) { $utcOverride = [datetime]$Record.TimeUtc }
    }
    elseif ($Record -is [xml]) { $xml = $Record }
    elseif ($Record -is [string]) { $xml = [xml]$Record }
    else {
        # Duck-typed EventLogRecord: avoids a hard type dependency so the
        # module imports on non-Windows platforms (CI unit tests).
        if ($Record.PSObject.Methods['ToXml']) {
            $xml = [xml]$Record.ToXml()
            $computerOverride = $Record.MachineName
            if ($IncludeMessage) {
                try { $messageOverride = $Record.Message } catch { $messageOverride = $null }
            }
        }
        else {
            throw [ArgumentException]::new(
                'Record must be an EventLogRecord, [xml], an XML string or a remote payload hashtable.')
        }
    }
    if (-not $xml -or -not $xml.Event -or -not $xml.Event.System) {
        throw [ArgumentException]::new('Input XML is not a Windows event (missing Event/System).')
    }

    # ---- System section (SelectSingleNode: StrictMode- and namespace-safe) ----
    $sys = $xml.Event.SelectSingleNode("*[local-name()='System']")
    if (-not $sys) {
        throw [ArgumentException]::new('Event XML has no System section.')
    }

    $node = $sys.SelectSingleNode("*[local-name()='EventID']")
    $eventId = $node ? [int]$node.InnerText : 0
    $node = $sys.SelectSingleNode("*[local-name()='Channel']")
    $logName = $node ? [string]$node.InnerText : ''
    $node = $sys.SelectSingleNode("*[local-name()='Provider']")
    $provider = $node ? [string]$node.GetAttribute('Name') : ''
    $node = $sys.SelectSingleNode("*[local-name()='EventRecordID']")
    $recordId = $node ? [long]$node.InnerText : 0L
    $node = $sys.SelectSingleNode("*[local-name()='Computer']")
    $computer = $computerOverride ? $computerOverride : ($node ? [string]$node.InnerText : '')

    $timeUtc = [datetime]::MinValue
    $node = $sys.SelectSingleNode("*[local-name()='TimeCreated']")
    $sysTime = $node ? [string]$node.GetAttribute('SystemTime') : ''
    if ($sysTime) {
        [void][datetime]::TryParse(
            $sysTime, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal,
            [ref]$timeUtc)
    }
    if ($utcOverride -ne [datetime]::MinValue) { $timeUtc = $utcOverride.ToUniversalTime() }
    if ($timeUtc -eq [datetime]::MinValue) { $timeUtc = [datetime]::UtcNow }

    # ---- Data section (named EventData or UserData/EventXML) ----------------
    $data = @{}   # PowerShell hashtables are case-insensitive
    $eventData = $xml.Event.SelectSingleNode("*[local-name()='EventData']")
    if ($eventData) {
        $idx = 0
        foreach ($d in $eventData.SelectNodes("*[local-name()='Data']")) {
            $name = $d.HasAttribute('Name') ? $d.GetAttribute('Name') : "D$idx"
            $data[$name] = ([string]$d.InnerText).Trim()
            $idx++
        }
        # Positional (unnamed) data from legacy providers (System log).
        if ($data.ContainsKey('D0') -and $script:WinSecIndexFieldMaps.ContainsKey([string]$eventId)) {
            $names = $script:WinSecIndexFieldMaps[[string]$eventId]
            for ($i = 0; $i -lt $names.Count; $i++) {
                if ($data.ContainsKey("D$i")) { $data[$names[$i]] = $data["D$i"] }
            }
        }
    }
    else {
        $userData = $xml.Event.SelectSingleNode("*[local-name()='UserData']")
        if ($userData) {
            $container = $userData.SelectSingleNode("*[local-name()='EventXML']")
            if (-not $container) { $container = $userData }
            foreach ($child in $container.ChildNodes) {
                if ($child -is [System.Xml.XmlElement]) {
                    $data[$child.LocalName] = ([string]$child.InnerText).Trim()
                }
            }
        }
    }
    # Correlation ActivityID (RDP session chaining across RCM/LSM logs).
    $corr = $sys.SelectSingleNode("*[local-name()='Correlation']")
    $activityId = $corr ? [string]$corr.GetAttribute('ActivityID') : ''
    if ($activityId) { $data['ActivityID'] = $activityId }

    # ---- Catalog classification ----------------------------------------------
    $info = Get-WinSecEventInfo -EventId $eventId -LogName $logName
    $category   = [WinSecEventCategory]::Unknown
    $importance = [WinSecSeverity]::Informational
    $attackIds  = [string[]]@()
    $eventName  = "Event $eventId"
    $description= $null
    if ($info) {
        $parsedCat = $null
        if ([enum]::TryParse([WinSecEventCategory], [string]$info['Category'], $true, [ref]$parsedCat)) { $category = $parsedCat }
        $parsedImp = $null
        if ([enum]::TryParse([WinSecSeverity], [string]$info['Importance'], $true, [ref]$parsedImp)) { $importance = $parsedImp }
        $attackIds = [string[]]@($info['Attack'])
        $eventName = [string]$info['Name']
        $description = $info['Notes']
    }

    # ---- Field mapping ---------------------------------------------------------
    function script:Get-FirstData {
        param([hashtable]$D, [string[]]$Names)
        foreach ($n in $Names) {
            if ($D.ContainsKey($n)) {
                $v = $D[$n]
                if (-not [string]::IsNullOrWhiteSpace($v) -and $v -ne '-') { return $v }
            }
        }
        return $null
    }

    $isRcm = $logName -like '*RemoteConnectionManager*'
    $isLsm = $logName -like '*LocalSessionManager*'

    $sourceIp = Get-FirstData $data @('IpAddress', 'ClientAddress', 'SourceAddress', 'SourceIp', 'SourceNetworkAddress', 'Address')
    if (-not $sourceIp -and $isRcm) { $sourceIp = Get-FirstData $data @('Param3') }

    $sourcePort = Get-FirstData $data @('IpPort', 'SourcePort')
    $destIp     = Get-FirstData $data @('DestAddress', 'DestinationIp')
    $destPort   = Get-FirstData $data @('DestPort', 'DestinationPort')

    # Target account
    $targetAccount = $null
    $tu = Get-FirstData $data @('TargetUserName')
    $td = Get-FirstData $data @('TargetDomainName')
    if ($tu) { $targetAccount = ($td -and $td -ne 'NT AUTHORITY') ? "$td\$tu" : $tu }
    if (-not $targetAccount) {
        if ($isRcm) {
            $p1 = Get-FirstData $data @('Param1')   # user (sometimes already domain\user or user@domain)
            $p2 = Get-FirstData $data @('Param2')   # domain
            if ($p1) { $targetAccount = ($p2 -and $p1 -notmatch '[\\@]') ? "$p2\$p1" : $p1 }
        }
        elseif ($isLsm) {
            $u = Get-FirstData $data @('User')
            $d = Get-FirstData $data @('Domain')
            if ($u) { $targetAccount = ($d -and $u -notmatch '[\\@]') ? "$d\$u" : $u }
        }
    }

    $su = Get-FirstData $data @('SubjectUserName')
    $sd = Get-FirstData $data @('SubjectDomainName')
    $subjectAccount = if ($su) { ($sd -and $sd -ne 'NT AUTHORITY') ? "$sd\$su" : $su } else { $null }

    $logonTypeRaw = Get-FirstData $data @('LogonType')
    $logonType = [WinSecLogonType]::Unknown
    if ($logonTypeRaw) {
        $lt = 0
        if ([int]::TryParse($logonTypeRaw, [ref]$lt) -and [enum]::IsDefined([WinSecLogonType], $lt)) {
            $logonType = [WinSecLogonType]$lt
        }
    }

    $direction = [WinSecDirection]::Unknown
    $dirRaw = Get-FirstData $data @('Direction')
    if ($dirRaw) {
        $decodedDir = Get-WinSecNetworkConstant -Value $dirRaw -Type Direction
        $parsedDir = $null
        if ([enum]::TryParse([WinSecDirection], $decodedDir, $true, [ref]$parsedDir)) { $direction = $parsedDir }
    }
    else {
        $initiated = Get-FirstData $data @('Initiated')   # Sysmon EID 3
        if ($initiated) { $direction = ($initiated -eq 'true') ? [WinSecDirection]::Outbound : [WinSecDirection]::Inbound }
    }

    $protocolRaw = Get-FirstData $data @('Protocol')
    $protocol = $protocolRaw ? (Get-WinSecNetworkConstant -Value $protocolRaw -Type Protocol) : $null

    # ---- Outcome & status decoding --------------------------------------------
    $status      = Get-FirstData $data @('Status')
    $subStatus   = Get-FirstData $data @('SubStatus')
    $failureCode = Get-FirstData $data @('FailureCode')          # 4771
    $resultCode  = Get-FirstData $data @('ResultCode', 'TicketResultCode') # 4768/4769/4770
    $errorCode   = Get-FirstData $data @('ErrorCode')            # 4776
    $failReason  = Get-FirstData $data @('FailureReason')        # %%2313

    $outcome = [WinSecOutcome]::Informational
    if ($eventId -in $script:WinSecOutcomeSuccessIds) { $outcome = [WinSecOutcome]::Success }
    elseif ($eventId -in $script:WinSecOutcomeFailureIds) { $outcome = [WinSecOutcome]::Failure }
    elseif ($eventId -in $script:WinSecOutcomeStatusIds) {
        $driver = $failureCode ?? $resultCode ?? $errorCode ?? $status
        $outcome = if ($driver) {
            ($driver.Trim() -in '0x0', '0x00', '0', '%%0') ? [WinSecOutcome]::Success : [WinSecOutcome]::Failure
        }
        else { [WinSecOutcome]::Informational }
    }
    elseif ($null -eq $info) { $outcome = [WinSecOutcome]::Unknown }

    $statusCode = $null
    $candidates = @(
        @{ Code = $subStatus;   Kind = 'NtStatus' },
        @{ Code = $failureCode; Kind = 'Kerberos' },
        @{ Code = $resultCode;  Kind = 'Kerberos' },
        @{ Code = $errorCode;   Kind = ($eventId -eq 4776) ? 'NtStatus' : 'Auto' },
        @{ Code = $failReason;  Kind = 'LogonFailureReason' },
        @{ Code = $status;      Kind = ($eventId -eq 4771) ? 'Kerberos' : 'NtStatus' }
    )
    foreach ($cand in $candidates) {
        if ($cand.Code) {
            $desc = Get-WinSecStatusDescription -Code $cand.Code -Kind $cand.Kind -EventId $eventId
            if ($desc) { $statusCode = $desc; break }
            if (-not $statusCode) { $statusCode = $cand.Code }   # keep raw until something decodes
        }
    }

    # ---- Assemble ----------------------------------------------------------
    $e = [WinSecEvent]::new()
    $e.Computer       = $computer
    $e.LogName        = $logName
    $e.ProviderName   = $provider
    $e.RecordId       = $recordId
    $e.EventId        = $eventId
    $e.TimeUtc        = $timeUtc
    $e.TimeCreated    = $timeUtc.ToLocalTime()
    $e.MatchedIp      = $MatchedIp
    $e.MatchedOn      = $MatchedOn
    $e.Category       = $category
    $e.Outcome        = $outcome
    $e.Importance     = $importance
    $e.EventName      = $eventName
    $e.AttackIds      = $attackIds
    $e.Description    = $description
    $sp = 0; if ($sourcePort) { [void][int]::TryParse($sourcePort, [ref]$sp) }
    $dp = 0; if ($destPort)   { [void][int]::TryParse($destPort,   [ref]$dp) }
    $e.SourceIp       = $sourceIp
    $e.SourcePort     = $sp
    $e.DestinationIp  = $destIp
    $e.DestinationPort= $dp
    $e.Direction      = $direction
    $e.TargetAccount  = $targetAccount
    $e.SubjectAccount = $subjectAccount
    $e.LogonType      = $logonType
    $e.LogonId        = Get-FirstData $data @('LogonId', 'TargetLogonId', 'SubjectLogonId')
    $e.AuthPackage    = Get-FirstData $data @('AuthenticationPackageName', 'PackageName')
    $e.LogonProcess   = Get-FirstData $data @('LogonProcessName', 'Process')
    $e.Workstation    = Get-FirstData $data @('WorkstationName', 'Workstation', 'SourceWorkstation')
    $e.Status         = $status
    $e.SubStatus      = $subStatus
    $e.StatusCode     = $statusCode
    $e.FailureReason  = $failReason
    $e.ProcessName    = Get-FirstData $data @('ProcessName', 'NewProcessName', 'Image', 'ParentImage')
    $e.ServiceName    = Get-FirstData $data @('ServiceName')
    $e.TaskName       = Get-FirstData $data @('TaskName')
    $e.ObjectName     = Get-FirstData $data @('ObjectName', 'ShareName', 'RelativeTargetName')
    $e.Protocol       = $protocol
    $e.Data           = $data
    if ($IncludeMessage -or $messageOverride) {
        $msg = $messageOverride
        if (-not $msg) { try { $msg = [string]$xml.Event.RenderingInfo } catch { Write-Verbose "Message rendering unavailable: $($_.Exception.Message)" } }
        $e.Message = $msg ? (($msg -replace '\r\n|\r|\n', ' ') -replace '\s+', ' ').Trim() : $null
    }
    if ($IncludeRawXml) { $e.Xml = $xml.OuterXml }
    return $e
}

