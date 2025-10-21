<#
.SYNOPSIS
    Retrieves Windows Security events referencing a specific IP address, CIDR range, or all failed authentication attempts.

.DESCRIPTION
    Full-featured security event analyzer with time filtering, CIDR support,
    multiple output formats (Text, CSV, JSON, Markdown, HTML, MySQL), and compliance-ready reporting.
    If IpAddress is not specified, collects all failed authentication, logon, and resource access attempts.

.PARAMETER IpAddress
    Optional. IP address or CIDR range (e.g., 192.168.1.100, 10.0.0.0/24, ::1, 2001:db8::/64).
    If omitted, collects all failed authentication events from any IP.

.PARAMETER Category
    Event category: RDP, FileShare, Authentication, AllEvents. Default: 'RDP'.
    Ignored when IpAddress is not specified.

.PARAMETER OutputPath
    Output file path. Default: "C:\security_events_by_ip.txt".

.PARAMETER MaxEvents
    Maximum number of events to process. Default: 1000.

.PARAMETER Decode
    Decode status codes? Values: 'Yes' (default) or 'No'.

.PARAMETER ShowColumns
    Explicitly specify columns to display.

.PARAMETER HideColumns
    Specify columns to hide.

.PARAMETER LastHours
    Filter events from the last N hours.

.PARAMETER LastDays
    Filter events from the last N days.

.PARAMETER StartTime
    Start time for filtering.

.PARAMETER EndTime
    End time for filtering.

.PARAMETER OutputFormat
    Output format: Text, CSV, JSON, Markdown, HTML, MySQL. Default: Text.

.PARAMETER ShowOutput
    Display results in console (in addition to file export).

.EXAMPLE
    .\Get-SecurityEventsByIP.ps1 -LastDays 7 -OutputFormat HTML -ShowOutput
    Collects all failed authentication events from the last 7 days

.EXAMPLE
    .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.0/24" -Category RDP -OutputFormat CSV
    Collects RDP events from specific CIDR range

.NOTES
    Author: Mikhail Deynekin
    Email: mid1977@gmail.com
    Version: 4.1 (Added collection of all failed auth events when IpAddress is not specified  + MySQL export + ShowOutput)
#>

#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'Default')]
param (
    [Parameter(Mandatory = $false)]
    [string]$IpAddress,

    [Parameter(Mandatory = $false)]
    [ValidateSet('RDP', 'FileShare', 'Authentication', 'AllEvents')]
    [string]$Category = 'RDP',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "C:\security_events_by_ip.txt",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 100000)]
    [int]$MaxEvents = 1000,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Yes', 'No')]
    [string]$Decode = 'Yes',

    [Parameter(Mandatory = $false, ParameterSetName = 'Show')]
    [string[]]$ShowColumns,

    [Parameter(Mandatory = $false, ParameterSetName = 'Hide')]
    [string[]]$HideColumns,

    [Parameter(Mandatory = $false)]
    [int]$LastHours,

    [Parameter(Mandatory = $false)]
    [int]$LastDays,

    [Parameter(Mandatory = $false)]
    [datetime]$StartTime,

    [Parameter(Mandatory = $false)]
    [datetime]$EndTime,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Text', 'CSV', 'JSON', 'Markdown', 'HTML', 'MySQL')]
    [string]$OutputFormat = 'Text',

    [Parameter(Mandatory = $false)]
    [switch]$ShowOutput
)

# === IP and Time Validation ===
$ipParsed = $null
$cidrPrefix = $null
$isCidr = $false
$baseIp = $null

if ($IpAddress) {
    if ($IpAddress -match '^([0-9a-f:.]+)(?:/(\d+))?$') {
        $ipPart = $matches[1]
        $cidrPart = $matches[2]
        if (-not [System.Net.IPAddress]::TryParse($ipPart, [ref]$ipParsed)) {
            throw "Invalid IP address in '$IpAddress'"
        }
        if ($cidrPart) {
            $cidrPrefix = [int]$cidrPart
            if ($ipParsed.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
                if ($cidrPrefix -lt 0 -or $cidrPrefix -gt 32) { throw "Invalid IPv4 CIDR prefix: $cidrPrefix" }
            } else {
                if ($cidrPrefix -lt 0 -or $cidrPrefix -gt 128) { throw "Invalid IPv6 CIDR prefix: $cidrPrefix" }
            }
            $isCidr = $true
        }
        $baseIp = $ipParsed.ToString()
    } else {
        throw "Invalid IP/CIDR format: $IpAddress"
    }
}

$finalStartTime = if ($PSBoundParameters.ContainsKey('StartTime')) { $StartTime } elseif ($LastDays) { (Get-Date).AddDays(-$LastDays) } elseif ($LastHours) { (Get-Date).AddHours(-$LastHours) } else { $null }
$finalEndTime = if ($PSBoundParameters.ContainsKey('EndTime')) { $EndTime } else { Get-Date }

# === Status Codes ===
$StatusCodes = @{
    '0xc0000064' = 'Account does not exist'
    '0xc000006a' = 'Incorrect password'
    '0xc000006d' = 'Bad username or password'
    '0xc000006e' = 'Account restriction'
    '0xc000006f' = 'Logon time restriction violation'
    '0xc0000070' = 'Workstation restriction violation'
    '0xc0000071' = 'Password expired'
    '0xc0000072' = 'Account disabled'
    '0xc0000193' = 'Account expired'
    '0xc0000224' = 'User must change password at next logon'
    '0xc0000234' = 'Account locked out'
    '0xc000015b' = 'Logon type not granted'
    '0xc0000413' = 'Machine is shutting down'
}

$FailureReasons = @{
    '%%2305' = 'Account does not exist'
    '%%2309' = 'Guest account'
    '%%2310' = 'Account disabled'
    '%%2311' = 'Account expired'
    '%%2312' = 'User not allowed at this computer'
    '%%2313' = 'Unknown user or bad password'
    '%%2304' = 'Logon error occurred'
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AllPossibleColumns = @(
    'TimeCreated', 'EventId', 'Account', 'SourceIP', 'Computer', 'Port',
    'LogonType', 'AuthPackage', 'LogonProcess', 'Status', 'SubStatus', 'Message', 'Result'
)

#region Helper Functions

function Test-AdministratorPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-SecurityLogAvailability {
    try { $log = Get-WinEvent -ListLog 'Security' -ErrorAction Stop; return $log.IsEnabled } catch { return $false }
}

function Test-IpInCidr {
    param([byte[]]$eventIpBytes, [byte[]]$networkBytes, [int]$prefixLength)
    $bytesNeeded = [Math]::Ceiling($prefixLength / 8)
    for ($i = 0; $i -lt $bytesNeeded; $i++) {
        if ($i -eq $bytesNeeded - 1) {
            $maskBits = $prefixLength % 8
            if ($maskBits -eq 0) { $maskBits = 8 }
            $mask = (0xFF -shl (8 - $maskBits)) -band 0xFF
            if (($eventIpBytes[$i] -band $mask) -ne ($networkBytes[$i] -band $mask)) { return $false }
        } else {
            if ($eventIpBytes[$i] -ne $networkBytes[$i]) { return $false }
        }
    }
    return $true
}

function Get-FailedAuthXPathQuery {
    # XPath for all failed authentication, logon, and access events
    return @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4625 or EventID=4771 or EventID=4776 or EventID=4768 or EventID=4770)]] 
    </Select>
  </Query>
</QueryList>
"@
}

function Get-CategoryXPathQuery {
    param([string]$Category, [string]$IpAddress, [bool]$IsCidr)
    
    if ($IsCidr) {
        $xpath = switch ($Category) {
            'RDP' { "*[System[(EventID=4624 or EventID=4625)]] and *[EventData[Data[@Name='LogonType']='10']]" }
            { $_ -in 'FileShare', 'Authentication' } { "*[System[(EventID=4624 or EventID=4625)]] and *[EventData[Data[@Name='LogonType']='3']]" }
            'AllEvents' { 
                "*[EventData[Data[@Name='IpAddress'] and (Data[@Name='IpAddress']!='-') and (Data[@Name='IpAddress']!='::1') and (Data[@Name='IpAddress']!='127.0.0.1')]]" 
            }
            default { throw "Unknown category '$Category'" }
        }
    } else {
        $xpath = switch ($Category) {
            'RDP' { "*[System[(EventID=4624 or EventID=4625)]] and *[EventData[Data[@Name='IpAddress']='$IpAddress']] and *[EventData[Data[@Name='LogonType']='10']]" }
            { $_ -in 'FileShare', 'Authentication' } { "*[System[(EventID=4624 or EventID=4625)]] and *[EventData[Data[@Name='IpAddress']='$IpAddress']] and *[EventData[Data[@Name='LogonType']='3']]" }
            'AllEvents' { 
                "*[EventData[Data[@Name='IpAddress']='$IpAddress']]" 
            }
            default { throw "Unknown category '$Category'" }
        }
    }
    return @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      $xpath
    </Select>
  </Query>
</QueryList>
"@
}

function Get-EventDataByName {
    param(
        [Parameter(Mandatory = $true)] [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        [Parameter(Mandatory = $true)] [string]$FieldName,
        [Parameter(Mandatory = $false)] [string]$DefaultValue = "N/A"
    )
    try {
        $eventXml = [xml]$Event.ToXml()
        $dataNode = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
        if ($null -ne $dataNode -and -not [string]::IsNullOrWhiteSpace($dataNode.'#text')) {
            $value = $dataNode.'#text'
            if ($value -eq '-' -or $value -eq '%%2313') { return $DefaultValue }
            return $value
        }
        return $DefaultValue
    } catch {
        return $DefaultValue
    }
}

function Export-MySQL {
    param(
        [object[]]$Events,
        [string]$Path,
        [string[]]$DisplayColumns
    )
    
    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { 
        New-Item -Path $dir -ItemType Directory -Force | Out-Null 
    }
    
    $tableName = "security_events"
    $sqlCommands = @()
    
    $columnDefinitions = @()
    $columnDefinitions += "id INT AUTO_INCREMENT PRIMARY KEY"
    $columnDefinitions += "time_created DATETIME"
    $columnDefinitions += "event_id INT"
    $columnDefinitions += "account VARCHAR(255)"
    $columnDefinitions += "source_ip VARCHAR(45)"
    $columnDefinitions += "computer VARCHAR(255)"
    $columnDefinitions += "port VARCHAR(10)"
    $columnDefinitions += "logon_type VARCHAR(50)"
    $columnDefinitions += "auth_package VARCHAR(100)"
    $columnDefinitions += "logon_process VARCHAR(100)"
    $columnDefinitions += "status VARCHAR(50)"
    $columnDefinitions += "sub_status VARCHAR(50)"
    $columnDefinitions += "message TEXT"
    $columnDefinitions += "result TEXT"
    $columnDefinitions += "record_id BIGINT"
    $columnDefinitions += "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"
    
    $createTableSQL = @"
CREATE TABLE IF NOT EXISTS `$tableName` (
    $($columnDefinitions -join ",`n    ")
);
"@
    $sqlCommands += $createTableSQL
    $sqlCommands += ""

    foreach ($event in $Events) {
        $columns = @()
        $values = @()
        
        foreach ($prop in $event.PSObject.Properties) {
            if ($prop.Name -eq 'PSTypeName') { continue }
            
            $value = $prop.Value
            if ($null -eq $value) { $value = '' }
            
            $escapedValue = $value.ToString().Replace("'", "''").Replace("\", "\\")
            
            switch ($prop.Name) {
                'TimeCreated' { 
                    $columns += 'time_created'
                    $values += "'$($value.ToString('yyyy-MM-dd HH:mm:ss'))'"
                }
                'EventId' { 
                    $columns += 'event_id'
                    $values += if ($value -eq 'N/A') { 'NULL' } else { $value }
                }
                'Account' { 
                    $columns += 'account'
                    $values += "'$escapedValue'"
                }
                'SourceIP' { 
                    $columns += 'source_ip'
                    $values += "'$escapedValue'"
                }
                'Computer' { 
                    $columns += 'computer'
                    $values += "'$escapedValue'"
                }
                'Port' { 
                    $columns += 'port'
                    $values += if ($value -eq 'N/A') { 'NULL' } else { "'$escapedValue'" }
                }
                'LogonType' { 
                    $columns += 'logon_type'
                    $values += "'$escapedValue'"
                }
                'AuthPackage' { 
                    $columns += 'auth_package'
                    $values += "'$escapedValue'"
                }
                'LogonProcess' { 
                    $columns += 'logon_process'
                    $values += "'$escapedValue'"
                }
                'Status' { 
                    $columns += 'status'
                    $values += if ($value -eq 'N/A') { 'NULL' } else { "'$escapedValue'" }
                }
                'SubStatus' { 
                    $columns += 'sub_status'
                    $values += if ($value -eq 'N/A') { 'NULL' } else { "'$escapedValue'" }
                }
                'Message' { 
                    $columns += 'message'
                    $values += "'$escapedValue'"
                }
                'Result' { 
                    $columns += 'result'
                    $values += "'$escapedValue'"
                }
                'RecordId' { 
                    $columns += 'record_id'
                    $values += if ($value -eq 'N/A') { 'NULL' } else { $value }
                }
            }
        }
        
        $insertSQL = "INSERT INTO `$tableName` ($($columns -join ', ')) VALUES ($($values -join ', '));"
        $sqlCommands += $insertSQL
    }
    
    $sqlCommands += ""
    $sqlCommands += "-- Total events: $($Events.Count)"
    $sqlCommands += "-- Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $sqlCommands += "-- Script: Get-SecurityEventsByIP.ps1"
    
    $sqlCommands | Set-Content -Path $Path -Encoding UTF8
}

function ConvertTo-ProcessedEvent {
    param([Parameter(Mandatory = $true)] [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event, [bool]$ShouldDecode)
    try {
        $eventTargetUser = Get-EventDataByName -Event $Event -FieldName 'TargetUserName'
        $eventTargetDomain = Get-EventDataByName -Event $Event -FieldName 'TargetDomainName'
        $eventSourceIp = Get-EventDataByName -Event $Event -FieldName 'IpAddress'
        $eventIpPort = Get-EventDataByName -Event $Event -FieldName 'IpPort'
        $eventLogonType = Get-EventDataByName -Event $Event -FieldName 'LogonType'
        $eventAuthPackage = Get-EventDataByName -Event $Event -FieldName 'AuthenticationPackageName'
        $eventLogonProcess = Get-EventDataByName -Event $Event -FieldName 'LogonProcessName'
        $eventComputer = $Event.MachineName

        $eventFailureReason = Get-EventDataByName -Event $Event -FieldName 'FailureReason' -DefaultValue ""
        $eventStatus = Get-EventDataByName -Event $Event -FieldName 'Status' -DefaultValue ""
        $eventSubStatus = Get-EventDataByName -Event $Event -FieldName 'SubStatus' -DefaultValue ""

        $fullAccount = if ($eventTargetDomain -ne "N/A" -and $eventTargetUser -ne "N/A") { "$eventTargetDomain\$eventTargetUser" } elseif ($eventTargetUser -ne "N/A") { $eventTargetUser } else { "N/A" }

        $eventMessage = if ($Event.Message) { ($Event.Message -replace "`r`n|`r|`n", " " -replace "\s+", " ").Trim() } else { "No description" }

        $eventResult = switch ($Event.Id) {
            4624 { "Logon successful" }
            4625 { 
                if (-not $ShouldDecode) {
                    $parts = @()
                    if ($eventFailureReason) { $parts += "FailureReason=$eventFailureReason" }
                    if ($eventStatus -ne "") { $parts += "Status=$eventStatus" }
                    if ($eventSubStatus -ne "") { $parts += "SubStatus=$eventSubStatus" }
                    if ($parts.Count -eq 0) { "Logon failed" } else { "Logon failed: $($parts -join '; ')" }
                } else {
                    if ($eventFailureReason -and $FailureReasons.ContainsKey($eventFailureReason)) { "Logon failed: $($FailureReasons[$eventFailureReason])" }
                    elseif ($eventStatus -and $StatusCodes.ContainsKey($eventStatus)) { "Logon failed: $($StatusCodes[$eventStatus])" }
                    elseif ($eventSubStatus -and $StatusCodes.ContainsKey($eventSubStatus)) { "Logon failed: $($StatusCodes[$eventSubStatus])" }
                    elseif ($eventFailureReason) { "Logon failed: $eventFailureReason" }
                    else { "Logon failed" }
                }
            }
            4634 { "Logoff" }
            4648 { "Explicit credentials logon" }
            4672 { "Special privileges assigned" }
            4720 { "User account created" }
            4722 { "User account enabled" }
            4728 { "Member added to security-enabled group" }
            4732 { "Member added to local group" }
            4768 { "Kerberos TGT request" }
            4770 { "Kerberos service ticket renewal failed" }
            4771 { "Kerberos pre-authentication failed" }
            4776 { "Credential validation failed" }
            default { "Event ID $($Event.Id)" }
        }

        $logonTypeDescription = switch ($eventLogonType) {
            "2"  { "Interactive (2)" }
            "3"  { "Network (3)" }
            "4"  { "Batch (4)" }
            "5"  { "Service (5)" }
            "7"  { "Unlock (7)" }
            "8"  { "NetworkCleartext (8)" }
            "9"  { "NewCredentials (9)" }
            "10" { "RemoteInteractive/RDP (10)" }
            "11" { "CachedInteractive (11)" }
            default { $eventLogonType }
        }

        return [PSCustomObject]@{
            PSTypeName      = 'SecurityEvent.IPAnalysis'
            TimeCreated     = $Event.TimeCreated
            EventId         = $Event.Id
            Account         = $fullAccount
            SourceIP        = $eventSourceIp
            Computer        = $eventComputer
            Port            = $eventIpPort
            LogonType       = $logonTypeDescription
            AuthPackage     = $eventAuthPackage
            LogonProcess    = $eventLogonProcess
            Status          = $eventStatus
            SubStatus       = $eventSubStatus
            Message         = $eventMessage
            RecordId        = $Event.RecordId
            Result          = $eventResult
        }
    } catch {
        Write-Warning "Failed to process event RecordId=$($Event.RecordId): $_"
        return $null
    }
}

function Get-ColumnsToDisplay {
    param([string[]]$ShowColumns, [string[]]$HideColumns, [string[]]$AllColumns)
    $show = if ($ShowColumns) { $ShowColumns | ForEach-Object { $_.Trim() } } else { @() }
    $hide = if ($HideColumns) { $HideColumns | ForEach-Object { $_.Trim() } } else { @() }

    $invalidShow = $show | Where-Object { $_ -notin $AllColumns }
    $invalidHide = $hide | Where-Object { $_ -notin $AllColumns }
    if ($invalidShow) { throw "Invalid -ShowColumns: $($invalidShow -join ', ')" }
    if ($invalidHide) { throw "Invalid -HideColumns: $($invalidHide -join ', ')" }

    if ($show.Count -gt 0) {
        $cols = $show | Select-Object -Unique
        if ($cols -contains 'Result') { $cols = @($cols | Where-Object { $_ -ne 'Result' }) + @('Result') }
        return $cols
    } else {
        $cols = $AllColumns
        if ($hide.Count -gt 0) { $cols = $cols | Where-Object { $_ -notin $hide } }
        if ($cols -contains 'Result') { $cols = @($cols | Where-Object { $_ -ne 'Result' }) + @('Result') }
        return $cols
    }
}

function Get-SummaryStatistics {
    param([object[]]$Events)
    $minTime = ($Events | Measure-Object TimeCreated -Minimum).Minimum
    $maxTime = ($Events | Measure-Object TimeCreated -Maximum).Maximum

    $eventIdGroups = $Events | Group-Object EventId | Sort-Object Count -Descending
    $accountGroups = $Events | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10
    $ipGroups = $Events | Group-Object SourceIP | Sort-Object Count -Descending
    $logonTypeGroups = $Events | Group-Object LogonType | Sort-Object Count -Descending

    return [PSCustomObject]@{
        TotalEvents = $Events.Count
        PeriodStart = $minTime
        PeriodEnd   = $maxTime
        EventIdGroups = $eventIdGroups
        AccountGroups = $accountGroups
        IpGroups      = $ipGroups
        LogonTypeGroups = $logonTypeGroups
    }
}

function Export-Results {
    param(
        [object[]]$Events,
        [string]$Path,
        [string]$Format,
        [string[]]$DisplayColumns
    )

    $dir = Split-Path $Path -Parent
    if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }

    $stats = Get-SummaryStatistics -Events $Events

    switch ($Format) {
        'CSV' {
            $Events | Select-Object $DisplayColumns | Export-Csv -Path $Path -Encoding UTF8 -NoTypeInformation
        }
        'JSON' {
            $output = @{
                Events = $Events | Select-Object $DisplayColumns
                Summary = $stats
            }
            $output | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding UTF8
        }
        'MySQL' {
            Export-MySQL -Events $Events -Path $Path -DisplayColumns $DisplayColumns
        }
        'Markdown' {
            $lines = @()
            $lines += "# Security Events Report"
            $lines += ""
            $lines += "## Summary"
            $lines += ""
            $lines += "- **Total events**: $($stats.TotalEvents)"
            $lines += "- **Period**: $($stats.PeriodStart) - $($stats.PeriodEnd)"
            $lines += ""

            $lines += "### EventID Distribution"
            $lines += ""
            $lines += "| EventID | Count |"
            $lines += "|---------|-------|"
            foreach ($item in $stats.EventIdGroups) {
                $lines += "| $($item.Name) | $($item.Count) |"
            }
            $lines += ""

            $lines += "### LogonType Distribution"
            $lines += ""
            $lines += "| LogonType | Count |"
            $lines += "|-----------|-------|"
            foreach ($item in $stats.LogonTypeGroups) {
                $lines += "| $($item.Name) | $($item.Count) |"
            }
            $lines += ""

            $lines += "### Top Accounts"
            $lines += ""
            $lines += "| Account | Count |"
            $lines += "|---------|-------|"
            foreach ($item in $stats.AccountGroups) {
                $lines += "| $($item.Name) | $($item.Count) |"
            }
            $lines += ""
            $lines += "## Events"
            $lines += ""
            $lines += "| " + ($DisplayColumns -join " | ") + " |"
            $lines += "| " + ($DisplayColumns | ForEach-Object { "---" }) -join " | " + " |"
            foreach ($event in $Events) {
                $row = $event | Select-Object $DisplayColumns
                $values = @()
                foreach ($prop in $row.PSObject.Properties) {
                    $val = if ($null -eq $prop.Value) { '' } else { $prop.Value.ToString() -replace '\|', '\|' }
                    $values += $val
                }
                $lines += "| " + ($values -join " | ") + " |"
            }
            $lines | Set-Content -Path $Path -Encoding UTF8
        }
        'HTML' {
            $eventIdLabels = ($stats.EventIdGroups | ForEach-Object { "'Event $($_.Name)'" }) -join ', '
            $eventIdData = ($stats.EventIdGroups | ForEach-Object { $_.Count }) -join ', '
            $logonTypeLabels = ($stats.LogonTypeGroups | ForEach-Object { "'$($_.Name)'" }) -join ', '
            $logonTypeData = ($stats.LogonTypeGroups | ForEach-Object { $_.Count }) -join ', '

            $accountRows = foreach ($item in $stats.AccountGroups) {
                "<tr><td>$($item.Name)</td><td>$($item.Count)</td></tr>"
            }

            $eventRows = foreach ($event in $Events) {
                $row = $event | Select-Object $DisplayColumns
                $cells = foreach ($prop in $row.PSObject.Properties) {
                    $val = if ($null -eq $prop.Value) { '' } else { $prop.Value.ToString() }
                    if ($val -like "*failed*") {
                        "<td class='danger'>$val</td>"
                    } else {
                        "<td>$val</td>"
                    }
                }
                "<tr>$($cells -join '')</tr>"
            }

            $headerRow = ($DisplayColumns | ForEach-Object { "<th>$_</th>" }) -join ''

            $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Events Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        :root { --bg: #fff; --text: #333; --card: #f8f9fa; --border: #dee2e6; --danger: #dc3545; }
        @media (prefers-color-scheme: dark) {
            :root { --bg: #121212; --text: #e0e0e0; --card: #1e1e1e; --border: #333; }
        }
        body { font-family: system-ui, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; }
        .header { text-align: center; margin-bottom: 30px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid var(--border); }
        th { background: var(--card); }
        .danger { color: var(--danger); font-weight: bold; }
        .chart-container { height: 250px; margin-top: 10px; }
        h2 { border-bottom: 1px solid var(--border); padding-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Events Report</h1>
            <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
        </div>

        <div class="grid">
            <div class="card">
                <h3>Summary</h3>
                <p><strong>Total events:</strong> $($stats.TotalEvents)</p>
                <p><strong>Period:</strong> $($stats.PeriodStart) — $($stats.PeriodEnd)</p>
            </div>
            <div class="card">
                <h3>EventID Distribution</h3>
                <div class="chart-container"><canvas id="eventIdChart"></canvas></div>
            </div>
            <div class="card">
                <h3>LogonType Distribution</h3>
                <div class="chart-container"><canvas id="logonTypeChart"></canvas></div>
            </div>
        </div>

        <h2>Top Accounts</h2>
        <table>
            <thead><tr><th>Account</th><th>Count</th></tr></thead>
            <tbody>$($accountRows -join '')</tbody>
        </table>

        <h2>Events</h2>
        <table>
            <thead><tr>$headerRow</tr></thead>
            <tbody>$($eventRows -join '')</tbody>
        </table>
    </div>

    <script>
        const eventIdCtx = document.getElementById('eventIdChart').getContext('2d');
        new Chart(eventIdCtx, {
            type: 'pie',
            data: {
                labels: [$eventIdLabels],
                datasets: [{
                    data: [$eventIdData],
                    backgroundColor: ['#ff6384', '#36a2eb', '#cc65fe', '#ffce56', '#4bc0c0']
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });

        const logonTypeCtx = document.getElementById('logonTypeChart').getContext('2d');
        new Chart(logonTypeCtx, {
            type: 'doughnut',
            data: {
                labels: [$logonTypeLabels],
                datasets: [{
                    data: [$logonTypeData],
                    backgroundColor: ['#ff9f40', '#ffcd56', '#4bc0c0', '#ff6384', '#36a2eb']
                }]
            },
            options: { responsive: true, maintainAspectRatio: false }
        });
    </script>
</body>
</html>
"@
            $html | Set-Content -Path $Path -Encoding UTF8
        }
        'Text' {
            $Events |
                Sort-Object TimeCreated -Descending |
                Format-Table -AutoSize -Wrap -Property $DisplayColumns |
                Out-File -FilePath $Path -Encoding UTF8 -Width 4096 -Force

            $summaryText = @"

========================================
PROCESSING SUMMARY
========================================
Total events: $($stats.TotalEvents)
Period: $($stats.PeriodStart) - $($stats.PeriodEnd)

EventID distribution:
$($stats.EventIdGroups | Format-Table Name, Count -AutoSize | Out-String)

Source IP distribution:
$($stats.IpGroups | Format-Table Name, Count -AutoSize | Out-String)

LogonType distribution:
$($stats.LogonTypeGroups | Format-Table Name, Count -AutoSize | Out-String)

Top Accounts:
$($stats.AccountGroups | Format-Table Name, Count -AutoSize | Out-String)
"@
            Add-Content -Path $Path -Value $summaryText -Encoding UTF8
        }
    }
}
#endregion

#region Main Logic

try {
    if (-not (Test-AdministratorPrivileges)) { throw "Run as Administrator" }
    if (-not (Test-SecurityLogAvailability)) { throw "Security log unavailable" }

    if ($IpAddress) {
        $queryXml = Get-CategoryXPathQuery -Category $Category -IpAddress $baseIp -IsCidr $isCidr
    } else {
        $queryXml = Get-FailedAuthXPathQuery
        Write-Host "Collecting all failed authentication events..." -ForegroundColor Yellow
    }
    
    $rawEvents = Get-WinEvent -FilterXml ([xml]$queryXml) -MaxEvents $MaxEvents -ErrorAction Stop

    if ($finalStartTime -or $finalEndTime) {
        $rawEvents = $rawEvents | Where-Object {
            $evtTime = $_.TimeCreated
            (! $finalStartTime -or $evtTime -ge $finalStartTime) -and
            (! $finalEndTime -or $evtTime -le $finalEndTime)
        }
    }

    if ($isCidr) {
        $networkBytes = $ipParsed.GetAddressBytes()
        $addressFamily = $ipParsed.AddressFamily
        $filteredEvents = @()
        
        foreach ($event in $rawEvents) {
            $ipStr = Get-EventDataByName -Event $event -FieldName 'IpAddress' -DefaultValue ""
            if ($ipStr -eq "N/A" -or $ipStr -eq "::1" -or $ipStr -eq "127.0.0.1") { continue }
            
            $evtIp = $null
            if ([System.Net.IPAddress]::TryParse($ipStr, [ref]$evtIp)) {
                if ($evtIp.AddressFamily -eq $addressFamily) {
                    $evtBytes = $evtIp.GetAddressBytes()
                    if (Test-IpInCidr -eventIpBytes $evtBytes -networkBytes $networkBytes -prefixLength $cidrPrefix) {
                        $filteredEvents += $event
                    }
                }
            }
        }
        $rawEvents = $filteredEvents
    }

    if ($rawEvents.Count -eq 0) {
        $msg = if ($IpAddress) { "No events found for: $IpAddress" } else { "No failed authentication events found in the specified time period." }
        Set-Content -Path $OutputPath -Value $msg -Encoding UTF8
        Write-Host "`n⚠️ $msg" -ForegroundColor Yellow
        exit 0
    }

    $processed = @()
    $shouldDecode = ($Decode -eq 'Yes')
    foreach ($e in $rawEvents) {
        $p = ConvertTo-ProcessedEvent -Event $e -ShouldDecode $shouldDecode
        if ($p) { $processed += $p }
    }

    if ($processed.Count -eq 0) { throw "No events processed" }

    $columns = Get-ColumnsToDisplay -ShowColumns $ShowColumns -HideColumns $HideColumns -AllColumns $AllPossibleColumns
    Export-Results -Events $processed -Path $OutputPath -Format $OutputFormat -DisplayColumns $columns

    if ($ShowOutput) {
        Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
        Write-Host "SECURITY EVENTS (first 20 shown)" -ForegroundColor Cyan
        Write-Host ("=" * 80) -ForegroundColor Cyan
        $processed | Select-Object -First 20 | Format-Table -AutoSize -Wrap -Property $columns
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "Total events: $($processed.Count) | Saved to: $OutputPath" -ForegroundColor Green
    } else {
        Write-Host "`n✅ Results saved to: $OutputPath" -ForegroundColor Green
        Write-Host "   Format: $OutputFormat | Events: $($processed.Count)" -ForegroundColor Cyan
    }

} catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

#endregion
