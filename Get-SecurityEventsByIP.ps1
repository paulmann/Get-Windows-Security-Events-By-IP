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
 Event category: RDP, FileShare, Authentication, AllEvents. Default: 'AllEvents' when IpAddress is provided.
 Ignored when IpAddress is not specified.

.PARAMETER OutputPath
 Output file path. If not specified, outputs to screen only.
 Format is auto-detected from file extension (.txt, .csv, .json, .md, .html, .sql)

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
 Output format: Text, CSV, JSON, Markdown, HTML, MySQL. 
 Auto-detected from file extension if OutputPath is provided.

.PARAMETER ShowOutput
 Display results in console (in addition to file export).

.PARAMETER Help
 Display help information with usage examples.

.EXAMPLE
 .\Get-SecurityEventsByIP.ps1 -Help
 Shows help with usage examples

.EXAMPLE
 .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.100"
 Shows all events for specific IP on screen (all fields, all event codes)

.EXAMPLE
 .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.100" -OutputPath "report.html"
 Saves all events for specific IP to HTML file (format auto-detected)

.EXAMPLE
 .\Get-SecurityEventsByIP.ps1 -LastDays 7 -OutputFormat HTML -ShowOutput
 Collects all failed authentication events from the last 7 days

.EXAMPLE
 .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.0/24" -Category RDP -OutputPath "rdp_events.csv"
 Collects RDP events from specific CIDR range and saves to CSV

.NOTES
 Author: Mikhail Deynekin
 Email: mid1977@gmail.com
 Website: https://deynekin.com
 Version: 5.0.2
 - Added -Update parameter for self-update capability
 - Added -Version parameter
 - Fixed all @($variable).Count issues for reliability
 - Auto-format detection from file extension
 - Improved error handling and user experience
#>

#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'Operation')]
param (
    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [string]$IpAddress,

    [Parameter(Mandatory = $false, ParameterSetName = 'Update')]
    [switch]$Update,

    [Parameter(Mandatory = $false, ParameterSetName = 'Version')]
    [switch]$Version,

    [Parameter(Mandatory = $false, ParameterSetName = 'Help')]
    [switch]$Help,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [ValidateSet('RDP', 'FileShare', 'Authentication', 'AllEvents')]
    [string]$Category,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [ValidateRange(1, 100000)]
    [int]$MaxEvents = 1000,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [ValidateSet('Yes', 'No')]
    [string]$Decode = 'Yes',

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [string[]]$ShowColumns,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [string[]]$HideColumns,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [int]$LastHours,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [int]$LastDays,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [datetime]$StartTime,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [datetime]$EndTime,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [ValidateSet('Text', 'CSV', 'JSON', 'Markdown', 'HTML', 'MySQL')]
    [string]$OutputFormat,

    [Parameter(Mandatory = $false, ParameterSetName = 'Operation')]
    [switch]$ShowOutput
)


# Configuration
$Script:Config = @{
    Version = '5.0.2'
    Author = 'Mikhail Deynekin'
    Email = 'mid1977@gmail.com'
    Website = 'https://deynekin.com'
    UpdateUrl = 'https://raw.githubusercontent.com/paulmann/Get-Windows-Security-Events-By-IP/refs/heads/main/Get-SecurityEventsByIP.ps1'
}


# Handle -Update parameter
if ($Update) {
    Write-Host "`n+--------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|           Script Update Check                               |" -ForegroundColor Cyan
    Write-Host "+--------------------------------------------------------------+`n" -ForegroundColor Cyan
    Write-Host "Current version: $($Script:Config.Version)" -ForegroundColor Yellow
    Write-Host "Checking for updates from GitHub...`n" -ForegroundColor Cyan
    try {
        $latestScript = Invoke-WebRequest -Uri $Script:Config.UpdateUrl -UseBasicParsing -ErrorAction Stop
        if ($latestScript.Content) {
            $currentScriptPath = $MyInvocation.MyCommand.Path
            if (-not $currentScriptPath) { $currentScriptPath = $PSCommandPath }
            $backupPath = "$currentScriptPath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Copy-Item -Path $currentScriptPath -Destination $backupPath -Force
            Write-Host "✅ Backup created: $backupPath" -ForegroundColor Green
            $latestScript.Content | Set-Content -Path $currentScriptPath -Encoding UTF8 -Force
            Write-Host "✅ Script updated successfully!" -ForegroundColor Green
        }
    } catch {
        Write-Host "❌ Update failed: $_" -ForegroundColor Red
    }
    exit 0
}

# Handle -Version parameter
if ($Version) {
    Write-Host "`n+--------------------------------------------------------------+" -ForegroundColor Cyan
    Write-Host "|           Script Version Information                         |" -ForegroundColor Cyan
    Write-Host "+--------------------------------------------------------------+`n" -ForegroundColor Cyan
    Write-Host "Version:  $($Script:Config.Version)" -ForegroundColor Green
    Write-Host "Author:   $($Script:Config.Author)" -ForegroundColor Gray
    Write-Host "Email:    $($Script:Config.Email)" -ForegroundColor Gray
    Write-Host "Website:  $($Script:Config.Website)" -ForegroundColor Gray
    Write-Host "`nTo update: .\Get-SecurityEventsByIP.ps1 -Update" -ForegroundColor Yellow
    exit 0
}

# Handle -Help parameter
if ($Help) {
    Write-Host @"

+--------------------------------------------------------------------------+
| Get-SecurityEventsByIP.ps1 - Usage Examples & Quick Start              |
+--------------------------------------------------------------------------+

BASIC USAGE:
------------

1. Search for specific IP (all fields, all event codes, output to screen):
   .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.100"

2. Search for IP and save to file (format auto-detected from extension):
   .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.100" -OutputPath "events.csv"
   .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.100" -OutputPath "events.html"

3. Search CIDR range:
   .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.0/24" -OutputPath "network.html"

4. Get all failed authentication events (no IP filter):
   .\Get-SecurityEventsByIP.ps1 -LastDays 7 -OutputPath "failed_logins.html"

MAINTENANCE COMMANDS:
---------------------

5. Update to latest version:
   .\Get-SecurityEventsByIP.ps1 -Update

6. Check version:
   .\Get-SecurityEventsByIP.ps1 -Version

7. Show this help:
   .\Get-SecurityEventsByIP.ps1 -Help

ADVANCED USAGE:
---------------

8. Filter by time range:
   .\Get-SecurityEventsByIP.ps1 -IpAddress "10.0.0.5" -LastHours 24

9. Filter by category:
   .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.100" -Category RDP

10. Export to MySQL format:
    .\Get-SecurityEventsByIP.ps1 -LastDays 30 -OutputPath "events.sql"

For more information: $($Script:Config.Website)

"@ -ForegroundColor Cyan
    exit 0
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# === IP and Time Validation ===
$ipParsed = $null
$cidrPrefix = $null
$isCidr = $false
$baseIp = $null

# Auto-detect format from file extension if OutputPath is provided
if ($OutputPath -and -not $OutputFormat) {
    $extension = [System.IO.Path]::GetExtension($OutputPath).ToLower()
    $OutputFormat = switch ($extension) {
        '.txt'  { 'Text' }
        '.csv'  { 'CSV' }
        '.json' { 'JSON' }
        '.md'   { 'Markdown' }
        '.html' { 'HTML' }
        '.sql'  { 'MySQL' }
        default { 'Text' }
    }
    Write-Host "Auto-detected output format: $OutputFormat from extension: $extension" -ForegroundColor Cyan
}

# Set default format if still not set
if (-not $OutputFormat) {
    $OutputFormat = 'Text'
}

# Set default Category to AllEvents when IpAddress is provided and Category not specified
if ($IpAddress -and -not $PSBoundParameters.ContainsKey('Category')) {
    $Category = 'AllEvents'
    Write-Host "Using default category: AllEvents (showing all event types)" -ForegroundColor Cyan
} elseif (-not $Category) {
    $Category = 'RDP'
}

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
CREATE TABLE IF NOT EXISTS ``$tableName`` (
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

        $insertSQL = "INSERT INTO ``$tableName`` ($($columns -join ', ')) VALUES ($($values -join ', '));"
        $sqlCommands += $insertSQL
    }

    $sqlCommands += ""
    $sqlCommands += "-- Total events: $(@($Events).Count)"
    $sqlCommands += "-- Generated on: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $sqlCommands += "-- Script: Get-SecurityEventsByIP.ps1"
    $sqlCommands += "-- Author: Mikhail Deynekin (mid1977@gmail.com)"
    $sqlCommands += "-- Website: https://deynekin.com"

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
                    if (@($parts).Count -eq 0) { "Logon failed" } else { "Logon failed: $($parts -join '; ')" }
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
            "2" { "Interactive (2)" }
            "3" { "Network (3)" }
            "4" { "Batch (4)" }
            "5" { "Service (5)" }
            "7" { "Unlock (7)" }
            "8" { "NetworkCleartext (8)" }
            "9" { "NewCredentials (9)" }
            "10" { "RemoteInteractive/RDP (10)" }
            "11" { "CachedInteractive (11)" }
            default { $eventLogonType }
        }

        return [PSCustomObject]@{
            PSTypeName = 'SecurityEvent.IPAnalysis'
            TimeCreated = $Event.TimeCreated
            EventId = $Event.Id
            Account = $fullAccount
            SourceIP = $eventSourceIp
            Computer = $eventComputer
            Port = $eventIpPort
            LogonType = $logonTypeDescription
            AuthPackage = $eventAuthPackage
            LogonProcess = $eventLogonProcess
            Status = $eventStatus
            SubStatus = $eventSubStatus
            Message = $eventMessage
            RecordId = $Event.RecordId
            Result = $eventResult
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
    if ($invalidShow) { throw "Invalid -ShowColumns: $($invalidShow -join ', '). Available columns: $($AllColumns -join ', ')" }
    if ($invalidHide) { throw "Invalid -HideColumns: $($invalidHide -join ', '). Available columns: $($AllColumns -join ', ')" }

    if (@($show).Count -gt 0) {
        $cols = $show | Select-Object -Unique
        if ($cols -contains 'Result') { $cols = @($cols | Where-Object { $_ -ne 'Result' }) + @('Result') }
        return $cols
    } else {
        $cols = $AllColumns
        if (@($show).Count -gt 0) { $cols = $cols | Where-Object { $_ -notin $hide } }
        if ($cols -contains 'Result') { $cols = @($cols | Where-Object { $_ -ne 'Result' }) + @('Result') }
        return $cols
    }
}

function Get-SummaryStatistics {
    param([object[]]$Events)
    $minTime = ($Events | Measure-Object TimeCreated -Minimum).Minimum
    $maxTime = ($Events | Measure-Object TimeCreated -Maximum).Maximum

    $eventIdGroups = @($Events | Group-Object EventId | Sort-Object Count -Descending)
    $accountGroups = @($Events | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10)
    $ipGroups = @($Events | Group-Object SourceIP | Sort-Object Count -Descending)
    $logonTypeGroups = @($Events | Group-Object LogonType | Sort-Object Count -Descending)

    return [PSCustomObject]@{
        TotalEvents = @($Events).Count
        PeriodStart = $minTime
        PeriodEnd = $maxTime
        EventIdGroups = $eventIdGroups
        AccountGroups = $accountGroups
        IpGroups = $ipGroups
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
	    $lines += "- **Total events**: $(@($Events).Count)"
	    $lines += "- **Period**: $($stats.PeriodStart) - $($stats.PeriodEnd)"
	    $lines += ""

	    if (@($stats.EventIdGroups).Count -gt 0) {
	        $lines += "## EventID Distribution"
	        $lines += "| EventID | Count |"
	        $lines += "|---------|-------|"
	        foreach ($item in $stats.EventIdGroups) {
	            $itemCount = $item.Count
	            $lines += "| $($item.Name) | $itemCount |"
	        }
	        $lines += ""
	    }

	    if (@($stats.LogonTypeGroups).Count -gt 0) {
	        $lines += "## LogonType Distribution"
	        $lines += "| LogonType | Count |"
	        $lines += "|-----------|-------|"
	        foreach ($item in $stats.LogonTypeGroups) {
	            $itemCount = $item.Count
	            $lines += "| $($item.Name) | $itemCount |"
	        }
	        $lines += ""
	    }

	    if (@($stats.AccountGroups).Count -gt 0) {
	        $lines += "## Top Accounts"
	        $lines += "| Account | Count |"
	        $lines += "|---------|-------|"
	        foreach ($item in $stats.AccountGroups) {
	            $itemCount = $item.Count
	            $lines += "| $($item.Name) | $itemCount |"
	        }
	        $lines += ""
	    }

	    $lines += "## Events"
	    $lines += "| " + ($DisplayColumns -join " | ") + " |"
	    $lines += "| " + ($DisplayColumns | ForEach-Object { "---" }) -join " | " + " |"

	    foreach ($event in @($Events)) {
	        $row = $event | Select-Object $DisplayColumns
	        $values = @()
	        foreach ($prop in $row.PSObject.Properties) {
	            $val = if ($null -eq $prop.Value) { '' } else { $prop.Value.ToString() }
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
                "<tr><td>$($item.Name)</td><td>$($item.Count)</td></tr>`n"
            }

            $eventRows = foreach ($event in $Events) {
                $row = $event | Select-Object $DisplayColumns
                $cells = foreach ($prop in $row.PSObject.Properties) {
                    $val = if ($null -eq $prop.Value) { '' } else { $prop.Value.ToString() }
                    if ($val -like "*failed*") {
                        "<td style='color: #d9534f;'>$val</td>"
                    } else {
                        "<td>$val</td>"
                    }
                }
                "<tr>$($cells -join '')</tr>`n"
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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; border-bottom: 3px solid #007bff; padding-bottom: 10px; }
        h2, h3 { color: #555; }
        .summary { background: white; padding: 20px; border-radius: 5px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }
        .chart-container { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; background: white; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin: 20px 0; }
        th { background: #007bff; color: white; padding: 12px; text-align: left; position: sticky; top: 0; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f8f9fa; }
        .failed { color: #d9534f; font-weight: bold; }
        .footer { text-align: center; margin-top: 30px; color: #777; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>Security Events Report</h1>
    <p style="color: #666;">Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm') | Author: Mikhail Deynekin | <a href="https://deynekin.com">deynekin.com</a></p>

    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Total events:</strong> $($stats.TotalEvents)</p>
        <p><strong>Period:</strong> $($stats.PeriodStart) � $($stats.PeriodEnd)</p>
    </div>

    <div class="charts">
        <div class="chart-container">
            <h3>EventID Distribution</h3>
            <canvas id="eventIdChart"></canvas>
        </div>
        <div class="chart-container">
            <h3>LogonType Distribution</h3>
            <canvas id="logonTypeChart"></canvas>
        </div>
    </div>

    <h2>Top Accounts</h2>
    <table>
        <thead>
            <tr><th>Account</th><th>Count</th></tr>
        </thead>
        <tbody>
            $($accountRows -join '')
        </tbody>
    </table>

    <h2>Events</h2>
    <table>
        <thead>
            <tr>$headerRow</tr>
        </thead>
        <tbody>
            $($eventRows -join '')
        </tbody>
    </table>

    <div class="footer">
        <p>Generated by Get-SecurityEventsByIP.ps1 | Mikhail Deynekin (mid1977@gmail.com) | <a href="https://deynekin.com">https://deynekin.com</a></p>
    </div>

    <script>
        new Chart(document.getElementById('eventIdChart'), {
            type: 'bar',
            data: {
                labels: [$eventIdLabels],
                datasets: [{
                    label: 'Event Count',
                    data: [$eventIdData],
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: { responsive: true, maintainAspectRatio: true }
        });

        new Chart(document.getElementById('logonTypeChart'), {
            type: 'pie',
            data: {
                labels: [$logonTypeLabels],
                datasets: [{
                    data: [$logonTypeData],
                    backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40']
                }]
            },
            options: { responsive: true, maintainAspectRatio: true }
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
    if (-not (Test-AdministratorPrivileges)) { 
        Write-Host "`n[ERROR] This script requires Administrator privileges." -ForegroundColor Red
        Write-Host "        Please run PowerShell as Administrator and try again." -ForegroundColor Yellow
        Write-Host "`nHow to run as Administrator:" -ForegroundColor Cyan
        Write-Host "  1. Right-click PowerShell icon" -ForegroundColor White
        Write-Host "  2. Select 'Run as Administrator'" -ForegroundColor White
        Write-Host "  3. Run the script again" -ForegroundColor White
        exit 1
    }

    if (-not (Test-SecurityLogAvailability)) { 
        Write-Host "`n[ERROR] Security event log is not available or not enabled." -ForegroundColor Red
        Write-Host "        Please check Event Viewer to ensure Security log is accessible." -ForegroundColor Yellow
        exit 1
    }

    # Build query based on parameters
    if ($IpAddress) {
        $queryXml = Get-CategoryXPathQuery -Category $Category -IpAddress $baseIp -IsCidr $isCidr
        Write-Host "Searching for IP address: $IpAddress (Category: $Category)" -ForegroundColor Cyan
    } else {
        $queryXml = Get-FailedAuthXPathQuery
        Write-Host "Collecting all failed authentication events..." -ForegroundColor Yellow
    }

    # Execute query with proper error handling
    try {
        $rawEvents = Get-WinEvent -FilterXml ([xml]$queryXml) -MaxEvents $MaxEvents -ErrorAction Stop
    } catch {
        if ($_.Exception.Message -match "No events were found") {
            $msg = if ($IpAddress) { 
                "No events found for IP address: $IpAddress" 
            } else { 
                "No failed authentication events found in the specified time period." 
            }

            if ($OutputPath) {
                Set-Content -Path $OutputPath -Value $msg -Encoding UTF8
                Write-Host "`n??  $msg" -ForegroundColor Yellow
                Write-Host "    Empty result saved to: $OutputPath" -ForegroundColor Cyan
            } else {
                Write-Host "`n??  $msg" -ForegroundColor Yellow
            }

            Write-Host "`nTips:" -ForegroundColor Cyan
            Write-Host "  � Check if the IP address is correct" -ForegroundColor White
            Write-Host "  � Try expanding the time range with -LastDays or -LastHours" -ForegroundColor White
            Write-Host "  � Verify events exist in Event Viewer (Security log)" -ForegroundColor White
            Write-Host "  � Try -Category AllEvents for broader search" -ForegroundColor White
            exit 0
        } else {
            throw
        }
    }

    # Apply time filtering if specified
    if ($finalStartTime -or $finalEndTime) {
        $rawEvents = $rawEvents | Where-Object {
            $evtTime = $_.TimeCreated
            (! $finalStartTime -or $evtTime -ge $finalStartTime) -and
            (! $finalEndTime -or $evtTime -le $finalEndTime)
        }
    }

    # Apply CIDR filtering if needed
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

    # Check if any events remain after filtering
    if (@($rawEvents).Count -eq 0) {
        $msg = if ($IpAddress) { 
            "No events found for IP address: $IpAddress after applying filters" 
        } else { 
            "No failed authentication events found matching the criteria." 
        }

        if ($OutputPath) {
            Set-Content -Path $OutputPath -Value $msg -Encoding UTF8
            Write-Host "`n??  $msg" -ForegroundColor Yellow
            Write-Host "    Empty result saved to: $OutputPath" -ForegroundColor Cyan
        } else {
            Write-Host "`n??  $msg" -ForegroundColor Yellow
        }
        exit 0
    }

    # Process events
    Write-Host "Processing $(@($rawEvents).Count) events..." -ForegroundColor Cyan
    $processed = @()
    $shouldDecode = ($Decode -eq 'Yes')
    foreach ($e in $rawEvents) {
        $p = ConvertTo-ProcessedEvent -Event $e -ShouldDecode $shouldDecode
        if ($p) { $processed += $p }
    }

    if (@($rawEvents).Count -eq 0) {
        Write-Host "`n[ERROR] No events could be processed." -ForegroundColor Red
        exit 1
    }

    # Determine columns to display
    $columns = Get-ColumnsToDisplay -ShowColumns $ShowColumns -HideColumns $HideColumns -AllColumns $AllPossibleColumns

    # Export or display results
    if ($OutputPath) {
        Export-Results -Events $processed -Path $OutputPath -Format $OutputFormat -DisplayColumns $columns
        Write-Host "`n? Results saved to: $OutputPath" -ForegroundColor Green
        Write-Host "   Format: $OutputFormat | Events: $(@($processed).Count)" -ForegroundColor Cyan

        if ($ShowOutput) {
            Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
            Write-Host "SECURITY EVENTS (first 20 shown)" -ForegroundColor Cyan
            Write-Host ("=" * 80) -ForegroundColor Cyan
            $processed | Select-Object -First 20 | Format-Table -AutoSize -Wrap -Property $columns
            Write-Host ("=" * 80) -ForegroundColor Cyan
        }
    } else {
        # No OutputPath specified, display on screen only
        Write-Host "`n" + ("=" * 80) -ForegroundColor Cyan
        Write-Host "SECURITY EVENTS" -ForegroundColor Cyan
        Write-Host ("=" * 80) -ForegroundColor Cyan
        $processed | Format-Table -AutoSize -Wrap -Property $columns
        Write-Host ("=" * 80) -ForegroundColor Cyan
        Write-Host "Total events: $(@($processed).Count)" -ForegroundColor Green
        Write-Host "`nTip: Use -OutputPath to save results to a file" -ForegroundColor Yellow
    }

} catch {
    Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "`nFor help, run: .\Get-SecurityEventsByIP.ps1 -Help" -ForegroundColor Yellow
    exit 1
}

#endregion
