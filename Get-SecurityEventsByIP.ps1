<#
.SYNOPSIS
    Retrieves Windows Security events referencing a specific IP address.

.DESCRIPTION
    This script queries the Security event log for events containing the specified
    IP address (IPv4 or IPv6), supporting RDP, FileShare, Authentication and AllEvents categories.

.PARAMETER IpAddress
    Source IP address to search for. Must be a valid IPv4 or IPv6 address.

.PARAMETER Category
    Event category: RDP, FileShare, Authentication, AllEvents. Default: 'RDP'.

.PARAMETER OutputPath
    Output file path. Default: "C:\security_events_by_ip.txt".

.PARAMETER MaxEvents
    Maximum number of events to process. Default: 1000.

.PARAMETER Decode
    Whether to decode status/failure codes into human-readable messages.
    Values: 'Yes' (default) or 'No'.

.PARAMETER ShowColumns
    Explicitly specify which columns to display (e.g., 'TimeCreated','Account','Result').
    If used, HideColumns is ignored.
    Available columns: TimeCreated, EventId, Account, SourceIP, Port, LogonType, AuthPackage, LogonProcess, Status, SubStatus, Message, Result

.PARAMETER HideColumns
    Specify columns to hide from output (e.g., 'Status','SubStatus').
    Ignored if ShowColumns is specified.

.EXAMPLE
    .\Get-SecurityEventsByIP.ps1 -IpAddress "::1" -ShowColumns TimeCreated,Account,SourceIP,Result

.EXAMPLE
    .\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.100" -HideColumns Status,SubStatus,Message

.NOTES
    Author: Mikhail Deynekin
    Email: mid1977@gmail.com
    Website: https://deynekin.com  
    Requires: PowerShell 5.1+, Administrator rights
    License: MIT
    Version: 2.6 (IPv6 + Decode + Column control)
#>

#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName = 'Default')]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Enter an IP address (e.g., 192.168.1.1 or ::1)")]
    [string]$IpAddress,

    [Parameter(Mandatory = $false, HelpMessage = "Event category: RDP, FileShare, Authentication, AllEvents")]
    [ValidateSet('RDP', 'FileShare', 'Authentication', 'AllEvents')]
    [string]$Category = 'RDP',

    [Parameter(Mandatory = $false, HelpMessage = "Path to output file")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = "C:\security_events_by_ip.txt",

    [Parameter(Mandatory = $false, HelpMessage = "Max events to process")]
    [ValidateRange(1, 100000)]
    [int]$MaxEvents = 1000,

    [Parameter(Mandatory = $false, HelpMessage = "Decode status codes into messages? (Yes/No)")]
    [ValidateSet('Yes', 'No')]
    [string]$Decode = 'Yes',

    [Parameter(Mandatory = $false, ParameterSetName = 'Show')]
    [string[]]$ShowColumns,

    [Parameter(Mandatory = $false, ParameterSetName = 'Hide')]
    [string[]]$HideColumns
)

# Validate IP address (IPv4 or IPv6)
$ipParsed = $null
if (-not [System.Net.IPAddress]::TryParse($IpAddress, [ref]$ipParsed)) {
    throw "Invalid IP address: '$IpAddress'. Must be a valid IPv4 or IPv6 address."
}
$IpAddress = $ipParsed.ToString()

# Windows Status Codes for logon failures
$script:StatusCodes = @{
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

# Failure Reason Codes
$script:FailureReasons = @{
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

# All possible column names (Workstation is excluded permanently)
$AllPossibleColumns = @(
    'TimeCreated', 'EventId', 'Account', 'SourceIP', 'Port',
    'LogonType', 'AuthPackage', 'LogonProcess', 'Status', 'SubStatus', 'Message', 'Result'
)

#region Helper Functions

function Test-AdministratorPrivileges {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-Error "Unable to verify administrator privileges: $_"
        return $false
    }
}

function Test-SecurityLogAvailability {
    try {
        $log = Get-WinEvent -ListLog 'Security' -ErrorAction Stop
        
        if (-not $log.IsEnabled) {
            Write-Warning "Security log is disabled. No data available."
            return $false
        }
        
        Write-Verbose "Security log available. Records: $($log.RecordCount)"
        return $true
    }
    catch {
        Write-Error "Cannot access Security event log: $_"
        return $false
    }
}

function Get-CategoryXPathQuery {
    param(
        [string]$Category,
        [string]$IpAddress
    )
    
    switch ($Category) {
        'RDP' {
            $xpathQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625)]]
      and
      *[EventData[Data[@Name='IpAddress']='$IpAddress']]
      and
      *[EventData[Data[@Name='LogonType']='10']]
    </Select>
  </Query>
</QueryList>
"@
            $description = "RDP logon events"
        }
        
        { $_ -in 'FileShare', 'Authentication' } {
            $xpathQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624 or EventID=4625)]]
      and
      *[EventData[Data[@Name='IpAddress']='$IpAddress']]
      and
      *[EventData[Data[@Name='LogonType']='3']]
    </Select>
  </Query>
</QueryList>
"@
            if ($_ -eq 'FileShare') {
                $description = "File/printer access events"
            }
            else {
                $description = "Network authentication events"
            }
        }
        
        'AllEvents' {
            $xpathQuery = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[EventData[Data[@Name='IpAddress']='$IpAddress']]
    </Select>
  </Query>
</QueryList>
"@
            $description = "All Security events containing the IP"
        }
        
        default {
            throw "Unknown category '$Category'"
        }
    }
    
    return @{
        Query       = $xpathQuery
        Description = $description
    }
}

function Get-EventDataByName {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        
        [Parameter(Mandatory = $true)]
        [string]$FieldName,
        
        [Parameter(Mandatory = $false)]
        [string]$DefaultValue = "N/A"
    )
    
    try {
        $eventXml = [xml]$Event.ToXml()
        $dataNode = $eventXml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
        
        if ($null -ne $dataNode -and -not [string]::IsNullOrWhiteSpace($dataNode.'#text')) {
            $value = $dataNode.'#text'
            if ($value -eq '-' -or $value -eq '%%2313') {
                return $DefaultValue
            }
            return $value
        }
        
        return $DefaultValue
    }
    catch {
        Write-Verbose "Failed to extract field '$FieldName' from event: $_"
        return $DefaultValue
    }
}

function ConvertTo-ProcessedEvent {
    param(
        [Parameter(Mandatory = $true)]
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        [Parameter(Mandatory = $true)]
        [bool]$ShouldDecode
    )
    
    try {
        $eventTargetUser = Get-EventDataByName -Event $Event -FieldName 'TargetUserName'
        $eventTargetDomain = Get-EventDataByName -Event $Event -FieldName 'TargetDomainName'
        $eventSourceIp = Get-EventDataByName -Event $Event -FieldName 'IpAddress'
        $eventIpPort = Get-EventDataByName -Event $Event -FieldName 'IpPort'
        $eventLogonType = Get-EventDataByName -Event $Event -FieldName 'LogonType'
        $eventAuthPackage = Get-EventDataByName -Event $Event -FieldName 'AuthenticationPackageName'
        $eventLogonProcess = Get-EventDataByName -Event $Event -FieldName 'LogonProcessName'
        
        $eventFailureReason = Get-EventDataByName -Event $Event -FieldName 'FailureReason' -DefaultValue ""
        $eventStatus = Get-EventDataByName -Event $Event -FieldName 'Status' -DefaultValue ""
        $eventSubStatus = Get-EventDataByName -Event $Event -FieldName 'SubStatus' -DefaultValue ""
        
        if ($eventTargetDomain -ne "N/A" -and $eventTargetUser -ne "N/A") {
            $fullAccount = "$eventTargetDomain\$eventTargetUser"
        }
        elseif ($eventTargetUser -ne "N/A") {
            $fullAccount = $eventTargetUser
        }
        else {
            $fullAccount = "N/A"
        }
        
        if ($Event.Message) {
            $eventMessage = ($Event.Message -replace "`r`n|`r|`n", " " -replace "\s+", " ").Trim()
        }
        else {
            $eventMessage = "No description"
        }
        
        $eventResult = switch ($Event.Id) {
            4624 { "Logon successful" }
            4625 { 
                if (-not $ShouldDecode) {
                    $parts = @()
                    if ($eventFailureReason) { $parts += "FailureReason=$eventFailureReason" }
                    if ($eventStatus -ne "") { $parts += "Status=$eventStatus" }
                    if ($eventSubStatus -ne "") { $parts += "SubStatus=$eventSubStatus" }
                    if ($parts.Count -eq 0) { "Logon failed" }
                    else { "Logon failed: $($parts -join '; ')" }
                }
                else {
                    if ($eventFailureReason -and $script:FailureReasons.ContainsKey($eventFailureReason)) {
                        "Logon failed: $($script:FailureReasons[$eventFailureReason])"
                    }
                    elseif ($eventStatus -and $script:StatusCodes.ContainsKey($eventStatus)) {
                        "Logon failed: $($script:StatusCodes[$eventStatus])"
                    }
                    elseif ($eventSubStatus -and $script:StatusCodes.ContainsKey($eventSubStatus)) {
                        "Logon failed: $($script:StatusCodes[$eventSubStatus])"
                    }
                    elseif ($eventFailureReason) {
                        "Logon failed: $eventFailureReason"
                    }
                    else {
                        "Logon failed"
                    }
                }
            }
            4634 { "Logoff" }
            4648 { "Explicit credentials logon" }
            4768 { "Kerberos TGT request" }
            4769 { "Kerberos service ticket" }
            4776 { "Credential validation" }
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
    }
    catch {
        Write-Warning "Failed to process event RecordId=$($Event.RecordId): $_"
        return $null
    }
}

function Get-ColumnsToDisplay {
    param(
        [string[]]$ShowColumns,
        [string[]]$HideColumns,
        [string[]]$AllColumns
    )

    # Normalize input: trim and case-insensitive comparison
    $show = if ($ShowColumns) { $ShowColumns | ForEach-Object { $_.Trim() } } else { @() }
    $hide = if ($HideColumns) { $HideColumns | ForEach-Object { $_.Trim() } } else { @() }

    # Validate column names
    $invalidShow = $show | Where-Object { $_ -notin $AllColumns }
    $invalidHide = $hide | Where-Object { $_ -notin $AllColumns }

    if ($invalidShow) {
        throw "Invalid column name(s) in -ShowColumns: $($invalidShow -join ', '). Valid: $($AllColumns -join ', ')"
    }
    if ($invalidHide) {
        throw "Invalid column name(s) in -HideColumns: $($invalidHide -join ', '). Valid: $($AllColumns -join ', ')"
    }

    if ($show.Count -gt 0) {
        # Use only ShowColumns, ensure Result is last if present
        $cols = $show | Select-Object -Unique
        if ($cols -contains 'Result') {
            $cols = @($cols | Where-Object { $_ -ne 'Result' }) + @('Result')
        }
        return $cols
    }
    else {
        # Start with all columns
        $cols = $AllColumns
        # Remove hidden ones
        if ($hide.Count -gt 0) {
            $cols = $cols | Where-Object { $_ -notin $hide }
        }
        # Ensure Result is last if present
        if ($cols -contains 'Result') {
            $cols = @($cols | Where-Object { $_ -ne 'Result' }) + @('Result')
        }
        return $cols
    }
}

function Export-EventsToFile {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ProcessedEvents,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory = $true)]
        [string[]]$DisplayColumns,
        
        [Parameter(Mandatory = $false)]
        [int]$Width = 4096
    )
    
    try {
        $outputDir = Split-Path -Path $OutputPath -Parent
        if (-not [string]::IsNullOrEmpty($outputDir) -and -not (Test-Path -Path $outputDir)) {
            New-Item -Path $outputDir -ItemType Directory -Force | Out-Null
            Write-Verbose "Created directory: $outputDir"
        }
        
        $ProcessedEvents |
            Sort-Object -Property TimeCreated -Descending |
            Format-Table -AutoSize -Wrap -Property $DisplayColumns |
            Out-File -FilePath $OutputPath -Encoding UTF8 -Width $Width -Force
        
        $minTime = ($ProcessedEvents | Measure-Object TimeCreated -Minimum).Minimum
        $maxTime = ($ProcessedEvents | Measure-Object TimeCreated -Maximum).Maximum
        
        $eventIdGroups = $ProcessedEvents | Group-Object EventId | Sort-Object Count -Descending
        $eventIdTable = $eventIdGroups | Format-Table Name, Count -AutoSize | Out-String
        
        $accountGroups = $ProcessedEvents | Group-Object Account | Sort-Object Count -Descending | Select-Object -First 10
        $accountTable = $accountGroups | Format-Table Name, Count -AutoSize | Out-String
        
        $ipGroups = $ProcessedEvents | Group-Object SourceIP | Sort-Object Count -Descending
        $ipTable = $ipGroups | Format-Table Name, Count -AutoSize | Out-String
        
        $logonTypeGroups = $ProcessedEvents | Group-Object LogonType | Sort-Object Count -Descending
        $logonTypeTable = $logonTypeGroups | Format-Table Name, Count -AutoSize | Out-String
        
        $statistics = @"

========================================
PROCESSING SUMMARY
========================================
Total events: $($ProcessedEvents.Count)
Period: $minTime - $maxTime

EventID distribution:
$eventIdTable

Source IP distribution:
$ipTable

LogonType distribution:
$logonTypeTable

Top Accounts:
$accountTable
"@
        
        Add-Content -Path $OutputPath -Value $statistics -Encoding UTF8
        
        Write-Host "`nResults successfully saved to: " -ForegroundColor Green -NoNewline
        Write-Host $OutputPath -ForegroundColor Cyan
        Write-Host "Processed events: " -ForegroundColor Green -NoNewline
        Write-Host $ProcessedEvents.Count -ForegroundColor Yellow
        
        return $true
    }
    catch {
        Write-Error "Failed to write output file '$OutputPath': $_"
        return $false
    }
}

#endregion

#region Main Script Logic

try {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  Security Events Analysis by IP" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    if (-not (Test-AdministratorPrivileges)) {
        throw "Administrator privileges are required to read Security event log. Run PowerShell as Administrator."
    }
    Write-Host "[OK] Administrator privileges confirmed" -ForegroundColor Green
    
    if (-not (Test-SecurityLogAvailability)) {
        throw "Security event log is unavailable or disabled."
    }
    Write-Host "[OK] Security log available" -ForegroundColor Green
    
    $queryInfo = Get-CategoryXPathQuery -Category $Category -IpAddress $IpAddress
    Write-Host "`nSearch parameters:" -ForegroundColor Yellow
    Write-Host "  IP Address : " -NoNewline -ForegroundColor Gray
    Write-Host $IpAddress -ForegroundColor White
    Write-Host "  Category   : " -NoNewline -ForegroundColor Gray
    Write-Host $queryInfo.Description -ForegroundColor White
    Write-Host "  Max Events : " -NoNewline -ForegroundColor Gray
    Write-Host $MaxEvents -ForegroundColor White
    Write-Host "  Decode     : " -NoNewline -ForegroundColor Gray
    Write-Host $Decode -ForegroundColor White
    
    if ($ShowColumns) {
        Write-Host "  ShowCols   : " -NoNewline -ForegroundColor Gray
        Write-Host ($ShowColumns -join ', ') -ForegroundColor White
    }
    elseif ($HideColumns) {
        Write-Host "  HideCols   : " -NoNewline -ForegroundColor Gray
        Write-Host ($HideColumns -join ', ') -ForegroundColor White
    }
    
    Write-Host "`nQuerying Security log..." -ForegroundColor Cyan
    $events = @()
    
    try {
        $events = Get-WinEvent -FilterXml ([xml]$queryInfo.Query) -MaxEvents $MaxEvents -ErrorAction Stop
        Write-Host "[OK] Found events: " -ForegroundColor Green -NoNewline
        Write-Host $events.Count -ForegroundColor Yellow
    }
    catch {
        if ($_.Exception.Message -match "No events were found") {
            Write-Host "[INFO] No events found for this IP address" -ForegroundColor Yellow
            $events = @()
        }
        else {
            throw "Query failed: $_"
        }
    }
    
    if ($events.Count -eq 0) {
        $emptyMsg = "No events found for IP: $IpAddress (Category: $Category, Decode: $Decode"
        if ($ShowColumns) { $emptyMsg += ", Show: $($ShowColumns -join ',')" }
        elseif ($HideColumns) { $emptyMsg += ", Hide: $($HideColumns -join ',')" }
        $emptyMsg += ")"
        Write-Host "`nCreating empty output file..." -ForegroundColor Cyan
        Set-Content -Path $OutputPath -Value $emptyMsg -Encoding UTF8
        Write-Host "[OK] File created: $OutputPath" -ForegroundColor Green
        exit 0
    }
    
    Write-Host "`nProcessing events..." -ForegroundColor Cyan
    $processedEvents = @()
    $errorCount = 0
    $shouldDecode = ($Decode -eq 'Yes')
    
    foreach ($event in $events) {
        $processed = ConvertTo-ProcessedEvent -Event $event -ShouldDecode $shouldDecode
        if ($null -ne $processed) {
            $processedEvents += $processed
        }
        else {
            $errorCount++
        }
    }
    
    if ($errorCount -gt 0) {
        Write-Warning "Failed to process $errorCount out of $($events.Count) events"
    }
    
    Write-Host "[OK] Successfully processed: " -ForegroundColor Green -NoNewline
    Write-Host "$($processedEvents.Count) of $($events.Count)" -ForegroundColor Yellow
    
    # Determine columns to display
    $columnsToDisplay = Get-ColumnsToDisplay -ShowColumns $ShowColumns -HideColumns $HideColumns -AllColumns $AllPossibleColumns

    Write-Host "`nSaving results..." -ForegroundColor Cyan
    $exportSuccess = Export-EventsToFile -ProcessedEvents $processedEvents -OutputPath $OutputPath -DisplayColumns $columnsToDisplay
    
    if ($exportSuccess) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "  Analysis completed successfully" -ForegroundColor Green
        Write-Host "========================================`n" -ForegroundColor Cyan
        exit 0
    }
    else {
        throw "Failed to save results to file"
    }
}
catch {
    Write-Host "`n[ERROR] Critical failure" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Error $_.Exception.Message
    Write-Host "`nStack trace:" -ForegroundColor Yellow
    Write-Host $_.ScriptStackTrace -ForegroundColor Gray
    exit 1
}
finally {
    $ErrorActionPreference = 'Continue'
}

#endregion
