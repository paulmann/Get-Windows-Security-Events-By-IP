#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Private: query execution engine (local / remote / EVTX)
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

<#
    Runs on every remote host. Returns a serializable hashtable so results
    survive CLIXML remoting without class/type dependencies on the target.

    The query is executed ONE Select at a time: a missing optional channel
    (Sysmon not installed, RDP log absent on a DC, firewall log disabled) must
    not fail the whole sweep. Each Select produces its own log detail row.
#>
$script:WinSecRemoteQueryBlock = {
    param([string]$QueryXmlText, [int]$MaxEvents, [bool]$IncludeMessage)

    $ErrorActionPreference = 'Stop'
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $payload = [System.Collections.Generic.List[hashtable]]::new()
    $details = [System.Collections.Generic.List[hashtable]]::new()

    function Get-RemoteWinSecErrorKind {
        param($ErrorRecord)
        $ex = $ErrorRecord.Exception
        while ($ex -and $ex.InnerException) { $ex = $ex.InnerException }
        $win32 = $ex.HResult -band 0xFFFF
        if ($ex -is [System.ComponentModel.Win32Exception]) { $win32 = $ex.NativeErrorCode }
        if ($ex -is [System.UnauthorizedAccessException] -or $win32 -eq 5) { return 'Skipped' }
        if ($win32 -in 2, 3, 15007) { return 'Skipped' }
        if ($ex.Message -match 'No events (were found|match)|No matching events') { return 'NoEvents' }
        if ($ex.Message -match 'channel was not found|cannot find|does not exist|not enabled|there is not an event log') { return 'Skipped' }
        return 'Failed'
    }

    try {
        $doc = [xml]$QueryXmlText
        $selects = @($doc.SelectNodes("//*[local-name()='Select']"))
        if ($selects.Count -eq 0) { throw 'Query contains no Select statements.' }

        foreach ($sel in $selects) {
            $selPath = $sel.GetAttribute('Path')
            $logName = if ($selPath -match '^(?<log>[^!]+)!') { $Matches['log'] } else { $selPath }
            if (-not $logName) { $logName = 'unknown' }
            $inner = [System.Security.SecurityElement]::Escape($sel.InnerText)
            $pathEsc = [System.Security.SecurityElement]::Escape($selPath)
            $single = '<QueryList><Query Id="0" Path="{0}"><Select Path="{0}">{1}</Select></Query></QueryList>' -f $pathEsc, $inner

            $partSw = [System.Diagnostics.Stopwatch]::StartNew()
            $partCount = 0
            try {
                $params = @{ FilterXml = [xml]$single; ErrorAction = 'Stop' }
                if ($MaxEvents -gt 0) { $params.MaxEvents = $MaxEvents }
                $records = @(Get-WinEvent @params)
                foreach ($r in $records) {
                    $h = @{
                        Xml      = $r.ToXml()
                        Computer = $r.MachineName
                        RecordId = $r.RecordId
                        TimeUtc  = $r.TimeCreated.ToUniversalTime()
                        LogName  = $r.LogName
                    }
                    if ($IncludeMessage) {
                        try { $h.Message = $r.Message } catch { $h.Message = $null }
                    }
                    $payload.Add($h)
                    $partCount++
                }
                $partStatus = $partCount -gt 0 ? 'Completed' : 'NoEvents'
                $partError = $null
            }
            catch {
                $partStatus = Get-RemoteWinSecErrorKind $_
                $partError = $_.Exception.Message
            }
            $partSw.Stop()
            $details.Add(@{
                LogName     = $logName
                Status      = $partStatus
                EventsFound = $partCount
                Error       = $partError
                DurationMs  = $partSw.Elapsed.TotalMilliseconds
            })
        }
    }
    catch {
        $sw.Stop()
        return @{
            Computer   = $env:COMPUTERNAME
            Status     = 'Failed'
            Error      = $_.Exception.Message
            Events     = @()
            LogDetails = @()
            DurationMs = $sw.Elapsed.TotalMilliseconds
        }
    }

    $sw.Stop()
    $failed = @($details | Where-Object { $_.Status -eq 'Failed' })
    $good   = @($details | Where-Object { $_.Status -in 'Completed', 'NoEvents', 'Skipped' })
    $status = if ($payload.Count -gt 0) { 'Completed' }
              elseif ($failed.Count -gt 0 -and $good.Count -eq 0) { 'Failed' }
              elseif ($failed.Count -gt 0) { 'Completed' }
              elseif (@($details | Where-Object { $_.Status -eq 'Skipped' }).Count -eq $details.Count) { 'Skipped' }
              else { 'NoEvents' }

    @{
        Computer   = $env:COMPUTERNAME
        Status     = $status
        Error      = ($failed.Count -gt 0) ? (($failed | ForEach-Object { '{0}: {1}' -f $_.LogName, $_.Error }) -join '; ') : $null
        Events     = $payload.ToArray()
        LogDetails = $details.ToArray()
        DurationMs = $sw.Elapsed.TotalMilliseconds
    }
}

<#
    .SYNOPSIS
        Splits a QueryList into one single-Select query per log channel.
    .DESCRIPTION
        Get-WinEvent fails the whole FilterXml query when any referenced channel
        is missing. Executing Select-by-Select turns "Sysmon is not installed"
        from a fatal error into one Skipped row and keeps every other channel.
    .OUTPUTS
        PSCustomObject: LogName, SelectPath, QueryXml ([xml])
#>
function Split-WinSecQueryXml {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][xml] $Query)

    $queryPath = ''
    $queryNode = $Query.SelectSingleNode("//*[local-name()='Query']")
    if ($queryNode) { $queryPath = $queryNode.GetAttribute('Path') }

    $selects = @($Query.SelectNodes("//*[local-name()='Select']"))
    foreach ($sel in $selects) {
        $selPath = $sel.GetAttribute('Path')
        $logName = if ($selPath -match '^(?<log>[^!]+)!') { $Matches['log'] } else { $selPath }
        if (-not $logName) { $logName = 'unknown' }
        $inner   = [System.Security.SecurityElement]::Escape($sel.InnerText)
        $pathEsc = [System.Security.SecurityElement]::Escape($selPath)
        $rootEsc = [System.Security.SecurityElement]::Escape($queryPath)
        $text = '<QueryList><Query Id="0" Path="{0}"><Select Path="{1}">{2}</Select></Query></QueryList>' -f $rootEsc, $pathEsc, $inner
        [pscustomobject]@{
            LogName    = $logName
            SelectPath = $selPath
            QueryXml   = [xml]$text
        }
    }
}

<#
    .SYNOPSIS
        Classifies an event-log error WITHOUT depending on the OS display language.
    .DESCRIPTION
        Uses HResult / Win32 error code first (5 = access denied,
        15007 = ERROR_EVT_CHANNEL_NOT_FOUND, 2/3 = not found) and falls back to
        the message only for unknown codes. Returns Completed-like verbs:
        'NoEvents' (empty result, success), 'Skipped' (channel/log unavailable,
        not a failure) or 'Failed' (real error).
#>
function Get-WinSecLogErrorKind {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $ErrorRecord)

    $ex = $ErrorRecord.Exception
    while ($ex -and $ex.InnerException) { $ex = $ex.InnerException }

    $win32 = $ex.HResult -band 0xFFFF
    if ($ex -is [System.ComponentModel.Win32Exception]) { $win32 = $ex.NativeErrorCode }

    if ($ex -is [System.UnauthorizedAccessException] -or $win32 -eq 5) { return 'Skipped' }
    if ($win32 -in 2, 3, 15007) { return 'Skipped' }
    if ($ex.GetType().Name -match 'EventLogNotFoundException') { return 'Skipped' }
    if ($ex.Message -match 'No events (were found|match)|No matching events') { return 'NoEvents' }
    if ($ex.Message -match 'channel was not found|cannot find the (log|channel)|does not exist|is not enabled|there is not an event log') { return 'Skipped' }
    return 'Failed'
}

<#
    .SYNOPSIS
        Runs ONE single-Select query against a live channel or an EVTX file.
#>
function Invoke-WinSecLogQueryPart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Part,
        [int] $MaxEvents = 0,
        [string] $FilePath
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $records = @()
    try {
        $params = @{ FilterXml = $Part.QueryXml; ErrorAction = 'Stop' }
        if ($FilePath) { $params.Path = $FilePath }
        if ($MaxEvents -gt 0) { $params.MaxEvents = $MaxEvents }
        $records = @(Get-WinEvent @params)
        $status = $records.Count -gt 0 ? 'Completed' : 'NoEvents'
        $errorText = $null
    }
    catch {
        $status = Get-WinSecLogErrorKind $_
        $errorText = $_.Exception.Message
    }
    $sw.Stop()

    [pscustomobject]@{
        LogName     = $Part.LogName
        Status      = $status
        EventsFound = $records.Count
        Error       = $errorText
        DurationMs  = $sw.Elapsed.TotalMilliseconds
        Records     = $records
    }
}

<#
    .SYNOPSIS
        Executes a WinSecHunter query against local logs, remote hosts or EVTX files.
    .DESCRIPTION
        - Local:  Get-WinEvent -FilterXml per log channel (no WinRM dependency).
        - Remote: Invoke-Command over WinRM, parallel per host
                  (ForEach-Object -Parallel), with retry and per-host status.
                  -CimSession targets run sequentially (session handles are
                  not safe to fan out across runspaces).
        - Files:  Get-WinEvent -Path per Select per EVTX file (offline forensics).

        Every Select is executed separately, so a missing optional channel
        (Sysmon not installed, RDP logs on a DC, firewall log disabled) is
        reported as 'Skipped' for that channel only — never as a fatal error.
    .OUTPUTS
        PSCustomObject: .Raw (hashtable payloads) and .HostResults
        (WinSecHostResult per target, with .LogDetails per channel).
#>
function Invoke-WinSecEventQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][xml] $Query,

        [string[]] $ComputerName,
        [object[]] $CimSession,
        [pscredential] $Credential,

        [ValidateSet('Basic', 'Credssp', 'Default', 'Digest', 'Negotiate', 'NegotiateWithImplicitCredential')]
        [string] $Authentication = 'Default',

        [object] $SessionOption,

        [string[]] $Path,

        [int] $MaxEvents = 0,          # 0 = unlimited; per log channel
        [int] $ThrottleLimit = 8,
        [switch] $IncludeMessage,
        [int] $RetryCount = 1,

        # EVTX file mode needs its own query (Select Path = file)
        [AllowNull()][hashtable] $LogEventIds,
        [datetime] $StartTimeUtc = [datetime]::MinValue,
        [datetime] $EndTimeUtc   = [datetime]::MinValue,
        [AllowNull()][string[]] $IpExactVariants
    )

    $raw     = [System.Collections.Generic.List[hashtable]]::new()
    $results = [System.Collections.Generic.List[WinSecHostResult]]::new()
    $queryText = $Query.OuterXml
    $incMsg = [bool]$IncludeMessage
    # A scriptblock cannot be passed through $using: into ForEach-Object -Parallel
    # (PSArgumentException). Pass its TEXT and rebuild the block in the runspace.
    $remoteSbText = $script:WinSecRemoteQueryBlock.ToString()

    $addResult = {
        param($Label, $StatusStr, $ErrorText, $Events, $DurationMs, $LogDetails)
        foreach ($h in $Events) { $raw.Add($h) }
        $hr = [WinSecHostResult]::new()
        $hr.Computer     = $Label
        $hr.Status       = [WinSecHostStatus]$StatusStr
        $hr.EventsFound  = @($Events).Count
        $hr.ErrorMessage = $ErrorText
        $hr.DurationMs   = $DurationMs
        $hr.LogDetails   = @($LogDetails)
        $results.Add($hr)
    }

    # ------------------------------------------------------------------ files
    if ($Path) {
        foreach ($file in $Path) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $resolved = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($file)
            if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
                $sw.Stop()
                & $addResult $file 'Failed' "EVTX file not found: $resolved" @() $sw.Elapsed.TotalMilliseconds @()
                continue
            }

            $parts = @(Split-WinSecQueryXml -Query $Query)
            $payload = [System.Collections.Generic.List[hashtable]]::new()
            $details = [System.Collections.Generic.List[object]]::new()
            foreach ($part in $parts) {
                $r = Invoke-WinSecLogQueryPart -Part $part -MaxEvents $MaxEvents -FilePath $resolved
                foreach ($rec in $r.Records) {
                    $h = @{
                        Xml      = $rec.ToXml()
                        Computer = $rec.MachineName ? $rec.MachineName : (Split-Path -Leaf $resolved)
                        RecordId = $rec.RecordId
                        TimeUtc  = $rec.TimeCreated.ToUniversalTime()
                        LogName  = $rec.LogName
                    }
                    if ($incMsg) { try { $h.Message = $rec.Message } catch { $h.Message = $null } }
                    $payload.Add($h)
                }
                $details.Add([pscustomobject]@{
                    LogName = $r.LogName; Status = $r.Status; EventsFound = $r.EventsFound
                    Error = $r.Error; DurationMs = $r.DurationMs
                })
            }
            $sw.Stop()

            $failed = @($details | Where-Object Status -eq 'Failed')
            $ok     = @($details | Where-Object { $_.Status -in 'Completed', 'NoEvents' })
            $status = if ($payload.Count -gt 0) { 'Completed' }
                      elseif ($failed.Count -gt 0 -and $ok.Count -eq 0) { 'Failed' }
                      elseif ($failed.Count -gt 0) { 'Completed' }
                      elseif (@($details | Where-Object Status -eq 'Skipped').Count -eq $details.Count) { 'Skipped' }
                      else { 'NoEvents' }
            $errText = ($failed.Count -gt 0) ? (($failed | ForEach-Object { '{0}: {1}' -f $_.LogName, $_.Error }) -join '; ') : $null
            & $addResult $file $status $errText $payload.ToArray() $sw.Elapsed.TotalMilliseconds $details
        }
    }
    # ----------------------------------------------------------------- remote
    elseif ($ComputerName -or $CimSession) {
        if ($ComputerName) {
            $remoteResults = $ComputerName | ForEach-Object -Parallel {
                $target = $_
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                $inner = [scriptblock]::Create($using:remoteSbText)
                $icp = @{
                    ScriptBlock  = $inner
                    ArgumentList = $using:queryText, $using:MaxEvents, $using:incMsg
                    ErrorAction  = 'Stop'
                }
                if ($using:Credential)   { $icp.Credential   = $using:Credential }
                if ($using:Authentication -ne 'Default') { $icp.Authentication = $using:Authentication }
                if ($using:SessionOption) { $icp.SessionOption = $using:SessionOption }

                $attempt = 0
                $res = $null
                while ($true) {
                    try { $res = Invoke-Command -ComputerName $target @icp; break }
                    catch {
                        $attempt++
                        if ($attempt -gt $using:RetryCount) {
                            $res = @{ Computer = $target; Status = 'Failed'; Error = $_.Exception.Message; Events = @(); LogDetails = @() }
                            break
                        }
                        Start-Sleep -Milliseconds 1500
                    }
                }
                $sw.Stop()
                $out = @{
                    RequestedComputer = $target
                    Computer          = $res.Computer
                    Status            = $res.Status
                    Error             = $res.Error
                    Events            = @($res.Events)
                    LogDetails        = @($res.LogDetails)
                    DurationMs        = $sw.Elapsed.TotalMilliseconds
                }
                Write-Progress -Activity 'WinSecHunter sweep' -Status ("{0} → {1} ({2} events)" -f $target, $res.Status, @($res.Events).Count)
                $out
            } -ThrottleLimit $ThrottleLimit

            foreach ($res in @($remoteResults)) {
                $label = $res.RequestedComputer
                if ($res.Computer -and $res.Computer -ne $label) { $label = "$label ($($res.Computer))" }
                & $addResult $label $res.Status $res.Error @($res.Events) $res.DurationMs @($res.LogDetails)
            }
        }

        if ($CimSession) {
            foreach ($cs in $CimSession) {
                $label = $cs.ComputerName
                $sw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    $icp = @{
                        CimSession   = $cs
                        ScriptBlock  = $script:WinSecRemoteQueryBlock
                        ArgumentList = $queryText, $MaxEvents, $incMsg
                        ErrorAction  = 'Stop'
                    }
                    $res = Invoke-Command @icp
                }
                catch {
                    $sw.Stop()
                    & $addResult $label 'Failed' $_.Exception.Message @() $sw.Elapsed.TotalMilliseconds @()
                    continue
                }
                $sw.Stop()
                & $addResult $label $res.Status $res.Error @($res.Events) $sw.Elapsed.TotalMilliseconds @($res.LogDetails)
            }
        }
    }
    # ------------------------------------------------------------------ local
    else {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $localName = $env:COMPUTERNAME
        if (-not $localName) {
            try { $localName = (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).Name } catch { $localName = [System.Net.Dns]::GetHostName() }
        }

        $parts = @(Split-WinSecQueryXml -Query $Query)
        $payload = [System.Collections.Generic.List[hashtable]]::new()
        $details = [System.Collections.Generic.List[object]]::new()
        foreach ($part in $parts) {
            $r = Invoke-WinSecLogQueryPart -Part $part -MaxEvents $MaxEvents
            foreach ($rec in $r.Records) {
                $h = @{
                    Xml      = $rec.ToXml()
                    Computer = $rec.MachineName
                    RecordId = $rec.RecordId
                    TimeUtc  = $rec.TimeCreated.ToUniversalTime()
                    LogName  = $rec.LogName
                }
                if ($incMsg) { try { $h.Message = $rec.Message } catch { $h.Message = $null } }
                $payload.Add($h)
            }
            $details.Add([pscustomobject]@{
                LogName = $r.LogName; Status = $r.Status; EventsFound = $r.EventsFound
                Error = $r.Error; DurationMs = $r.DurationMs
            })
        }
        $sw.Stop()

        $failed = @($details | Where-Object Status -eq 'Failed')
        $ok     = @($details | Where-Object { $_.Status -in 'Completed', 'NoEvents' })
        $status = if ($payload.Count -gt 0) { 'Completed' }
                  elseif ($failed.Count -gt 0 -and $ok.Count -eq 0) { 'Failed' }
                  elseif ($failed.Count -gt 0) { 'Completed' }
                  elseif (@($details | Where-Object Status -eq 'Skipped').Count -eq $details.Count) { 'Skipped' }
                  else { 'NoEvents' }
        $errText = ($failed.Count -gt 0) ? (($failed | ForEach-Object { '{0}: {1}' -f $_.LogName, $_.Error }) -join '; ') : $null
        & $addResult $localName $status $errText $payload.ToArray() $sw.Elapsed.TotalMilliseconds $details
    }

    [pscustomobject]@{
        Raw         = $raw.ToArray()
        HostResults = $results.ToArray()
    }
}

