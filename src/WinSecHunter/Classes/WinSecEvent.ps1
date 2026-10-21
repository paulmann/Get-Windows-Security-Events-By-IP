#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Core event class
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

<#
    .SYNOPSIS
        Normalized Windows security event produced by Get-WinSecEventByIp.

    .DESCRIPTION
        One WinSecEvent instance wraps one raw event record with all fields an
        incident responder needs: normalized timestamps (source-local AND UTC),
        the matched attacker IP, extracted/decoded authentication fields, the
        catalog classification (category, ATT&CK techniques, importance) and —
        optionally — the raw XML and rendered message.

        Parsed by the private ConvertTo-WinSecEvent from either a live
        EventLogRecord or an [xml] document + metadata hashtable, which keeps
        the parser unit-testable on any platform.

    .NOTES
        Use `using module WinSecHunter` to reference the type by name in your
        own scripts. Without it, objects still work — property access, pipeline
        and formatting are unaffected.
#>
class WinSecEvent {

    # ---- Identity & provenance -------------------------------------------
    [string]   $Computer            # host the record was collected from
    [string]   $LogName             # Security, System, RCM/LSM operational, ...
    [string]   $ProviderName        # e.g. Microsoft-Windows-Security-Auditing
    [long]     $RecordId            # in-log record number (dedup + bookmarking)
    [int]     $EventId

    # ---- Time (IR-critical: always keep BOTH) ----------------------------
    [datetime] $TimeCreated         # source-machine local time, as stored
    [datetime] $TimeUtc             # authoritative UTC (computed source-side)

    # ---- Match context ----------------------------------------------------
    [string]   $MatchedIp           # which query IP/CIDR produced the hit
    [string]   $MatchedOn           # 'EventData' | 'UserData' | 'Message' | 'Xml'

    # ---- Classification ---------------------------------------------------
    [WinSecEventCategory] $Category
    [WinSecOutcome]       $Outcome
    [WinSecSeverity]      $Importance
    [string]   $EventName           # catalog display name
    [string[]] $AttackIds           # MITRE ATT&CK technique IDs
    [string]   $Description         # short catalog description/notes

    # ---- Authentication & network fields ---------------------------------
    [string]   $SourceIp            # normalized attacker/source address
    [int]     $SourcePort
    [string]   $DestinationIp
    [int]     $DestinationPort
    [WinSecDirection] $Direction
    [string]   $TargetAccount       # DOMAIN\user the action targeted
    [string]   $SubjectAccount      # DOMAIN\user that performed the action
    [WinSecLogonType] $LogonType
    [string]   $LogonId
    [string]   $AuthPackage         # Kerberos / NTLM / Negotiate
    [string]   $LogonProcess
    [string]   $Workstation         # client name (4625/4776)
    [string]   $Status              # raw status hex, e.g. 0xC000006A
    [string]   $SubStatus           # raw sub-status hex (the real reason)
    [string]   $StatusCode          # human-readable decoded status/sub-status
    [string]   $FailureReason       # raw %%2313-style reason
    [string]   $ProcessName
    [string]   $ServiceName
    [string]   $TaskName
    [string]   $ObjectName            # file/share/registry path when present
    [string]   $Protocol            # TCP/UDP for firewall & Sysmon network

    # ---- Payload ----------------------------------------------------------
    [hashtable] $Data               # ALL named EventData/UserData fields
    [string]   $Message             # rendered message (only with -IncludeMessage)
    [string]   $Xml                 # raw event XML (only with -IncludeRawXml)

    # ---- Behavior ---------------------------------------------------------
    [string] ToString() {
        $ts = $this.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
        $what = [string]::IsNullOrEmpty($this.StatusCode) ? $this.EventName : $this.StatusCode
        return ('{0}  {1,-18}  [{2}] {3,-6}  {4}' -f $ts, $this.Computer, $this.LogName.Split('/')[-1], $this.EventId, $what)
    }

    <#
        Flattened hashtable used for CSV/JSON export and remote marshaling.
        Nested Data hashtable is JSON-encoded when -FlattenData is requested.
    #>
    [System.Collections.IDictionary] ToHashtable([bool]$FlattenData = $false) {
        $h = [ordered]@{
            TimeCreated    = $this.TimeCreated.ToString('o')
            TimeUtc        = $this.TimeUtc.ToString('o')
            Computer       = $this.Computer
            LogName        = $this.LogName
            ProviderName   = $this.ProviderName
            RecordId       = $this.RecordId
            EventId        = $this.EventId
            EventName      = $this.EventName
            Category       = $this.Category.ToString()
            Outcome        = $this.Outcome.ToString()
            Importance     = $this.Importance.ToString()
            AttackIds      = ($this.AttackIds -join ',')
            MatchedIp      = $this.MatchedIp
            SourceIp       = $this.SourceIp
            SourcePort     = $this.SourcePort
            DestinationIp  = $this.DestinationIp
            DestinationPort= $this.DestinationPort
            Direction      = $this.Direction.ToString()
            TargetAccount  = $this.TargetAccount
            SubjectAccount = $this.SubjectAccount
            LogonType      = if ($this.LogonType -ne [WinSecLogonType]::Unknown) { [int]$this.LogonType } else { $null }
            LogonId        = $this.LogonId
            AuthPackage    = $this.AuthPackage
            LogonProcess   = $this.LogonProcess
            Workstation    = $this.Workstation
            Status         = $this.Status
            SubStatus      = $this.SubStatus
            StatusCode     = $this.StatusCode
            FailureReason  = $this.FailureReason
            ProcessName    = $this.ProcessName
            ServiceName    = $this.ServiceName
            TaskName       = $this.TaskName
            ObjectName     = $this.ObjectName
            Protocol       = $this.Protocol
            Message        = $this.Message
            Xml            = $this.Xml
        }
        if ($FlattenData -and $this.Data) {
            foreach ($k in $this.Data.Keys) {
                $key = "Data_$k"
                $h[$key] = $this.Data[$k]
            }
        }
        return $h
    }

    <#
        Stable dedup key: same physical record can be returned by overlapping
        queries (multi-profile, multi-IP CIDR sweeps).
    #>
    [string] GetDedupKey() {
        return ('{0}|{1}|{2}|{3}' -f $this.Computer, $this.LogName, $this.RecordId, $this.EventId)
    }
}

