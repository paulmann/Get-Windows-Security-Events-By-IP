#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Domain model classes
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

<#
    Investigation case: the unit of work for an incident responder.
    Created by New-WinSecCase, enriched by findings, exported by
    Export-WinSecInvestigation (which fills Evidence with SHA-256 hashes —
    chain of custody).
#>
class WinSecCase {
    [string]   $CaseId
    [string]   $Title
    [string]   $Description
    [string]   $Operator
    [datetime] $CreatedUtc
    [string[]] $SubjectIps          # attacker IP(s)/CIDRs under investigation
    [string[]] $ScopeHosts          # hosts in scope (empty = local)
    [System.Collections.Generic.List[string]] $Notes
    [System.Collections.Generic.List[object]] $Findings
    [System.Collections.Specialized.OrderedDictionary] $Evidence # relative path -> @{ Sha256; Bytes; WrittenUtc; Source }

    WinSecCase() {
        $this.CaseId     = 'WSC-{0:yyyyMMdd}-{1}' -f (Get-Date).ToUniversalTime(), [guid]::NewGuid().ToString('n').Substring(0, 8).ToUpperInvariant()
        $this.CreatedUtc = [datetime]::UtcNow
        $this.Notes      = [System.Collections.Generic.List[string]]::new()
        $this.Findings   = [System.Collections.Generic.List[object]]::new()
        $this.Evidence   = [ordered]@{}
        $this.Operator   = $env:USERNAME ?? $env:USER ?? 'unknown'
    }

    [void] AddNote([string]$Note) {
        $stamp = [datetime]::UtcNow.ToString('u')
        $this.Notes.Add("[$stamp] $Note")
    }

    [void] AddFinding([object]$Finding) {
        $this.Findings.Add($Finding)
    }

    [void] RegisterEvidence([string]$RelativePath, [string]$Sha256, [long]$Bytes, [string]$Source) {
        $this.Evidence[$RelativePath] = [ordered]@{
            Sha256     = $Sha256
            Bytes      = $Bytes
            WrittenUtc = [datetime]::UtcNow.ToString('o')
            Source     = $Source
        }
    }
}

<#
    Reconstructed logon session (Get-WinSecLogonSession).
    A session starts at 4624 (LogonId), ends at 4634/4647 for the same
    LogonId on the same computer; 4648 spawns linked child sessions;
    4672 marks administrative token.
#>
class WinSecSession {
    [string]   $LogonId
    [string]   $Computer
    [string]   $Account
    [WinSecLogonType] $LogonType
    [string]   $SourceIp
    [string]   $AuthPackage
    [string]   $LogonProcess
    [datetime] $StartUtc
    [datetime] $EndUtc             # [datetime]::MaxValue when still open
    [bool]     $IsAdmin            # 4672 observed for this LogonId
    [bool]     $Ended              # 4634/4647 observed
    [string[]] $ChildLogonIds      # 4648 explicit-credential pivots
    [string[]] $AttackIds
    [System.Collections.Generic.List[WinSecEvent]] $Events

    WinSecSession() {
        $this.Events       = [System.Collections.Generic.List[WinSecEvent]]::new()
        $this.ChildLogonIds= @()
        $this.AttackIds    = @()
        $this.EndUtc       = [datetime]::MaxValue
    }

    [timespan] GetDuration() {
        if ($this.EndUtc -eq [datetime]::MaxValue) { return [timespan]::MaxValue }
        return $this.EndUtc - $this.StartUtc
    }

    [string] ToString() {
        $dur = if ($this.EndUtc -eq [datetime]::MaxValue) { 'open' } else { $this.GetDuration().ToString() }
        return ('LogonId {0}  {1}@{2}  {3}  from {4}  {5}  admin={6}' -f `
            $this.LogonId, $this.Account, $this.Computer, $this.LogonType, ($this.SourceIp ?? '-'), $dur, $this.IsAdmin)
    }
}

<#
    Detection finding produced by Test-WinSecBruteForce.
#>
class WinSecBruteForceFinding {
    [WinSecVerdict]   $Pattern
    [WinSecSeverity]  $Severity
    [string]   $TargetAccount       # account focused by the pattern ('*' = many)
    [string]   $SourceIp            # attacker source ('*' = distributed)
    [string[]] $SourceHosts         # victim/target computers involved
    [int]      $FailureCount
    [int]      $SuccessCount
    [int]      $DistinctAccounts
    [int]      $DistinctSources
    [datetime] $FirstSeenUtc
    [datetime] $LastSeenUtc
    [double]   $AttemptsPerMinute
    [bool]     $SucceededAfterFailures
    [string[]] $AttackIds
    [string]   $Description
    [System.Collections.Generic.List[WinSecEvent]] $Evidence

    WinSecBruteForceFinding() {
        $this.Evidence    = [System.Collections.Generic.List[WinSecEvent]]::new()
        $this.SourceHosts = @()
        $this.AttackIds   = @()
    }
}

<#
    Log coverage / completeness snapshot (Get-WinSecLogCoverage).
    Tells the responder whether absence of events is evidence of absence
    or just a wrapped/disabled log.
#>
class WinSecLogCoverage {
    [string]   $Computer
    [string]   $LogName
    [string]   $FilePath            # evtx location (live path or analyzed file)
    [bool]     $IsEnabled
    [bool]     $IsAccessible
    [long]     $RecordCount
    [long]     $FileSizeBytes
    [long]     $MaxSizeBytes
    [double]   $UsedPercent
    [string]   $RetentionSetting    # OverwriteOlder / Retain:Ndays / Archive
    [datetime] $OldestRecordUtc
    [datetime] $NewestRecordUtc
    [timespan] $Span
    [WinSecSeverity] $Risk           # completeness risk rating
    [string]   $Warning             # human-readable caveat, empty when fine
}

<#
    IP attribution result (Resolve-WinSecIpAttribution).
    Offline-first: PTR + classification are always populated; provider
    fields only when a threat-intel provider was queried.
#>
class WinSecIpAttribution {
    [string]   $IpAddress           # canonical form
    [int]      $Version             # 4 or 6
    [bool]     $IsPrivate
    [bool]     $IsLoopback
    [bool]     $IsLinkLocal
    [string]   $PtrHostname         # reverse DNS
    [bool]     $PtrResolved
    [string]   $Provider            # '' | AbuseIPDB | OTX | IpApi
    [datetime] $QueriedUtc
    [bool]     $FromCache
    [string]   $Country
    [string]   $CountryCode
    [string]   $Region
    [string]   $City
    [int]      $Asn
    [string]   $AsnOrganization
    [int]      $AbuseConfidenceScore # AbuseIPDB 0..100
    [int]      $TotalReports
    [string[]] $Categories
    [string]   $Verdict             # provider verdict summary line
    [hashtable]$Raw                 # untouched provider response
}

<#
    One bucket of the activity timeline (Get-WinSecIpTimeline).
#>
class WinSecTimelineBucket {
    [datetime] $BucketStartUtc
    [int]      $Count
    [int]      $SuccessCount
    [int]      $FailureCount
    [int]      $DistinctAccounts
    [int]      $DistinctHosts
    [string]   $TopEventIds         # '4625x120, 4771x30'
    [int]      $BarWidth            # scaled 0..MaxBarWidth
    [string]   $Bar                 # rendered ASCII bar
}

<#
    Audit-policy gap (Test-WinSecAuditPolicy): a required subcategory that is
    not auditing the events the IP investigation relies on.
#>
class WinSecAuditGap {
    [string]   $Subcategory         # e.g. 'Logon' / 'Kerberos Authentication Service'
    [string]   $Guid                # auditpol subcategory GUID
    [string]   $CurrentSetting      # No Auditing / Success / Failure / Success and Failure
    [string]   $RequiredSetting
    [int[]]    $AffectedEventIds
    [WinSecSeverity] $Severity
    [string]   $Recommendation      # auditpol /set command line
}

<#
    Per-host execution status for multi-computer queries. Emitted with
    -PassHostStatus so a sweep over 200 hosts explains every one of them.
#>
class WinSecHostResult {
    [string]   $Computer
    [WinSecHostStatus] $Status
    [int]      $EventsFound
    [string]   $ErrorMessage
    [double]   $DurationMs
    [object[]] $LogDetails          # per-channel: LogName, Status, EventsFound, Error, DurationMs
}

