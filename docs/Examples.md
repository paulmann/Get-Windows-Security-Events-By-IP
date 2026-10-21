# Scenario Cookbook

Real-world recipes for IP-centric incident response with WinSecHunter.
All examples assume `Import-Module WinSecHunter` and an elevated shell on Windows.

---

## 1. First 10 minutes of an alert ("IP 203.0.113.7 hit our VPN")

```powershell
# What happened, everything retained, all relevant channels:
$events = Get-WinSecEventByIp 203.0.113.7 -PassHostStatus

# Attack pattern + severity immediately:
$events | Test-WinSecBruteForce | Format-List Pattern, Severity, TargetAccount,
    FailureCount, SuccessCount, AttemptsPerMinute, Description

# Shape of the attack over time (console histogram):
$events | Get-WinSecIpTimeline -AsciiChart | ForEach-Object {
    if ($_.AsciiChart) { $_.AsciiChart }   # summary object carries the chart
}
```

## 2. "Did they get in?" — success-after-failure triage

```powershell
$findings = $events | Test-WinSecBruteForce
$findings | Where-Object SucceededAfterFailures |
    Format-List TargetAccount, SourceIp, Description   # ← Critical: assume compromise

# Reconstruct exactly what the successful logon did:
$sessions = $events | Get-WinSecLogonSession
$sessions | Where-Object { -not $_.Ended } | Format-Table   # still-open sessions!
$sessions | Where-Object IsAdmin | Format-Table LogonId, Account, Computer, StartUtc
```

## 3. Estate-wide sweep (jump box → 200 servers)

```powershell
$targets = Get-Content .\servers.txt          # or query CMDB/AD
$events = Get-WinSecEventByIp 203.0.113.7 -ComputerName $targets -Credential $cred `
              -LastDays 7 -ThrottleLimit 32 -PassHostStatus -IncludeRawXml

# Every host is accounted for — including unreachable ones and hosts where the
# queried channels simply don't exist:
$events | Where-Object { $_ -is [WinSecHostResult] } |
    Group-Object Status | Format-Table Name, Count
```

## 4. Internal pivot hunt (attacker landed on WKS-12, now what?)

```powershell
# CIDR sweep + deep scan catches IPs inside command lines, UNC paths, task XML:
Get-WinSecEventByIp '10.10.5.0/24' -Path '\\fileserver\ir$\WKS-12-*.evtx' `
    -DeepScan -Profile All |
    Export-WinSecInvestigation -Format Csv, Html -OutputDirectory D:\IR

# Sysmon deployed? EID 3 gives process ↔ IP with direction:
Get-WinSecEventByIp 10.10.5.77 -Profile Sysmon -LastDays 2 |
    Where-Object EventId -eq 3 |
    Format-Table TimeUtc, Computer, ProcessName, SourceIp, DestinationIp, Direction
```

## 5. Offline forensics on acquired EVTX (air-gapped lab)

```powershell
$ev = Get-WinSecEventByIp 203.0.113.7 -Path 'E:\case042\*.evtx' -DeepScan

Get-WinSecLogCoverage -Path 'E:\case042\Security.evtx'   # retention bounds of the image
$ev | Get-WinSecIpTimeline -AsciiChart
$ev | Test-WinSecBruteForce
```

## 6. RDP-specific investigation

```powershell
Get-WinSecEventByIp 203.0.113.7 -Profile Rdp -LastDays 14 |
    Format-Table TimeUtc, Computer, EventId, LogName, TargetAccount, SourceIp, StatusCode

# 1149 (NLA auth) fires BEFORE 4624 type 10 — gaps between them reveal
# pre-authentication abuse; 4778/4779 + LSM 24/25 show reconnect patterns
# (attackers often reconnect to abandoned sessions).
```

## 7. "Why do I see nothing?" — proving the negative

```powershell
# a) Is the window actually retained?
Get-WinSecLogCoverage -CoveringFrom (Get-Date).AddDays(-14) |
    Where-Object Risk -in 'High', 'Critical' | Format-Table LogName, Risk, Warning

# b) Would the events even be audited?
Test-WinSecAuditPolicy -Profile BruteForce, Rdp | Format-List Subcategory,
    CurrentSetting, RequiredSetting, Recommendation

# c) Was the log cleared mid-incident? (1102 / System 104)
Get-WinSecEventByIp 203.0.113.7 -EventId 1102, 104 -LastDays 30
```

## 8. Live monitoring during an active incident

```powershell
Trace-WinSecIp 203.0.113.7 -Profile BruteForce -IntervalSeconds 5 |
    Tee-Object -FilePath .\live.jsonl -Append |
    ForEach-Object {
        Write-Information ('{0:HH:mm:ss} [{1}] {2} {3}' -f $_.TimeCreated, $_.EventId,
            $_.TargetAccount, $_.StatusCode) -InformationAction Continue
    }
# Ctrl+C stops cleanly; bookmarks are reported in verbose output.
```

## 9. Threat-intel enrichment before blocking

```powershell
$env:ABUSEIPDB_KEY = '…'
$ips = $events | ForEach-Object SourceIp | Where-Object { $_ } | Sort-Object -Unique
$ips | Resolve-WinSecIpAttribution -Provider AbuseIPDB |
    Format-Table IpAddress, IsPrivate, CountryCode, AbuseConfidenceScore, TotalReports, Verdict
# Private sources are classified locally — never sent to third parties.
```

## 10. Handing off to SIEM / case management

```powershell
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'INC-4242 VPN brute force' `
        -ScopeHosts VPN01, DC01 -Operator 'soc@contoso.com'
$case.AddNote('Perimeter firewall blocked source at 03:42 UTC after ticket.')

Export-WinSecInvestigation -Case $case -Event $events -Finding $findings `
    -Session $sessions -Coverage (Get-WinSecLogCoverage) -Format All -PassThru
# → WSC-…/manifest.json holds SHA-256 for every artifact (chain of custody).
```

## 11. Kerberoasting / DC-side checks by requester IP

```powershell
Get-WinSecEventByIp 10.10.9.5 -ComputerName DC01, DC02 -Profile Kerberos -LastDays 1 |
    Where-Object EventId -in 4769, 4771 |
    Format-Table TimeUtc, TargetAccount, EventId, StatusCode
# 4769 with TicketEncryptionType 0x17 (RC4) → likely kerberoastable service ticket.
```

## 12. Portable IR kit (USB)

```powershell
$env:WINSECHUNTER_CONFIG_DIR = 'E:\IRKit\WinSecHunter'
Set-WinSecHunterOption -Options @{ DefaultProfile = 'BruteForce'; DefaultMaxEvents = 50000 }
# All defaults + attribution cache now travel with the kit.
```

## 13. Incident report and abuse report (2.1.0)

```powershell
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force'
$case = Export-WinSecInvestigation -Case $case -Event $events -Finding $findings `
            -Session $sessions -Format All -OutputDirectory D:\IR -PassThru

New-WinSecIncidentReport -Case $case -Event $events -Finding $findings -Session $sessions `
    -Template Full -Format Both -OutputDirectory D:\IR -PassThru

New-WinSecAbuseReport -Case $case -Event $events -Finding $findings `
    -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' `
    -RedactAccounts -Format All -OutputDirectory D:\IR
```

Reports land in `D:\IR\<CaseId>-reports\`: Markdown and self-contained HTML for the incident,
`.eml`/`.md`/`.json` for the abuse desk.

## 14. Indicators for a TIP (STIX 2.1)

```powershell
Export-WinSecIocList -Case $case -Event $events -Finding $findings -Format Stix21 -PassThru
Export-WinSecIocList -Case $case -Event $events -Format Csv -FileName blocklist-candidates
```

## 15. Verify a bundle before sharing

```powershell
$s = Test-WinSecEvidenceIntegrity -Path D:\IR\WSC-20261021-AB12CD34 -Summary
if (-not $s.IsIntact) { $s.Rows | Where-Object Status -ne 'OK' | Format-Table RelativePath, Status }
```

`Extra` means a file was added after export — the check a plain hash list cannot perform.

## 16. Reopen a case next week

```powershell
$b = Import-WinSecCase -Path D:\IR\WSC-20261021-AB12CD34
$b.Events | Test-WinSecBruteForce -WindowMinutes 60
$b.Coverage | Format-Table Computer, LogName, Risk
```

The case keeps its id, notes and evidence table, so a follow-up report references the same
chain of custody.
