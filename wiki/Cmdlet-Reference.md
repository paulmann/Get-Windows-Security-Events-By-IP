# 📚 Cmdlet Reference

All 20 exported cmdlets of **WinSecHunter 2.1.0**. For the same content rendered from live
metadata, run `Show-WinSecHunterHelp -Markdown` or see
[docs/Command-Reference.md](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/blob/main/docs/Command-Reference.md).

[← Home](Home)

> [!TIP]
> `Show-WinSecHunterHelp -Cmdlet <name>` prints syntax, every parameter and examples for one
> cmdlet — always in sync with the installed build.

---

## Collect

### Get-WinSecEventByIp

Sweeps local logs, remote hosts or EVTX files for every event that references an IP/CIDR.

```powershell
Get-WinSecEventByIp [-IpAddress] <string[]> [-ComputerName <string[]>] [-CimSession <object[]>]
    [-Credential <pscredential>] [-Authentication <string>] [-SessionOption <object>]
    [-ThrottleLimit <int>] [-StartTime <datetime>] [-EndTime <datetime>] [-LastHours <int>]
    [-LastDays <int>] [-Profile <string[]>] [-Category <string[]>] [-EventId <int[]>]
    [-LogName <string[]>] [-MaxEvents <int>] [-DeepScan] [-NoServerSideIpFilter]
    [-IncludeMessage] [-IncludeRawXml] [-PassHostStatus] [-RetryCount <int>]
```

| Parameter | Notes |
|---|---|
| `-IpAddress` | IPv4, IPv6 or CIDR; multiple values allowed; pipeline-friendly |
| `-ComputerName` / `-CimSession` | remote targets (parallel over WinRM; CIM sessions run sequentially) |
| `-Path` | offline `.evtx` files (wildcards allowed) |
| `-LastHours` / `-LastDays` / `-StartTime` / `-EndTime` | time window; all optional |
| `-Profile` | hunt profile (default from configuration: `IncidentResponse`) |
| `-MaxEvents` | **per-channel** cap; `0` = unlimited |
| `-DeepScan` | drop the server-side IP gate and regex the whole record |
| `-PassHostStatus` | emit `WinSecHostResult` per target, with `LogDetails` per channel |
| `-IncludeMessage` / `-IncludeRawXml` | heavier payload for deep analysis |

```powershell
Get-WinSecEventByIp 203.0.113.7 -LastDays 2 -PassHostStatus
Get-WinSecEventByIp 203.0.113.0/24 -ComputerName SRV1, SRV2 -Credential (Get-Credential)
Get-WinSecEventByIp 198.51.100.9 -Path D:\Evidence\*.evtx -Profile All -DeepScan
```

### Trace-WinSecIp

Near-real-time tail with per-log record bookmarks (polling by design).

```powershell
Trace-WinSecIp [-IpAddress] <string[]> [-Profile <string[]>] [-Category <string[]>]
    [-EventId <int[]>] [-LogName <string[]>] [-IntervalSeconds <int>] [-Duration <timespan>]
    [-StartTime <datetime>] [-DeepScan] [-IncludeMessage]
```

| Parameter | Notes |
|---|---|
| `-Duration` | total tracing time, e.g. `([timespan]::FromHours(2))` |
| `-IntervalSeconds` | poll interval, default from configuration |
| `-StartTime` | start of the first window (default: now) |

```powershell
Trace-WinSecIp 203.0.113.7 -Duration ([timespan]::FromMinutes(30)) -IntervalSeconds 5
```

### Get-WinSecLogCoverage

Retention, size, wrap risk and accessibility per channel — proof of what the logs can answer.

```powershell
Get-WinSecLogCoverage [-LogName <string[]>] [-CoveringFrom <datetime>]
Get-WinSecLogCoverage [-ComputerName <string[]>] [-Credential <pscredential>] [-ThrottleLimit <int>] ...
Get-WinSecLogCoverage -Path <string[]> ...
```

```powershell
Get-WinSecLogCoverage -LogName Security, System | Format-Table Computer, LogName, RecordCount, UsedPercent, Risk
Get-WinSecLogCoverage -Path .\Security.evtx -CoveringFrom (Get-Date).AddDays(-7)
```

## Analyze

### Get-WinSecIpTimeline

UTC buckets, ASCII histogram, top accounts and hosts, success-after-failure marker.

```powershell
Get-WinSecIpTimeline [-Event] <WinSecEvent[]> [[-BucketSize] <timespan>] [[-MaxBarWidth] <int>]
    [[-Top] <int>] [-AsciiChart]
```

```powershell
$events | Get-WinSecIpTimeline -BucketSize ([timespan]::FromHours(1)) -AsciiChart
```

### Get-WinSecLogonSession

Chains 4624 → 4672/4648 → 4634/4647 into sessions with duration and admin flag.

```powershell
Get-WinSecLogonSession -Event <WinSecEvent[]> [-IncludeEnded]
Get-WinSecLogonSession -Event <WinSecEvent[]> [-ActiveOnly]
Get-WinSecLogonSession -Event <WinSecEvent[]> [-EndedOnly]
```

| Switch | Result |
|---|---|
| *(none)* / `-IncludeEnded` | all sessions |
| `-ActiveOnly` | sessions without a matching logoff — possible live footholds |
| `-EndedOnly` | closed sessions — dwell-time statistics |

```powershell
$events | Get-WinSecLogonSession -ActiveOnly | Format-Table Account, Computer, LogonType, SourceIp, IsAdmin
```

### Test-WinSecBruteForce

Detects brute force, spraying, credential stuffing, lockout storms and success after failure.

```powershell
Test-WinSecBruteForce [-Event] <WinSecEvent[]> [[-FailureThreshold] <int>] [[-WindowMinutes] <int>]
    [[-SprayAccountThreshold] <int>] [[-SuccessWindowMinutes] <int>] [[-LockoutThreshold] <int>]
    [[-MaxEvidencePerFinding] <int>]
```

| Parameter | Default | Meaning |
|---|---|---|
| `-FailureThreshold` | 5 (config) | failures per account before a brute-force finding |
| `-WindowMinutes` | 10 (config) | sliding window for counting |
| `-SprayAccountThreshold` | 5 (config) | distinct accounts that turns failures into spraying |
| `-SuccessWindowMinutes` | 60 | how long after failures a success is still linked |
| `-LockoutThreshold` | 3 | lockouts (4740) for a lockout storm |

```powershell
$findings = $events | Test-WinSecBruteForce -WindowMinutes 30
$findings | Format-Table Pattern, Severity, TargetAccount, SourceIp, FailureCount, SuccessCount
```

### Test-WinSecAuditPolicy

Compares effective audit policy with what the selected profiles need; emits ready-to-paste
`auditpol` remediation. Output is parsed positionally, so localized Windows works.

```powershell
Test-WinSecAuditPolicy [[-ComputerName] <string[]>] [[-Credential] <pscredential>]
    [[-ThrottleLimit] <int>] [[-Profile] <string[]>] [-IncludeCompliant]
```

```powershell
Test-WinSecAuditPolicy | Where-Object Severity -in 'High','Critical'
Test-WinSecAuditPolicy -ComputerName DC01, DC02 -IncludeCompliant
```

## Enrich

### Resolve-WinSecIpAttribution

Offline-first PTR and classification; optional AbuseIPDB / AlienVault OTX / ip-api.

```powershell
Resolve-WinSecIpAttribution [-IpAddress] <string[]> [-Provider <string>] [-NoCache] [-CacheHours <int>]
```

| Parameter | Notes |
|---|---|
| `-Provider` | `None` (default), `AbuseIPDB`, `OTX`, `IpApi` |
| `-NoCache` | bypass the on-disk cache |
| `-CacheHours` | cache lifetime, default from configuration |

API keys come from environment variables (`ABUSEIPDB_KEY`, `OTX_API_KEY`), never parameters.
Invalid input produces a warning and does not abort a batch.

```powershell
Resolve-WinSecIpAttribution 203.0.113.7 -Provider None
```

### Expand-WinSecIpRange

Expands a CIDR into individual addresses with a safety limit.

```powershell
Expand-WinSecIpRange [-Range] <string> [-MaxAddresses <int>] [-IncludeNetworkAddress] [-IncludeBroadcast]
```

```powershell
Expand-WinSecIpRange 10.0.0.0/29 -IncludeNetworkAddress
```

## Report

### New-WinSecIncidentReport

Executive, technical or full report to Markdown and self-contained HTML.

```powershell
New-WinSecIncidentReport [[-Case] <WinSecCase>] [[-Event] <object[]>] [[-Finding] <object[]>]
    [[-Session] <object[]>] [[-Coverage] <object[]>] [[-Attribution] <object[]>]
    [[-Timeline] <object[]>] [[-Summary] <hashtable>] [[-Template] <string>]
    [[-Format] <string>] [[-OutputDirectory] <string>] [[-FileName] <string>] [-PassThru]
```

| Parameter | Values |
|---|---|
| `-Template` | `Executive`, `Technical` (default), `Full` |
| `-Format` | `Markdown`, `Html`, `Both` (default) |
| `-OutputDirectory` | parent folder; files go to `<CaseId>-reports/` |

```powershell
New-WinSecIncidentReport -Case $case -Event $events -Finding $findings -Session $sessions `
    -Template Full -Format Both -PassThru
```

### New-WinSecAbuseReport

RFC 5322 `.eml` (plus Markdown and JSON) for the network that hosts the source address.

```powershell
New-WinSecAbuseReport [[-Case] <WinSecCase>] [[-Event] <object[]>] [[-Finding] <object[]>]
    [[-Attribution] <object[]>] [[-TargetIp] <string>] [[-Provider] <string>]
    [[-ContactEmail] <string>] [[-ReporterName] <string>] [-ReporterEmail] <string>
    [[-ReporterOrg] <string>] [[-Format] <string>] [[-OutputDirectory] <string>]
    [[-FileName] <string>] [[-MaxEventsInBody] <int>] [-RedactAccounts] [-PassThru]
```

| Parameter | Notes |
|---|---|
| `-ReporterEmail` | **mandatory**; becomes the `From` header |
| `-Provider` | `Auto` (default) or a provider name; `Generic` needs `-ContactEmail` |
| `-Format` | `Eml`, `Markdown`, `Json`, `All` (default) |
| `-RedactAccounts` | consistent pseudonyms, including inside attachments |

```powershell
New-WinSecAbuseReport -Case $case -Event $events -Attribution $attribution `
    -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' -RedactAccounts
```

### Export-WinSecIocList

Indicators as CSV, grep-friendly text, JSON or STIX 2.1.

```powershell
Export-WinSecIocList [[-Case] <WinSecCase>] [[-Event] <object[]>] [[-Finding] <object[]>]
    [[-Format] <string>] [[-OutputDirectory] <string>] [[-FileName] <string>] [-PassThru]
```

Indicator types: `TargetIp`, `SourceIp`, `DestinationIp`, `Account`, `Host`, `Process`,
`Service`, `Task`, `Path`.

```powershell
Export-WinSecIocList -Case $case -Event $events -Format Stix21 -PassThru
```

## Preserve

### New-WinSecCase

Creates the case object that binds subject IPs, scope hosts, notes and findings.

```powershell
New-WinSecCase [-SubjectIps] <string[]> [-Title <string>] [-Description <string>]
    [-ScopeHosts <string[]>] [-Operator <string>]
```

```powershell
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force' -ScopeHosts VPN01
$case.AddNote('Lockouts reported 02:00-03:00 UTC')
```

### Export-WinSecInvestigation

Writes the tamper-evident bundle and its SHA-256 manifest.

```powershell
Export-WinSecInvestigation [[-Case] <WinSecCase>] [[-Event] <WinSecEvent[]>] [[-Finding] <object[]>]
    [[-Session] <object[]>] [[-Coverage] <object[]>] [[-Attribution] <object[]>]
    [[-Timeline] <object[]>] [[-Summary] <hashtable>] [[-OutputDirectory] <string>]
    [[-Format] <WinSecExportFormat[]>] [[-MaxHtmlEventRows] <int>] [-PassThru]
```

`-Format`: `Csv`, `Json`, `Html`, `Markdown`, `CliXml`, `All`.

```powershell
Export-WinSecInvestigation -Case $case -Event $events -Finding $findings -Format All -PassThru
```

### Import-WinSecCase

Reopens a bundle, rehydrates typed events and restores the case with its evidence table.

```powershell
Import-WinSecCase [-Path] <string> [-SkipEvents]
```

```powershell
$b = Import-WinSecCase .\WSC-20261021-AB12CD34
$b.Events | Get-WinSecIpTimeline -AsciiChart
```

### Test-WinSecEvidenceIntegrity

Verifies manifest hashes and detects modified, missing **and added** files.

```powershell
Test-WinSecEvidenceIntegrity [-Path] <string> [-Algorithm <string>] [-ProblemsOnly] [-Summary] [-Json]
```

| Parameter | Notes |
|---|---|
| `-Algorithm` | `SHA256` (default), `SHA384`, `SHA512` |
| `-ProblemsOnly` | hide rows with `Status = OK` |
| `-Summary` | one object with counts and `Rows` |
| `-Json` | JSON document for pipelines |

```powershell
$s = Test-WinSecEvidenceIntegrity .\WSC-20261021-AB12CD34 -Summary
if (-not $s.IsIntact) { $s.Rows | Where-Object Status -ne 'OK' | Format-Table }
```

## Reference

### Show-WinSecHunterHelp

The whole toolkit at a glance, or one cmdlet in full.

```powershell
Show-WinSecHunterHelp [[-Cmdlet] <string>] [[-OutFile] <string>] [-Detailed] [-Markdown] [-Plain] [-PassThru]
```

```powershell
Show-WinSecHunterHelp
Show-WinSecHunterHelp -Cmdlet New-WinSecAbuseReport
Show-WinSecHunterHelp -Markdown -OutFile .\docs\Command-Reference.md
```

### Get-WinSecEventCatalog

The catalog: 156 events, 14 profiles, ATT&CK mapping, IP-bearing fields.

```powershell
Get-WinSecEventCatalog [-Category <string[]>] [-LogName <string[]>] [-Profile <string[]>]
    [-EventId <int[]>] [-Importance <string>] [-AttackId <string>] [-IpMatchable]
Get-WinSecEventCatalog [-ListProfiles]
```

```powershell
Get-WinSecEventCatalog -AttackId T1021.001
Get-WinSecEventCatalog -Profile Rdp -LogName Security
Get-WinSecEventCatalog -ListProfiles
```

### Get-WinSecHunterOption / Set-WinSecHunterOption

```powershell
Get-WinSecHunterOption [-Name] <string>
Get-WinSecHunterOption [-ShowResolved]
Set-WinSecHunterOption [-Name] <string> [-Value] <object>
Set-WinSecHunterOption -Options <hashtable>
Set-WinSecHunterOption [-Reset]
```

```powershell
Get-WinSecHunterOption
Get-WinSecHunterOption -ShowResolved          # key PRESENCE, never values
Set-WinSecHunterOption -DefaultProfile BruteForce -DefaultMaxEvents 20000
Set-WinSecHunterOption -Reset
```

`Set-WinSecHunterOption` supports `-WhatIf` and writes `config.json` atomically.
`-ShowResolved` reports whether an API key is present in the environment, never its value.

