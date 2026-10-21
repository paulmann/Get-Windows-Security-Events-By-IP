# WinSecHunter 2.1.0 — command reference

> Generated from live module metadata. Do not edit by hand; regenerate with `Show-WinSecHunterHelp -Markdown`.

## What it is

WinSecHunter is an incident-response toolkit for Windows security events. It answers one question completely: **what did a given attacker IP do to this estate?** — across local hosts, remote hosts over WinRM and offline EVTX files, then turns the answer into evidence and reports.

## Five-minute quick start

```powershell
git clone https://github.com/paulmann/Get-Windows-Security-Events-By-IP.git
cd Get-Windows-Security-Events-By-IP; ./build/Install-Dev.ps1 -Force
$events = Get-WinSecEventByIp 203.0.113.7 -LastDays 2 -PassHostStatus
$events | Test-WinSecBruteForce
$events | Get-WinSecIpTimeline -AsciiChart
Export-WinSecInvestigation -Event $events -Format All -PassThru
```

## Workflow map

### Collect

- **`Get-WinSecEventByIp`** — Collects Windows security events that reference an attacker IP address
(IPv4/IPv6/CIDR) from local logs, remote hosts or offline EVTX files.
- **`Trace-WinSecIp`** — Near-real-time tail of Windows event logs for a specific IP — live
monitoring during an ongoing incident.
- **`Get-WinSecLogCoverage`** — Reports event log completeness: is each channel enabled, how far back
does it reach, and is it about to wrap?

### Analyze

- **`Get-WinSecIpTimeline`** — Builds a chronological activity timeline with volume buckets, ASCII
histogram and attacker-behavior summaries for collected events.
- **`Get-WinSecLogonSession`** — Reconstructs logon sessions from collected events by chaining LogonId
references (4624 → 4672/4648 → 4634/4647).
- **`Test-WinSecBruteForce`** — Detects brute-force, password-spraying, credential-stuffing and
lockout-storm patterns in collected events and rates their severity.
- **`Test-WinSecAuditPolicy`** — Finds audit-policy gaps: subcategories that are NOT recording the
events an IP investigation depends on.

### Enrich

- **`Resolve-WinSecIpAttribution`** — Enriches attacker IPs: reverse DNS, RFC classification, optional
threat-intel lookups (AbuseIPDB / AlienVault OTX / ip-api) with caching.
- **`Expand-WinSecIpRange`** — Enumerates the individual addresses of an IPv4/IPv6 CIDR or dash range.

### Report

- **`New-WinSecIncidentReport`** — Produces a narrative incident report (Markdown and/or HTML) from
collected events, detections, sessions, coverage and attribution.
- **`New-WinSecAbuseReport`** — Builds a ready-to-send abuse report for the network that hosts the
attacking IP: RFC 5322 .eml with evidence attachments, plus Markdown and
a structured JSON payload.
- **`Export-WinSecIocList`** — Extracts indicators of compromise from events and findings and writes
them as CSV, plain text, JSON or a STIX 2.1 bundle.

### Preserve

- **`New-WinSecCase`** — Creates an investigation case that binds evidence, findings and notes
to a tamper-evident export bundle.
- **`Export-WinSecInvestigation`** — Writes a complete, tamper-evident investigation bundle: events,
findings, sessions, coverage, attribution, timeline and a
self-contained HTML report — hashed into manifest.json.
- **`Import-WinSecCase`** — Reopens an exported investigation bundle so analysis and reporting can
continue in a new session, on another workstation, or after a reboot.
- **`Test-WinSecEvidenceIntegrity`** — Verifies an exported evidence bundle against its SHA-256 manifest and
reports modified, missing or unexpected files.

### Reference

- **`Get-WinSecEventCatalog`** — Browses the built-in WinSecHunter event catalog: IDs, logs, categories,
MITRE ATT&CK mappings, importance and IP-bearing fields.
- **`Get-WinSecHunterOption`** — Shows the effective WinSecHunter configuration.
- **`Set-WinSecHunterOption`** — Persists WinSecHunter configuration options.
- **`Show-WinSecHunterHelp`** — One-stop reference for the whole toolkit: workflow, cmdlets, profiles,
configuration, requirements and troubleshooting — or the full help of a
single cmdlet.

## Cmdlets

| Cmdlet | Purpose |
|---|---|
| `Expand-WinSecIpRange` | Enumerates the individual addresses of an IPv4/IPv6 CIDR or dash range. |
| `Export-WinSecInvestigation` | Writes a complete, tamper-evident investigation bundle: events,
findings, sessions, coverage, attribution, timeline and a
self-contained HTML report — hashed into manifest.json. |
| `Export-WinSecIocList` | Extracts indicators of compromise from events and findings and writes
them as CSV, plain text, JSON or a STIX 2.1 bundle. |
| `Get-WinSecEventByIp` | Collects Windows security events that reference an attacker IP address
(IPv4/IPv6/CIDR) from local logs, remote hosts or offline EVTX files. |
| `Get-WinSecEventCatalog` | Browses the built-in WinSecHunter event catalog: IDs, logs, categories,
MITRE ATT&CK mappings, importance and IP-bearing fields. |
| `Get-WinSecHunterOption` | Shows the effective WinSecHunter configuration. |
| `Get-WinSecIpTimeline` | Builds a chronological activity timeline with volume buckets, ASCII
histogram and attacker-behavior summaries for collected events. |
| `Get-WinSecLogCoverage` | Reports event log completeness: is each channel enabled, how far back
does it reach, and is it about to wrap? |
| `Get-WinSecLogonSession` | Reconstructs logon sessions from collected events by chaining LogonId
references (4624 → 4672/4648 → 4634/4647). |
| `Import-WinSecCase` | Reopens an exported investigation bundle so analysis and reporting can
continue in a new session, on another workstation, or after a reboot. |
| `New-WinSecAbuseReport` | Builds a ready-to-send abuse report for the network that hosts the
attacking IP: RFC 5322 .eml with evidence attachments, plus Markdown and
a structured JSON payload. |
| `New-WinSecCase` | Creates an investigation case that binds evidence, findings and notes
to a tamper-evident export bundle. |
| `New-WinSecIncidentReport` | Produces a narrative incident report (Markdown and/or HTML) from
collected events, detections, sessions, coverage and attribution. |
| `Resolve-WinSecIpAttribution` | Enriches attacker IPs: reverse DNS, RFC classification, optional
threat-intel lookups (AbuseIPDB / AlienVault OTX / ip-api) with caching. |
| `Set-WinSecHunterOption` | Persists WinSecHunter configuration options. |
| `Show-WinSecHunterHelp` | One-stop reference for the whole toolkit: workflow, cmdlets, profiles,
configuration, requirements and troubleshooting — or the full help of a
single cmdlet. |
| `Test-WinSecAuditPolicy` | Finds audit-policy gaps: subcategories that are NOT recording the
events an IP investigation depends on. |
| `Test-WinSecBruteForce` | Detects brute-force, password-spraying, credential-stuffing and
lockout-storm patterns in collected events and rates their severity. |
| `Test-WinSecEvidenceIntegrity` | Verifies an exported evidence bundle against its SHA-256 manifest and
reports modified, missing or unexpected files. |
| `Trace-WinSecIp` | Near-real-time tail of Windows event logs for a specific IP — live
monitoring during an ongoing incident. |

## Hunt profiles

| Profile | Purpose |
|---|---|
| `AccountManagement` | User/group lifecycle and lockouts — attacker post-exploitation actions. |
| `All` | Every cataloged event across all supported logs. |
| `BruteForce` | Failures + successes + lockouts needed for brute-force/spray correlation and success-after-failure detection. |
| `Critical` | Only events the catalog marks Critical. |
| `DefenseEvasion` | Anti-forensics and security-control tampering: log clearing, audit policy changes, firewall/service shutdown, Sysmon config changes. |
| `FailedAuth` | Only failed authentication events (classic brute-force sweep, superset of the legacy script behavior). |
| `Firewall` | Windows Firewall/WFP: rule lifecycle, service health and connection permit/block (5152-level noise excluded by default). |
| `IncidentResponse` | DEFAULT. Balanced IP-incident sweep: authentication, Kerberos, remote access, account lifecycle, credential access, persistence and anti-forensics. Excludes high-noise object/firewall/connection logs. |
| `Kerberos` | Kerberos authentication chain (AS/TGS/pre-auth failures, replay, SPN issues). |
| `Lateral` | Lateral movement indicators: network logons, explicit-credential logons, share access, remote service/task installation. |
| `ObjectAccess` | File/share/registry/DS object access (high noise — enable when you have object SACLs). |
| `Persistence` | Persistence installation: services, scheduled tasks, autostart artifacts. |
| `Rdp` | RDP/remote interactive access chain: RCM + LSM operational logs plus Security logon events. |
| `Sysmon` | Sysmon coverage for IP hunting: network connections (EID 3), process creation, remote threads, credential access, config changes. |

## Catalog and configuration

- Catalog: **156** events across **6** channels (version 2.1.0).
- Configuration file: `%LOCALAPPDATA%\WinSecHunter\config.json` (Windows) or `~/.config/WinSecHunter/config.json` (Linux/macOS)
- Override directory with `WINSECHUNTER_CONFIG_DIR` (portable IR kit on read-only media is supported for reads).

| Option | Default | Meaning |
|---|---|---|
| `AbuseIpDbKeyEnvVar` | `ABUSEIPDB_KEY` | Environment variable holding the AbuseIPDB API key. |
| `AttributionCacheHours` | `72` | How long attribution results stay cached. |
| `BruteForceFailureThreshold` | `5` | Failures per account before a brute-force finding. |
| `BruteForceSprayAccountThreshold` | `5` | Distinct accounts that turns failures into spraying. |
| `BruteForceWindowMinutes` | `10` | Sliding window for brute-force counting. |
| `DeepScan` | `False` | Regex the IP anywhere in the record, including messages. |
| `DefaultMaxEvents` | `5000` | Per-channel record cap for collection (0 = unlimited). |
| `DefaultOutputDirectory` | `` | Default parent folder for evidence bundles and reports. |
| `DefaultProfile` | `IncidentResponse` | Profile used when no -Profile/-Category/-EventId is supplied. |
| `DefaultThrottleLimit` | `8` | Parallel host fan-out for remote collection. |
| `IncludeMessage` | `False` | Collect the rendered message text (slower, larger). |
| `IpApiContactEmail` | `` | Contact e-mail required by the ip-api free tier. |
| `OtxKeyEnvVar` | `OTX_API_KEY` | Environment variable holding the AlienVault OTX key. |
| `ThreatIntelProvider` | `None` | Optional enrichment provider: None, AbuseIPDB, OTX, IpApi. |
| `TraceIntervalSeconds` | `5` | Polling interval for Trace-WinSecIp. |

## Requirements and platform support

- PowerShell **7.6+** (Core). Windows PowerShell 5.1 is not supported.
- Collection (`Get-WinSecEventByIp`, `Trace-WinSecIp`, `Get-WinSecLogCoverage`, `Test-WinSecAuditPolicy`) requires Windows and, for the Security log, an elevated session.
- Remote collection uses WinRM/`Invoke-Command` or pre-built CIM sessions; configure `Enable-PSRemoting` and the appropriate TrustedHosts/CredSSP policy.
- Offline EVTX analysis works on any OS that can read the file; pure analysis cmdlets (timeline, brute force, sessions, reporting) run everywhere.
- No external binaries, no cloud dependency. Optional threat-intel providers read API keys from environment variables only.

## Troubleshooting

| Symptom | First check |
|---|---|
| "No events" but activity is known | `Get-WinSecLogCoverage` (retention), `Test-WinSecAuditPolicy` (is the subcategory audited?) |
| Access denied reading Security | Run elevated; the channel requires Administrator |
| Remote host failed | `-PassHostStatus` lists per-channel status; verify WinRM, firewall, credentials |
| Missing Sysmon/RDP channel | Expected on servers without those roles: the channel reports `Skipped`, the sweep continues |
| Report hashes do not match | Files were modified after export; re-export and keep bundles read-only |
| Abuse mailbox unknown | `New-WinSecAbuseReport` never invents an address; pass `-ContactEmail` |

## Detailed cmdlet reference

### `Expand-WinSecIpRange`

Enumerates the individual addresses of an IPv4/IPv6 CIDR or dash range.

```text
Expand-WinSecIpRange [-Range] <string> [-MaxAddresses <int>] [-IncludeNetworkAddress] [-IncludeBroadcast] [<CommonParameters>]
```

Utility for allow/deny-list building and sweep planning: expands
'203.0.113.0/24', '10.0.0.5-10.0.0.9' or '2001:db8::/126' into
canonical address strings. Guarded by -MaxAddresses (default 4096)
because enumerating wide ranges is a memory hazard, not a feature.
Network and broadcast addresses of IPv4 ranges are excluded unless
requested — they never appear as authentication sources.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-IncludeBroadcast` | `SwitchParameter` | no |  |
| `-IncludeNetworkAddress` | `SwitchParameter` | no |  |
| `-MaxAddresses` | `Int32` | no |  |
| `-Range` | `String` | yes |  |

**Examples**

```powershell
Expand-WinSecIpRange 203.0.113.0/30
```


```powershell
Expand-WinSecIpRange '10.0.0.5-10.0.0.9'
```


```powershell
Expand-WinSecIpRange '2001:db8::/126' -IncludeNetworkAddress
```

### `Export-WinSecInvestigation`

Writes a complete, tamper-evident investigation bundle: events,
findings, sessions, coverage, attribution, timeline and a
self-contained HTML report — hashed into manifest.json.

```text
Export-WinSecInvestigation [[-Case] <WinSecCase>] [[-Event] <WinSecEvent[]>] [[-Finding] <Object[]>] [[-Session] <Object[]>] [[-Coverage] <Object[]>] [[-Attribution] <Object[]>] [[-Timeline] <Object[]>] [[-Summary] <hashtable>] [[-OutputDirectory] <string>] [[-Format] <WinSecExportFormat[]>] [[-MaxHtmlEventRows] <int>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Production evidence export for an IP investigation. Creates (or reuses)
a case folder, writes each selected artifact, then computes SHA-256 for
every file and records it in manifest.json together with tool version,
operator, host and timestamps — the chain-of-custody anchor you can
hand to a responder, auditor or court.

Artifacts (written when the corresponding input is supplied):
  events.csv / events.json / events.clixml   — normalized events
  findings.json                              — brute-force/spray detections
  sessions.csv                               — reconstructed logon sessions
  coverage.csv                               — log completeness snapshot
  attribution.json                           — IP enrichment results
  timeline.csv                               — activity buckets
  report.html                                — self-contained HTML report
  report.md                                  — Markdown summary
  case.json                                  — case metadata + notes
  manifest.json                              — SHA-256 manifest (written last)

CLIXML preserves WinSecEvent objects for re-analysis with
Import-Clixml; JSON/CSV are SIEM/spreadsheet-friendly. The HTML report
has zero external dependencies (inline CSS/SVG) and renders anywhere.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Attribution` | `Object[]` | no |  |
| `-Case` | `WinSecCase` | no | WinSecCase from New-WinSecCase. When omitted, an ad-hoc case is
created from the event data (subject IPs = distinct MatchedIp). |
| `-Confirm` | `SwitchParameter` | no |  |
| `-Coverage` | `Object[]` | no |  |
| `-Event` | `WinSecEvent[]` | no |  |
| `-Finding` | `Object[]` | no |  |
| `-Format` | `WinSecExportFormat[]` | no | Artifact set: Csv, Json, Html, Markdown, CliXml or All. Events are
written in each requested tabular/structured format; report.html and
report.md follow Html/Markdown respectively. |
| `-MaxHtmlEventRows` | `Int32` | no |  |
| `-OutputDirectory` | `String` | no | Parent directory; the case folder is created inside it. Defaults to
the DefaultOutputDirectory configuration option, else the current
directory. |
| `-PassThru` | `SwitchParameter` | no | Return the WinSecCase with Evidence (path → SHA-256) populated. |
| `-Session` | `Object[]` | no |  |
| `-Summary` | `Hashtable` | no |  |
| `-Timeline` | `Object[]` | no |  |
| `-WhatIf` | `SwitchParameter` | no |  |

**Examples**

```powershell
$events = Get-WinSecEventByIp 203.0.113.7 -ComputerName SRV1, SRV2 -LastDays 2 -IncludeRawXml
$case   = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force vs SRV tier'
$events | Test-WinSecBruteForce | Set-Variable findings
Export-WinSecInvestigation -Case $case -Event $events -Finding $findings -Format All -PassThru
```


```powershell
Get-WinSecEventByIp 10.0.0.0/24 -Path C:\Cases\*.evtx |
    Export-WinSecInvestigation -Format Csv, Html -OutputDirectory D:\IR
```

### `Export-WinSecIocList`

Extracts indicators of compromise from events and findings and writes
them as CSV, plain text, JSON or a STIX 2.1 bundle.

```text
Export-WinSecIocList [[-Case] <WinSecCase>] [[-Event] <Object[]>] [[-Finding] <Object[]>] [[-Format] <string>] [[-OutputDirectory] <string>] [[-FileName] <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Reports are read by people; blocklists and TIPs are read by machines.
This cmdlet produces the machine-readable side: one row per indicator
value with its type (TargetIp, SourceIp, DestinationIp, Account, Host,
Process, Service, Task, Path), sighting count and first/last UTC time.

Formats:
  Csv     Spreadsheet/SIEM import: Type,Value,Count,FirstUtc,LastUtc.
  Txt     Grep-friendly: "type<TAB>value<TAB>count", one per line.
  Json    Document with metadata, counts and the indicator array.
  Stix21  STIX 2.1 bundle of indicators (IP addresses and accounts),
          ready for a TIP, MISP import or information sharing.

STIX indicators are generated from the observed values only; no
judgement is implied beyond the label 'anomalous-activity'. Values are
quoted and escaped according to the STIX patterning rules.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Case` | `WinSecCase` | no | Case providing subject IPs (reported as TargetIp). |
| `-Confirm` | `SwitchParameter` | no |  |
| `-Event` | `Object[]` | no | WinSecEvent objects to mine. |
| `-FileName` | `String` | no | Base file name without extension. Defaults to
<CaseId>-iocs. |
| `-Finding` | `Object[]` | no | Findings whose source IP, target account and hosts should be included. |
| `-Format` | `String` | no | Csv, Txt, Json or Stix21. Default Csv. |
| `-OutputDirectory` | `String` | no | Parent folder. Defaults to the DefaultOutputDirectory option, else the
current directory. |
| `-PassThru` | `SwitchParameter` | no | Emit a descriptor with path, SHA-256, counts and format. |
| `-WhatIf` | `SwitchParameter` | no |  |

**Examples**

```powershell
Export-WinSecIocList -Event $events -Format Csv -OutputDirectory D:\IR -PassThru
```


```powershell
$case = New-WinSecCase -SubjectIps 203.0.113.7
Export-WinSecIocList -Case $case -Event $events -Finding $findings -Format Stix21 -FileName sharing-bundle
```


```powershell
Export-WinSecIocList -Event $events -Format Txt |
    ForEach-Object { $_.Path }
```

### `Get-WinSecEventByIp`

Collects Windows security events that reference an attacker IP address
(IPv4/IPv6/CIDR) from local logs, remote hosts or offline EVTX files.

```text
Get-WinSecEventByIp [-IpAddress] <string[]> [-StartTime <datetime>] [-EndTime <datetime>] [-LastHours <int>] [-LastDays <int>] [-Profile <string[]>] [-Category <string[]>] [-EventId <int[]>] [-LogName <string[]>] [-MaxEvents <int>] [-DeepScan] [-NoServerSideIpFilter] [-IncludeMessage] [-IncludeRawXml] [-PassHostStatus] [-RetryCount <int>] [<CommonParameters>]

Get-WinSecEventByIp [-IpAddress] <string[]> [-ComputerName <string[]>] [-CimSession <Object[]>] [-Credential <pscredential>] [-Authentication <string>] [-SessionOption <Object>] [-ThrottleLimit <int>] [-StartTime <datetime>] [-EndTime <datetime>] [-LastHours <int>] [-LastDays <int>] [-Profile <string[]>] [-Category <string[]>] [-EventId <int[]>] [-LogName <string[]>] [-MaxEvents <int>] [-DeepScan] [-NoServerSideIpFilter] [-IncludeMessage] [-IncludeRawXml] [-PassHostStatus] [-RetryCount <int>] [<CommonParameters>]

Get-WinSecEventByIp [-IpAddress] <string[]> -Path <string[]> [-StartTime <datetime>] [-EndTime <datetime>] [-LastHours <int>] [-LastDays <int>] [-Profile <string[]>] [-Category <string[]>] [-EventId <int[]>] [-LogName <string[]>] [-MaxEvents <int>] [-DeepScan] [-NoServerSideIpFilter] [-IncludeMessage] [-IncludeRawXml] [-PassHostStatus] [-RetryCount <int>] [<CommonParameters>]
```

The core evidence-collection cmdlet of WinSecHunter, built for incident
responders answering "everything this IP did to us".

Data sources (per target): Security log, System log, RDP operational
logs (RemoteConnectionManager + LocalSessionManager), Windows Firewall
operational log and — when present — Sysmon. The event set is driven by
a built-in catalog with MITRE ATT&CK mapping, selected via -Profile,
-Category or explicit -EventId.

Query strategy (three layers):
  1. Server-side pushdown — an Event Log XPath QueryList restricts by
     channel, event IDs and a UTC time window; for a single exact IP
     the query is additionally gated on IP equality (including
     IPv4-mapped IPv6 renderings and the UserData/EventXML/Address
     layout of the RDP logs) for maximum speed on huge logs.
  2. Client-side verification — every returned record is matched with
     a boundary-aware regex so mapped/compressed IPv6 variants and
     message-embedded addresses are never missed.
  3. -DeepScan — disables the server-side IP gate entirely, sweeping
     every cataloged event in the time window and matching the IP
     anywhere in the record XML (finds IPs inside command lines, UNC
     paths, task XML, etc. at the cost of throughput).

Remote execution uses WinRM (Invoke-Command) with parallel fan-out and
per-host retry; -CimSession is honored for pre-built sessions. EVTX
files are analyzed offline via -Path. Results are normalized, decoded
(NTSTATUS/Kerberos/%% codes), classified, deduplicated and sorted by
UTC time.

Every result carries BOTH timestamps: TimeCreated (source-local) and
TimeUtc (authoritative). Analysis functions sort on TimeUtc so
multi-timezone estates correlate correctly.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Authentication` | `String` | no |  |
| `-Category` | `String[]` | no | Additional WinSecEventCategory values to include (union with profiles). |
| `-CimSession` | `Object[]` | no | Pre-built CIM sessions (New-CimSession) as an alternative transport. |
| `-ComputerName` | `String[]` | no | Remote hosts to sweep over WinRM. Requires WinRM connectivity and
(normally) administrator credentials on the target. |
| `-Credential` | `PSCredential` | no | PSCredential for remote targets. |
| `-DeepScan` | `SwitchParameter` | no | Drop the server-side IP gate and regex-match the IP anywhere in every
cataloged event of the window. Slower; catches IPs embedded in command
lines, UNC paths, firewall rule XML, scheduled task definitions, etc. |
| `-EndTime` | `DateTime` | no | End of the investigation window. Defaults to now. |
| `-EventId` | `Int32[]` | no | Explicit event IDs to include (union). Unknown IDs default to the
Security log unless -LogName restricts otherwise. |
| `-IncludeMessage` | `SwitchParameter` | no | Populate the Message property (renders event messages on the source;
slower remotely). Default can be set via Set-WinSecHunterOption. |
| `-IncludeRawXml` | `SwitchParameter` | no | Populate the Xml property with the raw event XML (useful for evidence
exports; increases memory). |
| `-IpAddress` | `String[]` | yes | One or more IPv4/IPv6 addresses or CIDR ranges (e.g. '203.0.113.7',
'2001:db8::/64', '10.0.0.0/24'). CIDR members are matched client-side. |
| `-LastDays` | `Int32` | no | Convenience window: last N days. |
| `-LastHours` | `Int32` | no | Convenience window: last N hours (mutually exclusive with StartTime). |
| `-LogName` | `String[]` | no | Restrict the sweep to these channels. Aliases: RDP, TerminalServices,
Firewall, Sysmon. |
| `-MaxEvents` | `Int32` | no | Per-log record cap passed to each channel query (default from
configuration, 5000). Client-side filtering may yield fewer matches.
Because channels are queried independently, the total can reach
MaxEvents × number of channels. 0 means unlimited. |
| `-NoServerSideIpFilter` | `SwitchParameter` | no | Keep catalog IDs/time pushdown but skip only the exact-IP gate (middle
ground between default and -DeepScan; required semantics for CIDR are
applied automatically). |
| `-PassHostStatus` | `SwitchParameter` | no | Also emit WinSecHostResult objects (one per target: status, event
count, duration, error) at the start of the output stream so sweeps
over many hosts explain every machine — including unreachable ones
and channels that are simply not installed (status Skipped). |
| `-Path` | `String[]` | yes | Offline EVTX files to analyze. Wildcards allowed. |
| `-Profile` | `String[]` | no | Catalog profile(s) selecting which events to hunt:
IncidentResponse (default), FailedAuth, BruteForce, Rdp, Lateral,
AccountManagement, Kerberos, Firewall, DefenseEvasion, Persistence,
Sysmon, ObjectAccess, Critical, All. See Get-WinSecEventCatalog. |
| `-RetryCount` | `Int32` | no | Per-host retry attempts on transport failure (default 1). |
| `-SessionOption` | `Object` | no |  |
| `-StartTime` | `DateTime` | no | Start of the investigation window (interpreted in the COLLECTING
machine's local time zone, converted to UTC for the query). |
| `-ThrottleLimit` | `Int32` | no | Maximum parallel remote hosts (default from configuration, 8). |

**Examples**

```powershell
Get-WinSecEventByIp -IpAddress 203.0.113.7
```


```powershell
Get-WinSecEventByIp 203.0.113.7 -ComputerName SRV1, SRV2, DC01 -Credential $cred -LastDays 3 -PassHostStatus
```


```powershell
Get-WinSecEventByIp '10.10.0.0/24' -Path 'C:\Cases\DC01-Security.evtx' -DeepScan -IncludeRawXml
```


```powershell
Get-WinSecEventByIp 203.0.113.7 -Profile BruteForce,Rdp -LastHours 12 |
    Test-WinSecBruteForce
```

### `Get-WinSecEventCatalog`

Browses the built-in WinSecHunter event catalog: IDs, logs, categories,
MITRE ATT&CK mappings, importance and IP-bearing fields.

```text
Get-WinSecEventCatalog [-Category <string[]>] [-LogName <string[]>] [-Profile <string[]>] [-EventId <int[]>] [-Importance <string>] [-AttackId <string>] [-IpMatchable] [<CommonParameters>]

Get-WinSecEventCatalog [-ListProfiles] [<CommonParameters>]
```

The catalog is the knowledge base behind profiles, classification and
the audit-policy requirement matrix. Use this cmdlet to discover what
a profile collects, which events carry IP addresses natively, and how
they map to ATT&CK techniques — e.g. when tuning a sweep or writing
detection documentation.

-ListProfiles shows all available hunt profiles with descriptions.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-AttackId` | `String` | no |  |
| `-Category` | `String[]` | no |  |
| `-EventId` | `Int32[]` | no |  |
| `-Importance` | `String` | no |  |
| `-IpMatchable` | `SwitchParameter` | no |  |
| `-ListProfiles` | `SwitchParameter` | no |  |
| `-LogName` | `String[]` | no |  |
| `-Profile` | `String[]` | no |  |

**Examples**

```powershell
Get-WinSecEventCatalog -ListProfiles
```


```powershell
Get-WinSecEventCatalog -IpMatchable | Format-Table EventId, Log, Name -AutoSize
```


```powershell
Get-WinSecEventCatalog -AttackId T1021.001
```


```powershell
Get-WinSecEventCatalog -Profile BruteForce | Sort-Object EventId
```


```powershell
Get-WinSecEventCatalog -Category Kerberos -Importance Critical
```

### `Get-WinSecHunterOption`

Shows the effective WinSecHunter configuration.

```text
Get-WinSecHunterOption [-ShowResolved] [<CommonParameters>]

Get-WinSecHunterOption [-Name] <string> [<CommonParameters>]
```

Returns the merged configuration (built-in defaults overlaid by the
persisted config.json). Pass -Name to read a single option, or
-ShowResolved to also display where threat-intel keys are sourced from
and whether they are currently set (values are never printed).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Name` | `String` | yes |  |
| `-ShowResolved` | `SwitchParameter` | no |  |

**Examples**

```powershell
Get-WinSecHunterOption
```


```powershell
Get-WinSecHunterOption -Name DefaultProfile
```


```powershell
Get-WinSecHunterOption -ShowResolved
```

### `Get-WinSecIpTimeline`

Builds a chronological activity timeline with volume buckets, ASCII
histogram and attacker-behavior summaries for collected events.

```text
Get-WinSecIpTimeline [-Event] <WinSecEvent[]> [[-BucketSize] <timespan>] [[-MaxBarWidth] <int>] [[-Top] <int>] [-AsciiChart] [<CommonParameters>]
```

Answers the first questions of any IP investigation: when did the
activity start/stop, how intense was it, which accounts and hosts were
touched in each window, and did failures turn into successes?

Buckets are emitted as WinSecTimelineBucket objects (pipeline-friendly,
consumed by Export-WinSecInvestigation for the HTML histogram). With
-AsciiChart the same data is rendered as console-safe strings —
no host output, fully testable and redirectable.

A leading summary object (PSTypeName WinSecTimelineSummary) carries
totals, first/last seen (UTC), per-host/per-account/per-event breakdowns
and the success-after-failure indicator.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-AsciiChart` | `SwitchParameter` | no |  |
| `-BucketSize` | `TimeSpan` | no | Bucket granularity. Default: automatic — 1h for spans ≤ 48h, 6h for
≤ 14 days, 1 day beyond. |
| `-Event` | `WinSecEvent[]` | yes | WinSecEvent objects, typically piped from Get-WinSecEventByIp. |
| `-MaxBarWidth` | `Int32` | no | Width of the longest ASCII bar (default 50). |
| `-Top` | `Int32` | no | How many entries per breakdown table (default 10). |

**Examples**

```powershell
Get-WinSecEventByIp 203.0.113.7 | Get-WinSecIpTimeline -AsciiChart
```


```powershell
$timeline = $events | Get-WinSecIpTimeline -BucketSize ([timespan]::FromMinutes(15))
$timeline | Where-Object PSTypeName -eq 'WinSecTimelineBucket'
```

### `Get-WinSecLogCoverage`

Reports event log completeness: is each channel enabled, how far back
does it reach, and is it about to wrap?

```text
Get-WinSecLogCoverage [-LogName <string[]>] [-CoveringFrom <datetime>] [<CommonParameters>]

Get-WinSecLogCoverage [-ComputerName <string[]>] [-Credential <pscredential>] [-ThrottleLimit <int>] [-LogName <string[]>] [-CoveringFrom <datetime>] [<CommonParameters>]

Get-WinSecLogCoverage -Path <string[]> [-LogName <string[]>] [-CoveringFrom <datetime>] [<CommonParameters>]
```

"No events found" only means something when the logs CAN prove it.
This cmdlet answers the evidence-completeness questions before you
write that line into an incident report:

  * Is the channel enabled and accessible?
  * Oldest/newest record (UTC) — does retention actually cover the
    investigation window (-CoveringFrom)?
  * Size vs. maximum, retention mode, and wrap risk rating.

Works live (local/remote via WinRM, parallel) and offline against
acquired EVTX files (-Path). Channels that are not installed
(Sysmon absent, RDP logs on a DC) are reported with Risk=Informational
instead of erroring.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-ComputerName` | `String[]` | no |  |
| `-CoveringFrom` | `DateTime` | no | Investigation window start (UTC-converted). If a log's oldest record
is NEWER than this, the log cannot prove absence before that point →
High risk warning. |
| `-Credential` | `PSCredential` | no |  |
| `-LogName` | `String[]` | no | Channels to inspect. Default: all catalog-supported channels. |
| `-Path` | `String[]` | yes |  |
| `-ThrottleLimit` | `Int32` | no |  |

**Examples**

```powershell
Get-WinSecLogCoverage -CoveringFrom (Get-Date).AddDays(-7)
```


```powershell
Get-WinSecLogCoverage -ComputerName DC01, VPN01 -Credential $cred -LogName Security
```


```powershell
Get-WinSecLogCoverage -Path C:\Cases\*.evtx
```

### `Get-WinSecLogonSession`

Reconstructs logon sessions from collected events by chaining LogonId
references (4624 → 4672/4648 → 4634/4647).

```text
Get-WinSecLogonSession -Event <WinSecEvent[]> [-IncludeEnded] [<CommonParameters>]

Get-WinSecLogonSession -Event <WinSecEvent[]> [-ActiveOnly] [<CommonParameters>]

Get-WinSecLogonSession -Event <WinSecEvent[]> [-EndedOnly] [<CommonParameters>]
```

Turns a flat event list into attacker sessions: who logged on, from
where, with what logon type, whether the session held administrative
privileges (4672), which child sessions it spawned with explicit
credentials (4648 SubjectLogonId → new TargetLogonId), and how long it
lasted (4634/4647 close). Sessions that never closed are flagged —
on a live incident that is your "attacker may still be inside" list.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-ActiveOnly` | `SwitchParameter` | no | Return only sessions without a matching logoff — potential live
attacker footholds. |
| `-EndedOnly` | `SwitchParameter` | no | Return only sessions with a recorded 4634/4647 logoff — useful to
compute dwell time and to exclude still-open footholds from statistics. |
| `-Event` | `WinSecEvent[]` | yes | WinSecEvent objects (pipe from Get-WinSecEventByIp). Include the
BruteForce or IncidentResponse profile so 4624/4634/4647/4672/4648
are present. |
| `-IncludeEnded` | `SwitchParameter` | no | Explicitly return both open and closed sessions. This is the default
behaviour when no filter switch is given; the switch exists to make the
intent readable in scripts and to document that ended sessions are in
scope. Cannot be combined with -ActiveOnly or -EndedOnly. |

**Examples**

```powershell
$sessions = Get-WinSecEventByIp 203.0.113.7 -LastDays 2 | Get-WinSecLogonSession
$sessions | Where-Object IsAdmin | Sort-Object StartUtc
```


```powershell
Get-WinSecEventByIp 203.0.113.7 | Get-WinSecLogonSession -ActiveOnly
```

### `Import-WinSecCase`

Reopens an exported investigation bundle so analysis and reporting can
continue in a new session, on another workstation, or after a reboot.

```text
Import-WinSecCase [-Path] <string> [-SkipEvents] [<CommonParameters>]
```

Reads manifest.json, case.json and every artifact present in the bundle
and rebuilds the objects:

  Events       rehydrated WinSecEvent instances from events.json (or
               events.clixml when JSON is absent)
  Findings     Test-WinSecBruteForce findings
  Sessions     logon sessions (string-typed CSV rows)
  Coverage     log coverage rows
  Attribution  enrichment results
  Timeline     activity buckets

The case object is restored with its id, title, operator, notes and the
evidence table from the manifest, so a follow-up report references the
same chain of custody instead of inventing a new case.

Nothing is written; the cmdlet is read-only and safe on evidence media.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Path` | `String` | yes | Bundle directory (containing manifest.json) or the manifest path itself. |
| `-SkipEvents` | `SwitchParameter` | no | Skip event rehydration for very large bundles; other artifacts are still
loaded. |

**Examples**

```powershell
$b = Import-WinSecCase .\WSC-20261011-AB12CD34
$b.Events | Test-WinSecBruteForce -WindowMinutes 30
New-WinSecIncidentReport -Case $b.Case -Event $b.Events -Coverage $b.Coverage -PassThru
```


```powershell
$b = Import-WinSecCase .\bundle\manifest.json -SkipEvents
Test-WinSecEvidenceIntegrity -Path $b.BundlePath -Summary
```

### `New-WinSecAbuseReport`

Builds a ready-to-send abuse report for the network that hosts the
attacking IP: RFC 5322 .eml with evidence attachments, plus Markdown and
a structured JSON payload.

```text
New-WinSecAbuseReport [[-Case] <WinSecCase>] [[-Event] <Object[]>] [[-Finding] <Object[]>] [[-Attribution] <Object[]>] [[-TargetIp] <string>] [[-Provider] <string>] [[-ContactEmail] <string>] [[-ReporterName] <string>] [-ReporterEmail] <string> [[-ReporterOrg] <string>] [[-Format] <string>] [[-OutputDirectory] <string>] [[-FileName] <string>] [[-MaxEventsInBody] <int>] [-RedactAccounts] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Network operators act on evidence, not adjectives. This cmdlet packages
the facts an abuse desk needs — source address, ASN/PTR, UTC window,
attempt counts, targeted accounts and hosts, event IDs, sample records —
into three artifacts:

  EML   A complete MIME message with From/To/Subject/Date/Message-ID and
        base64 attachments (events.csv, evidence.json). Open it in any
        mail client and press Send; no SMTP configuration is required.
  MD    The same content for a ticket or a web form.
  JSON  Structured payload for APIs and ticketing systems.

The recipient is resolved from the attribution data (ASN organisation,
PTR) using a table of well-known abuse desks. Unknown networks produce
an empty mailbox and NeedsContact = true: the tool never invents an
address, and you must pass -ContactEmail.

Account names can be pseudonymised with -RedactAccounts when the report
leaves your organisation; the pseudonyms stay consistent inside one
report so the timeline remains readable.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Attribution` | `Object[]` | no | Enrichment from Resolve-WinSecIpAttribution — used for ASN, country,
PTR and the abuse-desk lookup. |
| `-Case` | `WinSecCase` | no | WinSecCase providing case id, title and subject IPs. |
| `-Confirm` | `SwitchParameter` | no |  |
| `-ContactEmail` | `String` | no | Explicit recipient. Overrides the built-in table. |
| `-Event` | `Object[]` | no | Collected events. Used for counts and evidence samples. |
| `-FileName` | `String` | no | Base file name without extension. |
| `-Finding` | `Object[]` | no | Detections from Test-WinSecBruteForce. They drive the verdict and the
summary sentence. |
| `-Format` | `String` | no | Eml, Markdown, Json or All (default). |
| `-MaxEventsInBody` | `Int32` | no | How many sample events to embed in the message body (1-500, default 25). |
| `-OutputDirectory` | `String` | no | Parent folder. Defaults to the DefaultOutputDirectory option, else the
current directory. |
| `-PassThru` | `SwitchParameter` | no | Emit a descriptor with paths, recipient, SHA-256 and NeedsContact. |
| `-Provider` | `String` | no | Abuse desk to address. Auto (default) infers it from ASN/PTR; Generic
requires -ContactEmail. |
| `-RedactAccounts` | `SwitchParameter` | no | Replace account names with stable pseudonyms (acct-XXXXXX). |
| `-ReporterEmail` | `String` | yes | Sender address (required — it becomes the From header). |
| `-ReporterName` | `String` | no | Display name of the sender. Defaults to 'Security Operations'. |
| `-ReporterOrg` | `String` | no | Organisation name inserted into the body and the JSON payload. |
| `-TargetIp` | `String` | no | Source address being reported. Defaults to the first subject IP of the
case, else the most frequent SourceIp among events. |
| `-WhatIf` | `SwitchParameter` | no |  |

**Examples**

```powershell
$att = Resolve-WinSecIpAttribution -IpAddress 203.0.113.7 -Provider None
New-WinSecAbuseReport -Case $case -Event $events -Attribution $att -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' -Format All -PassThru
```


```powershell
New-WinSecAbuseReport -Event $events -TargetIp 203.0.113.7 -Provider Hetzner -ReporterEmail 'ir@example.org' -RedactAccounts -Format Eml
```


```powershell
New-WinSecAbuseReport -Event $events -TargetIp 198.51.100.9 -Provider Generic -ContactEmail 'abuse@example.net' -ReporterEmail 'soc@contoso.com' -Format Json
```

### `New-WinSecCase`

Creates an investigation case that binds evidence, findings and notes
to a tamper-evident export bundle.

```text
New-WinSecCase [-SubjectIps] <string[]> [-Title <string>] [-Description <string>] [-ScopeHosts <string[]>] [-Operator <string>] [<CommonParameters>]
```

A WinSecCase is the unit of work for an incident responder. It carries
the case id, operator, subject IP(s), scope hosts, free-form notes and
findings. Export-WinSecInvestigation writes every artifact into a case
folder and records SHA-256 hashes in manifest.json (chain of custody).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Description` | `String` | no |  |
| `-Operator` | `String` | no |  |
| `-ScopeHosts` | `String[]` | no |  |
| `-SubjectIps` | `String[]` | yes | Attacker IP address(es)/CIDR(s) under investigation. Validated with the
same strict parser as Get-WinSecEventByIp. |
| `-Title` | `String` | no |  |

**Examples**

```powershell
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'Brute force vs VPN concentrator'
```


```powershell
$case = New-WinSecCase -SubjectIps 203.0.113.0/24 -ScopeHosts DC01, VPN01 -Operator 'soc@contoso.com'
$case.AddNote('Customer reported lockouts 02:00-03:00 UTC.')
```

### `New-WinSecIncidentReport`

Produces a narrative incident report (Markdown and/or HTML) from
collected events, detections, sessions, coverage and attribution.

```text
New-WinSecIncidentReport [[-Case] <WinSecCase>] [[-Event] <Object[]>] [[-Finding] <Object[]>] [[-Session] <Object[]>] [[-Coverage] <Object[]>] [[-Attribution] <Object[]>] [[-Timeline] <Object[]>] [[-Summary] <hashtable>] [[-Template] <string>] [[-Format] <string>] [[-OutputDirectory] <string>] [[-FileName] <string>] [-PassThru] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Turns raw telemetry into the document a responder actually hands over:
executive summary with verdict, severity and confidence; scope and
method; timeline; detection findings; indicators of compromise; logon
sessions; evidence-quality assessment; source attribution;
recommendations; and the chain-of-custody statement.

Two templates are available:
  Executive — one page for management: verdict, key facts, top
              indicators, immediate actions, custody.
  Technical — the full report for the case file.
  Full      — Technical plus appendices (events by ID, ATT&CK coverage).

Markdown is review-friendly (pull requests, tickets); HTML is a
self-contained dark-theme document with inline CSS, no scripts and no
external requests — safe to attach to an e-mail or open offline.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Attribution` | `Object[]` | no | Results from Resolve-WinSecIpAttribution. |
| `-Case` | `WinSecCase` | no | WinSecCase from New-WinSecCase. When omitted an ad-hoc case is derived
from the supplied events. |
| `-Confirm` | `SwitchParameter` | no |  |
| `-Coverage` | `Object[]` | no | Coverage rows from Get-WinSecLogCoverage — they drive the confidence
rating and the evidence-quality section. |
| `-Event` | `Object[]` | no | WinSecEvent objects from Get-WinSecEventByIp (or Import-WinSecCase). |
| `-FileName` | `String` | no | Base file name without extension. Defaults to
<CaseId>-incident-report. |
| `-Finding` | `Object[]` | no | Findings from Test-WinSecBruteForce. |
| `-Format` | `String` | no | Markdown, Html or Both (default). |
| `-OutputDirectory` | `String` | no | Parent folder. Defaults to the DefaultOutputDirectory option, else the
current directory. |
| `-PassThru` | `SwitchParameter` | no | Emit the descriptor object (paths, SHA-256, verdict, counts). |
| `-Session` | `Object[]` | no | Sessions from Get-WinSecLogonSession. |
| `-Summary` | `Hashtable` | no | Optional free-form facts merged into the report context. |
| `-Template` | `String` | no | Executive, Technical (default) or Full. |
| `-Timeline` | `Object[]` | no | Buckets from Get-WinSecIpTimeline. Without them the report falls back to
an events-by-ID summary. |
| `-WhatIf` | `SwitchParameter` | no |  |

**Examples**

```powershell
$events = Get-WinSecEventByIp 203.0.113.7 -LastDays 2 -PassHostStatus
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force vs VPN tier'
$events | Export-WinSecInvestigation -Case $case -Format All -PassThru
New-WinSecIncidentReport -Case $case -Event $events -Template Full -PassThru
```


```powershell
Import-WinSecCase .\WSC-20261011-AB12CD34 |
    ForEach-Object { New-WinSecIncidentReport -Case $_.Case -Event $_.Events -Coverage $_.Coverage -Format Html }
```

### `Resolve-WinSecIpAttribution`

Enriches attacker IPs: reverse DNS, RFC classification, optional
threat-intel lookups (AbuseIPDB / AlienVault OTX / ip-api) with caching.

```text
Resolve-WinSecIpAttribution [-IpAddress] <string[]> [-Provider <string>] [-NoCache] [-CacheHours <int>] [<CommonParameters>]
```

Offline-first by design: PTR resolution and private/loopback/link-local
classification never touch third-party services. Threat intelligence
is opt-in via -Provider (or the ThreatIntelProvider configuration
option) because sending internal IPs to public services can leak
investigation context.

API keys are read from ENVIRONMENT VARIABLES only (names configurable:
AbuseIpDbKeyEnvVar → ABUSEIPDB_KEY, OtxKeyEnvVar → OTX_API_KEY) — never
from parameters, so they cannot leak into shell history, transcripts or
logs. Results are cached per IP for AttributionCacheHours (default 72)
under the WinSecHunter config directory; -NoCache bypasses the cache.

ip-api.com free tier is HTTP-only — it is offered for lab use and
clearly marked in the Verdict.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-CacheHours` | `Int32` | no |  |
| `-IpAddress` | `String[]` | yes |  |
| `-NoCache` | `SwitchParameter` | no |  |
| `-Provider` | `String` | no |  |

**Examples**

```powershell
Resolve-WinSecIpAttribution -IpAddress 203.0.113.7
```


```powershell
$env:ABUSEIPDB_KEY = '...'
'203.0.113.7', '198.51.100.23' | Resolve-WinSecIpAttribution -Provider AbuseIPDB
```


```powershell
Get-WinSecEventByIp 203.0.113.7 | Select-Object -Expand SourceIp -Unique |
    Resolve-WinSecIpAttribution -Provider OTX
```

### `Set-WinSecHunterOption`

Persists WinSecHunter configuration options.

```text
Set-WinSecHunterOption [-Name] <string> [-Value] <Object> [-WhatIf] [-Confirm] [<CommonParameters>]

Set-WinSecHunterOption -Options <hashtable> [-WhatIf] [-Confirm] [<CommonParameters>]

Set-WinSecHunterOption [-Reset] [-WhatIf] [-Confirm] [<CommonParameters>]
```

Writes options to config.json under the WinSecHunter configuration
directory (%LOCALAPPDATA%\WinSecHunter on Windows,
~/.config/WinSecHunter elsewhere; override with
$env:WINSECHUNTER_CONFIG_DIR — handy for portable IR kits).

Threat-intel API keys are NEVER stored as options directly; store the
NAME of the environment variable that holds the key
(AbuseIpDbKeyEnvVar / OtxKeyEnvVar defaults: ABUSEIPDB_KEY / OTX_API_KEY).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Confirm` | `SwitchParameter` | no |  |
| `-Name` | `String` | yes |  |
| `-Options` | `Hashtable` | yes |  |
| `-Reset` | `SwitchParameter` | no |  |
| `-Value` | `Object` | yes |  |
| `-WhatIf` | `SwitchParameter` | no |  |

**Examples**

```powershell
Set-WinSecHunterOption -Options @{ DefaultProfile = 'BruteForce'; DefaultMaxEvents = 20000 }
```


```powershell
Set-WinSecHunterOption -Name ThreatIntelProvider -Value AbuseIPDB
```

### `Show-WinSecHunterHelp`

One-stop reference for the whole toolkit: workflow, cmdlets, profiles,
configuration, requirements and troubleshooting — or the full help of a
single cmdlet.

```text
Show-WinSecHunterHelp [[-Cmdlet] <string>] [[-OutFile] <string>] [-Detailed] [-Markdown] [-Plain] [-PassThru] [<CommonParameters>]
```

WinSecHunter ships 20 cmdlets, 14 hunt profiles and a 156-event catalog.
Remembering the parameter surface is unnecessary: this cmdlet prints a
task-oriented map (Collect → Analyze → Attribute → Report → Preserve)
plus a per-cmdlet reference.

With -Cmdlet it renders syntax, parameter table and examples for that
cmdlet. With -Markdown it returns a documentation-ready Markdown
document (used to generate docs/Command-Reference.md). With -OutFile the
content is written atomically, so the same command can feed a runbook.

Output is colourised on an interactive console and plain text when
redirected or with -Plain, which keeps CI logs readable.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Cmdlet` | `String` | no | Cmdlet name to describe (for example Get-WinSecEventByIp). Wildcards are
not supported; an unknown name lists every exported cmdlet. |
| `-Detailed` | `SwitchParameter` | no | Include parameter tables and examples for every cmdlet, not only the
overview. Ignored with -Cmdlet (that output is always detailed). |
| `-Markdown` | `SwitchParameter` | no | Emit Markdown instead of console text. Combine with -OutFile to write a
reference page, or with -PassThru to capture the string. |
| `-OutFile` | `String` | no | Write the rendered text to this path (UTF-8, no BOM, atomic replace).
Parent directories are created. The path is returned. |
| `-PassThru` | `SwitchParameter` | no | Return the rendered text as a string instead of writing it to the host. |
| `-Plain` | `SwitchParameter` | no | Disable ANSI colour even on an interactive console. |

**Examples**

```powershell
Show-WinSecHunterHelp
```


```powershell
Show-WinSecHunterHelp -Cmdlet Get-WinSecEventByIp -Detailed
```


```powershell
Show-WinSecHunterHelp -Markdown -OutFile .\docs\Command-Reference.md
```


```powershell
Show-WinSecHunterHelp -Cmdlet New-WinSecAbuseReport | Out-String -Width 200
```

### `Test-WinSecAuditPolicy`

Finds audit-policy gaps: subcategories that are NOT recording the
events an IP investigation depends on.

```text
Test-WinSecAuditPolicy [[-ComputerName] <string[]>] [[-Credential] <pscredential>] [[-ThrottleLimit] <int>] [[-Profile] <string[]>] [-IncludeCompliant] [<CommonParameters>]
```

The most painful IR discovery is "the events you need were never
audited". This cmdlet reads the effective advanced audit policy
(auditpol /get /category:* /r — CSV, parsed locale-independently by
subcategory GUID) and compares it against the WinSecHunter requirement
matrix derived from the event catalog.

Each gap is emitted as WinSecAuditGap with the affected event IDs and
a ready-to-paste remediation command:
    auditpol /set /subcategory:"{GUID}" /success:enable /failure:enable

-Profile restricts the requirement matrix to what you actually hunt
(e.g. Rdp needs Logon + Other Logon/Logoff; BruteForce adds Kerberos
Authentication Service and Credential Validation).

Requires elevation to read the full policy on some configurations;
remote hosts are queried over WinRM in parallel.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-ComputerName` | `String[]` | no |  |
| `-Credential` | `PSCredential` | no |  |
| `-IncludeCompliant` | `SwitchParameter` | no |  |
| `-Profile` | `String[]` | no |  |
| `-ThrottleLimit` | `Int32` | no |  |

**Examples**

```powershell
Test-WinSecAuditPolicy
```


```powershell
Test-WinSecAuditPolicy -ComputerName DC01, SRV02 -Credential $cred -Profile BruteForce, Rdp
```


```powershell
Test-WinSecAuditPolicy -IncludeCompliant | Format-Table -AutoSize
```

### `Test-WinSecBruteForce`

Detects brute-force, password-spraying, credential-stuffing and
lockout-storm patterns in collected events and rates their severity.

```text
Test-WinSecBruteForce [-Event] <WinSecEvent[]> [[-FailureThreshold] <int>] [[-WindowMinutes] <int>] [[-SprayAccountThreshold] <int>] [[-SuccessWindowMinutes] <int>] [[-LockoutThreshold] <int>] [[-MaxEvidencePerFinding] <int>] [<CommonParameters>]
```

Detection logic (all UTC, all thresholds configurable):

* BruteForce — ≥ FailureThreshold failed authentications from ONE
  source IP against ONE account inside WindowMinutes.
* PasswordSpraying — ONE source IP touching ≥ SprayAccountThreshold
  DISTINCT accounts with failures inside WindowMinutes (typically
  few attempts per account — defeats per-account thresholds).
* CredentialStuffing — ONE account hit from ≥ 3 distinct source IPs
  with failures inside WindowMinutes (distributed attack).
* BruteForceWithSuccess — any of the above followed by a SUCCESS for
  the same source/account within SuccessWindowMinutes → treat as
  possible compromise (Critical). Successes include 4624, RDP 1149/21/25,
  Kerberos 0x0 results and NTLM 4776 with status 0x0.
* LockoutStorm — ≥ LockoutThreshold account lockouts (4740) in scope.

Failure sources: 4625, 4771, 4776 (non-zero status), RCM 1148, wireless
5632/5633. Findings carry an evidence list (capped at 1000 events) and
MITRE ATT&CK IDs (T1110 family).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Event` | `WinSecEvent[]` | yes | WinSecEvent objects (pipe from Get-WinSecEventByIp). |
| `-FailureThreshold` | `Int32` | no |  |
| `-LockoutThreshold` | `Int32` | no |  |
| `-MaxEvidencePerFinding` | `Int32` | no |  |
| `-SprayAccountThreshold` | `Int32` | no |  |
| `-SuccessWindowMinutes` | `Int32` | no |  |
| `-WindowMinutes` | `Int32` | no |  |

**Examples**

```powershell
Get-WinSecEventByIp 203.0.113.7 -LastDays 1 | Test-WinSecBruteForce
```


```powershell
$findings = $events | Test-WinSecBruteForce -FailureThreshold 10 -WindowMinutes 5
$findings | Where-Object SucceededAfterFailures   # compromise candidates
```

### `Test-WinSecEvidenceIntegrity`

Verifies an exported evidence bundle against its SHA-256 manifest and
reports modified, missing or unexpected files.

```text
Test-WinSecEvidenceIntegrity [-Path] <string> [-Algorithm <string>] [-ProblemsOnly] [-Summary] [-Json] [<CommonParameters>]
```

Export-WinSecInvestigation writes manifest.json last and records the
SHA-256, byte size and UTC write time of every artifact. This cmdlet
re-computes those hashes and compares them, so "the bundle is intact"
becomes a measured statement rather than an assumption.

Four conditions are reported:
  OK         hash and size match
  Modified   file exists but content or size changed
  Missing    manifest lists a file that is not present
  Extra      file exists in the bundle but is not in the manifest
  Unreadable file exists but cannot be hashed (locked/permissions)

Extra files matter: an attacker (or a careless operator) can append a
file to a bundle without breaking any recorded hash. The manifest alone
cannot detect addition — this cmdlet can.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Algorithm` | `String` | no | Hash algorithm recorded in the manifest. SHA256 by default; SHA384 and
SHA512 are accepted for bundles produced by other tooling. |
| `-Json` | `SwitchParameter` | no | Return a JSON document (summary + rows) for ingestion by a pipeline. |
| `-Path` | `String` | yes | Bundle directory (the one containing manifest.json) or the path to
manifest.json itself. |
| `-ProblemsOnly` | `SwitchParameter` | no | Return only rows whose Status is not OK. |
| `-Summary` | `SwitchParameter` | no | Return one object with counts, bundle path, case id, generation time and
a Rows property instead of a row stream. |

**Examples**

```powershell
Test-WinSecEvidenceIntegrity -Path .\WSC-20261011-AB12CD34
```


```powershell
$r = Test-WinSecEvidenceIntegrity .\WSC-20261011-AB12CD34 -ProblemsOnly -Summary
if ($r.Problems -gt 0) { throw "Evidence bundle failed verification: $($r.Problems) problem(s)" }
```


```powershell
Test-WinSecEvidenceIntegrity .\bundle -Json | Set-Content .\integrity.json -Encoding utf8NoBOM
```

### `Trace-WinSecIp`

Near-real-time tail of Windows event logs for a specific IP — live
monitoring during an ongoing incident.

```text
Trace-WinSecIp [-IpAddress] <string[]> [-Profile <string[]>] [-Category <string[]>] [-EventId <int[]>] [-LogName <string[]>] [-IntervalSeconds <int>] [-Duration <timespan>] [-StartTime <datetime>] [-DeepScan] [-IncludeMessage] [<CommonParameters>]
```

Polls the selected channels every -IntervalSeconds using a per-log
RecordId bookmark with a small time overlap, so nothing is missed
between cycles and nothing is duplicated in the output. Each matching
WinSecEvent is emitted to the pipeline as it appears (works with
Out-GridView, Tee-Object, SIEM forwarders, etc.).

Deliberately polling-based: no ETW consumer dependency, works from an
elevated shell on any Windows host, and degrades gracefully. Ctrl+C
stops the trace cleanly (bookmarks are reported on exit).

Runs against the LOCAL machine by design — for remote live monitoring,
run WinSecHunter inside a remote session (Enter-PSSession) or schedule
repeated Get-WinSecEventByIp sweeps.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `-Category` | `String[]` | no |  |
| `-DeepScan` | `SwitchParameter` | no |  |
| `-Duration` | `TimeSpan` | no | Stop after this timespan (default: run until Ctrl+C). |
| `-EventId` | `Int32[]` | no |  |
| `-IncludeMessage` | `SwitchParameter` | no |  |
| `-IntervalSeconds` | `Int32` | no |  |
| `-IpAddress` | `String[]` | yes |  |
| `-LogName` | `String[]` | no |  |
| `-Profile` | `String[]` | no |  |
| `-StartTime` | `DateTime` | no | Begin scanning from this point instead of "now" (e.g. catch the last
hour while you set up). |

**Examples**

```powershell
Trace-WinSecIp -IpAddress 203.0.113.7 -IntervalSeconds 5
```


```powershell
Trace-WinSecIp 203.0.113.7 -Profile Rdp -Duration ([timespan]::FromHours(2)) |
    Tee-Object -FilePath .\live-rdp.jsonl -Append |
    ForEach-Object { Write-Information ("{0:HH:mm:ss} {1} {2}" -f $_.TimeCreated, $_.EventId, $_.TargetAccount) -InformationAction Continue }
```
