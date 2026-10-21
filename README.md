# WinSecHunter

**Incident-response toolkit for Windows security events — collect everything an attacker IP did to your estate, prove it, and report it.**

[![CI](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/actions/workflows/ci.yml/badge.svg)](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/actions/workflows/ci.yml)
[![PowerShell 7.6+](https://img.shields.io/badge/PowerShell-7.6%2B-blue)](https://aka.ms/powershell)
[![Platform](https://img.shields.io/badge/collect-Windows%20%7C%20analyse-any-lightgrey)](#platform-support)
[![License: PolyForm NC 1.0.0](https://img.shields.io/badge/License-PolyForm%20NC%201.0.0-orange.svg)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-168%20passing-brightgreen)](./tests)

WinSecHunter is a complete, ground-up refactoring of
[`Get-SecurityEventsByIP.ps1`](https://github.com/paulmann/Get-Windows-Security-Events-By-IP)
(v5.0.2, Mikhail Deynekin) into a production **PowerShell 7.6+ module**. It turns a single
log query into a full DFIR workflow: multi-host collection, offline EVTX analysis,
brute-force detection, session reconstruction, evidence with a SHA-256 chain of custody,
incident reports and ready-to-send abuse reports.

---

## What it does

- **Collects** every event that references an attacker IP — IPv4, IPv6 or CIDR — from the
  local host, remote hosts over WinRM/CIM, or acquired `.evtx` files.
- **Normalizes and decodes** the records: UTC and local time, logon types, NTSTATUS,
  Kerberos and `%%` failure codes, WFP direction, MITRE ATT&CK mapping, catalog metadata.
- **Analyzes**: brute force, password spraying, credential stuffing, lockout storms,
  success-after-failure, logon-session chaining, activity timeline, audit-policy gaps and
  log-coverage completeness.
- **Attributes**: offline-first PTR/classification, optional AbuseIPDB, AlienVault OTX and
  ip-api enrichment with caching. API keys are read from environment variables only.
- **Reports**: executive or technical incident report (Markdown + self-contained HTML),
  RFC 5322 abuse report with evidence attachments, and IOC export as CSV/TXT/JSON/STIX 2.1.
- **Preserves**: tamper-evident evidence bundle with a SHA-256 manifest, integrity
  verification, and case re-import for follow-up work.

Everything is one module with 20 cmdlets and an in-module reference (`Show-WinSecHunterHelp`).

## Why it exists

The legacy script answered one question well but could not survive production use: one
1,092-line file, `Write-Host`/`exit`, no tests, `-MaxEvents` applied before time filtering,
a single log channel, and no way to hand evidence to anyone else.

| Concern | Legacy script | WinSecHunter 2.1 |
|---|---|---|
| Structure | 1,092-line script | module, typed classes, 20 cmdlets |
| Channels | Security only | Security, System, RDP (RCM/LSM), Firewall, Sysmon |
| Collection | local only | local, WinRM/CIM multi-host, offline EVTX |
| Failure model | one missing channel aborts | per-channel status; missing channel = `Skipped` |
| Evidence | CSV/HTML | bundle + SHA-256 manifest + integrity verification |
| Reporting | table dump | incident report, abuse report, IOC/STIX |
| Quality | none | 168 passing tests, PSScriptAnalyzer gate, CI matrix |

## Quick start

```powershell
# 1. Install from source (a PSGallery release may lag behind the repository)
git clone https://github.com/paulmann/Get-Windows-Security-Events-By-IP.git
cd Get-Windows-Security-Events-By-IP
./build/Install-Dev.ps1 -Force

# 2. Collect: local host, last 48 hours, with per-channel status
$events = Get-WinSecEventByIp -IpAddress 203.0.113.7 -LastDays 2 -PassHostStatus

# 3. Understand what the logs can prove
Get-WinSecLogCoverage -LogName Security
Test-WinSecAuditPolicy

# 4. Analyze
$events | Get-WinSecIpTimeline -AsciiChart
$findings = $events | Test-WinSecBruteForce
$sessions = $events | Get-WinSecLogonSession -ActiveOnly

# 5. Attribute and preserve
$attribution = Resolve-WinSecIpAttribution -IpAddress 203.0.113.7 -Provider None
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force vs VPN tier'
$case = Export-WinSecInvestigation -Case $case -Event $events -Finding $findings `
            -Session $sessions -Attribution $attribution -Format All -PassThru

# 6. Report
New-WinSecIncidentReport -Case $case -Event $events -Finding $findings `
    -Session $sessions -Attribution $attribution -Template Full -Format Both -PassThru
New-WinSecAbuseReport -Case $case -Event $events -Finding $findings `
    -Attribution $attribution -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC'
Export-WinSecIocList -Case $case -Event $events -Finding $findings -Format Stix21

# 7. Verify before sharing
Test-WinSecEvidenceIntegrity -Path .\WSC-20261021-XXXXXXXX -Summary
```

Need the whole map at any time?

```powershell
Show-WinSecHunterHelp                    # workflow, cmdlets, profiles, config, troubleshooting
Show-WinSecHunterHelp -Cmdlet New-WinSecAbuseReport
Show-WinSecHunterHelp -Markdown -OutFile .\docs\Command-Reference.md
```

## Workflow map

| Stage | Cmdlets | Question answered |
|---|---|---|
| **Collect** | `Get-WinSecEventByIp`, `Trace-WinSecIp`, `Get-WinSecLogCoverage` | What happened, where, and can the logs prove it? |
| **Analyze** | `Get-WinSecIpTimeline`, `Get-WinSecLogonSession`, `Test-WinSecBruteForce`, `Test-WinSecAuditPolicy` | Was it an attack, did it succeed, who is still inside? |
| **Enrich** | `Resolve-WinSecIpAttribution`, `Expand-WinSecIpRange` | Whose address is it, and what does the range cover? |
| **Report** | `New-WinSecIncidentReport`, `New-WinSecAbuseReport`, `Export-WinSecIocList` | What do I hand to management, the ISP, the TIP? |
| **Preserve** | `New-WinSecCase`, `Export-WinSecInvestigation`, `Import-WinSecCase`, `Test-WinSecEvidenceIntegrity` | Can I prove the evidence was not altered? |
| **Reference** | `Get-WinSecEventCatalog`, `Get-WinSecHunterOption`, `Set-WinSecHunterOption`, `Show-WinSecHunterHelp` | What is catalogued, how is it configured? |

## What's new in 2.1.0

- **Six new cmdlets**: `Show-WinSecHunterHelp`, `New-WinSecIncidentReport`,
  `New-WinSecAbuseReport`, `Export-WinSecIocList`, `Test-WinSecEvidenceIntegrity`,
  `Import-WinSecCase`.
- **Per-channel execution.** Every channel is queried separately; a missing Sysmon, RDP or
  firewall log is one `Skipped` row, not a failed sweep. `WinSecHostResult.LogDetails`
  explains each channel.
- **Three collection defects fixed**, each of which made normal use impossible:
  `-LastHours/-LastDays` crashed on `$null` time binding; every `-ComputerName` sweep
  aborted on a `$foreach -Parallel` scriptblock restriction; `-PassHostStatus` output was
  lost when a channel was unavailable.
- **Evidence hardening**: IOC artifacts inside the manifest, reports written outside the
  bundle, atomic configuration writes, localized `auditpol` parsing.
- **Privacy**: `-RedactAccounts` now also masks account names inside attached evidence.
- **Honest numbers** in documentation and a `build/` toolchain the CI actually uses.

Full details: [CHANGELOG.md](CHANGELOG.md).

## Command reference

### Collect

| Cmdlet | Purpose |
|---|---|
| `Get-WinSecEventByIp` | Sweep local logs, remote hosts or EVTX files for an IP/CIDR. |
| `Trace-WinSecIp` | Near-real-time tail with per-log record bookmarks. |
| `Get-WinSecLogCoverage` | Retention, size, wrap risk and accessibility per channel. |

### Analyze

| Cmdlet | Purpose |
|---|---|
| `Get-WinSecIpTimeline` | UTC buckets, ASCII histogram, top accounts/hosts. |
| `Get-WinSecLogonSession` | Reconstruct sessions from 4624 → 4672/4648 → 4634/4647. |
| `Test-WinSecBruteForce` | Brute force, spraying, stuffing, lockout storms, success after failure. |
| `Test-WinSecAuditPolicy` | Audit-policy gaps that would hide the activity. |

### Enrich

| Cmdlet | Purpose |
|---|---|
| `Resolve-WinSecIpAttribution` | PTR/classification always; optional AbuseIPDB/OTX/ip-api. |
| `Expand-WinSecIpRange` | Expand a CIDR into addresses with safety limits. |

### Report

| Cmdlet | Purpose |
|---|---|
| `New-WinSecIncidentReport` | Executive/Technical/Full report to Markdown and HTML. |
| `New-WinSecAbuseReport` | RFC 5322 `.eml` + Markdown + JSON for the source network. |
| `Export-WinSecIocList` | Indicators as CSV, text, JSON or STIX 2.1. |

### Preserve

| Cmdlet | Purpose |
|---|---|
| `New-WinSecCase` | Case object binding subject IPs, scope hosts, notes. |
| `Export-WinSecInvestigation` | Evidence bundle with SHA-256 manifest. |
| `Import-WinSecCase` | Reopen a bundle with typed events for follow-up. |
| `Test-WinSecEvidenceIntegrity` | Verify hashes; detect modified, missing **and added** files. |

### Reference

| Cmdlet | Purpose |
|---|---|
| `Get-WinSecEventCatalog` | 156 events, 14 profiles, ATT&CK mapping. |
| `Get-WinSecHunterOption` / `Set-WinSecHunterOption` | Effective configuration, validated writes. |
| `Show-WinSecHunterHelp` | Whole-toolkit reference, console or Markdown. |

## Scenarios

### 1. RDP brute force that succeeded

```powershell
$events = Get-WinSecEventByIp 203.0.113.7 -LastDays 3 -Profile IncidentResponse -PassHostStatus
$findings = $events | Test-WinSecBruteForce -WindowMinutes 30
$findings | Format-Table Pattern, Severity, TargetAccount, FailureCount, SuccessCount

# The report escalates the verdict to "Credential compromise — success observed after failures"
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force vs VPN tier' -ScopeHosts VPN01, VPN02
New-WinSecIncidentReport -Case $case -Event $events -Finding $findings -Template Executive -Format Html -PassThru
```

### 2. Multi-host sweep that explains every host

```powershell
$status = Get-WinSecEventByIp 203.0.113.7 -ComputerName (Get-Content .\hosts.txt) `
            -Credential (Get-Credential) -ThrottleLimit 16 -LastHours 12 -PassHostStatus
$status | Format-Table Computer, Status, EventsFound, ErrorMessage
$status | ForEach-Object { $_.LogDetails } | Group-Object Status | Select-Object Name, Count
```

### 3. Offline EVTX from an acquired disk

```powershell
$events = Get-WinSecEventByIp 198.51.100.9 -Path D:\Evidence\*.evtx -Profile All
$events | Export-WinSecInvestigation -Format All -OutputDirectory D:\IR -PassThru
```

### 4. Share indicators with a TIP and report to the ISP

```powershell
$attribution = Resolve-WinSecIpAttribution -IpAddress 203.0.113.7 -Provider None
Export-WinSecIocList -Case $case -Event $events -Finding $findings -Format Stix21
New-WinSecAbuseReport -Case $case -Event $events -Finding $findings -Attribution $attribution `
    -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' -RedactAccounts
```

## Reporting and abuse workflow

`New-WinSecIncidentReport` writes two files into `<CaseId>-reports/`:
`<CaseId>-incident-report.md` and `.html`. The HTML document is fully self-contained
(inline CSS, no scripts, no external requests), so it can be attached to a ticket or opened
offline. Sections: executive summary (verdict, severity, confidence), scope and method,
timeline, findings, indicators, sessions, evidence quality, attribution, recommendations,
chain of custody, and — in the `Full` template — events by ID and ATT&CK coverage.

`New-WinSecAbuseReport` produces an `.eml` you can open in any mail client and send:

- recipient resolved from ASN/PTR (AWS, Azure, GCP, DigitalOcean, Hetzner, OVH, Cloudflare,
  Contabo, Linode, Vultr, Oracle, Alibaba, Tencent); unknown networks require
  `-ContactEmail` — the tool never invents an address;
- plain-text body (friendly to abuse-desk automation) with source facts, counts, sample
  events and requested action;
- `events.csv` and `evidence.json` attached as base64, with consistent pseudonyms when
  `-RedactAccounts` is used.

Reports never go inside the evidence bundle, so `Test-WinSecEvidenceIntegrity` stays green.

## Evidence and chain of custody

```text
WSC-20261021-AB12CD34/
  events.csv / events.json / events.clixml
  findings.json
  sessions.csv
  coverage.csv
  attribution.json
  timeline.csv
  iocs.csv / iocs.json
  report.html / report.md
  case.json
  manifest.json          ← SHA-256, bytes, UTC write time for every artifact
```

```powershell
$s = Test-WinSecEvidenceIntegrity -Path .\WSC-20261021-AB12CD34 -Summary
if (-not $s.IsIntact) { $s.Rows | Where-Object Status -ne 'OK' | Format-Table }

$b = Import-WinSecCase -Path .\WSC-20261021-AB12CD34
$b.Events | Get-WinSecIpTimeline -AsciiChart
```

`Extra` is a first-class status: the manifest cannot detect a file added after export, the
verifier can.

## Platform support

- **Collection** (`Get-WinSecEventByIp`, `Trace-WinSecIp`, `Get-WinSecLogCoverage`,
  `Test-WinSecAuditPolicy`): Windows 10/11/Server 2016+. Reading the Security log requires
  an elevated session. Remote collection needs WinRM (`Enable-PSRemoting`) or a CIM session.
- **Analysis and reporting** (timeline, brute force, sessions, reports, IOC, integrity,
  import): any OS with PowerShell 7.6 — including Linux and macOS.
- **Offline EVTX**: reading acquired files works wherever `Get-WinEvent -Path` is available.
- No external binaries, no cloud dependency, no telemetry.

## Configuration

```powershell
Get-WinSecHunterOption                     # effective values
Set-WinSecHunterOption -DefaultProfile BruteForce -DefaultMaxEvents 20000
Show-WinSecHunterHelp                      # all 15 options with defaults
```

| Location | Value |
|---|---|
| Windows | `%LOCALAPPDATA%\WinSecHunter\config.json` (resolved via `[Environment]::GetFolderPath`) |
| Linux/macOS | `$XDG_CONFIG_HOME/WinSecHunter/config.json` or `~/.config/WinSecHunter/config.json` |
| Override | `WINSECHUNTER_CONFIG_DIR` (portable IR kit) |

Threat-intel keys are read only from environment variables named by configuration
(`AbuseIpDbKeyEnvVar`, `OtxKeyEnvVar`) — never from parameters, never written to disk.
`config.json` is written atomically; a crashed writer cannot leave a truncated file.

## Requirements

| Requirement | Notes |
|---|---|
| PowerShell **7.6+** (Core) | Windows PowerShell 5.1 is not supported |
| Pester 5.4+ | tests only |
| PSScriptAnalyzer 1.25+ | static analysis gate |
| WinRM / CIM | remote collection |
| Elevated session | Security log, audit policy |

## Troubleshooting

| Symptom | First check |
|---|---|
| `No events` but activity is known | `Get-WinSecLogCoverage` (retention) and `Test-WinSecAuditPolicy` (is it audited?) |
| `Access is denied` reading Security | run elevated; the channel requires Administrator |
| A host failed | `-PassHostStatus`: `Status` plus `LogDetails` per channel |
| Sysmon/RDP channel missing | expected on servers without those roles; it is `Skipped`, the sweep continues |
| Audit policy analysis empty | `auditpol` needs elevation; output is parsed positionally, so localization is fine |
| Report hashes do not match | files changed after export; re-export and keep bundles read-only |
| Abuse recipient empty | `NeedsContact = true`; pass `-ContactEmail` |
| `Install-Module` fails | the gallery release may lag; use `build/Install-Dev.ps1` from source |

## Project layout

```text
src/WinSecHunter/
  Enums/      enums used by the typed model
  Classes/    WinSecEvent, WinSecCase, sessions, findings, coverage, attribution, host results
  Private/    query builder, per-channel executor, parser, decoders, config, reporting
  Public/     20 cmdlets, one file each
  Resources/  EventCatalog.json (156 events, 6 channels, 14 profiles)
tests/        Pester 5 suites (168 passing, 1 Windows-only guard skipped)
build/        Build-Module, Install-Dev, validate, Export-CatalogDoc
docs/         architecture, examples, audit guide, generated catalog and command reference
wiki/         source of the GitHub Wiki
```

## Build, test, contribute

```powershell
./build/validate.ps1 -Tests            # AST, manifest, exports, help, PSSA, Pester
./build/Build-Module.ps1 -Zip          # validated artifact + zip under output/
./build/Install-Dev.ps1 -Force         # install into the user module path
./build/Export-CatalogDoc.ps1          # regenerate docs/EventCatalog.md and Command-Reference.md
./build/Export-CatalogDoc.ps1 -Check   # exit 10 when generated docs are stale
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and the definition of done, and
[SECURITY.md](SECURITY.md) for the security model and vulnerability reporting.

## Documentation

- [Architecture](docs/Architecture.md) — layers, query engine, reporting pipeline.
- [Examples](docs/Examples.md) — runnable scenarios.
- [Audit Policy Guide](docs/AuditPolicyGuide.md) — what must be audited for the tool to see anything.
- [Event Catalog](docs/EventCatalog.md) — 156 events with ATT&CK mapping (generated).
- [Command Reference](docs/Command-Reference.md) — every cmdlet, parameter and example (generated).
- [Wiki](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/wiki) — task-oriented guides.

## Licence and attribution

**PolyForm Noncommercial License 1.0.0** — free for noncommercial use; commercial use, support
and custom terms require a licence: **mid1977@gmail.com**. The full text is in
[LICENSE](LICENSE).

WinSecHunter is a derivative work of `Get-SecurityEventsByIP.ps1` by **Mikhail Deynekin**
(mid1977@gmail.com, https://deynekin.com). Releases up to 2.0.0 were published under
GPL-3.0-or-later; 2.1.0 is relicensed by the copyright holder under PolyForm Noncommercial
1.0.0. Attribution is preserved in the module manifest and in every source header. See
[CHANGELOG.md](CHANGELOG.md) for the full history.

