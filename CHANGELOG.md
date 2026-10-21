# Changelog

All notable changes to WinSecHunter are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [2.1.0] - 2026-10-21

Production hardening and the reporting surface an incident responder was missing.
Version 2.1.0 also fixes three defects that made normal collection fail outright.

### Added — Reporting and case work
- `Show-WinSecHunterHelp` — one-stop reference: workflow map, all cmdlets, profiles,
  configuration, requirements, troubleshooting; `-Cmdlet` for a single cmdlet,
  `-Markdown`/`-OutFile` to generate documentation.
- `New-WinSecIncidentReport` — Executive / Technical / Full templates rendered to
  Markdown and a self-contained HTML document: verdict, severity, confidence,
  timeline, findings, IOCs, sessions, coverage, attribution, recommendations and
  chain-of-custody statement.
- `New-WinSecAbuseReport` — RFC 5322 `.eml` ready to send, plus Markdown and JSON.
  Resolves the abuse desk from ASN/PTR (AWS, Azure, GCP, DigitalOcean, Hetzner, OVH,
  Cloudflare, Contabo, Linode, Vultr, Oracle, Alibaba, Tencent), attaches CSV/JSON
  evidence as base64, and can pseudonymise account names consistently.
- `Export-WinSecIocList` — CSV, grep-friendly text, JSON and a STIX 2.1 bundle.
- `Test-WinSecEvidenceIntegrity` — verifies manifest hashes and detects modified,
  missing and *added* files; `-Summary` and `-Json` for automation.
- `Import-WinSecCase` — reopens a bundle in a new session, rehydrating typed events
  and restoring the case with its evidence table.
- Evidence bundles now include `iocs.csv` and `iocs.json`.
- `WinSecHostResult.LogDetails` — per-channel status (Completed / NoEvents / Skipped /
  Failed) so a sweep explains every channel instead of failing as a whole.

### Added — Engineering
- Restored the `build/` toolchain the CI and documentation already referenced:
  `Build-Module.ps1`, `Install-Dev.ps1`, `validate.ps1`, `Export-CatalogDoc.ps1`.
- `docs/Command-Reference.md` generated from live help metadata.
- Regression suites for every defect below (`tests/Regression.Tests.ps1`) and the new
  reporting surface (`tests/Reporting.Tests.ps1`).
- `SECURITY.md`, `CONTRIBUTING.md`, `.gitattributes`.

### Changed
- `-MaxEvents` is now a **per-channel** cap (channels are queried independently).
- Reports are written to `<CaseId>-reports/`, never into the evidence bundle, so the
  manifest stays verifiable.
- Configuration directory is resolved through `[Environment]::GetFolderPath`, so the
  module works in service accounts, scheduled tasks and stripped environments where
  `LOCALAPPDATA`/`HOME` are absent.
- `Get-WinSecLogonSession` gains `-EndedOnly`; `-IncludeEnded` is now an explicit,
  documented filter (mutually exclusive with `-ActiveOnly`).
- Invalid IP input in `Resolve-WinSecIpAttribution` is a warning, not a terminating
  error, so one bad address cannot abort a batch.
- `auditpol /r` output is parsed by column position: localized Windows headers no longer
  break audit-policy analysis.
- Project relicensed to **PolyForm Noncommercial 1.0.0** (owner decision). Releases up to
  2.0.0 were published under GPL-3.0-or-later; attribution to the original author is preserved.
- Legacy `Get-SecurityEventsByIP.ps1` removed from `main`. It remains available at tag
  [`v5.0.2`](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/tree/v5.0.2) and as
  a release asset, and is no longer maintained.
- Log errors are classified by `HResult`/Win32 code with a message fallback, so access
  denied and missing channels are recognized on non-English systems.

### Fixed
- **Collection crashed whenever no time window was supplied** — `[AllowNull()][datetime]`
  cannot bind `$null`; `-LastHours`, `-LastDays`, EVTX mode and the CI smoke job all failed.
  Time bounds now use an explicit sentinel and no `$null` reaches value types.
- **Every `-ComputerName` sweep aborted** with "A ForEach-Object -Parallel using variable
  cannot be a script block" in `Get-WinSecEventByIp`, `Get-WinSecLogCoverage` and
  `Test-WinSecAuditPolicy`. The remote block is passed as text and rebuilt in the runspace.
- **`-PassHostStatus` output was lost** and a single unavailable channel aborted the sweep:
  the module sets `EAP=Stop`, and `Write-Error` terminated the call before statuses were
  emitted. Status is emitted first; channel problems are warnings; each channel is queried
  separately, so a missing Sysmon log no longer hides Security events.
- AlienVault OTX endpoint corrected (`otx.aliengault.com` did not resolve).
- IPv6 attribution cache used `:` in a Windows file name and silently never cached.
- `config.json` is written atomically (temp file + replace); concurrent writers cannot
  truncate it.
- HTML/CSV export no longer crashes on empty coverage timestamps.
- `-RedactAccounts` now also masks account names inside the attached CSV/JSON evidence.
- Abuse `.eml` `Message-ID` had a doubled angle bracket.
- Help for `New-WinSecAbuseReport` was not parsed at all (lines beginning with `.eml`).
- `Get-WinSecLogonSession` documentation promised a parameter that did not exist.
- `Set-WinSecHunterOption` help named `*KeyEnv` instead of `*KeyEnvVar`.
- Collection of `iocs.csv`/`iocs.json` is now part of the manifest instead of appearing
  after export and breaking integrity checks.

## [2.0.0] - 2026-10-11

Complete ground-up refactoring of `Get-SecurityEventsByIP.ps1` v5.0.2
(Mikhail Deynekin, GPL-3.0) into a production-grade PowerShell 7.6+ module.
No backward compatibility with the legacy script is provided by design.

### Added — Architecture
- Proper PowerShell module (`WinSecHunter`) with manifest, dot-sourced
  loader, explicit export allow-list, typed classes and enums, formatting
  file (`.Format.ps1xml`) and lazy-loaded JSON resources.
- 14 public cmdlets replacing one 1,092-line script:
  `Get-WinSecEventByIp`, `Get-WinSecIpTimeline`, `Get-WinSecLogonSession`,
  `Test-WinSecBruteForce`, `Get-WinSecLogCoverage`, `Test-WinSecAuditPolicy`,
  `Resolve-WinSecIpAttribution`, `Export-WinSecInvestigation`,
  `New-WinSecCase`, `Trace-WinSecIp`, `Expand-WinSecIpRange`,
  `Get-WinSecEventCatalog`, `Set-WinSecHunterOption`, `Get-WinSecHunterOption`.

### Added — Collection
- Event catalog of 156 Windows event IDs across 6 channels: Security,
  System, RDP RemoteConnectionManager/LocalSessionManager operational logs,
  Windows Firewall operational log and Sysmon — each with MITRE ATT&CK
  mapping, importance rating and IP-bearing field metadata.
- 14 hunt profiles (IncidentResponse default, FailedAuth, BruteForce, Rdp,
  Lateral, AccountManagement, Kerberos, Firewall, DefenseEvasion,
  Persistence, Sysmon, ObjectAccess, Critical, All).
- Remote multi-host sweeps over WinRM with parallel fan-out
  (`ForEach-Object -Parallel`), throttling, retry and per-host status
  reporting (`-PassHostStatus`); `-CimSession` transport; `-Credential`,
  `-Authentication`, `-SessionOption` pass-through.
- Offline EVTX forensics (`-Path`, wildcards).
- Server-side XPath pushdown for channels, event IDs and UTC time windows;
  exact-IP gating incl. IPv4-mapped IPv6 (`::ffff:a.b.c.d`, hex-mapped) and
  `UserData/EventXML/Address` (RDP logs); `-DeepScan` mode that regex-matches
  the IP anywhere in the record (command lines, UNC paths, task XML).
- IPv4/IPv6/CIDR sweep targets with strict validation and canonicalization.
- `Trace-WinSecIp`: bookmarked near-real-time tailing for live incidents.

### Added — Analysis
- `Test-WinSecBruteForce`: brute force, password spraying, credential
  stuffing, lockout storms and success-after-failure (compromise) detection
  with severity, ATT&CK IDs and evidence lists.
- `Get-WinSecLogonSession`: LogonId session chaining (4624→4672/4648→4634/4647),
  admin-token flagging, open-session ("still inside") detection.
- `Get-WinSecIpTimeline`: UTC buckets, ASCII histogram, top accounts/hosts,
  success-after-failure indicator.
- `Get-WinSecLogCoverage`: evidence-completeness snapshot (enabled state,
  retention bounds, wrap risk) so "no events found" conclusions are sound.
- `Test-WinSecAuditPolicy`: GUID-based auditpol gap analysis with
  ready-to-paste remediation commands.
- `Resolve-WinSecIpAttribution`: offline-first PTR/classification plus
  opt-in AbuseIPDB / AlienVault OTX / ip-api enrichment with caching;
  API keys only via environment variables.

### Added — Reporting
- `Export-WinSecInvestigation`: evidence bundle (CSV/JSON/CLIXML/HTML/Markdown)
  with SHA-256 `manifest.json` chain of custody, case metadata and notes.
- Self-contained HTML report (inline CSS/SVG, zero external deps): verdict
  banner, summary cards, activity histogram, findings, sessions, coverage,
  attribution and full event tables.
- Normalized `WinSecEvent` objects with decoded NTSTATUS/Kerberos/`%%`
  status codes, logon types, WFP direction/protocol constants, catalog
  classification and both source-local and UTC timestamps.

### Added — Engineering
- 132 Pester 5 unit tests (pure-logic tests run cross-platform; Windows-only
  paths guarded), PSScriptAnalyzer gate, GitHub Actions CI (ubuntu + windows
  matrix, live-log smoke job) and tag-triggered PSGallery publish workflow.
- Persistent configuration (`Set/Get-WinSecHunterOption`) with type-coerced,
  validated JSON storage; `WINSECHUNTER_CONFIG_DIR` override for portable
  IR kits.
- Build tooling: `Build-Module.ps1` (validated release artifact + zip),
  `Install-Dev.ps1`.

### Fixed (relative to the legacy script)
- FailureReason `%%` code table corrected to the Microsoft-documented
  mapping (legacy script mislabeled `%%2305` as "Account does not exist";
  it is "The specified user account has expired", etc.).
- Time filtering now pushes down into the query instead of applying
  `-MaxEvents` before filtering (legacy behavior silently truncated the
  window under load).
- IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) now match IPv4 queries.
- CIDR sweeps no longer scan every IP-bearing event client-side by byte
  comparison of a single field — all IP-bearing fields are evaluated.
- No `Write-Host`/`exit` in library code; full pipeline/stream semantics,
  `ShouldProcess` on mutating operations, structured errors per host.

### Removed (legacy behaviors intentionally dropped)
- MySQL `.sql` export, `-Help`/`-Version`/`-Update` self-service switches
  (use `Get-Help`, module metadata and PSGallery/`Update-Module`),
  column show/hide string API (use pipeline `Select-Object`).

## [5.0.2] and earlier — legacy `Get-SecurityEventsByIP.ps1`
See the upstream repository history (Mikhail Deynekin). This module is a
derivative work relicensed under the same GPL-3.0 terms with attribution.

[2.1.0]: https://github.com/paulmann/Get-Windows-Security-Events-By-IP/releases/tag/v2.1.0
[2.0.0]: https://github.com/paulmann/Get-Windows-Security-Events-By-IP/releases/tag/v2.0.0
