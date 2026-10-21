# Task board — WinSecHunter

Status: `[ ]` todo · `[~]` in progress · `[x]` done · `[!]` blocked.
This board tracks engineering work, not user stories.

## Released

### 2.0.0 — module refactor (2026-10-11)
- [x] Typed model: events, case, sessions, findings, coverage, attribution, timeline, audit gaps.
- [x] Query engine: server-side XPath pushdown, client-side verification, CIDR, EVTX, WinRM.
- [x] 14 analysis/collection cmdlets, HTML report, evidence bundle with SHA-256 manifest.
- [x] Pester suite, PSScriptAnalyzer gate, CI matrix, tag-triggered publish workflow.

### 2.1.0 — production hardening and reporting (2026-10-21)
- [x] Fix: collection crashed without a time window (`[AllowNull()][datetime]` vs `$null`).
- [x] Fix: every `-ComputerName` sweep aborted (`$using:`scriptblock in `ForEach-Object -Parallel`).
- [x] Fix: `-PassHostStatus` output lost and one missing channel aborted the sweep
      (per-channel execution + statuses before diagnostics).
- [x] Fix: OTX endpoint, IPv6 cache file name, non-atomic config write, null coverage timestamps.
- [x] Fix: localized `auditpol /r` headers, English-only error classification.
- [x] Fix: `-RedactAccounts` leaked account names in attached CSV/JSON.
- [x] New: `Show-WinSecHunterHelp` (workflow map, per-cmdlet reference, Markdown/OutFile).
- [x] New: `New-WinSecIncidentReport` (Executive/Technical/Full, Markdown + self-contained HTML).
- [x] New: `New-WinSecAbuseReport` (RFC 5322 `.eml`, provider resolution, attachments, redaction).
- [x] New: `Export-WinSecIocList` (CSV/TXT/JSON/STIX 2.1).
- [x] New: `Test-WinSecEvidenceIntegrity` (OK/Modified/Missing/Extra/Unreadable).
- [x] New: `Import-WinSecCase` (rehydrates typed events and the case).
- [x] New: `iocs.csv`/`iocs.json` inside evidence bundles; reports moved to `<CaseId>-reports`.
- [x] New: `WinSecHostResult.LogDetails` per-channel status.
- [x] Restore `build/` toolchain: Build-Module, Install-Dev, validate, Export-CatalogDoc.
- [x] Regression and reporting Pester suites; 168 passing, 1 skipped.
- [x] `SECURITY.md`, `CONTRIBUTING.md`, `.gitattributes`, honest test/event numbers in docs.
- [x] README and wiki rewritten for 2.1.0.

## Backlog

- [ ] `windows-latest` integration tests for report cmdlets and `-PassHostStatus` under WinRM.
- [ ] Offline MaxMind GeoIP reader (no external service).
- [ ] STIX/TAXII outbound push behind an explicit switch.
- [ ] CEF/LEEF export for SIEM ingestion.
- [ ] Optional PDF rendering of the executive report (dependency-free or opt-in).
- [ ] PlatyPS MAML help generation for `Get-Help -Online`.
- [ ] Expand the abuse-desk table and allow a custom resolver file.

## Definition of done

1. `./build/validate.ps1 -Tests` green (AST, manifest, exports, help, PSSA, Pester).
2. `./build/Build-Module.ps1 -Zip` produces an artifact that imports in a child process.
3. `./build/Export-CatalogDoc.ps1 -Check` reports no stale documentation.
4. New behaviour has a test that fails on the previous code.
5. `CHANGELOG.md` updated in the same change.
