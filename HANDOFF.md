# HANDOFF — WinSecHunter (context recovery)

**Read this first if you are continuing work on the module.**
Last updated: 2026-10-21. Current release: **2.1.0**. Status: green.

## 1. Mission

Turn `Get-SecurityEventsByIP.ps1` (legacy 1,092-line script by Mikhail Deynekin,
GPL-3.0 at the time, v5.0.2; relicensed by the owner to PolyForm Noncommercial 1.0.0 in 2.1.0) into a production PowerShell 7.6+ module that answers one question
completely: *what did a given attacker IP do to this estate?* — and produces the
evidence and reports an incident responder must hand over.

No backward compatibility with the legacy script is attempted.

## 2. Environment

- Windows 10/11/Server 2016+ for collection (`Get-WinEvent`, WinRM).
- Any OS for analysis and reporting (pure functions, Pester suite runs on Linux CI).
- PowerShell **7.6+**, Core only. Pester 5.4+ and PSScriptAnalyzer 1.25+ for the gates.
- No external binaries; no cloud dependency; threat-intel keys only via environment.

## 3. Architecture (short)

```
src/WinSecHunter/
  Enums/       WinSecEventCategory, LogonType, Outcome, Verdict, Severity, ExportFormat
  Classes/     WinSecEvent, WinSecCase, WinSecSession, WinSecBruteForceFinding,
               WinSecLogCoverage, WinSecIpAttribution, WinSecTimelineBucket,
               WinSecAuditGap, WinSecHostResult (with LogDetails)
  Private/     Config, Resource (catalog), IpUtils, Decode,
               New-WinSecEventQuery (XPath builder),
               Invoke-WinSecEventQuery (per-channel executor: local/remote/EVTX),
               ConvertTo-WinSecEvent (parser), ConvertTo-WinSecHtmlReport,
               Reporting (context, IOCs, Markdown/HTML renderers, EML), Help
  Public/      20 cmdlets, one file each
  Resources/   EventCatalog.json (156 events, 6 channels, 14 profiles)
```

Key behaviours:

1. **Per-channel execution.** `New-WinSecEventQuery` emits a `QueryList`; the executor
   splits it (`Split-WinSecQueryXml`) and queries each `Select` separately. A missing
   optional channel becomes one `Skipped` row, never a failed sweep.
2. **Time bounds use `[datetime]::MinValue` as "not set".** `$null` cannot bind to
   `[datetime]` and `[AllowNull()]` does not help; `Nullable<T>` is unboxed during
   binding, so `HasValue` is unreliable.
3. **Parallel remote execution** passes the remote scriptblock as *text*
   (`$using:remoteSbText` + `[scriptblock]::Create`) because `$using:`scriptblock is
   rejected by `ForEach-Object -Parallel`.
4. **Error classification** uses `HResult`/Win32 code first (5, 15007, 2/3), message
   second. No dependency on English OS strings.
5. **Evidence is immutable.** `Export-WinSecInvestigation` writes a bundle with
   `manifest.json`; report cmdlets write to `<CaseId>-reports`, never into the bundle.
6. **Reporting pipeline:** `Get-WinSecCaseContext` derives verdict/severity/confidence/
   IOCs once; `Get-WinSecReportSection` builds a renderer-agnostic section model;
   Markdown and HTML renderers consume the same model, so both formats carry identical
   facts.

## 4. Validation (must be green before any release)

```powershell
./build/validate.ps1 -Tests
./build/Build-Module.ps1 -Zip
./build/Export-CatalogDoc.ps1 -Check
```

Expected: AST 0 errors, manifest 2.1.0 with 20 exports, import 20 exports, help ≥2
examples per cmdlet, catalog 156/14, PSScriptAnalyzer 0 Error/0 Warning, Pester 168
passed / 0 failed / 1 skipped (Windows-only guard).

## 5. Known limitations (backlog)

1. Live Windows integration tests (`Get-WinEvent`, WinRM, `auditpol`) only run in the
   `windows-smoke` CI job; they cannot run in a Linux sandbox.
2. GeoIP offline MaxMind reader is not implemented; PTR + REST providers only.
3. IPv6 CIDR expansion is guarded at /64 for memory safety.
4. `Trace-WinSecIp` is polling-based by design (no ETW consumer dependency).
5. CEF/LEEF export for SIEMs is not implemented.
6. PlatyPS MAML help is not generated; comment-based help is complete.
7. Abuse-desk table covers major clouds; other networks require `-ContactEmail`.

## 6. Decisions not to revisit without reason

- Module name `WinSecHunter`, PolyForm Noncommercial 1.0.0, attribution preserved.
- 20 exported cmdlets; allow-list mirrored in `.psm1` and `.psd1`.
- Reports outside the evidence bundle (integrity).
- Account pseudonymisation must cover attachments, not only the body.
- No telemetry, no automatic uploads, no secrets in parameters.

## 7. Next steps

- Real-Windows integration coverage for the new report cmdlets.
- STIX/TAXII push (outbound) behind an explicit switch.
- Optional PDF rendering of the executive report.
- CEF/LEEF exporter.

