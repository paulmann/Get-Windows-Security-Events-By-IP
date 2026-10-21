# Architecture

WinSecHunter is structured for three properties that matter in incident response:
**correctness under hostile data** (missing channels, weird encodings, huge logs),
**testability** (pure logic separated from Windows I/O), and **evidence integrity**
(hashes, UTC discipline, completeness proofs).

## Layer model

```
┌───────────────────────────────────────────────────────────────────────┐
│ Public API (20 cmdlets, allow-listed in .psm1 + .psd1)                 │
│  Collection: Get-WinSecEventByIp · Trace-WinSecIp · Get-WinSecLogCoverage │
│  Analysis:   Get-WinSecIpTimeline · Get-WinSecLogonSession              │
│              Test-WinSecBruteForce · Test-WinSecAuditPolicy             │
│              Resolve-WinSecIpAttribution                                │
│  Reporting:  New-WinSecCase · Export-WinSecInvestigation                │
│  Utility:    Get-WinSecEventCatalog · Expand-WinSecIpRange · Options    │
├───────────────────────────────────────────────────────────────────────┤
│ Private engine (dot-sourced, never exported)                            │
│  Resource.ps1        catalog loader/index, profile→event-id resolution  │
│  IpUtils.ps1         validation, canonicalization, variants, regex,     │
│                      CIDR membership, classification (BigInteger math)  │
│  Decode.ps1          NTSTATUS / Kerberos / %% / logon-type / WFP tables │
│  New-WinSecEventQuery   XPath QueryList builder (pushdown strategy)     │
│  Invoke-WinSecEventQuery execution: local | parallel WinRM | CimSession │
│                      | EVTX files; per-host status; retry               │
│  ConvertTo-WinSecEvent  record/XML → typed WinSecEvent (pure function)  │
│  ConvertTo-WinSecHtmlReport self-contained HTML renderer (inline CSS/SVG)│
│  Config.ps1          persisted, type-coerced JSON configuration         │
├───────────────────────────────────────────────────────────────────────┤
│ Types & data                                                            │
│  Enums/WinSecEnums.ps1     8 enums (category, outcome, verdict, …)      │
│  Classes/WinSecEvent.ps1   normalized event (typed, dedup key, flatten) │
│  Classes/WinSecModel.ps1   Case, Session, Finding, Coverage,            │
│                            Attribution, TimelineBucket, AuditGap,       │
│                            HostResult                                   │
│  Resources/EventCatalog.json  156 events × {log, category, importance,  │
│                            ATT&CK, IpFields} + 14 profiles + aliases    │
└───────────────────────────────────────────────────────────────────────┘
```

Loader order matters: `Enums → Classes → Private → Public` (class definitions
reference enum types at compile time). Classes are module-scoped; consumers who
need type names in their own session use `using module WinSecHunter`.

## Collection pipeline (Get-WinSecEventByIp)

```
input IPs ──► validate/normalize (strict: rejects '1', '01.2.3.4', zones, brackets)
        └──► per-IP: canonical form, textual variants (compressed/expanded/::ffff:),
                     boundary-aware compiled regex
profile ───► catalog resolution ──► {log → event ids} map (+explicit ids/categories)
time ──────► UTC window (StartTime/EndTime or LastHours/LastDays)
        └──► New-WinSecEventQuery: QueryList XML
              · System[EventID=… and TimeCreated[@SystemTime>=…<=…]]
              · exact single IP: gated clause  Data='ip' / Address='ip' (all variants)
              · ids WITHOUT IpFields (4740, 7045, …) pass through ungated —
                they are contextual evidence even though the IP never appears
              · CIDR / multi-IP / -DeepScan: no IP gate (client-side decides)
execution ─► Invoke-WinSecEventQuery
              · local:  Get-WinEvent -FilterXml (no WinRM dependency)
              · remote: Invoke-Command via ForEach-Object -Parallel (throttled,
                        retrying); remote block returns plain hashtables
                        {Xml, Computer, RecordId, TimeUtc(source-side!), LogName,
                        Message?} — no type dependencies on the target
              · CimSession: sequential Invoke-Command -CimSession
              · files: Get-WinEvent -Path per EVTX (query rebuilt with file path)
              · missing channels → status Skipped (Sysmon absent is not an error)
matching ──► regex over raw XML (fast pre-filter) ─► ConvertTo-WinSecEvent
              · CIDR: structural membership test on SourceIp/DestinationIp/IP-like data
              · MatchedOn refinement: EventData | UserData | Message | Xml
              · dedup by Computer|Log|RecordId|EventId|MatchedIp
output ────► WinSecEvent[] sorted by TimeUtc (+WinSecHostResult[] with -PassHostStatus)
```

### Timestamp discipline
`TimeCreated` on remote records is the *source machine's local time* — useless for
correlation across time zones. Every payload therefore carries `TimeUtc` computed
**on the source side**; all sorting, bucketing, bookmarking and detection windows
use `TimeUtc`. `TimeCreated` is kept for display continuity.

## Parser (ConvertTo-WinSecEvent)

Pure function: accepts `EventLogRecord`, `[xml]`, XML string, or the remote payload
hashtable → `[WinSecEvent]`. This is what makes the parser unit-testable on Linux CI.

- Namespace-safe navigation via `SelectSingleNode("*[local-name()='…']")`
  (event XML uses the 2004 events namespace; hand-made test fixtures may not).
- `EventData/Data[@Name]` → case-insensitive hashtable; unnamed positional data
  (System-log providers like ServiceControlManager 7045) mapped by per-ID index tables.
- `UserData/EventXML` for RDP logs: RCM `Param1/2/3` (user/domain/IP),
  LSM `User/SessionID/Address`; `Correlation/@ActivityID` captured for RDP chaining.
- Outcome resolution: static success/failure ID sets + status-driven IDs
  (4768/4769/4770/4776: `0x0` → Success, else Failure).
- Status decoding priority: SubStatus → FailureCode → ResultCode → ErrorCode →
  FailureReason(%%) → Status, each through the right table (NTSTATUS vs Kerberos
  space, disambiguated by event ID).

## Detection (Test-WinSecBruteForce)

Sliding-window burst analysis over chronologically sorted failures:

- grouping keys: (source, account) → brute force; (source) → spraying;
  (account) → stuffing; lockouts counted globally.
- success-after-failure: successes (4624/1149/21/25/Kerberos/NTLM 0x0) within
  `SuccessWindowMinutes` after the burst escalate the finding to
  `BruteForceWithSuccess` / **Critical** — the compromise indicator.
- findings embed evidence lists (capped) so exports are self-sufficient.

## Evidence & configuration

- `WinSecCase` accumulates notes/findings; `Export-WinSecInvestigation` hashes every
  artifact into `manifest.json` (SHA-256, collector metadata) — chain of custody.
- HTML report: single file, inline CSS/SVG, no JS/CDN — renders in air-gapped
  review environments and survives e-mail gateways.
- Config: JSON with defaults overlay, strict type coercion on read AND write,
  `WINSECHUNTER_CONFIG_DIR` override. Secrets: environment variables only.

## Testing strategy

| Layer | Approach |
|---|---|
| Pure logic (parsers, decoders, IP math, query builder, detection, renderer) | Pester 5 on **any OS** — no Windows required |
| Windows-only I/O (Get-WinEvent, auditpol, WinRM) | platform-guarded; CI `windows-smoke` job exercises live logs read-only |
| Static quality | AST parse check, PSScriptAnalyzer (Error+Warning gate), help/OutputType/ShouldProcess tests |
| Regression fixtures | real-world event XML shapes (MS docs + forensic handbook samples) |

168 tests, run in CI on ubuntu + windows matrix.

## 2.1.0 — per-channel execution and the reporting pipeline

**Per-channel execution.** `New-WinSecEventQuery` emits a `QueryList` with one `Select` per
channel. `Split-WinSecQueryXml` converts it into one single-`Select` query per channel, and
the executor (`Invoke-WinSecEventQuery`) runs them independently. Consequences:

- a missing optional channel (Sysmon, RDP, firewall) is one `Skipped` row, not a failed host;
- `WinSecHostResult.LogDetails` explains every channel;
- `-MaxEvents` applies per channel, not per host;
- `-PassHostStatus` is emitted before diagnostics, so statuses cannot be lost behind an error.

Errors are classified by `HResult`/Win32 code (5 = access denied, 15007 = channel not found)
with a message fallback, so localized Windows is supported.

**Reporting pipeline.** One context derivation feeds three renderers:

```text
Events · Findings · Sessions · Coverage · Attribution · Timeline
        │
        ▼
Get-WinSecCaseContext      verdict · severity · confidence · IOCs · limitations · recommendations
        │
        ├── Get-WinSecReportSection → Markdown renderer
        │                            → HTML renderer (self-contained)
        ├── New-WinSecAbuseReport  → RFC 5322 .eml + CSV/JSON attachments
        └── Export-WinSecIocList   → CSV · TXT · JSON · STIX 2.1
```

All renderers consume the same facts, so a number or a verdict cannot differ between the
Markdown report, the HTML report and the abuse message. Reports are written to
`<CaseId>-reports`, outside the evidence bundle, so `manifest.json` remains verifiable.

