# 🧾 Evidence and Reporting

How WinSecHunter preserves what it found, how you prove it was not altered, and how the
bundle differs from the narrative reports.

[← Home](Home) · [Reporting and Abuse](Reporting-and-Abuse)

---

## Two kinds of output

| Output | Written by | Goes where | Purpose |
|---|---|---|---|
| **Evidence bundle** | `Export-WinSecInvestigation` | `<OutputDirectory>/<CaseId>/` | immutable facts + hashes |
| **Reports** | `New-WinSecIncidentReport`, `New-WinSecAbuseReport`, `Export-WinSecIocList` | `<OutputDirectory>/<CaseId>-reports/` | documents for humans and third parties |

Reports are deliberately **outside** the bundle. Adding a file after export would make the
manifest report an `Extra` file, and a verifier would be right to flag it.

## Bundle anatomy

```text
WSC-20261021-AB12CD34/
├── events.csv            flattened events (spreadsheet / SIEM)
├── events.json           flattened events (API / jq)
├── events.clixml         typed WinSecEvent objects for Import-Clixml
├── findings.json         brute-force / spraying / stuffing findings
├── sessions.csv          reconstructed logon sessions
├── coverage.csv          log completeness snapshot
├── attribution.json      PTR / geo / ASN / provider verdicts
├── timeline.csv          activity buckets
├── iocs.csv              indicators with count and first/last sighting
├── iocs.json             same, structured
├── report.html           self-contained event-centric report
├── report.md             Markdown summary
├── case.json             case metadata and notes
└── manifest.json         SHA-256 + bytes + UTC write time for every artifact above
```

Artifacts are written only when the corresponding input exists (for example, no
`findings.json` when no findings were supplied).

## Manifest

```json
{
  "caseId": "WSC-20261021-AB12CD34",
  "generatedUtc": "2026-10-21T12:34:56.0000000Z",
  "collector": {
    "host": "IR-WS01",
    "user": "analyst",
    "tool": "WinSecHunter",
    "toolVersion": "2.1.0",
    "catalogVersion": "2.1.0",
    "psVersion": "7.6.6",
    "os": "Microsoft Windows 11 ..."
  },
  "hashAlgorithm": "SHA256",
  "artifacts": {
    "WSC-20261021-AB12CD34/events.csv": {
      "Sha256": "…",
      "Bytes": 123456,
      "WrittenUtc": "2026-10-21T12:34:55.0000000Z",
      "Source": "Get-WinSecEventByIp events (flattened)"
    }
  }
}
```

The manifest is written last and does not hash itself. Every other file is listed.

## Verify integrity

```powershell
$s = Test-WinSecEvidenceIntegrity -Path D:\IR\WSC-20261021-AB12CD34 -Summary
$s | Format-List BundlePath, CaseId, Artifacts, Verified, Modified, Missing, Extra, Unreadable, IsIntact
```

| Status | Meaning | Action |
|---|---|---|
| `OK` | hash and size match | none |
| `Modified` | file exists, content or size changed | treat evidence as unreliable; re-export from source |
| `Missing` | listed in the manifest, not present | restore from a copy; do not "fix" the manifest |
| `Extra` | present in the folder, not in the manifest | added after export — remove or document it |
| `Unreadable` | exists but cannot be hashed | permissions or a lock; resolve and re-run |

`Extra` is the check a hash list alone cannot perform: an added file breaks no recorded hash.

```powershell
# machine-readable for a pipeline
Test-WinSecEvidenceIntegrity .\bundle -Json | Set-Content .\integrity.json -Encoding utf8NoBOM

# only problems
Test-WinSecEvidenceIntegrity .\bundle -ProblemsOnly | Format-Table RelativePath, Status
```

## Reopen a case

```powershell
$b = Import-WinSecCase -Path D:\IR\WSC-20261021-AB12CD34
$b.Case.CaseId
$b.Events.Count
$b.Events[0].GetType().Name        # WinSecEvent — typed, not a flat row
$b.Events | Get-WinSecIpTimeline -AsciiChart
```

`events.json` is preferred; if it is absent, `events.clixml` is used. `-SkipEvents` loads the
case and the other artifacts without rehydrating events — useful for very large bundles.

The restored case keeps its evidence table, so a follow-up report references the same
chain of custody.

## What to hand over

| Recipient | Hand over | Do not hand over |
|---|---|---|
| Internal case file | whole bundle + `<CaseId>-reports` | raw credentials |
| Management | executive incident report (`.html` or `.md`) | raw event dump |
| Auditor / court | bundle + verification output + custody notes | modified copies |
| ISP abuse desk | `.eml` (attachments included) | unrelated internal data |
| TIP / SIEM | `iocs.stix.json` or `iocs.csv` | account names, unless policy allows |

## Custody checklist

1. Export once; keep the bundle read-only afterwards.
2. Record `Test-WinSecEvidenceIntegrity -Summary` output and store it with the bundle.
3. Keep the original EVTX or disk image alongside the bundle when available.
4. Share copies, never the only copy.
5. If a file must be added, create a new bundle version instead of editing the old one.
6. Include the case id and UTC timestamps in every hand-off message.

## Report vs bundle report

The bundle contains `report.html` — an event-centric document generated during export
(summary cards, histogram, tables). `New-WinSecIncidentReport` produces a **narrative**
report with verdict, confidence, recommendations and custody statement. They complement each
other: the bundle report is raw evidence, the incident report is the story told about it.
