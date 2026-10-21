# 📝 Reporting and Abuse

How WinSecHunter turns telemetry into documents a human can act on: an incident report for
your organisation, an abuse report for the network that hosts the attacker, and machine-readable
indicators for a TIP or blocklist.

[← Home](Home) · [Evidence and Reporting](Evidence-and-Reporting)

---

## Why a separate reporting layer

A CSV of 4,000 events is not a report. Management needs a verdict and a risk statement; the
ISP needs a concise, verifiable complaint; a TIP needs STIX. All three must carry the same
facts, or the investigation contradicts itself.

WinSecHunter derives the facts once (`Get-WinSecCaseContext`) and renders them into three
shapes. Verdict, severity, counts, indicators and time window are identical across Markdown,
HTML, `.eml` and JSON.

## Incident report

```powershell
New-WinSecIncidentReport -Case $case -Event $events -Finding $findings `
    -Session $sessions -Coverage $coverage -Attribution $attribution -Timeline $timeline `
    -Template Full -Format Both -OutputDirectory D:\IR -PassThru
```

Output goes to `D:\IR\<CaseId>-reports\` — **outside** the evidence bundle, so the manifest
stays verifiable.

| File | Purpose |
|---|---|
| `<CaseId>-incident-report.md` | review in a ticket, pull request or wiki |
| `<CaseId>-incident-report.html` | self-contained document: inline CSS, no scripts, no external requests |

The descriptor returned with `-PassThru` includes the SHA-256 of each file, so the report
itself can be registered as evidence.

### Templates

| Template | Audience | Contents |
|---|---|---|
| `Executive` | management, customer | verdict, severity, confidence, key facts, top indicators, immediate actions, custody |
| `Technical` | case file | full scope, timeline, findings, IOCs, sessions, coverage, attribution, recommendations |
| `Full` | deep dive | Technical + events by ID + ATT&CK coverage appendix |

### Sections and where the numbers come from

| Section | Source |
|---|---|
| Executive summary | `Get-WinSecCaseContext`: verdict, severity, confidence, counts, window |
| Scope and method | case scope hosts, subject IPs, channels from coverage, tool version |
| Timeline | `Get-WinSecIpTimeline` buckets (falls back to events-by-ID) |
| Findings | `Test-WinSecBruteForce` |
| Indicators | `Get-WinSecIocSet` over events, findings and subject IPs |
| Sessions | `Get-WinSecLogonSession` |
| Evidence quality | `Get-WinSecLogCoverage` (risk, access, retention) |
| Attribution | `Resolve-WinSecIpAttribution` |
| Recommendations | derived from verdict and coverage gaps |
| Chain of custody | case evidence table and manifest statement |

### Verdict logic

| Condition | Verdict |
|---|---|
| success from a source with ≥5 failures | **Credential compromise — success observed after failures** |
| finding `BruteForceWithSuccess` | Credential compromise |
| finding `BruteForce` | Brute-force attack |
| finding `PasswordSpraying` | Password spraying |
| finding `CredentialStuffing` | Credential stuffing |
| finding `LockoutStorm` | Account lockout storm |
| events but no threshold exceeded | Suspicious authentication activity |
| no events | No matching activity in the collected window |

Severity is the highest finding severity (or highest event importance when there are no
findings). Confidence drops to **Low** when no events matched or a channel is inaccessible,
and to **Medium** when coverage data is missing.

> [!IMPORTANT]
> "No matching activity" is a statement about the collected window, not about the world.
> The report lists the limitations explicitly, including retention gaps and missing channels.

## Abuse report

```powershell
New-WinSecAbuseReport -Case $case -Event $events -Finding $findings -Attribution $attribution `
    -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' `
    -Provider Auto -Format All -RedactAccounts -OutputDirectory D:\IR
```

| File | Purpose |
|---|---|
| `<CaseId>-abuse-<ip>.eml` | complete RFC 5322 message with attachments; open and send |
| `<CaseId>-abuse-<ip>.md` | same content for a web form or ticket |
| `<CaseId>-abuse-<ip>.json` | structured payload for APIs and ticketing |

### Recipient resolution

`-Provider Auto` inspects ASN organisation and PTR:

| Provider | Abuse desk |
|---|---|
| AWS | `abuse@amazonaws.com` |
| Azure / Microsoft | `abuse@microsoft.com` |
| Google Cloud | `network-abuse@google.com` |
| DigitalOcean | `abuse@digitalocean.com` |
| Hetzner | `abuse@hetzner.com` |
| OVHcloud | `abuse@ovh.net` |
| Cloudflare | `abuse@cloudflare.com` |
| Contabo | `abuse@contabo.com` |
| Akamai / Linode | `abuse@linode.com` |
| Vultr | `abuse@vultr.com` |
| Oracle Cloud | `abuse@oracle.com` |
| Alibaba Cloud | `abuse@alibabacloud.com` |
| Tencent Cloud | `abuse@tencent.com` |

Unknown networks produce `NeedsContact = true` and an empty mailbox. The tool **never invents
an address**: re-run with `-ContactEmail`.

### Message anatomy

- headers: `From`, `Reply-To`, `To`, `Subject`, `Date`, `Message-ID`, `MIME-Version`;
- plain-text body (abuse desks often parse mail with scripts): source IP/ASN/PTR, UTC window,
  record and failure counts, targeted hosts and accounts, event IDs, verdict, sample events,
  requested action, reporter contact and case reference;
- attachments: `events.csv` (flattened events) and `evidence.json` (summary, indicators, up to
  200 events), base64 with 76-character lines.

### Privacy

`-RedactAccounts` replaces account names with stable `acct-XXXXXX` pseudonyms and applies
them to the body **and to the attached CSV/JSON**. Pseudonyms stay consistent within one
report, so the timeline remains readable. Review the body before sending: host names and
internal addresses are still present by design — they are the evidence.

> [!NOTE]
> Abuse reports are outbound communication. Confirm your organisation's policy on sharing
> host names and security telemetry with third parties.

## IOC export

```powershell
Export-WinSecIocList -Case $case -Event $events -Finding $findings -Format Stix21
```

| Format | Shape |
|---|---|
| `Csv` | `Type,Value,Count,FirstUtc,LastUtc` — spreadsheet/SIEM import |
| `Txt` | `type<TAB>value<TAB>count`, one per line — grep-friendly |
| `Json` | metadata, counts and the indicator array |
| `Stix21` | STIX 2.1 bundle with `indicator` objects for IPs and accounts |

STIX indicators use the observed values only, labelled `anomalous-activity`; no judgement
beyond what the investigation found is implied. Quote and escape rules follow STIX patterning.

## End-to-end playbook

```powershell
# 1. Collect and prove the logs
$events = Get-WinSecEventByIp 203.0.113.7 -LastDays 3 -PassHostStatus
$coverage = Get-WinSecLogCoverage -LogName Security, System
$gaps = Test-WinSecAuditPolicy

# 2. Analyze
$findings = $events | Test-WinSecBruteForce -WindowMinutes 30
$sessions = $events | Get-WinSecLogonSession
$timeline = $events | Get-WinSecIpTimeline -BucketSize ([timespan]::FromHours(1))

# 3. Attribute
$attribution = Resolve-WinSecIpAttribution 203.0.113.7 -Provider None

# 4. Case and evidence
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'VPN brute force'
$case = Export-WinSecInvestigation -Case $case -Event $events -Finding $findings `
            -Session $sessions -Coverage $coverage -Attribution $attribution `
            -Timeline $timeline -Format All -PassThru

# 5. Reports
New-WinSecIncidentReport -Case $case -Event $events -Finding $findings -Session $sessions `
    -Coverage $coverage -Attribution $attribution -Timeline $timeline -Template Full -Format Both
New-WinSecAbuseReport -Case $case -Event $events -Finding $findings -Attribution $attribution `
    -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' -RedactAccounts
Export-WinSecIocList -Case $case -Event $events -Finding $findings -Format Stix21

# 6. Verify
Test-WinSecEvidenceIntegrity -Path $case.CaseId -Summary
```

## Limitations

- Reports describe Windows event evidence only; they do not see network flows, EDR telemetry
  or application logs.
- Confidence is a heuristic over coverage and volume, not a statistical measure.
- The abuse-desk table covers major clouds; niche hosting providers need `-ContactEmail`.
- HTML reports are self-contained by design: no charts library, no JavaScript, no fonts
  fetched from the internet.
- `Export-WinSecIocList` includes accounts and hosts in CSV/JSON/TXT; only IPs and accounts
  become STIX indicators, because other object types would need context STIX does not carry here.

