# 🩺 Troubleshooting and FAQ

Symptom → cause → what to do. Most entries are about **proving** the negative, not about
crashes: an empty result is usually a coverage problem, not a quiet attacker.

[← Home](Home)

---

## Collection

### `Get-WinSecEventByIp` returns nothing

Work through this in order:

```powershell
Get-WinSecLogCoverage -LogName Security          # retention, size, accessibility
Test-WinSecAuditPolicy                           # is the subcategory even audited?
Get-WinSecEventByIp 203.0.113.7 -LastDays 30 -Profile All -DeepScan
```

1. **Window too narrow.** `-LastHours 24` on a log that wraps every 6 hours proves nothing.
2. **Audit policy off.** Without "Audit Logon" you will never see 4624/4625.
3. **IP embedded in a message.** Use `-DeepScan` (drops the server-side IP gate).
4. **Wrong profile.** `-Profile All` widens the scope.
5. **Wrong host.** Confirm `-ComputerName` and that the event was logged on that host.

> [!WARNING]
> "No events" is a statement about the collected window. Say so in the report; do not upgrade
> it to "no activity".

### `Access is denied` reading the Security log

Run the session **elevated**. The Security channel requires Administrator; there is no
supported workaround. In a remote sweep this appears as `Skipped` with an access-denied note
in `LogDetails`, while other channels continue.

### A channel is missing (Sysmon, RDP, Firewall)

Expected on servers without those roles. Since 2.1.0 each channel is queried separately:
the channel is `Skipped`, the rest of the sweep completes.

```powershell
$rows = Get-WinSecEventByIp 203.0.113.7 -LastHours 12 -PassHostStatus
$rows[0].LogDetails | Format-Table LogName, Status, EventsFound, Error
```

### Remote hosts fail

| Status | Meaning | Check |
|---|---|---|
| `Failed` | transport or credentials | WinRM enabled, firewall, `Test-WSMan`, credential rights |
| `Skipped` | channel/log unavailable or access denied | elevation on the target, channel installed |
| `NoEvents` | query ran, nothing matched | window, profile, IP |

```powershell
Test-WSMan SRV01
Invoke-Command -ComputerName SRV01 -ScriptBlock { whoami; Get-WinEvent -ListLog Security }
```

For HTTPS transport pass `-SessionOption (New-PSSessionOption -UseSSL)`. CredSSP is needed
only for double-hop scenarios and should be enabled deliberately.

### `-ComputerName` used to abort with "A ForEach-Object -Parallel using variable cannot be a script block"

Fixed in 2.1.0. If you see it, you are running 2.0.x — upgrade.

### Collection crashed with "Cannot convert null to DateTime"

Fixed in 2.1.0: `-LastHours`, `-LastDays` and EVTX mode worked only when an explicit window
was supplied. Upgrade, or pass `-StartTime`/`-EndTime` as a workaround on 2.0.x.

## Analysis

### No brute-force finding although there were many failures

Check the threshold and the window:

```powershell
$findings = $events | Test-WinSecBruteForce -WindowMinutes 60 -FailureThreshold 3
```

Failures spread over hours do not exceed a 10-minute window. Also confirm the events are
failures (`Outcome -eq 'Failure'`) and carry the source IP.

### Sessions look incomplete

`Get-WinSecLogonSession` needs 4624 **and** 4634/4647. If the profile excluded logoff events,
sessions stay open. Use `-Profile IncidentResponse` or `-Profile All`, and remember that a
missing 4634 can genuinely mean the session is still open.

### Timeline has no buckets

`Get-WinSecIpTimeline` needs events with `TimeUtc`. An empty pipeline returns nothing; check
that the previous command actually produced events.

## Reporting

### Where are the reports?

`<OutputDirectory>/<CaseId>-reports/` — deliberately outside the evidence bundle. The bundle
contains its own `report.html`/`report.md`, which are evidence artifacts, not narrative reports.

### The abuse report has no recipient

`NeedsContact = true` means the ASN/PTR did not match a known abuse desk. Pass
`-ContactEmail 'abuse@example.net'`. The tool never guesses an address.

### Account names are visible in the attached CSV/JSON

Use `-RedactAccounts`. Since 2.1.0 redaction covers the body **and** the attachments with
consistent pseudonyms.

### The `.eml` does not open in my mail client

The file is UTF-8 with CRLF line endings and a `multipart/mixed` body. If your client refuses
it, send the `.md` version through a web form or paste the body into a new message and attach
`events.csv` manually.

## Evidence

### `Test-WinSecEvidenceIntegrity` reports `Extra`

A file exists in the bundle folder that the manifest does not list — usually a report written
into the case folder, or a manually copied file. Reports belong in `<CaseId>-reports/`.
Remove the extra file or document it; do not regenerate the manifest to hide it.

### `Modified` on a file nobody touched

Check line-ending conversion (Git, editors) and any antivirus rewriting the file. Compare
`LastWriteUtc` in the report. Re-export from the source if the content really changed.

### `Missing` after copying

Copy the whole folder, not selected files. Case-sensitive file systems and cloud sync tools
that rename files also cause this.

## Configuration

### `config.json` is ignored

Check the path printed by:

```powershell
Get-WinSecHunterOption -ShowResolved
```

`WINSECHUNTER_CONFIG_DIR` overrides the default. A corrupt file is ignored with a warning;
fix or delete it.

### API key is "present" but the provider fails

`-ShowResolved` only checks presence. Verify the key works with a single lookup and check
egress/firewall. OTX and AbuseIPDB require HTTPS; ip-api's free tier is HTTP-only and is
intended for lab use.

## Platform

### Module does not import on Linux

It should: analysis and reporting are cross-platform. Collection cmdlets throw
`PlatformNotSupportedException` by design. If import fails, check PowerShell version (7.6+)
and that the whole module folder was copied.

### `auditpol` output looks empty or garbled

`auditpol /r` output is parsed by **column position**, so localized Windows is supported. An
empty result usually means the process is not elevated.

## FAQ

**Does it modify the event logs?**
No. Collection is read-only; `Trace-WinSecIp` bookmarks by record id.

**Does it phone home?**
Only to the enrichment provider you explicitly enable, plus reverse DNS. No telemetry.

**Can I run it from a USB stick?**
Yes — set `WINSECHUNTER_CONFIG_DIR` inside the stick; reading works from read-only media.

**Does it support Windows PowerShell 5.1?**
No, and it will not: the module requires PowerShell 7.6+ (Core).

**How do I cite a finding?**
Case id + artifact + SHA-256 from `manifest.json` + UTC timestamp. `Test-WinSecEvidenceIntegrity`
gives you the verification line.
