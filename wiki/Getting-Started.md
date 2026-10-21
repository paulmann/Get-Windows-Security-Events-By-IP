# 🚀 Getting Started

From zero to a verified evidence bundle and an incident report.

[← Home](Home)

---

## Prerequisites

| Requirement | Why |
|---|---|
| PowerShell **7.6+** (`pwsh`) | the module targets Core only; Windows PowerShell 5.1 is not supported |
| Windows 10/11/Server 2016+ | collection via `Get-WinEvent` / WinRM |
| Elevated session | reading the Security log and `auditpol` |
| Pester 5.4+ | only to run the test suite |
| PSScriptAnalyzer 1.25+ | only to run the static-analysis gate |

```powershell
$PSVersionTable.PSVersion      # must be 7.6 or later
$PSVersionTable.PSEdition      # must be Core
```

## Install

### From source (recommended until the gallery release matches the repository)

```powershell
git clone https://github.com/paulmann/Get-Windows-Security-Events-By-IP.git
cd Get-Windows-Security-Events-By-IP
./build/Install-Dev.ps1 -Force
```

`Install-Dev.ps1` copies `src/WinSecHunter` into your per-user module path and prints it.

### From a release zip

```powershell
$version = '2.1.0'
$zip = Join-Path $env:TEMP "WinSecHunter-$version-module.zip"
Invoke-WebRequest "https://github.com/paulmann/Get-Windows-Security-Events-By-IP/releases/download/v$version/WinSecHunter-$version-module.zip" -OutFile $zip -UseBasicParsing
Expand-Archive -LiteralPath $zip -DestinationPath "$env:USERPROFILE\Documents\PowerShell\Modules" -Force
```

### For automation and agents (portable, no profile changes)

```powershell
$dir = Join-Path $env:TEMP 'WinSecHunter-2.1.0'
Import-Module (Join-Path $dir 'WinSecHunter/2.1.0/WinSecHunter.psd1') -Force
(Get-Module WinSecHunter).ExportedFunctions.Count   # 20
```

Always pass a time window and `-PassHostStatus`, never use `Read-Host`/`Get-Credential`, and
keep API keys in environment variables. The full protocol is in
[AGENTS.md](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/blob/main/AGENTS.md).

### Verify

```powershell
Import-Module WinSecHunter -Force
(Get-Module WinSecHunter).Version                        # 2.1.0
(Get-Module WinSecHunter).ExportedFunctions.Count        # 20
Show-WinSecHunterHelp                                     # workflow map
```

## First sweep

```powershell
$events = Get-WinSecEventByIp -IpAddress 203.0.113.7 -LastDays 2 -PassHostStatus
```

What happens:

1. the catalog expands the default `IncidentResponse` profile into 6 channels;
2. each channel is queried **separately** with server-side XPath (time window, event IDs,
   exact IP variants such as `::ffff:203.0.113.7`);
3. every returned record is re-verified client-side against the IP;
4. `-PassHostStatus` emits one `WinSecHostResult` per target with `LogDetails` per channel.

If a channel is not installed (Sysmon on a stock server, RDP logs on a DC), it appears as
`Skipped` and the rest of the sweep continues. That is expected, not an error.

> [!IMPORTANT]
> "No events" is a conclusion, not an observation. Before writing it down, check retention
> (`Get-WinSecLogCoverage`) and audit policy (`Test-WinSecAuditPolicy`).

## Understand what you collected

```powershell
$events | Measure-Object                                   # count
$events | Group-Object EventId | Sort-Object Count -Descending | Select-Object -First 10
$events | Get-WinSecIpTimeline -AsciiChart -BucketSize ([timespan]::FromHours(1))
```

## Detect

```powershell
$findings = $events | Test-WinSecBruteForce -WindowMinutes 30
$findings | Format-Table Pattern, Severity, TargetAccount, SourceIp, FailureCount, SuccessCount

$sessions = $events | Get-WinSecLogonSession -ActiveOnly     # potential live footholds
$sessions | Format-Table Account, Computer, LogonType, SourceIp, StartUtc, IsAdmin
```

Verdicts: `BruteForce`, `PasswordSpraying`, `CredentialStuffing`, `LockoutStorm`,
`BruteForceWithSuccess`. When a success follows sustained failures from the same source,
the reporting layer escalates the case verdict to **Credential compromise**.

## Build a case and preserve evidence

```powershell
$case = New-WinSecCase -SubjectIps 203.0.113.7 -Title 'RDP brute force vs VPN tier' `
            -ScopeHosts VPN01, VPN02
$case.AddNote('Customer reported lockouts 02:00–03:00 UTC.')

$case = Export-WinSecInvestigation -Case $case -Event $events -Finding $findings `
            -Session $sessions -Format All -OutputDirectory D:\IR -PassThru
```

The bundle contains events, findings, sessions, coverage, attribution, timeline, IOCs, HTML
and Markdown reports, case metadata and `manifest.json` with SHA-256 for every artifact.

## Report

```powershell
New-WinSecIncidentReport -Case $case -Event $events -Finding $findings -Session $sessions `
    -Template Full -Format Both -OutputDirectory D:\IR -PassThru

New-WinSecAbuseReport -Case $case -Event $events -Finding $findings `
    -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' -Format All -OutputDirectory D:\IR
```

Both write to `D:\IR\<CaseId>-reports\`, never into the bundle.

## Verify before sharing

```powershell
$s = Test-WinSecEvidenceIntegrity -Path D:\IR\WSC-20261021-XXXXXXXX -Summary
$s | Format-List IsIntact, Verified, Modified, Missing, Extra

$b = Import-WinSecCase -Path D:\IR\WSC-20261021-XXXXXXXX
$b.Events | Get-WinSecIpTimeline -AsciiChart
```

## Remote collection

```powershell
$hosts = Get-Content .\hosts.txt
$status = Get-WinSecEventByIp 203.0.113.7 -ComputerName $hosts `
            -Credential (Get-Credential) -ThrottleLimit 16 -LastHours 12 -PassHostStatus

$status | Format-Table Computer, Status, EventsFound, ErrorMessage
$status | ForEach-Object { $_.LogDetails } | Format-Table LogName, Status, EventsFound
```

Prerequisites on targets: WinRM enabled, firewall open, credentials with event-log read
access. See [Remote Collection](Remote-Collection).

## Offline EVTX

```powershell
$events = Get-WinSecEventByIp 198.51.100.9 -Path D:\Evidence\*.evtx -Profile All
```

## Next steps

- [Cmdlet Reference](Cmdlet-Reference) — every parameter and example.
- [Reporting and Abuse](Reporting-and-Abuse) — what goes into the reports.
- [Evidence and Reporting](Evidence-and-Reporting) — chain of custody in detail.
- [Configuration](Configuration) — defaults, output directory, API keys.


