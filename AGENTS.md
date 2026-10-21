# AGENTS.md — machine instructions for WinSecHunter

This file is written for AI agents. The human-facing introduction is [README.md](README.md);
this page is the shortest reliable path from zero to a verified result, plus the required
bug-report protocol.

## What this repository is

WinSecHunter is a PowerShell 7.6+ incident-response module (20 cmdlets) that collects Windows
security events for an IP address, analyses them, produces incident/abuse reports and preserves
tamper-evident evidence. Collection requires Windows; analysis and reporting run on any OS.

## 1. Download

Release asset (preferred):

```powershell
$version = '2.1.0'
$zip = Join-Path $env:TEMP "WinSecHunter-$version-module.zip"
$dir = Join-Path $env:TEMP "WinSecHunter-$version"
Invoke-WebRequest "https://github.com/paulmann/Get-Windows-Security-Events-By-IP/releases/download/v$version/WinSecHunter-$version-module.zip" -OutFile $zip -UseBasicParsing
Expand-Archive -LiteralPath $zip -DestinationPath $dir -Force
```

Repository (when tests, build scripts or docs are needed):

```powershell
git clone --depth 1 https://github.com/paulmann/Get-Windows-Security-Events-By-IP.git
```

npm launcher (bundles the module; still needs `pwsh` 7.6+):

```bash
npm install -g winsechunter
winsechunter --version
```

The full module path remains the preferred route for agents that need reports, evidence or
catalog filters; the launcher covers `help`, `catalog` and `sweep`.

## 2. Install

```powershell
# Portable: nothing is written outside the working directory
Import-Module (Join-Path $dir "WinSecHunter/$version/WinSecHunter.psd1") -Force

# Per-user (persists)
./build/Install-Dev.ps1 -Force
```

## 3. Verify

```powershell
$m = Get-Module WinSecHunter
$m.Version.ToString()            # 2.1.0
$m.ExportedFunctions.Count       # 20
@(Get-WinSecEventCatalog).Count  # 156
```

Stop and report if any value differs.

## 4. Use

Hard rules:

1. Always pass a time window: `-LastHours`, `-LastDays`, or `-StartTime`/`-EndTime`.
2. Always pass `-PassHostStatus` for remote sweeps; inspect `LogDetails`.
3. Never call `Read-Host`, `Get-Credential` or `Pause`; pass `-Credential` explicitly.
4. Never place API keys on a command line; keys come from environment variables.
5. Keep evidence bundles read-only after export.

```powershell
$events   = Get-WinSecEventByIp -IpAddress $ip -LastHours 24 -PassHostStatus -WarningAction SilentlyContinue
$findings = $events | Test-WinSecBruteForce
$case     = New-WinSecCase -SubjectIps $ip -Title "Agent sweep $ip"
$case     = Export-WinSecInvestigation -Case $case -Event $events -Finding $findings -Format All -PassThru
$report   = New-WinSecIncidentReport -Case $case -Event $events -Finding $findings -Template Technical -Format Both -PassThru
$check    = Test-WinSecEvidenceIntegrity -Path $case.CaseId -Summary
```

Success criteria: no terminating error, `$check.IsIntact -eq $true`, report file exists.

`Events = 0` is a valid result **only** when every `LogDetails` row is `Completed` or `NoEvents`.
`Skipped`/`Failed` rows are coverage limitations and must be reported as such.

## 5. Report bugs — required

Open an issue: **https://github.com/paulmann/Get-Windows-Security-Events-By-IP/issues/new/choose**

Include:

- module version, PowerShell version, OS;
- exact command with sensitive values redacted;
- expected vs actual behaviour, full error (`Get-Error | Out-String`);
- for collection issues: `-PassHostStatus` output including `LogDetails`, and elevation state;
- portable or installed import.

Do not include API keys, personal data, event dumps or evidence bundles. Security issues go
through [SECURITY.md](SECURITY.md), never a public issue.

## 6. Repository conventions (when changing code)

- PowerShell 7.6+ only; `#Requires -Version 7.6` and `#Requires -PSEdition Core`.
- Gates: `./build/validate.ps1 -Tests`, `./build/Build-Module.ps1 -Zip`,
  `./build/Export-CatalogDoc.ps1 -Check`.
- No `Write-Host`/`exit` in `src/`; approved verbs; StrictMode-safe property access.
- Reports go to `<CaseId>-reports`, never into the evidence bundle.
- Read [CONTRIBUTING.md](CONTRIBUTING.md) before a pull request.


---

## Addendum: prerequisites, configuration, host changes and rollback

Verified against `main` at module version 2.1.0 (release `v2.1.0`, published 2026-10-21) on 2026-10-22.
Sections 1-5 above cover download, install, verification, non-interactive use and bug reporting; this
addendum adds what an agent needs before touching a host: prerequisites, persisted configuration, what
is written, how to undo it, and the safe first-run order.

### A1. Prerequisites

| Requirement | Why | Check |
|---|---|---|
| PowerShell 7.6+, Core edition | `WinSecHunter.psd1` sets `PowerShellVersion = '7.6'` and `CompatiblePSEditions = @('Core')`; all 34 module source files declare `#Requires -Version 7.6` | `$PSVersionTable.PSVersion` |
| Windows for collection | `Get-WinSecEventByIp` throws `PlatformNotSupportedException` (error id `WinSecNotWindows`) off Windows; `Test-WinSecAuditPolicy` throws `PlatformNotSupportedException` off Windows (no `auditpol`) | `$IsWindows` |
| Elevated session for the Security log | The Security channel normally requires Administrator; `Get-WinSecLogCoverage` marks an inaccessible channel with an `Access denied` warning | `([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)` |
| WinRM on remote targets | `-ComputerName` runs `Invoke-Command` over WinRM and normally needs administrator credentials there | `Test-WSMan DC01` |
| `Get-WinEvent -Path` for EVTX mode | Offline analysis reads records through `Get-WinEvent -Path` | `Get-Command Get-WinEvent` |
| Git only for source install | The release zip needs no Git | `git --version` |

If a check fails, stop and report it; do not install or collect around it.

### A2. Configuration

`Set-WinSecHunterOption` persists options; nothing is written until it is called.

- Windows: `%LOCALAPPDATA%\WinSecHunter\config.json`, resolved with
  `[Environment]::GetFolderPath('LocalApplicationData')`.
- Linux/macOS: `$XDG_CONFIG_HOME/WinSecHunter/config.json` or `~/.config/WinSecHunter/config.json`.
- Override the directory with `$env:WINSECHUNTER_CONFIG_DIR` (portable IR kit). A `cache/`
  subdirectory is created on demand; `config.json` is written atomically (temp file + replace).
- Read: `Get-WinSecHunterOption`. Write: `Set-WinSecHunterOption -Name ThreatIntelProvider -Value AbuseIPDB`
  or `-Options @{ DefaultProfile = 'BruteForce' }`. Reset: `Set-WinSecHunterOption -Reset`.
  `-WhatIf` is supported.
- Defaults from `src/WinSecHunter/Private/Config.ps1`: `DefaultProfile = IncidentResponse`,
  `DefaultMaxEvents = 5000`, `DefaultThrottleLimit = 8`, `DefaultOutputDirectory = ''` (current
  directory), `IncludeMessage = $false`, `DeepScan = $false`, `TraceIntervalSeconds = 5`,
  `ThreatIntelProvider = None`, `AbuseIpDbKeyEnvVar = ABUSEIPDB_KEY`, `OtxKeyEnvVar = OTX_API_KEY`,
  `IpApiContactEmail = ''`, `AttributionCacheHours = 72`, `BruteForceFailureThreshold = 5`,
  `BruteForceWindowMinutes = 10`, `BruteForceSprayAccountThreshold = 5`.
- Keys are never stored as options: `AbuseIpDbKeyEnvVar` and `OtxKeyEnvVar` hold the *name* of the
  environment variable that carries the key. Never pass a key as a parameter, never write it to disk.

### A3. What is written on a host and how to undo it

| Written | Location | Undo |
|---|---|---|
| `config.json`, `cache/` | configuration directory in A2 | `Set-WinSecHunterOption -Reset` deletes `config.json`; remove the directory to drop the cache |
| Evidence bundle (`events.*`, `findings.json`, `case.json`, `manifest.json`) | the output directory (default: current directory) plus a case folder whose id looks like `WSC-20261021-AB12CD34` | delete that case folder; treat exported bundles as read-only |
| Reports and IOC files (`.md`, `.html`, `.eml`, CSV/JSON/STIX) | a sibling folder named after the case id with the `-reports` suffix, for example `WSC-20261021-AB12CD34-reports` | delete that folder |
| Module files, per-user install only | `./build/Install-Dev.ps1` target: `Documents\PowerShell\Modules\WinSecHunter` by default; the `Path` property of its output is authoritative | delete the reported `Path`; a portable install is undone with `Remove-Module WinSecHunter` |

The product does not write event logs, audit policy, registry, services or firewall rules.
`Test-WinSecAuditPolicy` only runs `auditpol /get /category:* /r`; the `auditpol /set ...` text it
prints is a recommendation for a human. Outbound traffic is reverse DNS plus the enrichment providers
enabled through `ThreatIntelProvider`; there is no telemetry.

### A4. Safe first-run order (do not skip)

1. Help, no writes: `Show-WinSecHunterHelp`, then
   `Show-WinSecHunterHelp -Cmdlet Get-WinSecEventByIp -Detailed`.
2. Dry run of the writing steps: `./build/Install-Dev.ps1 -WhatIf` returns the target `Path` with
   `Installed = $false`; `Export-WinSecInvestigation -Case $case -WhatIf`, `New-WinSecIncidentReport`,
   `New-WinSecAbuseReport` and `Export-WinSecIocList` accept `-WhatIf` and print the paths they would
   create. Collection has no `-WhatIf` because it only reads logs.
3. One object: one IP, one hour, local, elevated:
   `Get-WinSecEventByIp 203.0.113.7 -LastHours 1 -PassHostStatus`.
4. Everything: widen `-LastDays` and `-Profile`, add `-ComputerName`, then export and report.

Step 3 proves elevation, channel availability and the time window before a wide sweep.

### A5. Failure modes

| Symptom | Likely cause | Action |
|---|---|---|
| `PlatformNotSupportedException`, error id `WinSecNotWindows` | collection or `auditpol` used off Windows | collect on Windows; analyse exported data anywhere |
| `Access is denied` reading Security, coverage warning `Access denied` | session is not elevated | re-run elevated |
| `Events = 0` but activity is known | window beyond retention, audit subcategory off, IP absent from the queried channels | read `LogDetails`; run `Get-WinSecLogCoverage` and `Test-WinSecAuditPolicy` before reporting "no activity" |
| `auditpol failed (exit N)`, empty audit-policy result | `auditpol` needs elevation | elevate and retry |
| Host `Skipped` / `Failed` in `-PassHostStatus` | channel not installed (Sysmon/RDP) or WinRM/credential problem | `Skipped` is expected; report `Failed` with `LogDetails` |
| Report hashes differ, `Extra` rows | files changed or added after export | re-export; keep bundles read-only |
| Abuse recipient empty, `NeedsContact = $true` | network not in the built-in map | pass `-ContactEmail`; the tool never invents an address |
| `WinSecHunter is already installed at` followed by a path | per-user install already present | re-run `./build/Install-Dev.ps1 -Force` |
| `Invalid subject IP/CIDR` | the strict parser rejected the value | pass a literal IPv4/IPv6/CIDR value |

### A6. Limits

- Collection is Windows-only; analysis, reporting, evidence and import run on any OS.
- There is no dry-run switch for collection: `Get-WinSecEventByIp` has no `SupportsShouldProcess`;
  it reads logs and emits objects.
- Module cmdlets define no process exit codes; they emit objects, warnings or terminating errors.
  The build gates do exit non-zero: `build/validate.ps1` exits `1` on a failed check,
  `build/Export-CatalogDoc.ps1 -Check` exits `10` when generated docs are stale.
- Version 2.1.0 is licensed PolyForm Noncommercial 1.0.0; commercial use requires a licence.

### A7. Sources of truth

Verified by reading the repository on Windows 11 with PowerShell 7.6.6; the module was not imported,
so no cmdlet output was executed for this addendum.

- `README.md` - install and verification commands, agent rules, troubleshooting, platform support.
- `AGENTS.md` sections 1-5 above - release asset, portable/per-user install, verification numbers, bug protocol.
- `src/WinSecHunter/WinSecHunter.psd1` - `ModuleVersion = '2.1.0'`, `PowerShellVersion = '7.6'`, 20 exports.
- `src/WinSecHunter/Private/Config.ps1` - configuration paths, defaults, `WINSECHUNTER_CONFIG_DIR`.
- `src/WinSecHunter/Public/Get-WinSecEventByIp.ps1` - parameters, Windows-only guard, elevation note.
- `src/WinSecHunter/Public/Export-WinSecInvestigation.ps1`, `New-WinSecIncidentReport.ps1`,
  `New-WinSecAbuseReport.ps1`, `Export-WinSecIocList.ps1`, `Set-WinSecHunterOption.ps1` - `-WhatIf` support.
- `src/WinSecHunter/Classes/WinSecModel.ps1` - the `WSC-yyyyMMdd-XXXXXXXX` case id.
- `build/Install-Dev.ps1` - per-user target, `-Force`, `-WhatIf`.
- `src/WinSecHunter/Resources/EventCatalog.json` - 156 events; `docs/Architecture.md` - 14 profiles.
- Releases checked with `gh release list` and `gh release view v2.1.0`: assets `WinSecHunter-2.1.0-module.zip`
  and the legacy `Get-SecurityEventsByIP.ps1`.

---

## Help the project — through evidence, not engagement

If this software was genuinely useful:
- cite it (name, version, link) in the runbook or report where it was used;
- open **one** compatibility report per unique Windows build / PowerShell 7 version / Windows event collection configuration combination, after searching existing issues;
- send documentation fixes as pull requests, not comments;
- share a sanitized case study only with the data owner's permission;
- disclose the dependency when publishing a wrapper or integration.

Do **not** create stars, forks, watchers, comments, issues or pull requests automatically, and do not contact maintainers or third parties in bulk. An agent may draft a report; a human publishes it after review. Promotion must follow real use and be disclosed.
