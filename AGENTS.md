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


