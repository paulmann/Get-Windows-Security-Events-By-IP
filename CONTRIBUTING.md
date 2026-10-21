# Contributing to WinSecHunter

Thanks for taking the time to improve the toolkit. This project is maintained as
production incident-response software: correctness, evidence integrity and reviewable
diffs matter more than feature volume.

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| PowerShell | 7.6+ (`pwsh`) | the module targets Core only |
| Pester | 5.4+ | unit tests |
| PSScriptAnalyzer | 1.25+ | static analysis gate |

```powershell
Install-Module Pester -MinimumVersion 5.4 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser
git clone https://github.com/paulmann/Get-Windows-Security-Events-By-IP.git
cd Get-Windows-Security-Events-By-IP
```

## Definition of done

A change is complete only when **all** of the following pass locally:

```powershell
./build/validate.ps1 -Tests     # AST, manifest, imports, help, PSSA, Pester
./build/Build-Module.ps1 -Zip   # artifact builds and imports in a child process
./build/Export-CatalogDoc.ps1 -Check  # generated docs are current
```

Additional rules:

- New or changed public cmdlets need comment-based help with synopsis, every parameter,
  at least two examples and `.OUTPUTS`.
- Behaviour changes need a test that would fail on the previous code.
- Security-relevant changes (parsing, XPath, evidence hashing, redaction) need an explicit
  test for the failure mode, not only the happy path.
- Update `CHANGELOG.md` under `## [Unreleased]` (or the next version) in the same change.

## Layout

```
src/WinSecHunter/
  Enums/      enums used by classes (first in the loader)
  Classes/    WinSecEvent, WinSecCase, sessions, findings, coverage, attribution
  Private/    query builder, executor, parser, decoders, config, reporting helpers
  Public/     one file per exported cmdlet
  Resources/  EventCatalog.json
tests/        Pester 5 suites + TestHelpers.ps1
build/        Build-Module, Install-Dev, validate, Export-CatalogDoc
docs/         repository-side documentation (generated catalog/reference included)
wiki/         source of the GitHub Wiki (published separately)
```

## Conventions

1. **Approved verbs only** (`Get-`, `Test-`, `New-`, `Export-`, `Import-`, `Show-`, `Resolve-`).
   Private helpers follow the same rule (`Get-WinSecResource`, not `LoadResource`).
2. **No `Write-Host` or `exit` in `src/`.** The single exception is `Show-WinSecHunterHelp`,
   whose purpose is interactive rendering; it returns strings with `-PassThru` and writes
   files atomically with `-OutFile`.
3. **`ShouldProcess`** on every cmdlet that writes (`Export-`, `New-WinSecIncidentReport`,
   `New-WinSecAbuseReport`, `Install-Dev`). `-WhatIf` must not create directories or files.
4. **StrictMode 3.0 is always on.** Never dot-access a property that may be absent; use
   `$obj.PSObject.Properties['Name']`, hashtable indexers, or a typed default.
5. **UTC everywhere in analysis.** `TimeCreated` is display-only; sorting, bucketing and
   report timelines use `TimeUtc`.
6. **No secrets in parameters or files.** Environment variables only; keys must never reach
   reports, logs, manifests or HTML.
7. **Locale independence.** Do not branch on English OS messages when an `HResult`/Win32
   code exists; parse `auditpol /r` by column position, not by localized headers.
8. **Evidence is immutable.** Report cmdlets write to `<CaseId>-reports`, never into the
   evidence bundle, so `Test-WinSecEvidenceIntegrity` stays green.

## Tests

```powershell
Invoke-Pester ./tests -Output Detailed
```

- Pure logic is tested with synthetic events (`New-TestEvent`), so the suite runs on Linux
  and Windows CI.
- Windows-only behaviour is guarded with `-Skip:(-not $IsWindows)` and must be listed in the
  pull request description.
- Regression tests for fixed defects live in `tests/Regression.Tests.ps1`; keep them.

## Pull requests

- One concern per pull request; keep unrelated formatting out.
- Describe the failure mode and how the change is verified (commands and output).
- Never commit investigation data, `output/`, `.ragraf/`, `.zwork/` or generated reports.
- Commit messages: imperative mood, one line under 72 characters, details in the body.

## Code of conduct

Be precise and civil. Assume good faith, attack the problem, not the person.
