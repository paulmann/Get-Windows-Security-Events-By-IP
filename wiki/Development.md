# 🧑‍💻 Development

How to build, test, extend and release WinSecHunter 2.1.0.

[← Home](Home) · [Contributing](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/blob/main/CONTRIBUTING.md)

---

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| PowerShell | 7.6+ (`pwsh`) | module runtime and gates |
| Pester | 5.4+ | unit tests |
| PSScriptAnalyzer | 1.25+ | static analysis |

```powershell
Install-Module Pester -MinimumVersion 5.4 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -Scope CurrentUser
```

## Layout

```text
src/WinSecHunter/
├── WinSecHunter.psd1          manifest — export allow-list mirrored in the psm1
├── WinSecHunter.psm1          loader: Enums → Classes → Private → Public
├── WinSecHunter.Format.ps1xml table/list views
├── Enums/WinSecEnums.ps1
├── Classes/                   WinSecEvent, WinSecModel (case, sessions, findings, coverage, attribution, host results)
├── Private/                   Resource, IpUtils, Decode, Config,
│                              New-WinSecEventQuery, Invoke-WinSecEventQuery,
│                              ConvertTo-WinSecEvent, ConvertTo-WinSecHtmlReport,
│                              Reporting (context, IOCs, renderers, EML), Help
├── Public/                    20 cmdlets, one file each
└── Resources/EventCatalog.json
tests/                         Pester 5 suites + TestHelpers.ps1
build/                         Build-Module · Install-Dev · validate · Export-CatalogDoc
docs/                          architecture, examples, audit guide, generated catalog/reference
wiki/                          source for this wiki
```

## Daily loop

```powershell
./build/validate.ps1 -Tests              # all gates
./build/Build-Module.ps1 -Zip            # artifact + zip under output/
./build/Install-Dev.ps1 -Force           # install for manual play
./build/Export-CatalogDoc.ps1            # regenerate docs
Invoke-Pester ./tests -Output Detailed   # tests only
```

`validate.ps1` runs, in order: AST parse (classes together with enums), manifest,
import/export parity, comment-based help (synopsis + ≥2 examples), catalog smoke,
PSScriptAnalyzer (0 Error/0 Warning, `TypeNotFound` excluded), and — with `-Tests` — Pester.

Current baseline: **168 passed, 0 failed, 1 skipped** (the Windows-only guard test is skipped
on Windows), 169 tests total.

## Conventions

1. **Approved verbs only**, private helpers included (`Get-WinSecResource`, not `LoadResource`).
2. **No `Write-Host` or `exit` in `src/`.** The single exception is `Show-WinSecHunterHelp`,
   whose purpose is interactive rendering; it returns strings with `-PassThru`.
3. **`ShouldProcess`** on everything that writes. `-WhatIf` must not create files or folders.
4. **StrictMode 3.0** is always on: never dot-access a property that may be absent — use
   `$obj.PSObject.Properties['Name']`, hashtable indexers or a typed default.
5. **UTC for analysis**, local time for display only.
6. **No `$null` into value types.** Time bounds use `[datetime]::MinValue` as "not set";
   `[AllowNull()][datetime]` does not accept `$null`, and `Nullable<T>` is unboxed during binding.
7. **No `$using:`scriptblock** in `ForEach-Object -Parallel`: pass text and rebuild with
   `[scriptblock]::Create`.
8. **Classify OS errors by `HResult`/Win32 code**, never by English message text.
9. **Evidence is immutable**: reports go to `<CaseId>-reports`, never into the bundle.
10. **No secrets in parameters, files, reports or logs** — environment variables only.

## Extending

### Add an event ID

1. Append an entry to `Resources/EventCatalog.json`:
   `{ "Id": …, "Log": …, "Name": …, "Category": …, "Importance": …, "Attack": [...], "IpFields": [...], "Notes": "…" }`.
2. Add it to a profile if it belongs to one.
3. `./build/Export-CatalogDoc.ps1` — regenerate the catalog page.
4. Add a parser test if the event has a new field layout.

### Add a decoder entry

`Private/Decode.ps1` — NTSTATUS, Kerberos and `%%` tables are plain hashtables keyed by
lowercase bare hex. Add a `Decoder.Tests.ps1` case.

### Add a threat-intel provider

Extend the `ValidateSet` in `Resolve-WinSecIpAttribution`, add a branch with timeout and
error handling, add a `*KeyEnvVar` option, and update the provider table in the wiki.

### Add a cmdlet

1. New file in `Public/`.
2. Add the name to **both** allow-lists: `WinSecHunter.psm1` and `.psd1` `FunctionsToExport`.
3. Comment-based help: synopsis, every parameter, ≥2 examples, `.OUTPUTS`.
4. Tests, including a failure-mode case.
5. `./build/validate.ps1 -Tests` and update `CHANGELOG.md`.

## Testing

- Pester 5 syntax, module bootstrapped by `tests/TestHelpers.ps1`.
- `New-TestEvent` builds typed `WinSecEvent` objects inside module scope.
- Private functions are tested with `InModuleScope WinSecHunter { … }`.
- Windows-only behaviour is guarded with `-Skip:(-not $IsWindows)`.
- Regression tests for fixed defects live in `tests/Regression.Tests.ps1`; reporting tests in
  `tests/Reporting.Tests.ps1`.

## Release

```powershell
# 1. Bump ModuleVersion in WinSecHunter.psd1 and add a CHANGELOG section
# 2. Regenerate documentation
./build/Export-CatalogDoc.ps1
# 3. Gates
./build/validate.ps1 -Tests
./build/Build-Module.ps1 -Zip
# 4. Tag and push
git tag v2.1.0
git push origin main --tags
```

`publish.yml` re-runs the suite, rebuilds, checks tag ↔ manifest version, and publishes to
PSGallery using the `PSGALLERY_API_KEY` repository secret.

## Wiki

The wiki is a separate git repository (`<repo>.wiki.git`, branch `master`). Pages live in
`wiki/` for review, then are copied into the wiki clone:

```powershell
git clone https://github.com/paulmann/Get-Windows-Security-Events-By-IP.wiki.git
Copy-Item .\wiki\*.md .\Get-Windows-Security-Events-By-IP.wiki\ -Force
cd .\Get-Windows-Security-Events-By-IP.wiki
git add -A; git commit -m "wiki: 2.1.0"; git push
```

Links between pages use page names without `.md` (`[Getting Started](Getting-Started)`);
repository files need absolute GitHub URLs.
