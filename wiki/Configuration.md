# ⚙️ Configuration

Persistent options, where they live, how they are validated, and how secrets are handled.

[← Home](Home)

---

## Where configuration lives

| OS | Path |
|---|---|
| Windows | `%LOCALAPPDATA%\WinSecHunter\config.json` |
| Linux / macOS | `$XDG_CONFIG_HOME/WinSecHunter/config.json`, else `~/.config/WinSecHunter/config.json` |
| Override | `$env:WINSECHUNTER_CONFIG_DIR` (portable IR kit, tests) |

The Windows path is resolved through `[Environment]::GetFolderPath('LocalApplicationData')`,
not `$env:LOCALAPPDATA`. That matters in service accounts, scheduled tasks and hardened
environments where the variable is absent.

```powershell
Get-WinSecHunterOption                 # effective configuration
Get-WinSecHunterOption -ShowResolved   # plus resolved context
```

`-ShowResolved` reports whether an API key is **present**, never its value.

## Options

| Option | Default | Meaning |
|---|---|---|
| `DefaultProfile` | `IncidentResponse` | profile used when no `-Profile`/`-Category`/`-EventId` is given |
| `DefaultMaxEvents` | `5000` | per-channel record cap (`0` = unlimited) |
| `DefaultThrottleLimit` | `8` | parallel remote hosts |
| `DefaultOutputDirectory` | `''` | parent folder for bundles and reports (`''` = current directory) |
| `IncludeMessage` | `$false` | collect rendered message text (slower, larger) |
| `DeepScan` | `$false` | regex the IP anywhere in the record by default |
| `TraceIntervalSeconds` | `5` | polling interval for `Trace-WinSecIp` |
| `ThreatIntelProvider` | `None` | `None`, `AbuseIPDB`, `OTX`, `IpApi` |
| `AbuseIpDbKeyEnvVar` | `ABUSEIPDB_KEY` | environment variable holding the AbuseIPDB key |
| `OtxKeyEnvVar` | `OTX_API_KEY` | environment variable holding the OTX key |
| `IpApiContactEmail` | `''` | contact address required by the ip-api free tier |
| `AttributionCacheHours` | `72` | attribution cache lifetime |
| `BruteForceFailureThreshold` | `5` | failures per account before a finding |
| `BruteForceWindowMinutes` | `10` | sliding window for counting |
| `BruteForceSprayAccountThreshold` | `5` | distinct accounts that means spraying |

## Read and write

```powershell
Get-WinSecHunterOption -Name DefaultProfile
Set-WinSecHunterOption -DefaultProfile BruteForce -DefaultMaxEvents 20000
Set-WinSecHunterOption -Options @{ DefaultThrottleLimit = 16; DeepScan = $true }
Set-WinSecHunterOption -Reset
```

`Set-WinSecHunterOption` supports `-WhatIf`. Values are coerced to the type of the default and
rejected when they do not fit; unknown option names are rejected with the list of valid ones.

## Atomic writes

`config.json` is written to a temporary file in the same directory and moved into place with
overwrite. A crash, a full disk or two concurrent writers cannot leave a truncated file; the
previous valid configuration survives.

If the file is corrupt, the module warns and falls back to defaults rather than failing.

## Secrets

- API keys are **never** accepted as parameters and **never** written to `config.json`.
- Configuration stores the **name** of the environment variable, not the key.
- Keys appear in no report, HTML, manifest or log.

```powershell
$env:ABUSEIPDB_KEY = '<key>'     # current session only
Resolve-WinSecIpAttribution 203.0.113.7 -Provider AbuseIPDB
Remove-Item Env:\ABUSEIPDB_KEY
```

On Windows, prefer a user-scope environment variable or a secret store that injects it into
the process; do not commit keys to a profile script.

## Output directory semantics

| Cmdlet | Writes to |
|---|---|
| `Export-WinSecInvestigation` | `<OutputDirectory>/<CaseId>/` |
| `New-WinSecIncidentReport` | `<OutputDirectory>/<CaseId>-reports/` |
| `New-WinSecAbuseReport` | `<OutputDirectory>/<CaseId>-reports/` |
| `Export-WinSecIocList` | `<OutputDirectory>/<CaseId>-reports/` |

`-OutputDirectory` overrides `DefaultOutputDirectory` per call. Reports never enter the
evidence bundle.

## Portable kit

```powershell
$env:WINSECHUNTER_CONFIG_DIR = 'E:\IR-Kit\config'
Import-Module E:\IR-Kit\Modules\WinSecHunter
```

Everything (configuration and attribution cache) stays inside the kit directory. Reading from
read-only media works; writes fail loudly rather than silently.

## Environment overrides

| Variable | Effect |
|---|---|
| `WINSECHUNTER_CONFIG_DIR` | configuration and cache directory |
| `ABUSEIPDB_KEY` | AbuseIPDB API key (name configurable) |
| `OTX_API_KEY` | AlienVault OTX key (name configurable) |
| `NO_COLOR` | disable ANSI colour in `Show-WinSecHunterHelp` |
