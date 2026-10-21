# winsechunter

**Incident-response toolkit for Windows security events — as an npm launcher.**

This package bundles the [WinSecHunter](https://github.com/paulmann/Get-Windows-Security-Events-By-IP)
PowerShell module and exposes a small CLI, so an npm-managed environment can install and call it
without cloning the repository. Package version `2.1.1` ships module `2.1.0` plus the `catalog`
CLI fix.

```bash
npm install -g winsechunter
winsechunter help
```

## Requirements

| Component | Version | Notes |
|---|---|---|
| Node.js | 18+ | the launcher only |
| PowerShell | 7.6+ (`pwsh`) | the actual engine; must be in `PATH` |
| Windows | 10/11/Server 2016+ | for event-log collection; the Security log needs elevation |
| Any OS | — | analysis, reporting and evidence verification work cross-platform |

If `pwsh` is not on `PATH`, point to it explicitly:

```bash
WINSECHUNTER_PWSH=/opt/microsoft/powershell/7/pwsh winsechunter help
```

## Commands

```bash
winsechunter --version
winsechunter help
winsechunter help Get-WinSecEventByIp
winsechunter catalog
winsechunter catalog --profile BruteForce
winsechunter sweep 203.0.113.7 --last-hours 24
winsechunter sweep 203.0.113.0/24 --last-hours 12 --json
```

`winsechunter sweep` returns events and per-channel status (`-PassHostStatus`). With `--json`
the output is a JSON array suitable for pipelines.

## What is inside

- `module/` — the complete WinSecHunter 2.1.0 module (20 cmdlets, 156-event catalog).
- `bin/winsechunter.js` — a thin launcher that imports the module and calls its cmdlets.

For the full workflow — incident reports, abuse reports, IOC/STIX export, evidence bundles —
use the module directly:

```powershell
Import-Module "$(npm root -g)/winsechunter/module/WinSecHunter.psd1"
Show-WinSecHunterHelp
New-WinSecIncidentReport -Case $case -Event $events -Format Both -PassThru
```

## Security

- No telemetry, no phone-home.
- API keys are read only from environment variables (`ABUSEIPDB_KEY`, `OTX_API_KEY`).
- The launcher passes arguments through environment variables; addresses are validated before
  they reach PowerShell.
- The npm package contains the same code as the GitHub release; compare `module/` if in doubt.

## Bugs

Please report issues at
https://github.com/paulmann/Get-Windows-Security-Events-By-IP/issues/new/choose
with the npm package version, `pwsh --version`, OS and the exact command.

## Licence

PolyForm Noncommercial License 1.0.0 — see `LICENSE`. Commercial use requires a licence from
mid1977@gmail.com. WinSecHunter is a derivative work of `Get-SecurityEventsByIP.ps1` by
Mikhail Deynekin.
