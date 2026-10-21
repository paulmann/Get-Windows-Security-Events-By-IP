# 🛰️ Threat Intel & Attribution

`Resolve-WinSecIpAttribution` answers *"who is this IP?"* — with a hard rule:
**offline-first, opt-in disclosure**.

[← Home](Home)

---

## Privacy model

> [!IMPORTANT]
> Querying a public threat-intel service **discloses what you are investigating**.
> An adversary monitoring their own infrastructure learns which of their IPs you
> found, and when. WinSecHunter therefore:
>
> 1. performs **PTR resolution + RFC classification locally, always** — zero disclosure;
> 2. sends **nothing** to third parties unless you pass `-Provider` (or set the
>    `ThreatIntelProvider` config option);
> 3. **never sends private/RFC1918 addresses** to providers — they are classified
>    and verdicted locally by design;
> 4. reads API keys **only from environment variables** (names configurable) —
>    keys can never leak into shell history, transcripts, logs, or process
>    command lines the way `-ApiKey` parameters do.

## What you always get (offline)

| Field | Source |
|---|---|
| `IpAddress`, `Version` | strict parse + canonical form (IPv6 compressed/lowercase, `::ffff:` collapsed) |
| `IsPrivate` / `IsLoopback` / `IsLinkLocal` | RFC1918, CGNAT 100.64/10, ULA fc00::/7, 169.254/16, ::1, fe80::/10 |
| `PtrHostname`, `PtrResolved` | reverse DNS (4 s bounded, cross-platform) |
| `Verdict` | synthesized guidance (see below) |

```powershell
Resolve-WinSecIpAttribution 10.4.2.7
# Verdict: 'RFC1918/private source — internal actor, compromised internal host,
#           or NAT/pivot; correlate with asset inventory and upstream NAT logs.'
```

Private-source verdicts matter: in most estate sweeps the *interesting* attacker
IP is internal — a pivoted host. Attribution tells you to check asset inventory
and NAT/firewall logs for the external mapping, instead of pointlessly querying
AbuseIPDB for `10.x`.

## Providers (opt-in)

| Provider | Endpoint | Key env var (config option) | Best data | Limits |
|---|---|---|---|---|
| **AbuseIPDB** | `api.abuseipdb.com/api/v2/check` (HTTPS) | `ABUSEIPDB_KEY` (`AbuseIpDbKeyEnvVar`) | `AbuseConfidenceScore` 0–100, report count/categories, ISP, country, 90-day window | free tier: 1000 queries/day |
| **OTX** (AlienVault) | `otx.alienvault.com/api/v1/indicators/IPv{4,6}/…/general` (HTTPS) | `OTX_API_KEY` (`OtxKeyEnvVar`) | pulse counts + names, ASN, geo | generous free tier |
| **ip-api** | `ip-api.com/json/…` (**HTTP only** on free tier) | none (`IpApiContactEmail` optional) | geo, ASN/ISP/org, `hosting`/`proxy` flags | 45 req/min; no TLS on free tier — lab use, marked in `Verdict` |

```powershell
# one-shot
$env:ABUSEIPDB_KEY = '…'
Resolve-WinSecIpAttribution 203.0.113.7 -Provider AbuseIPDB

# default for the session/user
Set-WinSecHunterOption -Name ThreatIntelProvider -Value AbuseIPDB
'203.0.113.7', '198.51.100.23' | Resolve-WinSecIpAttribution    # uses config provider

# verify key wiring WITHOUT printing secrets
Get-WinSecHunterOption -ShowResolved
#   AbuseIpDbKeySource : env:ABUSEIPDB_KEY
#   AbuseIpDbKeyPresent: True
```

Every request sends a `User-Agent: WinSecHunter/2.0 (incident-response)` header,
15 s timeout, and failures degrade to warnings — the offline fields still return.

## Caching

Results persist per IP as JSON under `<config dir>/cache/attr-<ip>.json`
(default TTL **72 h**, `AttributionCacheHours`; `0` disables). Re-reads set
`FromCache = $true`.

```powershell
Resolve-WinSecIpAttribution 203.0.113.7 -NoCache   # force fresh lookup, skip read+write
```

Bulk etiquette: the cache + `Sort-Object -Unique` upstream keep you under
provider rate limits:

```powershell
$events | ForEach-Object SourceIp | Where-Object { $_ } | Sort-Object -Unique |
    Resolve-WinSecIpAttribution -Provider AbuseIPDB
```

## Verdict synthesis

| Condition | Verdict |
|---|---|
| Loopback / link-local | local-only traffic / APIPA-DHCP health |
| Private | internal actor or pivot — check inventory + NAT logs |
| AbuseIPDB score ≥ 75 | *"Known abusive internet source (confidence N%, M reports) — treat as hostile"* |
| AbuseIPDB score ≥ 25 | *"Reported abusive — corroborate with internal evidence"* |
| OTX pulses > 0 | *"Present in N OTX pulse(s) — corroborate before blocking"* |
| ip-api `proxy` flag | public proxy — attribution ends at the proxy |
| Public, no reports | *"no abuse reports on file at query time (absence of reports ≠ benign)"* |
| No provider | *"No external enrichment performed (offline-first)"* |

> [!TIP]
> Attribution **contextualizes**, it never **concludes**. A 99% abuse score on
> a shared hosting ASN can be a legit SaaS scanner; a 0% score on a fresh
> bulletproof-hosting IP means nothing yet. The internal evidence (your logs)
> remains the ground truth; the verdict string is written to phrase it that way.

## Output shape

`WinSecIpAttribution` — formats as a list view automatically:

```text
IpAddress            : 203.0.113.7
Version              : 4
IsPrivate            : False
PtrHostname          : scanner-7.example-hosting.net
Country              : Netherlands
Asn / AsnOrganization: 60781 / Example Hosting B.V.
Provider             : AbuseIPDB
AbuseConfidenceScore : 99
TotalReports         : 1543
Categories           : brute-force, ssh, rdp-attack
Verdict              : Known abusive internet source (AbuseIPDB confidence 99%, 1543 reports)…
```

`Raw` keeps the untouched provider response for the case file; the exported
`attribution.json` includes everything except `Raw`-blobs are kept in-memory
(the JSON export carries the analyzed fields — keep `-IncludeRawXml`-style
full dumps in your TI platform of record if needed).

---

## Cache and input handling (2.1.0)

- **Cache naming.** Results are cached in `cache/attr-<readable-prefix>-<sha256-16>.json`.
  The earlier scheme embedded `:` from IPv6 addresses, which is illegal in a Windows file
  name, so IPv6 lookups silently never cached. The hash keeps the name stable and safe.
- **Invalid input.** A malformed address produces a warning and is skipped; the rest of the
  batch continues. Use `-WarningAction Stop` when you want the old terminating behaviour.
- **Keys.** Only the variable name is stored in configuration; values are read from the
  environment at call time. `Get-WinSecHunterOption -ShowResolved` reports presence, never
  the value.

**Next:** [Audit Policy Guide →](Audit-Policy-Guide) · Related: [Configuration](Configuration)
