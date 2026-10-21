# 📋 Reference Tables

Decoding tables, enums, object models and profile quick-reference — the page
you keep open in a second tab during an investigation.

[← Home](Home)

> [!NOTE]
> Everything here is live in the module: `Get-WinSecEventCatalog` for events,
> `Get-Help` for parameters, and the decoder runs automatically — `StatusCode`
> on every `WinSecEvent` is already human-readable. These tables are for
> reading *raw* logs and reports.

---

## Hunt profiles

`-Profile` values for `Get-WinSecEventByIp` / `Trace-WinSecIp` / `Test-WinSecAuditPolicy`
(unions allowed; live source of truth: `Get-WinSecEventCatalog -ListProfiles`):

| Profile | Scope |
|---|---|
| **`IncidentResponse`** *(default)* | auth + Kerberos + RDP + account mgmt + credential access + persistence + anti-forensics + shares; excludes high-noise object/firewall/connection logs |
| `FailedAuth` | failed authentication only — 4625, 4771, 4776, 4770, 4649, 5168, 5632/5633, RCM 1148 |
| `BruteForce` | failures **and** successes + lockouts (4624/4625/4768–4771/4776/4740/4767/4648/1148/1149/LSM 21/25) |
| `Rdp` | RCM 1147–1149 + LSM 21–25 + 4624/4625/4778/4779/4800–4803 |
| `Lateral` | 4624/4648/4778/4779, shares 5140–5145, remote services/tasks 4697/4698/7045, Sysmon 3/8 |
| `AccountManagement` | 4720–4766, 4767, 4794 |
| `Kerberos` | 4649, 4768–4771, 5168 |
| `Firewall` | rule lifecycle 2004–2006/4946–4958, service health 5024–5037, connections 5154–5159 |
| `DefenseEvasion` | 104/1100/1102/1104/1108, 4699, 4710/4715/4719/4817/4907, firewall-service shutdowns, 5038, 5712, Sysmon 16/23 |
| `Persistence` | tasks, services, autostart categories |
| `Sysmon` | EID 1, 3, 8–11, 13, 15, 16, 22, 23, 25 |
| `ObjectAccess` | file/share/registry/DS object access (needs SACLs; noisy) |
| `Critical` | everything the catalog rates Critical |
| `All` | all 156 cataloged events |

## Logon types

| Value | Name | Meaning / IR note |
|---|---|---|
| 2 | Interactive | physical console or KVM |
| **3** | **Network** | SMB, remote registry, IIS — hash-based; **PtH surfaces here** |
| 4 | Batch | scheduled task |
| 5 | Service | service control manager |
| 6 | Proxy | IIS impersonation (rare) |
| 7 | Unlock | workstation unlock (password re-validated) |
| 8 | NetworkCleartext | network logon, **plaintext credentials** (IIS Basic auth) |
| **9** | **NewCredentials** | `runas /netonly`, CloneToken — local identity kept, remote creds supplied |
| **10** | **RemoteInteractive** | **RDP** |
| 11 | CachedInteractive | cached domain credentials (DC unreachable) |
| 12 | CachedRemoteInteractive | cached remote interactive (rare) |
| 13 | CachedUnlock | cached unlock |

## NTSTATUS — logon failures (4625 `Status`/`SubStatus`, 4776 `ErrorCode`)

<details open>
<summary><b>Table (the SubStatus is the real reason — Status is usually generic 0xC000006D)</b></summary>

| Code | Meaning |
|---|---|
| `0x00000000` | Success |
| `0xC0000064` | Account does not exist |
| `0xC000006A` | **Incorrect password** |
| `0xC000006D` | Generic logon failure |
| `0xC000006E` | Account restriction (logon hours, workstation limit) |
| `0xC000006F` | Logon outside authorized time window |
| `0xC0000070` | Logon from unauthorized workstation |
| `0xC0000071` | Password expired |
| `0xC0000072` | **Account disabled** |
| `0xC000009A` | Insufficient system resources |
| `0xC0000133` | Clocks out of sync (client ↔ server) |
| `0xC000015B` | Logon type not granted at this machine |
| `0xC0000193` | Account expired |
| `0xC0000224` | Password change required at next logon |
| `0xC0000225` | Non-retryable error during logon |
| `0xC0000234` | **Account locked out** |
| `0xC00002EE` | Error occurred during logon |
| `0xC0000413` | Authentication firewall (silos) prohibits logon |

</details>

## FailureReason — `%%` string IDs (4625)

| Code | Meaning |
|---|---|
| `%%2304` | An error occurred during logon |
| `%%2305` | The specified user account has expired |
| `%%2308` | Requested logon type not granted at this machine |
| `%%2309` | The specified account's password has expired |
| `%%2310` | Account currently disabled |
| `%%2311` | Account logon time restriction violation |
| `%%2312` | User not allowed to log on at this computer |
| `%%2313` | **Unknown user name or bad password** |

> [!WARNING]
> The legacy script v5.0.2 mapped these **incorrectly** (e.g. `%%2305` →
> "Account does not exist"). WinSecHunter follows the Microsoft-documented
> table above. If you have old legacy reports, re-verify their failure reasons.

## Kerberos result codes (4768/4769/4770 `ResultCode`, 4771 `FailureCode`)

<details>
<summary><b>Full table (0x0 – 0x3D)</b></summary>

| Code | Meaning | IR note |
|---|---|---|
| `0x0` | No error | success |
| `0x1` | Client entry expired | |
| `0x2` | Server entry expired | |
| `0x3` | Protocol version not supported | |
| `0x4`/`0x5` | Key encrypted in old master key | |
| `0x6` | **Client not found in Kerberos database** | typo-squatting / enumeration (user doesn't exist) |
| `0x7` | Server not found | new computer account not replicated |
| `0x8` | Multiple principal entries | |
| `0x9` | Null key | reset the account password |
| `0xA`–`0xB` | Postdating/start-time issues | |
| `0xC` | KDC policy rejects request | e.g. workstation restriction |
| `0xD` | KDC cannot accommodate option | |
| `0xE`–`0x11` | Unsupported etype/checksum/padata/transited | downgrade attempts |
| `0x12` | **Client credentials revoked** | disabled / expired / **locked out** / logon-hours |
| `0x13`/`0x14` | Server/TGT revoked | |
| `0x15`/`0x16` | Client/server not yet valid | time issues |
| `0x17` | **Password expired** | |
| `0x18` | **Pre-auth invalid — usually bad password** | the Kerberos "wrong password" |
| `0x19` | Additional pre-auth required | |
| `0x1F` | Integrity check on decrypted field failed | |
| `0x20` | Ticket expired | common on computer accounts |
| `0x21` | Ticket not yet valid | |
| `0x22` | **Request is a replay** | pairs with 4649 |
| `0x23`–`0x24` | Ticket not for us / authenticator mismatch | |
| `0x25` | **Clock skew too great** | |
| `0x26` | Incorrect net address | IP changed mid-session? |
| `0x27`–`0x2A` | Protocol/message anomalies | |
| `0x2C` | Specified version of key not available | golden-ticket smell (with 0x2E) |
| `0x2D` | Service key not available | |
| `0x2E` | Mutual authentication failed | |
| `0x2F`–`0x32` | Message direction/sequence/checksum anomalies | |
| `0x3C`/`0x3D` | Generic / field too long | |

</details>

## Network constants

| Field | Encoded | Decoded |
|---|---|---|
| Direction (5156/5157) | `%%14592` | Inbound |
| | `%%14593` | Outbound |
| | `%%14594` | Loopback |
| Protocol (firewall) | `6` / `17` / `1` / `58` | TCP / UDP / ICMP / ICMPv6 |
| Protocol (Sysmon) | `tcp` / `udp` | uppercased pass-through |
| Direction (Sysmon EID 3) | `Initiated=true/false` | Outbound / Inbound |

## Enums (module types)

| Enum | Values |
|---|---|
| `WinSecEventCategory` | Unknown · Authentication · Kerberos · RemoteAccess · LogonLogoff · AccountLockout · AccountManagement · SpecialPrivilege · LateralMovement · ShareAccess · ObjectAccess · DirectoryAccess · Firewall · PolicyChange · DefenseEvasion · Persistence · ServiceActivity · ScheduledTask · ProcessExecution · NetworkActivity · CredentialAccess · SystemIntegrity |
| `WinSecOutcome` | Unknown · Success · Failure · Informational |
| `WinSecVerdict` | None · BruteForce · PasswordSpraying · CredentialStuffing · BruteForceWithSuccess · LockoutStorm · SuspiciousVolume |
| `WinSecSeverity` | Informational · Low · Medium · High · Critical |
| `WinSecExportFormat` | Csv · Json · Html · Markdown · CliXml · All |
| `WinSecDirection` | Unknown · Inbound · Outbound |
| `WinSecHostStatus` | Completed · NoEvents · Failed · Skipped |
| `WinSecLogonType` | see [logon types](#logon-types) |

## `WinSecEvent` property dictionary

<details open>
<summary><b>The normalized event object</b></summary>

| Group | Properties |
|---|---|
| Provenance | `Computer` · `LogName` · `ProviderName` · `RecordId` · `EventId` |
| Time | `TimeCreated` (source-local) · **`TimeUtc`** (authoritative — sort/analyze on this) |
| Match | `MatchedIp` (which queried IP/CIDR hit) · `MatchedOn` (`EventData`·`UserData`·`Message`·`Xml`) |
| Classification | `Category` · `Outcome` · `Importance` · `EventName` · `AttackIds` · `Description` |
| Network | `SourceIp` · `SourcePort` · `DestinationIp` · `DestinationPort` · `Direction` · `Protocol` |
| Authentication | `TargetAccount` · `SubjectAccount` · `LogonType` · `LogonId` · `AuthPackage` · `LogonProcess` · `Workstation` |
| Status | `Status` · `SubStatus` · **`StatusCode`** (decoded) · `FailureReason` |
| Objects | `ProcessName` · `ServiceName` · `TaskName` · `ObjectName` |
| Payload | `Data` (all named fields, incl. `ActivityID` for RDP chaining) · `Message`* · `Xml`* |

\* only with `-IncludeMessage` / `-IncludeRawXml`.
Methods: `.ToHashtable($flattenData)` · `.GetDedupKey()` → `Computer|LogName|RecordId|EventId`.

</details>

## RDP field layouts (why UserData matters)

| Event | Subtree | Fields |
|---|---|---|
| RCM 1149/1148/1147 | `UserData/EventXML` | `Param1` user · `Param2` domain · **`Param3` source IP** |
| LSM 21–25 | `UserData/EventXML` | `User` (`HOST\user`) · `SessionID` · **`Address` source IP** |
| Correlation | `System/Correlation` | `@ActivityID` — chains RCM ↔ LSM ↔ 4624 for one connection |

## ATT&CK quick index (most-hunted)

| Technique | Events in catalog |
|---|---|
| T1110 Brute Force (.001/.003) | 4625, 4771, 4776, 1148, 5632/5633, 4740 |
| T1078 Valid Accounts (.002/.003) | 4624, 4648, 4672, 4778, 1149 |
| T1021.001 RDP | 4778/4779, 1149, LSM 21–25 |
| T1021.002 SMB | 5140, 5145 |
| T1558/.003 Kerberoasting | 4768, 4769, 4771, 4649 |
| T1543.003 Windows Service | 4697, 7045 |
| T1053.005 Scheduled Task | 4698–4702 |
| T1136 Create Account | 4720, 4741, 5137 |
| T1098 Account Manipulation | 4724, 4728, 4732, 4738, 4756, 4794 |
| T1070.001 Clear Logs | **1102, 104** |
| T1562.002 Disable Audit | 4715, 4719, 4907, 4710, 1100 |
| T1562.004 Disable Firewall | 4950, 5025–5037, 2004–2006 |
| T1562.001 Impair Defenses | 5038, Sysmon 16 |
| T1003 Credential Dumping | 4662 (DCSync w/ SACL), 5058, 5376/5377, Sysmon 10 |
| T1059 Command & Scripting | 4688, Sysmon 1 |
| T1071/T1571 C2 channels | Sysmon 3 |
| T1055 Injection | Sysmon 8, 25 |

Full mapping per event: [docs/EventCatalog.md](https://github.com/paulmann/Get-Windows-Security-Events-By-IP/blob/main/docs/EventCatalog.md) or `Get-WinSecEventCatalog -AttackId T1021.001`.

---

## Host results and report artifacts (2.1.0)

`WinSecHostResult` (emitted with `-PassHostStatus`):

| Property | Type | Meaning |
|---|---|---|
| `Computer` | string | requested label, plus resolved name when it differs |
| `Status` | enum | `Completed`, `NoEvents`, `Skipped`, `Failed` |
| `EventsFound` | int | records returned for the host |
| `ErrorMessage` | string | failure summary (empty when fine) |
| `DurationMs` | double | wall-clock time |
| `LogDetails` | object[] | per channel: `LogName`, `Status`, `EventsFound`, `Error`, `DurationMs` |

Artifacts produced by the reporting layer:

| Artifact | Cmdlet | Container |
|---|---|---|
| `<CaseId>-incident-report.md` / `.html` | `New-WinSecIncidentReport` | `<CaseId>-reports/` |
| `<CaseId>-abuse-<ip>.eml` / `.md` / `.json` | `New-WinSecAbuseReport` | `<CaseId>-reports/` |
| `<CaseId>-iocs.csv` / `.txt` / `.json` / `.stix.json` | `Export-WinSecIocList` | `<CaseId>-reports/` |
| `iocs.csv` / `iocs.json` | `Export-WinSecInvestigation` | evidence bundle |

Integrity statuses: `OK`, `Modified`, `Missing`, `Extra`, `Unreadable`.

**Next:** [Architecture →](Architecture) · Related: [Cmdlet Reference](Cmdlet-Reference)
