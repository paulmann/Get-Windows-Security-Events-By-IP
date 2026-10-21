# Audit Policy Guide

WinSecHunter can only find what Windows actually recorded. This guide maps the
event catalog to the **Advanced Audit Policy** subcategories that produce those
events, explains the built-in gap analyzer, and gives hardening baselines for
IP-incident readiness.

## 1. Check the current state

```powershell
# What is missing for a brute-force + RDP investigation on this host:
Test-WinSecAuditPolicy -Profile BruteForce, Rdp

# Fleet-wide (parallel over WinRM):
Test-WinSecAuditPolicy -ComputerName (Get-Content servers.txt) -Credential $cred

# Every gap carries a copy-paste fix, e.g.:
#   auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

`Test-WinSecAuditPolicy` matches subcategories **by GUID**, so it works on
non-English systems, and derives the requirement matrix from the profiles you
actually hunt with.

## 2. Requirement matrix (what WinSecHunter relies on)

| Subcategory (GUID suffix) | Recommended | Enables events | Why it matters for IP hunts |
|---|---|---|---|
| Logon `…9215` | Success + Failure | 4624, 4625 | The core signal: who logged on from where, and every failure with source IP + SubStatus |
| Logoff `…9216` | Success | 4634, 4647 | Session duration; detects sessions left open |
| Special Logon `…921B` | Success | 4672 | Marks administrative tokens — attacker privilege level |
| Other Logon/Logoff `…921C` | Success + Failure | 4648, 4649, 4778, 4779, 5632, 5633 | Explicit-credential pivots, RDP reconnects, replay attacks, wireless auth |
| Account Lockout `…9217` | Failure | 4740 (+4625 substatus) | Lockout source machine pinpoints where the attack lands |
| Credential Validation `…923F` | Success + Failure | 4776 | NTLM authentication (VPN, IIS, shares) — often the only signal on non-domain paths |
| Kerberos Authentication Service `…9242` | Success + Failure | 4768, 4771 | Domain-level brute force with client IP (DC logs) |
| Kerberos Service Ticket Ops `…9240` | Success + Failure | 4769, 4770 | Kerberoasting indicators (RC4 ticket encryption) |
| User Account Management `…9235` | Success | 4720–4726, 4738, 4794 | Attacker-created/backdoored accounts |
| Security Group Management `…9237` | Success | 4728, 4732, 4756 | Privilege escalation into Administrators/RDP Users |
| Audit Policy Change `…922F` | Success + Failure | 4719, 4715, 4907 | Detects the attacker blinding you mid-incident |
| Authentication Policy Change `…9230` | Success | 4713, 4739 | Kerberos/domain trust tampering |
| Authorization Policy Change `…9231` | Success | 4704, 4705 | User-right grants (SeRemoteInteractiveLogonRight etc.) |
| Process Creation `…922B` | Success | 4688 | Command lines contain IPs (net use, PsExec, WinRM); enable *and* configure "Include command line in process creation events" GPO |
| Sensitive Privilege Use `…9228` | Success + Failure | 4672–4674 | Privileged operations during a session |
| File Share `…9244` | Failure (Success optional — noisy) | 5140, 5145 | SMB lateral movement with source IP |

Not controlled by subcategories but worth knowing:

- **1102 (audit log cleared)** — always recorded; WinSecHunter flags it Critical (T1070.001).
- **System log 7045 (service installed)** — always on; catches PsExec-style remote services.
- **RDP operational logs** (RCM 1149/1148, LSM 21–25) — enabled by default since
  Windows 8/2012; if missing, the channel was disabled via WEVTUTIL/GPO.
- **Windows Firewall operational log** — disabled by default; enable:
  `netsh advfirewall set allprofiles logging enable` (or the Firewall log channel).
- **Sysmon** — separate deployment (Sysinternals); WinSecHunter auto-uses it when present
  and reports `Skipped` (not an error) when absent.
- **Firewall connection auditing (5156/5157)** — via `auditpol /set /subcategory:"Filtering Platform Connection"`;
  very high volume — enable targeted, not fleet-wide.

## 3. Baseline for IP-incident readiness

Apply on servers/workstations via GPO (Computer Configuration → Windows Settings →
Security Settings → Advanced Audit Policy Configuration), or per host:

```bat
:: Authentication core (the minimum WinSecHunter needs)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable

:: Domain controllers additionally
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable

:: Post-exploitation visibility
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

Then verify: `Test-WinSecAuditPolicy -IncludeCompliant`.

## 4. Log sizing & retention

Audit success is worthless if the log wraps in 4 hours:

```powershell
Get-WinSecLogCoverage -CoveringFrom (Get-Date).AddDays(-14)
```

- Security log ≥ 1–4 GB on busy servers (default 20 MB wraps fast under attack load).
- Consider `RetentionSetting = Retain:Ndays` (archive when full) for critical tiers.
- Forward to a collector (WEC/SIEM) — WinSecHunter complements, not replaces, retention.

## 5. Remote collection prerequisites

WinRM-based sweeps need, on each target:

```powershell
Enable-PSRemoting -Force            # one-time, elevated
# Firewall: 'Windows Remote Management (HTTP-In)' rule enabled.
# Cross-domain/workgroup: Kerberos realm trust or -Authentication Negotiate/CredSSP
# (CredSSP only with full awareness of its delegation risks).
```

The querying identity needs *SeSecurityPrivilege* ("Manage auditing and security
log") or membership in local Administrators on the target for the Security log.
WinSecHunter reports `Failed` with the precise WinRM/authorization error per host —
no silent holes in your sweep.

## Localized Windows and parsing (2.1.0)

`auditpol /get /subcategory:* /r` produces a CSV whose header is **localized**. WinSecHunter
parses the report by column position (machine, policy target, subcategory, subcategory GUID,
inclusion setting, exclusion setting), so non-English Windows builds are supported. An empty
result almost always means the session is not elevated, not that the policy is missing.

Per-host failures (elevation, connectivity) are reported as warnings with the host name; one
unreachable host does not stop the analysis of the others.
