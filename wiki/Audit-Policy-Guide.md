# 📜 Audit Policy Guide

WinSecHunter can only find what Windows actually recorded. This page maps the
event catalog to **Advanced Audit Policy** subcategories, documents the built-in
gap analyzer, and gives a readiness baseline.

[← Home](Home)

---

## 1 · Check current state (60 seconds)

```powershell
# Gaps that matter for a brute-force + RDP investigation, local host:
Test-WinSecAuditPolicy -Profile BruteForce, Rdp

# Fleet-wide (parallel over WinRM):
Test-WinSecAuditPolicy -ComputerName (Get-Content servers.txt) -Credential $cred

# Compliant rows too (audit trail / evidence of diligence):
Test-WinSecAuditPolicy -IncludeCompliant | Format-Table Computer, Subcategory, CurrentSetting, Severity
```

Each gap carries a ready-to-run fix:

```text
Subcategory    : Logon
CurrentSetting : Success
RequiredSetting: Success and Failure
Severity       : Critical
AffectedEventIds: 4624, 4625
Recommendation : Events 4624,4625 are NOT audited (Failure missing). Fix:
                 auditpol /set /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable
```

> [!NOTE]
> Matching is **by subcategory GUID**, not display name — the analyzer works on
> non-English systems where `auditpol` localizes names.

## 2 · Requirement matrix

What WinSecHunter's hunt profiles need, and why:

| Subcategory (GUID suffix) | Recommended | Enables | Why it matters for IP hunts |
|---|---|---|---|
| Logon `…9215` | Success + Failure | 4624, 4625 | the core signal: every logon + every failure with source IP and decoded SubStatus |
| Logoff `…9216` | Success | 4634, 4647 | session durations; abandoned sessions |
| Special Logon `…921B` | Success | 4672 | administrative token marker per session |
| Other Logon/Logoff `…921C` | Success + Failure | 4648, 4649, 4778, 4779, 5632/5633 | explicit-credential pivots, RDP reconnects, replay, wireless auth |
| Account Lockout `…9217` | Failure | 4740 (+4625 substatus) | lockout **names the trigger host** — pivot gold |
| Credential Validation `…923F` | Success + Failure | 4776 | NTLM (VPN, IIS, shares) — often the *only* signal off the domain path |
| Kerberos Auth Service `…9242` | Success + Failure | 4768, 4771 | domain-level brute force with client IP (DCs) |
| Kerberos Service Ticket `…9240` | Success + Failure | 4769, 4770 | kerberoasting indicators (RC4 ticket encryption) |
| User Account Mgmt `…9235` | Success | 4720–4726, 4738, 4794 | attacker-created/backdoored accounts |
| Security Group Mgmt `…9237` | Success | 4728, 4732, 4756 | elevation into Administrators / Remote Desktop Users |
| Audit Policy Change `…922F` | Success + Failure | 4719, 4715, 4907 | attacker blinding you mid-incident |
| Authentication Policy Change `…9230` | Success | 4713, 4739 | Kerberos/trust tampering |
| Authorization Policy Change `…9231` | Success | 4704, 4705 | user-right grants (e.g. `SeRemoteInteractiveLogonRight`) |
| Process Creation `…922B` | Success | 4688 | IPs inside command lines (`net use \\IP\share`, PsExec, WinRM); also enable the *"Include command line in process creation events"* GPO |
| Sensitive Privilege Use `…9228` | Success + Failure | 4672–4674 | privileged operations during a session |
| File Share `…9244` | Failure (Success noisy) | 5140, 5145 | SMB lateral movement with source IP |

### Not subcategory-controlled (but WinSecHunter watches them)

| Source | Events | Notes |
|---|---|---|
| Always recorded | **1102** audit log cleared · **104** (System) log cleared | flagged Critical, T1070.001 |
| Service Control Manager (System log) | **7045** service installed | always on; catches PsExec-style remote services |
| RDP operational logs (RCM/LSM) | 1149/1148, 21–25 | enabled by default since Win8/2012; if absent → someone disabled the channels (investigate that) |
| Firewall operational log | 2004–2006 rule changes | channel logging off by default: `netsh advfirewall set allprofiles logging enable` |
| WFP connection auditing | 5156/5157 | `auditpol /set /subcategory:"Filtering Platform Connection"` — **very** high volume; enable targeted |
| Sysmon | EID 1/3/8/10/13/16… | separate Sysinternals deployment; WinSecHunter auto-uses it, reports `Skipped` when absent |

## 3 · Readiness baseline (copy-paste)

Servers & workstations:

```bat
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
```

Domain controllers additionally:

```bat
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
```

Prefer GPO? *Computer Configuration → Windows Settings → Security Settings →
Advanced Audit Policy Configuration* — same subcategories, enforced fleet-wide.
Then verify everywhere: `Test-WinSecAuditPolicy -ComputerName $fleet -IncludeCompliant`.

## 4 · Log sizing & retention

Auditing is worthless if the log wraps mid-incident:

```powershell
Get-WinSecLogCoverage -CoveringFrom (Get-Date).AddDays(-14) |
    Where-Object Risk -in 'Medium','High','Critical' |
    Format-Table Computer, LogName, UsedPercent, OldestRecordUtc, Risk, Warning
```

- Default Security log = **20 MB** — an RDP brute-force storm evicts a day of
  history in hours. Size critical tiers at **1–4 GB**.
- `wevtutil sl Security /ms:4294967296` or GPO *Maximum Log Size*.
- Consider retention mode `Retain` (archive when full) on crown-jewel hosts.
- Forward to WEC/SIEM for long-horizon storage — WinSecHunter complements
  retention, it doesn't replace it.

## 5 · Remote collection prerequisites

Sweeps need WinRM + rights on targets (full detail:
[Remote Collection](Remote-Collection#winrm-prerequisites)):

```powershell
Enable-PSRemoting -Force                        # one-time on each target
# dedicated IR service account → local Administrators or SeSecurityPrivilege
```

`Test-WinSecAuditPolicy` itself runs over the same transport and reports
per-host errors (elevation, connectivity) instead of failing silently.

---

## Localized Windows (2.1.0)

`auditpol /get /subcategory:* /r` writes a CSV whose **header is localized**. Since 2.1.0 the
output is parsed by column position — machine, policy target, subcategory, subcategory GUID,
inclusion setting, exclusion setting — so Russian, German or any other Windows display
language no longer breaks the analysis.

`auditpol` still requires an elevated session; without it the cmdlet reports the policy as
unavailable instead of throwing.

**Next:** [Configuration →](Configuration) · Related: [Problem Domain — evidence doctrine](Problem-Domain#the-evidence-doctrine)
