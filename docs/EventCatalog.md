# Event Catalog Reference

> Generated from `Resources/EventCatalog.json` (catalog v2.1.0, 156 events) by `build/Export-CatalogDoc.ps1`. Do not edit manually.
>
> **IP fields** lists the event data fields that natively carry IP addresses.
> Events without IP fields still participate in sweeps as *contextual evidence*.

## Supported channels

| Channel | Events |
|---|---|
| `Microsoft-Windows-Sysmon/Operational` | 12 |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | 5 |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | 3 |
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | 3 |
| `Security` | 124 |
| `System` | 9 |

## Hunt profiles

| Profile | Description |
|---|---|
| `AccountManagement` | User/group lifecycle and lockouts — attacker post-exploitation actions. |
| `All` | Every cataloged event across all supported logs. |
| `BruteForce` | Failures + successes + lockouts needed for brute-force/spray correlation and success-after-failure detection. |
| `Critical` | Only events the catalog marks Critical. |
| `DefenseEvasion` | Anti-forensics and security-control tampering: log clearing, audit policy changes, firewall/service shutdown, Sysmon config changes. |
| `FailedAuth` | Only failed authentication events (classic brute-force sweep, superset of the legacy script behavior). |
| `Firewall` | Windows Firewall/WFP: rule lifecycle, service health and connection permit/block (5152-level noise excluded by default). |
| `IncidentResponse` | DEFAULT. Balanced IP-incident sweep: authentication, Kerberos, remote access, account lifecycle, credential access, persistence and anti-forensics. Excludes high-noise object/firewall/connection logs. |
| `Kerberos` | Kerberos authentication chain (AS/TGS/pre-auth failures, replay, SPN issues). |
| `Lateral` | Lateral movement indicators: network logons, explicit-credential logons, share access, remote service/task installation. |
| `ObjectAccess` | File/share/registry/DS object access (high noise — enable when you have object SACLs). |
| `Persistence` | Persistence installation: services, scheduled tasks, autostart artifacts. |
| `Rdp` | RDP/remote interactive access chain: RCM + LSM operational logs plus Security logon events. |
| `Sysmon` | Sysmon coverage for IP hunting: network connections (EID 3), process creation, remote threads, credential access, config changes. |

## Microsoft-Windows-Sysmon/Operational

| ID | Name | Category | Importance | ATT&CK | IP fields | Notes |
|---|---|---|---|---|---|---|
| 1 | Sysmon: process creation | ProcessExecution | High | T1059, T1204 |  | CommandLine often contains attacker IPs during lateral movement. |
| 3 | Sysmon: network connection detected | NetworkActivity | Critical | T1021, T1071, T1571 | SourceIp, DestinationIp | The richest IP-hunting source when Sysmon is deployed: process ↔ IP with direction. |
| 8 | Sysmon: CreateRemoteThread detected | LateralMovement | High | T1055 |  |  |
| 9 | Sysmon: RawAccessRead detected | CredentialAccess | Medium | T1006 |  |  |
| 10 | Sysmon: ProcessAccess detected | CredentialAccess | Medium | T1003.001 |  |  |
| 11 | Sysmon: FileCreate detected | Persistence | Medium | T1105 |  |  |
| 13 | Sysmon: RegistryValueSet detected | DefenseEvasion | Medium | T1112, T1547.001 |  |  |
| 15 | Sysmon: FileCreateStreamHash detected | DefenseEvasion | Medium | T1105, T1564.004 |  |  |
| 16 | Sysmon: configuration state changed | DefenseEvasion | Critical | T1562.001 |  | Attackers reconfigure/disable Sysmon to blind EDR-adjacent telemetry. |
| 22 | Sysmon: DNS query detected | NetworkActivity | Low | T1071.004 |  | QueryName rarely equals an IP; useful for C2 domain resolution context. |
| 23 | Sysmon: FileDelete archived | DefenseEvasion | Medium | T1070.004 |  |  |
| 25 | Sysmon: ProcessTampering detected | DefenseEvasion | High | T1055.013 |  |  |

## Microsoft-Windows-TerminalServices-LocalSessionManager/Operational

| ID | Name | Category | Importance | ATT&CK | IP fields | Notes |
|---|---|---|---|---|---|---|
| 21 | Remote Desktop Services: session logon succeeded | RemoteAccess | High | T1021.001 | Address | UserData/EventXML/Address contains source IP. |
| 22 | Remote Desktop Services: shell start notification received | RemoteAccess | Medium | T1021.001 | Address |  |
| 23 | Remote Desktop Services: session logoff succeeded | RemoteAccess | Medium |  | Address |  |
| 24 | Remote Desktop Services: session has been disconnected | RemoteAccess | Medium |  | Address |  |
| 25 | Remote Desktop Services: session reconnection succeeded | RemoteAccess | High | T1021.001 | Address |  |

## Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational

| ID | Name | Category | Importance | ATT&CK | IP fields | Notes |
|---|---|---|---|---|---|---|
| 1147 | Connection failure (transport-level error) | RemoteAccess | Medium | T1021.001 | Address | IP lives in UserData/EventXML. |
| 1148 | RDP user authentication failed | RemoteAccess | High | T1110, T1021.001 | Address | IP lives in UserData/EventXML/Address. Pre-NLA failures. |
| 1149 | RDP user authentication succeeded (network level) | RemoteAccess | Critical | T1021.001, T1078 | Address | IP lives in UserData/EventXML/Address; fires BEFORE 4624 type 10. |

## Microsoft-Windows-Windows Firewall With Advanced Security/Firewall

| ID | Name | Category | Importance | ATT&CK | IP fields | Notes |
|---|---|---|---|---|---|---|
| 2004 | A rule has been added to the Windows Defender Firewall exception list | Firewall | High | T1562.004 |  |  |
| 2005 | A rule has been modified in the Windows Defender Firewall exception list | Firewall | Medium | T1562.004 |  |  |
| 2006 | A rule has been deleted from the Windows Defender Firewall exception list | Firewall | Medium | T1562.004 |  |  |

## Security

| ID | Name | Category | Importance | ATT&CK | IP fields | Notes |
|---|---|---|---|---|---|---|
| 1100 | The event logging service has shut down | SystemIntegrity | Medium | T1562.002 |  |  |
| 1102 | The audit log was cleared | SystemIntegrity | Critical | T1070.001 |  | Anti-forensics. The SubjectAccount + ClientDomainName of the clearer matter. |
| 1104 | The security log is now full | SystemIntegrity | Medium |  |  |  |
| 1105 | Event log automatic backup | SystemIntegrity | Low |  |  |  |
| 1108 | The event logging service encountered an error while processing an incoming event | SystemIntegrity | High | T1562 |  |  |
| 4608 | Windows is starting up | SystemIntegrity | Medium |  |  |  |
| 4609 | Windows is shutting down | SystemIntegrity | Low |  |  |  |
| 4611 | A trusted logon process has been registered with the LSA | LogonLogoff | Low |  |  |  |
| 4612 | Internal resources allocated for the queuing of audit messages have been exhausted (events dropped) | SystemIntegrity | High | T1562.002 |  |  |
| 4616 | The system time was changed | SystemIntegrity | High | T1070.006 |  | Time changes break timeline correlation — flag in reports. |
| 4624 | An account was successfully logged on | Authentication | Critical | T1078, T1078.002, T1078.003, T1021 | IpAddress | Check LogonType: 2/10 interactive, 3 network (SMB), 9 runas /netonly. Success after failures = compromise indicator. |
| 4625 | An account failed to log on | Authentication | Critical | T1110.001, T1110.003, T1078 | IpAddress | Primary brute-force indicator. Decode SubStatus: 0xC000006A bad password, 0xC0000064 unknown user, 0xC0000234 locked out. |
| 4634 | An account was logged off | LogonLogoff | Low |  |  | Closes sessions started by 4624 (same LogonId). |
| 4647 | User initiated logoff | LogonLogoff | Low |  |  |  |
| 4648 | A logon was attempted using explicit credentials | LateralMovement | High | T1078, T1550.002 | IpAddress | runas /creds, RDP delegation. AuthPackage NTLM here can indicate pass-the-hash. TargetServerName shows the pivot destination. |
| 4649 | A replay attack was detected | Kerberos | High | T1558 |  |  |
| 4656 | A handle to an object was requested | ObjectAccess | Low | T1005 |  | Requires object SACLs. ObjectName may embed a UNC path with the attacker IP. |
| 4662 | An operation was performed on an object (directory service) | DirectoryAccess | Low | T1003.003 |  |  |
| 4663 | An attempt was made to access an object | ObjectAccess | Medium | T1005 |  |  |
| 4672 | Special privileges assigned to new logon | SpecialPrivilege | Medium | T1078.002 |  | Administrative logon marker — pair with 4624 by LogonId. |
| 4673 | A privileged service was called | SpecialPrivilege | Low |  |  |  |
| 4674 | An operation was attempted on a privileged object | SpecialPrivilege | Medium | T1078.002 |  |  |
| 4688 | A new process has been created | ProcessExecution | High | T1059, T1204 |  | Needs 'Audit Process Creation' + command-line auditing. CommandLine may contain attacker IPs (net use, PsExec, WinRM). |
| 4697 | A service was installed in the system | Persistence | High | T1543.003 |  | Service binary path may point at \\attacker-ip\share. |
| 4698 | A scheduled task was created | Persistence | High | T1053.005 |  | TaskContent XML often embeds remote paths/IPs. |
| 4699 | A scheduled task was deleted | DefenseEvasion | Medium | T1053.005 |  |  |
| 4700 | A scheduled task was enabled | ScheduledTask | Medium | T1053.005 |  |  |
| 4701 | A scheduled task was disabled | ScheduledTask | Medium |  |  |  |
| 4702 | A scheduled task was updated | ScheduledTask | Low |  |  |  |
| 4704 | A user right was assigned | PolicyChange | Medium | T1098 |  |  |
| 4705 | A user right was removed | PolicyChange | Medium |  |  |  |
| 4710 | The Windows Event Log service was shut down | DefenseEvasion | High | T1562.002 |  |  |
| 4713 | Kerberos policy was changed | PolicyChange | Medium | T1558 |  |  |
| 4715 | The audit policy (SACL) on an object was changed | DefenseEvasion | High | T1562.002 |  |  |
| 4719 | System audit policy was changed | DefenseEvasion | Critical | T1562.002 |  | Attacker disabling auditing mid-incident — always investigate. |
| 4720 | A user account was created | AccountManagement | Critical | T1136, T1136.001, T1136.002 |  |  |
| 4722 | A user account was enabled | AccountManagement | Medium | T1098 |  |  |
| 4723 | An attempt was made to change an account's password | AccountManagement | Medium | T1098 |  |  |
| 4724 | An attempt was made to reset an account's password | AccountManagement | High | T1098 |  |  |
| 4725 | A user account was disabled | AccountManagement | Medium |  |  |  |
| 4726 | A user account was deleted | AccountManagement | High | T1531 |  |  |
| 4728 | A member was added to a security-enabled global group | AccountManagement | High | T1098, T1078.002 |  |  |
| 4729 | A member was removed from a security-enabled global group | AccountManagement | Low |  |  |  |
| 4732 | A member was added to a security-enabled local group | AccountManagement | High | T1098, T1078.003 |  | Watch for additions to local Administrators / Remote Desktop Users. |
| 4733 | A member was removed from a security-enabled local group | AccountManagement | Low |  |  |  |
| 4735 | A security-enabled local group was changed | AccountManagement | Low |  |  |  |
| 4737 | A security-enabled global group was changed | AccountManagement | Low |  |  |  |
| 4738 | A user account was changed | AccountManagement | High | T1098 |  | PasswordNotRequired/UfTrustedForDelegation flag changes are attacker tradecraft. |
| 4739 | Domain policy was changed | PolicyChange | Medium | T1484.001 |  |  |
| 4740 | A user account was locked out | AccountLockout | High | T1110 |  | SubjectComputerName shows WHERE the lockout was triggered — pivot there. |
| 4741 | A computer account was created | AccountManagement | Low | T1136.002 |  |  |
| 4742 | A computer account was changed | AccountManagement | Low |  |  |  |
| 4743 | A computer account was deleted | AccountManagement | Medium |  |  |  |
| 4754 | A security-enabled universal group was created | AccountManagement | Medium | T1098 |  |  |
| 4756 | A member was added to a security-enabled universal group | AccountManagement | High | T1098 |  |  |
| 4764 | A group's type was changed | AccountManagement | Low |  |  |  |
| 4765 | SID history was added to an account | AccountManagement | Low | T1134.005 |  |  |
| 4766 | An attempt to add SID history to an account failed | AccountManagement | Medium | T1134.005 |  |  |
| 4767 | A user account was unlocked | AccountLockout | Medium |  |  |  |
| 4768 | A Kerberos authentication service (TGT) request was made | Kerberos | Critical | T1558 | IpAddress | DC only. TicketEncryptionType 0x17 (RC4) on modern networks = downgrade indicator. |
| 4769 | A Kerberos service ticket was requested | Kerberos | High | T1558.003 | IpAddress | RC4 encryption (0x17) for service tickets may indicate kerberoasting. |
| 4770 | A Kerberos service ticket was renewed | Kerberos | Medium | T1558 | IpAddress |  |
| 4771 | Kerberos pre-authentication failed | Kerberos | Critical | T1110, T1558 | IpAddress | Kerberos-level brute force. FailureCode 0x18 = wrong password, 0x17 = password expired, 0x12 = client revoked (disabled/locked). |
| 4776 | The computer attempted to validate the credentials for an account (NTLM) | Authentication | Critical | T1110, T1078 |  | No IP field — Workstation holds the client NAME. NTSTATUS in 'Error Code'. |
| 4778 | A session was reconnected to a Window Station | RemoteAccess | High | T1021.001 | IpAddress |  |
| 4779 | A session was disconnected from a Window Station | RemoteAccess | Medium | T1021.001 | IpAddress |  |
| 4794 | An attempt was made to set the Directory Services Restore Mode administrator password | AccountManagement | High | T1098 |  |  |
| 4800 | The workstation was locked | LogonLogoff | Low |  |  |  |
| 4801 | The workstation was unlocked | LogonLogoff | Low |  |  |  |
| 4802 | The screen saver was invoked | LogonLogoff | Low |  |  |  |
| 4803 | The screen saver was dismissed or an administrator console was started | LogonLogoff | Low |  |  |  |
| 4816 | RPC detected an integrity violation while decrypting an incoming message | SystemIntegrity | Medium |  |  |  |
| 4817 | Auditing settings on object were changed | DefenseEvasion | Medium | T1562.002 |  |  |
| 4902 | The Per-user audit policy table was created | PolicyChange | Low |  |  |  |
| 4907 | Auditing settings on object were changed | DefenseEvasion | Medium | T1562.002 |  |  |
| 4946 | Windows Firewall exception list: a rule was added | Firewall | High | T1562.004 |  |  |
| 4947 | Windows Firewall exception list: a rule was modified | Firewall | Medium | T1562.004 |  |  |
| 4948 | Windows Firewall exception list: a rule was deleted | Firewall | Medium | T1562.004 |  |  |
| 4950 | A Windows Firewall setting has changed | PolicyChange | High | T1562.004 |  |  |
| 4951 | A rule has been ignored because its major version number was not recognized | Firewall | Medium |  |  |  |
| 4952 | Parts of a rule have been ignored because its minor version number was not recognized | Firewall | Medium |  |  |  |
| 4953 | A rule has been ignored by Windows Firewall because it failed to parse the rule | Firewall | Medium | T1562.004 |  |  |
| 4954 | Windows Firewall Group Policy settings have changed | PolicyChange | Medium |  |  |  |
| 4956 | Windows Firewall has changed the active profile | Firewall | Medium |  |  |  |
| 4957 | Windows Firewall did not apply a rule | Firewall | Medium |  |  |  |
| 4958 | Windows Firewall did not apply a rule because it refers to items not configured on this computer | Firewall | Low |  |  |  |
| 5024 | The Windows Firewall service has started successfully | Firewall | Medium | T1562.004 |  |  |
| 5025 | The Windows Firewall service has been stopped | Firewall | High | T1562.004 |  |  |
| 5027 | The Windows Firewall service was unable to retrieve the security policy from the local storage | Firewall | High | T1562.004 |  |  |
| 5028 | The Windows Firewall service was unable to parse the new security policy | Firewall | High | T1562.004 |  |  |
| 5029 | The Windows Firewall service failed to initialize the driver | Firewall | High | T1562.004 |  |  |
| 5030 | The Windows Firewall service failed to start | Firewall | High | T1562.004 |  |  |
| 5031 | The Windows Firewall service blocked an application from accepting incoming connections | Firewall | Medium | T1562.004 |  |  |
| 5032 | Windows Firewall was unable to notify the user that it blocked an application | Firewall | High | T1562.004 |  |  |
| 5033 | The Windows Firewall Driver has started successfully | Firewall | Medium |  |  |  |
| 5034 | The Windows Firewall Driver has been stopped | Firewall | High | T1562.004 |  |  |
| 5035 | The Windows Firewall Driver failed to start | Firewall | High | T1562.004 |  |  |
| 5037 | The Windows Firewall Driver detected an unexpected runtime error and has terminated | Firewall | Critical | T1562.004 |  |  |
| 5038 | Code integrity determined that the image hash of a file is not valid | DefenseEvasion | Critical | T1562.001 |  |  |
| 5058 | Key cryptographic operation | CredentialAccess | High | T1003 |  |  |
| 5061 | Cryptographic operation | CredentialAccess | Medium | T1003 |  |  |
| 5136 | A directory service object was modified | DirectoryAccess | Low | T1098 |  |  |
| 5137 | A directory service object was created | DirectoryAccess | Low | T1136 |  |  |
| 5138 | A directory service object was undeleted | DirectoryAccess | Low |  |  |  |
| 5139 | A directory service object was moved | DirectoryAccess | Low |  |  |  |
| 5140 | A network share object was accessed | ShareAccess | Medium | T1021.002 | IpAddress | SMB lateral movement with source IP. |
| 5141 | A directory service object was deleted | DirectoryAccess | Low | T1485 |  |  |
| 5142 | A network share object was added | ShareAccess | High | T1021.002 |  |  |
| 5143 | A network share object was modified | ShareAccess | Medium |  |  |  |
| 5144 | A network share object was deleted | ShareAccess | Medium | T1021.002 |  |  |
| 5145 | A network share object was checked for client access rights | ShareAccess | Medium | T1021.002 | IpAddress | Detailed file-level share access; noisy but shows ShareName + relative paths. |
| 5152 | The Windows Filtering Platform blocked a packet | Firewall | Low |  | SourceAddress | Very high volume — excluded from all default profiles. |
| 5154 | The Windows Filtering Platform has permitted an application to listen for inbound connections | NetworkActivity | Low |  | SourceAddress |  |
| 5155 | The Windows Filtering Platform has blocked an application from listening for inbound connections | Firewall | Medium |  | SourceAddress |  |
| 5156 | The Windows Filtering Platform has permitted a connection | NetworkActivity | Medium | T1021 | SourceAddress, DestAddress | Requires WFP audit policy. High volume; Direction field gives Inbound/Outbound. |
| 5157 | The Windows Filtering Platform has blocked a connection | Firewall | Medium |  | SourceAddress, DestAddress | Blocked connection attempts from/to the attacker IP. |
| 5158 | The Windows Filtering Platform has permitted a bind of a local port | NetworkActivity | Low |  | SourceAddress |  |
| 5159 | The Windows Filtering Platform has blocked a bind of a local port | Firewall | Low |  | SourceAddress |  |
| 5168 | SPN check for SMB/SMB2 failed | Kerberos | Medium | T1558 |  |  |
| 5376 | Credential Manager credentials were backed up | CredentialAccess | High | T1003 |  |  |
| 5377 | Credential Manager credentials were restored | CredentialAccess | High | T1003 |  |  |
| 5632 | A request was made to authenticate to a wireless network | RemoteAccess | Medium | T1110 |  |  |
| 5633 | A request was made to authenticate to a wired network | RemoteAccess | Medium | T1110 |  |  |
| 5712 | A Remote Procedure Call (RPC) was attempted to run against the LSASS process | DefenseEvasion | High | T1210 |  | Associated with remote exploitation attempts against LSASS (e.g., Zerologon-class). |

## System

| ID | Name | Category | Importance | ATT&CK | IP fields | Notes |
|---|---|---|---|---|---|---|
| 104 | The log file was cleared | SystemIntegrity | Critical | T1070.001 |  | Logged in System when ANY log is cleared — cross-checks Security 1102. |
| 6005 | The Event log service was started | SystemIntegrity | Medium |  |  |  |
| 6006 | The Event log service was stopped | SystemIntegrity | Medium |  |  |  |
| 6008 | The previous system shutdown was unexpected | SystemIntegrity | High |  |  |  |
| 6013 | The system uptime | SystemIntegrity | Low |  |  |  |
| 7031 | The service terminated unexpectedly and corrective action was configured | ServiceActivity | Medium |  |  |  |
| 7034 | The service terminated unexpectedly | ServiceActivity | Medium |  |  |  |
| 7040 | The service start type was changed | ServiceActivity | Low | T1543.003 |  |  |
| 7045 | A service was installed in the system | ServiceActivity | High | T1543.003, T1021 |  | PsExec-style remote service installs land here (ImagePath may contain \\attacker-ip\). |

