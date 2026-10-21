#Requires -Version 7.6
# ---------------------------------------------------------------------------
# WinSecHunter — Enumerations
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# ---------------------------------------------------------------------------

<#
    Event categories used to classify Windows security-relevant events.
    Categories drive profile expansion (Get-WinSecEventIdsByProfile) and
    report grouping. Values are intentionally MITRE ATT&CK-tactic aligned.
#>
enum WinSecEventCategory {
    Unknown            = 0
    Authentication     # 4624/4625/4648/4776 logon & credential validation
    Kerberos           # 4768/4769/4770/4771/5168/4649
    RemoteAccess       # RDP (4778/4779, RCM/LSM operational logs), VPN, wireless
    LogonLogoff        # 4634/4647/4800/4801/4802
    AccountLockout     # 4740/4767
    AccountManagement  # 4720-4739/4794 user & group lifecycle
    SpecialPrivilege   # 4672/4673/4674 sensitive privilege use
    LateralMovement    # remote session artifacts pointing at other systems
    ShareAccess        # 5140-5145 SMB share access
    ObjectAccess       # 4656/4663/4670 file/registry object access
    DirectoryAccess    # 5136-5141 AD DS changes
    Firewall           # WFP filtering & Windows Firewall rule lifecycle
    PolicyChange       # 4704/4705/4715/4719/4902/4950 audit & firewall policy
    DefenseEvasion     # 1102/104 log clearing, 4710/4907 auditing tampering
    Persistence        # 4698 tasks, service installs, autostart
    ServiceActivity    # 7045/4697/7034/7031/7040 service lifecycle
    ScheduledTask      # 4698-4702, TaskScheduler operational
    ProcessExecution   # 4688, Sysmon EID 1
    NetworkActivity    # firewall connections, Sysmon EID 3
    CredentialAccess   # 4800/5058/5376/5378, Sysmon EID 10
    SystemIntegrity    # boot/shutdown/time-change/log-cleared
}

<#
    Windows logon types as documented for event 4624/4625.
    Numeric values mirror the LogonType field in the events.
#>
enum WinSecLogonType : int {
    Unknown              = 0
    Interactive          = 2   # physical console logon
    Network              = 3   # SMB, remote registry, IIS, etc. (hash-based)
    Batch                = 4   # scheduled task
    Service              = 5   # service control manager
    Proxy                = 6   # IIS impersonation (rare)
    Unlock               = 7   # workstation unlock
    NetworkCleartext   = 8   # network logon with plaintext credentials (IIS)
    NewCredentials       = 9   # runas /netonly, CloneToken
    RemoteInteractive    = 10  # RDP / Terminal Services
    CachedInteractive    = 11  # cached domain credentials
    CachedRemoteInteractive = 12
    CachedUnlock         = 13
}

# Result of the operation the event describes.
enum WinSecOutcome {
    Unknown        = 0
    Success
    Failure
    Informational
}

# Verdict produced by Test-WinSecBruteForce and investigation summaries.
enum WinSecVerdict {
    None                   = 0   # no attack pattern detected
    BruteForce                   # many failures against one account from one source
    PasswordSpraying             # few failures against many accounts from one source
    CredentialStuffing           # many account+source combinations, low per-pair count
    BruteForceWithSuccess        # failures followed by success — assume compromise
    LockoutStorm                 # repeated lockouts (4740) across hosts/accounts
    SuspiciousVolume             # high volume, pattern below explicit thresholds
}

# Severity scale shared by findings, audit gaps and catalog entries.
enum WinSecSeverity {
    Informational = 0
    Low
    Medium
    High
    Critical
}

# Formats supported by Export-WinSecInvestigation.
enum WinSecExportFormat {
    Csv      = 0
    Json
    Html
    Markdown
    CliXml
    All
}

# Network direction (firewall & Sysmon network events).
enum WinSecDirection {
    Unknown  = 0
    Inbound
    Outbound
}

# Per-host execution status for multi-computer queries.
enum WinSecHostStatus {
    Completed = 0   # query executed, events may or may not exist
    NoEvents        # query executed, zero matches
    Failed          # transport/log error
    Skipped         # not attempted (e.g. platform guard)
}

