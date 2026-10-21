# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 2.1.x | Yes — security fixes are shipped in patch releases |
| 2.0.x | No — upgrade to 2.1.x |
| 1.x / legacy script | No |

## Reporting a vulnerability

Do **not** open a public issue for a security problem.

Send a report to **security@deynekin.com** with:

- affected version (`Get-Module WinSecHunter | Select-Object Version`) and PowerShell version;
- a minimal reproduction (command line, input data shape, expected vs actual behaviour);
- impact assessment: what an attacker gains, what preconditions are required;
- whether the issue is in collection, parsing, reporting or evidence handling.

You will receive an acknowledgement within 5 business days. Please allow a coordinated
disclosure window before publishing details.

## Security model

WinSecHunter is an incident-response tool that runs with the privileges of the operator.
It is designed to minimise its own attack surface:

- **Read-only by default.** Collection uses `Get-WinEvent`; no event log is modified.
  `Trace-WinSecIp` polls and bookmarks by record id — it never writes to a channel.
- **No telemetry, no phone-home.** The only outbound requests are the threat-intelligence
  providers you explicitly enable (`-Provider AbuseIPDB|OTX|IpApi`) and reverse DNS.
- **Secrets stay in the environment.** API keys are read from environment variables named
  by configuration (`ABUSEIPDB_KEY`, `OTX_API_KEY`); they are never accepted as parameters,
  never written to configuration, reports, HTML, manifests or logs.
- **Evidence integrity.** Bundles carry a SHA-256 manifest; verify with
  `Test-WinSecEvidenceIntegrity` before sharing. Reports never rewrite bundle artifacts.
- **Conservative handling of personal data.** `New-WinSecAbuseReport` supports
  `-RedactAccounts`, which pseudonymises account names consistently (including inside the
  attached CSV/JSON evidence), so a report can leave the organisation without exposing
  user identities.
- **No dynamic code execution from data.** Event XML is parsed as XML; XPath is built from
  validated IP addresses and catalog data, never from free-form operator input.

## Operational guidance

- Run collection from a dedicated administrative workstation or jump host.
- Keep evidence bundles on write-once or read-only media after export.
- Treat generated reports as confidential: they contain internal host names, account names
  and authentication telemetry.
- Remote collection over WinRM transmits event XML; use HTTPS transport
  (`-SessionOption (New-PSSessionOption -UseSSL)`) or CredSSP only where policy allows.

## Out of scope

- Vulnerabilities in Windows event logging itself.
- Social-engineering of the operator.
- Denial of service caused by querying exceptionally large logs without `-MaxEvents`.
