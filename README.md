# Windows Security Event Analyzer

**PowerShell script for deep forensic analysis of Windows Security logs by source IP address with full IPv4/IPv6 support, status code decoding, and customizable output.**

---

## 1. Overview

`Get-SecurityEventsByIP.ps1` is a professional-grade PowerShell tool designed for system administrators, security analysts, and IT professionals to investigate authentication activities tied to specific IP addresses in Windows Security event logs. The script enables rapid identification of logon attempts (successful or failed), file access events, and other security-relevant activities originating from a given IPv4 or IPv6 address.

Built with strict error handling, administrator privilege enforcement, and extensible output formatting, this utility supports forensic investigations, intrusion detection validation, and routine security audits.

---

## 2. Key Features

- 🔍 **IP-Based Event Filtering**: Query Security logs for any IPv4 or IPv6 address.
- 📊 **Multiple Event Categories**:
  - **RDP**: Remote Desktop logons (`LogonType = 10`)
  - **FileShare**: Network file/printer access (`LogonType = 3`)
  - **Authentication**: General network logon events (`LogonType = 3`)
  - **AllEvents**: Every Security event containing the IP
- 🧠 **Automatic Status Code Decoding**:
  - Translates Windows NTSTATUS codes (e.g., `0xc000006a`) and Failure Reason tokens (e.g., `%%2313`) into human-readable messages.
  - Toggle decoding on/off via `-Decode Yes|No`.
- 🎛️ **Customizable Output Columns**:
  - Use `-ShowColumns` to display only selected fields.
  - Use `-HideColumns` to suppress technical details (e.g., `Status`, `SubStatus`).
  - `Result` column is always placed last for readability.
- 📁 **Structured Export**:
  - Saves results to a UTF-8 text file with auto-generated statistics (event counts, top accounts, IP distribution).
  - Creates output directory if missing.
- 🛡️ **Robust Execution**:
  - Requires administrator privileges (enforced via `#Requires -RunAsAdministrator`).
  - Validates IP format using .NET `IPAddress.TryParse()`.
  - Handles empty results gracefully.
- 🌐 **Full IPv6 Support**:
  - Accepts any valid IPv6 format (e.g., `::1`, `2001:db8::1`, `::ffff:192.168.1.1`).
  - Normalizes IP representation for consistency.

---

## 3. Requirements

- **Windows**: 7 / 8 / 10 / 11 or Windows Server 2008 R2+
- **PowerShell**: Version 5.1 or higher
- **Permissions**: Must be run **as Administrator** (to read Security log)
- **Event Log**: Windows Security log must be enabled and populated

---

## 4. Installation

1. Download the script:
   ```powershell
   Invoke-WebRequest -Uri "https://yourdomain.com/Get-SecurityEventsByIP.ps1" -OutFile "Get-SecurityEventsByIP.ps1"
   ```
   *(Replace with actual URL or clone the repository.)*

2. Unblock the file (if downloaded from the internet):
   ```powershell
   Unblock-File .\Get-SecurityEventsByIP.ps1
   ```

3. Ensure script execution is allowed:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

---

## 5. Usage

### Basic Syntax
```powershell
.\Get-SecurityEventsByIP.ps1 -IpAddress <IPv4_or_IPv6> [-Category <RDP|FileShare|Authentication|AllEvents>] [-OutputPath <Path>] [-MaxEvents <Int>] [-Decode <Yes|No>] [-ShowColumns <String[]>] [-HideColumns <String[]>]
```

### Examples

#### Analyze all RDP logon attempts from an IPv6 address:
```powershell
.\Get-SecurityEventsByIP.ps1 -IpAddress "2001:db8::100" -Category RDP
```

#### Investigate file share access without decoding status codes:
```powershell
.\Get-SecurityEventsByIP.ps1 -IpAddress "192.168.1.50" -Category FileShare -Decode No
```

#### Generate a concise report showing only essential columns:
```powershell
.\Get-SecurityEventsByIP.ps1 -IpAddress "::ffff:10.0.0.25" -ShowColumns TimeCreated,Account,SourceIP,Result
```

#### Hide technical fields for executive summary:
```powershell
.\Get-SecurityEventsByIP.ps1 -IpAddress "89.108.109.173" -HideColumns Status,SubStatus,Message,LogonProcess
```

---

## 6. Parameters

| Parameter       | Type          | Default                     | Description |
|-----------------|---------------|-----------------------------|-------------|
| `-IpAddress`    | `string`      | *(Required)*                | Source IPv4 or IPv6 address to search for. |
| `-Category`     | `string`      | `RDP`                       | Event category: `RDP`, `FileShare`, `Authentication`, or `AllEvents`. |
| `-OutputPath`   | `string`      | `C:\security_events_by_ip.txt` | Path to output file. Directory will be created if missing. |
| `-MaxEvents`    | `int`         | `1000`                      | Maximum number of events to retrieve (1–100,000). |
| `-Decode`       | `string`      | `Yes`                       | Decode status/failure codes? (`Yes` = human-readable, `No` = raw codes). |
| `-ShowColumns`  | `string[]`    | *(All except Workstation)*  | Explicit list of columns to display. Takes precedence over `-HideColumns`. |
| `-HideColumns`  | `string[]`    | —                           | List of columns to exclude from output. Ignored if `-ShowColumns` is used. |

> **Available Column Names**:  
> `TimeCreated`, `EventId`, `Account`, `SourceIP`, `Port`, `LogonType`, `AuthPackage`, `LogonProcess`, `Status`, `SubStatus`, `Message`, `Result`

> **Note**: The `Workstation` column is permanently excluded per design.

---

## 7. Output Format

The script generates a `.txt` report containing:

1. **Formatted Event Table** (sorted newest-first) with selected columns.
2. **Processing Summary** including:
   - Total event count and time range
   - EventID distribution
   - Source IP frequency
   - Logon type breakdown
   - Top 10 accounts involved

Example snippet:
```
TimeCreated           EventId Account        SourceIP        Port LogonType                 AuthPackage Result
-----------           ------- -------        --------        ---- ---------                 ----------- ------
10/20/2025 2:30:15 PM    4625 DOMAIN\user1  192.168.1.100   54321 RemoteInteractive/RDP (10) Negotiate   Logon failed: Incorrect password

========================================
PROCESSING SUMMARY
========================================
Total events: 42
Period: 10/19/2025 9:12:03 AM - 10/20/2025 2:30:15 PM

EventID distribution:
Name Count
---- -----
4625    38
4624     4
...
```

---

## 8. Exit Codes

- `0`: Success (events processed or empty result handled)
- `1`: Critical error (e.g., access denied, invalid parameters, export failure)

---

## 9. Author & License

- **Author**: Mikhail Deynekin  
- **Email**: mid1977@gmail.com  
- **Website**: https://deynekin.com  
- **License**: MIT  

---

## 10. Disclaimer

This tool is intended for **authorized security and system administration purposes only**. Misuse may violate organizational policies or local laws. Always ensure you have proper authorization before analyzing system logs.
