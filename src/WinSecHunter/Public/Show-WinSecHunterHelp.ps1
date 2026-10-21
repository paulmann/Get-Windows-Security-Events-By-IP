#Requires -Version 7.6
#Requires -PSEdition Core
function Show-WinSecHunterHelp {
    <#
    .SYNOPSIS
        One-stop reference for the whole toolkit: workflow, cmdlets, profiles,
        configuration, requirements and troubleshooting — or the full help of a
        single cmdlet.

    .DESCRIPTION
        WinSecHunter ships 20 cmdlets, 14 hunt profiles and a 156-event catalog.
        Remembering the parameter surface is unnecessary: this cmdlet prints a
        task-oriented map (Collect → Analyze → Attribute → Report → Preserve)
        plus a per-cmdlet reference.

        With -Cmdlet it renders syntax, parameter table and examples for that
        cmdlet. With -Markdown it returns a documentation-ready Markdown
        document (used to generate docs/Command-Reference.md). With -OutFile the
        content is written atomically, so the same command can feed a runbook.

        Output is colourised on an interactive console and plain text when
        redirected or with -Plain, which keeps CI logs readable.

    .PARAMETER Cmdlet
        Cmdlet name to describe (for example Get-WinSecEventByIp). Wildcards are
        not supported; an unknown name lists every exported cmdlet.

    .PARAMETER Detailed
        Include parameter tables and examples for every cmdlet, not only the
        overview. Ignored with -Cmdlet (that output is always detailed).

    .PARAMETER Markdown
        Emit Markdown instead of console text. Combine with -OutFile to write a
        reference page, or with -PassThru to capture the string.

    .PARAMETER OutFile
        Write the rendered text to this path (UTF-8, no BOM, atomic replace).
        Parent directories are created. The path is returned.

    .PARAMETER Plain
        Disable ANSI colour even on an interactive console.

    .PARAMETER PassThru
        Return the rendered text as a string instead of writing it to the host.

    .EXAMPLE
        Show-WinSecHunterHelp

        Prints the workflow map, cmdlet catalogue, profiles and configuration
        locations.

    .EXAMPLE
        Show-WinSecHunterHelp -Cmdlet Get-WinSecEventByIp -Detailed

        Full syntax, parameters and examples for the collection cmdlet.

    .EXAMPLE
        Show-WinSecHunterHelp -Markdown -OutFile .\docs\Command-Reference.md

        Regenerates the command reference page from the live module metadata.

    .EXAMPLE
        Show-WinSecHunterHelp -Cmdlet New-WinSecAbuseReport | Out-String -Width 200

        Captures a plain-text reference for a ticket or runbook.

    .OUTPUTS
        System.String when -PassThru or -Markdown; the written path when
        -OutFile is used; otherwise nothing (host output only).

    .NOTES
        This cmdlet writes to the host on purpose: it is the module's console
        UX. All other cmdlets emit objects and use the information stream.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive reference is the explicit purpose of this cmdlet; -PassThru returns objects for automation.')]
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string] $Cmdlet,
        [switch] $Detailed,
        [switch] $Markdown,
        [string] $OutFile,
        [switch] $Plain,
        [switch] $PassThru
    )

    $module = Get-Module WinSecHunter
    $version = $script:WinSecModuleVersion
    $exported = @($module.ExportedFunctions.Keys | Sort-Object)
    $config = Get-WinSecConfig
    $res = Get-WinSecResource

    $text = [System.Text.StringBuilder]::new()
    $line = { param([string]$s = '') $null = $text.AppendLine($s) }
    $md = [bool]$Markdown

    # ---------------------------------------------------------------- overview
    if (-not $Cmdlet) {
        $profiles = @($res.Profiles.Keys | Sort-Object)
        $logs = @($res.Logs)

        if ($md) {
            & $line "# WinSecHunter $version — command reference"
            & $line
            & $line '> Generated from live module metadata. Do not edit by hand; regenerate with `Show-WinSecHunterHelp -Markdown`.'
            & $line
            & $line '## What it is'
            & $line
            & $line 'WinSecHunter is an incident-response toolkit for Windows security events. It answers one question completely: **what did a given attacker IP do to this estate?** — across local hosts, remote hosts over WinRM and offline EVTX files, then turns the answer into evidence and reports.'
            & $line
            & $line '## Five-minute quick start'
            & $line
            & $line '```powershell'
            & $line 'Install-Module WinSecHunter -Scope CurrentUser        # or: .\build\Install-Dev.ps1'
            & $line '$events = Get-WinSecEventByIp 203.0.113.7 -LastDays 2 -PassHostStatus'
            & $line '$events | Test-WinSecBruteForce'
            & $line '$events | Get-WinSecIpTimeline -AsciiChart'
            & $line 'Export-WinSecInvestigation -Event $events -Format All -PassThru'
            & $line '```'
            & $line
        }
        else {
            & $line ("WinSecHunter {0}  —  Windows security event investigation" -f $version)
            & $line ('=' * 78)
            & $line 'What did a given attacker IP do to this estate? Collect it, prove it, report it.'
            & $line
            & $line 'QUICK START'
            & $line '  Import-Module WinSecHunter            # or .\build\Install-Dev.ps1'
            & $line '  $events = Get-WinSecEventByIp 203.0.113.7 -LastDays 2 -PassHostStatus'
            & $line '  $events | Test-WinSecBruteForce'
            & $line '  $events | Get-WinSecIpTimeline -AsciiChart'
            & $line '  Export-WinSecInvestigation -Event $events -Format All'
            & $line
        }

        $groups = [ordered]@{
            'Collect'  = @('Get-WinSecEventByIp', 'Trace-WinSecIp', 'Get-WinSecLogCoverage')
            'Analyze'  = @('Get-WinSecIpTimeline', 'Get-WinSecLogonSession', 'Test-WinSecBruteForce', 'Test-WinSecAuditPolicy')
            'Enrich'   = @('Resolve-WinSecIpAttribution', 'Expand-WinSecIpRange')
            'Report'   = @('New-WinSecIncidentReport', 'New-WinSecAbuseReport', 'Export-WinSecIocList')
            'Preserve' = @('New-WinSecCase', 'Export-WinSecInvestigation', 'Import-WinSecCase', 'Test-WinSecEvidenceIntegrity')
            'Reference'= @('Get-WinSecEventCatalog', 'Get-WinSecHunterOption', 'Set-WinSecHunterOption', 'Show-WinSecHunterHelp')
        }
        & $line ($md ? '## Workflow map' : 'WORKFLOW MAP')
        & $line
        foreach ($g in $groups.Keys) {
            $names = @($groups[$g] | Where-Object { $exported -contains $_ })
            if ($names.Count -eq 0) { continue }
            if ($md) {
                & $line "### $g"
                & $line
                foreach ($n in $names) {
                    $syn = (Get-Help $n).Synopsis.Trim()
                    & $line ("- **``$n``** — $syn")
                }
                & $line
            }
            else {
                $label = $g.ToUpperInvariant() + ':'
                & $line ('  {0,-10} {1}' -f $label, ($names -join ' · '))
            }
        }
        if (-not $md) { & $line }

        # ---- per-cmdlet table -------------------------------------------------
        & $line ($md ? '## Cmdlets' : 'CMDLETS')
        & $line
        if ($md) {
            & $line '| Cmdlet | Purpose |'
            & $line '|---|---|'
            foreach ($n in $exported) { & $line ('| `{0}` | {1} |' -f $n, ((Get-Help $n).Synopsis.Trim() -replace '\|', '\|')) }
            & $line
        }
        else {
            foreach ($n in $exported) {
                $syn = (Get-Help $n).Synopsis.Trim()
                & $line ('  {0,-32} {1}' -f $n, $syn)
            }
            & $line
        }

        # ---- profiles ---------------------------------------------------------
        & $line ($md ? '## Hunt profiles' : 'HUNT PROFILES')
        & $line
        if ($md) {
            & $line '| Profile | Purpose |'
            & $line '|---|---|'
            foreach ($p in $profiles) { & $line ('| `{0}` | {1} |' -f $p, [string]$res.Profiles[$p]['description']) }
            & $line
        }
        else {
            foreach ($p in $profiles) {
                $d = [string]$res.Profiles[$p]['description']
                if ($d.Length -gt 60) { $d = $d.Substring(0, 57) + '...' }
                & $line ('  {0,-20} {1}' -f $p, $d)
            }
            & $line
        }

        # ---- catalog & config -------------------------------------------------
        & $line ($md ? '## Catalog and configuration' : 'CATALOG AND CONFIGURATION')
        & $line
        & $line ("- Catalog: **{0}** events across **{1}** channels (version {2})." -f @($res.Catalog.events).Count, $logs.Count, $res.Version)
        & $line ("- Configuration file: ``{0}``" -f (Join-Path (Get-WinSecConfigPath) 'config.json'))
        & $line ("- Override directory with ``WINSECHUNTER_CONFIG_DIR`` (portable IR kit on read-only media is supported for reads).")
        & $line
        if ($md) {
            & $line '| Option | Default | Meaning |'
            & $line '|---|---|---|'
            foreach ($k in ($config.Keys | Sort-Object)) { & $line ('| `{0}` | `{1}` | {2} |' -f $k, $config[$k], (Get-WinSecOptionDescription $k)) }
            & $line
        }
        else {
            foreach ($k in ($config.Keys | Sort-Object)) {
                & $line ('  {0,-32} {1}' -f $k, (Get-WinSecOptionDescription $k))
            }
            & $line
        }

        # ---- requirements -----------------------------------------------------
        & $line ($md ? '## Requirements and platform support' : 'REQUIREMENTS AND PLATFORM SUPPORT')
        & $line
        & $line '- PowerShell **7.6+** (Core). Windows PowerShell 5.1 is not supported.'
        & $line '- Collection (`Get-WinSecEventByIp`, `Trace-WinSecIp`, `Get-WinSecLogCoverage`, `Test-WinSecAuditPolicy`) requires Windows and, for the Security log, an elevated session.'
        & $line '- Remote collection uses WinRM/`Invoke-Command` or pre-built CIM sessions; configure `Enable-PSRemoting` and the appropriate TrustedHosts/CredSSP policy.'
        & $line '- Offline EVTX analysis works on any OS that can read the file; pure analysis cmdlets (timeline, brute force, sessions, reporting) run everywhere.'
        & $line '- No external binaries, no cloud dependency. Optional threat-intel providers read API keys from environment variables only.'
        & $line

        & $line ($md ? '## Troubleshooting' : 'TROUBLESHOOTING')
        & $line
        & $line '| Symptom | First check |'
        & $line '|---|---|'
        & $line '| "No events" but activity is known | `Get-WinSecLogCoverage` (retention), `Test-WinSecAuditPolicy` (is the subcategory audited?) |'
        & $line '| Access denied reading Security | Run elevated; the channel requires Administrator |'
        & $line '| Remote host failed | `-PassHostStatus` lists per-channel status; verify WinRM, firewall, credentials |'
        & $line '| Missing Sysmon/RDP channel | Expected on servers without those roles: the channel reports `Skipped`, the sweep continues |'
        & $line '| Report hashes do not match | Files were modified after export; re-export and keep bundles read-only |'
        & $line '| Abuse mailbox unknown | `New-WinSecAbuseReport` never invents an address; pass `-ContactEmail` |'
        & $line

        if ($Detailed) {
            & $line ($md ? '## Detailed cmdlet reference' : 'DETAILED CMDLET REFERENCE')
            foreach ($n in $exported) {
                & $line
                & $line (Get-WinSecCmdletReference -Name $n -Markdown:$md)
            }
        }
        elseif (-not $md) {
            & $line 'Run Show-WinSecHunterHelp -Detailed for parameters and examples of every cmdlet,'
            & $line 'or Show-WinSecHunterHelp -Cmdlet <name> for one cmdlet.'
        }
    }
    else {
        $resolved = @($exported | Where-Object { $_ -eq $Cmdlet })
        if ($resolved.Count -eq 0) {
            $hint = ($exported | Sort-Object) -join ', '
            throw [ArgumentException]::new("Unknown WinSecHunter cmdlet '$Cmdlet'. Exported cmdlets: $hint")
        }
        $text.Append((Get-WinSecCmdletReference -Name $resolved[0] -Markdown:$md)) | Out-Null
    }

    $rendered = $text.ToString()

    if ($OutFile) {
        $full = [System.IO.Path]::GetFullPath($OutFile)
        $null = Write-WinSecFileAtomic -Path $full -Content $rendered
        if ($PassThru) { return $rendered }
        return $full
    }
    if ($PassThru -or $md) { return $rendered }

    # Console rendering with optional colour.
    $useColor = -not $Plain -and -not $env:NO_COLOR -and $Host.Name -ne 'ServerRemoteHost'
    $c = if ($useColor) {
        @{ Head = $PSStyle.Foreground.Cyan + $PSStyle.Bold; Key = $PSStyle.Foreground.BrightBlack; Accent = $PSStyle.Foreground.BrightCyan; Reset = $PSStyle.Reset }
    }
    else { @{ Head = ''; Key = ''; Accent = ''; Reset = '' } }

    foreach ($ln in ($rendered -split "`n")) {
        $isHead = $ln -match '^[A-Z][A-Z0-9 ,/&-]{3,}$' -or $ln -match '^\S.*\s—\s' -or $ln -match '^={5,}'
        if ($isHead) { Write-Host ($c.Head + $ln + $c.Reset) }
        else { Write-Host $ln }
    }
}

