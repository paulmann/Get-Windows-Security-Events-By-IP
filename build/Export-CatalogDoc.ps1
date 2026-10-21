#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Regenerates docs/EventCatalog.md and docs/Command-Reference.md from the live
    module metadata.

.DESCRIPTION
    Documentation that is copied by hand drifts. Both pages are generated:
      * EventCatalog.md      — every catalog entry grouped by channel, with
                               category, importance, ATT&CK mapping and IP fields.
      * Command-Reference.md — full cmdlet reference rendered by
                               Show-WinSecHunterHelp -Markdown.

    With -Check nothing is written: the script compares generated content with
    the files on disk and exits 10 when regeneration is required (CI gate).

.PARAMETER Check
    Do not write; exit 10 if a file is stale, 0 if up to date.

.EXAMPLE
    ./build/Export-CatalogDoc.ps1

.EXAMPLE
    ./build/Export-CatalogDoc.ps1 -Check

.OUTPUTS
    PSCustomObject per generated file: Path, Changed, Bytes.
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [switch] $Check
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $repoRoot 'src/WinSecHunter/WinSecHunter.psd1'
$docsDir  = Join-Path $repoRoot 'docs'
$null = New-Item -ItemType Directory -Path $docsDir -Force

Remove-Module WinSecHunter -Force -ErrorAction SilentlyContinue
Import-Module $manifest -Force -ErrorAction Stop

$version = (Get-Module WinSecHunter).Version.ToString()
$catalog = @(Get-WinSecEventCatalog)

$md = [System.Text.StringBuilder]::new()
$null = $md.AppendLine('# Event Catalog Reference')
$null = $md.AppendLine()
$null = $md.AppendLine(('> Generated from `Resources/EventCatalog.json` (catalog v{0}, {1} events) by `build/Export-CatalogDoc.ps1`. Do not edit manually.' -f $version, $catalog.Count))
$null = $md.AppendLine('>')
$null = $md.AppendLine('> **IP fields** lists the event data fields that natively carry IP addresses.')
$null = $md.AppendLine('> Events without IP fields still participate in sweeps as *contextual evidence*.')
$null = $md.AppendLine()
$null = $md.AppendLine('## Supported channels')
$null = $md.AppendLine()
$null = $md.AppendLine('| Channel | Events |')
$null = $md.AppendLine('|---|---|')
foreach ($ch in ($catalog | Group-Object Log | Sort-Object Name)) {
    $null = $md.AppendLine(('| `{0}` | {1} |' -f $ch.Name, $ch.Count))
}
$null = $md.AppendLine()
$null = $md.AppendLine('## Hunt profiles')
$null = $md.AppendLine()
$null = $md.AppendLine('| Profile | Description |')
$null = $md.AppendLine('|---|---|')
foreach ($p in @(Get-WinSecEventCatalog -ListProfiles)) {
    $info = $p | Select-Object -First 1
    $desc = [string]$info.Description
    $null = $md.AppendLine(('| `{0}` | {1} |' -f $info.Profile, ($desc -replace '\|', '\|')))
}
$null = $md.AppendLine()

foreach ($group in ($catalog | Group-Object Log | Sort-Object Name)) {
    $null = $md.AppendLine(('## {0}' -f $group.Name))
    $null = $md.AppendLine()
    $null = $md.AppendLine('| ID | Name | Category | Importance | ATT&CK | IP fields | Notes |')
    $null = $md.AppendLine('|---|---|---|---|---|---|---|')
    foreach ($e in ($group.Group | Sort-Object EventId)) {
        $attack = @($e.Attack) -join ', '
        $ipf = @($e.IpFields) -join ', '
        $notes = ([string]$e.Notes -replace '\|', '\|' -replace "`r?`n", ' ')
        $null = $md.AppendLine(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f
            $e.EventId, $e.Name, $e.Category, $e.Importance, $attack, $ipf, $notes))
    }
    $null = $md.AppendLine()
}

$outputs = @(
    @{ Path = Join-Path $docsDir 'EventCatalog.md'; Content = $md.ToString() },
    @{ Path = Join-Path $docsDir 'Command-Reference.md'; Content = (Show-WinSecHunterHelp -Markdown -Detailed) }
)

$results = [System.Collections.Generic.List[object]]::new()
$stale = 0
foreach ($o in $outputs) {
    $existing = (Test-Path -LiteralPath $o.Path) ? (Get-Content -Raw -LiteralPath $o.Path) : ''
    $normalizedNew = ($o.Content -replace "`r`n", "`n")
    $changed = ($existing -replace "`r`n", "`n") -ne $normalizedNew
    if ($changed) { $stale++ }
    if (-not $Check -and $changed) {
        # Private module helpers are not exported; write atomically here.
        $tmp = $o.Path + '.tmp'
        [System.IO.File]::WriteAllText($tmp, $normalizedNew, [System.Text.UTF8Encoding]::new($false))
        [System.IO.File]::Move($tmp, $o.Path, $true)
    }
    $results.Add([pscustomobject]@{ Path = $o.Path; Changed = $changed; Bytes = $normalizedNew.Length })
    if (-not $Check) { Write-Host ("{0}: {1}" -f ($changed ? 'updated' : 'unchanged'), $o.Path) }
}

if ($Check -and $stale -gt 0) {
    Write-Host "Documentation is stale: $stale file(s) need regeneration. Run ./build/Export-CatalogDoc.ps1"
    exit 10
}
return $results
