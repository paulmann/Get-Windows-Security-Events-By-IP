#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Runs every static and behavioural gate WinSecHunter must pass before a release.

.DESCRIPTION
    Gates, in order:
      1. AST parse of every .ps1/.psm1/.psd1 (classes are parsed together with
         the enums, exactly as the loader sees them).
      2. Test-ModuleManifest.
      3. Import in the current session and export allow-list parity
         (manifest vs module vs Get-Command).
      4. Comment-based help: synopsis and at least two examples per exported cmdlet.
      5. Catalog smoke: event count, profile count, catalog lookups.
      6. PSScriptAnalyzer (when installed): zero Error/Warning, TypeNotFound excluded.
      7. Pester suite (with -Tests, when installed).

    Exit code 0 = all green, 1 = at least one gate failed.

.PARAMETER Tests
    Also run the Pester suite.

.PARAMETER Quiet
    Only print failures and the final summary.

.EXAMPLE
    ./build/validate.ps1

.EXAMPLE
    ./build/validate.ps1 -Tests

.OUTPUTS
    PSCustomObject summary; exit code reflects the result.
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [switch] $Tests,
    [switch] $Quiet
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$src      = Join-Path $repoRoot 'src/WinSecHunter'
$manifest = Join-Path $src 'WinSecHunter.psd1'
$failures = [System.Collections.Generic.List[string]]::new()
$checks = [System.Collections.Generic.List[object]]::new()

function Add-Check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $checks.Add([pscustomobject]@{ Check = $Name; Result = $Ok ? 'PASS' : 'FAIL'; Detail = $Detail })
    if (-not $Ok) { $failures.Add("$Name — $Detail") }
    if (-not $Quiet -or -not $Ok) { Write-Host ("[{0}] {1}{2}" -f ($Ok ? 'PASS' : 'FAIL'), $Name, ($Detail ? " — $Detail" : '')) }
}

# 1. Parse -------------------------------------------------------------------
# Classes reference enums and each other; the loader dot-sources them into one
# scope. Parse them as one document, then every other file on its own.
$parseErrors = [System.Collections.Generic.List[string]]::new()
$allFiles = @(Get-ChildItem -LiteralPath $src -Recurse -File -Include *.ps1, *.psm1, *.psd1)
$classFiles = @($allFiles | Where-Object { $_.Directory.Name -eq 'Classes' })
$enumsText = Get-Content -Raw -LiteralPath (Join-Path $src 'Enums/WinSecEnums.ps1')
$classesText = $enumsText + "`n" + (($classFiles | ForEach-Object { Get-Content -Raw -LiteralPath $_.FullName }) -join "`n")

$classErrs = $null
$null = [System.Management.Automation.Language.Parser]::ParseInput($classesText, [ref]$null, [ref]$classErrs)
foreach ($e in @($classErrs)) { $parseErrors.Add(('Classes (combined):{0} {1}' -f $e.Extent.StartLineNumber, $e.Message)) }

foreach ($f in ($allFiles | Where-Object { $_.Directory.Name -ne 'Classes' })) {
    $errs = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$errs)
    foreach ($e in @($errs)) { $parseErrors.Add(('{0}:{1} {2}' -f $f.FullName.Replace($repoRoot + '\', ''), $e.Extent.StartLineNumber, $e.Message)) }
}
Add-Check 'AST parse' ($parseErrors.Count -eq 0) (($parseErrors | Select-Object -First 3) -join '; ')

# 2. Manifest ----------------------------------------------------------------
try {
    $mf = Test-ModuleManifest -Path $manifest -ErrorAction Stop
    Add-Check 'Module manifest' $true ("version $($mf.Version)")
}
catch {
    Add-Check 'Module manifest' $false $_.Exception.Message
}

# 3. Import + export parity ---------------------------------------------------
Remove-Module WinSecHunter -Force -ErrorAction SilentlyContinue
try {
    Import-Module $manifest -Force -ErrorAction Stop
    $mod = Get-Module WinSecHunter
    $runtime = @($mod.ExportedFunctions.Keys | Sort-Object)
    $declared = @($mf.ExportedFunctions.Keys | Sort-Object)
    $onlyManifest = @($declared | Where-Object { $_ -notin $runtime })
    $onlyRuntime  = @($runtime | Where-Object { $_ -notin $declared })
    Add-Check 'Import' $true ("$($runtime.Count) exports")
    Add-Check 'Export parity' ($onlyManifest.Count -eq 0 -and $onlyRuntime.Count -eq 0) (
        "manifest-only: $($onlyManifest -join ', '); runtime-only: $($onlyRuntime -join ', ')")
}
catch {
    Add-Check 'Import' $false $_.Exception.Message
}

# 4. Help --------------------------------------------------------------------
$helpProblems = [System.Collections.Generic.List[string]]::new()
foreach ($name in @((Get-Module WinSecHunter).ExportedFunctions.Keys)) {
    $h = Get-Help $name -Full
    $examples = @($h.Examples.Example).Count
    $syn = [string]$h.Synopsis
    if ([string]::IsNullOrWhiteSpace($syn) -or $syn -match '^\s*$') { $helpProblems.Add("${name}: missing synopsis") }
    if ($examples -lt 2) { $helpProblems.Add("${name}: $examples example(s)") }
}
Add-Check 'Comment-based help' ($helpProblems.Count -eq 0) (($helpProblems | Select-Object -First 4) -join '; ')

# 5. Catalog smoke -----------------------------------------------------------
try {
    $catalog = @(Get-WinSecEventCatalog)
    $profiles = @(Get-WinSecEventCatalog -ListProfiles)
    $byId = @(Get-WinSecEventCatalog -EventId 4625)
    Add-Check 'Catalog' ($catalog.Count -ge 150 -and $profiles.Count -ge 10 -and $byId.Count -ge 1) (
        "$($catalog.Count) events, $($profiles.Count) profiles")
}
catch {
    Add-Check 'Catalog' $false $_.Exception.Message
}

# 6. PSScriptAnalyzer --------------------------------------------------------
$pssa = Get-Module -ListAvailable PSScriptAnalyzer | Select-Object -First 1
if ($pssa) {
    $settings = Join-Path $repoRoot 'PSScriptAnalyzerSettings.psd1'
    $issues = @(Invoke-ScriptAnalyzer -Path $src -Recurse -Settings $settings -Severity Error, Warning |
        Where-Object RuleName -ne 'TypeNotFound')
    Add-Check 'PSScriptAnalyzer' ($issues.Count -eq 0) ("$($issues.Count) issue(s)")
}
else {
    Add-Check 'PSScriptAnalyzer' $true 'not installed — skipped'
}

# 7. Pester ------------------------------------------------------------------
if ($Tests) {
    $pester = Get-Module -ListAvailable Pester | Where-Object { $_.Version -ge [version]'5.0.0' } | Select-Object -First 1
    if ($pester) {
        $conf = New-PesterConfiguration
        $conf.Run.Path = Join-Path $repoRoot 'tests'
        $conf.Run.PassThru = $true
        $conf.Output.Verbosity = $Quiet ? 'Normal' : 'Detailed'
        $r = Invoke-Pester -Configuration $conf
        Add-Check 'Pester' ($r.FailedCount -eq 0) ("passed $($r.PassedCount), failed $($r.FailedCount), skipped $($r.SkippedCount)")
    }
    else {
        Add-Check 'Pester' $false 'Pester 5+ not installed'
    }
}

$summary = [pscustomobject]@{
    Version  = (Get-Module WinSecHunter).Version.ToString()
    Checks   = $checks.Count
    Failed   = $failures.Count
    Results  = $checks
}
Write-Host ''
Write-Host ("{0}: {1} check(s), {2} failed" -f ($failures.Count -eq 0 ? 'OK' : 'FAILED'), $checks.Count, $failures.Count)
if ($failures.Count -gt 0) {
    foreach ($f in $failures) { Write-Host "  - $f" }
    exit 1
}
return $summary

