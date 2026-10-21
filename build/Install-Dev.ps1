#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Installs the working copy of WinSecHunter into the current user's module path
    for manual testing (no manifest signing, no gallery).

.DESCRIPTION
    Copies src/WinSecHunter to a per-user Modules folder and reports the path.
    Existing installation is replaced only with -Force. This is the developer
    loop; end users install from the gallery or a release zip.

.PARAMETER Destination
    Explicit destination folder (the parent that will contain WinSecHunter).
    Default: the first user-writable entry of $env:PSModulePath
    (typically Documents\PowerShell\Modules).

.PARAMETER Force
    Overwrite an existing installation.

.EXAMPLE
    ./build/Install-Dev.ps1 -Force

.EXAMPLE
    ./build/Install-Dev.ps1 -Destination D:\tools\PSModules -WhatIf

.OUTPUTS
    PSCustomObject: Path, Version, Installed.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
[OutputType([pscustomobject])]
param(
    [string] $Destination,
    [switch] $Force
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$source   = Join-Path $repoRoot 'src/WinSecHunter'
$manifest = Join-Path $source 'WinSecHunter.psd1'
if (-not (Test-Path -LiteralPath $manifest)) { throw "Manifest not found: $manifest" }
$version = [string](Import-PowerShellDataFile -LiteralPath $manifest).ModuleVersion

if (-not $Destination) {
    $userRoot = [Environment]::GetFolderPath('MyDocuments')
    $candidates = @(
        (Join-Path $userRoot 'PowerShell/Modules'),
        (Join-Path $userRoot 'WindowsPowerShell/Modules')
    )
    $Destination = $candidates | Where-Object { Test-Path -LiteralPath (Split-Path -Parent $_) } | Select-Object -First 1
    if (-not $Destination) { $Destination = $candidates[0] }
}

$target = Join-Path $Destination 'WinSecHunter'
if ((Test-Path -LiteralPath $target) -and -not $Force) {
    throw "WinSecHunter is already installed at $target. Re-run with -Force to replace it."
}

if (-not $PSCmdlet.ShouldProcess($target, "Install WinSecHunter $version")) {
    return [pscustomobject]@{ Path = $target; Version = $version; Installed = $false }
}

if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Recurse -Force }
$null = New-Item -ItemType Directory -Path $target -Force
Copy-Item -Path (Join-Path $source '*') -Destination $target -Recurse -Force

Write-Host "Installed WinSecHunter $version to $target"
Write-Host "Verify with: Import-Module WinSecHunter -Force; Show-WinSecHunterHelp"

[pscustomobject]@{ Path = $target; Version = $version; Installed = $true }
