#Requires -Version 7.6
#Requires -PSEdition Core
<#
.SYNOPSIS
    Builds a validated, versioned WinSecHunter release artifact (optionally zipped).

.DESCRIPTION
    Copies src/WinSecHunter into output/WinSecHunter/<version>, validates the
    manifest, imports the built module in a clean child process, and optionally
    creates a zip package. The build fails loudly if the manifest, exports or
    help metadata do not match — a broken artifact is never produced silently.

.PARAMETER OutputPath
    Parent output folder. Default: ./output

.PARAMETER Zip
    Also produce output/WinSecHunter-<version>.zip.

.PARAMETER Clean
    Remove the version folder before building.

.PARAMETER SkipValidation
    Skip the import/export validation (not recommended; used for quick local loops).

.EXAMPLE
    ./build/Build-Module.ps1 -Zip

.EXAMPLE
    ./build/Build-Module.ps1 -OutputPath D:\artifacts -Clean

.OUTPUTS
    PSCustomObject: Version, Path, ZipPath, ExportedFunctions, Bytes.
#>
[CmdletBinding()]
[OutputType([pscustomobject])]
param(
    [string] $OutputPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'output'),
    [switch] $Zip,
    [switch] $Clean,
    [switch] $SkipValidation
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$source   = Join-Path $repoRoot 'src/WinSecHunter'
$manifest = Join-Path $source 'WinSecHunter.psd1'

if (-not (Test-Path -LiteralPath $manifest)) { throw "Manifest not found: $manifest" }
$data = Import-PowerShellDataFile -LiteralPath $manifest
$version = [string]$data.ModuleVersion

$destRoot = Join-Path $OutputPath 'WinSecHunter'
$dest     = Join-Path $destRoot $version
if ($Clean -and (Test-Path -LiteralPath $dest)) {
    Write-Host "Cleaning $dest"
    Remove-Item -LiteralPath $dest -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $dest -Force

Write-Host "Building WinSecHunter $version -> $dest"
Copy-Item -Path (Join-Path $source '*') -Destination $dest -Recurse -Force

$builtManifest = Join-Path $dest 'WinSecHunter.psd1'
$tested = Test-ModuleManifest -Path $builtManifest -ErrorAction Stop
if ([string]$tested.Version -ne $version) { throw "Built manifest version $($tested.Version) != requested $version" }

$exported = @($tested.ExportedFunctions.Keys)
if ($exported.Count -eq 0) { throw 'Manifest exports no functions.' }

if (-not $SkipValidation) {
    Write-Host "Validating artifact in a child pwsh process..."
    $probe = @'
param($ManifestPath)
$ErrorActionPreference = 'Stop'
Import-Module $ManifestPath -Force -ErrorAction Stop
$m = Get-Module WinSecHunter
$missing = @($m.ExportedFunctions.Keys | Where-Object { -not (Get-Command $_ -ErrorAction SilentlyContinue) })
if ($missing.Count) { throw "Exports not resolvable: $($missing -join ', ')" }
$count = @(Get-WinSecEventCatalog).Count
if ($count -lt 150) { throw "Catalog too small: $count" }
"{0}|{1}|{2}" -f $m.Version, $m.ExportedFunctions.Count, $count
'@
    $probeFile = Join-Path ([System.IO.Path]::GetTempPath()) ('wsx-build-probe-' + [guid]::NewGuid().ToString('n') + '.ps1')
    Set-Content -LiteralPath $probeFile -Value $probe -Encoding utf8NoBOM
    try {
        $result = & pwsh -NoLogo -NoProfile -NonInteractive -File $probeFile -ManifestPath $builtManifest
        if ($LASTEXITCODE -ne 0) { throw "Artifact validation failed (exit $LASTEXITCODE)." }
        Write-Host "  validation: $result"
    }
    finally {
        Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue
    }
}

$zipPath = $null
if ($Zip) {
    $zipPath = Join-Path $OutputPath ("WinSecHunter-{0}.zip" -f $version)
    if (Test-Path -LiteralPath $zipPath) { Remove-Item -LiteralPath $zipPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $dest, $zipPath, [System.IO.Compression.CompressionLevel]::Optimal, $false)
    Write-Host "Zip: $zipPath"
}

$bytes = (Get-ChildItem -LiteralPath $dest -Recurse -File | Measure-Object -Sum Length).Sum
$result = [pscustomobject]@{
    Version           = $version
    Path              = $dest
    ZipPath           = $zipPath
    ExportedFunctions = $exported.Count
    Bytes             = $bytes
}
Write-Host ("Done: {0} functions, {1:N0} bytes" -f $result.ExportedFunctions, $result.Bytes)
return $result
