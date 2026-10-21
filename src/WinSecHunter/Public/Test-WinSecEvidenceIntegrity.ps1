#Requires -Version 7.6
#Requires -PSEdition Core
function Test-WinSecEvidenceIntegrity {
    <#
    .SYNOPSIS
        Verifies an exported evidence bundle against its SHA-256 manifest and
        reports modified, missing or unexpected files.

    .DESCRIPTION
        Export-WinSecInvestigation writes manifest.json last and records the
        SHA-256, byte size and UTC write time of every artifact. This cmdlet
        re-computes those hashes and compares them, so "the bundle is intact"
        becomes a measured statement rather than an assumption.

        Four conditions are reported:
          OK         hash and size match
          Modified   file exists but content or size changed
          Missing    manifest lists a file that is not present
          Extra      file exists in the bundle but is not in the manifest
          Unreadable file exists but cannot be hashed (locked/permissions)

        Extra files matter: an attacker (or a careless operator) can append a
        file to a bundle without breaking any recorded hash. The manifest alone
        cannot detect addition — this cmdlet can.

    .PARAMETER Path
        Bundle directory (the one containing manifest.json) or the path to
        manifest.json itself.

    .PARAMETER Algorithm
        Hash algorithm recorded in the manifest. SHA256 by default; SHA384 and
        SHA512 are accepted for bundles produced by other tooling.

    .PARAMETER ProblemsOnly
        Return only rows whose Status is not OK.

    .PARAMETER Summary
        Return one object with counts, bundle path, case id, generation time and
        a Rows property instead of a row stream.

    .PARAMETER Json
        Return a JSON document (summary + rows) for ingestion by a pipeline.

    .EXAMPLE
        Test-WinSecEvidenceIntegrity -Path .\WSC-20261011-AB12CD34

        Verifies every artifact and prints one row per file.

    .EXAMPLE
        $r = Test-WinSecEvidenceIntegrity .\WSC-20261011-AB12CD34 -ProblemsOnly -Summary
        if ($r.Problems -gt 0) { throw "Evidence bundle failed verification: $($r.Problems) problem(s)" }

    .EXAMPLE
        Test-WinSecEvidenceIntegrity .\bundle -Json | Set-Content .\integrity.json -Encoding utf8NoBOM

    .OUTPUTS
        PSCustomObject per artifact (RelativePath, Status, ExpectedSha256,
        ActualSha256, ExpectedBytes, ActualBytes, LastWriteUtc). With -Summary a
        single summary object; with -Json a string.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string] $Path,

        [ValidateSet('SHA256', 'SHA384', 'SHA512')]
        [string] $Algorithm = 'SHA256',

        [switch] $ProblemsOnly,
        [switch] $Summary,
        [switch] $Json
    )

    process {
        $manifestPath = if (Test-Path -LiteralPath $Path -PathType Container) {
            Join-Path $Path 'manifest.json'
        }
        elseif ((Split-Path -Leaf $Path) -eq 'manifest.json') { $Path }
        else { throw [ArgumentException]::new("Path must be a bundle directory or manifest.json: '$Path'.") }

        if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
            throw [System.IO.FileNotFoundException]::new("Evidence manifest not found: '$manifestPath'.", $manifestPath)
        }

        try {
            $manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json -AsHashtable
        }
        catch {
            throw [System.IO.InvalidDataException]::new("Manifest '$manifestPath' is not valid JSON: $($_.Exception.Message)", $_.Exception)
        }
        if (-not $manifest -or -not $manifest['artifacts']) {
            throw [System.IO.InvalidDataException]::new("Manifest '$manifestPath' has no 'artifacts' section.")
        }

        $caseDir = Split-Path -Parent $manifestPath
        $root    = Split-Path -Parent $caseDir
        $caseId  = [string]$manifest['caseId']
        $recordedAlgorithm = [string]$manifest['hashAlgorithm']
        if ($recordedAlgorithm -and $recordedAlgorithm -ne $Algorithm) {
            Write-Verbose "Manifest records $recordedAlgorithm; verifying with $Algorithm as requested."
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

        foreach ($rel in @($manifest['artifacts'].Keys)) {
            $expected = $manifest['artifacts'][$rel]
            $candidates = @(
                (Join-Path $root $rel)
                (Join-Path $caseDir $rel)
                (Join-Path $caseDir (Split-Path -Leaf $rel))
            )
            $full = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1

            if (-not $full) {
                $rows.Add([pscustomobject]@{
                    RelativePath = $rel; FullPath = (Join-Path $root $rel); Status = 'Missing'
                    ExpectedSha256 = [string]$expected['Sha256']; ActualSha256 = $null
                    ExpectedBytes = [long]$expected['Bytes']; ActualBytes = $null
                    LastWriteUtc = $null
                })
                continue
            }

            $null = $seen.Add([System.IO.Path]::GetFullPath($full))
            try {
                $actualHash = (Get-FileHash -LiteralPath $full -Algorithm $Algorithm).Hash
                $actualBytes = (Get-Item -LiteralPath $full).Length
                $expectedHash = [string]$expected['Sha256']
                $status = if ($actualHash -eq $expectedHash -and $actualBytes -eq [long]$expected['Bytes']) { 'OK' } else { 'Modified' }
                $rows.Add([pscustomobject]@{
                    RelativePath = $rel; FullPath = $full; Status = $status
                    ExpectedSha256 = $expectedHash; ActualSha256 = $actualHash
                    ExpectedBytes = [long]$expected['Bytes']; ActualBytes = $actualBytes
                    LastWriteUtc = (Get-Item -LiteralPath $full).LastWriteTimeUtc
                })
            }
            catch {
                $rows.Add([pscustomobject]@{
                    RelativePath = $rel; FullPath = $full; Status = 'Unreadable'
                    ExpectedSha256 = [string]$expected['Sha256']; ActualSha256 = $null
                    ExpectedBytes = [long]$expected['Bytes']; ActualBytes = $null
                    LastWriteUtc = $null
                })
            }
        }

        # Files present but not listed: addition is invisible to hashes.
        foreach ($file in @(Get-ChildItem -LiteralPath $caseDir -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            if ($file.FullName -eq [System.IO.Path]::GetFullPath($manifestPath)) { continue }
            if ($seen.Contains($file.FullName)) { continue }
            $rows.Add([pscustomobject]@{
                RelativePath = $file.FullName.Substring($caseDir.Length).TrimStart('\', '/')
                FullPath = $file.FullName; Status = 'Extra'
                ExpectedSha256 = $null; ActualSha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm $Algorithm).Hash
                ExpectedBytes = $null; ActualBytes = $file.Length
                LastWriteUtc = $file.LastWriteTimeUtc
            })
        }

        $all = @($rows)
        if ($ProblemsOnly) { $all = @($all | Where-Object Status -ne 'OK') }
        $ok = @($rows | Where-Object Status -eq 'OK').Count
        $report = [pscustomobject]@{
            BundlePath    = $caseDir
            ManifestPath  = $manifestPath
            CaseId        = $caseId
            GeneratedUtc  = $manifest['generatedUtc']
            Algorithm     = $Algorithm
            Artifacts     = @($manifest['artifacts'].Keys).Count
            Verified      = $ok
            Modified      = @($rows | Where-Object Status -eq 'Modified').Count
            Missing       = @($rows | Where-Object Status -eq 'Missing').Count
            Extra         = @($rows | Where-Object Status -eq 'Extra').Count
            Unreadable    = @($rows | Where-Object Status -eq 'Unreadable').Count
            Problems      = @($rows | Where-Object Status -ne 'OK').Count
            IsIntact      = (@($rows | Where-Object Status -ne 'OK').Count -eq 0)
            Rows          = $all
        }

        if ($Json) { return ($report | ConvertTo-Json -Depth 6) }
        if ($Summary) { return $report }
        return $all
    }
}

