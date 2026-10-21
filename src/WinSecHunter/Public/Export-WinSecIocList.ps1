#Requires -Version 7.6
#Requires -PSEdition Core
function Export-WinSecIocList {
    <#
    .SYNOPSIS
        Extracts indicators of compromise from events and findings and writes
        them as CSV, plain text, JSON or a STIX 2.1 bundle.

    .DESCRIPTION
        Reports are read by people; blocklists and TIPs are read by machines.
        This cmdlet produces the machine-readable side: one row per indicator
        value with its type (TargetIp, SourceIp, DestinationIp, Account, Host,
        Process, Service, Task, Path), sighting count and first/last UTC time.

        Formats:
          Csv     Spreadsheet/SIEM import: Type,Value,Count,FirstUtc,LastUtc.
          Txt     Grep-friendly: "type<TAB>value<TAB>count", one per line.
          Json    Document with metadata, counts and the indicator array.
          Stix21  STIX 2.1 bundle of indicators (IP addresses and accounts),
                  ready for a TIP, MISP import or information sharing.

        STIX indicators are generated from the observed values only; no
        judgement is implied beyond the label 'anomalous-activity'. Values are
        quoted and escaped according to the STIX patterning rules.

    .PARAMETER Case
        Case providing subject IPs (reported as TargetIp).

    .PARAMETER Event
        WinSecEvent objects to mine.

    .PARAMETER Finding
        Findings whose source IP, target account and hosts should be included.

    .PARAMETER Format
        Csv, Txt, Json or Stix21. Default Csv.

    .PARAMETER OutputDirectory
        Parent folder. Defaults to the DefaultOutputDirectory option, else the
        current directory.

    .PARAMETER FileName
        Base file name without extension. Defaults to
        <CaseId>-iocs.

    .PARAMETER PassThru
        Emit a descriptor with path, SHA-256, counts and format.

    .EXAMPLE
        Export-WinSecIocList -Event $events -Format Csv -OutputDirectory D:\IR -PassThru

    .EXAMPLE
        $case = New-WinSecCase -SubjectIps 203.0.113.7
        Export-WinSecIocList -Case $case -Event $events -Finding $findings -Format Stix21 -FileName sharing-bundle

    .EXAMPLE
        Export-WinSecIocList -Event $events -Format Txt |
            ForEach-Object { $_.Path }

    .OUTPUTS
        PSCustomObject with -PassThru; otherwise the path is written to the
        information stream.

    .NOTES
        Deduplication is case-insensitive per type. Placeholder values such as
        '-', 'N/A' and '0.0.0.0' are ignored.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [WinSecCase] $Case,
        [object[]] $Event,
        [object[]] $Finding,

        [ValidateSet('Csv', 'Txt', 'Json', 'Stix21')]
        [string] $Format = 'Csv',

        [string] $OutputDirectory,
        [string] $FileName,
        [switch] $PassThru
    )

    $config = Get-WinSecConfig
    if (-not $OutputDirectory) { $OutputDirectory = [string]$config.DefaultOutputDirectory }
    if (-not $OutputDirectory) { $OutputDirectory = (Get-Location).Path }

    $ctx = Get-WinSecCaseContext -Case $Case -Event $Event -Finding $Finding
    $iocs = $ctx.Iocs
    $rows = @($iocs.Rows)

    $caseId = $ctx.Case.CaseId
    $base = if ($FileName) { [System.IO.Path]::GetFileNameWithoutExtension($FileName) } else { "$caseId-iocs" }
    $ext  = switch ($Format) { 'Csv' { 'csv' } 'Txt' { 'txt' } 'Json' { 'json' } default { 'stix.json' } }
    $caseDir = Join-Path $OutputDirectory ($caseId + '-reports')
    $path = Join-Path $caseDir ("{0}.{1}" -f $base, $ext)

    $content = switch ($Format) {
        'Csv' {
            (@($rows | ForEach-Object {
                [pscustomobject]@{
                    Type = $_.Type; Value = $_.Value; Count = $_.Count
                    FirstUtc = (Format-WinSecUtc $_.FirstUtc); LastUtc = (Format-WinSecUtc $_.LastUtc)
                }
            }) | ConvertTo-Csv -NoTypeInformation) -join "`n"
        }
        'Txt' {
            $sb = [System.Text.StringBuilder]::new()
            $null = $sb.AppendLine("# WinSecHunter IOC list — case $caseId — generated $((Format-WinSecUtc ([datetime]::UtcNow))) UTC")
            $null = $sb.AppendLine('# type<TAB>value<TAB>count')
            foreach ($r in $rows) { $null = $sb.AppendLine(("{0}`t{1}`t{2}" -f $r.Type, $r.Value, $r.Count)) }
            $sb.ToString()
        }
        'Json' {
            [ordered]@{
                generatedUtc = [datetime]::UtcNow.ToString('o')
                tool         = "WinSecHunter $($script:WinSecModuleVersion)"
                caseId       = $caseId
                subjectIps   = @($ctx.Case.SubjectIps)
                verdict      = $ctx.Verdict
                severity     = $ctx.Severity
                counts       = [ordered]@{
                    total = $rows.Count
                    ips   = @($iocs.IpAddresses).Count
                    accounts = @($iocs.Accounts).Count
                    hosts = @($iocs.Hosts).Count
                    processes = @($iocs.Processes).Count
                }
                indicators   = @($rows | ForEach-Object {
                    [ordered]@{
                        type = $_.Type; value = $_.Value; count = $_.Count
                        firstSeenUtc = (Format-WinSecUtc $_.FirstUtc); lastSeenUtc = (Format-WinSecUtc $_.LastUtc)
                    }
                })
            } | ConvertTo-Json -Depth 6
        }
        default {
            $objects = [System.Collections.Generic.List[object]]::new()
            $now = [datetime]::UtcNow.ToString('o')
            $newId = { param($t) '{0}--{1}' -f $t, [guid]::NewGuid().ToString('b') }
            $esc = { param($v) ([string]$v) -replace "\\", '\\' -replace "'", "\'" }

            foreach ($r in $rows) {
                $pattern = switch ($r.Type) {
                    'TargetIp'      { if ($r.Value -match ':') { "[ipv6-addr:value = '{0}']" -f (& $esc $r.Value) } else { "[ipv4-addr:value = '{0}']" -f (& $esc $r.Value) } }
                    'SourceIp'      { if ($r.Value -match ':') { "[ipv6-addr:value = '{0}']" -f (& $esc $r.Value) } else { "[ipv4-addr:value = '{0}']" -f (& $esc $r.Value) } }
                    'DestinationIp' { if ($r.Value -match ':') { "[ipv6-addr:value = '{0}']" -f (& $esc $r.Value) } else { "[ipv4-addr:value = '{0}']" -f (& $esc $r.Value) } }
                    'Account'       { "[user-account:account_login = '{0}']" -f (& $esc (($r.Value -split '\\')[-1])) }
                    default         { $null }
                }
                if (-not $pattern) { continue }
                $objects.Add([ordered]@{
                    type            = 'indicator'
                    spec_version    = '2.1'
                    id              = (& $newId 'indicator')
                    created         = $now
                    modified        = $now
                    name            = ('{0}: {1}' -f $r.Type, $r.Value)
                    description     = ('Observed {0} time(s) in case {1} between {2} and {3} UTC.' -f $r.Count, $caseId, (Format-WinSecUtc $r.FirstUtc), (Format-WinSecUtc $r.LastUtc))
                    indicator_types = @('anomalous-activity')
                    pattern         = $pattern
                    pattern_type    = 'stix'
                    valid_from      = ($r.FirstUtc -and $r.FirstUtc -ne [datetime]::MinValue) ? $r.FirstUtc.ToUniversalTime().ToString('o') : $now
                    labels          = @('anomalous-activity')
                    x_winsechunter_type  = $r.Type
                    x_winsechunter_count = $r.Count
                })
            }

            [ordered]@{
                type    = 'bundle'
                id      = (& $newId 'bundle')
                spec_version = '2.1'
                objects = @($objects)
            } | ConvertTo-Json -Depth 8
        }
    }

    if (-not $PSCmdlet.ShouldProcess($path, "Write IOC list ($Format)")) {
        return [pscustomobject]@{ Format = $Format; Path = $path; Written = $false; Count = $rows.Count }
    }

    $null = Write-WinSecFileAtomic -Path $path -Content $content
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Write-Information ("IOC list ({0}) written to {1} — {2} indicator(s)" -f $Format, $path, $rows.Count) -InformationAction Continue

    $result = [pscustomobject]@{
        Format   = $Format
        Path     = $path
        Sha256   = $hash
        Bytes    = (Get-Item -LiteralPath $path).Length
        Count    = $rows.Count
        CaseId   = $caseId
        Written  = $true
    }
    if ($PassThru) { return $result }
}

