#Requires -Version 7.6
function Test-WinSecAuditPolicy {
    <#
    .SYNOPSIS
        Finds audit-policy gaps: subcategories that are NOT recording the
        events an IP investigation depends on.

    .DESCRIPTION
        The most painful IR discovery is "the events you need were never
        audited". This cmdlet reads the effective advanced audit policy
        (auditpol /get /category:* /r — CSV, parsed locale-independently by
        subcategory GUID) and compares it against the WinSecHunter requirement
        matrix derived from the event catalog.

        Each gap is emitted as WinSecAuditGap with the affected event IDs and
        a ready-to-paste remediation command:
            auditpol /set /subcategory:"{GUID}" /success:enable /failure:enable

        -Profile restricts the requirement matrix to what you actually hunt
        (e.g. Rdp needs Logon + Other Logon/Logoff; BruteForce adds Kerberos
        Authentication Service and Credential Validation).

        Requires elevation to read the full policy on some configurations;
        remote hosts are queried over WinRM in parallel.

    .EXAMPLE
        Test-WinSecAuditPolicy

    .EXAMPLE
        Test-WinSecAuditPolicy -ComputerName DC01, SRV02 -Credential $cred -Profile BruteForce, Rdp

    .EXAMPLE
        Test-WinSecAuditPolicy -IncludeCompliant | Format-Table -AutoSize

    .OUTPUTS
        WinSecAuditGap (non-compliant rows by default; all rows with -IncludeCompliant)
    #>
    [CmdletBinding()]
    [OutputType('WinSecAuditGap')]
    param(
        [string[]] $ComputerName,
        [pscredential] $Credential,
        [ValidateRange(1, 64)] [int] $ThrottleLimit = 8,
        [string[]] $Profile = @('IncidentResponse'),
        [switch] $IncludeCompliant
    )

    if (-not $IsWindows) {
        throw [System.PlatformNotSupportedException]::new('Test-WinSecAuditPolicy requires Windows (auditpol).')
    }

    # Requirement matrix: subcategory GUID → (canonical name, required tokens, event ids, severity).
    # GUIDs are locale-independent; names are for display only.
    $requirements = @(
        @{ Guid = '{0CCE9215-69AE-11D9-BED3-505054503030}'; Name = 'Logon';                             Need = 'Success', 'Failure'; Ids = 4624, 4625;                          Severity = 'Critical'; Always = $true }
        @{ Guid = '{0CCE9216-69AE-11D9-BED3-505054503030}'; Name = 'Logoff';                            Need = 'Success';             Ids = 4634, 4647;                          Severity = 'Medium';   Always = $false }
        @{ Guid = '{0CCE921B-69AE-11D9-BED3-505054503030}'; Name = 'Special Logon';                     Need = 'Success';             Ids = 4672;                                Severity = 'Medium';   Always = $false }
        @{ Guid = '{0CCE921C-69AE-11D9-BED3-505054503030}'; Name = 'Other Logon/Logoff Events';         Need = 'Success', 'Failure'; Ids = 4648, 4649, 4778, 4779, 5632, 5633;  Severity = 'High';     Always = $true }
        @{ Guid = '{0CCE9217-69AE-11D9-BED3-505054503030}'; Name = 'Account Lockout';                   Need = 'Failure';             Ids = 4625, 4740;                          Severity = 'High';     Always = $true }
        @{ Guid = '{0CCE9235-69AE-11D9-BED3-505054503030}'; Name = 'User Account Management';           Need = 'Success';             Ids = 4720, 4722, 4723, 4724, 4725, 4726, 4738, 4794; Severity = 'High'; Always = $false }
        @{ Guid = '{0CCE9237-69AE-11D9-BED3-505054503030}'; Name = 'Security Group Management';         Need = 'Success';             Ids = 4728, 4732, 4756;                    Severity = 'High';     Always = $false }
        @{ Guid = '{0CCE922F-69AE-11D9-BED3-505054503030}'; Name = 'Audit Policy Change';               Need = 'Success', 'Failure'; Ids = 4719, 4715, 4907;                    Severity = 'Critical'; Always = $true }
        @{ Guid = '{0CCE9230-69AE-11D9-BED3-505054503030}'; Name = 'Authentication Policy Change';      Need = 'Success';             Ids = 4713, 4739;                          Severity = 'Medium';   Always = $false }
        @{ Guid = '{0CCE9231-69AE-11D9-BED3-505054503030}'; Name = 'Authorization Policy Change';       Need = 'Success';             Ids = 4704, 4705;                          Severity = 'Medium';   Always = $false }
        @{ Guid = '{0CCE9242-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Authentication Service';   Need = 'Success', 'Failure'; Ids = 4768, 4771;                          Severity = 'Critical'; Always = $false }
        @{ Guid = '{0CCE9240-69AE-11D9-BED3-505054503030}'; Name = 'Kerberos Service Ticket Operations';Need = 'Success', 'Failure'; Ids = 4769, 4770;                          Severity = 'High';     Always = $false }
        @{ Guid = '{0CCE923F-69AE-11D9-BED3-505054503030}'; Name = 'Credential Validation';             Need = 'Success', 'Failure'; Ids = 4776;                                Severity = 'Critical'; Always = $true }
        @{ Guid = '{0CCE922B-69AE-11D9-BED3-505054503030}'; Name = 'Process Creation';                  Need = 'Success';             Ids = 4688;                                Severity = 'High';     Always = $false }
        @{ Guid = '{0CCE9228-69AE-11D9-BED3-505054503030}'; Name = 'Sensitive Privilege Use';           Need = 'Success', 'Failure'; Ids = 4672, 4673, 4674;                    Severity = 'Medium';   Always = $false }
        @{ Guid = '{0CCE9244-69AE-11D9-BED3-505054503030}'; Name = 'File Share';                        Need = 'Failure';             Ids = 5140, 5145;                          Severity = 'Medium';   Always = $false }
    )

    # Which requirements matter for the selected profiles?
    $res = Get-WinSecResource
    $scopeIds = [System.Collections.Generic.HashSet[int]]::new()
    $scope = Get-WinSecEventIdsByScope -Profile $Profile
    foreach ($ids in $scope.LogEventIds.Values) { foreach ($i in $ids) { [void]$scopeIds.Add([int]$i) } }
    $active = foreach ($r in $requirements) {
        if ($r.Always -or (@($r.Ids | Where-Object { $scopeIds.Contains([int]$_) }).Count -gt 0)) { $r }
    }
    if (-not $active) { Write-Warning 'Selected profiles produced no audit requirements.' }
    $active = @($active)

    $collector = {
        try {
            $csv = auditpol /get /category:* /r 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $csv) { return @{ Error = "auditpol failed (exit $LASTEXITCODE). Elevation may be required."; Rows = @() } }
            # auditpol /r header is LOCALIZED; columns are positional and stable.
            # Machine Name, Policy Target, Subcategory, Subcategory GUID, Inclusion Setting, Exclusion Setting
            $rows = @($csv | Select-Object -Skip 1 | ConvertFrom-Csv -Header @('Machine', 'Target', 'Subcategory', 'Guid', 'Setting', 'Exclusion'))
            return @{ Error = $null; Rows = @($rows | ForEach-Object {
                    @{ Guid = $_.Guid; Name = $_.Subcategory; Setting = $_.Setting } }) }
        }
        catch { return @{ Error = $_.Exception.Message; Rows = @() } }
    }

    $hostPolicies = @{}
    if ($ComputerName) {
        # Scriptblocks cannot travel through $using: into ForEach-Object -Parallel.
        $collectorText = $collector.ToString()
        $results = $ComputerName | ForEach-Object -Parallel {
            $inner = [scriptblock]::Create($using:collectorText)
            $icp = @{ ScriptBlock = $inner; ErrorAction = 'Stop' }
            if ($using:Credential) { $icp.Credential = $using:Credential }
            try { $r = Invoke-Command -ComputerName $_ @icp }
            catch { $r = @{ Error = $_.Exception.Message; Rows = @() } }
            [pscustomobject]@{ Computer = $_; Policy = $r }
        } -ThrottleLimit $ThrottleLimit
        foreach ($r in $results) { $hostPolicies[$r.Computer] = $r.Policy }
    }
    else {
        $hostPolicies[([Environment]::MachineName ?? 'localhost')] = & $collector
    }

    foreach ($hostName in $hostPolicies.Keys) {
        $policy = $hostPolicies[$hostName]
        if ($policy.Error) {
            Write-Warning ("Audit policy unavailable on '{0}': {1}" -f $hostName, $policy.Error)
            continue
        }
        $byGuid = @{}
        foreach ($row in $policy.Rows) { if ($row.Guid) { $byGuid[$row.Guid.Trim().ToUpperInvariant()] = $row } }

        foreach ($req in $active) {
            $row = $byGuid[$req.Guid.ToUpperInvariant()]
            $current = $row ? [string]$row.Setting : 'Not reported'
            $currentTokens = @(($current -split '(,|\band\b)') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            $missing = @($req.Need | Where-Object { $_ -notin $currentTokens })

            $gap = [WinSecAuditGap]::new()
            $gap.Subcategory = $req.Name
            $gap.Guid = $req.Guid
            $gap.CurrentSetting = $current
            $gap.RequiredSetting = ($req.Need -join ' and ')
            $gap.AffectedEventIds = [int[]]$req.Ids
            $gap.Severity = [WinSecSeverity]$req.Severity

            if ($missing.Count -eq 0) {
                if ($IncludeCompliant) {
                    $gap.Severity = [WinSecSeverity]::Informational
                    $gap.Recommendation = 'Compliant.'
                    $gap | Add-Member -NotePropertyName Computer -NotePropertyValue $hostName -PassThru -Force
                }
                continue
            }

            $enable = ($req.Need | ForEach-Object { ('{0}:{1}' -f $_.ToLowerInvariant(), 'enable') }) -join ' /'
            $gap.Recommendation = ('Events {0} are NOT audited ({1} missing). Fix: auditpol /set /subcategory:"{2}" /{3}' -f
                ($req.Ids -join ','), ($missing -join '+'), $req.Guid, $enable)
            $gap | Add-Member -NotePropertyName Computer -NotePropertyValue $hostName -Force
            $gap
        }
    }
}
