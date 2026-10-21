#Requires -Version 7.6
#Requires -PSEdition Core
function New-WinSecAbuseReport {
    <#
    .SYNOPSIS
        Builds a ready-to-send abuse report for the network that hosts the
        attacking IP: RFC 5322 .eml with evidence attachments, plus Markdown and
        a structured JSON payload.

    .DESCRIPTION
        Network operators act on evidence, not adjectives. This cmdlet packages
        the facts an abuse desk needs — source address, ASN/PTR, UTC window,
        attempt counts, targeted accounts and hosts, event IDs, sample records —
        into three artifacts:

          EML   A complete MIME message with From/To/Subject/Date/Message-ID and
                base64 attachments (events.csv, evidence.json). Open it in any
                mail client and press Send; no SMTP configuration is required.
          MD    The same content for a ticket or a web form.
          JSON  Structured payload for APIs and ticketing systems.

        The recipient is resolved from the attribution data (ASN organisation,
        PTR) using a table of well-known abuse desks. Unknown networks produce
        an empty mailbox and NeedsContact = true: the tool never invents an
        address, and you must pass -ContactEmail.

        Account names can be pseudonymised with -RedactAccounts when the report
        leaves your organisation; the pseudonyms stay consistent inside one
        report so the timeline remains readable.

    .PARAMETER Case
        WinSecCase providing case id, title and subject IPs.

    .PARAMETER Event
        Collected events. Used for counts and evidence samples.

    .PARAMETER Finding
        Detections from Test-WinSecBruteForce. They drive the verdict and the
        summary sentence.

    .PARAMETER Attribution
        Enrichment from Resolve-WinSecIpAttribution — used for ASN, country,
        PTR and the abuse-desk lookup.

    .PARAMETER TargetIp
        Source address being reported. Defaults to the first subject IP of the
        case, else the most frequent SourceIp among events.

    .PARAMETER Provider
        Abuse desk to address. Auto (default) infers it from ASN/PTR; Generic
        requires -ContactEmail.

    .PARAMETER ContactEmail
        Explicit recipient. Overrides the built-in table.

    .PARAMETER ReporterName
        Display name of the sender. Defaults to 'Security Operations'.

    .PARAMETER ReporterEmail
        Sender address (required — it becomes the From header).

    .PARAMETER ReporterOrg
        Organisation name inserted into the body and the JSON payload.

    .PARAMETER Format
        Eml, Markdown, Json or All (default).

    .PARAMETER OutputDirectory
        Parent folder. Defaults to the DefaultOutputDirectory option, else the
        current directory.

    .PARAMETER FileName
        Base file name without extension.

    .PARAMETER RedactAccounts
        Replace account names with stable pseudonyms (acct-XXXXXX).

    .PARAMETER MaxEventsInBody
        How many sample events to embed in the message body (1-500, default 25).

    .PARAMETER PassThru
        Emit a descriptor with paths, recipient, SHA-256 and NeedsContact.

    .EXAMPLE
        $att = Resolve-WinSecIpAttribution -IpAddress 203.0.113.7 -Provider None
        New-WinSecAbuseReport -Case $case -Event $events -Attribution $att -ReporterEmail 'soc@contoso.com' -ReporterOrg 'Contoso SOC' -Format All -PassThru

    .EXAMPLE
        New-WinSecAbuseReport -Event $events -TargetIp 203.0.113.7 -Provider Hetzner -ReporterEmail 'ir@example.org' -RedactAccounts -Format Eml

    .EXAMPLE
        New-WinSecAbuseReport -Event $events -TargetIp 198.51.100.9 -Provider Generic -ContactEmail 'abuse@example.net' -ReporterEmail 'soc@contoso.com' -Format Json

    .OUTPUTS
        PSCustomObject with -PassThru; otherwise paths go to the information
        stream.

    .NOTES
        The .eml body is plain text on purpose: abuse desks often process
        messages with scripts, and HTML-only reports are frequently filtered.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([pscustomobject])]
    param(
        [WinSecCase] $Case,
        [object[]] $Event,
        [object[]] $Finding,
        [object[]] $Attribution,

        [string] $TargetIp,

        [ValidateSet('Auto', 'Generic', 'AWS', 'Azure', 'GCP', 'DigitalOcean', 'Hetzner', 'OVH', 'Cloudflare', 'Contabo', 'Linode', 'Vultr', 'Oracle', 'Alibaba', 'Tencent')]
        [string] $Provider = 'Auto',

        [string] $ContactEmail,
        [string] $ReporterName = 'Security Operations',

        [Parameter(Mandatory)]
        [ValidatePattern('^[^@\s]+@[^@\s]+\.[^@\s]+$')]
        [string] $ReporterEmail,

        [string] $ReporterOrg,

        [ValidateSet('Eml', 'Markdown', 'Json', 'All')]
        [string] $Format = 'All',

        [string] $OutputDirectory,
        [string] $FileName,

        [switch] $RedactAccounts,

        [ValidateRange(1, 500)]
        [int] $MaxEventsInBody = 25,

        [switch] $PassThru
    )

    $config = Get-WinSecConfig
    if (-not $OutputDirectory) { $OutputDirectory = [string]$config.DefaultOutputDirectory }
    if (-not $OutputDirectory) { $OutputDirectory = (Get-Location).Path }

    $ctx = Get-WinSecCaseContext -Case $Case -Event $Event -Finding $Finding -Attribution $Attribution
    $Case = $ctx.Case

    if (-not $TargetIp) {
        $TargetIp = @($Case.SubjectIps | Where-Object { $_ -and $_ -ne '(none)' } | Select-Object -First 1)
        if (-not $TargetIp) {
            $TargetIp = @($ctx.Events | ForEach-Object { $_.SourceIp } | Where-Object { $_ } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1 -ExpandProperty Name)
        }
    }
    if (-not $TargetIp) { throw [ArgumentException]::new('No target IP: pass -TargetIp or investigate at least one event with a source address.') }

    $attrib = @($Attribution | Where-Object { $_ -and $_.PSObject.Properties['IpAddress'] -and $_.IpAddress -eq $TargetIp } | Select-Object -First 1)
    if (-not $attrib) { $attrib = @($Attribution | Where-Object { $_ } | Select-Object -First 1) }
    $attribObj = $attrib.Count ? $attrib[0] : $null

    $contact = Get-WinSecAbuseContact -Provider $Provider -Attribution $attribObj -ContactEmail $ContactEmail

    $scoped = @($ctx.Events | Where-Object { $_.SourceIp -eq $TargetIp -or $_.MatchedIp -eq $TargetIp -or $_.DestinationIp -eq $TargetIp })
    if ($scoped.Count -eq 0) { $scoped = @($ctx.Events) }

    # ---- pseudonymisation ----------------------------------------------------
    $alias = @{}
    $mask = {
        param([string]$v)
        if (-not $v) { return $v }
        if (-not $RedactAccounts) { return $v }
        if (-not $alias.ContainsKey($v)) {
            $h = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData(
                    [System.Text.Encoding]::UTF8.GetBytes($v.ToLowerInvariant()))).Substring(0, 6).ToLowerInvariant()
            $alias[$v] = "acct-$h"
        }
        return $alias[$v]
    }

    $eventIds = @($scoped | Group-Object EventId | Sort-Object Count -Descending)
    $accounts = @($scoped | ForEach-Object { $_.TargetAccount, $_.SubjectAccount } | Where-Object { $_ } | Sort-Object -Unique)
    $hosts    = @($scoped | ForEach-Object { $_.Computer } | Where-Object { $_ } | Sort-Object -Unique)
    $first = ($scoped | Measure-Object TimeUtc -Minimum).Minimum
    $last  = ($scoped | Measure-Object TimeUtc -Maximum).Maximum
    $successCount = @($scoped | Where-Object { [string]$_.Outcome -eq 'Success' }).Count
    $failureCount = @($scoped | Where-Object { [string]$_.Outcome -eq 'Failure' }).Count

    $subjectLine = 'Abuse report: authentication abuse from {0} against {1} ({2} UTC)' -f
        $TargetIp, ($ReporterOrg ? $ReporterOrg : 'our network'), (Format-WinSecUtc $first 'yyyy-MM-dd')

    # ---- plain-text body ------------------------------------------------------
    $body = [System.Text.StringBuilder]::new()
    $add = { param([string]$s = '') $null = $body.AppendLine($s) }
    & $add 'To the network abuse desk,'
    & $add
    & $add ('We are reporting abusive authentication activity that originates from an address in your network: {0}.' -f $TargetIp)
    & $add 'The activity was observed in Windows security event logs and is documented below with UTC timestamps.'
    & $add
    & $add 'SOURCE'
    & $add ('  IP address      : {0}' -f $TargetIp)
    if ($attribObj) {
        & $add ('  ASN / operator  : AS{0} {1}' -f $attribObj.Asn, $attribObj.AsnOrganization)
        & $add ('  Country         : {0}' -f $attribObj.Country)
        & $add ('  Reverse DNS     : {0}' -f ($attribObj.PtrHostname ?? '—'))
        if ($attribObj.AbuseConfidenceScore) { & $add ('  AbuseIPDB score : {0}/100 ({1} reports)' -f $attribObj.AbuseConfidenceScore, $attribObj.TotalReports) }
    }
    & $add
    & $add 'ACTIVITY'
    & $add ('  Observed window : {0} → {1} UTC' -f (Format-WinSecUtc $first), (Format-WinSecUtc $last))
    & $add ('  Records         : {0} ({1} failures, {2} successes)' -f $scoped.Count, $failureCount, $successCount)
    & $add ('  Targeted hosts  : {0}' -f ($hosts -join ', '))
    & $add ('  Targeted accounts: {0}' -f (($accounts | ForEach-Object { & $mask $_ }) -join ', '))
    & $add ('  Event IDs       : {0}' -f (($eventIds | ForEach-Object { '{0}×{1}' -f $_.Name, $_.Count }) -join ', '))
    & $add
    & $add ('ASSESSMENT')
    & $add ('  {0} (severity {1}, confidence {2}).' -f $ctx.Verdict, $ctx.Severity, $ctx.Confidence)
    if (@($ctx.Findings).Count -gt 0) {
        foreach ($f in @($ctx.Findings | Select-Object -First 5)) {
            & $add ('  - {0}: {1} failure(s), {2} success(es), target {3} — {4} → {5} UTC' -f
                $f.Pattern, $f.FailureCount, $f.SuccessCount, (& $mask $f.TargetAccount),
                (Format-WinSecUtc $f.FirstSeenUtc), (Format-WinSecUtc $f.LastSeenUtc))
        }
    }
    & $add
    & $add ('SAMPLE EVENTS (first {0} of {1})' -f [Math]::Min($MaxEventsInBody, $scoped.Count), $scoped.Count)
    foreach ($e in @($scoped | Sort-Object TimeUtc | Select-Object -First $MaxEventsInBody)) {
        & $add ('  {0}  {1,-5} {2,-12} {3,-22} from {4}  status {5}' -f
            (Format-WinSecUtc $e.TimeUtc), $e.EventId, ($e.Computer ?? '-'),
            (& $mask ($e.TargetAccount ?? '-')), ($e.SourceIp ?? '-'), ($e.StatusCode ?? '-'))
    }
    & $add
    & $add 'REQUESTED ACTION'
    & $add '  1. Confirm whether the address was used by your customer or is compromised.'
    & $add '  2. Apply mitigation and notify the responsible party.'
    & $add '  3. Reply with a ticket reference so we can correlate further attempts.'
    & $add
    & $add 'The attached CSV/JSON contain the machine-readable evidence. Personal data is limited to'
    & $add 'account names required to demonstrate the attack; please handle the report accordingly.'
    & $add
    & $add 'Regards,'
    & $add ('{0}{1}' -f $ReporterName, ($ReporterOrg ? " — $ReporterOrg" : ''))
    & $add $ReporterEmail
    if ($Case.CaseId) { & $add ('Case reference: {0}' -f $Case.CaseId) }
    $bodyText = $body.ToString()

    # ---- attachments ----------------------------------------------------------
    # Redaction must apply to the machine-readable evidence too, not only to
    # the body: the events array is the easiest place to leak an account name.
    $eventRows = foreach ($e in ($scoped | Sort-Object TimeUtc)) {
        $h = $e.ToHashtable($false)
        $h['TargetAccount']  = & $mask $h['TargetAccount']
        $h['SubjectAccount'] = & $mask $h['SubjectAccount']
        $h
    }
    $csvText = (@($eventRows | ForEach-Object { [pscustomobject]$_ }) | ConvertTo-Csv -NoTypeInformation) -join "`n"
    $jsonObj = [ordered]@{
        reportVersion = '1.0'
        generatedUtc  = [datetime]::UtcNow.ToString('o')
        caseId        = $Case.CaseId
        reporter      = [ordered]@{ name = $ReporterName; email = $ReporterEmail; organization = $ReporterOrg }
        source        = [ordered]@{
            ip = $TargetIp
            asn = $attribObj ? $attribObj.Asn : $null
            asnOrganization = $attribObj ? $attribObj.AsnOrganization : $null
            country = $attribObj ? $attribObj.Country : $null
            ptr = $attribObj ? $attribObj.PtrHostname : $null
            abuseConfidenceScore = $attribObj ? $attribObj.AbuseConfidenceScore : 0
        }
        target        = [ordered]@{ organization = $ReporterOrg; hosts = $hosts; accounts = @($accounts | ForEach-Object { & $mask $_ }) }
        summary       = [ordered]@{
            verdict = $ctx.Verdict; severity = $ctx.Severity; confidence = $ctx.Confidence
            firstUtc = (Format-WinSecUtc $first); lastUtc = (Format-WinSecUtc $last)
            records = $scoped.Count; failures = $failureCount; successes = $successCount
            eventIds = @($eventIds | ForEach-Object { [int]$_.Name })
        }
        indicators    = [ordered]@{ ips = @($ctx.Iocs.IpAddresses.Value); hosts = $hosts; accounts = @($accounts | ForEach-Object { & $mask $_ }) }
        events        = @($eventRows | Select-Object -First 200)
    }
    $jsonText = $jsonObj | ConvertTo-Json -Depth 6

    # ---- Markdown -------------------------------------------------------------
    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# Abuse report — $TargetIp")
    $null = $md.AppendLine()
    $null = $md.AppendLine(('**To:** {0} <{1}>  ' -f $contact.Display, ($contact.Mailbox ? $contact.Mailbox : '(not resolved)')))
    $null = $md.AppendLine(('**From:** {0} <{1}>  ' -f $ReporterName, $ReporterEmail))
    $null = $md.AppendLine(('**Case:** {0}  ' -f $Case.CaseId))
    $null = $md.AppendLine(('**Generated:** {0} UTC' -f (Format-WinSecUtc ([datetime]::UtcNow))))
    $null = $md.AppendLine()
    $null = $md.AppendLine('```text')
    $null = $md.AppendLine($bodyText.TrimEnd())
    $null = $md.AppendLine('```')

    # ---- EML ------------------------------------------------------------------
    $eml = New-WinSecEmlMessage -From ('"{0}" <{1}>' -f $ReporterName, $ReporterEmail) `
        -To ($contact.Mailbox ? ('"{0}" <{1}>' -f $contact.Display, $contact.Mailbox) : 'undisclosed-recipients:;') `
        -Subject $subjectLine -Body $bodyText -ReplyTo $ReporterEmail `
        -Attachment @(
            @{ Name = 'events.csv'; ContentType = 'text/csv'; Content = $csvText }
            @{ Name = 'evidence.json'; ContentType = 'application/json'; Content = $jsonText }
        )

    # ---- write ----------------------------------------------------------------
    $base = if ($FileName) { [System.IO.Path]::GetFileNameWithoutExtension($FileName) }
            else { '{0}-abuse-{1}' -f $Case.CaseId, ($TargetIp -replace '[^0-9A-Za-z._-]', '_') }
    $caseDir = Join-Path $OutputDirectory ($Case.CaseId + '-reports')

    $formats = switch ($Format) { 'All' { @('Eml', 'Markdown', 'Json') } default { @($Format) } }
    $written = [System.Collections.Generic.List[object]]::new()
    foreach ($fmt in $formats) {
        $ext = switch ($fmt) { 'Eml' { 'eml' } 'Markdown' { 'md' } default { 'json' } }
        $path = Join-Path $caseDir ("{0}.{1}" -f $base, $ext)
        if (-not $PSCmdlet.ShouldProcess($path, "Write $fmt abuse report")) { continue }

        $content = switch ($fmt) { 'Eml' { $eml } 'Markdown' { $md.ToString() } default { $jsonText } }
        $null = Write-WinSecFileAtomic -Path $path -Content $content -Crlf:($fmt -eq 'Eml')
        $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        $written.Add([pscustomobject]@{ Format = $fmt; Path = $path; Sha256 = $hash; Bytes = (Get-Item -LiteralPath $path).Length })
        Write-Information ("Abuse report ({0}) written to {1}" -f $fmt, $path) -InformationAction Continue
    }

    $result = [pscustomobject]@{
        CaseId       = $Case.CaseId
        TargetIp     = $TargetIp
        Provider     = $contact.Provider
        Recipient    = $contact.Mailbox
        NeedsContact = $contact.NeedsContact
        Subject      = $subjectLine
        Verdict      = $ctx.Verdict
        Severity     = $ctx.Severity
        Files        = @($written)
    }
    if ($contact.NeedsContact) {
        Write-Warning ("Abuse mailbox for provider '{0}' is unknown. Re-run with -ContactEmail to address the report." -f $contact.Provider)
    }
    if ($PassThru -or $written.Count -eq 0) { return $result }
}

