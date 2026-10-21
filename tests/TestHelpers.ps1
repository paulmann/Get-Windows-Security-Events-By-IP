# WinSecHunter — shared Pester helpers (Pester 5)
# Dot-source from BeforeAll blocks: . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

$script:WinSecTestRoot = Split-Path -Parent $PSScriptRoot
$script:WinSecManifestPath = Join-Path $script:WinSecTestRoot 'src/WinSecHunter/WinSecHunter.psd1'

function Initialize-WinSecTestModule {
    if (Get-Module WinSecHunter) { Remove-Module WinSecHunter -Force }
    Import-Module $script:WinSecManifestPath -Force
    # Isolate configuration into a temp dir for the whole test run.
    $cfgDir = Join-Path ([System.IO.Path]::GetTempPath()) ("winsechunter-tests-" + [guid]::NewGuid().ToString('n'))
    $null = New-Item -ItemType Directory -Path $cfgDir -Force
    $env:WINSECHUNTER_CONFIG_DIR = $cfgDir
}

<#
    Builds a typed WinSecEvent inside module scope (classes are module-scoped).
#>
function New-TestEvent {
    [CmdletBinding()]
    param(
        [int] $EventId = 4625,
        [string] $Computer = 'SRV01',
        [string] $LogName = 'Security',
        [AllowNull()][datetime] $TimeUtc,
        [string] $SourceIp = '203.0.113.7',
        [string] $TargetAccount = 'CORP\alice',
        [ValidateSet('Unknown', 'Success', 'Failure', 'Informational')]
        [string] $Outcome = 'Failure',
        [int] $LogonType = 3,
        [string] $LogonId = '0x12345',
        [long] $RecordId = 1,
        [string] $StatusCode = '',
        [string] $MatchedIp = '203.0.113.7'
    )

    $p = @{
        EventId = $EventId; Computer = $Computer; LogName = $LogName
        TimeUtc = $TimeUtc ?? [datetime]::UtcNow
        SourceIp = $SourceIp; TargetAccount = $TargetAccount; Outcome = $Outcome
        LogonType = $LogonType; LogonId = $LogonId; RecordId = $RecordId
        StatusCode = $StatusCode; MatchedIp = $MatchedIp
    }

    & (Get-Module WinSecHunter) {
        param($p)
        $e = [WinSecEvent]::new()
        $e.Computer      = $p.Computer
        $e.LogName       = $p.LogName
        $e.EventId       = $p.EventId
        $e.TimeUtc       = $p.TimeUtc
        $e.TimeCreated   = $p.TimeUtc.ToLocalTime()
        $e.SourceIp      = $p.SourceIp
        $e.TargetAccount = $p.TargetAccount
        $e.Outcome       = [WinSecOutcome]$p.Outcome
        if ($p.LogonType -gt 0) { $e.LogonType = [WinSecLogonType]$p.LogonType }
        $e.LogonId    = $p.LogonId
        $e.RecordId   = $p.RecordId
        $e.StatusCode = $p.StatusCode
        $e.MatchedIp  = $p.MatchedIp
        $e.Data       = @{}
        $info = Get-WinSecEventInfo -EventId $p.EventId -LogName $p.LogName
        if ($info) {
            $e.Category   = [WinSecEventCategory]$info['Category']
            $e.Importance = [WinSecSeverity]$info['Importance']
            $e.EventName  = $info['Name']
            $e.AttackIds  = [string[]]@($info['Attack'])
        }
        else {
            $e.EventName = "Event $($p.EventId)"
        }
        return $e
    } $p
}
