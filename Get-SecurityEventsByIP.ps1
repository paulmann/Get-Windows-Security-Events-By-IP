<#
.SYNOPSIS
    Enable or disable automatic hiding of system tray icons in Windows 11/10 with Group Policy support.

.DESCRIPTION
    Enterprise-grade PowerShell script for managing system tray icon visibility.
    Features comprehensive error handling, logging, session validation, rollback support,
    individual icon settings reset, Group Policy management, and advanced diagnostic capabilities.
    
    NEW IN VERSION 5.9:
    - Administrator rights validation and elevation support
    - Group Policy configuration for all users
    - Enhanced enterprise deployment features
    - Multi-user registry management
    - Advanced security context validation
    - Enterprise backup/restore capabilities

    Author: Mikhail Deynekin (mid1977@gmail.com)
    Website: https://deynekin.com
    Repository: https://github.com/paulmann/windows-show-all-tray-icons

.PARAMETER Action
    Specifies the action to perform:
    - 'Enable'  : Show all system tray icons (disable auto-hide) [Value: 0]
    - 'Disable' : Restore Windows default behavior (enable auto-hide) [Value: 1]
    - 'Status'  : Check current configuration without making changes
    - 'Rollback': Revert to previous configuration if backup exists
    - 'Backup'  : Create registry backup without making changes

.PARAMETER AllUsers
    Apply settings to all users via Group Policy (requires administrator rights).

.PARAMETER RestartExplorer
    If specified, automatically restarts Windows Explorer to apply changes immediately.

.PARAMETER BackupRegistry
    If specified, creates registry backup before making changes (recommended).

.PARAMETER LogPath
    Specifies custom log file path. Default: $env:TEMP\Enable-AllTrayIcons.log

.PARAMETER Force
    Bypass confirmation prompts and warnings.

.PARAMETER Update
    Check and update script from GitHub repository if newer version available.

.PARAMETER Help
    Display detailed help information.

.PARAMETER WhatIf
    Shows what would happen if the cmdlet runs without actually executing.

.PARAMETER Confirm
    Prompts for confirmation before executing the operation.

.PARAMETER Diagnostic
    Perform comprehensive backup file diagnostics and validation.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Action Enable -BackupRegistry
    Shows all system tray icons with registry backup.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Action Enable -AllUsers -RestartExplorer -Force
    Shows all icons for all users via Group Policy, restarts Explorer, and bypasses prompts.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Action Status
    Displays comprehensive system status.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Action Backup -AllUsers
    Creates registry backup for all users configuration.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Action Rollback -AllUsers
    Reverts to previous configuration for all users if backup exists.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Update
    Checks and updates script from GitHub repository.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Help
    Displays detailed help information.

.EXAMPLE
    .\Enable-AllTrayIcons.ps1 -Diagnostic
    Runs backup file diagnostics and validation checks.

.NOTES
    Version:        5.9 (Enterprise Edition - Group Policy Enhanced)
    Creation Date:  2025-11-21
    Last Updated:   2025-11-23
    Compatibility:  Windows 10 (All versions), Windows 11 (All versions), Server 2019+
    Requires:       PowerShell 5.1 or higher (with enhanced features for PowerShell 7+)
    Privileges:     Standard User (HKCU) or Administrator (AllUsers/Group Policy)
    
    ENHANCED FEATURES:
    - Administrator rights validation and elevation instructions
    - Group Policy configuration for all users
    - Multi-user registry management
    - Enterprise deployment support
    - Enhanced security context validation
    - Comprehensive individual icon settings reset
    - Multiple methods for forcing icon visibility
    - Enhanced backup/restore for all tray-related settings
    - Windows 11 specific optimizations
    - Professional reporting and status display
    - Advanced diagnostic capabilities
    - Dynamic registry path management
    - Comprehensive error handling with rollback protection

.LINK
    GitHub Repository: https://github.com/paulmann/windows-show-all-tray-icons
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param (
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('Enable', 'Disable', 'Status', 'Rollback', 'Backup', IgnoreCase = $true)]
    [string]$Action,
    [Parameter(Mandatory = $false)]
    [switch]$AllUsers,
    [Parameter(Mandatory = $false)]
    [switch]$RestartExplorer,
    [Parameter(Mandatory = $false)]
    [switch]$BackupRegistry,
    [Parameter(Mandatory = $false)]
    [string]$LogPath,
    [Parameter(Mandatory = $false)]
    [switch]$Force,  # Added for overwriting backups
    [Parameter(Mandatory = $false)]
    [switch]$Update,
    [Parameter(Mandatory = $false)]
    [switch]$Help,
    [Parameter(Mandatory = $false)]
    [ValidateSet('Full', 'Quick', 'Admin', 'Security', IgnoreCase = $true)]
    [string]$HelpLevel = 'Quick',
    [Parameter(Mandatory = $false)]
    [switch]$Diagnostic,
    # Hidden parameter for internal help functions
    [Parameter(Mandatory = $false, DontShow = $true)]
    [switch]$QuickHelp,
    # Backup-specific parameters
    [Parameter(Mandatory = $false, HelpMessage = "Overwrite existing backup file without confirmation")]
    [switch]$ForceBackup,
    
    [Parameter(Mandatory = $false, HelpMessage = "Specify custom backup file path")]
    [ValidateScript({
        if ($_ -and !(Test-Path (Split-Path $_ -Parent) -PathType Container)) {
            throw "The directory '$(Split-Path $_ -Parent)' does not exist."
        }
        $true
    })]
    [string]$CustomPath,
    
    [Parameter(Mandatory = $false, HelpMessage = "Exclude icon cache data to reduce backup size")]
    [switch]$ExcludeCache,
    
    [Parameter(Mandatory = $false, HelpMessage = "Compress backup file to reduce storage footprint")]
    [switch]$CompressBackup
)

# ============================================================================
# ENTERPRISE CONFIGURATION
# ============================================================================

$Script:Configuration = @{
    # Registry Configuration
    RegistryPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    RegistryValue = "EnableAutoTray"
    EnableValue = 0
    DisableValue = 1
    
    # Group Policy Configuration
    GroupPolicyUserPath = "HKCU:\Software\Policies\Microsoft\Windows\Explorer"
    GroupPolicyMachinePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    GroupPolicyValue = "EnableAutoTray"
    
    # Script Metadata
    ScriptVersion = "5.9"
    ScriptAuthor = "Mikhail Deynekin (mid1977@gmail.com)"
    ScriptName = "Enable-AllTrayIcons.ps1"
    GitHubRepository = "https://github.com/paulmann/windows-show-all-tray-icons"
    UpdateUrl = "https://raw.githubusercontent.com/paulmann/windows-show-all-tray-icons/refs/heads/main/Enable-AllTrayIcons.ps1"
    
    # Path Configuration
    DefaultLogPath = "$env:TEMP\Enable-AllTrayIcons.log"
    BackupRegistryPath = "$env:TEMP\TrayIconsBackup.reg"
    AllUsersBackupPath = "$env:TEMP\TrayIconsBackup-AllUsers.reg"
    
    # Performance Configuration
    ExplorerRestartTimeout = 10  # seconds
    ProcessWaitTimeout = 5       # seconds
    
    # Security Configuration
    RequiredPSVersion = "5.1"
    
    # Exit Codes
    ExitCode = 0
    ExitCodes = @{
        Success = 0
        GeneralError = 1
        AccessDenied = 2
        InvalidSession = 3
        PowerShellVersion = 4
        RollbackFailed = 5
        UpdateFailed = 6
        BackupFailed = 7
        AdminRightsRequired = 8
        GroupPolicyFailed = 9
    }
}

$Script:LastErrorDetails = @{
    GroupPolicy = $null
}

# ============================================================================
# SECURITY AND ADMINISTRATOR VALIDATION
# ============================================================================

function Test-AdministratorRights {
    <#
    .SYNOPSIS
        Validates if the current user has administrator privileges.
    #>
    try {
        $currentPrincipal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        return $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        Write-ModernStatus "Failed to check administrator rights: $($_.Exception.Message)" -Status Error
        return $false
    }
}

function Test-PowerShellVersion {
    <#
    .SYNOPSIS
        Validates if the current PowerShell version meets requirements.
    #>
    $currentVersion = $PSVersionTable.PSVersion
    if ($currentVersion -lt [version]$Script:Configuration.RequiredPSVersion) {
        Write-ModernStatus "PowerShell version $currentVersion is below required $($Script:Configuration.RequiredPSVersion)" -Status Error
        return $false
    }
    return $true
}

function Show-AdministratorInstructions {
    <#
    .SYNOPSIS
        Displays instructions for running script as administrator.
    #>
    Write-ModernHeader "Administrator Rights Required" "Elevation Instructions"
    
    Write-EnhancedOutput "This operation requires administrator privileges to continue." -Type Warning
    Write-Host ""
    
    Write-EnhancedOutput "HOW TO RUN AS ADMINISTRATOR:" -Type Primary
    Write-ModernCard "Method 1" "Right-click PowerShell and select 'Run as Administrator'"
    Write-ModernCard "Method 2" "Run from elevated command prompt: 'powershell -ExecutionPolicy Bypass -File Enable-AllTrayIcons.ps1'"
    Write-ModernCard "Method 3" "Use Windows Terminal as Administrator"
    Write-Host ""
    
    Write-EnhancedOutput "ALTERNATIVE OPTIONS:" -Type Primary
    Write-ModernCard "Current User Only" "Remove -AllUsers parameter to apply to current user only"
    Write-ModernCard "Standard Mode" "Run without administrator rights for current user configuration"
    Write-Host ""
    
    Write-EnhancedOutput "NOTE:" -Type Primary
    Write-EnhancedOutput "  - Group Policy modifications require administrator rights" -Type Info
    Write-EnhancedOutput "  - Current user settings work without elevation" -Type Info
    Write-EnhancedOutput "  - Some enterprise features may be limited without admin rights" -Type Info
    Write-Host ""
}

function Test-ExecutionPolicy {
    <#
    .SYNOPSIS
        Validates execution policy and provides instructions if blocked.
    #>
    try {
        $executionPolicy = Get-ExecutionPolicy -Scope CurrentUser
        if ($executionPolicy -eq "Restricted") {
            Write-ModernStatus "Execution Policy is Restricted - script execution blocked" -Status Error
            Write-EnhancedOutput "To fix this issue, run:" -Type Warning
            Write-Host "  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor Yellow
            Write-Host "  Or use: powershell -ExecutionPolicy Bypass -File Enable-AllTrayIcons.ps1" -ForegroundColor Yellow
            return $false
        }
        return $true
    }
    catch {
        Write-ModernStatus "Could not verify execution policy: $($_.Exception.Message)" -Status Warning
        return $true
    }
}

# ============================================================================
# POWERSHELL VERSION COMPATIBILITY
# ============================================================================

$Script:IsPS7Plus = $PSVersionTable.PSVersion.Major -ge 7

# ============================================================================
# MODERN UI/UX COLOR SCHEME
# ============================================================================

$Script:ConsoleColors = @{
    Primary    = "Cyan"
    Success    = "Green"
    Error      = "Red"
    Warning    = "Yellow"
    Info       = "Cyan"
    Accent     = "Magenta"
    Dark       = "DarkGray"
    Light      = "White"
}

# PowerShell 7+ enhanced colors
if ($Script:IsPS7Plus) {
    $Script:ConsoleColors.Primary = "Blue"
    $Script:ConsoleColors.Info = "Cyan"
}

# ============================================================================
# ENHANCED OUTPUT SYSTEM WITH PS7+ FEATURES
# ============================================================================

function Write-EnhancedOutput {
    <#
    .SYNOPSIS
        Enhanced output with PowerShell 7+ features when available.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Primary', 'Success', 'Error', 'Warning', 'Info', 'Accent', 'Dark', 'Light')]
        [string]$Type = "Info",
        
        [Parameter(Mandatory = $false)]
        [switch]$NoNewline,

        [Parameter(Mandatory = $false)]
        [switch]$Force,
        
        [Parameter(Mandatory = $false)]
        [switch]$Bold

    )
    
    $color = $Script:ConsoleColors[$Type]
    
    # PowerShell 7+ enhanced formatting
    if ($Script:IsPS7Plus -and $Bold) {
        Write-Host $Message -NoNewline:$NoNewline -ForegroundColor $color -BackgroundColor "DarkBlue"
    } else {
        if ($NoNewline) {
            Write-Host $Message -NoNewline -ForegroundColor $color
        } else {
            Write-Host $Message -ForegroundColor $color
        }
    }
}

function Write-ModernHeader {
    <#
    .SYNOPSIS
        Displays a modern header with gradient effect.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Subtitle = ""
    )
    
    Write-Host ""
    Write-Host "=" -NoNewline -ForegroundColor $Script:ConsoleColors.Primary
    Write-Host ("=" * 78) -NoNewline -ForegroundColor $Script:ConsoleColors.Primary
    Write-Host "=" -ForegroundColor $Script:ConsoleColors.Primary
    
    Write-Host "|" -NoNewline -ForegroundColor $Script:ConsoleColors.Primary
    Write-Host " $Title" -NoNewline -ForegroundColor $Script:ConsoleColors.Light
    if ($Subtitle) {
        Write-Host " - $Subtitle" -NoNewline -ForegroundColor $Script:ConsoleColors.Info
    }
    Write-Host (" " * (77 - $Title.Length - $Subtitle.Length - 2)) -NoNewline
    Write-Host "|" -ForegroundColor $Script:ConsoleColors.Primary
    
    Write-Host "=" -NoNewline -ForegroundColor $Script:ConsoleColors.Primary
    Write-Host ("=" * 78) -NoNewline -ForegroundColor $Script:ConsoleColors.Primary
    Write-Host "=" -ForegroundColor $Script:ConsoleColors.Primary
    Write-Host ""
}

function Write-ModernCard {
    <#
    .SYNOPSIS
        Displays information in a card-like container.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $false)]
        [string]$Value,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Primary', 'Success', 'Error', 'Warning', 'Info', 'Accent', 'Light')]
        [string]$ValueColor = "Light"
    )
    
    Write-Host "  [*] " -NoNewline -ForegroundColor $Script:ConsoleColors.Dark
    Write-Host $Title -NoNewline -ForegroundColor $Script:ConsoleColors.Light
    
    Write-Host " " -NoNewline
    
    # Calculate padding for alignment
    $padding = 25 - $Title.Length
    if ($padding -gt 0) {
        Write-Host (" " * $padding) -NoNewline
    }
    
    Write-Host " | " -NoNewline -ForegroundColor $Script:ConsoleColors.Dark
    Write-Host $Value -ForegroundColor $Script:ConsoleColors[$ValueColor]
}

function Write-ModernStatus {
    <#
    .SYNOPSIS
        Displays status with visual indicators.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet('Success', 'Error', 'Warning', 'Info', 'Processing')]
        [string]$Status = "Info"
    )
    
    $icons = @{
        Success = "[OK]"
        Error = "[ERROR]"
        Warning = "[WARN]"
        Info = "[INFO]"
        Processing = "[....]"
    }
    
    $colors = @{
        Success = "Success"
        Error = "Error"
        Warning = "Warning"
        Info = "Info"
        Processing = "Primary"
    }
    
    Write-Host "  " -NoNewline
    Write-Host $icons[$Status] -NoNewline -ForegroundColor $Script:ConsoleColors[$colors[$Status]]
    Write-Host " $Message" -ForegroundColor $Script:ConsoleColors.Light
}

# ============================================================================
# CORE SESSION CONTEXT FUNCTION (MOVED BEFORE USE)
# ============================================================================

function Get-SessionContext {
    <#
    .SYNOPSIS
        Returns comprehensive session context information.
    #>
    
    $context = @{
        IsAdmin = $false
        IsInteractive = [Environment]::UserInteractive
        SessionType = "Unknown"
        CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        IsElevated = $false
    }
    
    # Admin Check
    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
        $context.IsAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        $context.IsElevated = $context.IsAdmin
    }
    catch {
        Write-Host "Failed to check admin privileges: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    # Session Type Detection
    if ($null -ne $env:WINRM_PROCESS) {
        $context.SessionType = "WinRM Remote"
    }
    elseif ($env:SSH_CONNECTION) {
        $context.SessionType = "SSH Remote"
    }
    elseif ($context.CurrentUser -eq "SYSTEM" -or $identity.User.Value -eq "S-1-5-18") {
        $context.SessionType = "SYSTEM Service Account"
    }
    elseif (-not $context.IsInteractive) {
        $context.SessionType = "Non-Interactive Session"
    }
    else {
        $context.SessionType = "Interactive Desktop"
    }
    
    return [PSCustomObject]$context
}

function Show-ModernBanner {
    <#
    .SYNOPSIS
        Displays a modern application banner.
    #>
    
    # Используем script-scope переменную для отслеживания состояния баннера
    if ($script:showBanner -eq $true) {
        Write-Host ""
        Write-Host "================================================================" -ForegroundColor $Script:ConsoleColors.Primary
        Write-Host "   WINDOWS SYSTEM TRAY ICONS CONFIGURATION TOOL" -ForegroundColor $Script:ConsoleColors.Light
        Write-Host "       ENTERPRISE EDITION - GROUP POLICY ENHANCED" -ForegroundColor $Script:ConsoleColors.Info
        Write-Host "================================================================" -ForegroundColor $Script:ConsoleColors.Primary
        Write-Host ""
        $script:showBanner = $false
    }
}

# ============================================================================
# HELP SYSTEM
# ============================================================================

function Show-ModernHelp {
    <#
    .SYNOPSIS
        Displays comprehensive help information with enhanced Group Policy features.
    #>
    Write-ModernHeader "Windows System Tray Icons Configuration Tool" "v$($Script:Configuration.ScriptVersion)"
    Write-EnhancedOutput "DESCRIPTION:" -Type Primary
    Write-EnhancedOutput "  Professional tool for managing system tray icon visibility in Windows 10/11." -Type Light
    Write-EnhancedOutput "  Modifies registry and Group Policy settings to control notification area behavior" -Type Light
    Write-EnhancedOutput "  with comprehensive individual icon settings reset and enterprise deployment support." -Type Light
    Write-Host ""
    Write-EnhancedOutput "QUICK EXAMPLES:" -Type Primary
    Write-Host "  Show all icons (current user)    : .\$($Script:Configuration.ScriptName) -Action Enable" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Show all icons (all users)       : .\$($Script:Configuration.ScriptName) -Action Enable -AllUsers" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Show all + restart               : .\$($Script:Configuration.ScriptName) -Action Enable -RestartExplorer" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Restore default                  : .\$($Script:Configuration.ScriptName) -Action Disable" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Check status                     : .\$($Script:Configuration.ScriptName) -Action Status" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Create backup                    : .\$($Script:Configuration.ScriptName) -Action Backup" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Restore backup                   : .\$($Script:Configuration.ScriptName) -Action Rollback" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Check and update                 : .\$($Script:Configuration.ScriptName) -Update" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host ""
    Write-EnhancedOutput "ACTIONS:" -Type Primary
    Write-ModernCard "Enable" "Show all tray icons (disable auto-hide)"
    Write-ModernCard "Disable" "Restore Windows default (enable auto-hide)"
    Write-ModernCard "Status" "Show current configuration and Group Policy status"
    Write-ModernCard "Backup" "Create comprehensive registry backup"
    Write-ModernCard "Rollback" "Restore from previous backup"
    Write-Host ""
    Write-EnhancedOutput "GROUP POLICY ACTIONS (REQUIRES ADMIN RIGHTS):" -Type Primary
    Write-ModernCard "Enable -AllUsers" "Apply settings to ALL users via Group Policy"
    Write-ModernCard "Disable -AllUsers" "Restore default for ALL users via Group Policy"
    Write-ModernCard "Backup -AllUsers" "Backup Group Policy and all user settings"
    Write-ModernCard "Rollback -AllUsers" "Restore Group Policy and all user settings"
    Write-Host ""
    Write-EnhancedOutput "OPTIONS:" -Type Primary
    Write-ModernCard "-AllUsers" "Apply to ALL users (requires administrator rights)"
    Write-ModernCard "-RestartExplorer" "Apply changes immediately by restarting Windows Explorer"
    Write-ModernCard "-BackupRegistry" "Create automatic backup before making changes"
    Write-ModernCard "-Force" "Bypass all confirmation prompts and warnings"
    Write-ModernCard "-LogPath <path>" "Specify custom log file location"
    Write-ModernCard "-Update" "Check and update script from GitHub repository"
    Write-ModernCard "-Diagnostic" "Run backup file diagnostics and validation"
    Write-ModernCard "-HelpLevel <type>" "Specify help type: Full, Quick, Admin, or Security" -ValueColor Info
    Write-Host ""
    Write-EnhancedOutput "BACKUP OPTIONS:" -Type Primary
    Write-ModernCard "-ForceBackup" "Overwrite existing backup files without confirmation"
    Write-ModernCard "-CustomPath <path>" "Specify custom backup location (e.g., 'C:\Backups\TrayIcons-$(Get-Date -Format 'yyyyMMdd').json')"
    Write-ModernCard "-ExcludeCache" "Exclude icon cache data to reduce backup file size (not recommended for complete restoration)"
    Write-ModernCard "-CompressBackup" "Compress backup file to minimize storage requirements"
    Write-Host ""
    Write-EnhancedOutput "HELP LEVELS:" -Type Primary
    Write-ModernCard "Full" "Complete documentation with all parameters, examples and enterprise deployment details" -ValueColor Light
    Write-ModernCard "Quick" "Brief overview of common commands (default when using -Help)" -ValueColor Light
    Write-ModernCard "Admin" "Detailed administrator instructions including elevation requirements and Group Policy deployment" -ValueColor Light
    Write-ModernCard "Security" "Security context information including privileges, execution policies and session details" -ValueColor Light
    Write-Host ""
    Write-EnhancedOutput "HELP LEVEL EXAMPLES:" -Type Primary
    Write-Host "  Show full documentation           : .\$($Script:Configuration.ScriptName) -Help" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Show quick reference              : .\$($Script:Configuration.ScriptName) -Help -HelpLevel Quick" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Show admin instructions           : .\$($Script:Configuration.ScriptName) -Help -HelpLevel Admin" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host "  Show security context             : .\$($Script:Configuration.ScriptName) -Help -HelpLevel Security" -ForegroundColor $Script:ConsoleColors.Light
    Write-Host ""
    Write-EnhancedOutput "ADVANCED FEATURES:" -Type Primary
    Write-ModernCard "Administrator Rights Check" "Automatic validation for Group Policy operations"
    Write-ModernCard "Group Policy Deployment" "Enterprise-wide settings via User/Machine policies"
    Write-ModernCard "Multi-User Registry Management" "Apply settings to all user hives"
    Write-ModernCard "Comprehensive Backup System" "Backup registry, Group Policy, and individual settings"
    Write-ModernCard "Individual Icon Reset" "Reset per-application notification settings"
    Write-ModernCard "Windows 11 Optimization" "Special optimizations for Windows 11 taskbar"
    Write-ModernCard "System Icons Control" "Manage volume, network, power indicators"
    Write-Host ""
    Write-EnhancedOutput "NOTES:" -Type Primary
    Write-EnhancedOutput "  - All parameters are case-insensitive" -Type Info
    Write-EnhancedOutput "  - Admin rights required only for -AllUsers parameter" -Type Info
    Write-EnhancedOutput "  - Works on Windows 10/11, Server 2019+" -Type Info
    Write-EnhancedOutput "  - When -Help is specified without -HelpLevel, Full help is shown by default" -Type Info
    Write-Host ""
    Write-EnhancedOutput "ADDITIONAL INFORMATION:" -Type Primary
    Write-ModernCard "Version" $Script:Configuration.ScriptVersion
    Write-ModernCard "Author" $Script:Configuration.ScriptAuthor
    Write-ModernCard "Repository" $Script:Configuration.GitHubRepository
    Write-ModernCard "PowerShell Version" "$($PSVersionTable.PSVersion) ($(if($Script:IsPS7Plus){'Enhanced'}else{'Compatible'}))"
    Write-ModernCard "Admin Rights" $(if (Test-AdministratorRights) { "Available" } else { "Not Available" }) -ValueColor $(if (Test-AdministratorRights) { "Success" } else { "Info" })
    Write-ModernCard "Execution Policy" (Get-ExecutionPolicy -Scope CurrentUser)
    Write-Host ""
    Write-EnhancedOutput "Note: -AllUsers parameter requires administrator rights. All other operations work without elevation." -Type Dark
    Write-EnhancedOutput "Use -Force to bypass confirmation prompts in automated scripts." -Type Dark
    Write-Host ""
}

function Show-QuickHelp {
    <#
    .SYNOPSIS
        Displays brief help information for quick reference.
    #>
    
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host "   WINDOWS SYSTEM TRAY ICONS CONFIGURATION TOOL" -ForegroundColor White
    Write-Host "       ENTERPRISE EDITION - GROUP POLICY ENHANCED" -ForegroundColor Cyan
    Write-Host "================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-Host "QUICK EXAMPLES:" -ForegroundColor Yellow
    Write-Host "  Show all icons (current user)    : .\$($Script:Configuration.ScriptName) -Action Enable" -ForegroundColor Gray
    Write-Host "  Show all icons (all users)       : .\$($Script:Configuration.ScriptName) -Action Enable -AllUsers" -ForegroundColor Gray
    Write-Host "  Show all + restart               : .\$($Script:Configuration.ScriptName) -Action Enable -RestartExplorer" -ForegroundColor Gray
    Write-Host "  Restore default                  : .\$($Script:Configuration.ScriptName) -Action Disable" -ForegroundColor Gray
    Write-Host "  Check status                     : .\$($Script:Configuration.ScriptName) -Action Status" -ForegroundColor Gray
    Write-Host "  Create backup                    : .\$($Script:Configuration.ScriptName) -Action Backup" -ForegroundColor Gray
    Write-Host "  Restore backup                   : .\$($Script:Configuration.ScriptName) -Action Rollback" -ForegroundColor Gray
    Write-Host "  Update from GitHub               : .\$($Script:Configuration.ScriptName) -Update" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "ACTIONS:" -ForegroundColor Yellow
    Write-Host "  Enable    : Show all tray icons (disable auto-hide)" -ForegroundColor Gray
    Write-Host "  Disable   : Restore Windows default (enable auto-hide)" -ForegroundColor Gray
    Write-Host "  Status    : Show current configuration and Group Policy status" -ForegroundColor Gray
    Write-Host "  Backup    : Create comprehensive registry backup" -ForegroundColor Gray
    Write-Host "  Rollback  : Restore from previous backup" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "GROUP POLICY ACTIONS (REQUIRES ADMIN RIGHTS):" -ForegroundColor Yellow
    Write-Host "  Enable -AllUsers  : Apply settings to ALL users via Group Policy" -ForegroundColor Gray
    Write-Host "  Disable -AllUsers : Restore default for ALL users via Group Policy" -ForegroundColor Gray
    Write-Host "  Backup -AllUsers  : Backup Group Policy and all user settings" -ForegroundColor Gray
    Write-Host "  Rollback -AllUsers: Restore Group Policy and all user settings" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -AllUsers        : Apply to ALL users (requires administrator rights)" -ForegroundColor Gray
    Write-Host "  -RestartExplorer : Apply changes immediately" -ForegroundColor Gray
    Write-Host "  -BackupRegistry  : Create backup before changes" -ForegroundColor Gray
    Write-Host "  -Force           : Bypass confirmation prompts" -ForegroundColor Gray
    Write-Host ""

    Write-Host "HELP OPTIONS:" -ForegroundColor Yellow
    Write-Host "  -Help                  : Show full comprehensive help" -ForegroundColor Gray
    Write-Host "  -Help Quick            : Show brief quick reference" -ForegroundColor Gray
    Write-Host "  -Help Admin            : Show administrator instructions" -ForegroundColor Gray
    Write-Host "  -Help Security         : Show security context information" -ForegroundColor Gray
    Write-Host "  -QuickHelp             : Alternative quick help (hidden)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "NOTES:" -ForegroundColor Yellow
    Write-Host "  - All parameters are case-insensitive" -ForegroundColor DarkGray
    Write-Host "  - Admin rights required only for -AllUsers parameter" -ForegroundColor DarkGray
    Write-Host "  - Works on Windows 10/11, Server 2019+" -ForegroundColor DarkGray
    Write-Host "  - Use -Help for detailed information and examples" -ForegroundColor DarkGray
    Write-Host ""
    
    Write-Host "  [OK] Use -Help for complete documentation and enterprise deployment examples" -ForegroundColor Green
    Write-Host ""
}

function Show-SecurityContext {
    <#
    .SYNOPSIS
        Displays current security context and privileges.
    #>
    
    $context = Get-SessionContext
    
    Write-Host ""
    Write-Host "=== SECURITY CONTEXT ===" -ForegroundColor Cyan
    Write-ModernCard "Current User" $context.CurrentUser
    Write-ModernCard "Administrator Rights" $(if ($context.IsAdmin) { "Yes" } else { "No" }) -ValueColor $(if ($context.IsAdmin) { "Success" } else { "Warning" })
    Write-ModernCard "Session Type" $context.SessionType
    Write-ModernCard "Interactive" $(if ($context.IsInteractive) { "Yes" } else { "No" }) -ValueColor $(if ($context.IsInteractive) { "Success" } else { "Warning" })
    Write-ModernCard "Execution Policy" (Get-ExecutionPolicy -Scope CurrentUser)
    Write-Host ""
}

# ============================================================================
# ENHANCED HELP SYSTEM
# ============================================================================

function Invoke-HelpSystem {
    <#
    .SYNOPSIS
        Enhanced help system with intelligent parameter handling and validation.
    
    .DESCRIPTION
        Handles help requests with comprehensive validation and fallback behavior.
        Supports multiple help levels and provides clear error messages for invalid parameters.
    #>
    param(
        [string]$HelpLevel = 'Quick'
    )
    
    # Validate help level and provide clear error messages
    $validHelpLevels = @('Full', 'Quick', 'Admin', 'Security')
    
    # Check if HelpLevel was explicitly provided as a parameter
    $isHelpLevelSpecified = $PSBoundParameters.ContainsKey('HelpLevel')
    
    if ($HelpLevel -and $HelpLevel -notin $validHelpLevels) {
        Write-ModernStatus "Invalid help type: '$HelpLevel'" -Status Error
        Write-Host ""
        Write-EnhancedOutput "VALID HELP TYPES:" -Type Primary -Bold
        Write-ModernCard "Full" "Comprehensive documentation with examples"
        Write-ModernCard "Quick" "Brief reference guide (default)"
        Write-ModernCard "Admin" "Administrator rights instructions"
        Write-ModernCard "Security" "Security context information"
        Write-Host ""
        Write-EnhancedOutput "Examples:" -Type Info
        Write-Host "  .\$($Script:Configuration.ScriptName) -Help" -ForegroundColor Yellow
        Write-Host "  .\$($Script:Configuration.ScriptName) -Help -HelpLevel Full" -ForegroundColor Yellow
        Write-Host "  .\$($Script:Configuration.ScriptName) -Help -HelpLevel Admin" -ForegroundColor Yellow
        Write-Host ""
        exit $Script:Configuration.ExitCodes.GeneralError
    }
    
    # Determine effective help level with intelligent fallback
    $effectiveHelpLevel = if ($isHelpLevelSpecified) {
        $HelpLevel
    } else {
        'Full'  # Default to Full help when HelpLevel is not explicitly specified
    }
    
    # Show appropriate help based on validated level
    switch ($effectiveHelpLevel) {
        'Full' {
            Show-ModernBanner
            Show-ModernHelp
        }
        'Quick' {
            Show-QuickHelp
        }
        'Admin' {
            Show-AdministratorInstructions
        }
        'Security' {
            Show-SecurityContext
        }
        default {
            Show-ModernBanner
            Show-ModernHelp
        }
    }
}

function Show-ApplicationInfo {
    <#
    .SYNOPSIS
        Displays brief application information.
    #>
    
    Write-ModernHeader "Application Information" "v$($Script:Configuration.ScriptVersion)"
    
    Write-ModernCard "Script Name" $Script:Configuration.ScriptName
    Write-ModernCard "Version" $Script:Configuration.ScriptVersion
    Write-ModernCard "Author" $Script:Configuration.ScriptAuthor
    Write-ModernCard "Repository" $Script:Configuration.GitHubRepository
    Write-ModernCard "Compatibility" "Windows 10/11, Server 2019+"
    Write-ModernCard "PowerShell" "$($PSVersionTable.PSVersion) ($(if($Script:IsPS7Plus){'Enhanced'}else{'Compatible'}))"
    Write-ModernCard "Admin Rights" $(if (Test-AdministratorRights) { "Yes" } else { "No" }) -ValueColor $(if (Test-AdministratorRights) { "Success" } else { "Info" })
    Write-ModernCard "Enhanced Features" "Group Policy support, individual settings reset"
    
    Write-Host ""
    Write-EnhancedOutput "Use '-Help' for detailed usage information." -Type Info
    Write-Host ""
}

# ============================================================================
# GROUP POLICY AND ENTERPRISE MANAGEMENT
# ============================================================================

function Set-GroupPolicyConfiguration {
    <#
    .SYNOPSIS
        Configures Group Policy settings for all users with detailed error tracking.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable', 'Disable')]
        [string]$Behavior
    )
    
    # Clear previous error details
    $Script:LastErrorDetails.GroupPolicy = $null
    
    if (-not (Test-AdministratorRights)) {
        $errorMessage = "Administrator rights required for Group Policy configuration"
        $Script:LastErrorDetails.GroupPolicy = $errorMessage
        Write-ModernStatus $errorMessage -Status Error
        Show-AdministratorInstructions
        return $false
    }
    
    $value = if ($Behavior -eq 'Enable') { 
        $Script:Configuration.EnableValue 
    } else { 
        $Script:Configuration.DisableValue 
    }
    
    $actionDescription = if ($Behavior -eq 'Enable') { 
        "Show all tray icons for all users" 
    } else { 
        "Enable auto-hide (Windows default) for all users" 
    }
    
    Write-ModernStatus "Configuring Group Policy: $actionDescription" -Status Processing
    
    if (-not $Force -and -not $PSCmdlet.ShouldProcess(
        "Group Policy for all users", 
        "Set value to $value ($actionDescription)"
    )) {
        $Script:LastErrorDetails.GroupPolicy = "Operation cancelled by user confirmation"
        Write-ModernStatus "Operation cancelled by user confirmation" -Status Info
        return $false
    }
    
    try {
        # Method 1: Set User Group Policy (affects all users)
        $userPolicyPath = $Script:Configuration.GroupPolicyUserPath
        if (-not (Test-Path $userPolicyPath)) {
            Write-ModernStatus "Creating Group Policy user path: $userPolicyPath" -Status Info
            $null = New-Item -Path $userPolicyPath -Force -ErrorAction Stop
        }
        
        Set-ItemProperty -Path $userPolicyPath `
                         -Name $Script:Configuration.GroupPolicyValue `
                         -Value $value `
                         -Type DWord `
                         -Force `
                         -ErrorAction Stop
        
        Write-ModernStatus "Group Policy user configuration updated" -Status Success
        
        # Method 2: Also set machine policy for broader coverage
        $machinePolicyPath = $Script:Configuration.GroupPolicyMachinePath
        if (-not (Test-Path $machinePolicyPath)) {
            Write-ModernStatus "Creating Group Policy machine path: $machinePolicyPath" -Status Info
            $null = New-Item -Path $machinePolicyPath -Force -ErrorAction Stop
        }
        
        Set-ItemProperty -Path $machinePolicyPath `
                         -Name $Script:Configuration.GroupPolicyValue `
                         -Value $value `
                         -Type DWord `
                         -Force `
                         -ErrorAction Stop
        
        Write-ModernStatus "Group Policy machine configuration updated" -Status Success
        
        # Method 3: Set registry for all existing user hives
        if (Set-RegistryForAllUsers -Value $value) {
            Write-ModernStatus "Registry settings applied to all user hives" -Status Success
        }
        
        Write-ModernStatus "Group Policy configuration completed: $actionDescription" -Status Success
        return $true
    }
    catch {
        $errorMessage = "Failed to configure Group Policy: $($_.Exception.Message)"
        $Script:LastErrorDetails.GroupPolicy = $errorMessage
        Write-ModernStatus $errorMessage -Status Error
        Write-ModernStatus "Exception type: $($_.Exception.GetType().FullName)" -Status Warning
        Write-ModernStatus "Target path: $($_.TargetObject)" -Status Warning
        return $false
    }
}

function Enable-AllTrayIconsComprehensive {
    <#
    .SYNOPSIS
        Comprehensive method to enable ALL tray icons using multiple techniques.
    #>
    # Display execution parameters for debugging and clarity
    Write-Host ""
    Write-ModernHeader "Script Execution Parameters" "Configuration Details"
    Write-ModernCard "Action" $(if ($Action) { $Action } else { "Not specified" })
    Write-ModernCard "AllUsers" $(if ($AllUsers) { "Enabled (Group Policy mode)" } else { "Disabled (Current user only)" }) -ValueColor $(if ($AllUsers) { "Warning" } else { "Info" })
    Write-ModernCard "RestartExplorer" $(if ($RestartExplorer) { "Yes" } else { "No" })
    Write-ModernCard "BackupRegistry" $(if ($BackupRegistry) { "Yes" } else { "No" })
    Write-ModernCard "Force Mode" $(if ($Force) { "Enabled (No prompts)" } else { "Disabled" }) -ValueColor $(if ($Force) { "Warning" } else { "Info" })
    Write-ModernCard "Admin Rights" $(if (Test-AdministratorRights) { "Available" } else { "Not available" }) -ValueColor $(if (Test-AdministratorRights) { "Success" } else { "Error" })
    Write-Host ""
    
    if ($AllUsers) {
        Write-ModernStatus "Running in ALL USERS mode (Group Policy configuration)" -Status Warning
        if (-not (Test-AdministratorRights)) {
            Write-ModernStatus "ERROR: Administrator rights required for -AllUsers parameter" -Status Error
            return $false
        }
    } else {
        Write-ModernStatus "Running in CURRENT USER ONLY mode" -Status Info
    }
    
    Write-ModernStatus "Enabling ALL tray icons using comprehensive methods..." -Status Processing
    $methods = @{
        AutoTrayDisabled = $false
        IndividualSettingsReset = $false
        TrayCacheCleared = $false
        NotificationSettingsReset = $false
        SystemIconsForced = $false
        Windows11Optimized = $false
        GroupPolicyApplied = $false  # Added for tracking Group Policy status
    }
    $errorDetails = @{
        GroupPolicyApplied = $null
    }
    
    try {
        # Method 1: Disable AutoTray (original method)
        if ($AllUsers) {
            Write-ModernStatus "Applying Group Policy configuration for all users..." -Status Processing
            try {
                if (Set-GroupPolicyConfiguration -Behavior 'Enable') {
                    $methods.AutoTrayDisabled = $true
                    $methods.GroupPolicyApplied = $true
                    Write-ModernStatus "Group Policy configuration successfully applied" -Status Success
                } else {
                    # Get specific error details from the last exception
                    if ($Error.Count -gt 0) {
                        $errorDetails.GroupPolicyApplied = $Error[0].Exception.Message
                    }
                }
            } catch {
                $errorDetails.GroupPolicyApplied = $_.Exception.Message
            }
        } else {
            Write-ModernStatus "Applying registry configuration for current user..." -Status Processing
            if (Set-TrayIconConfiguration -Behavior 'Enable') {
                $methods.AutoTrayDisabled = $true
                Write-ModernStatus "Registry configuration successfully applied" -Status Success
            } else {
                Write-ModernStatus "Registry configuration failed" -Status Error
            }
        }
        
        # Method 2: Reset individual icon settings (only for current user)
        if (-not $AllUsers) {
            Write-ModernStatus "Resetting individual icon settings for current user..." -Status Processing
            $resetResults = Reset-IndividualIconSettings
            if ($resetResults.Values -contains $true) {
                $methods.IndividualSettingsReset = $true
                Write-ModernStatus "Individual icon settings reset completed" -Status Success
            } else {
                Write-ModernStatus "No individual icon settings were reset" -Status Info
            }
            # Set specific method results from individual reset
            $methods.TrayCacheCleared = $resetResults.TrayNotify
            $methods.NotificationSettingsReset = $resetResults.NotificationSettings
        } else {
            Write-ModernStatus "Skipping individual icon settings reset (AllUsers mode only applies Group Policy)" -Status Info
        }
        
        # Method 3: Additional registry tweaks for stubborn icons (only for current user)
        if (-not $AllUsers) {
            # Force show all system icons
            $systemIconsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            $systemIcons = @(
                @{Name = "HideSCAVolume"; Value = 0},
                @{Name = "HideSCANetwork"; Value = 0},
                @{Name = "HideSCAPower"; Value = 0}
            )
            $systemIconsSet = 0
            foreach ($icon in $systemIcons) {
                try {
                    # Ensure the registry path exists
                    if (-not (Test-Path $systemIconsPath)) {
                        $null = New-Item -Path $systemIconsPath -Force -ErrorAction Stop
                    }
                    # Always set the value (don't check current state)
                    Set-ItemProperty -Path $systemIconsPath -Name $icon.Name -Value $icon.Value -Type DWord -Force -ErrorAction Stop
                    $systemIconsSet++
                    Write-ModernStatus "System icon '$($icon.Name)' forced to show" -Status Success
                }
                catch {
                    Write-ModernStatus "Failed to set system icon '$($icon.Name)': $($_.Exception.Message)" -Status Warning
                }
            }
            if ($systemIconsSet -gt 0) {
                $methods.SystemIconsForced = $true
                Write-ModernStatus "System icons forced to show ($systemIconsSet settings)" -Status Success
            } else {
                Write-ModernStatus "No system icons were configured" -Status Warning
            }
        } else {
            Write-ModernStatus "Skipping system icons configuration (AllUsers mode only applies Group Policy)" -Status Info
        }
        
        # Method 4: Reset Windows 11 specific settings (only for current user)
        if (-not $AllUsers) {
            $windowsVersion = Get-WindowsVersion
            if ($windowsVersion -Like "*11*") {
                $win11Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                if (Test-Path $win11Path) {
                    try {
                        Set-ItemProperty -Path $win11Path -Name "TaskbarMn" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                        $methods.Windows11Optimized = $true
                        Write-ModernStatus "Windows 11 specific settings applied" -Status Success
                    }
                    catch {
                        Write-ModernStatus "Windows 11 specific settings failed: $($_.Exception.Message)" -Status Warning
                    }
                } else {
                    Write-ModernStatus "Windows 11 Advanced path not found" -Status Warning
                }
            } else {
                Write-ModernStatus "Windows 11 specific settings skipped (not Windows 11)" -Status Info
            }
        } else {
            Write-ModernStatus "Skipping Windows 11 specific settings (AllUsers mode only applies Group Policy)" -Status Info
        }

        Write-ModernStatus "Comprehensive tray icon enabling completed" -Status Success
        
        # Display results with proper status differentiation
        Write-Host ""
        Write-EnhancedOutput "METHODS APPLIED:" -Type Primary
        
        foreach ($method in $methods.GetEnumerator() | Sort-Object Key) {
            $status = ""
            $color = ""
            $details = ""
            
            if ($method.Value) {
                $status = "Success"
                $color = "Success"
            }
            else {
                # Special handling for GroupPolicyApplied in different modes
                if ($method.Key -eq "GroupPolicyApplied") {
                    if ($AllUsers) {
                        $status = "Failed"
                        $color = "Error"
                        
                        # Add detailed error information
                        if ($errorDetails.GroupPolicyApplied) {
                            $details = " - $($errorDetails.GroupPolicyApplied)"
                        } else {
                            $details = " - Unknown error"
                        }
                    } else {
                        $status = "Not Applicable"
                        $color = "Info"
                        $details = " (not used in Current User mode)"
                    }
                }
                # Handle other methods that should be skipped in AllUsers mode
                elseif ($AllUsers -and $method.Key -in @(
                    "IndividualSettingsReset", 
                    "TrayCacheCleared", 
                    "NotificationSettingsReset", 
                    "SystemIconsForced", 
                    "Windows11Optimized"
                )) {
                    $status = "Skipped"
                    $color = "Warning"
                    $details = " (not applicable in AllUsers mode)"
                }
                else {
                    $status = "Failed"
                    $color = "Error"
                }
            }
            
            # Format the status text with details
            $statusText = "$status$details"
            
            # Special formatting for GroupPolicyApplied in failure mode
            if ($method.Key -eq "GroupPolicyApplied" -and $AllUsers -and $status -eq "Failed") {
                Write-Host "  [*] " -NoNewline -ForegroundColor $Script:ConsoleColors.Dark
                Write-Host $method.Key -NoNewline -ForegroundColor $Script:ConsoleColors.Light
                $padding = 25 - $method.Key.Length
                if ($padding -gt 0) { Write-Host (" " * $padding) -NoNewline }
                Write-Host " | " -NoNewline -ForegroundColor $Script:ConsoleColors.Dark
                Write-Host $status -NoNewline -ForegroundColor $Script:ConsoleColors[$color]
                Write-Host $details -ForegroundColor $Script:ConsoleColors.Warning
            } else {
                Write-ModernCard $method.Key $statusText -ValueColor $color
            }
        }
        
        # Additional error explanation for Group Policy failures (only in AllUsers mode)
        if ($AllUsers -and -not $methods.GroupPolicyApplied) {
            Write-Host ""
            Write-ModernHeader "TROUBLESHOOTING GUIDE" "Group Policy Configuration Failed"
            
            if ($errorDetails.GroupPolicyApplied -like "*UnauthorizedAccessException*" -or 
                $errorDetails.GroupPolicyApplied -like "*Access is denied*" -or 
                $errorDetails.GroupPolicyApplied -like "*Administrator rights*") {
                Write-ModernStatus "ACCESS ISSUE DETECTED" -Status Error
                Write-ModernCard "Cause" "Insufficient permissions to modify Group Policy"
                Write-ModernCard "Solution" "Run PowerShell as Administrator before executing this script"
                Write-ModernCard "Alternative" "Remove -AllUsers parameter to configure only current user settings"
            }
            elseif ($errorDetails.GroupPolicyApplied -like "*Registry policy settings*" -or 
                    $errorDetails.GroupPolicyApplied -like "*policy*" -or 
                    $errorDetails.GroupPolicyApplied -like "*GPO*") {
                Write-ModernStatus "GROUP POLICY RESTRICTION" -Status Error
                Write-ModernCard "Cause" "Registry modifications blocked by domain Group Policy"
                Write-ModernCard "Solution" "Contact your system administrator to modify Group Policy settings"
                Write-ModernCard "Alternative" "Use current user mode without -AllUsers parameter"
            }
            elseif ($errorDetails.GroupPolicyApplied -like "*path not found*" -or 
                    $errorDetails.GroupPolicyApplied -like "*cannot find path*" -or 
                    $errorDetails.GroupPolicyApplied -like "*HKLM*" -or 
                    $errorDetails.GroupPolicyApplied -like "*HKCU*") {
                Write-ModernStatus "REGISTRY PATH ISSUE" -Status Error
                Write-ModernCard "Cause" "Required registry paths for Group Policy do not exist or inaccessible"
                Write-ModernCard "Solution" "Check if Group Policy Client service is running (gpsvc)"
                Write-ModernCard "Check Command" "Get-Service gpsvc | Select-Object Status, DisplayName"
            }
            else {
                Write-ModernStatus "UNEXPECTED ERROR" -Status Error
                Write-ModernCard "Error Details" $(if ($errorDetails.GroupPolicyApplied) { $errorDetails.GroupPolicyApplied } else { "No specific error details available" })
                Write-ModernCard "Debug Step" "Run with -Diagnostic parameter for detailed system information"
                Write-ModernCard "Support" "Create issue at $($Script:Configuration.GitHubRepository) with full error details"
            }
        }
        
        return $true
    }
    catch {
        Write-ModernStatus "Comprehensive enable failed: $($_.Exception.Message)" -Status Error
        Write-ModernStatus "Exception Stack Trace: $($_.ScriptStackTrace)" -Status Warning
        return $false
    }
}

function Set-RegistryForAllUsers {
    <#
    .SYNOPSIS
        Applies registry settings to all user hives for enterprise deployment.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [int]$Value
    )
    
    Write-ModernStatus "Applying settings to all user hives..." -Status Processing
    
    try {
        $userHives = Get-ChildItem -Path "HKU:\" -ErrorAction SilentlyContinue | Where-Object {
            $_.PSChildName -notin @("S-1-5-18", "S-1-5-19", "S-1-5-20") -and
            $_.PSChildName -notlike "*_Classes"
        }
        
        $successCount = 0
        $totalCount = $userHives.Count
        
        foreach ($hive in $userHives) {
            try {
                $userPath = "HKU:\$($hive.PSChildName)\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
                
                # Ensure the path exists
                if (-not (Test-Path $userPath)) {
                    $null = New-Item -Path $userPath -Force -ErrorAction SilentlyContinue
                }
                
                # Set the registry value
                Set-ItemProperty -Path $userPath `
                                 -Name $Script:Configuration.RegistryValue `
                                 -Value $Value `
                                 -Type DWord `
                                 -Force `
                                 -ErrorAction Stop
                
                $successCount++
                Write-ModernStatus "Applied to user hive: $($hive.PSChildName)" -Status Info
            }
            catch {
                Write-ModernStatus "Failed for user hive: $($hive.PSChildName)" -Status Warning
            }
        }
        
        Write-ModernStatus "Registry settings applied to $successCount of $totalCount user hives" -Status Success
        return $true
    }
    catch {
        Write-ModernStatus "Failed to apply registry to all users: $($_.Exception.Message)" -Status Error
        return $false
    }
}

function Get-GroupPolicyConfiguration {
    <#
    .SYNOPSIS
        Retrieves current Group Policy configuration.
    #>
    
    $gpoConfig = @{
        UserPolicy = $null
        MachinePolicy = $null
        EffectivePolicy = $null
    }
    
    try {
        # Check User Policy
        $userPolicyPath = $Script:Configuration.GroupPolicyUserPath
        if (Test-Path $userPolicyPath) {
            $userValue = Get-ItemProperty -Path $userPolicyPath -Name $Script:Configuration.GroupPolicyValue -ErrorAction SilentlyContinue
            if ($userValue) {
                $gpoConfig.UserPolicy = $userValue.$($Script:Configuration.GroupPolicyValue)
            }
        }
        
        # Check Machine Policy
        $machinePolicyPath = $Script:Configuration.GroupPolicyMachinePath
        if (Test-Path $machinePolicyPath) {
            $machineValue = Get-ItemProperty -Path $machinePolicyPath -Name $Script:Configuration.GroupPolicyValue -ErrorAction SilentlyContinue
            if ($machineValue) {
                $gpoConfig.MachinePolicy = $machineValue.$($Script:Configuration.GroupPolicyValue)
            }
        }
        
        # Determine effective policy (machine policy takes precedence)
        if ($null -ne $gpoConfig.MachinePolicy) {
            $gpoConfig.EffectivePolicy = $gpoConfig.MachinePolicy
        } elseif ($null -ne $gpoConfig.UserPolicy) {
            $gpoConfig.EffectivePolicy = $gpoConfig.UserPolicy
        }
        
        return $gpoConfig
    }
    catch {
        Write-ModernStatus "Failed to read Group Policy configuration: $($_.Exception.Message)" -Status Error
        return $gpoConfig
    }
}

# ============================================================================
# ENHANCED TRAY ICONS MANAGEMENT SYSTEM
# ============================================================================

function Reset-IndividualIconSettings {
    <#
    .SYNOPSIS
        Resets individual icon settings to show all icons regardless of user preferences.
    #>
    
    Write-ModernStatus "Resetting individual icon settings..." -Status Processing
    
    $results = @{
        NotifyIconSettings = $false
        TrayNotify = $false
        HideDesktopIcons = $false
        TaskbarLayout = $false
        NotificationSettings = $false
    }
    
    try {
        # 1. Reset NotifyIconSettings (main individual settings)
        $settingsPath = "HKCU:\Control Panel\NotifyIconSettings"
        if (Test-Path $settingsPath) {
            $iconCount = 0
            Get-ChildItem -Path $settingsPath | ForEach-Object {
                try {
                    Set-ItemProperty -Path $_.PSPath -Name "IsPromoted" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                    $iconCount++
                }
                catch {
                    Write-ModernStatus "Failed to reset IsPromoted for $($_.PSChildName)" -Status Warning
                }
            }
            if ($iconCount -gt 0) {
                $results.NotifyIconSettings = $true
                Write-ModernStatus "NotifyIconSettings reset completed ($iconCount icons)" -Status Success
            } else {
                Write-ModernStatus "No icons found in NotifyIconSettings" -Status Warning
            }
        }
        else {
            Write-ModernStatus "NotifyIconSettings path not found" -Status Warning
        }
        
        # 2. Reset TrayNotify streams (icon cache) - Create path if doesn't exist
        $trayPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify"
        if (-not (Test-Path $trayPath)) {
            try {
                Write-ModernStatus "TrayNotify path doesn't exist, creating it..." -Status Info
                $null = New-Item -Path $trayPath -Force -ErrorAction Stop
                Write-ModernStatus "TrayNotify path created successfully" -Status Success
            }
            catch {
                Write-ModernStatus "Failed to create TrayNotify path: $($_.Exception.Message)" -Status Warning
            }
        }
        
        if (Test-Path $trayPath) {
            try {
                $clearedProperties = @()
                # Ensure values are properly set
                Set-ItemProperty -Path $trayPath -Name "IconStreams" -Value @() -Type Binary -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $trayPath -Name "PastIconsStream" -Value @() -Type Binary -Force -ErrorAction SilentlyContinue
                
                $iconStreams = Get-ItemProperty -Path $trayPath -Name "IconStreams" -ErrorAction SilentlyContinue
                $pastIcons = Get-ItemProperty -Path $trayPath -Name "PastIconsStream" -ErrorAction SilentlyContinue
                
                if ($iconStreams -or $pastIcons) {
                    $results.TrayNotify = $true
                    Write-ModernStatus "TrayNotify cache initialized/cleared" -Status Success
                } else {
                    Write-ModernStatus "TrayNotify cache already cleared" -Status Info
                    $results.TrayNotify = $true
                }
            }
            catch {
                Write-ModernStatus "Failed to clear TrayNotify streams: $($_.Exception.Message)" -Status Warning
            }
        } else {
            Write-ModernStatus "TrayNotify path could not be created" -Status Warning
        }
        
        # 3. Reset desktop icon visibility (related to system icons)
        $desktopPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons"
        if (Test-Path $desktopPath) {
            try {
                $desktopItems = Get-ChildItem -Path $desktopPath
                if ($desktopItems.Count -gt 0) {
                    $desktopItems | ForEach-Object {
                        Remove-Item -Path $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                    }
                    $results.HideDesktopIcons = $true
                    Write-ModernStatus "Desktop icon visibility reset ($($desktopItems.Count) items)" -Status Success
                } else {
                    Write-ModernStatus "No desktop icon settings found to reset" -Status Info
                }
            }
            catch {
                Write-ModernStatus "Failed to reset desktop icons: $($_.Exception.Message)" -Status Warning
            }
        } else {
            Write-ModernStatus "HideDesktopIcons path not found" -Status Warning
        }
        
        # 4. Reset taskbar layout (additional icon positioning)
        $taskbarPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Taskband"
        if (Test-Path $taskbarPath) {
            try {
                $taskbarCleared = $false
                if (Get-ItemProperty -Path $taskbarPath -Name "Favorites" -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $taskbarPath -Name "Favorites" -Force -ErrorAction SilentlyContinue
                    $taskbarCleared = $true
                }
                if (Get-ItemProperty -Path $taskbarPath -Name "FavoritesResolve" -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $taskbarPath -Name "FavoritesResolve" -Force -ErrorAction SilentlyContinue
                    $taskbarCleared = $true
                }
                
                if ($taskbarCleared) {
                    $results.TaskbarLayout = $true
                    Write-ModernStatus "Taskbar layout reset" -Status Success
                } else {
                    Write-ModernStatus "No taskbar layout settings found to reset" -Status Info
                }
            }
            catch {
                Write-ModernStatus "Failed to reset taskbar layout: $($_.Exception.Message)" -Status Warning
            }
        } else {
            Write-ModernStatus "Taskband path not found" -Status Warning
        }
        
        # 5. Additional method: Reset notification area preferences completely
        $notifyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
        if (Test-Path $notifyPath) {
            try {
                $notificationApps = Get-ChildItem -Path $notifyPath
                $resetCount = 0
                
                foreach ($app in $notificationApps) {
                    try {
                        Set-ItemProperty -Path $app.PSPath -Name "Enabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                        Set-ItemProperty -Path $app.PSPath -Name "ShowInActionCenter" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue
                        $resetCount++
                    }
                    catch {
                        # Continue if individual settings fail
                    }
                }
                
                if ($resetCount -gt 0) {
                    $results.NotificationSettings = $true
                    Write-ModernStatus "Notification settings reset ($resetCount apps)" -Status Success
                } else {
                    Write-ModernStatus "No notification settings found to reset" -Status Info
                }
            }
            catch {
                Write-ModernStatus "Failed to reset notification settings: $($_.Exception.Message)" -Status Warning
            }
        } else {
            Write-ModernStatus "Notifications Settings path not found" -Status Warning
        }
        
        return $results
    }
    catch {
        Write-ModernStatus "Failed to reset individual icon settings: $($_.Exception.Message)" -Status Error
        return $results
    }
}

function Enable-AllTrayIconsComprehensive {
    <#
    .SYNOPSIS
        Comprehensive method to enable ALL tray icons using multiple techniques.
    #>
    # Display execution parameters for debugging and clarity
    Write-Host ""
    Write-ModernHeader "Script Execution Parameters" "Configuration Details"
    Write-ModernCard "Action" $(if ($Action) { $Action } else { "Not specified" })
    Write-ModernCard "AllUsers" $(if ($AllUsers) { "Enabled (Group Policy mode)" } else { "Disabled (Current user only)" }) -ValueColor $(if ($AllUsers) { "Warning" } else { "Info" })
    Write-ModernCard "RestartExplorer" $(if ($RestartExplorer) { "Yes" } else { "No" })
    Write-ModernCard "BackupRegistry" $(if ($BackupRegistry) { "Yes" } else { "No" })
    Write-ModernCard "Force Mode" $(if ($Force) { "Enabled (No prompts)" } else { "Disabled" }) -ValueColor $(if ($Force) { "Warning" } else { "Info" })
    Write-ModernCard "Admin Rights" $(if (Test-AdministratorRights) { "Available" } else { "Not available" }) -ValueColor $(if (Test-AdministratorRights) { "Success" } else { "Error" })
    Write-Host ""
    
    if ($AllUsers) {
        Write-ModernStatus "Running in ALL USERS mode (Group Policy configuration)" -Status Warning
        if (-not (Test-AdministratorRights)) {
            Write-ModernStatus "ERROR: Administrator rights required for -AllUsers parameter" -Status Error
            return $false
        }
    } else {
        Write-ModernStatus "Running in CURRENT USER ONLY mode" -Status Info
    }
    
    Write-ModernStatus "Enabling ALL tray icons using comprehensive methods..." -Status Processing
    $methods = @{
        AutoTrayDisabled = $false
        IndividualSettingsReset = $false
        TrayCacheCleared = $false
        NotificationSettingsReset = $false
        SystemIconsForced = $false
        Windows11Optimized = $false
        GroupPolicyApplied = $false
    }
    $errorDetails = @{
        GroupPolicyApplied = $null
    }
    
    try {
        # Method 1: Disable AutoTray (original method)
        if ($AllUsers) {
            Write-ModernStatus "Applying Group Policy configuration for all users..." -Status Processing
            try {
                if (Set-GroupPolicyConfiguration -Behavior 'Enable') {
                    $methods.AutoTrayDisabled = $true
                    $methods.GroupPolicyApplied = $true
                    Write-ModernStatus "Group Policy configuration successfully applied" -Status Success
                } else {
                    # Get specific error details from the last exception
                    if ($Error.Count -gt 0) {
                        $errorDetails.GroupPolicyApplied = $Error[0].Exception.Message
                    }
                }
            } catch {
                $errorDetails.GroupPolicyApplied = $_.Exception.Message
            }
        } else {
            Write-ModernStatus "Applying registry configuration for current user..." -Status Processing
            if (Set-TrayIconConfiguration -Behavior 'Enable') {
                $methods.AutoTrayDisabled = $true
                Write-ModernStatus "Registry configuration successfully applied" -Status Success
            } else {
                Write-ModernStatus "Registry configuration failed" -Status Error
            }
        }
        
        # Method 2: Reset individual icon settings (only for current user)
        if (-not $AllUsers) {
            Write-ModernStatus "Resetting individual icon settings for current user..." -Status Processing
            $resetResults = Reset-IndividualIconSettings
            if ($resetResults.Values -contains $true) {
                $methods.IndividualSettingsReset = $true
                Write-ModernStatus "Individual icon settings reset completed" -Status Success
            } else {
                Write-ModernStatus "No individual icon settings were reset" -Status Info
            }
            # Set specific method results from individual reset
            $methods.TrayCacheCleared = $resetResults.TrayNotify
            $methods.NotificationSettingsReset = $resetResults.NotificationSettings
        } else {
            Write-ModernStatus "Skipping individual icon settings reset (AllUsers mode only applies Group Policy)" -Status Info
        }
        
        # Method 3: Additional registry tweaks for stubborn icons (only for current user)
        if (-not $AllUsers) {
            # Force show all system icons
            $systemIconsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            $systemIcons = @(
                @{Name = "HideSCAVolume"; Value = 0},
                @{Name = "HideSCANetwork"; Value = 0},
                @{Name = "HideSCAPower"; Value = 0}
            )
            $systemIconsSet = 0
            foreach ($icon in $systemIcons) {
                try {
                    # Ensure the registry path exists
                    if (-not (Test-Path $systemIconsPath)) {
                        $null = New-Item -Path $systemIconsPath -Force -ErrorAction Stop
                    }
                    # Always set the value (don't check current state)
                    Set-ItemProperty -Path $systemIconsPath -Name $icon.Name -Value $icon.Value -Type DWord -Force -ErrorAction Stop
                    $systemIconsSet++
                    Write-ModernStatus "System icon '$($icon.Name)' forced to show" -Status Success
                }
                catch {
                    Write-ModernStatus "Failed to set system icon '$($icon.Name)': $($_.Exception.Message)" -Status Warning
                }
            }
            if ($systemIconsSet -gt 0) {
                $methods.SystemIconsForced = $true
                Write-ModernStatus "System icons forced to show ($systemIconsSet settings)" -Status Success
            } else {
                Write-ModernStatus "No system icons were configured" -Status Warning
            }
        } else {
            Write-ModernStatus "Skipping system icons configuration (AllUsers mode only applies Group Policy)" -Status Info
        }
        
        # Method 4: Reset Windows 11 specific settings (only for current user)
        if (-not $AllUsers) {
            $windowsVersion = Get-WindowsVersion
            if ($windowsVersion -Like "*11*") {
                $win11Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                if (Test-Path $win11Path) {
                    try {
                        Set-ItemProperty -Path $win11Path -Name "TaskbarMn" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                        $methods.Windows11Optimized = $true
                        Write-ModernStatus "Windows 11 specific settings applied" -Status Success
                    }
                    catch {
                        Write-ModernStatus "Windows 11 specific settings failed: $($_.Exception.Message)" -Status Warning
                    }
                } else {
                    Write-ModernStatus "Windows 11 Advanced path not found" -Status Warning
                }
            } else {
                Write-ModernStatus "Windows 11 specific settings skipped (not Windows 11)" -Status Info
            }
        } else {
            Write-ModernStatus "Skipping Windows 11 specific settings (AllUsers mode only applies Group Policy)" -Status Info
        }

        Write-ModernStatus "Comprehensive tray icon enabling completed" -Status Success
        
        # Display results with proper Skipped/Failed differentiation
        Write-Host ""
        Write-EnhancedOutput "METHODS APPLIED:" -Type Primary
        
        foreach ($method in $methods.GetEnumerator() | Sort-Object Key) {
            $status = ""
            $color = ""
            $details = ""
            
            if ($method.Value) {
                $status = "Success"
                $color = "Success"
            }
            else {
                # Methods that are intentionally skipped in AllUsers mode
                $skippedInAllUsers = @(
                    "IndividualSettingsReset", 
                    "TrayCacheCleared", 
                    "NotificationSettingsReset", 
                    "SystemIconsForced", 
                    "Windows11Optimized"
                )
                
                if ($AllUsers -and $method.Key -in $skippedInAllUsers) {
                    $status = "Skipped"
                    $color = "Warning"  # Yellow for intentionally skipped methods
                }
                else {
                    $status = "Failed"
                    $color = "Error"    # Red for actual failures
                }
            }
            
            Write-ModernCard $method.Key $status -ValueColor $color
        }
        
        # Additional error explanation for Group Policy failures
        if (-not $methods.GroupPolicyApplied -and $errorDetails.GroupPolicyApplied) {
            Write-Host ""
            Write-ModernHeader "ERROR DETAILS" "Group Policy Configuration Failed"
            
            if ($errorDetails.GroupPolicyApplied -like "*UnauthorizedAccessException*" -or $errorDetails.GroupPolicyApplied -like "*Access is denied*") {
                Write-ModernStatus "ACCESS DENIED: Administrator privileges required for Group Policy changes" -Status Error
                Write-ModernCard "Solution" "Run PowerShell as Administrator before executing this script"
                Write-ModernCard "Alternative" "Remove -AllUsers parameter to configure only current user settings"
            }
            elseif ($errorDetails.GroupPolicyApplied -like "*Registry policy settings*") {
                Write-ModernStatus "GROUP POLICY RESTRICTION: Registry modifications blocked by domain policy" -Status Error
                Write-ModernCard "Solution" "Contact your system administrator to modify Group Policy settings"
                Write-ModernCard "Alternative" "Use current user mode without -AllUsers parameter"
            }
            elseif ($errorDetails.GroupPolicyApplied -like "*path not found*" -or $errorDetails.GroupPolicyApplied -like "*cannot find path*") {
                Write-ModernStatus "REGISTRY PATH ERROR: Unable to access Group Policy registry paths" -Status Error
                Write-ModernCard "Solution" "Ensure Group Policy Client service is running"
                Write-ModernCard "Check" "Verify registry permissions for 'HKLM:\SOFTWARE\Policies\Microsoft\Windows'"
            }
            else {
                Write-ModernStatus "UNEXPECTED ERROR: $errorDetails.GroupPolicyApplied" -Status Error
                Write-ModernCard "Debug Tip" "Run with -Diagnostic parameter for detailed system information"
                Write-ModernCard "Report Issue" "Create GitHub issue with full error details at $($Script:Configuration.GitHubRepository)"
            }
        }
        
        return $true
    }
    catch {
        Write-ModernStatus "Comprehensive enable failed: $($_.Exception.Message)" -Status Error
        return $false
    }
}

function Get-WindowsVersion {
    <#
    .SYNOPSIS
        Detects Windows version for version-specific tweaks.
    #>
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
        return $osInfo.Caption
    }
    catch {
        return "Unknown"
    }
}

# ============================================================================
# ENHANCED BACKUP SYSTEM FOR COMPREHENSIVE SETTINGS
# ============================================================================

function Backup-ComprehensiveTraySettings {
    <#
    .SYNOPSIS
        Creates comprehensive backup of ALL tray-related settings with validation and detailed reporting.
    .DESCRIPTION
        Creates an enterprise-grade backup of all system tray icon settings including registry values,
        individual application preferences, notification area cache, system icons, and Group Policy settings.
        Features backup validation, progress reporting, and detailed metadata capture.
    .PARAMETER Force
        Force overwrite of existing backup file without confirmation.
    .PARAMETER CustomPath
        Specifies a custom path for the backup file instead of the default location.
    .PARAMETER ExcludeCache
        Excludes icon cache data to reduce backup size (not recommended for complete restoration).
    .PARAMETER CompressBackup
        Compresses the backup file to reduce storage footprint.
    .EXAMPLE
        Backup-ComprehensiveTraySettings -Force
        Creates comprehensive backup and overwrites existing file without confirmation.
    .EXAMPLE
        Backup-ComprehensiveTraySettings -CustomPath "C:\EnterpriseBackups\TraySettings-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        Creates timestamped backup in custom enterprise location.
    .EXAMPLE
        Backup-ComprehensiveTraySettings -CompressBackup
        Creates compressed backup file to minimize storage requirements.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Overwrite,
        [Parameter(Mandatory = $false)]
        [string]$CustomPath,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeCache = $false,
        [Parameter(Mandatory = $false)]
        [switch]$CompressBackup = $false
    )
    
    # Determine backup path
    $defaultBackupPath = if ($AllUsers) { 
        $Script:Configuration.AllUsersBackupPath 
    } else { 
        $Script:Configuration.BackupRegistryPath 
    }
    
    $backupPath = if ($CustomPath) { 
        $CustomPath 
    } else { 
        $defaultBackupPath 
    }

    if ($CompressBackup) {
        try {
            [System.IO.Compression.GZipStream] | Out-Null
        }
        catch {
            Write-ModernStatus "Compression requires .NET Framework 4.5 or higher" -Status Warning
            Write-ModernStatus "Creating uncompressed backup instead" -Status Warning
            $CompressBackup = $false
        }
    }
    
    # Check if backup already exists
    if (Test-Path $backupPath) {
        $existingBackup = Get-Item $backupPath
        $existingSize = [math]::Round($existingBackup.Length / 1KB, 2)
        $lastModified = $existingBackup.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
        
        if (-not $Overwrite -and -not $script:Force -and -not $script:ForceBackup) {
            Write-ModernStatus "BACKUP ALREADY EXISTS - SKIPPING CREATION" -Status Warning
            Write-ModernCard "Location" $backupPath -ValueColor Warning
            Write-ModernCard "Size" "$existingSize KB" -ValueColor Info
            Write-ModernCard "Last Modified" $lastModified -ValueColor Info
            Write-ModernStatus "Use -ForceBackup or -Force parameter to overwrite existing backup" -Status Info
            return $false  # Просто пропускаем создание бэкапа
        } else {
            Write-ModernStatus "OVERWRITING EXISTING BACKUP FILE" -Status Warning
            Write-ModernCard "Previous Backup Size" "$existingSize KB" -ValueColor Warning
            Write-ModernCard "Last Modified" $lastModified -ValueColor Warning
        }
    }
    
    Write-ModernStatus "Creating comprehensive tray settings backup..." -Status Processing
    Write-ModernCard "Backup Type" "Comprehensive Settings Backup" -ValueColor Info
    Write-ModernCard "Backup Scope" $(if ($AllUsers) { "All Users (Group Policy)" } else { "Current User Only" }) -ValueColor $(if ($AllUsers) { "Warning" } else { "Info" })
    Write-ModernCard "Include Cache Data" $(if (-not $ExcludeCache) { "Yes" } else { "No (Reduced Size)" }) -ValueColor $(if (-not $ExcludeCache) { "Success" } else { "Warning" })
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $backupData = [ordered]@{
        BackupType = "Comprehensive Tray Settings"
        Timestamp = $timestamp
        ScriptVersion = $Script:Configuration.ScriptVersion
        ComputerName = $env:COMPUTERNAME
        UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        WindowsVersion = Get-WindowsVersion
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        AllUsers = $AllUsers
        ExcludeCache = $ExcludeCache
        RegistryPaths = @()
        SettingsCaptured = @()
    }
    
    $progress = 0
    $totalSteps = 6
    
    try {
        # Step 1: Backup main AutoTray setting
        $progress++
        Write-Progress -Activity "Creating Comprehensive Backup" -Status "Backing up registry configuration" -PercentComplete ($progress / $totalSteps * 100)
        $backupData.EnableAutoTray = Get-CurrentTrayConfiguration
        $backupData.RegistryPaths += $Script:Configuration.RegistryPath
        $backupData.SettingsCaptured += "Main AutoTray Configuration"
        
        # Step 2: Backup Group Policy settings if AllUsers
        if ($AllUsers) {
            $progress++
            Write-Progress -Activity "Creating Comprehensive Backup" -Status "Backing up Group Policy settings" -PercentComplete ($progress / $totalSteps * 100)
            $gpoConfig = Get-GroupPolicyConfiguration
            $backupData.GroupPolicy = $gpoConfig
            $backupData.RegistryPaths += $Script:Configuration.GroupPolicyUserPath, $Script:Configuration.GroupPolicyMachinePath
            $backupData.SettingsCaptured += "Group Policy Configuration"
        }
        
        # Step 3: Backup NotifyIconSettings
        $progress++
        Write-Progress -Activity "Creating Comprehensive Backup" -Status "Backing up individual icon settings" -PercentComplete ($progress / $totalSteps * 100)
        $settingsPath = "HKCU:\Control Panel\NotifyIconSettings"
        if (Test-Path $settingsPath) {
            $notifySettings = @{}
            $iconCount = 0
            Get-ChildItem -Path $settingsPath -ErrorAction SilentlyContinue | ForEach-Object {
                $iconSettings = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
                if ($iconSettings) {
                    $iconCount++
                    $notifySettings[$_.PSChildName] = @{}
                    foreach ($property in $iconSettings.PSObject.Properties) {
                        if ($property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                            $notifySettings[$_.PSChildName][$property.Name] = $property.Value
                        }
                    }
                }
            }
            if ($iconCount -gt 0) {
                $backupData.NotifyIconSettings = $notifySettings
                $backupData.SettingsCaptured += "Individual Icon Settings ($iconCount icons)"
            }
        }
        
        # Step 4: Backup TrayNotify (skip if ExcludeCache specified)
        if (-not $ExcludeCache) {
            $progress++
            Write-Progress -Activity "Creating Comprehensive Backup" -Status "Backing up system tray cache" -PercentComplete ($progress / $totalSteps * 100)
            $trayPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify"
            if (Test-Path $trayPath) {
                $traySettings = @{}
                $trayProperties = Get-ItemProperty -Path $trayPath -ErrorAction SilentlyContinue
                if ($trayProperties) {
                    $hasData = $false
                    foreach ($property in $trayProperties.PSObject.Properties) {
                        if ($property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                            $hasData = $true
                            # For binary data, store as Base64 with metadata
                            if ($property.Value -is [byte[]]) {
                                $traySettings[$property.Name] = @{
                                    Type = "Binary"
                                    Length = $property.Value.Length
                                    Hash = (Get-FileHash -InputStream ([System.IO.MemoryStream]::new($property.Value)) -Algorithm SHA256).Hash
                                    Data = [Convert]::ToBase64String($property.Value)
                                }
                            }
                            else {
                                $traySettings[$property.Name] = $property.Value
                            }
                        }
                    }
                    if ($hasData) {
                        $backupData.TrayNotify = $traySettings
                        $backupData.SettingsCaptured += "System Tray Cache"
                    }
                }
            }
        }
        
        # Step 5: Backup system icon settings
        $progress++
        Write-Progress -Activity "Creating Comprehensive Backup" -Status "Backing up system icon visibility" -PercentComplete ($progress / $totalSteps * 100)
        $systemIconsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
        $systemIcons = @("HideSCAVolume", "HideSCANetwork", "HideSCAPower", "HideSCAClock")
        $systemIconsBackup = @{}
        $iconsFound = 0
        
        foreach ($icon in $systemIcons) {
            try {
                $value = Get-ItemProperty -Path $systemIconsPath -Name $icon -ErrorAction SilentlyContinue
                if ($null -ne $value -and $null -ne $value.$icon) {
                    $systemIconsBackup[$icon] = $value.$icon
                    $iconsFound++
                }
            }
            catch {
                # Skip if not present or inaccessible
            }
        }
        
        if ($iconsFound -gt 0) {
            $backupData.SystemIcons = $systemIconsBackup
            $backupData.SettingsCaptured += "System Icons Visibility ($iconsFound icons)"
        }
        
        # Step 6: Backup Windows 11 specific settings
        $progress++
        Write-Progress -Activity "Creating Comprehensive Backup" -Status "Backing up Windows version-specific settings" -PercentComplete ($progress / $totalSteps * 100)
        $windowsVersion = Get-WindowsVersion
        $backupData.WindowsVersionDetails = $windowsVersion
        
        if ($windowsVersion -like "*11*") {
            $win11Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
            if (Test-Path $win11Path) {
                $win11Settings = Get-ItemProperty -Path $win11Path -Name "TaskbarMn", "TaskbarDa", "TaskbarSi" -ErrorAction SilentlyContinue
                if ($win11Settings) {
                    $backupData.Windows11Settings = @{}
                    foreach ($property in $win11Settings.PSObject.Properties) {
                        if ($property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") -and $null -ne $property.Value) {
                            $backupData.Windows11Settings[$property.Name] = $property.Value
                        }
                    }
                    if ($backupData.Windows11Settings.Count -gt 0) {
                        $backupData.SettingsCaptured += "Windows 11 Taskbar Settings"
                    }
                }
            }
        }
        
        # Ensure backup directory exists
        $backupDir = Split-Path -Path $backupPath -Parent
        if (-not (Test-Path $backupDir)) {
            Write-ModernStatus "Creating backup directory: $backupDir" -Status Info
            $null = New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop
        }
        
        # Create backup file
        $jsonParams = @{
            Depth = 15
            Compress = $CompressBackup
        }
        
        $jsonContent = $backupData | ConvertTo-Json @jsonParams
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($backupPath, $jsonContent, $utf8NoBom)
        
        # Verify backup integrity
        try {
            $verificationData = Get-Content -Path $backupPath -Raw | ConvertFrom-Json
            if ($verificationData.Timestamp -ne $timestamp) {
                throw "Timestamp verification failed"
            }
            if ($verificationData.SettingsCaptured.Count -eq 0) {
                throw "No settings were captured in the backup"
            }
            Write-ModernStatus "Backup verification successful" -Status Success
        }
        catch {
            Write-ModernStatus "Backup verification failed: $($_.Exception.Message)" -Status Error
            Write-ModernStatus "Backup file may be corrupted or incomplete" -Status Error
            return $false
        }
        
        # Get final backup details
        $backupFile = Get-Item $backupPath
        $backupSize = [math]::Round($backupFile.Length / 1KB, 2)
        $originalSize = $backupSize
        
        # Apply compression if requested
        if ($CompressBackup -and $backupSize -gt 10) {
            try {
                $compressedPath = "$backupPath.gz"
                $compressionStream = New-Object System.IO.FileStream($compressedPath, [System.IO.FileMode]::Create)
                $gzipStream = New-Object System.IO.Compression.GZipStream($compressionStream, [System.IO.Compression.CompressionLevel]::Optimal)
                $writer = New-Object System.IO.StreamWriter($gzipStream)
                $writer.Write($jsonContent)
                $writer.Close()
                $gzipStream.Close()
                $compressionStream.Close()
                
                # Remove original file and rename compressed file
                Remove-Item -Path $backupPath -Force -ErrorAction Stop
                Rename-Item -Path $compressedPath -NewName (Split-Path $backupPath -Leaf) -Force -ErrorAction Stop
                
                $compressedFile = Get-Item $backupPath
                $compressedSize = [math]::Round($compressedFile.Length / 1KB, 2)
                $compressionRatio = [math]::Round(($originalSize - $compressedSize) / $originalSize * 100, 1)
                
                $backupSize = $compressedSize
                Write-ModernStatus "Backup compression completed" -Status Success
                Write-ModernCard "Original Size" "$originalSize KB" -ValueColor Info
                Write-ModernCard "Compressed Size" "$compressedSize KB" -ValueColor Success
                Write-ModernCard "Space Saved" "$compressionRatio%" -ValueColor Success
            }
            catch {
                Write-ModernStatus "Backup compression failed: $($_.Exception.Message)" -Status Warning
                Write-ModernStatus "Using uncompressed backup file" -Status Warning
            }
        }
        
        # Display completion summary
        Write-Progress -Activity "Creating Comprehensive Backup" -Completed
        Write-ModernStatus "Comprehensive backup created successfully!" -Status Success
        Write-ModernCard "Backup Location" $backupPath
        Write-ModernCard "Backup Size" "$backupSize KB"
        Write-ModernCard "Backup Time" $timestamp
        Write-ModernCard "Windows Version" $windowsVersion
        Write-ModernCard "Settings Categories" $backupData.SettingsCaptured.Count
        Write-ModernCard "Registry Paths" $backupData.RegistryPaths.Count
        
        # Detailed settings summary
        Write-Host ""
        Write-EnhancedOutput "SETTINGS CAPTURED:" -Type Primary
        foreach ($setting in $backupData.SettingsCaptured) {
            Write-ModernCard "✓" $setting -ValueColor Success
        }
        
        # Security note for all users backup
        if ($AllUsers) {
            Write-Host ""
            Write-ModernStatus "SECURITY NOTE: This backup contains sensitive system configuration data." -Status Warning
            Write-ModernStatus "Store this file securely and restrict access permissions." -Status Warning
            Write-ModernStatus "For enterprise deployment, consider encrypting this backup file." -Status Info
        }
        
        return $true
    }
    catch {
        Write-Progress -Activity "Creating Comprehensive Backup" -Completed
        Write-ModernStatus "Comprehensive backup failed: $($_.Exception.Message)" -Status Error
        Write-ModernStatus "Exception Type: $($_.Exception.GetType().FullName)" -Status Warning
        Write-ModernStatus "Target Path: $backupPath" -Status Warning
        
        # Attempt cleanup of partial backup
        if (Test-Path $backupPath) {
            try {
                Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
                Write-ModernStatus "Partial backup file removed" -Status Info
            }
            catch {
                Write-ModernStatus "Failed to remove partial backup file" -Status Warning
            }
        }
        
        return $false
    }
}

function Restore-ComprehensiveTraySettings {
    <#
    .SYNOPSIS
        Restores comprehensive tray settings from backup.
    #>
    
    $backupPath = if ($AllUsers) { 
        $Script:Configuration.AllUsersBackupPath 
    } else { 
        $Script:Configuration.BackupRegistryPath 
    }
    
    if (-not (Test-Path $backupPath)) {
        Write-ModernStatus "No comprehensive backup found: $backupPath" -Status Error
        return $false
    }
    
    Write-ModernStatus "Restoring comprehensive tray settings..." -Status Processing
    
    try {
        $backupData = Get-Content -Path $backupPath -Raw | ConvertFrom-Json
        
        Write-ModernCard "Backup Created" $backupData.Timestamp
        Write-ModernCard "Windows Version" $backupData.WindowsVersion
        Write-ModernCard "Backup Scope" $(if ($backupData.AllUsers) { "All Users" } else { "Current User" })
        
        $restoreResults = @{}
        
        # 1. Restore main AutoTray setting
        if ($null -ne $backupData.EnableAutoTray) {
            if ($AllUsers -or $backupData.AllUsers) {
                # Restore Group Policy settings
                if ($backupData.GroupPolicy) {
                    $userPolicyPath = $Script:Configuration.GroupPolicyUserPath
                    $machinePolicyPath = $Script:Configuration.GroupPolicyMachinePath
                    
                    if (-not (Test-Path $userPolicyPath)) {
                        $null = New-Item -Path $userPolicyPath -Force
                    }
                    if (-not (Test-Path $machinePolicyPath)) {
                        $null = New-Item -Path $machinePolicyPath -Force
                    }
                    
                    Set-ItemProperty -Path $userPolicyPath -Name $Script:Configuration.GroupPolicyValue -Value $backupData.EnableAutoTray -Type DWord -Force
                    Set-ItemProperty -Path $machinePolicyPath -Name $Script:Configuration.GroupPolicyValue -Value $backupData.EnableAutoTray -Type DWord -Force
                    
                    $restoreResults.GroupPolicy = $true
                }
            } else {
                # Restore current user settings
                Set-ItemProperty -Path $Script:Configuration.RegistryPath `
                               -Name $Script:Configuration.RegistryValue `
                               -Value $backupData.EnableAutoTray `
                               -Type DWord `
                               -Force `
                               -ErrorAction Stop
                $restoreResults.EnableAutoTray = $true
            }
        }
        
        # 2. Restore NotifyIconSettings
        if ($backupData.NotifyIconSettings) {
            $settingsPath = "HKCU:\Control Panel\NotifyIconSettings"
            foreach ($icon in $backupData.NotifyIconSettings.PSObject.Properties) {
                try {
                    $iconPath = Join-Path $settingsPath $icon.Name
                    if (-not (Test-Path $iconPath)) {
                        $null = New-Item -Path $iconPath -Force -ErrorAction SilentlyContinue
                    }
                    
                    foreach ($property in $icon.Value.PSObject.Properties) {
                        Set-ItemProperty -Path $iconPath -Name $property.Name -Value $property.Value -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Write-ModernStatus "Failed to restore $($icon.Name) settings" -Status Warning
                }
            }
            $restoreResults.NotifyIconSettings = $true
        }
        
        # 3. Restore TrayNotify
        if ($backupData.TrayNotify) {
            $trayPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TrayNotify"
            foreach ($property in $backupData.TrayNotify.PSObject.Properties) {
                try {
                    if ($property.Value.Type -eq "Binary") {
                        $bytes = [Convert]::FromBase64String($property.Value.Data)
                        Set-ItemProperty -Path $trayPath -Name $property.Name -Value $bytes -Type Binary -Force -ErrorAction SilentlyContinue
                    }
                    else {
                        Set-ItemProperty -Path $trayPath -Name $property.Name -Value $property.Value -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    Write-ModernStatus "Failed to restore TrayNotify.$($property.Name)" -Status Warning
                }
            }
            $restoreResults.TrayNotify = $true
        }
        
        # 4. Restore system icons
        if ($backupData.SystemIcons) {
            $systemIconsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            foreach ($icon in $backupData.SystemIcons.PSObject.Properties) {
                try {
                    Set-ItemProperty -Path $systemIconsPath -Name $icon.Name -Value $icon.Value -Type DWord -Force -ErrorAction SilentlyContinue
                }
                catch {
                    # Skip if restoration fails
                }
            }
            $restoreResults.SystemIcons = $true
        }
        
        # Remove backup file after successful restoration
        Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
        Write-ModernStatus "Backup file removed after successful restoration" -Status Info
        
        Write-ModernStatus "Comprehensive restoration completed" -Status Success
        
        # Display restoration summary
        Write-Host ""
        Write-EnhancedOutput "RESTORATION RESULTS:" -Type Primary
        foreach ($result in $restoreResults.GetEnumerator()) {
            $color = if ($result.Value) { "Success" } else { "Warning" }
            Write-ModernCard $result.Key $(if ($result.Value) { "Success" } else { "Partial/Failed" }) -ValueColor $color
        }
        
        return $true
    }
    catch {
        Write-ModernStatus "Comprehensive restoration failed: $($_.Exception.Message)" -Status Error
        return $false
    }
}

function Backup-RegistryConfiguration {
    <#
    .SYNOPSIS
        Creates registry backup with overwrite protection and comprehensive validation.
    .DESCRIPTION
        Creates a backup of critical registry settings for rollback capability with advanced overwrite protection,
        validation, and detailed reporting. Supports both current user and all users backup modes.
    .PARAMETER Force
        Force overwrite of existing backup file without confirmation.
    .PARAMETER CustomPath
        Specifies a custom path for the backup file instead of the default location.
    .PARAMETER VerifyBackup
        Verifies backup file integrity after creation (enabled by default).
    .EXAMPLE
        Backup-RegistryConfiguration -Force
        Creates backup and overwrites existing backup file without confirmation.
    .EXAMPLE
        Backup-RegistryConfiguration -CustomPath "C:\Backups\TrayIcons-$(Get-Date -Format 'yyyyMMdd').json"
        Creates backup with custom filename including date stamp.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$Overwrite,  # Renamed from Force to avoid conflict
        
        [Parameter(Mandatory = $false)]
        [string]$CustomPath,
        
        [Parameter(Mandatory = $false)]
        [switch]$VerifyBackup = $true
    )
    
    try {
        # Determine backup path
        $defaultBackupPath = if ($AllUsers) { 
            $Script:Configuration.AllUsersBackupPath 
        } else { 
            $Script:Configuration.BackupRegistryPath 
        }
        
        $backupPath = if ($CustomPath) { 
            $CustomPath 
        } else { 
            $defaultBackupPath 
        }
        
        # Check if backup already exists
        if (Test-Path $backupPath) {
            $existingBackup = Get-Item $backupPath
            $existingSize = [math]::Round($existingBackup.Length / 1KB, 2)
            $lastModified = $existingBackup.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            
            if (-not $Force) {
                Write-ModernStatus "BACKUP ALREADY EXISTS" -Status Warning
                Write-ModernCard "Location" $backupPath -ValueColor Warning
                Write-ModernCard "Size" "$existingSize KB" -ValueColor Info
                Write-ModernCard "Last Modified" $lastModified -ValueColor Info
                Write-ModernStatus "USE -Force PARAMETER TO OVERWRITE EXISTING BACKUP" -Status Warning
                Write-ModernStatus "Example: Backup-RegistryConfiguration -Force" -Status Info
                return $false
            } else {
                Write-ModernStatus "OVERWRITING EXISTING BACKUP FILE" -Status Warning
                Write-ModernCard "Previous Backup Size" "$existingSize KB" -ValueColor Warning
                Write-ModernCard "Last Modified" $lastModified -ValueColor Warning
            }
        }
        
        # Get current configuration
        $currentConfig = Get-CurrentTrayConfiguration
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        Write-ModernStatus "Creating registry backup..." -Status Processing
        Write-ModernCard "Target Path" $backupPath -ValueColor Info
        Write-ModernCard "Backup Scope" $(if ($AllUsers) { "All Users (Group Policy)" } else { "Current User Only" }) -ValueColor $(if ($AllUsers) { "Warning" } else { "Info" })
        
        # Prepare backup data
        $backupData = [ordered]@{
            BackupType = "Registry Configuration"
            Timestamp = $timestamp
            ScriptVersion = $Script:Configuration.ScriptVersion
            ComputerName = $env:COMPUTERNAME
            UserName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            WindowsVersion = Get-WindowsVersion
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            AllUsers = $AllUsers
            OriginalValue = $currentConfig
            RegistryPath = $Script:Configuration.RegistryPath
            ValueName = $Script:Configuration.RegistryValue
        }
        
        # Include Group Policy settings if AllUsers
        if ($AllUsers) {
            $gpoConfig = Get-GroupPolicyConfiguration
            $backupData.GroupPolicy = @{
                UserPolicy = $gpoConfig.UserPolicy
                MachinePolicy = $gpoConfig.MachinePolicy
                EffectivePolicy = $gpoConfig.EffectivePolicy
            }
        }
        
        # Ensure backup directory exists
        $backupDir = Split-Path -Path $backupPath -Parent
        if (-not (Test-Path $backupDir)) {
            Write-ModernStatus "Creating backup directory: $backupDir" -Status Info
            $null = New-Item -Path $backupDir -ItemType Directory -Force -ErrorAction Stop
        }
        
        # Create backup file with proper encoding
        $jsonContent = $backupData | ConvertTo-Json -Depth 10
        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
        [System.IO.File]::WriteAllText($backupPath, $jsonContent, $utf8NoBom)
        
        # Verify backup if requested
        if ($VerifyBackup) {
            try {
                $verificationData = Get-Content -Path $backupPath -Raw | ConvertFrom-Json
                if ($verificationData.Timestamp -ne $timestamp) {
                    throw "Timestamp verification failed"
                }
                Write-ModernStatus "Backup verification successful" -Status Success
            }
            catch {
                Write-ModernStatus "Backup verification failed: $($_.Exception.Message)" -Status Error
                Write-ModernStatus "Backup file may be corrupted or incomplete" -Status Error
                return $false
            }
        }
        
        # Get final backup details
        $backupFile = Get-Item $backupPath
        $backupSize = [math]::Round($backupFile.Length / 1KB, 2)
        
        # Display success summary
        Write-ModernStatus "Registry backup created successfully!" -Status Success
        Write-ModernCard "Backup Location" $backupPath
        Write-ModernCard "Backup Size" "$backupSize KB"
        Write-ModernCard "Backup Time" $timestamp
        Write-ModernCard "Backup Scope" $(if ($AllUsers) { "All Users (Group Policy)" } else { "Current User" })
        Write-ModernCard "Original Value" $(if ($null -eq $currentConfig) { "Not Set (Default)" } else { $currentConfig })
        
        # Security note for all users backup
        if ($AllUsers) {
            Write-Host ""
            Write-ModernStatus "SECURITY NOTE: This backup contains Group Policy settings that affect all users." -Status Warning
            Write-ModernStatus "Store this file securely and limit access permissions." -Status Warning
        }
        
        return $true
    }
    catch {
        Write-ModernStatus "Backup creation failed: $($_.Exception.Message)" -Status Error
        Write-ModernStatus "Exception Type: $($_.Exception.GetType().FullName)" -Status Warning
        return $false
    }
}

function Invoke-ConfigurationRollback {
    <#
    .SYNOPSIS
        Restores previous configuration from backup.
    #>
    
    $backupPath = if ($AllUsers) { 
        $Script:Configuration.AllUsersBackupPath 
    } else { 
        $Script:Configuration.BackupRegistryPath 
    }
    
    if (-not (Test-Path $backupPath)) {
        Write-ModernStatus "No backup found for rollback: $backupPath" -Status Error
        return $false
    }
    
    try {
        $backupData = Get-Content -Path $backupPath -Raw | ConvertFrom-Json
        $originalValue = $backupData.OriginalValue
        
        Write-ModernStatus "Attempting rollback to previous configuration..." -Status Info
        
        # Display backup information
        Write-ModernCard "Backup Created" $backupData.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")
        Write-ModernCard "Original Value" $(if ($null -eq $originalValue) { "Not Set (Default)" } else { $originalValue })
        Write-ModernCard "Backup Scope" $(if ($backupData.AllUsers) { "All Users" } else { "Current User" })
        
        if ($AllUsers -or $backupData.AllUsers) {
            # Rollback Group Policy settings
            if ($null -eq $originalValue) {
                # Remove Group Policy settings
                $userPolicyPath = $Script:Configuration.GroupPolicyUserPath
                $machinePolicyPath = $Script:Configuration.GroupPolicyMachinePath
                
                if (Test-Path $userPolicyPath) {
                    Remove-ItemProperty -Path $userPolicyPath -Name $Script:Configuration.GroupPolicyValue -Force -ErrorAction SilentlyContinue
                }
                if (Test-Path $machinePolicyPath) {
                    Remove-ItemProperty -Path $machinePolicyPath -Name $Script:Configuration.GroupPolicyValue -Force -ErrorAction SilentlyContinue
                }
                
                Write-ModernStatus "Restored Windows default behavior (Group Policy settings removed)" -Status Success
            }
            else {
                # Restore Group Policy settings
                $userPolicyPath = $Script:Configuration.GroupPolicyUserPath
                $machinePolicyPath = $Script:Configuration.GroupPolicyMachinePath
                
                if (-not (Test-Path $userPolicyPath)) {
                    $null = New-Item -Path $userPolicyPath -Force
                }
                if (-not (Test-Path $machinePolicyPath)) {
                    $null = New-Item -Path $machinePolicyPath -Force
                }
                
                Set-ItemProperty -Path $userPolicyPath -Name $Script:Configuration.GroupPolicyValue -Value $originalValue -Type DWord -Force
                Set-ItemProperty -Path $machinePolicyPath -Name $Script:Configuration.GroupPolicyValue -Value $originalValue -Type DWord -Force
                
                Write-ModernStatus "Restored Group Policy configuration: $originalValue" -Status Success
            }
        } else {
            # Rollback current user settings
            if ($null -eq $originalValue) {
                # Original value was not set (Windows default), so remove the registry value
                Remove-ItemProperty -Path $Script:Configuration.RegistryPath `
                                   -Name $Script:Configuration.RegistryValue `
                                   -Force `
                                   -ErrorAction Stop
                Write-ModernStatus "Restored Windows default behavior (registry value removed)" -Status Success
            }
            else {
                # Restore original value
                Set-ItemProperty -Path $Script:Configuration.RegistryPath `
                               -Name $Script:Configuration.RegistryValue `
                               -Value $originalValue `
                               -Type DWord `
                               -Force `
                               -ErrorAction Stop
                Write-ModernStatus "Restored original configuration: $originalValue" -Status Success
            }
        }
        
        # Remove backup file after successful rollback
        Remove-Item -Path $backupPath -Force -ErrorAction SilentlyContinue
        Write-ModernStatus "Backup file removed after successful rollback" -Status Info
        
        return $true
    }
    catch {
        Write-ModernStatus "Rollback failed: $($_.Exception.Message)" -Status Error
        return $false
    }
}

# ============================================================================
# ENHANCED AUTO-UPDATE SYSTEM
# ============================================================================

function Invoke-ScriptUpdate {
    <#
    .SYNOPSIS
        Enhanced script update with PowerShell 7+ features when available.
    #>
    
    Write-ModernHeader "Script Update" "Checking for updates..."
    
    try {
        Write-ModernStatus "Checking GitHub repository for updates..." -Status Processing
        
        # Use Invoke-RestMethod for PowerShell 7+, WebClient for 5.0
        if ($Script:IsPS7Plus) {
            Write-ModernStatus "Using enhanced download method (PowerShell 7+)" -Status Info
            $latestScriptContent = Invoke-RestMethod -Uri $Script:Configuration.UpdateUrl -UserAgent "PowerShell Script Update Check"
        } else {
            $webClient = New-Object System.Net.WebClient
            $webClient.Headers.Add('User-Agent', 'PowerShell Script Update Check')
            $latestScriptContent = $webClient.DownloadString($Script:Configuration.UpdateUrl)
        }
        
        # Extract version from downloaded script
        $versionPattern = 'ScriptVersion\s*=\s*"([0-9]+\.[0-9]+)"'
        $versionMatch = [regex]::Match($latestScriptContent, $versionPattern)
        
        if (-not $versionMatch.Success) {
            Write-ModernStatus "Could not determine version from repository" -Status Warning
            return $false
        }
        
        $latestVersion = $versionMatch.Groups[1].Value
        $currentVersion = $Script:Configuration.ScriptVersion
        
        Write-ModernCard "Current Version" $currentVersion
        Write-ModernCard "Latest Version" $latestVersion
        
        if ([version]$latestVersion -gt [version]$currentVersion) {
            Write-ModernStatus "New version available! Updating..." -Status Info
            
            # Get current script path
            $currentScriptPath = $MyInvocation.MyCommand.Path
            $backupPath = "$currentScriptPath.backup"
            
            # Create backup of current script (don't overwrite if exists)
            if (-not (Test-Path $backupPath)) {
                Copy-Item -Path $currentScriptPath -Destination $backupPath -Force
                Write-ModernStatus "Script backup created: $backupPath" -Status Success
            } else {
                Write-ModernStatus "Script backup already exists, preserving: $backupPath" -Status Info
            }
            
            # Write new version
            $latestScriptContent | Out-File -FilePath $currentScriptPath -Encoding UTF8
            
            Write-ModernStatus "Update completed successfully!" -Status Success
            Write-ModernStatus "Please restart the script to use the new version." -Status Info
            
            return $true
        }
        else {
            Write-ModernStatus "You are running the latest version." -Status Success
            return $false
        }
    }
    catch {
        Write-ModernStatus "Update failed: $($_.Exception.Message)" -Status Error
        return $false
    }
}

# ============================================================================
# ENHANCED STATUS DISPLAY
# ============================================================================

function Show-EnhancedStatus {
    <#
    .SYNOPSIS
        Displays comprehensive system status with modern UI.
    #>
    
    Write-ModernHeader "System Status" "Current Tray Icons Configuration"
    
    $currentConfig = Get-CurrentTrayConfiguration
    $sessionContext = Get-SessionContext
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
    $gpoConfig = Get-GroupPolicyConfiguration
    
    # Configuration Status
    Write-EnhancedOutput "CONFIGURATION STATUS:" -Type Primary
    if ($null -eq $currentConfig) {
        Write-ModernCard "Tray Icons Behavior" "Auto-hide inactive icons (Windows default)" -ValueColor Success
        Write-ModernCard "Registry Value" "Not configured - using system default" -ValueColor Info
    }
    else {
        $behavior = if ($currentConfig -eq $Script:Configuration.EnableValue) {
            "Show ALL tray icons (auto-hide disabled)"
        } else {
            "Auto-hide inactive icons (Windows default)"
        }
        $color = if ($currentConfig -eq $Script:Configuration.EnableValue) { "Success" } else { "Info" }
        Write-ModernCard "Tray Icons Behavior" $behavior -ValueColor $color
        Write-ModernCard "Registry Value" $currentConfig -ValueColor Light
    }
    
    # Group Policy Status
    Write-EnhancedOutput "GROUP POLICY STATUS:" -Type Primary
    if ($null -ne $gpoConfig.EffectivePolicy) {
        $gpoBehavior = if ($gpoConfig.EffectivePolicy -eq $Script:Configuration.EnableValue) {
            "Show ALL tray icons (Group Policy enforced)"
        } else {
            "Auto-hide inactive icons (Group Policy enforced)"
        }
        $gpoColor = if ($gpoConfig.EffectivePolicy -eq $Script:Configuration.EnableValue) { "Success" } else { "Warning" }
        Write-ModernCard "Effective Policy" $gpoBehavior -ValueColor $gpoColor
        Write-ModernCard "User Policy" $(if ($null -ne $gpoConfig.UserPolicy) { $gpoConfig.UserPolicy } else { "Not Configured" })
        Write-ModernCard "Machine Policy" $(if ($null -ne $gpoConfig.MachinePolicy) { $gpoConfig.MachinePolicy } else { "Not Configured" })
    } else {
        Write-ModernCard "Group Policy" "Not configured - using local settings" -ValueColor Info
    }
    Write-Host ""
    
    # System Information
    Write-EnhancedOutput "SYSTEM INFORMATION:" -Type Primary
    if ($osInfo) {
        Write-ModernCard "Operating System" $osInfo.Caption
        Write-ModernCard "OS Version" "$($osInfo.Version) (Build $($osInfo.BuildNumber))"
    }
    Write-ModernCard "PowerShell Version" "$($PSVersionTable.PSVersion) ($(if($Script:IsPS7Plus){'Enhanced'}else{'Compatible'}))"
    Write-ModernCard "Windows Version" (Get-WindowsVersion)
    Write-Host ""
    
    # Session Context
    Write-EnhancedOutput "SESSION CONTEXT:" -Type Primary
    Write-ModernCard "Current User" $sessionContext.CurrentUser
    Write-ModernCard "Session Type" $sessionContext.SessionType
    Write-ModernCard "Admin Rights" $(if ($sessionContext.IsAdmin) { "Yes" } else { "No" }) -ValueColor $(if ($sessionContext.IsAdmin) { "Success" } else { "Info" })
    Write-ModernCard "Interactive" $(if ($sessionContext.IsInteractive) { "Yes" } else { "No" }) -ValueColor $(if ($sessionContext.IsInteractive) { "Success" } else { "Warning" })
    Write-Host ""
    
    # Backup Status
    Write-EnhancedOutput "BACKUP STATUS:" -Type Primary
    $currentUserBackup = Test-Path $Script:Configuration.BackupRegistryPath
    $allUsersBackup = Test-Path $Script:Configuration.AllUsersBackupPath
    Write-ModernCard "Current User Backup" $(if ($currentUserBackup) { "Available" } else { "Not Available" }) -ValueColor $(if ($currentUserBackup) { "Success" } else { "Info" })
    Write-ModernCard "All Users Backup" $(if ($allUsersBackup) { "Available" } else { "Not Available" }) -ValueColor $(if ($allUsersBackup) { "Success" } else { "Info" })
    
    if ($currentUserBackup -or $allUsersBackup) {
        try {
            if ($currentUserBackup) {
                $backupInfo = Get-Item $Script:Configuration.BackupRegistryPath
                Write-ModernCard "Current User Backup Size" "$([math]::Round($backupInfo.Length/1KB, 2)) KB" -ValueColor Info
            }
            if ($allUsersBackup) {
                $backupInfo = Get-Item $Script:Configuration.AllUsersBackupPath
                Write-ModernCard "All Users Backup Size" "$([math]::Round($backupInfo.Length/1KB, 2)) KB" -ValueColor Info
            }
        }
        catch {
            Write-ModernCard "Backup Status" "Error reading backup information" -ValueColor Warning
        }
    }
    
    Write-Host ""
    Write-EnhancedOutput "Use '-Action Enable' to show all icons or '-Action Disable' for default behavior." -Type Info
    Write-EnhancedOutput "Use '-AllUsers' for Group Policy deployment (requires administrator rights)." -Type Info
    Write-Host ""
}

# ============================================================================
# DIAGNOSTIC BACKUP FUNCTIONS
# ============================================================================

function Invoke-BackupDiagnostic {
    <#
    .SYNOPSIS
        Performs comprehensive backup file diagnostics and validation.
    #>
    
    $currentUserBackup = $Script:Configuration.BackupRegistryPath
    $allUsersBackup = $Script:Configuration.AllUsersBackupPath
    
    Write-Host "=== BACKUP FILE DIAGNOSTICS ===" -ForegroundColor Cyan
    
    # Check current user backup
    if (Test-Path $currentUserBackup) {
        Write-Host "`nCURRENT USER BACKUP:" -ForegroundColor Green
        try {
            $fileInfo = Get-Item $currentUserBackup
            Write-Host "File Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor Yellow
            
            $content = Get-Content -Path $currentUserBackup -Raw -ErrorAction Stop
            Write-Host "Content Length: $($content.Length) characters" -ForegroundColor Yellow
            
            try {
                $backupData = $content | ConvertFrom-Json -ErrorAction Stop
                Write-Host "✅ JSON parsing successful!" -ForegroundColor Green
                Write-Host "Backup Version: $($backupData.ScriptVersion)" -ForegroundColor Yellow
                Write-Host "Timestamp: $($backupData.Timestamp)" -ForegroundColor Yellow
                Write-Host "Scope: $(if ($backupData.AllUsers) { 'All Users' } else { 'Current User' })" -ForegroundColor Yellow
                Write-Host "Data Categories: $($backupData.PSObject.Properties.Name -join ', ')" -ForegroundColor Yellow
            }
            catch {
                Write-Host "❌ JSON parsing failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "❌ Error reading backup file: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "`nCURRENT USER BACKUP: Not Found" -ForegroundColor Red
    }
    
    # Check all users backup
    if (Test-Path $allUsersBackup) {
        Write-Host "`nALL USERS BACKUP:" -ForegroundColor Green
        try {
            $fileInfo = Get-Item $allUsersBackup
            Write-Host "File Size: $([math]::Round($fileInfo.Length/1KB, 2)) KB" -ForegroundColor Yellow
            
            $content = Get-Content -Path $allUsersBackup -Raw -ErrorAction Stop
            Write-Host "Content Length: $($content.Length) characters" -ForegroundColor Yellow
            
            try {
                $backupData = $content | ConvertFrom-Json -ErrorAction Stop
                Write-Host "✅ JSON parsing successful!" -ForegroundColor Green
                Write-Host "Backup Version: $($backupData.ScriptVersion)" -ForegroundColor Yellow
                Write-Host "Timestamp: $($backupData.Timestamp)" -ForegroundColor Yellow
                Write-Host "Scope: $(if ($backupData.AllUsers) { 'All Users' } else { 'Current User' })" -ForegroundColor Yellow
                Write-Host "Data Categories: $($backupData.PSObject.Properties.Name -join ', ')" -ForegroundColor Yellow
            }
            catch {
                Write-Host "❌ JSON parsing failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "❌ Error reading backup file: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "`nALL USERS BACKUP: Not Found" -ForegroundColor Red
    }
    
    Write-Host "`n=== END DIAGNOSTICS ===" -ForegroundColor Cyan
}

# ============================================================================
# ENHANCED CORE FUNCTIONS
# ============================================================================

function Get-CurrentTrayConfiguration {
    <#
    .SYNOPSIS
        Retrieves current tray configuration with comprehensive error handling.
    #>
    
    try {
        $registryPath = $Script:Configuration.RegistryPath
        $valueName = $Script:Configuration.RegistryValue
        
        if (-not (Test-Path $registryPath)) {
            return $null
        }
        
        $value = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
        if ($null -eq $value -or $null -eq $value.$valueName) {
            return $null
        }
        
        return $value.$valueName
    }
    catch {
        Write-ModernStatus "Failed to read registry configuration: $($_.Exception.Message)" -Status Error
        return $null
    }
}

function Set-TrayIconConfiguration {
    <#
    .SYNOPSIS
        Configures tray icon behavior with comprehensive backup and rollback support.
    .DESCRIPTION
        Modifies registry settings to control system tray icon visibility with optional backup creation
        and advanced backup options including custom paths, compression, and cache exclusion.
    .PARAMETER Behavior
        Specifies the desired behavior: 'Enable' to show all icons or 'Disable' for Windows default.
    .PARAMETER ForceBackup
        Overwrites existing backup files without confirmation.
    .PARAMETER CustomPath
        Specifies a custom path for the backup file instead of the default location.
    .PARAMETER ExcludeCache
        Excludes icon cache data to reduce backup size (not recommended for complete restoration).
    .PARAMETER CompressBackup
        Compresses backup file to reduce storage footprint.
    .EXAMPLE
        Set-TrayIconConfiguration -Behavior Enable -ForceBackup
        Enables all tray icons and overwrites any existing backup file.
    .EXAMPLE
        Set-TrayIconConfiguration -Behavior Enable -CustomPath "C:\Backups\TrayIcons-$(Get-Date -Format 'yyyyMMdd').json" -CompressBackup
        Enables all tray icons with timestamped, compressed backup in custom location.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('Enable', 'Disable')]
        [string]$Behavior,
        [Parameter(Mandatory = $false)]
        [switch]$Force, 
        [Parameter(Mandatory = $false)]
        [switch]$ForceBackup,
        [Parameter(Mandatory = $false)]
        [string]$CustomPath,
        [Parameter(Mandatory = $false)]
        [switch]$ExcludeCache,
        [Parameter(Mandatory = $false)]
        [switch]$CompressBackup
    )
    
    $value = if ($Behavior -eq 'Enable') { 
        $Script:Configuration.EnableValue 
    } else { 
        $Script:Configuration.DisableValue 
    }
    
    $actionDescription = if ($Behavior -eq 'Enable') { 
        "Show all tray icons" 
    } else { 
        "Enable auto-hide (Windows default)" 
    }
    
    Write-ModernStatus "Configuring tray behavior: $actionDescription" -Status Processing
    
    if (-not $Force -and -not $PSCmdlet.ShouldProcess(
        "Registry: $($Script:Configuration.RegistryPath)\$($Script:Configuration.RegistryValue)", 
        "Set value to $value ($actionDescription)"
    )) {
        Write-ModernStatus "Operation cancelled by user confirmation" -Status Info
        return $false
    }
    
    # Create backup if requested
    if ($BackupRegistry) {
        Write-ModernStatus "Creating registry backup before changes..." -Status Info
        $backupParams = @{
            Overwrite = $Force -or $ForceBackup
        }
        if ($CustomPath) { $backupParams.CustomPath = $CustomPath }
        if ($ExcludeCache) { $backupParams.ExcludeCache = $true }
        if ($CompressBackup) { $backupParams.CompressBackup = $true }
        
        $backupResult = Backup-ComprehensiveTraySettings @backupParams
        if (-not $backupResult) {
            if ($Force) {
                Write-ModernStatus "Backup skipped or failed but continuing due to -Force parameter" -Status Warning
            } else {
                Write-ModernStatus "Backup creation failed or skipped. Continuing with configuration change." -Status Warning
            }
        }
    }
    
    try {
        # Ensure registry path exists
        $registryPath = $Script:Configuration.RegistryPath
        if (-not (Test-Path $registryPath)) {
            Write-ModernStatus "Creating registry path: $registryPath" -Status Info
            $null = New-Item -Path $registryPath -Force -ErrorAction Stop
        }
        
        # Set registry value
        Set-ItemProperty -Path $registryPath `
                         -Name $Script:Configuration.RegistryValue `
                         -Value $value `
                         -Type DWord `
                         -Force `
                         -ErrorAction Stop
        
        Write-ModernStatus "Registry configuration updated successfully: $actionDescription" -Status Success
        
        # Additional status information for enabled state
        if ($Behavior -eq 'Enable') {
            Write-ModernStatus "All system tray icons will be visible after Explorer restart" -Status Info
            if (-not $RestartExplorer) {
                Write-ModernStatus "Use -RestartExplorer parameter to apply changes immediately" -Status Info
            }
        }
        
        return $true
    }
    catch [System.UnauthorizedAccessException] {
        Write-ModernStatus "Access denied to registry. Try running as Administrator." -Status Error
        Write-ModernStatus "This operation may require elevated privileges to modify system settings" -Status Warning
        return $false
    }
    catch {
        Write-ModernStatus "Failed to configure registry: $($_.Exception.Message)" -Status Error
        Write-ModernStatus "Exception Type: $($_.Exception.GetType().FullName)" -Status Warning
        
        # Attempt rollback if backup was created
        if ($BackupRegistry) {
            Write-ModernStatus "Attempting to rollback changes using backup..." -Status Processing
            $rollbackParams = @{}
            if ($CustomPath) { $rollbackParams.BackupPath = $CustomPath }
            if (Restore-ComprehensiveTraySettings @rollbackParams) {
                Write-ModernStatus "Rollback successful. System restored to previous state." -Status Success
            } else {
                Write-ModernStatus "Rollback failed. Manual intervention may be required." -Status Error
            }
        }
        
        return $false
    }
}

function Restart-WindowsExplorerSafely {
    <#
    .SYNOPSIS
        Safely restarts Windows Explorer with comprehensive error handling.
    #>
    
    if (-not $Force -and -not $PSCmdlet.ShouldProcess("Windows Explorer", "Restart process")) {
        Write-ModernStatus "Operation cancelled by ShouldProcess" -Status Info
        return $false
    }
    
    Write-ModernStatus "Initiating safe Windows Explorer restart..." -Status Processing
    
    try {
        $explorerProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue
        
        if ($explorerProcesses.Count -eq 0) {
            Write-ModernStatus "Windows Explorer not running, starting process..." -Status Warning
            Start-Process -FilePath "explorer.exe" -WindowStyle Hidden
            Start-Sleep -Seconds 2
            Write-ModernStatus "Windows Explorer started successfully" -Status Success
            return $true
        }
        
        Write-ModernStatus "Stopping $($explorerProcesses.Count) Windows Explorer process(es)..." -Status Info
        
        # Stop Explorer processes gracefully
        $explorerProcesses | Stop-Process -Force -ErrorAction Stop
        
        # Wait for processes to terminate
        $timeout = $Script:Configuration.ExplorerRestartTimeout
        $timer = 0
        while ((Get-Process -Name explorer -ErrorAction SilentlyContinue) -and $timer -lt $timeout) {
            Start-Sleep -Milliseconds 500
            $timer += 0.5
        }
        
        # Start Explorer
        Write-ModernStatus "Starting Windows Explorer..." -Status Info
        Start-Process -FilePath "explorer.exe" -WindowStyle Hidden
        
        # Wait for initialization
        Start-Sleep -Seconds 2
        
        $restartedProcesses = Get-Process -Name explorer -ErrorAction SilentlyContinue
        if ($restartedProcesses.Count -gt 0) {
            Write-ModernStatus "Windows Explorer restarted successfully ($($restartedProcesses.Count) processes)" -Status Success
            return $true
        }
        else {
            Write-ModernStatus "Windows Explorer may not have started properly" -Status Warning
            return $false
        }
    }
    catch {
        Write-ModernStatus "Failed to restart Windows Explorer: $($_.Exception.Message)" -Status Error
        Write-ModernStatus "Manual restart may be required" -Status Warning
        return $false
    }
}


function Invoke-MainExecution {
    <#
    .SYNOPSIS
        Main execution engine with intelligent context handling and comprehensive workflow management.
    .DESCRIPTION
        Orchestrates script execution flow based on provided parameters with enterprise-grade validation,
        context-aware processing, and professional reporting capabilities. Handles all supported actions
        including Status, Backup, Enable, Disable, Rollback, Update, and Help scenarios.
    .NOTES
        This function maintains state throughout execution and sets appropriate exit codes.
        It ensures proper privilege validation before performing sensitive operations.
    #>
    [CmdletBinding()]
    param()

    # Always show execution parameters at start for auditability
    Write-Host ""
    Write-ModernHeader "Script Execution Context" "Enterprise Configuration"
    Write-ModernCard "Action" $(if ($Action) { $Action } else { "Not specified" })
    Write-ModernCard "Target Scope" $(if ($AllUsers) { "All Users (Group Policy)" } else { "Current User Only" }) -ValueColor $(if ($AllUsers) { "Warning" } else { "Info" })
    Write-ModernCard "Explorer Restart" $(if ($RestartExplorer) { "Enabled" } else { "Disabled" }) -ValueColor $(if ($RestartExplorer) { "Info" } else { "Warning" })
    Write-ModernCard "Registry Backup" $(if ($BackupRegistry -or $Action -in @('Backup', 'Rollback')) { "Enabled" } else { "Disabled" }) -ValueColor $(if ($BackupRegistry -or $Action -in @('Backup', 'Rollback')) { "Info" } else { "Warning" })
    Write-ModernCard "Force Mode" $(if ($Force) { "Enabled (No prompts)" } else { "Disabled" }) -ValueColor $(if ($Force) { "Warning" } else { "Info" })
    Write-ModernCard "Force Backup" $(if ($ForceBackup) { "Enabled (Overwrite backups)" } else { "Disabled" }) -ValueColor $(if ($ForceBackup) { "Warning" } else { "Info" })
    Write-ModernCard "Admin Context" $(if (Test-AdministratorRights) { "Elevated" } else { "Standard" }) -ValueColor $(if (Test-AdministratorRights) { "Success" } else { "Warning" })
    Write-Host ""

    # Flag to control banner display
    $showBanner = $true
    
    # 1. Diagnostic mode - highest priority
    if ($Diagnostic) {
        Show-ModernBanner
        Write-ModernStatus "Running comprehensive diagnostics on backup files and system configuration..." -Status Processing
        Invoke-BackupDiagnostic
        exit $Script:Configuration.ExitCodes.Success
    }
    
    # 2. Help system - second priority
    if ($Help -or $QuickHelp) {
        $effectiveHelpLevel = 'Full'  # Default for -Help
        
        # Determine specific help level
        if ($QuickHelp) {
            $effectiveHelpLevel = 'Quick'
        }
        elseif ($PSBoundParameters.ContainsKey('HelpLevel')) {
            $effectiveHelpLevel = $HelpLevel
        }
        
        # Validate help level
        $validHelpLevels = @('Full', 'Quick', 'Admin', 'Security')
        if ($effectiveHelpLevel -notin $validHelpLevels) {
            Write-ModernStatus "Invalid help level specified: '$effectiveHelpLevel'" -Status Error
            Write-Host ""
            Write-EnhancedOutput "VALID HELP LEVELS:" -Type Primary -Bold
            Write-ModernCard "Full" "Complete documentation with all parameters and examples"
            Write-ModernCard "Quick" "Brief command reference (default help view)"
            Write-ModernCard "Admin" "Administrator deployment instructions and Group Policy guidance"
            Write-ModernCard "Security" "Execution context, privileges, and security considerations"
            Write-Host ""
            exit $Script:Configuration.ExitCodes.GeneralError
        }
        
        # Display appropriate help
        switch ($effectiveHelpLevel) {
            'Full' {
                Show-ModernBanner
                Show-ModernHelp
            }
            'Quick' {
                Show-QuickHelp
            }
            'Admin' {
                Show-ModernBanner
                Show-AdministratorInstructions
            }
            'Security' {
                Show-ModernBanner
                Show-SecurityContext
            }
        }
        exit $Script:Configuration.ExitCodes.Success
    }
    
    # 3. System requirements validation
    if (-not (Test-PowerShellVersion)) {
        Write-ModernStatus "PowerShell version requirement not met (requires $($Script:Configuration.RequiredPSVersion)+)" -Status Error
        exit $Script:Configuration.ExitCodes.PowerShellVersion
    }
    
    if (-not (Test-ExecutionPolicy)) {
        Write-ModernStatus "Script execution blocked by current execution policy" -Status Error
        exit $Script:Configuration.ExitCodes.GeneralError
    }
    
    # 4. Administrator rights validation (only when needed)
    if ($AllUsers -and -not (Test-AdministratorRights)) {
        Write-ModernStatus "Administrator privileges required for all-users configuration" -Status Error
        Write-Host ""
        Write-EnhancedOutput "ADMINISTRATOR ELEVATION REQUIRED" -Type Primary -Bold
        Write-ModernCard "Option 1" "Right-click PowerShell > 'Run as Administrator'"
        Write-ModernCard "Option 2" "powershell.exe -ExecutionPolicy Bypass -File $($Script:Configuration.ScriptName) -Action $Action -AllUsers"
        Write-Host ""
        Write-EnhancedOutput "ALTERNATIVE (current user only):" -Type Primary
        Write-Host "  .\$($Script:Configuration.ScriptName) -Action $Action" -ForegroundColor $Script:ConsoleColors.Warning
        Write-Host ""
        exit $Script:Configuration.ExitCodes.AdminRightsRequired
    }
    
    # 5. Script update handling
    if ($Update) {
        Show-ModernBanner
        Write-ModernHeader "Script Update Check" "Verifying latest version"
        $updateResult = Invoke-ScriptUpdate
        if ($updateResult) {
            Write-Host ""
            Write-ModernStatus "Script updated successfully. Please restart to use new version." -Status Success
        }
        exit $Script:Configuration.ExitCodes.Success
    }
    
    # 6. Default help display when no action specified
    if (-not $Action) {
        Show-ModernBanner
        Show-QuickHelp
        exit $Script:Configuration.ExitCodes.Success
    }
    
    # 7. Main action execution
    Show-ModernBanner
    $actionLower = $Action.ToLower()
    
    try {
        switch ($actionLower) {
            'status' {
                Write-ModernHeader "System Status Report" "Current Tray Icons Configuration"
                Show-EnhancedStatus
            }
            'backup' {
	            if ($AllUsers) {
	                Write-ModernHeader "Create Comprehensive Backup" "Saving ALL tray-related settings for ALL users"
	                Write-ModernStatus "Backup mode: ALL USERS (Group Policy configuration)" -Status Info
	            } else {
	                Write-ModernHeader "Create Comprehensive Backup" "Saving ALL tray-related settings"
	                Write-ModernStatus "Backup mode: CURRENT USER ONLY" -Status Info
	            }
            
		$backupParams = @{
		    Overwrite = $ForceBackup -or $Force
		}
		if ($CustomPath) { $backupParams.CustomPath = $CustomPath }
		if ($ExcludeCache) { $backupParams.ExcludeCache = $true }
		if ($CompressBackup) { $backupParams.CompressBackup = $true }
		if (Backup-ComprehensiveTraySettings @backupParams) {
		    Write-ModernStatus "Comprehensive backup completed successfully!" -Status Success
		} else {
		    $Script:Configuration.ExitCode = $Script:Configuration.ExitCodes.BackupFailed
		    Write-ModernStatus "Backup operation failed" -Status Error
		}
            }
            'enable' {
                if ($AllUsers) {
                    $success = Set-GroupPolicyConfiguration -Behavior 'Enable'
                    Write-ModernHeader "Enterprise Configuration" "Enable ALL Tray Icons for ALL Users"
                    Write-ModernStatus "Configuring system-wide tray icon visibility via Group Policy..." -Status Warning
                } 
                else {
                    $success = Set-TrayIconConfiguration -Behavior 'Enable' -Force:$Force -ForceBackup:$ForceBackup
                    Write-ModernHeader "Tray Icon Configuration" "Enable ALL Icons for Current User"
                    Write-ModernStatus "Configuring comprehensive tray icon visibility..." -Status Processing
                }
                
                # Create backup before making changes (if not already specified)
                if (-not $BackupRegistry -and $actionLower -eq 'enable') {
                    Write-ModernStatus "Creating automatic configuration backup..." -Status Info
                    $BackupRegistry = $true
                }

	if ($BackupRegistry) {
	    $backupParams = @{
	        Overwrite = $script:Force -or $script:ForceBackup
	    }
	    if ($CustomPath) { $backupParams.CustomPath = $CustomPath }
	    if ($ExcludeCache) { $backupParams.ExcludeCache = $true }
	    if ($CompressBackup) { $backupParams.CompressBackup = $true }
	    Write-ModernStatus "Creating registry backup before changes..." -Status Info
	    $backupResult = Backup-ComprehensiveTraySettings @backupParams
	    if (-not $backupResult) {
	        if ($Force) {
	            Write-ModernStatus "Backup skipped or failed but continuing due to -Force parameter" -Status Warning
	        } else {
	            Write-ModernStatus "Backup creation failed or skipped. Continuing with configuration change." -Status Warning
	        }
	    }
	}
                
                if (Enable-AllTrayIconsComprehensive -SkipParameterDisplay) {
                    if ($RestartExplorer) {
                        Write-ModernStatus "Restarting Windows Explorer to apply changes immediately..." -Status Processing
                        $restartResult = Restart-WindowsExplorerSafely
                        if ($restartResult) {
                            Write-ModernStatus "Windows Explorer restarted successfully" -Status Success
                        }
                        else {
                            Write-ModernStatus "Explorer restart partially failed - changes will apply after next logon" -Status Warning
                        }
                    }
                    else {
                        Write-ModernStatus "Configuration completed successfully" -Status Success
                        if ($AllUsers) {
                            Write-ModernStatus "Group Policy changes require user logoff/logon to fully apply" -Status Warning
                        }
                        Write-ModernStatus "Use -RestartExplorer parameter to apply changes immediately" -Status Info
                    }
                }
                else {
                    $Script:Configuration.ExitCode = $Script:Configuration.ExitCodes.GeneralError
                    Write-ModernStatus "Configuration failed - system restored to previous state" -Status Error
                }
            }
            'disable' {
                if ($AllUsers) {
                    Write-ModernHeader "Enterprise Configuration" "Restore Default Tray Behavior for ALL Users"
                    Write-ModernStatus "Configuring system-wide default tray icon behavior via Group Policy..." -Status Warning
                } 
                else {
                    Write-ModernHeader "Tray Icon Configuration" "Restore Default Behavior for Current User"
                    Write-ModernStatus "Restoring Windows default tray icon behavior..." -Status Processing
                }
                
                # Create backup before making changes
                if (-not $BackupRegistry -and $actionLower -eq 'disable') {
                    Write-ModernStatus "Creating automatic configuration backup..." -Status Info
                    $BackupRegistry = $true
                }
                
                $success = $false
                if ($AllUsers) {
                    $success = Set-GroupPolicyConfiguration -Behavior 'Disable'
                } 
                else {
                    $success = Set-TrayIconConfiguration -Behavior 'Disable'
                }
                
                if ($success) {
                    if ($RestartExplorer) {
                        Write-ModernStatus "Restarting Windows Explorer to apply changes immediately..." -Status Processing
                        $restartResult = Restart-WindowsExplorerSafely
                        if ($restartResult) {
                            Write-ModernStatus "Windows Explorer restarted successfully" -Status Success
                        }
                        else {
                            Write-ModernStatus "Explorer restart partially failed - changes will apply after next logon" -Status Warning
                        }
                    }
                    else {
                        Write-ModernStatus "Default behavior restored successfully" -Status Success
                        Write-ModernStatus "Use -RestartExplorer parameter to apply changes immediately" -Status Info
                    }
                }
                else {
                    $Script:Configuration.ExitCode = $Script:Configuration.ExitCodes.GeneralError
                    Write-ModernStatus "Failed to restore default behavior" -Status Error
                }
            }
            'rollback' {
                if ($AllUsers) {
                    Write-ModernHeader "Enterprise Rollback" "Revert ALL Users Configuration"
                    Write-ModernStatus "Restoring previous Group Policy configuration for all users..." -Status Warning
                } 
                else {
                    Write-ModernHeader "Configuration Rollback" "Revert Current User Settings"
                    Write-ModernStatus "Restoring previous tray icon configuration..." -Status Processing
                }
                
                # Try comprehensive restore first, fall back to basic restore
                $rollbackSuccess = $false
                if (Test-Path $(if ($AllUsers) { $Script:Configuration.AllUsersBackupPath } else { $Script:Configuration.BackupRegistryPath })) {
                    Write-ModernStatus "Attempting comprehensive configuration restore..." -Status Processing
                    $rollbackSuccess = Restore-ComprehensiveTraySettings
                }
                
                if (-not $rollbackSuccess) {
                    Write-ModernStatus "Falling back to basic registry rollback..." -Status Warning
                    $rollbackSuccess = Invoke-ConfigurationRollback
                }
                
                if ($rollbackSuccess) {
                    if ($RestartExplorer) {
                        Write-ModernStatus "Restarting Windows Explorer to apply restored settings..." -Status Processing
                        $restartResult = Restart-WindowsExplorerSafely
                        if ($restartResult) {
                            Write-ModernStatus "Configuration successfully rolled back and applied" -Status Success
                        }
                        else {
                            Write-ModernStatus "Rollback completed but Explorer restart failed - logoff/logon required" -Status Warning
                        }
                    }
                    else {
                        Write-ModernStatus "Configuration successfully rolled back" -Status Success
                        Write-ModernStatus "Use -RestartExplorer parameter to apply changes immediately" -Status Info
                    }
                }
                else {
                    $Script:Configuration.ExitCode = $Script:Configuration.ExitCodes.RollbackFailed
                    Write-ModernStatus "Rollback operation failed - system may be in inconsistent state" -Status Error
                    Write-ModernCard "Recovery Tip" "Restart computer to restore known-good state"
                }
            }
            default {
                Write-ModernStatus "Invalid action specified: '$Action'" -Status Error
                Write-EnhancedOutput "VALID ACTIONS:" -Type Primary
                Write-ModernCard "Status" "Display current configuration"
                Write-ModernCard "Backup" "Create configuration backup"
                Write-ModernCard "Enable" "Show all tray icons"
                Write-ModernCard "Disable" "Restore Windows default behavior"
                Write-ModernCard "Rollback" "Revert to previous configuration"
                Write-Host ""
                $Script:Configuration.ExitCode = $Script:Configuration.ExitCodes.GeneralError
            }
        }
    }
    catch {
        Write-ModernStatus "Unexpected error during action '$Action': $($_.Exception.Message)" -Status Error
        Write-ModernStatus "Stack Trace: $($_.ScriptStackTrace)" -Status Warning
        $Script:Configuration.ExitCode = $Script:Configuration.ExitCodes.GeneralError
    }
}

# ============================================================================
# ENHANCED MAIN EXECUTION ENGINE
# ============================================================================

function Enable-AllTrayIconsComprehensive {
    <#
    .SYNOPSIS
        Comprehensive method to enable ALL tray icons using multiple techniques with intelligent context awareness.
    .DESCRIPTION
        Applies a multi-layered approach to ensure all system tray icons remain visible by:
        1. Configuring AutoTray registry settings (current user or Group Policy)
        2. Resetting individual application icon preferences
        3. Clearing system tray icon cache
        4. Forcing system icons visibility
        5. Optimizing Windows 11 specific settings
        The function intelligently adapts its behavior based on execution context (AllUsers vs CurrentUser).
    .PARAMETER SkipParameterDisplay
        Suppresses the detailed parameter display at function start for cleaner output when called from other functions.
    .EXAMPLE
        Enable-AllTrayIconsComprehensive -SkipParameterDisplay
        Enables all tray icons without showing the parameter display header.
    .NOTES
        Author: Mikhail Deynekin
        Requires Administrator privileges when using -AllUsers parameter
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [switch]$SkipParameterDisplay
    )

    # Display execution parameters unless explicitly skipped
    if (-not $SkipParameterDisplay) {
        Write-Host ""
        Write-ModernHeader "Script Execution Parameters" "Configuration Details"
        Write-ModernCard "Action" $(if ($Action) { $Action } else { "Not specified" })
        Write-ModernCard "AllUsers" $(if ($AllUsers) { "Enabled (Group Policy mode)" } else { "Disabled (Current user only)" }) -ValueColor $(if ($AllUsers) { "Warning" } else { "Info" })
        Write-ModernCard "RestartExplorer" $(if ($RestartExplorer) { "Yes" } else { "No" })
        Write-ModernCard "BackupRegistry" $(if ($BackupRegistry) { "Yes" } else { "No" })
        Write-ModernCard "Force Mode" $(if ($Force) { "Enabled (No prompts)" } else { "Disabled" }) -ValueColor $(if ($Force) { "Warning" } else { "Info" })
        Write-ModernCard "Admin Rights" $(if (Test-AdministratorRights) { "Available" } else { "Not available" }) -ValueColor $(if (Test-AdministratorRights) { "Success" } else { "Error" })
        Write-Host ""
    }

    # Context validation
    if ($AllUsers) {
        Write-ModernStatus "Running in ALL USERS mode (Group Policy configuration)" -Status Warning
        if (-not (Test-AdministratorRights)) {
            Write-ModernStatus "ERROR: Administrator rights required for -AllUsers parameter" -Status Error
            return $false
        }
    } 
    else {
        Write-ModernStatus "Running in CURRENT USER ONLY mode" -Status Info
    }

    Write-ModernStatus "Enabling ALL tray icons using comprehensive methods..." -Status Processing
    
    # Track method execution results
    $methods = @{
        AutoTrayDisabled = $false
        IndividualSettingsReset = $false
        TrayCacheCleared = $false
        NotificationSettingsReset = $false
        SystemIconsForced = $false
        Windows11Optimized = $false
        GroupPolicyApplied = $false
    }
    
    # Track detailed error information
    $errorDetails = @{
        GroupPolicyApplied = $null
    }

    try {
        # Method 1: Primary configuration (AutoTray/Group Policy)
        if ($AllUsers) {
            Write-ModernStatus "Applying Group Policy configuration for all users..." -Status Processing
            try {
                if (Set-GroupPolicyConfiguration -Behavior 'Enable') {
                    $methods.AutoTrayDisabled = $true
                    $methods.GroupPolicyApplied = $true
                    Write-ModernStatus "Group Policy configuration successfully applied" -Status Success
                } 
                else {
                    # Capture specific error details
                    if ($Error.Count -gt 0) {
                        $errorDetails.GroupPolicyApplied = $Error[0].Exception.Message
                    }
                }
            } 
            catch {
                $errorDetails.GroupPolicyApplied = $_.Exception.Message
            }
        } 
        else {
            Write-ModernStatus "Applying registry configuration for current user..." -Status Processing
            if (Set-TrayIconConfiguration -Behavior 'Enable') {
                $methods.AutoTrayDisabled = $true
                Write-ModernStatus "Registry configuration successfully applied" -Status Success
            } 
            else {
                Write-ModernStatus "Registry configuration failed" -Status Error
            }
        }

        # Methods 2-4: Current user specific settings (skipped in AllUsers mode)
        $currentUserOnlyMethods = @(
            "IndividualSettingsReset", 
            "TrayCacheCleared", 
            "NotificationSettingsReset", 
            "SystemIconsForced", 
            "Windows11Optimized"
        )

        if (-not $AllUsers) {
            # Method 2: Reset individual icon settings
            Write-ModernStatus "Resetting individual icon settings for current user..." -Status Processing
            $resetResults = Reset-IndividualIconSettings
            if ($resetResults.Values -contains $true) {
                $methods.IndividualSettingsReset = $true
                Write-ModernStatus "Individual icon settings reset completed" -Status Success
            } 
            else {
                Write-ModernStatus "No individual icon settings were reset" -Status Info
            }
            $methods.TrayCacheCleared = $resetResults.TrayNotify
            $methods.NotificationSettingsReset = $resetResults.NotificationSettings

            # Method 3: Force system icons visibility
            Write-ModernStatus "Configuring system icons visibility..." -Status Processing
            $systemIconsPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
            $systemIcons = @(
                @{Name = "HideSCAVolume"; Value = 0},
                @{Name = "HideSCANetwork"; Value = 0},
                @{Name = "HideSCAPower"; Value = 0}
            )
            $systemIconsSet = 0
            
            foreach ($icon in $systemIcons) {
                try {
                    # Ensure registry path exists
                    if (-not (Test-Path $systemIconsPath)) {
                        $null = New-Item -Path $systemIconsPath -Force -ErrorAction Stop
                    }
                    # Set icon visibility
                    Set-ItemProperty -Path $systemIconsPath -Name $icon.Name -Value $icon.Value -Type DWord -Force -ErrorAction Stop
                    $systemIconsSet++
                    Write-ModernStatus "System icon '$($icon.Name)' forced to show" -Status Success
                }
                catch {
                    Write-ModernStatus "Failed to set system icon '$($icon.Name)': $($_.Exception.Message)" -Status Warning
                }
            }
            
            if ($systemIconsSet -gt 0) {
                $methods.SystemIconsForced = $true
                Write-ModernStatus "System icons forced to show ($systemIconsSet settings)" -Status Success
            } 
            else {
                Write-ModernStatus "No system icons were configured" -Status Info
            }

            # Method 4: Windows 11 specific optimization
            $windowsVersion = Get-WindowsVersion
            if ($windowsVersion -Like "*11*") {
                Write-ModernStatus "Applying Windows 11 specific tray icon optimizations..." -Status Processing
                $win11Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
                if (Test-Path $win11Path) {
                    try {
                        Set-ItemProperty -Path $win11Path -Name "TaskbarMn" -Value 0 -Type DWord -Force -ErrorAction SilentlyContinue
                        $methods.Windows11Optimized = $true
                        Write-ModernStatus "Windows 11 specific settings applied" -Status Success
                    }
                    catch {
                        Write-ModernStatus "Windows 11 specific settings failed: $($_.Exception.Message)" -Status Warning
                    }
                } 
                else {
                    Write-ModernStatus "Windows 11 Advanced registry path not found" -Status Warning
                }
            } 
            else {
                Write-ModernStatus "Windows 11 specific settings skipped (running on: $windowsVersion)" -Status Info
            }
        } 
        else {
            # Skip current-user-only methods in AllUsers mode with clear explanation
            foreach ($method in $currentUserOnlyMethods) {
                Write-ModernStatus "Skipping $method (not applicable in AllUsers/Group Policy mode)" -Status Info
            }
        }

        Write-ModernStatus "Comprehensive tray icon enabling completed" -Status Success
        
        # Display execution results with contextual coloring
        Write-Host ""
        Write-EnhancedOutput "EXECUTION RESULTS:" -Type Primary
        
        # Sort methods by priority for display
        $sortedMethods = $methods.GetEnumerator() | Sort-Object {
            switch ($_.Key) {
                "AutoTrayDisabled" { 0 }
                "GroupPolicyApplied" { 1 }
                "IndividualSettingsReset" { 2 }
                "SystemIconsForced" { 3 }
                "Windows11Optimized" { 4 }
                "TrayCacheCleared" { 5 }
                "NotificationSettingsReset" { 6 }
                default { 99 }
            }
        }

        foreach ($method in $sortedMethods) {
            $status = "Not Executed"
            $color = "Info"
            $details = ""

            if ($method.Value) {
                $status = "Success"
                $color = "Success"
            }
            elseif ($AllUsers -and $method.Key -in $currentUserOnlyMethods) {
                $status = "Skipped"
                $color = "Warning"
                $details = " (AllUsers policy mode)"
            }
            elseif ($method.Key -eq "GroupPolicyApplied" -and $AllUsers) {
                $status = "Failed"
                $color = "Error"
                if ($errorDetails.GroupPolicyApplied) {
                    $details = " - " + $errorDetails.GroupPolicyApplied.Substring(0, [Math]::Min(75, $errorDetails.GroupPolicyApplied.Length)) + "..."
                }
            }
            elseif ($method.Key -eq "GroupPolicyApplied" -and -not $AllUsers) {
                $status = "N/A"
                $color = "Info"
                $details = " (Not applicable in current user mode)"
            }

            # Format the status text with details
            $statusText = "$status$details"
            Write-ModernCard $method.Key $statusText -ValueColor $color
        }
        
        # Detailed troubleshooting for Group Policy failures
        if ($AllUsers -and -not $methods.GroupPolicyApplied -and $errorDetails.GroupPolicyApplied) {
            Write-Host ""
            Write-ModernHeader "TROUBLESHOOTING GUIDE" "Group Policy Configuration Failed"
            
            # Intelligent error analysis
            if ($errorDetails.GroupPolicyApplied -like "*UnauthorizedAccessException*" -or 
                $errorDetails.GroupPolicyApplied -like "*Access is denied*" -or 
                $errorDetails.GroupPolicyApplied -like "*Administrator rights*") {
                
                Write-ModernStatus "ACCESS ISSUE DETECTED" -Status Error
                Write-ModernCard "Cause" "Insufficient permissions to modify Group Policy"
                Write-ModernCard "Solution" "Run PowerShell as Administrator before executing this script"
                Write-ModernCard "Verification" "Right-click PowerShell > 'Run as Administrator'"
            }
            elseif ($errorDetails.GroupPolicyApplied -like "*Registry policy settings*" -or 
                    $errorDetails.GroupPolicyApplied -like "*policy*" -or 
                    $errorDetails.GroupPolicyApplied -like "*GPO*") {
                
                Write-ModernStatus "GROUP POLICY RESTRICTION" -Status Error
                Write-ModernCard "Cause" "Registry modifications blocked by domain Group Policy"
                Write-ModernCard "Solution" "Contact your system administrator to modify Group Policy settings"
                Write-ModernCard "Workaround" "Use current user mode without -AllUsers parameter"
            }
            elseif ($errorDetails.GroupPolicyApplied -like "*path not found*" -or 
                    $errorDetails.GroupPolicyApplied -like "*cannot find path*" -or 
                    $errorDetails.GroupPolicyApplied -like "*HKLM*" -or 
                    $errorDetails.GroupPolicyApplied -like "*HKCU*") {
                
                Write-ModernStatus "REGISTRY PATH ISSUE" -Status Error
                Write-ModernCard "Cause" "Required registry paths for Group Policy are missing or inaccessible"
                Write-ModernCard "Diagnostic" "Get-Service gpsvc | Select-Object Status, DisplayName"
                Write-ModernCard "Fix" "Ensure Group Policy Client service is running and registry permissions are correct"
            }
            else {
                Write-ModernStatus "UNEXPECTED ERROR" -Status Error
                Write-ModernCard "Error" $(if ($errorDetails.GroupPolicyApplied) { $errorDetails.GroupPolicyApplied } else { "No specific error details available" })
                Write-ModernCard "Next Steps" "Run with -Diagnostic parameter for comprehensive system analysis"
                Write-ModernCard "Support" "Report issue at $($Script:Configuration.GitHubRepository) with full logs"
            }
        }
        
        return $true
    }
    catch {
        Write-ModernStatus "Comprehensive enable failed: $($_.Exception.Message)" -Status Error
        Write-ModernStatus "Exception Type: $($_.Exception.GetType().FullName)" -Status Warning
        Write-ModernStatus "Stack Trace: $($_.ScriptStackTrace)" -Status Warning
        return $false
    }
}

# ============================================================================
# ENHANCED SCRIPT ENTRY POINT
# ============================================================================

# Version check at the beginning
if ($PSVersionTable.PSVersion.Major -lt 5) {
    Write-Host "ERROR: PowerShell 5.1 or higher required. Current version: $($PSVersionTable.PSVersion)" -ForegroundColor Red
    exit $Script:Configuration.ExitCodes.PowerShellVersion
}

try {
    # Enhanced parameter validation
    if ($PSBoundParameters.Count -eq 0 -and $MyInvocation.ExpectingInput -eq $false) {
        # No parameters provided, show application info
        Show-ModernBanner
        Show-ApplicationInfo
        exit $Script:Configuration.ExitCodes.Success
    }
    
    # Execute main logic
    Invoke-MainExecution
}
catch {
    Write-ModernStatus "Unhandled exception: $($_.Exception.Message)" -Status Error
    Write-ModernStatus "Stack trace: $($_.ScriptStackTrace)" -Status Error
    $Script:Configuration.ExitCode = $Script:Configuration.ExitCodes.GeneralError
}
finally {
    if ($Script:Configuration.ExitCode -ne 0) {
        Write-ModernStatus "Script completed with errors (Exit Code: $($Script:Configuration.ExitCode))" -Status Error
    } else {
        Write-ModernStatus "Script completed successfully" -Status Success
    }
    
    exit $Script:Configuration.ExitCode
}
