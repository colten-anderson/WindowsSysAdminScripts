<#
.SYNOPSIS
    Generates comprehensive reports for Exchange Online mailboxes.

.DESCRIPTION
    This script connects to Exchange Online and generates detailed reports about mailboxes,
    including mailbox statistics, permissions, and configuration details.

.PARAMETER OutputPath
    Path where the report files will be saved. Defaults to the script directory.

.PARAMETER ExportFormat
    Export format for the report. Options: CSV, JSON, HTML, All. Defaults to HTML.

.PARAMETER MailboxType
    Type of mailboxes to include: All, UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox. Defaults to All.

.PARAMETER IncludeStatistics
    Include mailbox size and item count statistics.

.PARAMETER IncludePermissions
    Include mailbox permissions and delegates.

.PARAMETER IncludeForwarding
    Include mail forwarding and redirection settings.

.PARAMETER IncludeArchive
    Include archive mailbox information.

.EXAMPLE
    .\Get-MailboxReport.ps1

.EXAMPLE
    .\Get-MailboxReport.ps1 -OutputPath "C:\Reports" -ExportFormat "All" -IncludeStatistics -IncludePermissions -MailboxType "UserMailbox"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - ExchangeOnlineManagement PowerShell module
    - Appropriate permissions in Exchange Online
    - Exchange Administrator or Global Administrator role
    
    Required Permissions:
    - View-Only Recipients or higher
    - Mailbox Import Export (for statistics)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "HTML", "All")]
    [string]$ExportFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "UserMailbox", "SharedMailbox", "RoomMailbox", "EquipmentMailbox")]
    [string]$MailboxType = "All",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeStatistics,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludePermissions,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeForwarding,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeArchive
)

# Import required modules
try {
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    Write-Host "ExchangeOnlineManagement module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import ExchangeOnlineManagement module. Please install using: Install-Module ExchangeOnlineManagement"
    exit 1
}

# Initialize variables
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportData = @{}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

Write-Log "Starting Exchange Online mailbox report generation"

# Connect to Exchange Online
try {
    Write-Log "Connecting to Exchange Online..."
    Connect-ExchangeOnline -ShowBanner:$false
    Write-Log "Successfully connected to Exchange Online" -Level "SUCCESS"
    
    # Get organization information
    $orgConfig = Get-OrganizationConfig
    Write-Log "Connected to organization: $($orgConfig.DisplayName)"
    
} catch {
    Write-Log "Failed to connect to Exchange Online: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Get mailboxes based on type filter
try {
    Write-Log "Retrieving mailboxes from Exchange Online..."
    
    if ($MailboxType -eq "All") {
        $mailboxes = Get-Mailbox -ResultSize Unlimited
    } else {
        $mailboxes = Get-Mailbox -RecipientTypeDetails $MailboxType -ResultSize Unlimited
    }
    
    Write-Log "Retrieved $($mailboxes.Count) mailboxes" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to retrieve mailboxes: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Process mailbox information
Write-Log "Processing mailbox information..."
$mailboxData = @()

foreach ($mailbox in $mailboxes) {
    try {
        $mailboxInfo = [PSCustomObject]@{
            DisplayName = $mailbox.DisplayName
            UserPrincipalName = $mailbox.UserPrincipalName
            PrimarySmtpAddress = $mailbox.PrimarySmtpAddress
            Alias = $mailbox.Alias
            RecipientTypeDetails = $mailbox.RecipientTypeDetails
            OrganizationalUnit = $mailbox.OrganizationalUnit
            Database = $mailbox.Database
            ServerName = $mailbox.ServerName
            UsageLocation = $mailbox.UsageLocation
            Office = $mailbox.Office
            Department = $mailbox.Department
            Title = $mailbox.Title
            Company = $mailbox.Company
            Manager = $mailbox.Manager
            WhenCreated = $mailbox.WhenCreated
            WhenChanged = $mailbox.WhenChanged
            HiddenFromAddressListsEnabled = $mailbox.HiddenFromAddressListsEnabled
            DeliverToMailboxAndForward = $mailbox.DeliverToMailboxAndForward
            ForwardingAddress = $mailbox.ForwardingAddress
            ForwardingSmtpAddress = $mailbox.ForwardingSmtpAddress
            LitigationHoldEnabled = $mailbox.LitigationHoldEnabled
            InPlaceHolds = ($mailbox.InPlaceHolds -join "; ")
            ArchiveStatus = $mailbox.ArchiveStatus
            ArchiveDatabase = $mailbox.ArchiveDatabase
            RetentionPolicy = $mailbox.RetentionPolicy
            AddressBookPolicy = $mailbox.AddressBookPolicy
            EmailAddresses = ($mailbox.EmailAddresses -join "; ")
            ProhibitSendQuota = $mailbox.ProhibitSendQuota
            ProhibitSendReceiveQuota = $mailbox.ProhibitSendReceiveQuota
            IssueWarningQuota = $mailbox.IssueWarningQuota
            UseDatabaseQuotaDefaults = $mailbox.UseDatabaseQuotaDefaults
        }
        
        $mailboxData += $mailboxInfo
        
    } catch {
        Write-Log "Error processing mailbox $($mailbox.DisplayName): $($_.Exception.Message)" -Level "WARNING"
    }
}

$reportData["Mailboxes"] = $mailboxData

# Get mailbox statistics if requested
if ($IncludeStatistics) {
    try {
        Write-Log "Retrieving mailbox statistics..."
        
        $statisticsData = @()
        $processedCount = 0
        
        foreach ($mailbox in $mailboxes) {
            $processedCount++
            Write-Progress -Activity "Getting Mailbox Statistics" -Status "Processing $($mailbox.DisplayName)" -PercentComplete (($processedCount / $mailboxes.Count) * 100)
            
            try {
                $stats = Get-MailboxStatistics -Identity $mailbox.UserPrincipalName -ErrorAction SilentlyContinue
                
                if ($stats) {
                    $statsInfo = [PSCustomObject]@{
                        DisplayName = $mailbox.DisplayName
                        UserPrincipalName = $mailbox.UserPrincipalName
                        TotalItemSize = $stats.TotalItemSize
                        TotalDeletedItemSize = $stats.TotalDeletedItemSize
                        ItemCount = $stats.ItemCount
                        DeletedItemCount = $stats.DeletedItemCount
                        LastLogonTime = $stats.LastLogonTime
                        LastLogoffTime = $stats.LastLogoffTime
                        LastUserActionTime = $stats.LastUserActionTime
                        DatabaseName = $stats.DatabaseName
                        ServerName = $stats.ServerName
                        StorageLimitStatus = $stats.StorageLimitStatus
                        DisconnectReason = $stats.DisconnectReason
                        DisconnectDate = $stats.DisconnectDate
                    }
                    
                    $statisticsData += $statsInfo
                }
                
            } catch {
                Write-Log "Error getting statistics for $($mailbox.DisplayName): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        Write-Progress -Activity "Getting Mailbox Statistics" -Completed
        $reportData["Statistics"] = $statisticsData
        Write-Log "Retrieved statistics for $($statisticsData.Count) mailboxes" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to retrieve mailbox statistics: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Get mailbox permissions if requested
if ($IncludePermissions) {
    try {
        Write-Log "Retrieving mailbox permissions..."
        
        $permissionsData = @()
        $processedCount = 0
        
        foreach ($mailbox in $mailboxes) {
            $processedCount++
            Write-Progress -Activity "Getting Mailbox Permissions" -Status "Processing $($mailbox.DisplayName)" -PercentComplete (($processedCount / $mailboxes.Count) * 100)
            
            try {
                # Get mailbox permissions
                $permissions = Get-MailboxPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.User -notlike "NT AUTHORITY\*" -and $_.User -notlike "S-1-*" }
                
                foreach ($permission in $permissions) {
                    $permissionInfo = [PSCustomObject]@{
                        Mailbox = $mailbox.DisplayName
                        MailboxUPN = $mailbox.UserPrincipalName
                        User = $permission.User
                        AccessRights = ($permission.AccessRights -join "; ")
                        IsInherited = $permission.IsInherited
                        Deny = $permission.Deny
                    }
                    
                    $permissionsData += $permissionInfo
                }
                
                # Get send-as permissions
                $sendAsPermissions = Get-RecipientPermission -Identity $mailbox.UserPrincipalName | Where-Object { $_.Trustee -notlike "NT AUTHORITY\*" -and $_.Trustee -notlike "S-1-*" }
                
                foreach ($sendAs in $sendAsPermissions) {
                    $sendAsInfo = [PSCustomObject]@{
                        Mailbox = $mailbox.DisplayName
                        MailboxUPN = $mailbox.UserPrincipalName
                        User = $sendAs.Trustee
                        AccessRights = "SendAs"
                        IsInherited = $sendAs.IsInherited
                        Deny = $sendAs.Deny
                    }
                    
                    $permissionsData += $sendAsInfo
                }
                
            } catch {
                Write-Log "Error getting permissions for $($mailbox.DisplayName): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        Write-Progress -Activity "Getting Mailbox Permissions" -Completed
        $reportData["Permissions"] = $permissionsData
        Write-Log "Retrieved permissions for $($permissionsData.Count) permission entries" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to retrieve mailbox permissions: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Get forwarding information if requested
if ($IncludeForwarding) {
    try {
        Write-Log "Retrieving mail forwarding information..."
        
        $forwardingData = @()
        
        foreach ($mailbox in $mailboxes) {
            if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress -or $mailbox.DeliverToMailboxAndForward) {
                $forwardingInfo = [PSCustomObject]@{
                    DisplayName = $mailbox.DisplayName
                    UserPrincipalName = $mailbox.UserPrincipalName
                    ForwardingAddress = $mailbox.ForwardingAddress
                    ForwardingSmtpAddress = $mailbox.ForwardingSmtpAddress
                    DeliverToMailboxAndForward = $mailbox.DeliverToMailboxAndForward
                }
                
                $forwardingData += $forwardingInfo
            }
        }
        
        $reportData["Forwarding"] = $forwardingData
        Write-Log "Found $($forwardingData.Count) mailboxes with forwarding configured" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to retrieve forwarding information: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Get archive information if requested
if ($IncludeArchive) {
    try {
        Write-Log "Retrieving archive mailbox information..."
        
        $archiveData = @()
        
        foreach ($mailbox in $mailboxes) {
            if ($mailbox.ArchiveStatus -ne "None") {
                try {
                    $archiveStats = Get-MailboxStatistics -Identity $mailbox.UserPrincipalName -Archive -ErrorAction SilentlyContinue
                    
                    $archiveInfo = [PSCustomObject]@{
                        DisplayName = $mailbox.DisplayName
                        UserPrincipalName = $mailbox.UserPrincipalName
                        ArchiveStatus = $mailbox.ArchiveStatus
                        ArchiveDatabase = $mailbox.ArchiveDatabase
                        ArchiveQuota = $mailbox.ArchiveQuota
                        ArchiveWarningQuota = $mailbox.ArchiveWarningQuota
                        ArchiveTotalItemSize = if ($archiveStats) { $archiveStats.TotalItemSize } else { "N/A" }
                        ArchiveItemCount = if ($archiveStats) { $archiveStats.ItemCount } else { "N/A" }
                        ArchiveLastLogonTime = if ($archiveStats) { $archiveStats.LastLogonTime } else { "N/A" }
                    }
                    
                    $archiveData += $archiveInfo
                    
                } catch {
                    Write-Log "Error getting archive info for $($mailbox.DisplayName): $($_.Exception.Message)" -Level "WARNING"
                }
            }
        }
        
        $reportData["Archives"] = $archiveData
        Write-Log "Retrieved archive information for $($archiveData.Count) mailboxes" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to retrieve archive information: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Generate summary statistics
$summary = [PSCustomObject]@{
    TotalMailboxes = $mailboxData.Count
    UserMailboxes = ($mailboxData | Where-Object { $_.RecipientTypeDetails -eq "UserMailbox" }).Count
    SharedMailboxes = ($mailboxData | Where-Object { $_.RecipientTypeDetails -eq "SharedMailbox" }).Count
    RoomMailboxes = ($mailboxData | Where-Object { $_.RecipientTypeDetails -eq "RoomMailbox" }).Count
    EquipmentMailboxes = ($mailboxData | Where-Object { $_.RecipientTypeDetails -eq "EquipmentMailbox" }).Count
    LitigationHoldEnabled = ($mailboxData | Where-Object { $_.LitigationHoldEnabled -eq $true }).Count
    ForwardingEnabled = ($mailboxData | Where-Object { $_.ForwardingAddress -or $_.ForwardingSmtpAddress }).Count
    ArchiveEnabled = ($mailboxData | Where-Object { $_.ArchiveStatus -ne "None" }).Count
    HiddenFromGAL = ($mailboxData | Where-Object { $_.HiddenFromAddressListsEnabled -eq $true }).Count
}

$reportData["Summary"] = $summary

# Export data based on format
Write-Log "Exporting report data..."

if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "All") {
    foreach ($category in $reportData.Keys) {
        $csvPath = Join-Path $OutputPath "ExchangeOnline_$($category)_$timestamp.csv"
        try {
            $reportData[$category] | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Log "CSV exported: $csvPath" -Level "SUCCESS"
        } catch {
            Write-Log "Failed to export CSV for $category`: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "All") {
    $jsonPath = Join-Path $OutputPath "ExchangeOnline_$timestamp.json"
    try {
        $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Log "JSON exported: $jsonPath" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to export JSON: $($_.Exception.Message)" -Level "ERROR"
    }
}

if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "All") {
    $htmlPath = Join-Path $OutputPath "ExchangeOnline_$timestamp.html"
    
    # Generate HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Exchange Online Mailbox Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; text-align: center; }
        h2 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 5px; }
        .summary { background-color: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .summary-item { background-color: white; padding: 10px; border-radius: 5px; text-align: center; border-left: 4px solid #0078d4; }
        .summary-value { font-size: 24px; font-weight: bold; color: #0078d4; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 10px; }
        th, td { border: 1px solid #ddd; padding: 4px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .category { margin-bottom: 30px; }
        .enabled { color: green; font-weight: bold; }
        .disabled { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Exchange Online Mailbox Report</h1>
        <div class="summary">
            <h3>Report Summary</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Organization:</strong> $($orgConfig.DisplayName)</p>
            <p><strong>Mailbox Filter:</strong> $MailboxType</p>
            
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value">$($summary.TotalMailboxes)</div>
                    <div>Total Mailboxes</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.UserMailboxes)</div>
                    <div>User Mailboxes</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.SharedMailboxes)</div>
                    <div>Shared Mailboxes</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.RoomMailboxes)</div>
                    <div>Room Mailboxes</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.LitigationHoldEnabled)</div>
                    <div>Litigation Hold</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.ForwardingEnabled)</div>
                    <div>Forwarding Enabled</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.ArchiveEnabled)</div>
                    <div>Archive Enabled</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.HiddenFromGAL)</div>
                    <div>Hidden from GAL</div>
                </div>
            </div>
        </div>
"@

    # Add mailboxes table
    if ($reportData.ContainsKey("Mailboxes") -and $reportData["Mailboxes"].Count -gt 0) {
        $htmlContent += @"
        <div class="category">
            <h2>Mailboxes</h2>
            <table>
                <thead>
                    <tr>
                        <th>Display Name</th>
                        <th>UPN</th>
                        <th>Type</th>
                        <th>Primary SMTP</th>
                        <th>Database</th>
                        <th>Litigation Hold</th>
                        <th>Archive Status</th>
                        <th>Forwarding</th>
                        <th>Created</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($mailbox in ($reportData["Mailboxes"] | Sort-Object DisplayName)) {
            $litigationClass = if ($mailbox.LitigationHoldEnabled) { "enabled" } else { "disabled" }
            $forwardingStatus = if ($mailbox.ForwardingAddress -or $mailbox.ForwardingSmtpAddress) { "Yes" } else { "No" }
            $forwardingClass = if ($forwardingStatus -eq "Yes") { "enabled" } else { "disabled" }
            
            $htmlContent += @"
                <tr>
                    <td>$($mailbox.DisplayName)</td>
                    <td>$($mailbox.UserPrincipalName)</td>
                    <td>$($mailbox.RecipientTypeDetails)</td>
                    <td>$($mailbox.PrimarySmtpAddress)</td>
                    <td>$($mailbox.Database)</td>
                    <td class="$litigationClass">$($mailbox.LitigationHoldEnabled)</td>
                    <td>$($mailbox.ArchiveStatus)</td>
                    <td class="$forwardingClass">$forwardingStatus</td>
                    <td>$($mailbox.WhenCreated)</td>
                </tr>
"@
        }
        
        $htmlContent += "</tbody></table></div>"
    }

    # Add statistics table if available
    if ($reportData.ContainsKey("Statistics") -and $reportData["Statistics"].Count -gt 0) {
        $htmlContent += @"
        <div class="category">
            <h2>Mailbox Statistics</h2>
            <table>
                <thead>
                    <tr>
                        <th>Display Name</th>
                        <th>Total Size</th>
                        <th>Item Count</th>
                        <th>Last Logon</th>
                        <th>Storage Status</th>
                        <th>Database</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($stat in ($reportData["Statistics"] | Sort-Object DisplayName)) {
            $htmlContent += @"
                <tr>
                    <td>$($stat.DisplayName)</td>
                    <td>$($stat.TotalItemSize)</td>
                    <td>$($stat.ItemCount)</td>
                    <td>$($stat.LastLogonTime)</td>
                    <td>$($stat.StorageLimitStatus)</td>
                    <td>$($stat.DatabaseName)</td>
                </tr>
"@
        }
        
        $htmlContent += "</tbody></table></div>"
    }

    $htmlContent += @"
    </div>
</body>
</html>
"@

    try {
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Log "HTML exported: $htmlPath" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to export HTML: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Disconnect from Exchange Online
try {
    Disconnect-ExchangeOnline -Confirm:$false
    Write-Log "Disconnected from Exchange Online" -Level "SUCCESS"
} catch {
    Write-Log "Error disconnecting from Exchange Online: $($_.Exception.Message)" -Level "WARNING"
}

# Display summary
Write-Host "`n=== EXCHANGE ONLINE MAILBOX REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Mailboxes: $($summary.TotalMailboxes)" -ForegroundColor White
Write-Host "User Mailboxes: $($summary.UserMailboxes)" -ForegroundColor White
Write-Host "Shared Mailboxes: $($summary.SharedMailboxes)" -ForegroundColor White
Write-Host "Room Mailboxes: $($summary.RoomMailboxes)" -ForegroundColor White
Write-Host "Equipment Mailboxes: $($summary.EquipmentMailboxes)" -ForegroundColor White
Write-Host "Litigation Hold Enabled: $($summary.LitigationHoldEnabled)" -ForegroundColor White
Write-Host "Forwarding Enabled: $($summary.ForwardingEnabled)" -ForegroundColor White
Write-Host "Archive Enabled: $($summary.ArchiveEnabled)" -ForegroundColor White
Write-Host "Export Format: $ExportFormat" -ForegroundColor White
Write-Host "Output Path: $OutputPath" -ForegroundColor White

Write-Log "Exchange Online mailbox report generation completed" -Level "SUCCESS"

