<#
.SYNOPSIS
    Generates a comprehensive security audit report for Windows systems.

.DESCRIPTION
    This script performs various security checks on Windows systems including user accounts,
    password policies, firewall status, Windows updates, and security event logs.

.PARAMETER ComputerName
    Name of the computer to audit. Defaults to local computer.

.PARAMETER OutputPath
    Path where the audit report will be saved. Defaults to the script directory.

.PARAMETER ExportFormat
    Export format for the report. Options: CSV, HTML, Both. Defaults to HTML.

.PARAMETER CheckEventLogs
    Include security event log analysis in the audit.

.PARAMETER DaysBack
    Number of days back to check for security events. Defaults to 7 days.

.EXAMPLE
    .\Get-SecurityAuditReport.ps1

.EXAMPLE
    .\Get-SecurityAuditReport.ps1 -ComputerName "SERVER01" -OutputPath "C:\Reports" -CheckEventLogs -DaysBack 30

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Run as Administrator
    - WMI/CIM access to target computer
    - Appropriate permissions on target computer
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "HTML", "Both")]
    [string]$ExportFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [switch]$CheckEventLogs,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 7
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$auditData = @{}
$findings = @()
$recommendations = @()

Write-Host "Starting security audit for: $ComputerName" -ForegroundColor Cyan

# Function to add findings
function Add-Finding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Severity,
        [string]$Recommendation
    )
    
    $script:findings += [PSCustomObject]@{
        Category = $Category
        Finding = $Finding
        Severity = $Severity
        Recommendation = $Recommendation
    }
}

# Test connectivity
try {
    $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
    if (-not $ping) {
        throw "Cannot connect to $ComputerName"
    }
    Write-Host "✓ Connectivity test passed" -ForegroundColor Green
} catch {
    Write-Error "Cannot connect to $ComputerName`: $($_.Exception.Message)"
    exit 1
}

# Get system information
try {
    Write-Host "Gathering system information..." -ForegroundColor Yellow
    $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName
    
    $auditData["SystemInfo"] = [PSCustomObject]@{
        ComputerName = $systemInfo.Name
        Domain = $systemInfo.Domain
        OSName = $osInfo.Caption
        OSVersion = $osInfo.Version
        OSBuild = $osInfo.BuildNumber
        LastBootUpTime = $osInfo.LastBootUpTime
        TotalPhysicalMemory = [math]::Round($systemInfo.TotalPhysicalMemory / 1GB, 2)
    }
    
    Write-Host "✓ System information collected" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to collect system information: $($_.Exception.Message)" -ForegroundColor Red
    Add-Finding -Category "System" -Finding "Failed to collect system information" -Severity "High" -Recommendation "Check WMI/CIM connectivity and permissions"
}

# Check local user accounts
try {
    Write-Host "Auditing local user accounts..." -ForegroundColor Yellow
    $localUsers = Get-LocalUser -ComputerName $ComputerName
    
    $userAudit = @()
    foreach ($user in $localUsers) {
        $userInfo = [PSCustomObject]@{
            Name = $user.Name
            Enabled = $user.Enabled
            PasswordRequired = $user.PasswordRequired
            PasswordExpires = $user.PasswordExpires
            PasswordLastSet = $user.PasswordLastSet
            LastLogon = $user.LastLogon
            PasswordChangeableDate = $user.PasswordChangeableDate
            AccountExpires = $user.AccountExpires
            Description = $user.Description
        }
        $userAudit += $userInfo
        
        # Check for security issues
        if ($user.Enabled -and -not $user.PasswordRequired) {
            Add-Finding -Category "User Accounts" -Finding "User '$($user.Name)' is enabled but has no password required" -Severity "High" -Recommendation "Enable password requirement for all user accounts"
        }
        
        if ($user.Enabled -and $user.PasswordLastSet -lt (Get-Date).AddDays(-90)) {
            Add-Finding -Category "User Accounts" -Finding "User '$($user.Name)' has not changed password in over 90 days" -Severity "Medium" -Recommendation "Implement password aging policy"
        }
        
        if ($user.Name -eq "Administrator" -and $user.Enabled) {
            Add-Finding -Category "User Accounts" -Finding "Built-in Administrator account is enabled" -Severity "Medium" -Recommendation "Disable built-in Administrator account and use named admin accounts"
        }
        
        if ($user.Name -eq "Guest" -and $user.Enabled) {
            Add-Finding -Category "User Accounts" -Finding "Guest account is enabled" -Severity "High" -Recommendation "Disable Guest account"
        }
    }
    
    $auditData["LocalUsers"] = $userAudit
    Write-Host "✓ Local user accounts audited ($($localUsers.Count) users)" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to audit local users: $($_.Exception.Message)" -ForegroundColor Red
    Add-Finding -Category "User Accounts" -Finding "Failed to audit local user accounts" -Severity "High" -Recommendation "Check permissions and PowerShell execution policy"
}

# Check local groups and memberships
try {
    Write-Host "Auditing local groups..." -ForegroundColor Yellow
    $localGroups = Get-LocalGroup -ComputerName $ComputerName
    
    $groupAudit = @()
    foreach ($group in $localGroups) {
        try {
            $members = Get-LocalGroupMember -Group $group.Name -ComputerName $ComputerName -ErrorAction SilentlyContinue
            $memberNames = ($members | ForEach-Object { $_.Name }) -join "; "
            
            $groupInfo = [PSCustomObject]@{
                Name = $group.Name
                Description = $group.Description
                Members = $memberNames
                MemberCount = $members.Count
            }
            $groupAudit += $groupInfo
            
            # Check for security issues
            if ($group.Name -eq "Administrators" -and $members.Count -gt 2) {
                Add-Finding -Category "Group Membership" -Finding "Administrators group has $($members.Count) members" -Severity "Medium" -Recommendation "Limit membership in Administrators group to essential accounts only"
            }
            
        } catch {
            $groupInfo = [PSCustomObject]@{
                Name = $group.Name
                Description = $group.Description
                Members = "Error retrieving members"
                MemberCount = 0
            }
            $groupAudit += $groupInfo
        }
    }
    
    $auditData["LocalGroups"] = $groupAudit
    Write-Host "✓ Local groups audited ($($localGroups.Count) groups)" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to audit local groups: $($_.Exception.Message)" -ForegroundColor Red
    Add-Finding -Category "Group Membership" -Finding "Failed to audit local groups" -Severity "Medium" -Recommendation "Check permissions and group access"
}

# Check Windows Firewall status
try {
    Write-Host "Checking Windows Firewall status..." -ForegroundColor Yellow
    $firewallProfiles = Get-NetFirewallProfile -ComputerName $ComputerName
    
    $firewallAudit = @()
    foreach ($profile in $firewallProfiles) {
        $profileInfo = [PSCustomObject]@{
            Name = $profile.Name
            Enabled = $profile.Enabled
            DefaultInboundAction = $profile.DefaultInboundAction
            DefaultOutboundAction = $profile.DefaultOutboundAction
            AllowInboundRules = $profile.AllowInboundRules
            AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
            AllowLocalIPsecRules = $profile.AllowLocalIPsecRules
            NotifyOnListen = $profile.NotifyOnListen
            EnableStealthModeForIPsec = $profile.EnableStealthModeForIPsec
        }
        $firewallAudit += $profileInfo
        
        # Check for security issues
        if (-not $profile.Enabled) {
            Add-Finding -Category "Firewall" -Finding "$($profile.Name) firewall profile is disabled" -Severity "High" -Recommendation "Enable Windows Firewall for all network profiles"
        }
        
        if ($profile.DefaultInboundAction -eq "Allow") {
            Add-Finding -Category "Firewall" -Finding "$($profile.Name) profile allows inbound connections by default" -Severity "High" -Recommendation "Set default inbound action to Block"
        }
    }
    
    $auditData["FirewallProfiles"] = $firewallAudit
    Write-Host "✓ Windows Firewall status checked" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check firewall status: $($_.Exception.Message)" -ForegroundColor Red
    Add-Finding -Category "Firewall" -Finding "Failed to check Windows Firewall status" -Severity "High" -Recommendation "Manually verify firewall configuration"
}

# Check Windows Update status
try {
    Write-Host "Checking Windows Update status..." -ForegroundColor Yellow
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $searchResult = $updateSearcher.Search("IsInstalled=0")
    
    $pendingUpdates = @()
    foreach ($update in $searchResult.Updates) {
        $updateInfo = [PSCustomObject]@{
            Title = $update.Title
            Description = $update.Description
            Size = [math]::Round($update.MaxDownloadSize / 1MB, 2)
            IsDownloaded = $update.IsDownloaded
            RebootRequired = $update.RebootRequired
            Severity = $update.MsrcSeverity
        }
        $pendingUpdates += $updateInfo
    }
    
    $auditData["PendingUpdates"] = $pendingUpdates
    
    # Check for security issues
    if ($pendingUpdates.Count -gt 0) {
        $criticalUpdates = $pendingUpdates | Where-Object { $_.Severity -eq "Critical" }
        if ($criticalUpdates.Count -gt 0) {
            Add-Finding -Category "Updates" -Finding "$($criticalUpdates.Count) critical updates are pending" -Severity "High" -Recommendation "Install critical security updates immediately"
        }
        
        Add-Finding -Category "Updates" -Finding "$($pendingUpdates.Count) total updates are pending" -Severity "Medium" -Recommendation "Install pending Windows updates"
    }
    
    Write-Host "✓ Windows Update status checked ($($pendingUpdates.Count) pending updates)" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check Windows Update status: $($_.Exception.Message)" -ForegroundColor Red
    Add-Finding -Category "Updates" -Finding "Failed to check Windows Update status" -Severity "Medium" -Recommendation "Manually check for Windows updates"
}

# Check installed software for known vulnerabilities
try {
    Write-Host "Checking installed software..." -ForegroundColor Yellow
    $installedSoftware = Get-WmiObject -Class Win32_Product -ComputerName $ComputerName | Select-Object Name, Version, Vendor, InstallDate
    
    $softwareAudit = @()
    foreach ($software in $installedSoftware) {
        $softwareInfo = [PSCustomObject]@{
            Name = $software.Name
            Version = $software.Version
            Vendor = $software.Vendor
            InstallDate = $software.InstallDate
        }
        $softwareAudit += $softwareInfo
        
        # Check for commonly vulnerable software
        $vulnerableSoftware = @("Adobe Flash Player", "Java", "Adobe Reader", "Adobe Acrobat")
        if ($vulnerableSoftware -contains $software.Name) {
            Add-Finding -Category "Software" -Finding "Potentially vulnerable software detected: $($software.Name)" -Severity "Medium" -Recommendation "Ensure $($software.Name) is updated to the latest version or consider removal if not needed"
        }
    }
    
    $auditData["InstalledSoftware"] = $softwareAudit
    Write-Host "✓ Installed software checked ($($installedSoftware.Count) programs)" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check installed software: $($_.Exception.Message)" -ForegroundColor Red
    Add-Finding -Category "Software" -Finding "Failed to enumerate installed software" -Severity "Low" -Recommendation "Manually review installed programs for security vulnerabilities"
}

# Check security event logs (if requested)
if ($CheckEventLogs) {
    try {
        Write-Host "Analyzing security event logs..." -ForegroundColor Yellow
        $startDate = (Get-Date).AddDays(-$DaysBack)
        
        # Get failed logon events
        $failedLogons = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName = 'Security'
            ID = 4625
            StartTime = $startDate
        } -MaxEvents 100 -ErrorAction SilentlyContinue
        
        # Get successful logons
        $successfulLogons = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName = 'Security'
            ID = 4624
            StartTime = $startDate
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        # Get account lockouts
        $accountLockouts = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
            LogName = 'Security'
            ID = 4740
            StartTime = $startDate
        } -MaxEvents 50 -ErrorAction SilentlyContinue
        
        $eventAudit = [PSCustomObject]@{
            FailedLogonCount = if ($failedLogons) { $failedLogons.Count } else { 0 }
            SuccessfulLogonCount = if ($successfulLogons) { $successfulLogons.Count } else { 0 }
            AccountLockoutCount = if ($accountLockouts) { $accountLockouts.Count } else { 0 }
            AnalysisPeriod = "$DaysBack days"
        }
        
        $auditData["SecurityEvents"] = $eventAudit
        
        # Check for security issues
        if ($failedLogons -and $failedLogons.Count -gt 50) {
            Add-Finding -Category "Security Events" -Finding "$($failedLogons.Count) failed logon attempts in the last $DaysBack days" -Severity "Medium" -Recommendation "Review failed logon events for potential brute force attacks"
        }
        
        if ($accountLockouts -and $accountLockouts.Count -gt 0) {
            Add-Finding -Category "Security Events" -Finding "$($accountLockouts.Count) account lockout events in the last $DaysBack days" -Severity "Medium" -Recommendation "Investigate account lockout events for potential security issues"
        }
        
        Write-Host "✓ Security event logs analyzed" -ForegroundColor Green
        
    } catch {
        Write-Host "✗ Failed to analyze security event logs: $($_.Exception.Message)" -ForegroundColor Red
        Add-Finding -Category "Security Events" -Finding "Failed to analyze security event logs" -Severity "Low" -Recommendation "Manually review security event logs for suspicious activity"
    }
}

# Generate summary
$summary = [PSCustomObject]@{
    ComputerName = $ComputerName
    AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    TotalFindings = $findings.Count
    HighSeverityFindings = ($findings | Where-Object { $_.Severity -eq "High" }).Count
    MediumSeverityFindings = ($findings | Where-Object { $_.Severity -eq "Medium" }).Count
    LowSeverityFindings = ($findings | Where-Object { $_.Severity -eq "Low" }).Count
    LocalUserCount = if ($auditData.ContainsKey("LocalUsers")) { $auditData["LocalUsers"].Count } else { 0 }
    EnabledUserCount = if ($auditData.ContainsKey("LocalUsers")) { ($auditData["LocalUsers"] | Where-Object { $_.Enabled }).Count } else { 0 }
    PendingUpdateCount = if ($auditData.ContainsKey("PendingUpdates")) { $auditData["PendingUpdates"].Count } else { 0 }
    InstalledSoftwareCount = if ($auditData.ContainsKey("InstalledSoftware")) { $auditData["InstalledSoftware"].Count } else { 0 }
}

$auditData["Summary"] = $summary
$auditData["Findings"] = $findings

# Export data based on format
Write-Host "Exporting audit report..." -ForegroundColor Yellow

if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "Both") {
    foreach ($category in $auditData.Keys) {
        $csvPath = Join-Path $OutputPath "SecurityAudit_$($ComputerName)_$($category)_$timestamp.csv"
        try {
            $auditData[$category] | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "✓ CSV exported: $csvPath" -ForegroundColor Green
        } catch {
            Write-Host "✗ Failed to export CSV for $category`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "Both") {
    $htmlPath = Join-Path $OutputPath "SecurityAudit_$($ComputerName)_$timestamp.html"
    
    # Generate HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Audit Report - $ComputerName</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #d32f2f; text-align: center; }
        h2 { color: #d32f2f; border-bottom: 2px solid #d32f2f; padding-bottom: 5px; }
        .summary { background-color: #fff3e0; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 5px solid #ff9800; }
        .findings { background-color: #ffebee; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 5px solid #f44336; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 12px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #d32f2f; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .high { color: #d32f2f; font-weight: bold; }
        .medium { color: #ff9800; font-weight: bold; }
        .low { color: #4caf50; font-weight: bold; }
        .enabled { color: green; font-weight: bold; }
        .disabled { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Audit Report</h1>
        <div class="summary">
            <h3>Audit Summary</h3>
            <p><strong>Computer:</strong> $($summary.ComputerName)</p>
            <p><strong>Audit Date:</strong> $($summary.AuditDate)</p>
            <p><strong>Total Findings:</strong> $($summary.TotalFindings)</p>
            <p><strong>High Severity:</strong> <span class="high">$($summary.HighSeverityFindings)</span></p>
            <p><strong>Medium Severity:</strong> <span class="medium">$($summary.MediumSeverityFindings)</span></p>
            <p><strong>Low Severity:</strong> <span class="low">$($summary.LowSeverityFindings)</span></p>
        </div>
"@

    # Add findings section
    if ($findings.Count -gt 0) {
        $htmlContent += @"
        <div class="findings">
            <h3>Security Findings</h3>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Finding</th>
                        <th>Severity</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($finding in $findings) {
            $severityClass = $finding.Severity.ToLower()
            $htmlContent += @"
                <tr>
                    <td>$($finding.Category)</td>
                    <td>$($finding.Finding)</td>
                    <td class="$severityClass">$($finding.Severity)</td>
                    <td>$($finding.Recommendation)</td>
                </tr>
"@
        }
        
        $htmlContent += "</tbody></table></div>"
    }

    # Add local users section
    if ($auditData.ContainsKey("LocalUsers")) {
        $htmlContent += @"
        <h2>Local User Accounts</h2>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Enabled</th>
                    <th>Password Required</th>
                    <th>Password Last Set</th>
                    <th>Last Logon</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($user in $auditData["LocalUsers"]) {
            $enabledClass = if ($user.Enabled) { "enabled" } else { "disabled" }
            $htmlContent += @"
                <tr>
                    <td>$($user.Name)</td>
                    <td class="$enabledClass">$($user.Enabled)</td>
                    <td>$($user.PasswordRequired)</td>
                    <td>$($user.PasswordLastSet)</td>
                    <td>$($user.LastLogon)</td>
                    <td>$($user.Description)</td>
                </tr>
"@
        }
        
        $htmlContent += "</tbody></table>"
    }

    $htmlContent += @"
    </div>
</body>
</html>
"@

    try {
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "✓ HTML report exported: $htmlPath" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to export HTML report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Display summary
Write-Host "`n=== SECURITY AUDIT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Computer: $($summary.ComputerName)" -ForegroundColor White
Write-Host "Total Findings: $($summary.TotalFindings)" -ForegroundColor White
Write-Host "High Severity: $($summary.HighSeverityFindings)" -ForegroundColor Red
Write-Host "Medium Severity: $($summary.MediumSeverityFindings)" -ForegroundColor Yellow
Write-Host "Low Severity: $($summary.LowSeverityFindings)" -ForegroundColor Green
Write-Host "Local Users: $($summary.LocalUserCount) (Enabled: $($summary.EnabledUserCount))" -ForegroundColor White
Write-Host "Pending Updates: $($summary.PendingUpdateCount)" -ForegroundColor White
Write-Host "Export Format: $ExportFormat" -ForegroundColor White
Write-Host "Output Path: $OutputPath" -ForegroundColor White

if ($summary.HighSeverityFindings -gt 0) {
    Write-Host "`n⚠️  HIGH PRIORITY: Address high severity findings immediately!" -ForegroundColor Red
}

Write-Host "`nSecurity audit completed!" -ForegroundColor Green

