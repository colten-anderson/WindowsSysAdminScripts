<#
.SYNOPSIS
    Generates comprehensive Active Directory user reports.

.DESCRIPTION
    This script creates detailed reports about Active Directory users, including account status,
    last logon information, password expiration, group memberships, and other useful attributes.

.PARAMETER OutputPath
    Path where the report files will be saved. Defaults to the script directory.

.PARAMETER IncludeDisabled
    Include disabled user accounts in the report.

.PARAMETER DaysInactive
    Number of days to consider a user inactive. Defaults to 90 days.

.PARAMETER ExportFormat
    Export format for the report. Options: CSV, HTML, Both. Defaults to Both.

.EXAMPLE
    .\Get-ADUserReport.ps1

.EXAMPLE
    .\Get-ADUserReport.ps1 -OutputPath "C:\Reports" -IncludeDisabled -DaysInactive 60

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - ActiveDirectory PowerShell module
    - Read permissions in Active Directory
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeDisabled,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysInactive = 90,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "HTML", "Both")]
    [string]$ExportFormat = "Both"
)

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "ActiveDirectory module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import ActiveDirectory module. Please ensure RSAT is installed."
    exit 1
}

# Initialize variables
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$csvPath = Join-Path $OutputPath "ADUserReport_$timestamp.csv"
$htmlPath = Join-Path $OutputPath "ADUserReport_$timestamp.html"
$inactiveDate = (Get-Date).AddDays(-$DaysInactive)

Write-Host "Starting Active Directory user report generation..." -ForegroundColor Cyan
Write-Host "Inactive threshold: $DaysInactive days (before $(Get-Date $inactiveDate -Format 'yyyy-MM-dd'))" -ForegroundColor Yellow

# Get all users
try {
    $filter = if ($IncludeDisabled) { "*" } else { "Enabled -eq 'True'" }
    $users = Get-ADUser -Filter $filter -Properties *
    Write-Host "Retrieved $($users.Count) users from Active Directory." -ForegroundColor Green
} catch {
    Write-Error "Failed to retrieve users from Active Directory: $($_.Exception.Message)"
    exit 1
}

# Process users and create report data
$reportData = @()
$totalUsers = $users.Count
$currentUser = 0

foreach ($user in $users) {
    $currentUser++
    Write-Progress -Activity "Processing Users" -Status "Processing $($user.SamAccountName)" -PercentComplete (($currentUser / $totalUsers) * 100)
    
    try {
        # Get group memberships
        $groups = (Get-ADPrincipalGroupMembership -Identity $user.SamAccountName | Select-Object -ExpandProperty Name) -join "; "
        
        # Determine account status
        $accountStatus = if ($user.Enabled) {
            if ($user.LockedOut) { "Enabled (Locked)" }
            elseif ($user.LastLogonDate -and $user.LastLogonDate -lt $inactiveDate) { "Enabled (Inactive)" }
            else { "Enabled (Active)" }
        } else { "Disabled" }
        
        # Calculate password age and expiration
        $passwordAge = if ($user.PasswordLastSet) { 
            (New-TimeSpan -Start $user.PasswordLastSet -End (Get-Date)).Days 
        } else { "Never Set" }
        
        $passwordExpiry = if ($user.PasswordNeverExpires) {
            "Never Expires"
        } elseif ($user.PasswordLastSet) {
            $domain = Get-ADDomain
            $maxPasswordAge = $domain.MaxPasswordAge.Days
            if ($maxPasswordAge -gt 0) {
                $expiryDate = $user.PasswordLastSet.AddDays($maxPasswordAge)
                if ($expiryDate -lt (Get-Date)) {
                    "Expired"
                } else {
                    $expiryDate.ToString("yyyy-MM-dd")
                }
            } else {
                "Never Expires"
            }
        } else {
            "Unknown"
        }
        
        # Create user object for report
        $userObj = [PSCustomObject]@{
            Username = $user.SamAccountName
            DisplayName = $user.DisplayName
            FirstName = $user.GivenName
            LastName = $user.Surname
            Email = $user.EmailAddress
            Department = $user.Department
            Title = $user.Title
            Manager = if ($user.Manager) { (Get-ADUser -Identity $user.Manager).Name } else { "" }
            AccountStatus = $accountStatus
            Enabled = $user.Enabled
            LockedOut = $user.LockedOut
            Created = if ($user.Created) { $user.Created.ToString("yyyy-MM-dd") } else { "" }
            LastLogon = if ($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm") } else { "Never" }
            PasswordLastSet = if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd") } else { "Never" }
            PasswordAge = $passwordAge
            PasswordExpiry = $passwordExpiry
            PasswordNeverExpires = $user.PasswordNeverExpires
            MustChangePassword = $user.PasswordExpired
            CannotChangePassword = $user.CannotChangePassword
            Groups = $groups
            OU = ($user.DistinguishedName -split ',')[1] -replace 'OU=', ''
            Description = $user.Description
            Office = $user.Office
            Phone = $user.OfficePhone
            Mobile = $user.MobilePhone
        }
        
        $reportData += $userObj
        
    } catch {
        Write-Warning "Error processing user $($user.SamAccountName): $($_.Exception.Message)"
    }
}

Write-Progress -Activity "Processing Users" -Completed

# Export to CSV
if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "Both") {
    try {
        $reportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "CSV report saved to: $csvPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to export CSV report: $($_.Exception.Message)"
    }
}

# Export to HTML
if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "Both") {
    try {
        # Create HTML report
        $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Active Directory User Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2E86AB; }
        .summary { background-color: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; font-size: 12px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #2E86AB; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .enabled { color: green; font-weight: bold; }
        .disabled { color: red; font-weight: bold; }
        .inactive { color: orange; font-weight: bold; }
        .locked { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Active Directory User Report</h1>
    <div class="summary">
        <h3>Report Summary</h3>
        <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        <p><strong>Total Users:</strong> $($reportData.Count)</p>
        <p><strong>Enabled Users:</strong> $($reportData | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p><strong>Disabled Users:</strong> $($reportData | Where-Object {$_.Enabled -eq $false} | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p><strong>Locked Users:</strong> $($reportData | Where-Object {$_.LockedOut -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)</p>
        <p><strong>Inactive Users (>$DaysInactive days):</strong> $($reportData | Where-Object {$_.AccountStatus -like "*Inactive*"} | Measure-Object | Select-Object -ExpandProperty Count)</p>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Username</th>
                <th>Display Name</th>
                <th>Email</th>
                <th>Department</th>
                <th>Title</th>
                <th>Account Status</th>
                <th>Last Logon</th>
                <th>Password Expiry</th>
                <th>Groups</th>
            </tr>
        </thead>
        <tbody>
"@

        foreach ($user in $reportData) {
            $statusClass = switch -Wildcard ($user.AccountStatus) {
                "*Active*" { "enabled" }
                "*Inactive*" { "inactive" }
                "*Locked*" { "locked" }
                "Disabled" { "disabled" }
                default { "" }
            }
            
            $htmlContent += @"
            <tr>
                <td>$($user.Username)</td>
                <td>$($user.DisplayName)</td>
                <td>$($user.Email)</td>
                <td>$($user.Department)</td>
                <td>$($user.Title)</td>
                <td class="$statusClass">$($user.AccountStatus)</td>
                <td>$($user.LastLogon)</td>
                <td>$($user.PasswordExpiry)</td>
                <td>$($user.Groups)</td>
            </tr>
"@
        }

        $htmlContent += @"
        </tbody>
    </table>
</body>
</html>
"@

        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "HTML report saved to: $htmlPath" -ForegroundColor Green
        
    } catch {
        Write-Error "Failed to export HTML report: $($_.Exception.Message)"
    }
}

# Display summary statistics
Write-Host "`n=== REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Users: $($reportData.Count)" -ForegroundColor White
Write-Host "Enabled Users: $($reportData | Where-Object {$_.Enabled -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Green
Write-Host "Disabled Users: $($reportData | Where-Object {$_.Enabled -eq $false} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
Write-Host "Locked Users: $($reportData | Where-Object {$_.LockedOut -eq $true} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Red
Write-Host "Inactive Users (>$DaysInactive days): $($reportData | Where-Object {$_.AccountStatus -like "*Inactive*"} | Measure-Object | Select-Object -ExpandProperty Count)" -ForegroundColor Yellow

Write-Host "`nReport generation completed successfully!" -ForegroundColor Green

