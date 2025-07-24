<#
.SYNOPSIS
    Generates comprehensive reports for Microsoft Intune managed devices.

.DESCRIPTION
    This script connects to Microsoft Graph and generates detailed reports about Intune managed devices,
    including compliance status, device information, and management details.

.PARAMETER OutputPath
    Path where the report files will be saved. Defaults to the script directory.

.PARAMETER ExportFormat
    Export format for the report. Options: CSV, JSON, HTML, All. Defaults to HTML.

.PARAMETER IncludeCompliance
    Include device compliance information in the report.

.PARAMETER IncludeApps
    Include installed applications information.

.PARAMETER DeviceFilter
    Filter devices by platform: All, Windows, iOS, Android, macOS. Defaults to All.

.EXAMPLE
    .\Get-IntuneDeviceReport.ps1

.EXAMPLE
    .\Get-IntuneDeviceReport.ps1 -OutputPath "C:\Reports" -ExportFormat "All" -IncludeCompliance -DeviceFilter "Windows"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Microsoft.Graph PowerShell module
    - Appropriate permissions in Azure AD/Microsoft 365
    - Global Administrator or Intune Administrator role
    
    Required Graph Permissions:
    - DeviceManagementManagedDevices.Read.All
    - DeviceManagementConfiguration.Read.All
    - DeviceManagementApps.Read.All (if IncludeApps is used)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "HTML", "All")]
    [string]$ExportFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeCompliance,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeApps,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("All", "Windows", "iOS", "Android", "macOS")]
    [string]$DeviceFilter = "All"
)

# Import required modules
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.DeviceManagement -ErrorAction Stop
    Write-Host "Microsoft Graph modules imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import Microsoft Graph modules. Please install using: Install-Module Microsoft.Graph"
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

Write-Log "Starting Intune device report generation"

# Connect to Microsoft Graph
try {
    Write-Log "Connecting to Microsoft Graph..."
    $requiredScopes = @(
        "DeviceManagementManagedDevices.Read.All",
        "DeviceManagementConfiguration.Read.All"
    )
    
    if ($IncludeApps) {
        $requiredScopes += "DeviceManagementApps.Read.All"
    }
    
    Connect-MgGraph -Scopes $requiredScopes -NoWelcome
    Write-Log "Successfully connected to Microsoft Graph" -Level "SUCCESS"
    
    # Get tenant information
    $context = Get-MgContext
    Write-Log "Connected to tenant: $($context.TenantId)"
    
} catch {
    Write-Log "Failed to connect to Microsoft Graph: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Get managed devices
try {
    Write-Log "Retrieving managed devices from Intune..."
    
    $deviceFilter = switch ($DeviceFilter) {
        "Windows" { "operatingSystem eq 'Windows'" }
        "iOS" { "operatingSystem eq 'iOS'" }
        "Android" { "operatingSystem eq 'Android'" }
        "macOS" { "operatingSystem eq 'macOS'" }
        default { $null }
    }
    
    if ($deviceFilter) {
        $devices = Get-MgDeviceManagementManagedDevice -Filter $deviceFilter -All
    } else {
        $devices = Get-MgDeviceManagementManagedDevice -All
    }
    
    Write-Log "Retrieved $($devices.Count) managed devices" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to retrieve managed devices: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Process device information
Write-Log "Processing device information..."
$deviceData = @()

foreach ($device in $devices) {
    try {
        $deviceInfo = [PSCustomObject]@{
            DeviceName = $device.DeviceName
            UserDisplayName = $device.UserDisplayName
            UserPrincipalName = $device.UserPrincipalName
            OperatingSystem = $device.OperatingSystem
            OSVersion = $device.OsVersion
            DeviceType = $device.DeviceType
            ManagementState = $device.ManagementState
            ComplianceState = $device.ComplianceState
            EnrollmentType = $device.DeviceEnrollmentType
            LastSyncDateTime = $device.LastSyncDateTime
            EnrolledDateTime = $device.EnrolledDateTime
            Manufacturer = $device.Manufacturer
            Model = $device.Model
            SerialNumber = $device.SerialNumber
            IMEI = $device.Imei
            WiFiMacAddress = $device.WiFiMacAddress
            EthernetMacAddress = $device.EthernetMacAddress
            TotalStorageSpaceInBytes = if ($device.TotalStorageSpaceInBytes) { [math]::Round($device.TotalStorageSpaceInBytes / 1GB, 2) } else { $null }
            FreeStorageSpaceInBytes = if ($device.FreeStorageSpaceInBytes) { [math]::Round($device.FreeStorageSpaceInBytes / 1GB, 2) } else { $null }
            ManagedDeviceOwnerType = $device.ManagedDeviceOwnerType
            DeviceRegistrationState = $device.DeviceRegistrationState
            ExchangeAccessState = $device.ExchangeAccessState
            ExchangeAccessStateReason = $device.ExchangeAccessStateReason
            IsEncrypted = $device.IsEncrypted
            IsSupervised = $device.IsSupervised
            JailBroken = $device.JailBroken
            ManagementAgent = $device.ManagementAgent
            AzureADDeviceId = $device.AzureAdDeviceId
            DeviceId = $device.Id
        }
        
        $deviceData += $deviceInfo
        
    } catch {
        Write-Log "Error processing device $($device.DeviceName): $($_.Exception.Message)" -Level "WARNING"
    }
}

$reportData["Devices"] = $deviceData

# Get compliance information if requested
if ($IncludeCompliance) {
    try {
        Write-Log "Retrieving device compliance information..."
        
        $complianceData = @()
        foreach ($device in $devices) {
            try {
                # Get device compliance policies
                $compliancePolicies = Get-MgDeviceManagementManagedDeviceDeviceCompliancePolicyState -ManagedDeviceId $device.Id -ErrorAction SilentlyContinue
                
                foreach ($policy in $compliancePolicies) {
                    $complianceInfo = [PSCustomObject]@{
                        DeviceName = $device.DeviceName
                        DeviceId = $device.Id
                        PolicyName = $policy.DisplayName
                        PolicyId = $policy.Id
                        State = $policy.State
                        Version = $policy.Version
                        LastReportedDateTime = $policy.LastReportedDateTime
                        UserId = $policy.UserId
                        UserName = $policy.UserPrincipalName
                    }
                    $complianceData += $complianceInfo
                }
            } catch {
                Write-Log "Error getting compliance info for device $($device.DeviceName): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        $reportData["Compliance"] = $complianceData
        Write-Log "Retrieved compliance information for $($complianceData.Count) policy assignments" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to retrieve compliance information: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Get application information if requested
if ($IncludeApps) {
    try {
        Write-Log "Retrieving device application information..."
        
        $appData = @()
        foreach ($device in $devices) {
            try {
                # Get detected apps for the device
                $detectedApps = Get-MgDeviceManagementManagedDeviceDetectedApp -ManagedDeviceId $device.Id -ErrorAction SilentlyContinue
                
                foreach ($app in $detectedApps) {
                    $appInfo = [PSCustomObject]@{
                        DeviceName = $device.DeviceName
                        DeviceId = $device.Id
                        AppName = $app.DisplayName
                        AppVersion = $app.Version
                        AppPublisher = $app.Publisher
                        SizeInByte = $app.SizeInByte
                        DeviceCount = $app.DeviceCount
                    }
                    $appData += $appInfo
                }
            } catch {
                Write-Log "Error getting app info for device $($device.DeviceName): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        $reportData["Applications"] = $appData
        Write-Log "Retrieved application information for $($appData.Count) app installations" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to retrieve application information: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Generate summary statistics
$summary = [PSCustomObject]@{
    TotalDevices = $deviceData.Count
    WindowsDevices = ($deviceData | Where-Object { $_.OperatingSystem -eq "Windows" }).Count
    iOSDevices = ($deviceData | Where-Object { $_.OperatingSystem -eq "iOS" }).Count
    AndroidDevices = ($deviceData | Where-Object { $_.OperatingSystem -eq "Android" }).Count
    macOSDevices = ($deviceData | Where-Object { $_.OperatingSystem -eq "macOS" }).Count
    CompliantDevices = ($deviceData | Where-Object { $_.ComplianceState -eq "compliant" }).Count
    NonCompliantDevices = ($deviceData | Where-Object { $_.ComplianceState -eq "noncompliant" }).Count
    UnknownComplianceDevices = ($deviceData | Where-Object { $_.ComplianceState -eq "unknown" }).Count
    EncryptedDevices = ($deviceData | Where-Object { $_.IsEncrypted -eq $true }).Count
    JailbrokenDevices = ($deviceData | Where-Object { $_.JailBroken -eq "True" }).Count
    SupervisedDevices = ($deviceData | Where-Object { $_.IsSupervised -eq $true }).Count
}

$reportData["Summary"] = $summary

# Export data based on format
Write-Log "Exporting report data..."

if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "All") {
    foreach ($category in $reportData.Keys) {
        $csvPath = Join-Path $OutputPath "IntuneDevices_$($category)_$timestamp.csv"
        try {
            $reportData[$category] | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Log "CSV exported: $csvPath" -Level "SUCCESS"
        } catch {
            Write-Log "Failed to export CSV for $category`: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "All") {
    $jsonPath = Join-Path $OutputPath "IntuneDevices_$timestamp.json"
    try {
        $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Log "JSON exported: $jsonPath" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to export JSON: $($_.Exception.Message)" -Level "ERROR"
    }
}

if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "All") {
    $htmlPath = Join-Path $OutputPath "IntuneDevices_$timestamp.html"
    
    # Generate HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Intune Device Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #0078d4; text-align: center; }
        h2 { color: #0078d4; border-bottom: 2px solid #0078d4; padding-bottom: 5px; }
        .summary { background-color: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .summary-item { background-color: white; padding: 10px; border-radius: 5px; text-align: center; border-left: 4px solid #0078d4; }
        .summary-value { font-size: 24px; font-weight: bold; color: #0078d4; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 11px; }
        th, td { border: 1px solid #ddd; padding: 6px; text-align: left; }
        th { background-color: #0078d4; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .compliant { color: green; font-weight: bold; }
        .noncompliant { color: red; font-weight: bold; }
        .unknown { color: orange; font-weight: bold; }
        .category { margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Microsoft Intune Device Report</h1>
        <div class="summary">
            <h3>Report Summary</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Tenant:</strong> $($context.TenantId)</p>
            <p><strong>Device Filter:</strong> $DeviceFilter</p>
            
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value">$($summary.TotalDevices)</div>
                    <div>Total Devices</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.CompliantDevices)</div>
                    <div>Compliant</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.NonCompliantDevices)</div>
                    <div>Non-Compliant</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.WindowsDevices)</div>
                    <div>Windows</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.iOSDevices)</div>
                    <div>iOS</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.AndroidDevices)</div>
                    <div>Android</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.EncryptedDevices)</div>
                    <div>Encrypted</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.JailbrokenDevices)</div>
                    <div>Jailbroken</div>
                </div>
            </div>
        </div>
"@

    # Add devices table
    if ($reportData.ContainsKey("Devices") -and $reportData["Devices"].Count -gt 0) {
        $htmlContent += @"
        <div class="category">
            <h2>Managed Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>User</th>
                        <th>OS</th>
                        <th>OS Version</th>
                        <th>Compliance</th>
                        <th>Last Sync</th>
                        <th>Manufacturer</th>
                        <th>Model</th>
                        <th>Serial Number</th>
                        <th>Encrypted</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($device in ($reportData["Devices"] | Sort-Object DeviceName)) {
            $complianceClass = switch ($device.ComplianceState) {
                "compliant" { "compliant" }
                "noncompliant" { "noncompliant" }
                default { "unknown" }
            }
            
            $lastSync = if ($device.LastSyncDateTime) { 
                ([DateTime]$device.LastSyncDateTime).ToString("yyyy-MM-dd HH:mm") 
            } else { "Never" }
            
            $htmlContent += @"
                <tr>
                    <td>$($device.DeviceName)</td>
                    <td>$($device.UserDisplayName)</td>
                    <td>$($device.OperatingSystem)</td>
                    <td>$($device.OSVersion)</td>
                    <td class="$complianceClass">$($device.ComplianceState)</td>
                    <td>$lastSync</td>
                    <td>$($device.Manufacturer)</td>
                    <td>$($device.Model)</td>
                    <td>$($device.SerialNumber)</td>
                    <td>$($device.IsEncrypted)</td>
                </tr>
"@
        }
        
        $htmlContent += "</tbody></table></div>"
    }

    # Add compliance table if available
    if ($reportData.ContainsKey("Compliance") -and $reportData["Compliance"].Count -gt 0) {
        $htmlContent += @"
        <div class="category">
            <h2>Compliance Policies</h2>
            <table>
                <thead>
                    <tr>
                        <th>Device Name</th>
                        <th>Policy Name</th>
                        <th>State</th>
                        <th>Last Reported</th>
                        <th>User</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($compliance in ($reportData["Compliance"] | Sort-Object DeviceName, PolicyName)) {
            $stateClass = switch ($compliance.State) {
                "compliant" { "compliant" }
                "noncompliant" { "noncompliant" }
                default { "unknown" }
            }
            
            $lastReported = if ($compliance.LastReportedDateTime) { 
                ([DateTime]$compliance.LastReportedDateTime).ToString("yyyy-MM-dd HH:mm") 
            } else { "Never" }
            
            $htmlContent += @"
                <tr>
                    <td>$($compliance.DeviceName)</td>
                    <td>$($compliance.PolicyName)</td>
                    <td class="$stateClass">$($compliance.State)</td>
                    <td>$lastReported</td>
                    <td>$($compliance.UserName)</td>
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

# Disconnect from Microsoft Graph
try {
    Disconnect-MgGraph | Out-Null
    Write-Log "Disconnected from Microsoft Graph" -Level "SUCCESS"
} catch {
    Write-Log "Error disconnecting from Microsoft Graph: $($_.Exception.Message)" -Level "WARNING"
}

# Display summary
Write-Host "`n=== INTUNE DEVICE REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total Devices: $($summary.TotalDevices)" -ForegroundColor White
Write-Host "Compliant Devices: $($summary.CompliantDevices)" -ForegroundColor Green
Write-Host "Non-Compliant Devices: $($summary.NonCompliantDevices)" -ForegroundColor Red
Write-Host "Unknown Compliance: $($summary.UnknownComplianceDevices)" -ForegroundColor Yellow
Write-Host "Windows Devices: $($summary.WindowsDevices)" -ForegroundColor White
Write-Host "iOS Devices: $($summary.iOSDevices)" -ForegroundColor White
Write-Host "Android Devices: $($summary.AndroidDevices)" -ForegroundColor White
Write-Host "macOS Devices: $($summary.macOSDevices)" -ForegroundColor White
Write-Host "Export Format: $ExportFormat" -ForegroundColor White
Write-Host "Output Path: $OutputPath" -ForegroundColor White

Write-Log "Intune device report generation completed" -Level "SUCCESS"

