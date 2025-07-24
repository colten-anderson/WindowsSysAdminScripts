<#
.SYNOPSIS
    Generates a comprehensive server health report.

.DESCRIPTION
    This script performs various health checks on Windows servers including disk space,
    memory usage, CPU utilization, service status, event logs, and system uptime.

.PARAMETER ComputerName
    Name of the computer to check. Defaults to local computer.

.PARAMETER OutputPath
    Path where the report will be saved. Defaults to the script directory.

.PARAMETER EmailReport
    Send the report via email.

.PARAMETER SMTPServer
    SMTP server for sending email reports.

.PARAMETER ToEmail
    Email address to send the report to.

.PARAMETER FromEmail
    Email address to send the report from.

.PARAMETER DiskThreshold
    Disk space threshold percentage for warnings. Defaults to 20%.

.PARAMETER MemoryThreshold
    Memory usage threshold percentage for warnings. Defaults to 80%.

.PARAMETER CPUThreshold
    CPU usage threshold percentage for warnings. Defaults to 80%.

.EXAMPLE
    .\Get-ServerHealthReport.ps1

.EXAMPLE
    .\Get-ServerHealthReport.ps1 -ComputerName "SERVER01" -EmailReport -SMTPServer "mail.contoso.com" -ToEmail "admin@contoso.com" -FromEmail "monitoring@contoso.com"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - WMI/CIM access to target computer
    - Appropriate permissions on target computer
    - SMTP server access for email reports (if using EmailReport)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [switch]$EmailReport,
    
    [Parameter(Mandatory=$false)]
    [string]$SMTPServer,
    
    [Parameter(Mandatory=$false)]
    [string]$ToEmail,
    
    [Parameter(Mandatory=$false)]
    [string]$FromEmail,
    
    [Parameter(Mandatory=$false)]
    [int]$DiskThreshold = 20,
    
    [Parameter(Mandatory=$false)]
    [int]$MemoryThreshold = 80,
    
    [Parameter(Mandatory=$false)]
    [int]$CPUThreshold = 80
)

# Initialize variables
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportPath = Join-Path $OutputPath "ServerHealth_$($ComputerName)_$timestamp.html"
$healthData = @{}
$warnings = @()
$errors = @()

Write-Host "Starting server health check for: $ComputerName" -ForegroundColor Cyan

# Function to add health data
function Add-HealthData {
    param(
        [string]$Category,
        [object]$Data,
        [string]$Status = "OK"
    )
    $healthData[$Category] = @{
        Data = $Data
        Status = $Status
    }
}

# Function to test connectivity
function Test-ServerConnectivity {
    try {
        $ping = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet
        if ($ping) {
            Write-Host "✓ Server connectivity: OK" -ForegroundColor Green
            return $true
        } else {
            Write-Host "✗ Server connectivity: Failed" -ForegroundColor Red
            $errors += "Cannot connect to server $ComputerName"
            return $false
        }
    } catch {
        Write-Host "✗ Server connectivity: Error - $($_.Exception.Message)" -ForegroundColor Red
        $errors += "Connectivity error: $($_.Exception.Message)"
        return $false
    }
}

# Check server connectivity
if (-not (Test-ServerConnectivity)) {
    Write-Error "Cannot proceed with health check due to connectivity issues."
    exit 1
}

# Get system information
try {
    Write-Host "Gathering system information..." -ForegroundColor Yellow
    $systemInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ComputerName $ComputerName
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName
    $biosInfo = Get-CimInstance -ClassName Win32_BIOS -ComputerName $ComputerName
    
    $systemData = [PSCustomObject]@{
        ComputerName = $systemInfo.Name
        Domain = $systemInfo.Domain
        Manufacturer = $systemInfo.Manufacturer
        Model = $systemInfo.Model
        TotalPhysicalMemory = [math]::Round($systemInfo.TotalPhysicalMemory / 1GB, 2)
        NumberOfProcessors = $systemInfo.NumberOfProcessors
        OSName = $osInfo.Caption
        OSVersion = $osInfo.Version
        OSBuild = $osInfo.BuildNumber
        InstallDate = $osInfo.InstallDate
        LastBootUpTime = $osInfo.LastBootUpTime
        BIOSVersion = $biosInfo.SMBIOSBIOSVersion
        BIOSDate = $biosInfo.ReleaseDate
    }
    
    Add-HealthData -Category "SystemInfo" -Data $systemData
    Write-Host "✓ System information collected" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to collect system information: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "System information error: $($_.Exception.Message)"
}

# Check disk space
try {
    Write-Host "Checking disk space..." -ForegroundColor Yellow
    $disks = Get-CimInstance -ClassName Win32_LogicalDisk -ComputerName $ComputerName | Where-Object { $_.DriveType -eq 3 }
    $diskData = @()
    $diskStatus = "OK"
    
    foreach ($disk in $disks) {
        $freeSpacePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)
        $diskInfo = [PSCustomObject]@{
            Drive = $disk.DeviceID
            Label = $disk.VolumeName
            TotalSize = [math]::Round($disk.Size / 1GB, 2)
            FreeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
            FreeSpacePercent = $freeSpacePercent
            Status = if ($freeSpacePercent -lt $DiskThreshold) { "WARNING" } else { "OK" }
        }
        
        if ($freeSpacePercent -lt $DiskThreshold) {
            $warnings += "Disk $($disk.DeviceID) has only $freeSpacePercent% free space"
            $diskStatus = "WARNING"
        }
        
        $diskData += $diskInfo
    }
    
    Add-HealthData -Category "DiskSpace" -Data $diskData -Status $diskStatus
    Write-Host "✓ Disk space checked" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check disk space: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "Disk space error: $($_.Exception.Message)"
}

# Check memory usage
try {
    Write-Host "Checking memory usage..." -ForegroundColor Yellow
    $memory = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $ComputerName
    $totalMemory = [math]::Round($memory.TotalVisibleMemorySize / 1MB, 2)
    $freeMemory = [math]::Round($memory.FreePhysicalMemory / 1MB, 2)
    $usedMemory = $totalMemory - $freeMemory
    $memoryUsagePercent = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
    
    $memoryData = [PSCustomObject]@{
        TotalMemory = $totalMemory
        UsedMemory = $usedMemory
        FreeMemory = $freeMemory
        UsagePercent = $memoryUsagePercent
    }
    
    $memoryStatus = if ($memoryUsagePercent -gt $MemoryThreshold) {
        $warnings += "Memory usage is high: $memoryUsagePercent%"
        "WARNING"
    } else { "OK" }
    
    Add-HealthData -Category "Memory" -Data $memoryData -Status $memoryStatus
    Write-Host "✓ Memory usage checked" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check memory usage: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "Memory usage error: $($_.Exception.Message)"
}

# Check CPU usage
try {
    Write-Host "Checking CPU usage..." -ForegroundColor Yellow
    $cpu = Get-CimInstance -ClassName Win32_Processor -ComputerName $ComputerName
    $cpuUsage = (Get-Counter -ComputerName $ComputerName -Counter "\Processor(_Total)\% Processor Time" -SampleInterval 1 -MaxSamples 3 | 
                 Select-Object -ExpandProperty CounterSamples | 
                 Measure-Object -Property CookedValue -Average).Average
    $cpuUsage = [math]::Round($cpuUsage, 2)
    
    $cpuData = [PSCustomObject]@{
        ProcessorName = $cpu.Name
        NumberOfCores = $cpu.NumberOfCores
        NumberOfLogicalProcessors = $cpu.NumberOfLogicalProcessors
        CurrentUsage = $cpuUsage
        MaxClockSpeed = $cpu.MaxClockSpeed
    }
    
    $cpuStatus = if ($cpuUsage -gt $CPUThreshold) {
        $warnings += "CPU usage is high: $cpuUsage%"
        "WARNING"
    } else { "OK" }
    
    Add-HealthData -Category "CPU" -Data $cpuData -Status $cpuStatus
    Write-Host "✓ CPU usage checked" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check CPU usage: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "CPU usage error: $($_.Exception.Message)"
}

# Check critical services
try {
    Write-Host "Checking critical services..." -ForegroundColor Yellow
    $criticalServices = @("Spooler", "DHCP", "DNS", "W32Time", "Netlogon", "NTDS", "IISAdmin")
    $serviceData = @()
    $serviceStatus = "OK"
    
    foreach ($serviceName in $criticalServices) {
        try {
            $service = Get-Service -Name $serviceName -ComputerName $ComputerName -ErrorAction SilentlyContinue
            if ($service) {
                $serviceInfo = [PSCustomObject]@{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartType = $service.StartType
                }
                
                if ($service.Status -ne "Running" -and $service.StartType -eq "Automatic") {
                    $warnings += "Service $($service.DisplayName) is not running"
                    $serviceStatus = "WARNING"
                }
                
                $serviceData += $serviceInfo
            }
        } catch {
            # Service doesn't exist on this server, which is normal
        }
    }
    
    Add-HealthData -Category "Services" -Data $serviceData -Status $serviceStatus
    Write-Host "✓ Critical services checked" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check services: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "Services error: $($_.Exception.Message)"
}

# Check event logs for recent errors
try {
    Write-Host "Checking event logs..." -ForegroundColor Yellow
    $eventData = @()
    $eventStatus = "OK"
    $since = (Get-Date).AddHours(-24)
    
    $events = Get-WinEvent -ComputerName $ComputerName -FilterHashtable @{
        LogName = 'System', 'Application'
        Level = 1, 2  # Critical and Error
        StartTime = $since
    } -MaxEvents 50 -ErrorAction SilentlyContinue
    
    if ($events) {
        foreach ($event in $events) {
            $eventInfo = [PSCustomObject]@{
                TimeCreated = $event.TimeCreated
                LogName = $event.LogName
                Level = switch ($event.Level) {
                    1 { "Critical" }
                    2 { "Error" }
                    3 { "Warning" }
                    4 { "Information" }
                    default { "Unknown" }
                }
                Source = $event.ProviderName
                EventID = $event.Id
                Message = $event.Message.Substring(0, [Math]::Min(200, $event.Message.Length))
            }
            $eventData += $eventInfo
        }
        
        $criticalCount = ($events | Where-Object { $_.Level -eq 1 }).Count
        $errorCount = ($events | Where-Object { $_.Level -eq 2 }).Count
        
        if ($criticalCount -gt 0 -or $errorCount -gt 5) {
            $warnings += "Found $criticalCount critical and $errorCount error events in the last 24 hours"
            $eventStatus = "WARNING"
        }
    }
    
    Add-HealthData -Category "EventLogs" -Data $eventData -Status $eventStatus
    Write-Host "✓ Event logs checked" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to check event logs: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "Event logs error: $($_.Exception.Message)"
}

# Calculate uptime
try {
    $uptime = (Get-Date) - $healthData["SystemInfo"].Data.LastBootUpTime
    $uptimeData = [PSCustomObject]@{
        LastBootTime = $healthData["SystemInfo"].Data.LastBootUpTime
        UptimeDays = [math]::Round($uptime.TotalDays, 2)
        UptimeHours = [math]::Round($uptime.TotalHours, 2)
        UptimeString = "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
    }
    
    Add-HealthData -Category "Uptime" -Data $uptimeData
    Write-Host "✓ Uptime calculated" -ForegroundColor Green
    
} catch {
    Write-Host "✗ Failed to calculate uptime: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "Uptime calculation error: $($_.Exception.Message)"
}

# Generate HTML report
Write-Host "Generating HTML report..." -ForegroundColor Yellow

$overallStatus = if ($errors.Count -gt 0) { "ERROR" } elseif ($warnings.Count -gt 0) { "WARNING" } else { "OK" }
$statusColor = switch ($overallStatus) {
    "OK" { "green" }
    "WARNING" { "orange" }
    "ERROR" { "red" }
}

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Server Health Report - $ComputerName</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2E86AB; text-align: center; }
        h2 { color: #2E86AB; border-bottom: 2px solid #2E86AB; padding-bottom: 5px; }
        .status-ok { color: green; font-weight: bold; }
        .status-warning { color: orange; font-weight: bold; }
        .status-error { color: red; font-weight: bold; }
        .summary { background-color: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 5px solid $statusColor; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #2E86AB; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .warning-list, .error-list { background-color: #fff3cd; padding: 10px; border-radius: 5px; margin: 10px 0; }
        .error-list { background-color: #f8d7da; }
        .metric-good { color: green; font-weight: bold; }
        .metric-warning { color: orange; font-weight: bold; }
        .metric-critical { color: red; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Server Health Report</h1>
        <div class="summary">
            <h3>Report Summary</h3>
            <p><strong>Server:</strong> $ComputerName</p>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Overall Status:</strong> <span class="status-$(($overallStatus).ToLower())">$overallStatus</span></p>
            <p><strong>Warnings:</strong> $($warnings.Count)</p>
            <p><strong>Errors:</strong> $($errors.Count)</p>
        </div>
"@

# Add warnings section
if ($warnings.Count -gt 0) {
    $htmlContent += @"
        <div class="warning-list">
            <h3>⚠️ Warnings</h3>
            <ul>
"@
    foreach ($warning in $warnings) {
        $htmlContent += "<li>$warning</li>"
    }
    $htmlContent += "</ul></div>"
}

# Add errors section
if ($errors.Count -gt 0) {
    $htmlContent += @"
        <div class="error-list">
            <h3>❌ Errors</h3>
            <ul>
"@
    foreach ($error in $errors) {
        $htmlContent += "<li>$error</li>"
    }
    $htmlContent += "</ul></div>"
}

# Add system information
if ($healthData.ContainsKey("SystemInfo")) {
    $sysInfo = $healthData["SystemInfo"].Data
    $htmlContent += @"
        <h2>System Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>Computer Name</td><td>$($sysInfo.ComputerName)</td></tr>
            <tr><td>Domain</td><td>$($sysInfo.Domain)</td></tr>
            <tr><td>Manufacturer</td><td>$($sysInfo.Manufacturer)</td></tr>
            <tr><td>Model</td><td>$($sysInfo.Model)</td></tr>
            <tr><td>Operating System</td><td>$($sysInfo.OSName)</td></tr>
            <tr><td>OS Version</td><td>$($sysInfo.OSVersion) (Build $($sysInfo.OSBuild))</td></tr>
            <tr><td>Total Memory</td><td>$($sysInfo.TotalPhysicalMemory) GB</td></tr>
            <tr><td>Processors</td><td>$($sysInfo.NumberOfProcessors)</td></tr>
            <tr><td>Install Date</td><td>$($sysInfo.InstallDate)</td></tr>
            <tr><td>Last Boot</td><td>$($sysInfo.LastBootUpTime)</td></tr>
        </table>
"@
}

# Add disk space information
if ($healthData.ContainsKey("DiskSpace")) {
    $htmlContent += @"
        <h2>Disk Space</h2>
        <table>
            <tr><th>Drive</th><th>Label</th><th>Total Size (GB)</th><th>Free Space (GB)</th><th>Free %</th><th>Status</th></tr>
"@
    foreach ($disk in $healthData["DiskSpace"].Data) {
        $statusClass = if ($disk.Status -eq "WARNING") { "metric-warning" } else { "metric-good" }
        $htmlContent += @"
            <tr>
                <td>$($disk.Drive)</td>
                <td>$($disk.Label)</td>
                <td>$($disk.TotalSize)</td>
                <td>$($disk.FreeSpace)</td>
                <td class="$statusClass">$($disk.FreeSpacePercent)%</td>
                <td class="$statusClass">$($disk.Status)</td>
            </tr>
"@
    }
    $htmlContent += "</table>"
}

# Add memory information
if ($healthData.ContainsKey("Memory")) {
    $mem = $healthData["Memory"].Data
    $statusClass = if ($healthData["Memory"].Status -eq "WARNING") { "metric-warning" } else { "metric-good" }
    $htmlContent += @"
        <h2>Memory Usage</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Total Memory</td><td>$($mem.TotalMemory) GB</td></tr>
            <tr><td>Used Memory</td><td>$($mem.UsedMemory) GB</td></tr>
            <tr><td>Free Memory</td><td>$($mem.FreeMemory) GB</td></tr>
            <tr><td>Usage Percentage</td><td class="$statusClass">$($mem.UsagePercent)%</td></tr>
        </table>
"@
}

# Add CPU information
if ($healthData.ContainsKey("CPU")) {
    $cpu = $healthData["CPU"].Data
    $statusClass = if ($healthData["CPU"].Status -eq "WARNING") { "metric-warning" } else { "metric-good" }
    $htmlContent += @"
        <h2>CPU Information</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Processor</td><td>$($cpu.ProcessorName)</td></tr>
            <tr><td>Cores</td><td>$($cpu.NumberOfCores)</td></tr>
            <tr><td>Logical Processors</td><td>$($cpu.NumberOfLogicalProcessors)</td></tr>
            <tr><td>Max Clock Speed</td><td>$($cpu.MaxClockSpeed) MHz</td></tr>
            <tr><td>Current Usage</td><td class="$statusClass">$($cpu.CurrentUsage)%</td></tr>
        </table>
"@
}

# Add services information
if ($healthData.ContainsKey("Services") -and $healthData["Services"].Data.Count -gt 0) {
    $htmlContent += @"
        <h2>Critical Services</h2>
        <table>
            <tr><th>Service Name</th><th>Display Name</th><th>Status</th><th>Start Type</th></tr>
"@
    foreach ($service in $healthData["Services"].Data) {
        $statusClass = if ($service.Status -eq "Running") { "metric-good" } else { "metric-warning" }
        $htmlContent += @"
            <tr>
                <td>$($service.Name)</td>
                <td>$($service.DisplayName)</td>
                <td class="$statusClass">$($service.Status)</td>
                <td>$($service.StartType)</td>
            </tr>
"@
    }
    $htmlContent += "</table>"
}

# Add uptime information
if ($healthData.ContainsKey("Uptime")) {
    $uptime = $healthData["Uptime"].Data
    $htmlContent += @"
        <h2>System Uptime</h2>
        <table>
            <tr><th>Metric</th><th>Value</th></tr>
            <tr><td>Last Boot Time</td><td>$($uptime.LastBootTime)</td></tr>
            <tr><td>Uptime</td><td>$($uptime.UptimeString)</td></tr>
            <tr><td>Uptime (Days)</td><td>$($uptime.UptimeDays)</td></tr>
        </table>
"@
}

# Add recent events
if ($healthData.ContainsKey("EventLogs") -and $healthData["EventLogs"].Data.Count -gt 0) {
    $htmlContent += @"
        <h2>Recent Critical Events (Last 24 Hours)</h2>
        <table>
            <tr><th>Time</th><th>Log</th><th>Level</th><th>Source</th><th>Event ID</th><th>Message</th></tr>
"@
    foreach ($event in ($healthData["EventLogs"].Data | Select-Object -First 20)) {
        $levelClass = switch ($event.Level) {
            "Critical" { "metric-critical" }
            "Error" { "metric-warning" }
            default { "" }
        }
        $htmlContent += @"
            <tr>
                <td>$($event.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))</td>
                <td>$($event.LogName)</td>
                <td class="$levelClass">$($event.Level)</td>
                <td>$($event.Source)</td>
                <td>$($event.EventID)</td>
                <td>$($event.Message)</td>
            </tr>
"@
    }
    $htmlContent += "</table>"
}

$htmlContent += @"
    </div>
</body>
</html>
"@

# Save HTML report
try {
    $htmlContent | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Host "✓ HTML report saved to: $reportPath" -ForegroundColor Green
} catch {
    Write-Host "✗ Failed to save HTML report: $($_.Exception.Message)" -ForegroundColor Red
    $errors += "Report generation error: $($_.Exception.Message)"
}

# Send email if requested
if ($EmailReport -and $SMTPServer -and $ToEmail -and $FromEmail) {
    try {
        $subject = "Server Health Report - $ComputerName - $overallStatus"
        $body = @"
Server Health Report for $ComputerName

Overall Status: $overallStatus
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')

Warnings: $($warnings.Count)
Errors: $($errors.Count)

Please see the attached HTML report for detailed information.
"@

        Send-MailMessage -To $ToEmail -From $FromEmail -Subject $subject -Body $body -SmtpServer $SMTPServer -Attachments $reportPath
        Write-Host "✓ Email report sent to: $ToEmail" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to send email report: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Display summary
Write-Host "`n=== HEALTH CHECK SUMMARY ===" -ForegroundColor Cyan
Write-Host "Server: $ComputerName" -ForegroundColor White
Write-Host "Overall Status: $overallStatus" -ForegroundColor $(if ($overallStatus -eq "OK") { "Green" } elseif ($overallStatus -eq "WARNING") { "Yellow" } else { "Red" })
Write-Host "Warnings: $($warnings.Count)" -ForegroundColor Yellow
Write-Host "Errors: $($errors.Count)" -ForegroundColor Red
Write-Host "Report: $reportPath" -ForegroundColor White

Write-Host "`nHealth check completed!" -ForegroundColor Green

