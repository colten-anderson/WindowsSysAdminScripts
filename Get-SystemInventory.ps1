<#
.SYNOPSIS
    Gathers comprehensive system inventory information from Windows desktops.

.DESCRIPTION
    This script collects detailed hardware and software information from Windows systems
    including hardware specifications, installed software, network configuration, and system settings.

.PARAMETER ComputerName
    Name of the computer to inventory. Defaults to local computer.

.PARAMETER OutputPath
    Path where the inventory report will be saved.

.PARAMETER ExportFormat
    Export format: CSV, JSON, HTML, or All. Defaults to HTML.

.PARAMETER IncludeSoftware
    Include detailed installed software inventory.

.PARAMETER IncludeHotfixes
    Include installed Windows updates and hotfixes.

.PARAMETER IncludeServices
    Include Windows services information.

.PARAMETER IncludeProcesses
    Include running processes information.

.EXAMPLE
    .\Get-SystemInventory.ps1

.EXAMPLE
    .\Get-SystemInventory.ps1 -ComputerName "DESKTOP01" -OutputPath "C:\Reports" -ExportFormat "All" -IncludeSoftware

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
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
    [ValidateSet("CSV", "JSON", "HTML", "All")]
    [string]$ExportFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSoftware,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeHotfixes,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeServices,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeProcesses
)

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$inventoryData = @{}

Write-Host "Starting system inventory for: $ComputerName" -ForegroundColor Cyan

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

# Function to safely get CIM data
function Get-SafeCimInstance {
    param(
        [string]$ClassName,
        [string]$ComputerName,
        [string]$Description
    )
    
    try {
        Write-Host "Gathering $Description..." -ForegroundColor Yellow
        $data = Get-CimInstance -ClassName $ClassName -ComputerName $ComputerName -ErrorAction Stop
        Write-Host "✓ $Description collected" -ForegroundColor Green
        return $data
    } catch {
        Write-Host "✗ Failed to collect $Description`: $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

# Gather system information
$systemInfo = Get-SafeCimInstance -ClassName "Win32_ComputerSystem" -ComputerName $ComputerName -Description "System Information"
$osInfo = Get-SafeCimInstance -ClassName "Win32_OperatingSystem" -ComputerName $ComputerName -Description "Operating System Information"
$biosInfo = Get-SafeCimInstance -ClassName "Win32_BIOS" -ComputerName $ComputerName -Description "BIOS Information"

if ($systemInfo -and $osInfo) {
    $inventoryData["System"] = [PSCustomObject]@{
        ComputerName = $systemInfo.Name
        Domain = $systemInfo.Domain
        Workgroup = $systemInfo.Workgroup
        Manufacturer = $systemInfo.Manufacturer
        Model = $systemInfo.Model
        SystemType = $systemInfo.SystemType
        TotalPhysicalMemory = [math]::Round($systemInfo.TotalPhysicalMemory / 1GB, 2)
        NumberOfProcessors = $systemInfo.NumberOfProcessors
        NumberOfLogicalProcessors = $systemInfo.NumberOfLogicalProcessors
        OSName = $osInfo.Caption
        OSVersion = $osInfo.Version
        OSBuild = $osInfo.BuildNumber
        OSArchitecture = $osInfo.OSArchitecture
        ServicePack = $osInfo.ServicePackMajorVersion
        InstallDate = $osInfo.InstallDate
        LastBootUpTime = $osInfo.LastBootUpTime
        WindowsDirectory = $osInfo.WindowsDirectory
        SystemDirectory = $osInfo.SystemDirectory
        BIOSVersion = if ($biosInfo) { $biosInfo.SMBIOSBIOSVersion } else { "N/A" }
        BIOSDate = if ($biosInfo) { $biosInfo.ReleaseDate } else { "N/A" }
        SerialNumber = if ($biosInfo) { $biosInfo.SerialNumber } else { "N/A" }
    }
}

# Gather processor information
$processorInfo = Get-SafeCimInstance -ClassName "Win32_Processor" -ComputerName $ComputerName -Description "Processor Information"
if ($processorInfo) {
    $inventoryData["Processor"] = $processorInfo | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Manufacturer = $_.Manufacturer
            Family = $_.Family
            Model = $_.Model
            Stepping = $_.Stepping
            MaxClockSpeed = $_.MaxClockSpeed
            CurrentClockSpeed = $_.CurrentClockSpeed
            NumberOfCores = $_.NumberOfCores
            NumberOfLogicalProcessors = $_.NumberOfLogicalProcessors
            L2CacheSize = $_.L2CacheSize
            L3CacheSize = $_.L3CacheSize
            Architecture = switch ($_.Architecture) {
                0 { "x86" }
                1 { "MIPS" }
                2 { "Alpha" }
                3 { "PowerPC" }
                6 { "Intel Itanium" }
                9 { "x64" }
                default { "Unknown" }
            }
        }
    }
}

# Gather memory information
$memoryInfo = Get-SafeCimInstance -ClassName "Win32_PhysicalMemory" -ComputerName $ComputerName -Description "Memory Information"
if ($memoryInfo) {
    $inventoryData["Memory"] = $memoryInfo | ForEach-Object {
        [PSCustomObject]@{
            BankLabel = $_.BankLabel
            DeviceLocator = $_.DeviceLocator
            Capacity = [math]::Round($_.Capacity / 1GB, 2)
            Speed = $_.Speed
            Manufacturer = $_.Manufacturer
            PartNumber = $_.PartNumber
            SerialNumber = $_.SerialNumber
            MemoryType = switch ($_.MemoryType) {
                20 { "DDR" }
                21 { "DDR2" }
                22 { "DDR2 FB-DIMM" }
                24 { "DDR3" }
                26 { "DDR4" }
                default { "Unknown" }
            }
        }
    }
}

# Gather disk information
$diskInfo = Get-SafeCimInstance -ClassName "Win32_DiskDrive" -ComputerName $ComputerName -Description "Disk Drive Information"
if ($diskInfo) {
    $inventoryData["DiskDrives"] = $diskInfo | ForEach-Object {
        [PSCustomObject]@{
            Model = $_.Model
            Size = [math]::Round($_.Size / 1GB, 2)
            InterfaceType = $_.InterfaceType
            MediaType = $_.MediaType
            Partitions = $_.Partitions
            SerialNumber = $_.SerialNumber
            FirmwareRevision = $_.FirmwareRevision
        }
    }
}

# Gather logical disk information
$logicalDiskInfo = Get-SafeCimInstance -ClassName "Win32_LogicalDisk" -ComputerName $ComputerName -Description "Logical Disk Information"
if ($logicalDiskInfo) {
    $inventoryData["LogicalDisks"] = $logicalDiskInfo | ForEach-Object {
        [PSCustomObject]@{
            DeviceID = $_.DeviceID
            DriveType = switch ($_.DriveType) {
                2 { "Removable Disk" }
                3 { "Local Disk" }
                4 { "Network Drive" }
                5 { "Compact Disc" }
                default { "Unknown" }
            }
            FileSystem = $_.FileSystem
            Size = if ($_.Size) { [math]::Round($_.Size / 1GB, 2) } else { 0 }
            FreeSpace = if ($_.FreeSpace) { [math]::Round($_.FreeSpace / 1GB, 2) } else { 0 }
            VolumeName = $_.VolumeName
            VolumeSerialNumber = $_.VolumeSerialNumber
        }
    }
}

# Gather network adapter information
$networkInfo = Get-SafeCimInstance -ClassName "Win32_NetworkAdapter" -ComputerName $ComputerName -Description "Network Adapter Information"
if ($networkInfo) {
    $inventoryData["NetworkAdapters"] = $networkInfo | Where-Object { $_.PhysicalAdapter -eq $true } | ForEach-Object {
        [PSCustomObject]@{
            Name = $_.Name
            Description = $_.Description
            MACAddress = $_.MACAddress
            AdapterType = $_.AdapterType
            Speed = $_.Speed
            NetConnectionStatus = switch ($_.NetConnectionStatus) {
                0 { "Disconnected" }
                1 { "Connecting" }
                2 { "Connected" }
                3 { "Disconnecting" }
                4 { "Hardware not present" }
                5 { "Hardware disabled" }
                6 { "Hardware malfunction" }
                7 { "Media disconnected" }
                8 { "Authenticating" }
                9 { "Authentication succeeded" }
                10 { "Authentication failed" }
                11 { "Invalid address" }
                12 { "Credentials required" }
                default { "Unknown" }
            }
        }
    }
}

# Gather network configuration
$networkConfig = Get-SafeCimInstance -ClassName "Win32_NetworkAdapterConfiguration" -ComputerName $ComputerName -Description "Network Configuration"
if ($networkConfig) {
    $inventoryData["NetworkConfiguration"] = $networkConfig | Where-Object { $_.IPEnabled -eq $true } | ForEach-Object {
        [PSCustomObject]@{
            Description = $_.Description
            IPAddress = $_.IPAddress -join ", "
            SubnetMask = $_.IPSubnet -join ", "
            DefaultGateway = $_.DefaultIPGateway -join ", "
            DNSServers = $_.DNSServerSearchOrder -join ", "
            DHCPEnabled = $_.DHCPEnabled
            DHCPServer = $_.DHCPServer
            MACAddress = $_.MACAddress
        }
    }
}

# Gather installed software (if requested)
if ($IncludeSoftware) {
    $softwareInfo = Get-SafeCimInstance -ClassName "Win32_Product" -ComputerName $ComputerName -Description "Installed Software"
    if ($softwareInfo) {
        $inventoryData["InstalledSoftware"] = $softwareInfo | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                Version = $_.Version
                Vendor = $_.Vendor
                InstallDate = $_.InstallDate
                InstallLocation = $_.InstallLocation
                InstallSource = $_.InstallSource
            }
        } | Sort-Object Name
    }
}

# Gather hotfixes (if requested)
if ($IncludeHotfixes) {
    $hotfixInfo = Get-SafeCimInstance -ClassName "Win32_QuickFixEngineering" -ComputerName $ComputerName -Description "Installed Hotfixes"
    if ($hotfixInfo) {
        $inventoryData["Hotfixes"] = $hotfixInfo | ForEach-Object {
            [PSCustomObject]@{
                HotFixID = $_.HotFixID
                Description = $_.Description
                InstalledBy = $_.InstalledBy
                InstalledOn = $_.InstalledOn
            }
        } | Sort-Object InstalledOn -Descending
    }
}

# Gather services (if requested)
if ($IncludeServices) {
    $serviceInfo = Get-SafeCimInstance -ClassName "Win32_Service" -ComputerName $ComputerName -Description "Windows Services"
    if ($serviceInfo) {
        $inventoryData["Services"] = $serviceInfo | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                DisplayName = $_.DisplayName
                State = $_.State
                StartMode = $_.StartMode
                ServiceType = $_.ServiceType
                PathName = $_.PathName
                StartName = $_.StartName
            }
        } | Sort-Object DisplayName
    }
}

# Gather processes (if requested)
if ($IncludeProcesses) {
    $processInfo = Get-SafeCimInstance -ClassName "Win32_Process" -ComputerName $ComputerName -Description "Running Processes"
    if ($processInfo) {
        $inventoryData["Processes"] = $processInfo | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                ProcessId = $_.ProcessId
                ParentProcessId = $_.ParentProcessId
                ExecutablePath = $_.ExecutablePath
                CommandLine = $_.CommandLine
                CreationDate = $_.CreationDate
                WorkingSetSize = if ($_.WorkingSetSize) { [math]::Round($_.WorkingSetSize / 1MB, 2) } else { 0 }
            }
        } | Sort-Object Name
    }
}

# Export data based on format
Write-Host "Exporting inventory data..." -ForegroundColor Yellow

if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "All") {
    foreach ($category in $inventoryData.Keys) {
        $csvPath = Join-Path $OutputPath "$($ComputerName)_$($category)_$timestamp.csv"
        try {
            $inventoryData[$category] | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Host "✓ CSV exported: $csvPath" -ForegroundColor Green
        } catch {
            Write-Host "✗ Failed to export CSV for $category`: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "All") {
    $jsonPath = Join-Path $OutputPath "$($ComputerName)_Inventory_$timestamp.json"
    try {
        $inventoryData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "✓ JSON exported: $jsonPath" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to export JSON: $($_.Exception.Message)" -ForegroundColor Red
    }
}

if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "All") {
    $htmlPath = Join-Path $OutputPath "$($ComputerName)_Inventory_$timestamp.html"
    
    # Generate HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Inventory - $ComputerName</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        h1 { color: #2E86AB; text-align: center; }
        h2 { color: #2E86AB; border-bottom: 2px solid #2E86AB; padding-bottom: 5px; }
        .summary { background-color: #f0f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; font-size: 12px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #2E86AB; color: white; }
        tr:nth-child(even) { background-color: #f2f2f2; }
        .category { margin-bottom: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>System Inventory Report</h1>
        <div class="summary">
            <h3>Report Summary</h3>
            <p><strong>Computer:</strong> $ComputerName</p>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Categories:</strong> $($inventoryData.Keys.Count)</p>
        </div>
"@

    # Add each category to HTML
    foreach ($category in $inventoryData.Keys) {
        $htmlContent += "<div class='category'><h2>$category</h2>"
        
        if ($inventoryData[$category] -is [array]) {
            if ($inventoryData[$category].Count -gt 0) {
                $htmlContent += "<table><thead><tr>"
                
                # Add headers
                $properties = $inventoryData[$category][0].PSObject.Properties.Name
                foreach ($prop in $properties) {
                    $htmlContent += "<th>$prop</th>"
                }
                $htmlContent += "</tr></thead><tbody>"
                
                # Add data rows
                foreach ($item in $inventoryData[$category]) {
                    $htmlContent += "<tr>"
                    foreach ($prop in $properties) {
                        $value = $item.$prop
                        if ($value -eq $null) { $value = "" }
                        $htmlContent += "<td>$value</td>"
                    }
                    $htmlContent += "</tr>"
                }
                $htmlContent += "</tbody></table>"
            } else {
                $htmlContent += "<p>No data available</p>"
            }
        } else {
            # Single object
            $htmlContent += "<table><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>"
            $properties = $inventoryData[$category].PSObject.Properties
            foreach ($prop in $properties) {
                $htmlContent += "<tr><td>$($prop.Name)</td><td>$($prop.Value)</td></tr>"
            }
            $htmlContent += "</tbody></table>"
        }
        
        $htmlContent += "</div>"
    }

    $htmlContent += @"
    </div>
</body>
</html>
"@

    try {
        $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Host "✓ HTML exported: $htmlPath" -ForegroundColor Green
    } catch {
        Write-Host "✗ Failed to export HTML: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Display summary
Write-Host "`n=== INVENTORY SUMMARY ===" -ForegroundColor Cyan
Write-Host "Computer: $ComputerName" -ForegroundColor White
Write-Host "Categories Collected: $($inventoryData.Keys.Count)" -ForegroundColor White
Write-Host "Export Format: $ExportFormat" -ForegroundColor White
Write-Host "Output Path: $OutputPath" -ForegroundColor White

foreach ($category in $inventoryData.Keys) {
    $count = if ($inventoryData[$category] -is [array]) { $inventoryData[$category].Count } else { 1 }
    Write-Host "- $category`: $count items" -ForegroundColor Gray
}

Write-Host "`nInventory collection completed!" -ForegroundColor Green

