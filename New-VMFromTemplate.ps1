<#
.SYNOPSIS
    Creates new Hyper-V virtual machines from a template or base configuration.

.DESCRIPTION
    This script automates the creation of Hyper-V virtual machines with standardized configurations.
    It can create VMs from existing templates, configure networking, and apply initial settings.

.PARAMETER VMName
    Name of the new virtual machine.

.PARAMETER TemplateVHD
    Path to the template VHD/VHDX file to use as a base.

.PARAMETER VMPath
    Path where the VM files will be stored. Defaults to default Hyper-V path.

.PARAMETER Memory
    Amount of memory to assign to the VM in GB. Defaults to 4GB.

.PARAMETER CPUCount
    Number of virtual CPUs to assign. Defaults to 2.

.PARAMETER SwitchName
    Name of the virtual switch to connect the VM to.

.PARAMETER Generation
    VM generation (1 or 2). Defaults to 2.

.PARAMETER StartVM
    Start the VM after creation.

.PARAMETER ConfigureNetwork
    Configure network settings in the VM (requires PowerShell Direct).

.PARAMETER IPAddress
    Static IP address to assign (if ConfigureNetwork is used).

.PARAMETER SubnetMask
    Subnet mask for static IP (if ConfigureNetwork is used).

.PARAMETER Gateway
    Default gateway for static IP (if ConfigureNetwork is used).

.PARAMETER DNSServers
    DNS servers for static IP configuration (if ConfigureNetwork is used).

.EXAMPLE
    .\New-VMFromTemplate.ps1 -VMName "WebServer01" -TemplateVHD "C:\Templates\WindowsServer2022.vhdx" -SwitchName "Internal"

.EXAMPLE
    .\New-VMFromTemplate.ps1 -VMName "WebServer01" -TemplateVHD "C:\Templates\WindowsServer2022.vhdx" -Memory 8 -CPUCount 4 -StartVM

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Hyper-V PowerShell module
    - Hyper-V role installed
    - Template VHD/VHDX file
    - Appropriate permissions to create VMs
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$VMName,
    
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$TemplateVHD,
    
    [Parameter(Mandatory=$false)]
    [string]$VMPath,
    
    [Parameter(Mandatory=$false)]
    [int]$Memory = 4,
    
    [Parameter(Mandatory=$false)]
    [int]$CPUCount = 2,
    
    [Parameter(Mandatory=$false)]
    [string]$SwitchName,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(1, 2)]
    [int]$Generation = 2,
    
    [Parameter(Mandatory=$false)]
    [switch]$StartVM,
    
    [Parameter(Mandatory=$false)]
    [switch]$ConfigureNetwork,
    
    [Parameter(Mandatory=$false)]
    [string]$IPAddress,
    
    [Parameter(Mandatory=$false)]
    [string]$SubnetMask = "255.255.255.0",
    
    [Parameter(Mandatory=$false)]
    [string]$Gateway,
    
    [Parameter(Mandatory=$false)]
    [string[]]$DNSServers = @("8.8.8.8", "8.8.4.4")
)

# Import required modules
try {
    Import-Module Hyper-V -ErrorAction Stop
    Write-Host "Hyper-V module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import Hyper-V module. Please ensure Hyper-V is installed."
    exit 1
}

# Initialize logging
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

Write-Log "Starting VM creation process for: $VMName"

# Check if VM already exists
if (Get-VM -Name $VMName -ErrorAction SilentlyContinue) {
    Write-Log "VM with name '$VMName' already exists" -Level "ERROR"
    exit 1
}

# Get default VM path if not specified
if (-not $VMPath) {
    $VMPath = (Get-VMHost).VirtualMachinePath
    Write-Log "Using default VM path: $VMPath"
}

# Validate virtual switch
if ($SwitchName) {
    $switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
    if (-not $switch) {
        Write-Log "Virtual switch '$SwitchName' not found" -Level "ERROR"
        exit 1
    }
    Write-Log "Using virtual switch: $SwitchName"
} else {
    # Get default switch
    $switch = Get-VMSwitch | Select-Object -First 1
    if ($switch) {
        $SwitchName = $switch.Name
        Write-Log "Using default virtual switch: $SwitchName"
    } else {
        Write-Log "No virtual switches found. VM will be created without network connectivity." -Level "WARNING"
    }
}

# Create VM directory
$vmDirectory = Join-Path $VMPath $VMName
try {
    if (-not (Test-Path $vmDirectory)) {
        New-Item -Path $vmDirectory -ItemType Directory -Force | Out-Null
        Write-Log "Created VM directory: $vmDirectory" -Level "SUCCESS"
    }
} catch {
    Write-Log "Failed to create VM directory: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Copy template VHD
$templateExtension = [System.IO.Path]::GetExtension($TemplateVHD)
$newVHDPath = Join-Path $vmDirectory "$VMName$templateExtension"

try {
    Write-Log "Copying template VHD to: $newVHDPath"
    Copy-Item -Path $TemplateVHD -Destination $newVHDPath -Force
    Write-Log "Template VHD copied successfully" -Level "SUCCESS"
} catch {
    Write-Log "Failed to copy template VHD: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Create the virtual machine
try {
    Write-Log "Creating virtual machine: $VMName"
    
    $vmParams = @{
        Name = $VMName
        Path = $VMPath
        Generation = $Generation
        MemoryStartupBytes = $Memory * 1GB
    }
    
    $vm = New-VM @vmParams
    Write-Log "Virtual machine created successfully" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to create virtual machine: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Configure VM settings
try {
    # Set processor count
    Set-VMProcessor -VMName $VMName -Count $CPUCount
    Write-Log "Set CPU count to: $CPUCount" -Level "SUCCESS"
    
    # Enable dynamic memory
    Set-VMMemory -VMName $VMName -DynamicMemoryEnabled $true -MinimumBytes (1GB) -MaximumBytes ($Memory * 2GB)
    Write-Log "Configured dynamic memory: Min 1GB, Startup $($Memory)GB, Max $($Memory * 2)GB" -Level "SUCCESS"
    
    # Add hard drive
    Add-VMHardDiskDrive -VMName $VMName -Path $newVHDPath
    Write-Log "Added hard disk drive: $newVHDPath" -Level "SUCCESS"
    
    # Configure network adapter
    if ($SwitchName) {
        $networkAdapter = Get-VMNetworkAdapter -VMName $VMName
        Connect-VMNetworkAdapter -VMNetworkAdapter $networkAdapter -SwitchName $SwitchName
        Write-Log "Connected network adapter to switch: $SwitchName" -Level "SUCCESS"
    }
    
    # Configure boot order for Generation 2 VMs
    if ($Generation -eq 2) {
        $hardDrive = Get-VMHardDiskDrive -VMName $VMName
        $networkAdapter = Get-VMNetworkAdapter -VMName $VMName
        Set-VMFirmware -VMName $VMName -BootOrder $hardDrive, $networkAdapter
        Write-Log "Configured boot order for Generation 2 VM" -Level "SUCCESS"
    }
    
} catch {
    Write-Log "Failed to configure VM settings: $($_.Exception.Message)" -Level "ERROR"
    # Don't exit here, VM is created but may need manual configuration
}

# Start VM if requested
if ($StartVM) {
    try {
        Write-Log "Starting virtual machine: $VMName"
        Start-VM -Name $VMName
        Write-Log "Virtual machine started successfully" -Level "SUCCESS"
        
        # Wait for VM to boot
        Write-Log "Waiting for VM to boot..."
        Start-Sleep -Seconds 30
        
    } catch {
        Write-Log "Failed to start virtual machine: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Configure network settings if requested
if ($ConfigureNetwork -and $IPAddress -and $StartVM) {
    try {
        Write-Log "Configuring network settings via PowerShell Direct"
        
        # Wait for PowerShell Direct to be available
        $timeout = 300 # 5 minutes
        $elapsed = 0
        $interval = 10
        
        do {
            Start-Sleep -Seconds $interval
            $elapsed += $interval
            Write-Log "Waiting for PowerShell Direct connectivity... ($elapsed/$timeout seconds)"
            
            try {
                $session = New-PSSession -VMName $VMName -ErrorAction Stop
                if ($session) {
                    Write-Log "PowerShell Direct connection established" -Level "SUCCESS"
                    break
                }
            } catch {
                # Continue waiting
            }
        } while ($elapsed -lt $timeout)
        
        if ($session) {
            # Configure static IP
            $networkScript = {
                param($IP, $Subnet, $GW, $DNS)
                
                try {
                    # Get network adapter
                    $adapter = Get-NetAdapter | Where-Object { $_.Status -eq "Up" } | Select-Object -First 1
                    
                    if ($adapter) {
                        # Remove existing IP configuration
                        Remove-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue
                        Remove-NetRoute -InterfaceIndex $adapter.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue
                        
                        # Set static IP
                        New-NetIPAddress -InterfaceIndex $adapter.InterfaceIndex -IPAddress $IP -PrefixLength 24 -DefaultGateway $GW
                        
                        # Set DNS servers
                        Set-DnsClientServerAddress -InterfaceIndex $adapter.InterfaceIndex -ServerAddresses $DNS
                        
                        return "Network configuration applied successfully"
                    } else {
                        return "No active network adapter found"
                    }
                } catch {
                    return "Error configuring network: $($_.Exception.Message)"
                }
            }
            
            $result = Invoke-Command -Session $session -ScriptBlock $networkScript -ArgumentList $IPAddress, $SubnetMask, $Gateway, $DNSServers
            Write-Log "Network configuration result: $result" -Level "SUCCESS"
            
            Remove-PSSession -Session $session
        } else {
            Write-Log "Failed to establish PowerShell Direct connection within timeout period" -Level "WARNING"
        }
        
    } catch {
        Write-Log "Failed to configure network settings: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Get VM information
try {
    $vmInfo = Get-VM -Name $VMName
    $vmHardDisk = Get-VMHardDiskDrive -VMName $VMName
    $vmNetwork = Get-VMNetworkAdapter -VMName $VMName
    
    Write-Host "`n=== VM CREATION SUMMARY ===" -ForegroundColor Cyan
    Write-Host "VM Name: $($vmInfo.Name)" -ForegroundColor White
    Write-Host "State: $($vmInfo.State)" -ForegroundColor $(if ($vmInfo.State -eq "Running") { "Green" } else { "Yellow" })
    Write-Host "Generation: $($vmInfo.Generation)" -ForegroundColor White
    Write-Host "Memory: $($vmInfo.MemoryStartup / 1GB) GB" -ForegroundColor White
    Write-Host "CPU Count: $($vmInfo.ProcessorCount)" -ForegroundColor White
    Write-Host "Hard Disk: $($vmHardDisk.Path)" -ForegroundColor White
    Write-Host "Network Switch: $($vmNetwork.SwitchName)" -ForegroundColor White
    Write-Host "VM Path: $($vmInfo.Path)" -ForegroundColor White
    
    if ($ConfigureNetwork -and $IPAddress) {
        Write-Host "IP Address: $IPAddress" -ForegroundColor White
        Write-Host "Gateway: $Gateway" -ForegroundColor White
        Write-Host "DNS Servers: $($DNSServers -join ', ')" -ForegroundColor White
    }
    
} catch {
    Write-Log "Failed to retrieve VM information: $($_.Exception.Message)" -Level "ERROR"
}

Write-Log "VM creation process completed for: $VMName" -Level "SUCCESS"

# Display next steps
Write-Host "`n=== NEXT STEPS ===" -ForegroundColor Cyan
Write-Host "1. Connect to the VM using Hyper-V Manager or VMConnect" -ForegroundColor Yellow
Write-Host "2. Complete the initial OS setup if using a template" -ForegroundColor Yellow
Write-Host "3. Install any required software or updates" -ForegroundColor Yellow
Write-Host "4. Configure additional settings as needed" -ForegroundColor Yellow

if (-not $StartVM) {
    Write-Host "5. Start the VM when ready: Start-VM -Name '$VMName'" -ForegroundColor Yellow
}

