<#
.SYNOPSIS
    Creates a new Azure Virtual Machine with standard configuration.

.DESCRIPTION
    This script automates the creation of an Azure Virtual Machine including all necessary
    components like network interface, public IP, network security group, and storage.

.PARAMETER VMName
    The name of the virtual machine to create.

.PARAMETER ResourceGroupName
    The name of the resource group where the VM will be created.

.PARAMETER Location
    The Azure region where the VM will be created.

.PARAMETER VMSize
    The size of the virtual machine (e.g., "Standard_B2s", "Standard_D2s_v3").

.PARAMETER AdminUsername
    The administrator username for the VM.

.PARAMETER AdminPassword
    The administrator password for the VM. If not provided, will prompt securely.

.PARAMETER OSType
    The operating system type: Windows or Linux. Defaults to Windows.

.PARAMETER ImagePublisher
    The image publisher (e.g., "MicrosoftWindowsServer", "Canonical").

.PARAMETER ImageOffer
    The image offer (e.g., "WindowsServer", "UbuntuServer").

.PARAMETER ImageSku
    The image SKU (e.g., "2022-Datacenter", "18.04-LTS").

.PARAMETER VNetName
    The name of the virtual network. If not specified, will create a new one.

.PARAMETER SubnetName
    The name of the subnet. If not specified, will create a new one.

.PARAMETER CreatePublicIP
    Create a public IP address for the VM. Defaults to true.

.PARAMETER OpenPorts
    Array of ports to open in the network security group (e.g., @(80, 443, 3389)).

.EXAMPLE
    .\New-AzureVM.ps1 -VMName "MyVM01" -ResourceGroupName "MyRG" -Location "eastus" -VMSize "Standard_B2s" -AdminUsername "azureuser"

.EXAMPLE
    .\New-AzureVM.ps1 -VMName "WebServer01" -ResourceGroupName "WebRG" -Location "westus2" -VMSize "Standard_D2s_v3" -AdminUsername "admin" -OSType "Linux" -ImagePublisher "Canonical" -ImageOffer "UbuntuServer" -ImageSku "18.04-LTS" -OpenPorts @(22, 80, 443)

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Az PowerShell module
    - Authenticated Azure session (Connect-AzAccount)
    - Appropriate permissions to create resources in Azure subscription
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$VMName,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$Location,
    
    [Parameter(Mandatory=$false)]
    [string]$VMSize = "Standard_B2s",
    
    [Parameter(Mandatory=$true)]
    [string]$AdminUsername,
    
    [Parameter(Mandatory=$false)]
    [SecureString]$AdminPassword,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Windows", "Linux")]
    [string]$OSType = "Windows",
    
    [Parameter(Mandatory=$false)]
    [string]$ImagePublisher,
    
    [Parameter(Mandatory=$false)]
    [string]$ImageOffer,
    
    [Parameter(Mandatory=$false)]
    [string]$ImageSku,
    
    [Parameter(Mandatory=$false)]
    [string]$VNetName,
    
    [Parameter(Mandatory=$false)]
    [string]$SubnetName,
    
    [Parameter(Mandatory=$false)]
    [bool]$CreatePublicIP = $true,
    
    [Parameter(Mandatory=$false)]
    [int[]]$OpenPorts
)

# Import required modules
try {
    Import-Module Az.Compute -ErrorAction Stop
    Import-Module Az.Network -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    Write-Host "Azure PowerShell modules imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import Azure PowerShell modules. Please ensure Az module is installed."
    exit 1
}

# Check for Azure login
try {
    $currentContext = Get-AzContext -ErrorAction Stop
    Write-Host "Connected to Azure subscription: $($currentContext.Subscription.Name)" -ForegroundColor Green
} catch {
    Write-Error "Not connected to Azure. Please run Connect-AzAccount first."
    exit 1
}

# Set default image parameters based on OS type
if (-not $ImagePublisher) {
    switch ($OSType) {
        "Windows" {
            $ImagePublisher = "MicrosoftWindowsServer"
            $ImageOffer = "WindowsServer"
            $ImageSku = "2022-Datacenter"
            if (-not $OpenPorts) { $OpenPorts = @(3389) }
        }
        "Linux" {
            $ImagePublisher = "Canonical"
            $ImageOffer = "0001-com-ubuntu-server-focal"
            $ImageSku = "20_04-lts-gen2"
            if (-not $OpenPorts) { $OpenPorts = @(22) }
        }
    }
}

# Set default network names if not provided
if (-not $VNetName) { $VNetName = "$VMName-vnet" }
if (-not $SubnetName) { $SubnetName = "$VMName-subnet" }

# Get password if not provided
if (-not $AdminPassword) {
    $AdminPassword = Read-Host "Enter administrator password" -AsSecureString
}

Write-Host "Starting Azure VM creation process for: $VMName" -ForegroundColor Cyan

# Check if resource group exists
try {
    $rg = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop
    Write-Host "Using existing resource group: $($rg.ResourceGroupName)" -ForegroundColor Green
} catch {
    Write-Error "Resource group '$ResourceGroupName' not found. Please create it first."
    exit 1
}

# Check if VM already exists
try {
    $existingVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -ErrorAction SilentlyContinue
    if ($existingVM) {
        Write-Error "VM '$VMName' already exists in resource group '$ResourceGroupName'."
        exit 1
    }
} catch {
    # VM doesn't exist, which is what we want
}

# Create or get virtual network
try {
    Write-Host "Checking for virtual network: $VNetName" -ForegroundColor Yellow
    $vnet = Get-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Name $VNetName -ErrorAction SilentlyContinue
    
    if (-not $vnet) {
        Write-Host "Creating virtual network: $VNetName" -ForegroundColor Yellow
        $subnetConfig = New-AzVirtualNetworkSubnetConfig -Name $SubnetName -AddressPrefix "10.0.1.0/24"
        $vnet = New-AzVirtualNetwork -ResourceGroupName $ResourceGroupName -Location $Location -Name $VNetName -AddressPrefix "10.0.0.0/16" -Subnet $subnetConfig
        Write-Host "Virtual network created successfully." -ForegroundColor Green
    } else {
        Write-Host "Using existing virtual network: $VNetName" -ForegroundColor Green
    }
    
    # Get subnet
    $subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $SubnetName -ErrorAction SilentlyContinue
    if (-not $subnet) {
        Write-Host "Creating subnet: $SubnetName" -ForegroundColor Yellow
        $vnet = Add-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $SubnetName -AddressPrefix "10.0.1.0/24"
        $vnet = Set-AzVirtualNetwork -VirtualNetwork $vnet
        $subnet = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet -Name $SubnetName
        Write-Host "Subnet created successfully." -ForegroundColor Green
    }
    
} catch {
    Write-Error "Failed to create/configure virtual network: $($_.Exception.Message)"
    exit 1
}

# Create public IP if requested
$publicIP = $null
if ($CreatePublicIP) {
    try {
        Write-Host "Creating public IP address..." -ForegroundColor Yellow
        $publicIPName = "$VMName-pip"
        $publicIP = New-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Location $Location -Name $publicIPName -AllocationMethod Dynamic
        Write-Host "Public IP address created: $publicIPName" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create public IP: $($_.Exception.Message)"
        exit 1
    }
}

# Create network security group
try {
    Write-Host "Creating network security group..." -ForegroundColor Yellow
    $nsgName = "$VMName-nsg"
    
    # Create security rules for specified ports
    $securityRules = @()
    $priority = 1000
    
    foreach ($port in $OpenPorts) {
        $ruleName = switch ($port) {
            22 { "SSH" }
            80 { "HTTP" }
            443 { "HTTPS" }
            3389 { "RDP" }
            default { "Port$port" }
        }
        
        $rule = New-AzNetworkSecurityRuleConfig -Name $ruleName -Protocol Tcp -Direction Inbound -Priority $priority -SourceAddressPrefix * -SourcePortRange * -DestinationAddressPrefix * -DestinationPortRange $port -Access Allow
        $securityRules += $rule
        $priority += 10
    }
    
    $nsg = New-AzNetworkSecurityGroup -ResourceGroupName $ResourceGroupName -Location $Location -Name $nsgName -SecurityRules $securityRules
    Write-Host "Network security group created with rules for ports: $($OpenPorts -join ', ')" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to create network security group: $($_.Exception.Message)"
    exit 1
}

# Create network interface
try {
    Write-Host "Creating network interface..." -ForegroundColor Yellow
    $nicName = "$VMName-nic"
    
    $nicParams = @{
        ResourceGroupName = $ResourceGroupName
        Location = $Location
        Name = $nicName
        SubnetId = $subnet.Id
        NetworkSecurityGroupId = $nsg.Id
    }
    
    if ($publicIP) {
        $nicParams.PublicIpAddressId = $publicIP.Id
    }
    
    $nic = New-AzNetworkInterface @nicParams
    Write-Host "Network interface created: $nicName" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to create network interface: $($_.Exception.Message)"
    exit 1
}

# Create virtual machine configuration
try {
    Write-Host "Creating virtual machine configuration..." -ForegroundColor Yellow
    
    # Create VM config
    $vmConfig = New-AzVMConfig -VMName $VMName -VMSize $VMSize
    
    # Set operating system configuration
    if ($OSType -eq "Windows") {
        $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Windows -ComputerName $VMName -Credential (New-Object PSCredential($AdminUsername, $AdminPassword)) -ProvisionVMAgent -EnableAutoUpdate
    } else {
        $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -Linux -ComputerName $VMName -Credential (New-Object PSCredential($AdminUsername, $AdminPassword))
    }
    
    # Set source image
    $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName $ImagePublisher -Offer $ImageOffer -Skus $ImageSku -Version latest
    
    # Add network interface
    $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id
    
    # Set OS disk configuration
    $osDiskName = "$VMName-osdisk"
    $vmConfig = Set-AzVMOSDisk -VM $vmConfig -Name $osDiskName -CreateOption FromImage -StorageAccountType Premium_LRS
    
    Write-Host "VM configuration created successfully." -ForegroundColor Green
    
} catch {
    Write-Error "Failed to create VM configuration: $($_.Exception.Message)"
    exit 1
}

# Create the virtual machine
try {
    Write-Host "Creating virtual machine: $VMName" -ForegroundColor Yellow
    Write-Host "This may take several minutes..." -ForegroundColor Yellow
    
    $vm = New-AzVM -ResourceGroupName $ResourceGroupName -Location $Location -VM $vmConfig
    Write-Host "Virtual machine created successfully!" -ForegroundColor Green
    
} catch {
    Write-Error "Failed to create virtual machine: $($_.Exception.Message)"
    exit 1
}

# Get final VM information
try {
    $finalVM = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName
    $vmStatus = Get-AzVM -ResourceGroupName $ResourceGroupName -Name $VMName -Status
    
    # Get public IP if created
    $publicIPAddress = $null
    if ($publicIP) {
        $publicIPInfo = Get-AzPublicIpAddress -ResourceGroupName $ResourceGroupName -Name $publicIP.Name
        $publicIPAddress = $publicIPInfo.IpAddress
    }
    
    # Display summary
    Write-Host "`n=== VIRTUAL MACHINE CREATION SUMMARY ===" -ForegroundColor Cyan
    Write-Host "VM Name: $($finalVM.Name)" -ForegroundColor White
    Write-Host "Resource Group: $($finalVM.ResourceGroupName)" -ForegroundColor White
    Write-Host "Location: $($finalVM.Location)" -ForegroundColor White
    Write-Host "VM Size: $($finalVM.HardwareProfile.VmSize)" -ForegroundColor White
    Write-Host "OS Type: $OSType" -ForegroundColor White
    Write-Host "Admin Username: $AdminUsername" -ForegroundColor White
    Write-Host "VM Status: $($vmStatus.Statuses[1].DisplayStatus)" -ForegroundColor Green
    Write-Host "Virtual Network: $VNetName" -ForegroundColor White
    Write-Host "Subnet: $SubnetName" -ForegroundColor White
    Write-Host "Network Security Group: $nsgName" -ForegroundColor White
    Write-Host "Open Ports: $($OpenPorts -join ', ')" -ForegroundColor White
    
    if ($publicIPAddress -and $publicIPAddress -ne "Not Assigned") {
        Write-Host "Public IP Address: $publicIPAddress" -ForegroundColor Green
    } else {
        Write-Host "Public IP Address: Not assigned or pending" -ForegroundColor Yellow
    }
    
    Write-Host "VM ID: $($finalVM.Id)" -ForegroundColor Gray
    
} catch {
    Write-Warning "VM created but failed to retrieve final information: $($_.Exception.Message)"
}

# Display connection information
Write-Host "`n=== CONNECTION INFORMATION ===" -ForegroundColor Cyan
if ($OSType -eq "Windows") {
    Write-Host "To connect via RDP:" -ForegroundColor Yellow
    if ($publicIPAddress -and $publicIPAddress -ne "Not Assigned") {
        Write-Host "  mstsc /v:$publicIPAddress" -ForegroundColor White
    } else {
        Write-Host "  Use the public IP address once assigned" -ForegroundColor White
    }
    Write-Host "  Username: $AdminUsername" -ForegroundColor White
} else {
    Write-Host "To connect via SSH:" -ForegroundColor Yellow
    if ($publicIPAddress -and $publicIPAddress -ne "Not Assigned") {
        Write-Host "  ssh $AdminUsername@$publicIPAddress" -ForegroundColor White
    } else {
        Write-Host "  ssh $AdminUsername@<public-ip-address>" -ForegroundColor White
    }
}

Write-Host "`nVirtual machine creation completed successfully!" -ForegroundColor Green

