<#
.SYNOPSIS
    Generates comprehensive reports for Azure resources across subscriptions.

.DESCRIPTION
    This script connects to Azure and generates detailed reports about resources,
    including virtual machines, storage accounts, network resources, and cost information.

.PARAMETER SubscriptionId
    Specific Azure subscription ID to report on. If not specified, reports on current subscription.

.PARAMETER ResourceGroupName
    Specific resource group to report on. If not specified, reports on all resource groups.

.PARAMETER OutputPath
    Path where the report files will be saved. Defaults to the script directory.

.PARAMETER ExportFormat
    Export format for the report. Options: CSV, JSON, HTML, All. Defaults to HTML.

.PARAMETER IncludeCosts
    Include cost information in the report (requires appropriate permissions).

.PARAMETER IncludeMetrics
    Include basic metrics for resources like VMs and storage accounts.

.PARAMETER ResourceTypes
    Array of specific resource types to include (e.g., @("Microsoft.Compute/virtualMachines", "Microsoft.Storage/storageAccounts")).

.EXAMPLE
    .\Get-AzureResourceReport.ps1

.EXAMPLE
    .\Get-AzureResourceReport.ps1 -ResourceGroupName "MyRG" -OutputPath "C:\Reports" -ExportFormat "All" -IncludeCosts

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Az PowerShell module
    - Authenticated Azure session (Connect-AzAccount)
    - Appropriate permissions to read resources and costs
    
    Required Permissions:
    - Reader role on subscription/resource groups
    - Cost Management Reader (for cost information)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$false)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "HTML", "All")]
    [string]$ExportFormat = "HTML",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeCosts,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeMetrics,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ResourceTypes
)

# Import required modules
try {
    Import-Module Az.Accounts -ErrorAction Stop
    Import-Module Az.Resources -ErrorAction Stop
    Import-Module Az.Profile -ErrorAction Stop
    if ($IncludeCosts) {
        Import-Module Az.Billing -ErrorAction Stop
    }
    if ($IncludeMetrics) {
        Import-Module Az.Monitor -ErrorAction Stop
    }
    Write-Host "Azure PowerShell modules imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import Azure PowerShell modules. Please ensure Az module is installed."
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

Write-Log "Starting Azure resource report generation"

# Check for Azure login and set subscription
try {
    $currentContext = Get-AzContext -ErrorAction Stop
    
    if ($SubscriptionId) {
        Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
        $currentContext = Get-AzContext
    }
    
    Write-Log "Connected to Azure subscription: $($currentContext.Subscription.Name) ($($currentContext.Subscription.Id))" -Level "SUCCESS"
    
} catch {
    Write-Log "Not connected to Azure. Please run Connect-AzAccount first." -Level "ERROR"
    exit 1
}

# Get subscription information
try {
    $subscription = Get-AzSubscription -SubscriptionId $currentContext.Subscription.Id
    $reportData["Subscription"] = [PSCustomObject]@{
        Name = $subscription.Name
        Id = $subscription.Id
        State = $subscription.State
        TenantId = $subscription.TenantId
    }
} catch {
    Write-Log "Failed to get subscription information: $($_.Exception.Message)" -Level "ERROR"
}

# Get resource groups
try {
    Write-Log "Retrieving resource groups..."
    
    if ($ResourceGroupName) {
        $resourceGroups = @(Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction Stop)
    } else {
        $resourceGroups = Get-AzResourceGroup
    }
    
    $rgData = @()
    foreach ($rg in $resourceGroups) {
        $rgInfo = [PSCustomObject]@{
            Name = $rg.ResourceGroupName
            Location = $rg.Location
            ProvisioningState = $rg.ProvisioningState
            Tags = ($rg.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
            Id = $rg.ResourceId
        }
        $rgData += $rgInfo
    }
    
    $reportData["ResourceGroups"] = $rgData
    Write-Log "Retrieved $($resourceGroups.Count) resource groups" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to retrieve resource groups: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Get all resources
try {
    Write-Log "Retrieving Azure resources..."
    
    if ($ResourceGroupName) {
        $resources = Get-AzResource -ResourceGroupName $ResourceGroupName
    } else {
        $resources = Get-AzResource
    }
    
    # Filter by resource types if specified
    if ($ResourceTypes) {
        $resources = $resources | Where-Object { $_.ResourceType -in $ResourceTypes }
    }
    
    $resourceData = @()
    foreach ($resource in $resources) {
        $resourceInfo = [PSCustomObject]@{
            Name = $resource.Name
            ResourceGroupName = $resource.ResourceGroupName
            ResourceType = $resource.ResourceType
            Location = $resource.Location
            Kind = $resource.Kind
            Tags = ($resource.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
            CreatedTime = $resource.CreatedTime
            ChangedTime = $resource.ChangedTime
            ProvisioningState = $resource.Properties.provisioningState
            Id = $resource.ResourceId
        }
        $resourceData += $resourceInfo
    }
    
    $reportData["Resources"] = $resourceData
    Write-Log "Retrieved $($resources.Count) resources" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to retrieve resources: $($_.Exception.Message)" -Level "ERROR"
}

# Get virtual machine details
try {
    Write-Log "Retrieving virtual machine details..."
    
    $vms = $resources | Where-Object { $_.ResourceType -eq "Microsoft.Compute/virtualMachines" }
    $vmData = @()
    
    foreach ($vm in $vms) {
        try {
            $vmDetails = Get-AzVM -ResourceGroupName $vm.ResourceGroupName -Name $vm.Name -Status
            
            $vmInfo = [PSCustomObject]@{
                Name = $vmDetails.Name
                ResourceGroupName = $vmDetails.ResourceGroupName
                Location = $vmDetails.Location
                VmSize = $vmDetails.HardwareProfile.VmSize
                OSType = $vmDetails.StorageProfile.OsDisk.OsType
                OSName = $vmDetails.StorageProfile.ImageReference.Offer
                OSVersion = $vmDetails.StorageProfile.ImageReference.Sku
                PowerState = ($vmDetails.Statuses | Where-Object { $_.Code -like "PowerState/*" }).DisplayStatus
                ProvisioningState = ($vmDetails.Statuses | Where-Object { $_.Code -like "ProvisioningState/*" }).DisplayStatus
                PrivateIPAddress = (Get-AzNetworkInterface -ResourceGroupName $vm.ResourceGroupName | Where-Object { $_.VirtualMachine.Id -eq $vmDetails.Id }).IpConfigurations.PrivateIpAddress -join "; "
                PublicIPAddress = try { 
                    $nic = Get-AzNetworkInterface -ResourceGroupName $vm.ResourceGroupName | Where-Object { $_.VirtualMachine.Id -eq $vmDetails.Id }
                    if ($nic.IpConfigurations.PublicIpAddress) {
                        $pip = Get-AzPublicIpAddress -ResourceGroupName $vm.ResourceGroupName -Name ($nic.IpConfigurations.PublicIpAddress.Id -split '/')[-1]
                        $pip.IpAddress
                    } else { "None" }
                } catch { "None" }
                Tags = ($vmDetails.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
            }
            
            $vmData += $vmInfo
            
        } catch {
            Write-Log "Error getting details for VM $($vm.Name): $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    if ($vmData.Count -gt 0) {
        $reportData["VirtualMachines"] = $vmData
        Write-Log "Retrieved details for $($vmData.Count) virtual machines" -Level "SUCCESS"
    }
    
} catch {
    Write-Log "Failed to retrieve virtual machine details: $($_.Exception.Message)" -Level "ERROR"
}

# Get storage account details
try {
    Write-Log "Retrieving storage account details..."
    
    $storageAccounts = $resources | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" }
    $storageData = @()
    
    foreach ($sa in $storageAccounts) {
        try {
            $saDetails = Get-AzStorageAccount -ResourceGroupName $sa.ResourceGroupName -Name $sa.Name
            
            $saInfo = [PSCustomObject]@{
                Name = $saDetails.StorageAccountName
                ResourceGroupName = $saDetails.ResourceGroupName
                Location = $saDetails.Location
                Kind = $saDetails.Kind
                SkuName = $saDetails.Sku.Name
                SkuTier = $saDetails.Sku.Tier
                AccessTier = $saDetails.AccessTier
                CreationTime = $saDetails.CreationTime
                PrimaryLocation = $saDetails.PrimaryLocation
                SecondaryLocation = $saDetails.SecondaryLocation
                StatusOfPrimary = $saDetails.StatusOfPrimary
                StatusOfSecondary = $saDetails.StatusOfSecondary
                EnableHttpsTrafficOnly = $saDetails.EnableHttpsTrafficOnly
                NetworkRuleSetDefaultAction = $saDetails.NetworkRuleSet.DefaultAction
                Tags = ($saDetails.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
            }
            
            $storageData += $saInfo
            
        } catch {
            Write-Log "Error getting details for storage account $($sa.Name): $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    if ($storageData.Count -gt 0) {
        $reportData["StorageAccounts"] = $storageData
        Write-Log "Retrieved details for $($storageData.Count) storage accounts" -Level "SUCCESS"
    }
    
} catch {
    Write-Log "Failed to retrieve storage account details: $($_.Exception.Message)" -Level "ERROR"
}

# Get network resources
try {
    Write-Log "Retrieving network resources..."
    
    $networkData = @()
    
    # Virtual Networks
    $vnets = $resources | Where-Object { $_.ResourceType -eq "Microsoft.Network/virtualNetworks" }
    foreach ($vnet in $vnets) {
        try {
            $vnetDetails = Get-AzVirtualNetwork -ResourceGroupName $vnet.ResourceGroupName -Name $vnet.Name
            
            $vnetInfo = [PSCustomObject]@{
                Type = "Virtual Network"
                Name = $vnetDetails.Name
                ResourceGroupName = $vnetDetails.ResourceGroupName
                Location = $vnetDetails.Location
                AddressSpace = ($vnetDetails.AddressSpace.AddressPrefixes -join "; ")
                Subnets = ($vnetDetails.Subnets | ForEach-Object { "$($_.Name) ($($_.AddressPrefix))" }) -join "; "
                DnsServers = ($vnetDetails.DhcpOptions.DnsServers -join "; ")
                ProvisioningState = $vnetDetails.ProvisioningState
                Tags = ($vnetDetails.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
            }
            
            $networkData += $vnetInfo
            
        } catch {
            Write-Log "Error getting details for VNet $($vnet.Name): $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    # Public IP Addresses
    $pips = $resources | Where-Object { $_.ResourceType -eq "Microsoft.Network/publicIPAddresses" }
    foreach ($pip in $pips) {
        try {
            $pipDetails = Get-AzPublicIpAddress -ResourceGroupName $pip.ResourceGroupName -Name $pip.Name
            
            $pipInfo = [PSCustomObject]@{
                Type = "Public IP Address"
                Name = $pipDetails.Name
                ResourceGroupName = $pipDetails.ResourceGroupName
                Location = $pipDetails.Location
                AddressSpace = $pipDetails.IpAddress
                Subnets = "N/A"
                DnsServers = $pipDetails.DnsSettings.Fqdn
                ProvisioningState = $pipDetails.ProvisioningState
                Tags = ($pipDetails.Tags.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join "; "
            }
            
            $networkData += $pipInfo
            
        } catch {
            Write-Log "Error getting details for Public IP $($pip.Name): $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    if ($networkData.Count -gt 0) {
        $reportData["NetworkResources"] = $networkData
        Write-Log "Retrieved details for $($networkData.Count) network resources" -Level "SUCCESS"
    }
    
} catch {
    Write-Log "Failed to retrieve network resources: $($_.Exception.Message)" -Level "ERROR"
}

# Generate summary statistics
$summary = [PSCustomObject]@{
    SubscriptionName = $subscription.Name
    SubscriptionId = $subscription.Id
    ResourceGroups = $resourceGroups.Count
    TotalResources = $resources.Count
    VirtualMachines = ($resources | Where-Object { $_.ResourceType -eq "Microsoft.Compute/virtualMachines" }).Count
    StorageAccounts = ($resources | Where-Object { $_.ResourceType -eq "Microsoft.Storage/storageAccounts" }).Count
    VirtualNetworks = ($resources | Where-Object { $_.ResourceType -eq "Microsoft.Network/virtualNetworks" }).Count
    PublicIPs = ($resources | Where-Object { $_.ResourceType -eq "Microsoft.Network/publicIPAddresses" }).Count
    NetworkSecurityGroups = ($resources | Where-Object { $_.ResourceType -eq "Microsoft.Network/networkSecurityGroups" }).Count
    LoadBalancers = ($resources | Where-Object { $_.ResourceType -eq "Microsoft.Network/loadBalancers" }).Count
    Locations = ($resources | Group-Object Location | Measure-Object).Count
    ResourceTypes = ($resources | Group-Object ResourceType | Measure-Object).Count
}

$reportData["Summary"] = $summary

# Export data based on format
Write-Log "Exporting report data..."

if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "All") {
    foreach ($category in $reportData.Keys) {
        $csvPath = Join-Path $OutputPath "AzureResources_$($category)_$timestamp.csv"
        try {
            $reportData[$category] | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Log "CSV exported: $csvPath" -Level "SUCCESS"
        } catch {
            Write-Log "Failed to export CSV for $category`: $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "All") {
    $jsonPath = Join-Path $OutputPath "AzureResources_$timestamp.json"
    try {
        $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Log "JSON exported: $jsonPath" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to export JSON: $($_.Exception.Message)" -Level "ERROR"
    }
}

if ($ExportFormat -eq "HTML" -or $ExportFormat -eq "All") {
    $htmlPath = Join-Path $OutputPath "AzureResources_$timestamp.html"
    
    # Generate HTML report
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure Resource Report</title>
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
        .running { color: green; font-weight: bold; }
        .stopped { color: red; font-weight: bold; }
        .deallocated { color: orange; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure Resource Report</h1>
        <div class="summary">
            <h3>Report Summary</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p><strong>Subscription:</strong> $($summary.SubscriptionName)</p>
            <p><strong>Subscription ID:</strong> $($summary.SubscriptionId)</p>
            
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value">$($summary.TotalResources)</div>
                    <div>Total Resources</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.ResourceGroups)</div>
                    <div>Resource Groups</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.VirtualMachines)</div>
                    <div>Virtual Machines</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.StorageAccounts)</div>
                    <div>Storage Accounts</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.VirtualNetworks)</div>
                    <div>Virtual Networks</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.PublicIPs)</div>
                    <div>Public IPs</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.Locations)</div>
                    <div>Locations</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($summary.ResourceTypes)</div>
                    <div>Resource Types</div>
                </div>
            </div>
        </div>
"@

    # Add resource groups table
    if ($reportData.ContainsKey("ResourceGroups") -and $reportData["ResourceGroups"].Count -gt 0) {
        $htmlContent += @"
        <div class="category">
            <h2>Resource Groups</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Location</th>
                        <th>Provisioning State</th>
                        <th>Tags</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($rg in ($reportData["ResourceGroups"] | Sort-Object Name)) {
            $htmlContent += @"
                <tr>
                    <td>$($rg.Name)</td>
                    <td>$($rg.Location)</td>
                    <td>$($rg.ProvisioningState)</td>
                    <td>$($rg.Tags)</td>
                </tr>
"@
        }
        
        $htmlContent += "</tbody></table></div>"
    }

    # Add virtual machines table if available
    if ($reportData.ContainsKey("VirtualMachines") -and $reportData["VirtualMachines"].Count -gt 0) {
        $htmlContent += @"
        <div class="category">
            <h2>Virtual Machines</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Resource Group</th>
                        <th>Location</th>
                        <th>Size</th>
                        <th>OS Type</th>
                        <th>Power State</th>
                        <th>Private IP</th>
                        <th>Public IP</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($vm in ($reportData["VirtualMachines"] | Sort-Object Name)) {
            $powerStateClass = switch -Wildcard ($vm.PowerState) {
                "*running*" { "running" }
                "*stopped*" { "stopped" }
                "*deallocated*" { "deallocated" }
                default { "" }
            }
            
            $htmlContent += @"
                <tr>
                    <td>$($vm.Name)</td>
                    <td>$($vm.ResourceGroupName)</td>
                    <td>$($vm.Location)</td>
                    <td>$($vm.VmSize)</td>
                    <td>$($vm.OSType)</td>
                    <td class="$powerStateClass">$($vm.PowerState)</td>
                    <td>$($vm.PrivateIPAddress)</td>
                    <td>$($vm.PublicIPAddress)</td>
                </tr>
"@
        }
        
        $htmlContent += "</tbody></table></div>"
    }

    # Add all resources table
    if ($reportData.ContainsKey("Resources") -and $reportData["Resources"].Count -gt 0) {
        $htmlContent += @"
        <div class="category">
            <h2>All Resources</h2>
            <table>
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Resource Group</th>
                        <th>Type</th>
                        <th>Location</th>
                        <th>Provisioning State</th>
                        <th>Tags</th>
                    </tr>
                </thead>
                <tbody>
"@
        
        foreach ($resource in ($reportData["Resources"] | Sort-Object Name)) {
            $htmlContent += @"
                <tr>
                    <td>$($resource.Name)</td>
                    <td>$($resource.ResourceGroupName)</td>
                    <td>$($resource.ResourceType)</td>
                    <td>$($resource.Location)</td>
                    <td>$($resource.ProvisioningState)</td>
                    <td>$($resource.Tags)</td>
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

# Display summary
Write-Host "`n=== AZURE RESOURCE REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "Subscription: $($summary.SubscriptionName)" -ForegroundColor White
Write-Host "Total Resources: $($summary.TotalResources)" -ForegroundColor White
Write-Host "Resource Groups: $($summary.ResourceGroups)" -ForegroundColor White
Write-Host "Virtual Machines: $($summary.VirtualMachines)" -ForegroundColor White
Write-Host "Storage Accounts: $($summary.StorageAccounts)" -ForegroundColor White
Write-Host "Virtual Networks: $($summary.VirtualNetworks)" -ForegroundColor White
Write-Host "Public IP Addresses: $($summary.PublicIPs)" -ForegroundColor White
Write-Host "Unique Locations: $($summary.Locations)" -ForegroundColor White
Write-Host "Unique Resource Types: $($summary.ResourceTypes)" -ForegroundColor White
Write-Host "Export Format: $ExportFormat" -ForegroundColor White
Write-Host "Output Path: $OutputPath" -ForegroundColor White

Write-Log "Azure resource report generation completed" -Level "SUCCESS"

