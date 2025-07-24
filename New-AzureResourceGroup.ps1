<#
.SYNOPSIS
    Creates a new Azure Resource Group.

.DESCRIPTION
    This script automates the creation of an Azure Resource Group in a specified location.
    It checks for existing resource groups and provides clear output.

.PARAMETER ResourceGroupName
    The name of the Azure Resource Group to create.

.PARAMETER Location
    The Azure region where the resource group will be created (e.g., "eastus", "westeurope").

.EXAMPLE
    .\New-AzureResourceGroup.ps1 -ResourceGroupName "MyNewRG" -Location "eastus"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Az PowerShell module
    - Authenticated Azure session (Connect-AzAccount)
    - Appropriate permissions to create resource groups in Azure subscription
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$Location
)

# Import required modules
try {
    Import-Module Az.Resources -ErrorAction Stop
    Write-Host "Az.Resources module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import Az.Resources module. Please ensure Az module is installed and you are logged in to Azure."
    exit 1
}

# Check for Azure login
try {
    $currentContext = Get-AzContext -ErrorAction Stop
    Write-Host "Connected to Azure subscription: $($currentContext.Subscription.Name) ($($currentContext.Subscription.Id))" -ForegroundColor Green
} catch {
    Write-Error "Not connected to Azure. Please run Connect-AzAccount first."
    exit 1
}

Write-Host "Attempting to create Azure Resource Group 
'$ResourceGroupName' in location 
'$Location'..." -ForegroundColor Cyan

try {
    # Check if Resource Group already exists
    if (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue) {
        Write-Warning "Resource Group 
'$ResourceGroupName' already exists. Skipping creation."
        exit 0
    }

    # Create the Resource Group
    $newRG = New-AzResourceGroup -Name $ResourceGroupName -Location $Location -ErrorAction Stop
    
    Write-Host "Successfully created Resource Group 
'$($newRG.ResourceGroupName)' in location 
'$($newRG.Location)'." -ForegroundColor Green
    
    # Display details
    Write-Host "`n=== RESOURCE GROUP DETAILS ===" -ForegroundColor Cyan
    Write-Host "Name: $($newRG.ResourceGroupName)" -ForegroundColor White
    Write-Host "Location: $($newRG.Location)" -ForegroundColor White
    Write-Host "Provisioning State: $($newRG.ProvisioningState)" -ForegroundColor White
    Write-Host "Id: $($newRG.Id)" -ForegroundColor White

} catch {
    Write-Error "Error creating Resource Group 
'$ResourceGroupName': $($_.Exception.Message)"
    exit 1
}

Write-Host "Azure Resource Group creation process completed." -ForegroundColor Green

