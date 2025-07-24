<#
.SYNOPSIS
    Manages Windows services (start, stop, restart, set startup type).

.DESCRIPTION
    This script provides a centralized way to control Windows services on local or remote computers.
    It can start, stop, restart services, and modify their startup type.

.PARAMETER ServiceName
    The name of the service to manage.

.PARAMETER Action
    The action to perform on the service: Start, Stop, Restart, SetStartupType.

.PARAMETER StartupType
    The startup type to set (for SetStartupType action): Automatic, Manual, Disabled.

.PARAMETER ComputerName
    The name of the computer where the service is located. Defaults to the local computer.

.EXAMPLE
    .\Manage-WindowsService.ps1 -ServiceName "Spooler" -Action Stop

.EXAMPLE
    .\Manage-WindowsService.ps1 -ServiceName "BITS" -Action SetStartupType -StartupType Disabled -ComputerName "DESKTOP01"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Run as Administrator on the target machine.
    - For remote execution, PowerShell Remoting must be enabled on the target.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ServiceName,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Start", "Stop", "Restart", "SetStartupType")]
    [string]$Action,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Automatic", "Manual", "Disabled")]
    [string]$StartupType,
    
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

Write-Host "Attempting to perform 
'$Action' on service 
'$ServiceName' on $ComputerName..." -ForegroundColor Cyan

try {
    # Get the service object
    $service = Get-Service -Name $ServiceName -ComputerName $ComputerName -ErrorAction Stop
    Write-Host "Service 
'$ServiceName' found. Current status: $($service.Status), Startup Type: $($service.StartType)" -ForegroundColor Green

    switch ($Action) {
        "Start" {
            if ($service.Status -ne "Running") {
                Start-Service -InputObject $service -ErrorAction Stop
                Write-Host "Service 
'$ServiceName' started successfully." -ForegroundColor Green
            } else {
                Write-Host "Service 
'$ServiceName' is already running." -ForegroundColor Yellow
            }
        }
        "Stop" {
            if ($service.Status -ne "Stopped") {
                Stop-Service -InputObject $service -ErrorAction Stop
                Write-Host "Service 
'$ServiceName' stopped successfully." -ForegroundColor Green
            } else {
                Write-Host "Service 
'$ServiceName' is already stopped." -ForegroundColor Yellow
            }
        }
        "Restart" {
            Restart-Service -InputObject $service -ErrorAction Stop
            Write-Host "Service 
'$ServiceName' restarted successfully." -ForegroundColor Green
        }
        "SetStartupType" {
            if (-not $StartupType) {
                throw "StartupType parameter is required for SetStartupType action."
            }
            Set-Service -InputObject $service -StartupType $StartupType -ErrorAction Stop
            Write-Host "Service 
'$ServiceName' startup type set to 
'$StartupType' successfully." -ForegroundColor Green
        }
        default {
            Write-Error "Invalid action specified: $Action"
        }
    }

} catch {
    Write-Error "Error managing service 
'$ServiceName' on $ComputerName: $($_.Exception.Message)"
    exit 1
}

Write-Host "Service management operation completed." -ForegroundColor Green

