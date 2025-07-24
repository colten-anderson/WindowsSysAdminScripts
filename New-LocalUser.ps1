<#
.SYNOPSIS
    Creates a new local user account on a Windows desktop.

.DESCRIPTION
    This script automates the creation of a new local user account, sets a password,
    and optionally adds the user to local groups.

.PARAMETER Username
    The username for the new local account.

.PARAMETER Password
    The password for the new local account. If not provided, a random password will be generated.

.PARAMETER FullName
    The full name for the new local account.

.PARAMETER Description
    A description for the new local account.

.PARAMETER AddToGroup
    A local group to add the new user to (e.g., "Administrators", "Users").

.PARAMETER ComputerName
    The name of the computer to create the user on. This script currently
    supports only the local computer due to limitations of the LocalAccounts
    module. The parameter is retained for compatibility but must reference the
    local machine.

.EXAMPLE
    .\New-LocalUser.ps1 -Username "jdoe" -Password "SecurePass123!" -FullName "John Doe"

.EXAMPLE
    .\New-LocalUser.ps1 -Username "adminuser" -AddToGroup "Administrators" -ComputerName "DESKTOP01"

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
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [string]$FullName,
    
    [Parameter(Mandatory=$false)]
    [string]$Description,
    
    [Parameter(Mandatory=$false)]
    [string]$AddToGroup,
    
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

# Function to generate a random password
function New-RandomPassword {
    param([int]$Length = 12)
    
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $password = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $password
}

Write-Host "Attempting to create local user '$Username' on $ComputerName..." -ForegroundColor Cyan

# LocalAccounts cmdlets do not support remote computer names. Exit if a remote
# computer is specified.
if ($ComputerName -ne $env:COMPUTERNAME -and $ComputerName -ne 'localhost') {
    Write-Warning "Remote computer management is not supported. Run this script locally on $ComputerName."
    exit 1
}

try {
    # Check if user already exists
    if (Get-LocalUser -Name $Username -ErrorAction SilentlyContinue) {
        Write-Warning "Local user '$Username' already exists on $ComputerName. Skipping creation."
        exit 0
    }

    # Generate password if not provided
    $userPassword = if ($Password) {
        $Password
    } else {
        $randomPass = New-RandomPassword
        Write-Host "Generated random password for $Username: $randomPass" -ForegroundColor Yellow
        $randomPass
    }

    # Create new local user
    $userParams = @{
        Name = $Username
        Password = (ConvertTo-SecureString $userPassword -AsPlainText -Force)
        FullName = $FullName
        Description = $Description
        AccountExpires = (Get-Date).AddYears(100) # Set a far future expiry
        PasswordNeverExpires = $true
    }
    
    New-LocalUser @userParams -ErrorAction Stop
    Write-Host "Successfully created local user $Username on $ComputerName." -ForegroundColor Green

    # Add to group if specified
    if ($AddToGroup) {
        try {
            Add-LocalGroupMember -Group $AddToGroup -Member $Username -ErrorAction Stop
            Write-Host "Successfully added $Username to local group $AddToGroup on $ComputerName." -ForegroundColor Green
        } catch {
            Write-Warning "Failed to add $Username to group $AddToGroup on $ComputerName: $($_.Exception.Message)"
        }
    }

} catch {
    Write-Error "Error creating local user $Username on $ComputerName: $($_.Exception.Message)"
    exit 1
}

Write-Host "Local user creation process completed." -ForegroundColor Green

