<#
.SYNOPSIS
    Creates Active Directory users from a CSV file.

.DESCRIPTION
    This script reads user information from a CSV file and creates corresponding Active Directory user accounts.
    It includes error handling, logging, and validation to ensure reliable user creation.

.PARAMETER CSVPath
    Path to the CSV file containing user information.

.PARAMETER LogPath
    Path where the log file will be created. Defaults to the script directory.

.PARAMETER DefaultPassword
    Default password for new users. If not specified, a random password will be generated.

.PARAMETER DefaultOU
    Default Organizational Unit where users will be created. Defaults to "CN=Users,DC=domain,DC=com"

.EXAMPLE
    .\New-ADUserFromCSV.ps1 -CSVPath "C:\Users\NewUsers.csv"

.EXAMPLE
    .\New-ADUserFromCSV.ps1 -CSVPath "C:\Users\NewUsers.csv" -DefaultPassword "TempPass123!" -DefaultOU "OU=NewUsers,DC=contoso,DC=com"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    CSV Format Required:
    FirstName,LastName,Username,Email,Department,Title,Manager
    
    Prerequisites:
    - ActiveDirectory PowerShell module
    - Appropriate permissions to create users in AD
    - Run as Administrator
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$CSVPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = (Join-Path $PSScriptRoot "ADUserCreation.log"),
    
    [Parameter(Mandatory=$false)]
    [string]$DefaultPassword,
    
    [Parameter(Mandatory=$false)]
    [string]$DefaultOU
)

# Import required modules
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Host "ActiveDirectory module imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import ActiveDirectory module. Please ensure RSAT is installed."
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
    Add-Content -Path $LogPath -Value $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

# Generate random password function
function New-RandomPassword {
    param([int]$Length = 12)
    
    $chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
    $password = ""
    for ($i = 0; $i -lt $Length; $i++) {
        $password += $chars[(Get-Random -Maximum $chars.Length)]
    }
    return $password
}

# Get domain information
try {
    $domain = Get-ADDomain
    if (-not $DefaultOU) {
        $DefaultOU = $domain.UsersContainer
    }
    Write-Log "Domain: $($domain.DNSRoot), Default OU: $DefaultOU"
} catch {
    Write-Log "Failed to get domain information: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Read and validate CSV
try {
    $users = Import-Csv -Path $CSVPath
    Write-Log "Successfully imported $($users.Count) users from CSV file."
} catch {
    Write-Log "Failed to import CSV file: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Validate CSV headers
$requiredHeaders = @("FirstName", "LastName", "Username")
$csvHeaders = $users[0].PSObject.Properties.Name
$missingHeaders = $requiredHeaders | Where-Object { $_ -notin $csvHeaders }

if ($missingHeaders) {
    Write-Log "Missing required CSV headers: $($missingHeaders -join ', ')" -Level "ERROR"
    exit 1
}

# Initialize counters
$successCount = 0
$errorCount = 0
$skippedCount = 0

Write-Log "Starting user creation process..."

foreach ($user in $users) {
    try {
        # Validate required fields
        if (-not $user.FirstName -or -not $user.LastName -or -not $user.Username) {
            Write-Log "Skipping user due to missing required fields: $($user.Username)" -Level "WARNING"
            $skippedCount++
            continue
        }
        
        # Check if user already exists
        if (Get-ADUser -Filter "SamAccountName -eq '$($user.Username)'" -ErrorAction SilentlyContinue) {
            Write-Log "User $($user.Username) already exists. Skipping." -Level "WARNING"
            $skippedCount++
            continue
        }
        
        # Prepare user parameters
        $userParams = @{
            Name = "$($user.FirstName) $($user.LastName)"
            GivenName = $user.FirstName
            Surname = $user.LastName
            SamAccountName = $user.Username
            UserPrincipalName = if ($user.Email) { $user.Email } else { "$($user.Username)@$($domain.DNSRoot)" }
            Path = $DefaultOU
            Enabled = $true
            ChangePasswordAtLogon = $true
        }
        
        # Add optional fields if present
        if ($user.Email) { $userParams.EmailAddress = $user.Email }
        if ($user.Department) { $userParams.Department = $user.Department }
        if ($user.Title) { $userParams.Title = $user.Title }
        if ($user.Description) { $userParams.Description = $user.Description }
        
        # Set password
        if ($DefaultPassword) {
            $securePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force
        } else {
            $randomPassword = New-RandomPassword
            $securePassword = ConvertTo-SecureString $randomPassword -AsPlainText -Force
            Write-Log "Generated password for $($user.Username): $randomPassword" -Level "INFO"
        }
        $userParams.AccountPassword = $securePassword
        
        # Create the user
        New-ADUser @userParams
        Write-Log "Successfully created user: $($user.Username)" -Level "SUCCESS"
        
        # Set manager if specified
        if ($user.Manager) {
            try {
                $manager = Get-ADUser -Filter "SamAccountName -eq '$($user.Manager)'" -ErrorAction Stop
                Set-ADUser -Identity $user.Username -Manager $manager.DistinguishedName
                Write-Log "Set manager for $($user.Username): $($user.Manager)" -Level "SUCCESS"
            } catch {
                Write-Log "Failed to set manager for $($user.Username): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        $successCount++
        
    } catch {
        Write-Log "Failed to create user $($user.Username): $($_.Exception.Message)" -Level "ERROR"
        $errorCount++
    }
}

# Summary
Write-Log "User creation process completed."
Write-Log "Successfully created: $successCount users" -Level "SUCCESS"
Write-Log "Errors: $errorCount users" -Level "ERROR"
Write-Log "Skipped: $skippedCount users" -Level "WARNING"
Write-Log "Log file saved to: $LogPath"

# Display summary to console
Write-Host "`n=== SUMMARY ===" -ForegroundColor Cyan
Write-Host "Total users processed: $($users.Count)" -ForegroundColor White
Write-Host "Successfully created: $successCount" -ForegroundColor Green
Write-Host "Errors: $errorCount" -ForegroundColor Red
Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host "Log file: $LogPath" -ForegroundColor White

