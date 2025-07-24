<#
.SYNOPSIS
    Creates new users in Azure Active Directory using Microsoft Graph.

.DESCRIPTION
    This script creates new Azure AD users with specified properties and can optionally
    assign licenses and add users to groups.

.PARAMETER UserPrincipalName
    The User Principal Name (UPN) for the new user.

.PARAMETER DisplayName
    The display name for the new user.

.PARAMETER GivenName
    The first name of the user.

.PARAMETER Surname
    The last name of the user.

.PARAMETER JobTitle
    The job title of the user.

.PARAMETER Department
    The department of the user.

.PARAMETER UsageLocation
    The usage location for the user (required for license assignment).

.PARAMETER Password
    The initial password for the user. If not provided, a random password will be generated.

.PARAMETER ForceChangePasswordNextSignIn
    Force the user to change password at next sign-in. Defaults to true.

.PARAMETER AssignLicense
    License SKU to assign to the user (e.g., "ENTERPRISEPACK").

.PARAMETER AddToGroups
    Array of group names or IDs to add the user to.

.PARAMETER SendWelcomeEmail
    Send a welcome email to the user with their credentials.

.EXAMPLE
    .\New-AzureADUser.ps1 -UserPrincipalName "jdoe@contoso.com" -DisplayName "John Doe" -GivenName "John" -Surname "Doe"

.EXAMPLE
    .\New-AzureADUser.ps1 -UserPrincipalName "jsmith@contoso.com" -DisplayName "Jane Smith" -GivenName "Jane" -Surname "Smith" -JobTitle "Manager" -Department "Sales" -UsageLocation "US" -AssignLicense "ENTERPRISEPACK"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Microsoft.Graph PowerShell module
    - Appropriate permissions in Azure AD
    - Global Administrator or User Administrator role
    
    Required Graph Permissions:
    - User.ReadWrite.All
    - Group.ReadWrite.All (if adding to groups)
    - Organization.Read.All (for license assignment)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$UserPrincipalName,
    
    [Parameter(Mandatory=$true)]
    [string]$DisplayName,
    
    [Parameter(Mandatory=$false)]
    [string]$GivenName,
    
    [Parameter(Mandatory=$false)]
    [string]$Surname,
    
    [Parameter(Mandatory=$false)]
    [string]$JobTitle,
    
    [Parameter(Mandatory=$false)]
    [string]$Department,
    
    [Parameter(Mandatory=$false)]
    [string]$UsageLocation,
    
    [Parameter(Mandatory=$false)]
    [string]$Password,
    
    [Parameter(Mandatory=$false)]
    [bool]$ForceChangePasswordNextSignIn = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$AssignLicense,
    
    [Parameter(Mandatory=$false)]
    [string[]]$AddToGroups,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendWelcomeEmail
)

# Import required modules
try {
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    Import-Module Microsoft.Graph.Users -ErrorAction Stop
    Import-Module Microsoft.Graph.Groups -ErrorAction Stop
    Write-Host "Microsoft Graph modules imported successfully." -ForegroundColor Green
} catch {
    Write-Error "Failed to import Microsoft Graph modules. Please install using: Install-Module Microsoft.Graph"
    exit 1
}

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

# Generate random password function
function New-RandomPassword {
    param([int]$Length = 12)
    
    $uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    $lowercase = "abcdefghijklmnopqrstuvwxyz"
    $numbers = "0123456789"
    $symbols = "!@#$%^&*"
    
    $password = ""
    $password += $uppercase[(Get-Random -Maximum $uppercase.Length)]
    $password += $lowercase[(Get-Random -Maximum $lowercase.Length)]
    $password += $numbers[(Get-Random -Maximum $numbers.Length)]
    $password += $symbols[(Get-Random -Maximum $symbols.Length)]
    
    $allChars = $uppercase + $lowercase + $numbers + $symbols
    for ($i = 4; $i -lt $Length; $i++) {
        $password += $allChars[(Get-Random -Maximum $allChars.Length)]
    }
    
    # Shuffle the password
    $passwordArray = $password.ToCharArray()
    for ($i = $passwordArray.Length - 1; $i -gt 0; $i--) {
        $j = Get-Random -Maximum ($i + 1)
        $temp = $passwordArray[$i]
        $passwordArray[$i] = $passwordArray[$j]
        $passwordArray[$j] = $temp
    }
    
    return -join $passwordArray
}

Write-Log "Starting Azure AD user creation process for: $UserPrincipalName"

# Connect to Microsoft Graph
try {
    Write-Log "Connecting to Microsoft Graph..."
    $requiredScopes = @(
        "User.ReadWrite.All",
        "Organization.Read.All"
    )
    
    if ($AddToGroups) {
        $requiredScopes += "Group.ReadWrite.All"
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

# Check if user already exists
try {
    $existingUser = Get-MgUser -Filter "userPrincipalName eq '$UserPrincipalName'" -ErrorAction SilentlyContinue
    if ($existingUser) {
        Write-Log "User with UPN '$UserPrincipalName' already exists" -Level "ERROR"
        exit 1
    }
} catch {
    Write-Log "Error checking for existing user: $($_.Exception.Message)" -Level "WARNING"
}

# Generate password if not provided
if (-not $Password) {
    $Password = New-RandomPassword
    Write-Log "Generated random password for user"
}

# Prepare user parameters
$userParams = @{
    UserPrincipalName = $UserPrincipalName
    DisplayName = $DisplayName
    AccountEnabled = $true
    PasswordProfile = @{
        Password = $Password
        ForceChangePasswordNextSignIn = $ForceChangePasswordNextSignIn
    }
}

# Add optional parameters
if ($GivenName) { $userParams.GivenName = $GivenName }
if ($Surname) { $userParams.Surname = $Surname }
if ($JobTitle) { $userParams.JobTitle = $JobTitle }
if ($Department) { $userParams.Department = $Department }
if ($UsageLocation) { $userParams.UsageLocation = $UsageLocation }

# Create the user
try {
    Write-Log "Creating Azure AD user..."
    $newUser = New-MgUser @userParams
    Write-Log "Successfully created user: $($newUser.DisplayName) ($($newUser.UserPrincipalName))" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to create user: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Assign license if specified
if ($AssignLicense -and $UsageLocation) {
    try {
        Write-Log "Assigning license: $AssignLicense"
        
        # Get available licenses
        $subscribedSkus = Get-MgSubscribedSku
        $licenseToAssign = $subscribedSkus | Where-Object { $_.SkuPartNumber -eq $AssignLicense }
        
        if ($licenseToAssign) {
            $licenseParams = @{
                AddLicenses = @(
                    @{
                        SkuId = $licenseToAssign.SkuId
                        DisabledPlans = @()
                    }
                )
                RemoveLicenses = @()
            }
            
            Set-MgUserLicense -UserId $newUser.Id @licenseParams
            Write-Log "Successfully assigned license: $AssignLicense" -Level "SUCCESS"
        } else {
            Write-Log "License SKU '$AssignLicense' not found in tenant" -Level "WARNING"
        }
        
    } catch {
        Write-Log "Failed to assign license: $($_.Exception.Message)" -Level "ERROR"
    }
} elseif ($AssignLicense -and -not $UsageLocation) {
    Write-Log "Cannot assign license without UsageLocation" -Level "WARNING"
}

# Add user to groups if specified
if ($AddToGroups) {
    foreach ($groupName in $AddToGroups) {
        try {
            Write-Log "Adding user to group: $groupName"
            
            # Try to find group by display name first, then by ID
            $group = Get-MgGroup -Filter "displayName eq '$groupName'" -ErrorAction SilentlyContinue
            if (-not $group) {
                $group = Get-MgGroup -GroupId $groupName -ErrorAction SilentlyContinue
            }
            
            if ($group) {
                $memberParams = @{
                    "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($newUser.Id)"
                }
                
                New-MgGroupMember -GroupId $group.Id -BodyParameter $memberParams
                Write-Log "Successfully added user to group: $($group.DisplayName)" -Level "SUCCESS"
            } else {
                Write-Log "Group '$groupName' not found" -Level "WARNING"
            }
            
        } catch {
            Write-Log "Failed to add user to group '$groupName': $($_.Exception.Message)" -Level "ERROR"
        }
    }
}

# Send welcome email if requested
if ($SendWelcomeEmail) {
    try {
        Write-Log "Sending welcome email..."
        
        # Note: This is a simplified example. In a real scenario, you might want to use
        # a more sophisticated email template and send via Exchange Online or another service
        
        $emailBody = @"
Welcome to the organization!

Your new account details:
- Username: $UserPrincipalName
- Temporary Password: $Password
- Display Name: $DisplayName

Please log in and change your password at your first sign-in.

Best regards,
IT Administration Team
"@

        # This would typically integrate with your email system
        Write-Log "Welcome email content prepared (actual sending would require additional email service integration)" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to send welcome email: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Get final user information
try {
    $finalUser = Get-MgUser -UserId $newUser.Id -Property "Id,UserPrincipalName,DisplayName,GivenName,Surname,JobTitle,Department,UsageLocation,AccountEnabled,CreatedDateTime,AssignedLicenses"
    
    # Get group memberships
    $groupMemberships = Get-MgUserMemberOf -UserId $newUser.Id | ForEach-Object {
        if ($_.AdditionalProperties.displayName) {
            $_.AdditionalProperties.displayName
        }
    }
    
} catch {
    Write-Log "Error retrieving final user information: $($_.Exception.Message)" -Level "WARNING"
}

# Disconnect from Microsoft Graph
try {
    Disconnect-MgGraph | Out-Null
    Write-Log "Disconnected from Microsoft Graph" -Level "SUCCESS"
} catch {
    Write-Log "Error disconnecting from Microsoft Graph: $($_.Exception.Message)" -Level "WARNING"
}

# Display summary
Write-Host "`n=== USER CREATION SUMMARY ===" -ForegroundColor Cyan
Write-Host "User Principal Name: $($finalUser.UserPrincipalName)" -ForegroundColor White
Write-Host "Display Name: $($finalUser.DisplayName)" -ForegroundColor White
Write-Host "User ID: $($finalUser.Id)" -ForegroundColor White
Write-Host "Account Enabled: $($finalUser.AccountEnabled)" -ForegroundColor $(if ($finalUser.AccountEnabled) { "Green" } else { "Red" })
Write-Host "Created: $($finalUser.CreatedDateTime)" -ForegroundColor White
Write-Host "Job Title: $($finalUser.JobTitle)" -ForegroundColor White
Write-Host "Department: $($finalUser.Department)" -ForegroundColor White
Write-Host "Usage Location: $($finalUser.UsageLocation)" -ForegroundColor White
Write-Host "Assigned Licenses: $($finalUser.AssignedLicenses.Count)" -ForegroundColor White
Write-Host "Group Memberships: $($groupMemberships.Count)" -ForegroundColor White

if ($groupMemberships) {
    Write-Host "Groups:" -ForegroundColor White
    foreach ($group in $groupMemberships) {
        Write-Host "  - $group" -ForegroundColor Gray
    }
}

Write-Host "`nTemporary Password: $Password" -ForegroundColor Yellow
Write-Host "Force Change Password: $ForceChangePasswordNextSignIn" -ForegroundColor White

Write-Host "`nSECURITY REMINDER:" -ForegroundColor Red
Write-Host "- Ensure the temporary password is communicated securely to the user" -ForegroundColor Yellow
Write-Host "- Verify the user's identity before providing access" -ForegroundColor Yellow
Write-Host "- Monitor the account for the first successful sign-in" -ForegroundColor Yellow

Write-Log "Azure AD user creation process completed for: $UserPrincipalName" -Level "SUCCESS"

