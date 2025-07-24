<#
.SYNOPSIS
    Resets Active Directory user passwords with logging and notification options.

.DESCRIPTION
    This script provides a secure way to reset Active Directory user passwords with options for
    random password generation, email notifications, and comprehensive logging.

.PARAMETER Username
    The username (SamAccountName) of the user whose password needs to be reset.

.PARAMETER NewPassword
    The new password for the user. If not specified, a random password will be generated.

.PARAMETER SendEmail
    Send email notification to the user with their new password.

.PARAMETER SMTPServer
    SMTP server for sending email notifications.

.PARAMETER FromEmail
    Email address to send notifications from.

.PARAMETER ForceChangeAtLogon
    Force the user to change password at next logon. Defaults to true.

.PARAMETER LogPath
    Path where the log file will be created. Defaults to the script directory.

.EXAMPLE
    .\Reset-ADUserPassword.ps1 -Username "jdoe"

.EXAMPLE
    .\Reset-ADUserPassword.ps1 -Username "jdoe" -NewPassword "TempPass123!" -SendEmail -SMTPServer "mail.contoso.com" -FromEmail "admin@contoso.com"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - ActiveDirectory PowerShell module
    - Appropriate permissions to reset passwords in AD
    - SMTP server access for email notifications (if using SendEmail)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username,
    
    [Parameter(Mandatory=$false)]
    [string]$NewPassword,
    
    [Parameter(Mandatory=$false)]
    [switch]$SendEmail,
    
    [Parameter(Mandatory=$false)]
    [string]$SMTPServer,
    
    [Parameter(Mandatory=$false)]
    [string]$FromEmail,
    
    [Parameter(Mandatory=$false)]
    [bool]$ForceChangeAtLogon = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = (Join-Path $PSScriptRoot "PasswordReset.log")
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
    
    # Ensure password meets complexity requirements
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

# Send email notification function
function Send-PasswordNotification {
    param(
        [string]$ToEmail,
        [string]$Username,
        [string]$Password,
        [string]$SMTPServer,
        [string]$FromEmail
    )
    
    try {
        $subject = "Password Reset Notification - $Username"
        $body = @"
Dear User,

Your password has been reset for the account: $Username

New Password: $Password

Please log in and change your password immediately for security purposes.

This is an automated message. Please do not reply to this email.

Best regards,
IT Administration Team
"@

        Send-MailMessage -To $ToEmail -From $FromEmail -Subject $subject -Body $body -SmtpServer $SMTPServer
        Write-Log "Email notification sent to $ToEmail" -Level "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to send email notification: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

Write-Log "Starting password reset process for user: $Username"

# Verify user exists
try {
    $user = Get-ADUser -Identity $Username -Properties EmailAddress, DisplayName -ErrorAction Stop
    Write-Log "User found: $($user.DisplayName) ($($user.SamAccountName))" -Level "SUCCESS"
} catch {
    Write-Log "User $Username not found in Active Directory: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Generate password if not provided
if (-not $NewPassword) {
    $NewPassword = New-RandomPassword
    Write-Log "Generated random password for user $Username"
}

# Validate password complexity (basic check)
if ($NewPassword.Length -lt 8) {
    Write-Log "Password does not meet minimum length requirement (8 characters)" -Level "ERROR"
    exit 1
}

# Reset the password
try {
    $securePassword = ConvertTo-SecureString $NewPassword -AsPlainText -Force
    Set-ADAccountPassword -Identity $Username -NewPassword $securePassword -Reset
    Write-Log "Password successfully reset for user $Username" -Level "SUCCESS"
    
    # Set password change at logon if specified
    if ($ForceChangeAtLogon) {
        Set-ADUser -Identity $Username -ChangePasswordAtLogon $true
        Write-Log "User $Username will be required to change password at next logon" -Level "SUCCESS"
    }
    
    # Unlock account if it's locked
    $userAccount = Get-ADUser -Identity $Username -Properties LockedOut
    if ($userAccount.LockedOut) {
        Unlock-ADAccount -Identity $Username
        Write-Log "Account $Username has been unlocked" -Level "SUCCESS"
    }
    
} catch {
    Write-Log "Failed to reset password for user $Username: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Send email notification if requested
if ($SendEmail) {
    if (-not $SMTPServer -or -not $FromEmail) {
        Write-Log "Email notification requested but SMTP server or from email not specified" -Level "WARNING"
    } elseif (-not $user.EmailAddress) {
        Write-Log "Email notification requested but user $Username has no email address in AD" -Level "WARNING"
    } else {
        Send-PasswordNotification -ToEmail $user.EmailAddress -Username $Username -Password $NewPassword -SMTPServer $SMTPServer -FromEmail $FromEmail
    }
}

# Display results
Write-Host "`n=== PASSWORD RESET SUMMARY ===" -ForegroundColor Cyan
Write-Host "User: $($user.DisplayName) ($Username)" -ForegroundColor White
Write-Host "New Password: $NewPassword" -ForegroundColor Yellow
Write-Host "Change at Logon: $ForceChangeAtLogon" -ForegroundColor White
Write-Host "Email Sent: $(if ($SendEmail -and $user.EmailAddress -and $SMTPServer -and $FromEmail) { 'Yes' } else { 'No' })" -ForegroundColor White
Write-Host "Log File: $LogPath" -ForegroundColor White

Write-Log "Password reset process completed for user $Username" -Level "SUCCESS"

# Security reminder
Write-Host "`nSECURITY REMINDER:" -ForegroundColor Red
Write-Host "- Ensure the new password is communicated securely to the user" -ForegroundColor Yellow
Write-Host "- Verify the user's identity before providing the new password" -ForegroundColor Yellow
Write-Host "- Consider using a secure password delivery method" -ForegroundColor Yellow

