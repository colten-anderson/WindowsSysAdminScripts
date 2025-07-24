<#
.SYNOPSIS
    Sends email reports with attachments using SMTP.

.DESCRIPTION
    This script provides a comprehensive way to send email reports with optional attachments,
    HTML formatting, and support for various SMTP configurations including authentication.

.PARAMETER SMTPServer
    SMTP server hostname or IP address.

.PARAMETER SMTPPort
    SMTP server port. Defaults to 587 for TLS, 25 for non-encrypted.

.PARAMETER From
    Email address of the sender.

.PARAMETER To
    Array of recipient email addresses.

.PARAMETER CC
    Array of CC recipient email addresses.

.PARAMETER BCC
    Array of BCC recipient email addresses.

.PARAMETER Subject
    Email subject line.

.PARAMETER Body
    Email body content. Can be plain text or HTML.

.PARAMETER BodyAsHTML
    Treat the body content as HTML.

.PARAMETER Attachments
    Array of file paths to attach to the email.

.PARAMETER Credential
    PSCredential object for SMTP authentication. If not provided, will prompt for credentials.

.PARAMETER UseSSL
    Use SSL/TLS encryption for SMTP connection.

.PARAMETER Priority
    Email priority: Low, Normal, or High. Defaults to Normal.

.PARAMETER LogPath
    Path where email logs will be saved. Defaults to the script directory.

.EXAMPLE
    .\Send-EmailReport.ps1 -SMTPServer "smtp.gmail.com" -From "admin@company.com" -To @("user@company.com") -Subject "Daily Report" -Body "Please find the daily report attached."

.EXAMPLE
    .\Send-EmailReport.ps1 -SMTPServer "mail.company.com" -SMTPPort 25 -From "reports@company.com" -To @("manager@company.com", "team@company.com") -Subject "Weekly Security Report" -Body $htmlBody -BodyAsHTML -Attachments @("C:\Reports\security.pdf", "C:\Reports\summary.xlsx") -Priority High

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - SMTP server access and credentials
    - Network connectivity to SMTP server
    - Valid email addresses
    - Attachment files must exist and be accessible
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SMTPServer,
    
    [Parameter(Mandatory=$false)]
    [int]$SMTPPort,
    
    [Parameter(Mandatory=$true)]
    [string]$From,
    
    [Parameter(Mandatory=$true)]
    [string[]]$To,
    
    [Parameter(Mandatory=$false)]
    [string[]]$CC,
    
    [Parameter(Mandatory=$false)]
    [string[]]$BCC,
    
    [Parameter(Mandatory=$true)]
    [string]$Subject,
    
    [Parameter(Mandatory=$true)]
    [string]$Body,
    
    [Parameter(Mandatory=$false)]
    [switch]$BodyAsHTML,
    
    [Parameter(Mandatory=$false)]
    [string[]]$Attachments,
    
    [Parameter(Mandatory=$false)]
    [System.Management.Automation.PSCredential]$Credential,
    
    [Parameter(Mandatory=$false)]
    [switch]$UseSSL,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Low", "Normal", "High")]
    [string]$Priority = "Normal",
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = $PSScriptRoot
)

# Initialize variables
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "EmailReport_$timestamp.log"

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $logEntry
    
    switch ($Level) {
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        default { Write-Host $logEntry -ForegroundColor White }
    }
}

Write-Log "Starting email report process" -Level "SUCCESS"
Write-Log "SMTP Server: $SMTPServer"
Write-Log "From: $From"
Write-Log "To: $($To -join '; ')"
Write-Log "Subject: $Subject"

# Set default SMTP port based on SSL usage
if (-not $SMTPPort) {
    $SMTPPort = if ($UseSSL) { 587 } else { 25 }
}

Write-Log "SMTP Port: $SMTPPort"
Write-Log "Use SSL: $UseSSL"

# Validate email addresses
function Test-EmailAddress {
    param([string]$EmailAddress)
    
    try {
        $null = [System.Net.Mail.MailAddress]$EmailAddress
        return $true
    } catch {
        return $false
    }
}

# Validate sender email
if (-not (Test-EmailAddress -EmailAddress $From)) {
    Write-Log "Invalid sender email address: $From" -Level "ERROR"
    exit 1
}

# Validate recipient emails
foreach ($recipient in $To) {
    if (-not (Test-EmailAddress -EmailAddress $recipient)) {
        Write-Log "Invalid recipient email address: $recipient" -Level "ERROR"
        exit 1
    }
}

# Validate CC emails
if ($CC) {
    foreach ($ccRecipient in $CC) {
        if (-not (Test-EmailAddress -EmailAddress $ccRecipient)) {
            Write-Log "Invalid CC email address: $ccRecipient" -Level "ERROR"
            exit 1
        }
    }
}

# Validate BCC emails
if ($BCC) {
    foreach ($bccRecipient in $BCC) {
        if (-not (Test-EmailAddress -EmailAddress $bccRecipient)) {
            Write-Log "Invalid BCC email address: $bccRecipient" -Level "ERROR"
            exit 1
        }
    }
}

# Validate attachments
$validAttachments = @()
if ($Attachments) {
    Write-Log "Validating attachments..."
    foreach ($attachment in $Attachments) {
        if (Test-Path $attachment) {
            $fileInfo = Get-Item $attachment
            $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
            Write-Log "Attachment found: $attachment ($fileSizeMB MB)"
            $validAttachments += $attachment
        } else {
            Write-Log "Attachment not found: $attachment" -Level "WARNING"
        }
    }
    
    if ($validAttachments.Count -eq 0 -and $Attachments.Count -gt 0) {
        Write-Log "No valid attachments found" -Level "WARNING"
    }
}

# Get credentials if not provided
if (-not $Credential) {
    try {
        Write-Host "SMTP authentication required. Please enter credentials:" -ForegroundColor Yellow
        $Credential = Get-Credential -Message "Enter SMTP server credentials"
        if (-not $Credential) {
            Write-Log "No credentials provided" -Level "ERROR"
            exit 1
        }
    } catch {
        Write-Log "Failed to get credentials: $($_.Exception.Message)" -Level "ERROR"
        exit 1
    }
}

# Test SMTP connectivity
Write-Log "Testing SMTP connectivity..."
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $connectResult = $tcpClient.BeginConnect($SMTPServer, $SMTPPort, $null, $null)
    $waitHandle = $connectResult.AsyncWaitHandle
    
    if ($waitHandle.WaitOne(5000, $false)) {
        if ($tcpClient.Connected) {
            Write-Log "SMTP connectivity test successful" -Level "SUCCESS"
            $tcpClient.Close()
        } else {
            Write-Log "SMTP connectivity test failed - cannot connect" -Level "ERROR"
            exit 1
        }
    } else {
        Write-Log "SMTP connectivity test timed out" -Level "ERROR"
        exit 1
    }
} catch {
    Write-Log "SMTP connectivity test error: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Create email message
try {
    Write-Log "Creating email message..."
    
    # Create mail message
    $mailMessage = New-Object System.Net.Mail.MailMessage
    $mailMessage.From = $From
    $mailMessage.Subject = $Subject
    $mailMessage.Body = $Body
    $mailMessage.IsBodyHtml = $BodyAsHTML
    
    # Set priority
    switch ($Priority) {
        "Low" { $mailMessage.Priority = [System.Net.Mail.MailPriority]::Low }
        "High" { $mailMessage.Priority = [System.Net.Mail.MailPriority]::High }
        default { $mailMessage.Priority = [System.Net.Mail.MailPriority]::Normal }
    }
    
    # Add recipients
    foreach ($recipient in $To) {
        $mailMessage.To.Add($recipient)
    }
    
    # Add CC recipients
    if ($CC) {
        foreach ($ccRecipient in $CC) {
            $mailMessage.CC.Add($ccRecipient)
        }
    }
    
    # Add BCC recipients
    if ($BCC) {
        foreach ($bccRecipient in $BCC) {
            $mailMessage.Bcc.Add($bccRecipient)
        }
    }
    
    # Add attachments
    foreach ($attachment in $validAttachments) {
        try {
            $attachmentObject = New-Object System.Net.Mail.Attachment($attachment)
            $mailMessage.Attachments.Add($attachmentObject)
            Write-Log "Added attachment: $(Split-Path $attachment -Leaf)"
        } catch {
            Write-Log "Failed to add attachment $attachment`: $($_.Exception.Message)" -Level "WARNING"
        }
    }
    
    Write-Log "Email message created successfully" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to create email message: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Create SMTP client and send email
try {
    Write-Log "Sending email..."
    
    # Create SMTP client
    $smtpClient = New-Object System.Net.Mail.SmtpClient($SMTPServer, $SMTPPort)
    $smtpClient.EnableSsl = $UseSSL
    $smtpClient.Credentials = $Credential.GetNetworkCredential()
    $smtpClient.Timeout = 30000  # 30 seconds
    
    # Send email
    $smtpClient.Send($mailMessage)
    
    Write-Log "Email sent successfully!" -Level "SUCCESS"
    
} catch {
    Write-Log "Failed to send email: $($_.Exception.Message)" -Level "ERROR"
    
    # Provide specific error guidance
    if ($_.Exception.Message -like "*authentication*") {
        Write-Log "Authentication failed. Check username and password." -Level "ERROR"
    } elseif ($_.Exception.Message -like "*timeout*") {
        Write-Log "Connection timed out. Check SMTP server and port." -Level "ERROR"
    } elseif ($_.Exception.Message -like "*SSL*" -or $_.Exception.Message -like "*TLS*") {
        Write-Log "SSL/TLS error. Check UseSSL parameter and server configuration." -Level "ERROR"
    }
    
    exit 1
    
} finally {
    # Clean up resources
    if ($mailMessage) {
        foreach ($attachment in $mailMessage.Attachments) {
            $attachment.Dispose()
        }
        $mailMessage.Dispose()
    }
    
    if ($smtpClient) {
        $smtpClient.Dispose()
    }
}

# Calculate email statistics
$totalAttachmentSize = 0
if ($validAttachments) {
    foreach ($attachment in $validAttachments) {
        $fileInfo = Get-Item $attachment
        $totalAttachmentSize += $fileInfo.Length
    }
}

$totalAttachmentSizeMB = [math]::Round($totalAttachmentSize / 1MB, 2)

# Log final statistics
Write-Log "Email delivery completed"
Write-Log "Recipients: $($To.Count + $(if ($CC) { $CC.Count } else { 0 }) + $(if ($BCC) { $BCC.Count } else { 0 }))"
Write-Log "Attachments: $($validAttachments.Count)"
Write-Log "Total attachment size: $totalAttachmentSizeMB MB"
Write-Log "Body format: $(if ($BodyAsHTML) { 'HTML' } else { 'Plain Text' })"
Write-Log "Priority: $Priority"

# Display summary
Write-Host "`n=== EMAIL REPORT SUMMARY ===" -ForegroundColor Cyan
Write-Host "SMTP Server: $SMTPServer`:$SMTPPort" -ForegroundColor White
Write-Host "From: $From" -ForegroundColor White
Write-Host "To: $($To -join '; ')" -ForegroundColor White
if ($CC) { Write-Host "CC: $($CC -join '; ')" -ForegroundColor White }
if ($BCC) { Write-Host "BCC: $($BCC.Count) recipients" -ForegroundColor White }
Write-Host "Subject: $Subject" -ForegroundColor White
Write-Host "Body Format: $(if ($BodyAsHTML) { 'HTML' } else { 'Plain Text' })" -ForegroundColor White
Write-Host "Priority: $Priority" -ForegroundColor White
Write-Host "Attachments: $($validAttachments.Count)" -ForegroundColor White
Write-Host "Total Attachment Size: $totalAttachmentSizeMB MB" -ForegroundColor White
Write-Host "SSL/TLS: $UseSSL" -ForegroundColor White
Write-Host "Log File: $logFile" -ForegroundColor White

Write-Host "`nEmail sent successfully!" -ForegroundColor Green

