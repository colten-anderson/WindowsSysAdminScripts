<#
.SYNOPSIS
    Backs up files and folders to a specified destination with logging and verification.

.DESCRIPTION
    This script provides a comprehensive file backup solution with options for incremental backups,
    compression, logging, and verification. It can backup individual files or entire directory structures.

.PARAMETER SourcePath
    The source path to backup (file or directory).

.PARAMETER DestinationPath
    The destination path where backups will be stored.

.PARAMETER BackupType
    Type of backup: Full, Incremental, or Differential. Defaults to Full.

.PARAMETER Compress
    Compress the backup using ZIP compression.

.PARAMETER IncludeSubdirectories
    Include subdirectories in the backup (for directory backups).

.PARAMETER ExcludeExtensions
    Array of file extensions to exclude from backup (e.g., @(".tmp", ".log")).

.PARAMETER ExcludeFolders
    Array of folder names to exclude from backup (e.g., @("temp", "cache")).

.PARAMETER RetentionDays
    Number of days to retain old backups. Older backups will be deleted. Defaults to 30 days.

.PARAMETER LogPath
    Path where backup logs will be saved. Defaults to the script directory.

.PARAMETER VerifyBackup
    Verify the backup by comparing file sizes and checksums.

.EXAMPLE
    .\Backup-Files.ps1 -SourcePath "C:\Important" -DestinationPath "D:\Backups"

.EXAMPLE
    .\Backup-Files.ps1 -SourcePath "C:\Data" -DestinationPath "\\server\backups" -BackupType "Incremental" -Compress -VerifyBackup

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Sufficient disk space at destination
    - Write permissions to destination path
    - Read permissions to source path
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SourcePath,
    
    [Parameter(Mandatory=$true)]
    [string]$DestinationPath,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Full", "Incremental", "Differential")]
    [string]$BackupType = "Full",
    
    [Parameter(Mandatory=$false)]
    [switch]$Compress,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeSubdirectories = $true,
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeExtensions = @(),
    
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeFolders = @(),
    
    [Parameter(Mandatory=$false)]
    [int]$RetentionDays = 30,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = $PSScriptRoot,
    
    [Parameter(Mandatory=$false)]
    [switch]$VerifyBackup
)

# Initialize variables
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "Backup_$timestamp.log"
$backupStats = @{
    FilesProcessed = 0
    FilesBackedUp = 0
    FilesSkipped = 0
    TotalSize = 0
    Errors = 0
    StartTime = Get-Date
    EndTime = $null
}

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

# Function to get file hash
function Get-FileChecksum {
    param([string]$FilePath)
    try {
        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256
        return $hash.Hash
    } catch {
        return $null
    }
}

# Function to check if file should be excluded
function Test-ExcludeFile {
    param(
        [string]$FilePath,
        [string[]]$ExcludeExt,
        [string[]]$ExcludeFolders
    )
    
    # Check file extension
    $extension = [System.IO.Path]::GetExtension($FilePath)
    if ($ExcludeExt -contains $extension) {
        return $true
    }
    
    # Check folder names in path
    $pathParts = $FilePath.Split([System.IO.Path]::DirectorySeparatorChar)
    foreach ($folder in $ExcludeFolders) {
        if ($pathParts -contains $folder) {
            return $true
        }
    }
    
    return $false
}

Write-Log "Starting backup process" -Level "SUCCESS"
Write-Log "Source: $SourcePath"
Write-Log "Destination: $DestinationPath"
Write-Log "Backup Type: $BackupType"
Write-Log "Compression: $Compress"

# Validate source path
if (-not (Test-Path $SourcePath)) {
    Write-Log "Source path does not exist: $SourcePath" -Level "ERROR"
    exit 1
}

# Create destination directory if it doesn't exist
if (-not (Test-Path $DestinationPath)) {
    try {
        New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
        Write-Log "Created destination directory: $DestinationPath" -Level "SUCCESS"
    } catch {
        Write-Log "Failed to create destination directory: $($_.Exception.Message)" -Level "ERROR"
        exit 1
    }
}

# Determine backup destination folder
$backupFolderName = "Backup_$timestamp"
if ($BackupType -ne "Full") {
    $backupFolderName = "$($BackupType)_$timestamp"
}

$backupDestination = Join-Path $DestinationPath $backupFolderName

# Create backup destination
try {
    New-Item -Path $backupDestination -ItemType Directory -Force | Out-Null
    Write-Log "Created backup destination: $backupDestination" -Level "SUCCESS"
} catch {
    Write-Log "Failed to create backup destination: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}

# Get reference date for incremental/differential backups
$referenceDate = $null
if ($BackupType -eq "Incremental" -or $BackupType -eq "Differential") {
    # Find the most recent backup
    $existingBackups = Get-ChildItem -Path $DestinationPath -Directory | 
                     Where-Object { $_.Name -match "^(Full_|Incremental_|Differential_|Backup_)\d{8}_\d{6}$" } |
                     Sort-Object CreationTime -Descending
    
    if ($existingBackups) {
        if ($BackupType -eq "Incremental") {
            $referenceDate = $existingBackups[0].CreationTime
        } else {
            # Differential - find last full backup
            $lastFullBackup = $existingBackups | Where-Object { $_.Name -match "^(Full_|Backup_)" } | Select-Object -First 1
            if ($lastFullBackup) {
                $referenceDate = $lastFullBackup.CreationTime
            }
        }
        
        if ($referenceDate) {
            Write-Log "Reference date for $BackupType backup: $referenceDate"
        } else {
            Write-Log "No reference backup found, performing full backup instead" -Level "WARNING"
            $BackupType = "Full"
        }
    } else {
        Write-Log "No existing backups found, performing full backup instead" -Level "WARNING"
        $BackupType = "Full"
    }
}

# Get files to backup
Write-Log "Scanning source files..."
$filesToBackup = @()

if (Test-Path $SourcePath -PathType Leaf) {
    # Single file
    $file = Get-Item $SourcePath
    if (-not (Test-ExcludeFile -FilePath $file.FullName -ExcludeExt $ExcludeExtensions -ExcludeFolders $ExcludeFolders)) {
        if ($referenceDate -eq $null -or $file.LastWriteTime -gt $referenceDate) {
            $filesToBackup += $file
        }
    }
} else {
    # Directory
    $searchParams = @{
        Path = $SourcePath
        File = $true
    }
    
    if ($IncludeSubdirectories) {
        $searchParams.Recurse = $true
    }
    
    $allFiles = Get-ChildItem @searchParams
    
    foreach ($file in $allFiles) {
        $backupStats.FilesProcessed++
        
        # Check exclusions
        if (Test-ExcludeFile -FilePath $file.FullName -ExcludeExt $ExcludeExtensions -ExcludeFolders $ExcludeFolders) {
            $backupStats.FilesSkipped++
            continue
        }
        
        # Check date for incremental/differential
        if ($referenceDate -ne $null -and $file.LastWriteTime -le $referenceDate) {
            $backupStats.FilesSkipped++
            continue
        }
        
        $filesToBackup += $file
    }
}

Write-Log "Found $($filesToBackup.Count) files to backup"

# Perform backup
$backupManifest = @()

foreach ($file in $filesToBackup) {
    try {
        # Calculate relative path
        $relativePath = $file.FullName.Substring($SourcePath.Length).TrimStart('\', '/')
        $destinationFile = Join-Path $backupDestination $relativePath
        
        # Create destination directory if needed
        $destinationDir = Split-Path $destinationFile -Parent
        if (-not (Test-Path $destinationDir)) {
            New-Item -Path $destinationDir -ItemType Directory -Force | Out-Null
        }
        
        # Copy file
        Copy-Item -Path $file.FullName -Destination $destinationFile -Force
        
        # Add to manifest
        $fileInfo = [PSCustomObject]@{
            SourcePath = $file.FullName
            DestinationPath = $destinationFile
            Size = $file.Length
            LastWriteTime = $file.LastWriteTime
            Checksum = if ($VerifyBackup) { Get-FileChecksum -FilePath $file.FullName } else { $null }
        }
        $backupManifest += $fileInfo
        
        $backupStats.FilesBackedUp++
        $backupStats.TotalSize += $file.Length
        
        if ($backupStats.FilesBackedUp % 100 -eq 0) {
            Write-Log "Backed up $($backupStats.FilesBackedUp) files..."
        }
        
    } catch {
        Write-Log "Failed to backup file $($file.FullName): $($_.Exception.Message)" -Level "ERROR"
        $backupStats.Errors++
    }
}

# Save backup manifest
$manifestPath = Join-Path $backupDestination "backup_manifest.json"
try {
    $backupManifest | ConvertTo-Json -Depth 10 | Out-File -FilePath $manifestPath -Encoding UTF8
    Write-Log "Backup manifest saved: $manifestPath" -Level "SUCCESS"
} catch {
    Write-Log "Failed to save backup manifest: $($_.Exception.Message)" -Level "WARNING"
}

# Compress backup if requested
if ($Compress) {
    try {
        Write-Log "Compressing backup..."
        $zipPath = "$backupDestination.zip"
        Compress-Archive -Path $backupDestination -DestinationPath $zipPath -Force
        
        # Remove uncompressed backup
        Remove-Item -Path $backupDestination -Recurse -Force
        Write-Log "Backup compressed to: $zipPath" -Level "SUCCESS"
        $backupDestination = $zipPath
        
    } catch {
        Write-Log "Failed to compress backup: $($_.Exception.Message)" -Level "ERROR"
    }
}

# Verify backup if requested
if ($VerifyBackup -and -not $Compress) {
    Write-Log "Verifying backup..."
    $verificationErrors = 0
    
    foreach ($fileInfo in $backupManifest) {
        try {
            if (Test-Path $fileInfo.DestinationPath) {
                $destFile = Get-Item $fileInfo.DestinationPath
                
                # Check file size
                if ($destFile.Length -ne $fileInfo.Size) {
                    Write-Log "Size mismatch for $($fileInfo.SourcePath)" -Level "ERROR"
                    $verificationErrors++
                    continue
                }
                
                # Check checksum if available
                if ($fileInfo.Checksum) {
                    $destChecksum = Get-FileChecksum -FilePath $fileInfo.DestinationPath
                    if ($destChecksum -ne $fileInfo.Checksum) {
                        Write-Log "Checksum mismatch for $($fileInfo.SourcePath)" -Level "ERROR"
                        $verificationErrors++
                    }
                }
            } else {
                Write-Log "Backup file not found: $($fileInfo.DestinationPath)" -Level "ERROR"
                $verificationErrors++
            }
        } catch {
            Write-Log "Verification error for $($fileInfo.SourcePath): $($_.Exception.Message)" -Level "ERROR"
            $verificationErrors++
        }
    }
    
    if ($verificationErrors -eq 0) {
        Write-Log "Backup verification completed successfully" -Level "SUCCESS"
    } else {
        Write-Log "Backup verification completed with $verificationErrors errors" -Level "ERROR"
    }
}

# Clean up old backups based on retention policy
if ($RetentionDays -gt 0) {
    try {
        Write-Log "Cleaning up old backups (retention: $RetentionDays days)..."
        $cutoffDate = (Get-Date).AddDays(-$RetentionDays)
        
        $oldBackups = Get-ChildItem -Path $DestinationPath | 
                     Where-Object { 
                         ($_.Name -match "^(Full_|Incremental_|Differential_|Backup_)\d{8}_\d{6}") -and 
                         $_.CreationTime -lt $cutoffDate 
                     }
        
        foreach ($oldBackup in $oldBackups) {
            try {
                if ($oldBackup.Extension -eq ".zip") {
                    Remove-Item -Path $oldBackup.FullName -Force
                } else {
                    Remove-Item -Path $oldBackup.FullName -Recurse -Force
                }
                Write-Log "Removed old backup: $($oldBackup.Name)"
            } catch {
                Write-Log "Failed to remove old backup $($oldBackup.Name): $($_.Exception.Message)" -Level "WARNING"
            }
        }
        
        Write-Log "Cleaned up $($oldBackups.Count) old backups" -Level "SUCCESS"
        
    } catch {
        Write-Log "Failed to clean up old backups: $($_.Exception.Message)" -Level "WARNING"
    }
}

# Calculate final statistics
$backupStats.EndTime = Get-Date
$duration = $backupStats.EndTime - $backupStats.StartTime
$totalSizeMB = [math]::Round($backupStats.TotalSize / 1MB, 2)

# Log final statistics
Write-Log "Backup completed" -Level "SUCCESS"
Write-Log "Files processed: $($backupStats.FilesProcessed)"
Write-Log "Files backed up: $($backupStats.FilesBackedUp)"
Write-Log "Files skipped: $($backupStats.FilesSkipped)"
Write-Log "Total size: $totalSizeMB MB"
Write-Log "Errors: $($backupStats.Errors)"
Write-Log "Duration: $($duration.ToString('hh\:mm\:ss'))"
Write-Log "Backup location: $backupDestination"

# Display summary
Write-Host "`n=== BACKUP SUMMARY ===" -ForegroundColor Cyan
Write-Host "Source: $SourcePath" -ForegroundColor White
Write-Host "Destination: $backupDestination" -ForegroundColor White
Write-Host "Backup Type: $BackupType" -ForegroundColor White
Write-Host "Files Backed Up: $($backupStats.FilesBackedUp)" -ForegroundColor Green
Write-Host "Files Skipped: $($backupStats.FilesSkipped)" -ForegroundColor Yellow
Write-Host "Total Size: $totalSizeMB MB" -ForegroundColor White
Write-Host "Errors: $($backupStats.Errors)" -ForegroundColor $(if ($backupStats.Errors -gt 0) { "Red" } else { "Green" })
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor White
Write-Host "Compressed: $Compress" -ForegroundColor White
Write-Host "Verified: $VerifyBackup" -ForegroundColor White
Write-Host "Log File: $logFile" -ForegroundColor White

if ($backupStats.Errors -eq 0) {
    Write-Host "`nBackup completed successfully!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`nBackup completed with errors. Check log file for details." -ForegroundColor Yellow
    exit 1
}

