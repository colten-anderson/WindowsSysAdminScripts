<#
.SYNOPSIS
    Intune Remediations script: clears safe-to-delete caches and temp files on the OS drive.

.DESCRIPTION
    Pairs with Detect-LowDiskSpace.ps1. Only removes data Windows regenerates or no longer
    needs:
      - Windows temp files older than 7 days
      - Each user profile's temp files older than 7 days
      - The Delivery Optimization cache
      - Queued Windows Error Reporting files

    Does not touch Downloads, the Recycle Bin, user documents, or the component store.
    Reports how much space was freed.

    Exit codes: 0 = ran (check output for space freed), 1 = unexpected failure.

.NOTES
    Author: Colten Anderson
    Provenance: AI-assisted draft. See the repository README for review and test status.
    Run as: SYSTEM, 64-bit PowerShell
    Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediate-LowDiskSpace.log
#>

$logFile    = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediate-LowDiskSpace.log'
$maxAgeDays = 7
$cutoff     = (Get-Date).AddDays(-$maxAgeDays)

# The IME log folder only exists on Intune-managed devices; create it so manual runs log too.
$logDir = Split-Path -Path $logFile -Parent
if (-not (Test-Path -LiteralPath $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

function Write-Log {
    param([string]$Message)
    $line = '{0:yyyy-MM-dd HH:mm:ss} {1}' -f (Get-Date), $Message
    Add-Content -Path $logFile -Value $line -ErrorAction SilentlyContinue
}

function Get-FreeGB {
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
    [math]::Round($disk.FreeSpace / 1GB, 2)
}

function Clear-OldTempItem {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt $cutoff } |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

try {
    $before = Get-FreeGB
    Write-Log "Starting cleanup. Free space: $before GB"

    Clear-OldTempItem -Path "$env:SystemRoot\Temp"
    Write-Log 'Cleaned Windows temp'

    $profiles = Get-CimInstance -ClassName Win32_UserProfile -Filter 'Special = False'
    foreach ($userProfile in $profiles) {
        Clear-OldTempItem -Path (Join-Path $userProfile.LocalPath 'AppData\Local\Temp')
    }
    Write-Log "Cleaned temp folders for $(@($profiles).Count) profile(s)"

    if (Get-Command -Name Delete-DeliveryOptimizationCache -ErrorAction SilentlyContinue) {
        Delete-DeliveryOptimizationCache -Force -ErrorAction SilentlyContinue *> $null
        Write-Log 'Cleared Delivery Optimization cache'
    }

    Clear-OldTempItem -Path "$env:ProgramData\Microsoft\Windows\WER\ReportQueue"
    Write-Log 'Cleaned Windows Error Reporting queue'

    $after = Get-FreeGB
    $freed = [math]::Round($after - $before, 2)
    Write-Log "Finished. Free space: $after GB (freed $freed GB)"
    Write-Output "Freed $freed GB. Free space now $after GB."
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output "Cleanup failed: $($_.Exception.Message)"
    exit 1
}
