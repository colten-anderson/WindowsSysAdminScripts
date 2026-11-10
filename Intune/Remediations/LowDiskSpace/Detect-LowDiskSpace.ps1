<#
.SYNOPSIS
    Intune Remediations detection script: flags devices whose OS drive is low on free space.

.DESCRIPTION
    Feature updates and monthly cumulative updates fail or stall on devices with little free
    space, and the failure often surfaces only as a stuck update ring report. This flags the
    device before that happens.

    Exit codes: 0 = enough free space, 1 = below threshold.

.NOTES
    Author: Colten Anderson
    Provenance: AI-assisted draft. See the repository README for review and test status.
    Run as: SYSTEM, 64-bit PowerShell
    Adjust $thresholdGB to match your fleet; 15 GB leaves room for a feature update.
#>

$thresholdGB = 15

$disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
$freeGB = [math]::Round($disk.FreeSpace / 1GB, 1)
$sizeGB = [math]::Round($disk.Size / 1GB, 1)

if ($freeGB -lt $thresholdGB) {
    Write-Output "Low disk space: $freeGB GB free of $sizeGB GB (threshold $thresholdGB GB)."
    exit 1
}

Write-Output "$freeGB GB free of $sizeGB GB."
exit 0
