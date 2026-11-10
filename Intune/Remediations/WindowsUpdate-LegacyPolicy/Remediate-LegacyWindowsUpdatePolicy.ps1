<#
.SYNOPSIS
    Intune Remediations script: removes leftover WSUS / Group Policy Windows Update values so
    Windows Update for Business policies can take effect.

.DESCRIPTION
    Pairs with Detect-LegacyWindowsUpdatePolicy.ps1. Removes only the specific values that
    redirect or block Windows Update; the rest of the policy key is left alone. Restarts the
    Windows Update service so the change is picked up without a reboot.

    If a domain GPO still delivers these settings, they will come back at the next Group
    Policy refresh. Fix the GPO (or the device's OU) first; this script cleans up tattooed
    values left behind after the GPO is gone.

    Exit codes: 0 = success, 1 = one or more values could not be removed.

.NOTES
    Author: Colten Anderson
    Provenance: AI-assisted draft. See the repository README for review and test status.
    Run as: SYSTEM, 64-bit PowerShell
    Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediate-LegacyWindowsUpdatePolicy.log
#>

$logFile    = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediate-LegacyWindowsUpdatePolicy.log'
$policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$auKey      = Join-Path $policyRoot 'AU'
$failed     = $false
$removed    = @()

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

$targets = @(
    @{ Path = $policyRoot; Name = 'WUServer' },
    @{ Path = $policyRoot; Name = 'WUStatusServer' },
    @{ Path = $policyRoot; Name = 'UpdateServiceUrlAlternate' },
    @{ Path = $policyRoot; Name = 'DoNotConnectToWindowsUpdateInternetLocations' },
    @{ Path = $policyRoot; Name = 'DisableWindowsUpdateAccess' },
    @{ Path = $auKey;      Name = 'UseWUServer' },
    @{ Path = $auKey;      Name = 'NoAutoUpdate' }
)

Write-Log 'Starting legacy Windows Update policy cleanup'

foreach ($target in $targets) {
    $exists = Get-ItemProperty -Path $target.Path -Name $target.Name -ErrorAction SilentlyContinue
    if (-not $exists) { continue }
    try {
        Remove-ItemProperty -Path $target.Path -Name $target.Name -ErrorAction Stop
        Write-Log "Removed $($target.Path)\$($target.Name)"
        $removed += $target.Name
    } catch {
        Write-Log "ERROR removing $($target.Path)\$($target.Name): $($_.Exception.Message)"
        $failed = $true
    }
}

if ($removed) {
    try {
        Restart-Service -Name 'wuauserv' -Force -ErrorAction Stop
        Write-Log 'Restarted Windows Update service'
    } catch {
        # Not fatal: the change is still picked up at the next service start or reboot.
        Write-Log "WARNING: could not restart wuauserv: $($_.Exception.Message)"
    }
}

if ($failed) {
    Write-Output "Partial cleanup. Removed: $($removed -join ', '). See $logFile"
    exit 1
}

Write-Output "Removed legacy values: $(if ($removed) { $removed -join ', ' } else { 'none' })"
exit 0
