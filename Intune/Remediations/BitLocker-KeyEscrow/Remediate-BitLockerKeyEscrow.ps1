<#
.SYNOPSIS
    Intune Remediations script: backs up the OS drive's BitLocker recovery password to
    Microsoft Entra ID, adding a recovery password protector first if none exists.

.DESCRIPTION
    Pairs with Detect-BitLockerKeyEscrow.ps1. Does not turn on encryption; that stays with the
    Intune disk encryption policy. Requires the device to be Entra ID joined or hybrid joined.

    Exit codes: 0 = backup succeeded, 1 = failure (see log).

.NOTES
    Author: Colten Anderson
    Provenance: AI-assisted draft. See the repository README for review and test status.
    Run as: SYSTEM, 64-bit PowerShell
    Log: C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediate-BitLockerKeyEscrow.log
#>

$logFile = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\Remediate-BitLockerKeyEscrow.log'

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

try {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop

    if ($volume.ProtectionStatus -ne 'On') {
        Write-Log "Protection is $($volume.ProtectionStatus); not adding protectors to an unprotected volume."
        Write-Output 'BitLocker protection is not on. Nothing to escrow.'
        exit 1
    }

    $recoveryProtectors = @($volume.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')

    if (-not $recoveryProtectors) {
        Write-Log 'No recovery password protector found; adding one.'
        Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -RecoveryPasswordProtector -ErrorAction Stop | Out-Null
        $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        $recoveryProtectors = @($volume.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword')
    }

    foreach ($protector in $recoveryProtectors) {
        BackupToAAD-BitLockerKeyProtector -MountPoint $env:SystemDrive -KeyProtectorId $protector.KeyProtectorId -ErrorAction Stop | Out-Null
        Write-Log "Backed up recovery password $($protector.KeyProtectorId) to Entra ID."
    }

    Write-Output "Escrowed $($recoveryProtectors.Count) recovery password(s) to Entra ID."
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    Write-Output "Escrow failed: $($_.Exception.Message)"
    exit 1
}
