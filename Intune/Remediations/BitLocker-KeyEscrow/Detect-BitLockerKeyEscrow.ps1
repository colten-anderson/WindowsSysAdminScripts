<#
.SYNOPSIS
    Intune Remediations detection script: checks that the OS drive's BitLocker recovery
    password has been backed up to Microsoft Entra ID.

.DESCRIPTION
    A device can be encrypted and still have no recovery key in Entra ID, for example when it
    was encrypted before enrollment or when the original escrow attempt failed. That device
    looks compliant until someone needs the key.

    Devices that are not Entra ID joined or hybrid joined are skipped (exit 0).

    The check passes when:
      - the OS volume is encrypted with protection on,
      - it has at least one recovery password protector, and
      - the BitLocker Management event log contains a successful Entra ID backup event
        (ID 845) that mentions that protector's ID.

    Exit codes: 0 = compliant, 1 = remediation needed.

    Event logs roll over, so a device whose 845 event has aged out will be flagged and
    re-escrowed. That is harmless: backing up an existing key again just refreshes it.

.NOTES
    Author: Colten Anderson
    Provenance: AI-assisted draft. See the repository README for review and test status.
    Run as: SYSTEM, 64-bit PowerShell
#>

# Escrow to Entra ID only works on Entra joined or hybrid joined devices. Skip anything else
# (workgroup or personal devices) so the remediation doesn't run and fail.
$joinState = dsregcmd /status | Select-String -Pattern '^\s*AzureAdJoined\s*:\s*YES'
if (-not $joinState) {
    Write-Output 'Device is not Entra ID joined or hybrid joined; Entra ID key escrow does not apply.'
    exit 0
}

$volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue

if (-not $volume) {
    Write-Output 'Could not read BitLocker status for the OS drive.'
    exit 1
}

if ($volume.ProtectionStatus -ne 'On') {
    # Turning on encryption is the job of the Intune disk encryption policy, not this script.
    Write-Output "BitLocker protection is $($volume.ProtectionStatus) on $env:SystemDrive. Not escrow-ready; check the encryption policy."
    exit 0
}

$recoveryProtectors = $volume.KeyProtector | Where-Object KeyProtectorType -eq 'RecoveryPassword'
if (-not $recoveryProtectors) {
    Write-Output 'No recovery password protector on the OS drive.'
    exit 1
}

$escrowEvents = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-BitLocker/BitLocker Management'
    Id      = 845
} -ErrorAction SilentlyContinue

foreach ($protector in $recoveryProtectors) {
    $id = $protector.KeyProtectorId.Trim('{}')
    if ($escrowEvents | Where-Object { $_.Message -match [regex]::Escape($id) }) {
        Write-Output "Recovery password $id has a successful Entra ID backup event."
        exit 0
    }
}

Write-Output 'No Entra ID backup event found for any recovery password protector.'
exit 1
