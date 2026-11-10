<#
.SYNOPSIS
    Intune Remediations detection script: finds leftover WSUS / Group Policy Windows Update
    settings that stop Windows Update for Business (WUfB) from working.

.DESCRIPTION
    After moving devices from ConfigMgr/WSUS and Group Policy to Intune, old policy values
    under HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate often survive. A device that
    still points at a WSUS server, or is blocked from contacting Windows Update, will ignore
    WUfB rings and fall behind on patches without reporting an obvious error.

    Exit codes (Intune Remediations convention):
      0 = compliant, nothing to fix
      1 = legacy values found; Intune runs the remediation script

    Devices that still have the ConfigMgr client (CcmExec) are skipped, because in a
    co-managed tenant ConfigMgr may legitimately own the Windows Update workload.

.NOTES
    Author: Colten Anderson
    Provenance: AI-assisted draft. See the repository README for review and test status.
    Run as: SYSTEM, 64-bit PowerShell
#>

$policyRoot = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$auKey      = Join-Path $policyRoot 'AU'

# Values that redirect or block Windows Update. A value is a finding when it exists and
# (for flag values) is set to 1.
$checks = @(
    @{ Path = $policyRoot; Name = 'WUServer' },
    @{ Path = $policyRoot; Name = 'WUStatusServer' },
    @{ Path = $policyRoot; Name = 'UpdateServiceUrlAlternate' },
    @{ Path = $policyRoot; Name = 'DoNotConnectToWindowsUpdateInternetLocations'; Flag = $true },
    @{ Path = $policyRoot; Name = 'DisableWindowsUpdateAccess'; Flag = $true },
    @{ Path = $auKey;      Name = 'UseWUServer'; Flag = $true },
    @{ Path = $auKey;      Name = 'NoAutoUpdate'; Flag = $true }
)

if (Get-Service -Name 'CcmExec' -ErrorAction SilentlyContinue) {
    Write-Output 'ConfigMgr client present; Windows Update workload may be co-managed. Skipping.'
    exit 0
}

$findings = foreach ($check in $checks) {
    $value = Get-ItemProperty -Path $check.Path -Name $check.Name -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty $check.Name -ErrorAction SilentlyContinue
    if ($null -eq $value) { continue }
    if ($check.Flag -and $value -ne 1) { continue }
    '{0}={1}' -f $check.Name, $value
}

if ($findings) {
    # Remediations shows the last line of output in the portal, so keep it on one line.
    Write-Output ('Legacy Windows Update policy found: ' + ($findings -join '; '))
    exit 1
}

Write-Output 'No legacy Windows Update policy values found.'
exit 0
