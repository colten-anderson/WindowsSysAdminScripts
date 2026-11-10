# Windows Endpoint & Microsoft Cloud Admin Scripts

PowerShell for Windows endpoint management with Microsoft Intune, Microsoft Entra ID, and Microsoft 365, plus some general Windows, Active Directory, and Azure administration.

The `Intune/` folder is the main focus: Graph reporting, Win32 app scripts, and Intune Remediations detection/remediation pairs for problems that come up after moving a fleet from ConfigMgr and Group Policy to Intune.

## How these scripts are written

Many of these scripts started as AI-assisted drafts. I review each one, fix what's wrong, and test it before marking it **Tested**. Treat anything marked **Not yet tested** as a starting point, and run it in a lab or pilot group before using it in production.

| Status | Meaning |
|---|---|
| ✅ Tested | Run in a real or lab environment; notes say where and when |
| 🔍 Reviewed | Code reviewed and corrected; not yet run end to end |
| ⏳ Not yet tested | Draft; read before running |

## Intune

| Script | What it does | Status |
|---|---|---|
| [Get-IntuneDeviceReport.ps1](Intune/Get-IntuneDeviceReport.ps1) | Managed device report via Microsoft Graph with optional compliance and app detail (CSV, JSON, HTML) | ⏳ Not yet tested |
| [Get-StaleIntuneDevices.ps1](Intune/Get-StaleIntuneDevices.ps1) | Read-only list of devices that haven't synced in N days, for hygiene reviews | ⏳ Not yet tested |
| [Apps/Uninstall-DotNetDesktopRuntime-10.0.13.ps1](Intune/Apps/Uninstall-DotNetDesktopRuntime-10.0.13.ps1) | Silent removal of a specific .NET Desktop Runtime version; usable as a Win32 app uninstall command or remediation | ⏳ Not yet tested |

### Intune Remediations

Each folder holds a detection script and a remediation script. Detection exits `1` when the remediation should run. Deploy both as a Remediations package, running as SYSTEM in 64-bit PowerShell. Logs go to `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`, so they come back with Intune's **Collect diagnostics** action.

| Package | Problem it fixes | Status |
|---|---|---|
| [WindowsUpdate-LegacyPolicy](Intune/Remediations/WindowsUpdate-LegacyPolicy/) | Leftover WSUS and Group Policy update values (`WUServer`, `UseWUServer`, `DoNotConnectToWindowsUpdateInternetLocations`, and others) that silently block Windows Update for Business rings after a ConfigMgr-to-Intune move. Skips devices that still run the ConfigMgr client. | 🔍 Reviewed. Detection run on Windows 11 (Nov 2026, compliant result); remediation not yet run. |
| [BitLocker-KeyEscrow](Intune/Remediations/BitLocker-KeyEscrow/) | Encrypted devices with no recovery key in Entra ID. Adds a recovery password protector if one is missing and backs it up. Doesn't turn on encryption. | 🔍 Reviewed. Detection run on a non-joined Windows 11 device (Nov 2026); added a join-state check as a result. Remediation not yet run. |
| [LowDiskSpace](Intune/Remediations/LowDiskSpace/) | Devices too full to install cumulative or feature updates. Clears old temp files, the Delivery Optimization cache, and queued error reports. | ✅ Tested. Detection and remediation run elevated on Windows 11 Home 25H2 with Windows PowerShell 5.1 (Nov 2026): exit 0, log written, Delivery Optimization cache cleared, 0.12 GB freed. Not yet deployed through Intune. |

## Windows endpoint

| Script | What it does | Status |
|---|---|---|
| [Get-SystemInventory.ps1](Endpoint/Get-SystemInventory.ps1) | Hardware, OS, network, software, and hotfix inventory for a local or remote machine | ⏳ Not yet tested |
| [Get-SecurityAuditReport.ps1](Endpoint/Get-SecurityAuditReport.ps1) | Local security checks: user accounts, group membership, firewall, updates, security events, installed software | ⏳ Not yet tested |
| [Install-Software.ps1](Endpoint/Install-Software.ps1) | Silent MSI/EXE install with logging and post-install verification | ⏳ Not yet tested |
| [Manage-WindowsService.ps1](Endpoint/Manage-WindowsService.ps1) | Start, stop, restart, or reconfigure a Windows service | ⏳ Not yet tested |
| [New-LocalUser.ps1](Endpoint/New-LocalUser.ps1) | Create a local account | ⏳ Not yet tested |
| [Test-NetworkConnectivity.ps1](Endpoint/Test-NetworkConnectivity.ps1) | Ping, DNS, and port checks against a target host | ⏳ Not yet tested |
| [Backup-Files.ps1](Endpoint/Backup-Files.ps1) | Full or incremental file backup with optional compression and verification | ⏳ Not yet tested |

## Identity

| Script | What it does | Status |
|---|---|---|
| [New-EntraIDUser.ps1](Identity/New-EntraIDUser.ps1) | Create an Entra ID user with groups and license via Microsoft Graph | ⏳ Not yet tested |
| [Get-ADUserReport.ps1](Identity/Get-ADUserReport.ps1) | Active Directory user report: account status, lockouts, inactive accounts | ⏳ Not yet tested |
| [New-ADUserFromCSV.ps1](Identity/New-ADUserFromCSV.ps1) | Bulk AD user creation from CSV | ⏳ Not yet tested |
| [Reset-ADUserPassword.ps1](Identity/Reset-ADUserPassword.ps1) | AD password reset with optional notification | ⏳ Not yet tested |

## Microsoft 365, Azure, and server

| Script | What it does | Status |
|---|---|---|
| [Microsoft365/Get-MailboxReport.ps1](Microsoft365/Get-MailboxReport.ps1) | Exchange Online mailbox size and usage report | ⏳ Not yet tested |
| [Azure/Get-AzureResourceReport.ps1](Azure/Get-AzureResourceReport.ps1) | Azure resource inventory across subscriptions | ⏳ Not yet tested |
| [Azure/New-AzureResourceGroup.ps1](Azure/New-AzureResourceGroup.ps1) | Create a resource group with tags | ⏳ Not yet tested |
| [Azure/New-AzureVM.ps1](Azure/New-AzureVM.ps1) | Create an Azure VM with networking | ⏳ Not yet tested |
| [Server/Get-ServerHealthReport.ps1](Server/Get-ServerHealthReport.ps1) | CPU, memory, disk, service, and event log health report | ⏳ Not yet tested |
| [Server/New-VMFromTemplate.ps1](Server/New-VMFromTemplate.ps1) | Create Hyper-V VMs from a template or base configuration | ⏳ Not yet tested |
| [Utilities/Send-EmailReport.ps1](Utilities/Send-EmailReport.ps1) | Send a report file by SMTP | ⏳ Not yet tested |

## Requirements

- Windows PowerShell 5.1 or PowerShell 7
- Graph-based scripts: the `Microsoft.Graph.Authentication` module plus the module named in each script's help (for example `Microsoft.Graph.DeviceManagement`). Each script lists the Graph permissions it requests.
- Active Directory scripts: RSAT Active Directory module
- Exchange Online: `ExchangeOnlineManagement`
- Azure: `Az.Accounts`, `Az.Resources`, and related Az modules
- Hyper-V: the Hyper-V PowerShell module

Run `Get-Help .\<script>.ps1 -Full` for parameters and examples.

## Known limitations

- `Get-ServerHealthReport.ps1` and `Reset-ADUserPassword.ps1` send mail with `Send-MailMessage`, which Microsoft has marked obsolete. Their email options need to move to Microsoft Graph or a supported SMTP library before they're used in production.
- Software inventory reads the registry uninstall keys rather than `Win32_Product`, because querying `Win32_Product` triggers an MSI consistency check of every installed package. Per-user installs under `HKCU` aren't included.
- `New-LocalUser.ps1`, `New-ADUserFromCSV.ps1`, and `Reset-ADUserPassword.ps1` handle passwords as plain-text strings (flagged by PSScriptAnalyzer). Rework them to take `SecureString` or credential input before production use.
- The Intune scripts pass PSScriptAnalyzer with no warnings. All scripts parse cleanly in Windows PowerShell 5.1.
