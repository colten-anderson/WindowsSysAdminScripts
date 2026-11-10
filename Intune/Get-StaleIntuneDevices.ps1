<#
.SYNOPSIS
    Lists Intune managed devices that have not checked in for a given number of days.

.DESCRIPTION
    Read-only report for device hygiene reviews. Stale records inflate license and compliance
    numbers, hide lost or retired hardware, and make patch reporting look worse than it is.
    This script does not retire, wipe, or delete anything; use the CSV to review devices with
    their owners first, then clean up through Intune device cleanup rules or by hand.

.PARAMETER DaysInactive
    Devices whose last sync is older than this many days are reported. Default: 30.

.PARAMETER OperatingSystem
    Limit to one platform: All, Windows, iOS, Android, macOS. Default: All.

.PARAMETER OutputPath
    Folder for the CSV. Default: the current directory.

.EXAMPLE
    .\Get-StaleIntuneDevices.ps1

.EXAMPLE
    .\Get-StaleIntuneDevices.ps1 -DaysInactive 60 -OperatingSystem Windows -OutputPath C:\Reports

.NOTES
    Author: Colten Anderson
    Provenance: AI-assisted draft. See the repository README for review and test status.

    Requires the Microsoft.Graph.Authentication and Microsoft.Graph.DeviceManagement modules:
        Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.DeviceManagement -Scope CurrentUser

    Graph permission (delegated): DeviceManagementManagedDevices.Read.All
    Role: Intune Administrator, or a custom role with read access to managed devices.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 3650)]
    [int]$DaysInactive = 30,

    [ValidateSet('All', 'Windows', 'iOS', 'Android', 'macOS')]
    [string]$OperatingSystem = 'All',

    [string]$OutputPath = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

Import-Module Microsoft.Graph.Authentication
Import-Module Microsoft.Graph.DeviceManagement

if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

Connect-MgGraph -Scopes 'DeviceManagementManagedDevices.Read.All' -NoWelcome

$cutoff = (Get-Date).ToUniversalTime().AddDays(-$DaysInactive)
$properties = @(
    'id', 'deviceName', 'userPrincipalName', 'operatingSystem', 'osVersion', 'complianceState',
    'lastSyncDateTime', 'enrolledDateTime', 'serialNumber', 'model', 'manufacturer',
    'azureADDeviceId', 'managementAgent', 'managedDeviceOwnerType'
)

Write-Verbose 'Retrieving managed devices from Microsoft Graph...'
$devices = Get-MgDeviceManagementManagedDevice -All -Property $properties

if ($OperatingSystem -ne 'All') {
    $devices = $devices | Where-Object { $_.OperatingSystem -eq $OperatingSystem }
}

$now = (Get-Date).ToUniversalTime()
$stale = $devices |
    Where-Object { $_.LastSyncDateTime -and $_.LastSyncDateTime.ToUniversalTime() -lt $cutoff } |
    Sort-Object LastSyncDateTime |
    ForEach-Object {
        [PSCustomObject]@{
            DeviceName        = $_.DeviceName
            UserPrincipalName = $_.UserPrincipalName
            OperatingSystem   = $_.OperatingSystem
            OSVersion         = $_.OsVersion
            ComplianceState   = $_.ComplianceState
            LastSyncUtc       = $_.LastSyncDateTime.ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
            DaysSinceSync     = [int]($now - $_.LastSyncDateTime.ToUniversalTime()).TotalDays
            EnrolledUtc       = $(if ($_.EnrolledDateTime) { $_.EnrolledDateTime.ToUniversalTime().ToString('yyyy-MM-dd') })
            Ownership         = $_.ManagedDeviceOwnerType
            ManagementAgent   = $_.ManagementAgent
            Manufacturer      = $_.Manufacturer
            Model             = $_.Model
            SerialNumber      = $_.SerialNumber
            EntraDeviceId     = $_.AzureAdDeviceId
            IntuneDeviceId    = $_.Id
        }
    }

$file = Join-Path $OutputPath ('StaleIntuneDevices_{0}d_{1:yyyyMMdd}.csv' -f $DaysInactive, (Get-Date))
$stale | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8

$total = @($devices).Count
$count = @($stale).Count
Write-Output "$count of $total device(s) have not synced in more than $DaysInactive days. Report: $file"

if ($count -gt 0) {
    $stale | Group-Object OperatingSystem | Sort-Object Count -Descending |
        Select-Object @{ n = 'OperatingSystem'; e = { $_.Name } }, Count |
        Format-Table -AutoSize | Out-String | Write-Output
}
