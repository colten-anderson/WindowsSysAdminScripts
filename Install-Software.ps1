<#
.SYNOPSIS
    Installs software silently on Windows desktops.

.DESCRIPTION
    This script provides a unified approach to installing software silently using various methods
    including MSI files, EXE installers, and package managers like Chocolatey or Winget.

.PARAMETER SoftwareName
    Name of the software to install (for display purposes).

.PARAMETER InstallerPath
    Path to the installer file (MSI or EXE).

.PARAMETER InstallerType
    Type of installer: MSI, EXE, Chocolatey, or Winget.

.PARAMETER PackageName
    Package name for Chocolatey or Winget installations.

.PARAMETER SilentArgs
    Silent installation arguments for EXE installers.

.PARAMETER LogPath
    Path where installation logs will be saved.

.PARAMETER ComputerName
    Target computer name for remote installation.

.EXAMPLE
    .\Install-Software.ps1 -SoftwareName "7-Zip" -InstallerPath "C:\Installers\7z1900-x64.msi" -InstallerType "MSI"

.EXAMPLE
    .\Install-Software.ps1 -SoftwareName "Google Chrome" -InstallerType "Chocolatey" -PackageName "googlechrome"

.EXAMPLE
    .\Install-Software.ps1 -SoftwareName "Notepad++" -InstallerType "Winget" -PackageName "Notepad++.Notepad++"

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - Run as Administrator
    - For Chocolatey: Chocolatey must be installed
    - For Winget: Windows Package Manager must be available
    - For remote installation: PowerShell Remoting enabled
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$SoftwareName,
    
    [Parameter(Mandatory=$false)]
    [string]$InstallerPath,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("MSI", "EXE", "Chocolatey", "Winget")]
    [string]$InstallerType,
    
    [Parameter(Mandatory=$false)]
    [string]$PackageName,
    
    [Parameter(Mandatory=$false)]
    [string]$SilentArgs,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = (Join-Path $PSScriptRoot "InstallationLogs"),
    
    [Parameter(Mandatory=$false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

# Create log directory if it doesn't exist
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}

$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logFile = Join-Path $LogPath "$SoftwareName`_$timestamp.log"

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

Write-Log "Starting installation of $SoftwareName on $ComputerName"

# Function to install MSI
function Install-MSI {
    param(
        [string]$MsiPath,
        [string]$LogFile
    )
    
    if (-not (Test-Path $MsiPath)) {
        throw "MSI file not found: $MsiPath"
    }
    
    $msiLogFile = $LogFile -replace "\.log$", "_msi.log"
    $arguments = "/i `"$MsiPath`" /quiet /norestart /l*v `"$msiLogFile`""
    
    Write-Log "Executing: msiexec.exe $arguments"
    $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru -NoNewWindow
    
    return $process.ExitCode
}

# Function to install EXE
function Install-EXE {
    param(
        [string]$ExePath,
        [string]$Arguments
    )
    
    if (-not (Test-Path $ExePath)) {
        throw "EXE file not found: $ExePath"
    }
    
    Write-Log "Executing: $ExePath $Arguments"
    $process = Start-Process -FilePath $ExePath -ArgumentList $Arguments -Wait -PassThru -NoNewWindow
    
    return $process.ExitCode
}

# Function to install via Chocolatey
function Install-Chocolatey {
    param(
        [string]$Package
    )
    
    # Check if Chocolatey is installed
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        throw "Chocolatey is not installed. Please install Chocolatey first."
    }
    
    Write-Log "Installing $Package via Chocolatey"
    $process = Start-Process -FilePath "choco" -ArgumentList "install", $Package, "-y" -Wait -PassThru -NoNewWindow
    
    return $process.ExitCode
}

# Function to install via Winget
function Install-Winget {
    param(
        [string]$Package
    )
    
    # Check if Winget is available
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "Windows Package Manager (winget) is not available."
    }
    
    Write-Log "Installing $Package via Winget"
    $process = Start-Process -FilePath "winget" -ArgumentList "install", "--id", $Package, "--silent", "--accept-package-agreements", "--accept-source-agreements" -Wait -PassThru -NoNewWindow
    
    return $process.ExitCode
}

# Main installation logic
try {
    $exitCode = 0
    
    switch ($InstallerType) {
        "MSI" {
            if (-not $InstallerPath) {
                throw "InstallerPath is required for MSI installations"
            }
            $exitCode = Install-MSI -MsiPath $InstallerPath -LogFile $logFile
        }
        
        "EXE" {
            if (-not $InstallerPath) {
                throw "InstallerPath is required for EXE installations"
            }
            if (-not $SilentArgs) {
                Write-Log "No silent arguments provided. Using default: /S" -Level "WARNING"
                $SilentArgs = "/S"
            }
            $exitCode = Install-EXE -ExePath $InstallerPath -Arguments $SilentArgs
        }
        
        "Chocolatey" {
            if (-not $PackageName) {
                throw "PackageName is required for Chocolatey installations"
            }
            $exitCode = Install-Chocolatey -Package $PackageName
        }
        
        "Winget" {
            if (-not $PackageName) {
                throw "PackageName is required for Winget installations"
            }
            $exitCode = Install-Winget -Package $PackageName
        }
    }
    
    # Check exit code
    if ($exitCode -eq 0) {
        Write-Log "Installation of $SoftwareName completed successfully" -Level "SUCCESS"
    } elseif ($exitCode -eq 3010) {
        Write-Log "Installation of $SoftwareName completed successfully (reboot required)" -Level "WARNING"
    } else {
        Write-Log "Installation of $SoftwareName failed with exit code: $exitCode" -Level "ERROR"
    }
    
} catch {
    Write-Log "Installation failed: $($_.Exception.Message)" -Level "ERROR"
    $exitCode = 1
}

# Verify installation (basic check)
try {
    Write-Log "Verifying installation..."
    
    # Check installed programs
    $installedPrograms = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*$SoftwareName*" }
    
    if ($installedPrograms) {
        Write-Log "Verification successful: $SoftwareName found in installed programs" -Level "SUCCESS"
        foreach ($program in $installedPrograms) {
            Write-Log "Found: $($program.Name) - Version: $($program.Version)"
        }
    } else {
        Write-Log "Verification: $SoftwareName not found in Win32_Product (this may be normal for some installers)" -Level "WARNING"
    }
    
} catch {
    Write-Log "Verification failed: $($_.Exception.Message)" -Level "WARNING"
}

# Summary
Write-Host "`n=== INSTALLATION SUMMARY ===" -ForegroundColor Cyan
Write-Host "Software: $SoftwareName" -ForegroundColor White
Write-Host "Target Computer: $ComputerName" -ForegroundColor White
Write-Host "Installation Type: $InstallerType" -ForegroundColor White
Write-Host "Exit Code: $exitCode" -ForegroundColor $(if ($exitCode -eq 0 -or $exitCode -eq 3010) { "Green" } else { "Red" })
Write-Host "Log File: $logFile" -ForegroundColor White

if ($exitCode -eq 3010) {
    Write-Host "`nREBOOT REQUIRED" -ForegroundColor Yellow
    Write-Host "The installation completed successfully but requires a system reboot." -ForegroundColor Yellow
}

Write-Log "Installation process completed with exit code: $exitCode"
exit $exitCode

