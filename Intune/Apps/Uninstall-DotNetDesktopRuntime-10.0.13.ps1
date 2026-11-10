<#
.SYNOPSIS
    Uninstalls Microsoft Windows Desktop Runtime 10.0.13 (x64 and/or x86) silently.
.NOTES
    Run as SYSTEM (Intune Win32 uninstall command, remediation, or platform script).
    Exit 0 = removed or not present, 3010 = removed but reboot pending, 1 = failure.
    Log: C:\Windows\Temp\Uninstall-DotNetDesktopRuntime-10.0.13.log
#>

$TargetVersion = '10.0.13'
$LogFile       = "$env:SystemRoot\Temp\Uninstall-DotNetDesktopRuntime-$TargetVersion.log"
$RebootNeeded  = $false
$Failed        = $false

function Write-Log {
    param([string]$Message)
    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    Add-Content -Path $LogFile -Value $line
    Write-Output $line
}

Write-Log "Starting uninstall of Windows Desktop Runtime $TargetVersion"

$UninstallPaths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)

$Entries = Get-ItemProperty -Path $UninstallPaths -ErrorAction SilentlyContinue |
    Where-Object {
        $_.DisplayName -like "Microsoft Windows Desktop Runtime - $TargetVersion*" -and
        $_.UninstallString
    }

if (-not $Entries) {
    Write-Log "Windows Desktop Runtime $TargetVersion not found. Nothing to do."
    exit 0
}

foreach ($Entry in $Entries) {
    Write-Log "Found: $($Entry.DisplayName)"

    # Bundle installers register an UninstallString like:
    #   "C:\ProgramData\Package Cache\{GUID}\windowsdesktop-runtime-10.0.13-win-x64.exe" /uninstall
    # Pull the EXE path out and run it with the proper silent switches.
    $ExePath = $null
    if ($Entry.UninstallString -match '^"([^"]+\.exe)"') {
        $ExePath = $Matches[1]
    } elseif ($Entry.UninstallString -match '^(\S+\.exe)') {
        $ExePath = $Matches[1]
    }

    if (-not $ExePath -or -not (Test-Path -LiteralPath $ExePath)) {
        Write-Log "ERROR: Could not locate bundle EXE from UninstallString: $($Entry.UninstallString)"
        $Failed = $true
        continue
    }

    Write-Log "Running: `"$ExePath`" /uninstall /quiet /norestart"
    $Proc = Start-Process -FilePath $ExePath `
                          -ArgumentList '/uninstall', '/quiet', '/norestart' `
                          -Wait -PassThru -NoNewWindow
    $Code = $Proc.ExitCode
    Write-Log "Exit code: $Code"

    switch ($Code) {
        0       { Write-Log "Removed $($Entry.DisplayName)" }
        3010    { Write-Log "Removed $($Entry.DisplayName) - reboot required"; $RebootNeeded = $true }
        1641    { Write-Log "Removed $($Entry.DisplayName) - reboot initiated"; $RebootNeeded = $true }
        default { Write-Log "ERROR: Uninstall of $($Entry.DisplayName) failed with $Code"; $Failed = $true }
    }
}

# Clean up the shared framework folder if the bundle left it behind (it usually doesn't).
foreach ($Root in @("$env:ProgramFiles\dotnet", "${env:ProgramFiles(x86)}\dotnet")) {
    $Fx = Join-Path $Root "shared\Microsoft.WindowsDesktop.App\$TargetVersion"
    if (Test-Path -LiteralPath $Fx) {
        Write-Log "Removing leftover folder: $Fx"
        Remove-Item -LiteralPath $Fx -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($Failed)       { Write-Log "Finished with errors."; exit 1 }
if ($RebootNeeded) { Write-Log "Finished - reboot pending."; exit 3010 }
Write-Log "Finished successfully."
exit 0
