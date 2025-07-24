<#
.SYNOPSIS
    Tests network connectivity to a target host using various methods.

.DESCRIPTION
    This script provides a comprehensive way to test network connectivity to a specified target
    by performing ping, TCP port check, and DNS resolution. It helps diagnose common network issues.

.PARAMETER TargetHost
    The hostname or IP address of the target to test connectivity to.

.PARAMETER Port
    The TCP port to test connectivity on (e.g., 80 for HTTP, 443 for HTTPS, 3389 for RDP).

.PARAMETER Count
    Number of ping requests to send. Defaults to 4.

.PARAMETER Timeout
    Timeout in milliseconds for ping and TCP port checks. Defaults to 1000.

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -TargetHost "google.com"

.EXAMPLE
    .\Test-NetworkConnectivity.ps1 -TargetHost "webserver01" -Port 80

.NOTES
    Author: Manus AI
    Version: 1.0
    
    Prerequisites:
    - ICMP (ping) must be allowed on target and intermediate firewalls.
    - For TCP port checks, the target service must be listening on the specified port.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetHost,
    
    [Parameter(Mandatory=$false)]
    [int]$Port,
    
    [Parameter(Mandatory=$false)]
    [int]$Count = 4,
    
    [Parameter(Mandatory=$false)]
    [int]$Timeout = 1000
)

Write-Host "Starting network connectivity test for: $TargetHost" -ForegroundColor Cyan

# Function to perform ping test
function Test-Ping {
    param(
        [string]$HostName,
        [int]$PingCount,
        [int]$PingTimeout
    )
    
    Write-Host "Performing Ping test to $HostName..." -ForegroundColor Yellow
    try {
        $pingResult = Test-Connection -ComputerName $HostName -Count $PingCount -ErrorAction Stop -TimeToLive 128 -BufferSize 32 -Delay $PingTimeout
        
        $successfulPings = ($pingResult | Where-Object { $_.StatusCode -eq 0 }).Count
        $averageLatency = ($pingResult | Measure-Object -Property ResponseTime -Average).Average
        
        if ($successfulPings -gt 0) {
            Write-Host "✓ Ping successful: $successfulPings/$PingCount replies, Average Latency: $($averageLatency)ms" -ForegroundColor Green
            return $true
        } else {
            Write-Host "✗ Ping failed: No replies received." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ Ping test error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Function to perform TCP port test
function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$PortNumber,
        [int]$TcpTimeout
    )
    
    Write-Host "Performing TCP Port $PortNumber test to $HostName..." -ForegroundColor Yellow
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectResult = $tcpClient.BeginConnect($HostName, $PortNumber, $null, $null)
        $waitHandle = $connectResult.AsyncWaitHandle
        
        if ($waitHandle.WaitOne($TcpTimeout, $false)) {
            if ($tcpClient.Connected) {
                Write-Host "✓ TCP Port $PortNumber is open on $HostName." -ForegroundColor Green
                return $true
            } else {
                Write-Host "✗ TCP Port $PortNumber is closed on $HostName." -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "✗ TCP Port $PortNumber test timed out on $HostName." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ TCP Port test error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    } finally {
        if ($tcpClient) { $tcpClient.Close() }
    }
}

# Function to perform DNS resolution test
function Test-DnsResolution {
    param(
        [string]$HostName
    )
    
    Write-Host "Performing DNS Resolution test for $HostName..." -ForegroundColor Yellow
    try {
        $dnsResult = Resolve-DnsName -Name $HostName -ErrorAction Stop
        
        if ($dnsResult) {
            Write-Host "✓ DNS Resolution successful for $HostName." -ForegroundColor Green
            foreach ($record in $dnsResult) {
                if ($record.Type -eq "A" -or $record.Type -eq "AAAA") {
                    Write-Host "  - Resolved IP: $($record.IPAddress)" -ForegroundColor Gray
                } elseif ($record.Type -eq "CNAME") {
                    Write-Host "  - CNAME: $($record.NameHost)" -ForegroundColor Gray
                }
            }
            return $true
        } else {
            Write-Host "✗ DNS Resolution failed for $HostName." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "✗ DNS Resolution error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Perform tests
$overallStatus = $true

# 1. DNS Resolution Test
$dnsStatus = Test-DnsResolution -HostName $TargetHost
if (-not $dnsStatus) { $overallStatus = $false }

# 2. Ping Test
$pingStatus = Test-Ping -HostName $TargetHost -PingCount $Count -PingTimeout $Timeout
if (-not $pingStatus) { $overallStatus = $false }

# 3. TCP Port Test (if port is specified)
if ($Port) {
    $tcpStatus = Test-TcpPort -HostName $TargetHost -PortNumber $Port -TcpTimeout $Timeout
    if (-not $tcpStatus) { $overallStatus = $false }
}

# Summary
Write-Host "`n=== CONNECTIVITY TEST SUMMARY ===" -ForegroundColor Cyan
Write-Host "Target Host: $TargetHost" -ForegroundColor White
if ($Port) { Write-Host "Target Port: $Port" -ForegroundColor White }
Write-Host "DNS Resolution: $(if ($dnsStatus) { "Success" } else { "Failed" })" -ForegroundColor $(if ($dnsStatus) { "Green" } else { "Red" })
Write-Host "Ping Test: $(if ($pingStatus) { "Success" } else { "Failed" })" -ForegroundColor $(if ($pingStatus) { "Green" } else { "Red" })
if ($Port) {
    Write-Host "TCP Port Test: $(if ($tcpStatus) { "Success" } else { "Failed" })" -ForegroundColor $(if ($tcpStatus) { "Green" } else { "Red" })
}

if ($overallStatus) {
    Write-Host "Overall Connectivity: SUCCESS" -ForegroundColor Green
} else {
    Write-Host "Overall Connectivity: FAILED" -ForegroundColor Red
}

Write-Host "Network connectivity test completed." -ForegroundColor Green

