# Server Administration Scripts

This directory contains PowerShell scripts specifically designed for Windows Server administration tasks. These scripts cover a wide range of server management activities, from Active Directory operations to system monitoring and maintenance. Most scripts have been generated directly by ManusAI as part of a project.

## Categories

### Active Directory Management
Scripts for managing users, groups, computers, and other Active Directory objects. These scripts often leverage the `ActiveDirectory` PowerShell module and are designed to automate common AD administrative tasks.

### System Monitoring
Scripts for monitoring server health, performance, and availability. These include checks for disk space, service status, event logs, and other critical system metrics.

### Hyper-V Management
Scripts for managing Hyper-V virtual machines, including creation, configuration, snapshot management, and virtual network administration.

### General Server Administration
Miscellaneous scripts for server configuration, maintenance, and troubleshooting that don't fall into the specific categories above.

## Prerequisites

Many scripts in this directory require specific PowerShell modules to be installed:

*   **ActiveDirectory Module:** Required for AD-related scripts. Install using `Install-WindowsFeature RSAT-AD-PowerShell` on Windows Server or download RSAT for Windows client.
*   **Hyper-V Module:** Required for Hyper-V scripts. Install using `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell`.

## Usage Notes

*   Scripts that modify Active Directory objects should be tested in a non-production environment first.
*   Many scripts require elevated privileges (Run as Administrator).
*   Server monitoring scripts can be integrated with Windows Task Scheduler for automated execution.

