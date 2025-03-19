<# 
.SYNOPSIS
    Intune & Configuration Manager Detection Script for verifying Windows 10/11 Enterprise edition.

.DESCRIPTION
    This script checks if the device is running Windows 10/11 Enterprise. It is designed to be used as a detection script in Microsoft Intune.

.VERSION
    20250319

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT
    
.RELEASE NOTES
    20250319 - Initial release

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\detection.ps1
    This example is how to run this script running Windows PowerShell. Run this command with your admin rights.
    This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or via Intune.

#>

# Function to check Windows edition
function Get-WindowsEdition {
    $osEdition = (Get-WmiObject -Class Win32_OperatingSystem).OperatingSystemSKU
    return $osEdition
}

# Get the current Windows edition
$windowsEdition = Get-WindowsEdition

# Check if the Windows edition is Enterprise (4 is the SKU for Enterprise)
if ($windowsEdition -eq 4) {
    Write-Output "Windows is running Enterprise edition."
    # Exit code for Intune and Configuration Manager (0 indicates detection success)
    [System.Environment]::Exit(0)
} else {
    Write-Output "Windows is not running Enterprise edition."
    # Exit code for Intune and Configuration Manager (1 indicates detection failure)
    [System.Environment]::Exit(1)
}
