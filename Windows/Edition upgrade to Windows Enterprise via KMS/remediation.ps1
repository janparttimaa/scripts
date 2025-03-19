<#﻿
.SYNOPSIS
    Edition Upgrade to Windows 10/11 Enterprise via KMS.

.DESCRIPTION
    If you came across situation where your KMS-activated Windows 10/11 Enterprise have been somehow downgraded to e.g. Windows 10/11 Pro, this script is for you! 
    This script upgrade your company-managed device back to KMS-activated Windows 10/11 Enterprise silently without any user interruption.
    Scope of this script: Corporate environments only.
    Platform: Windows 10 and later.

.VERSION
    20250312

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20250312 - Initial release

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1
    This example is how to run this script running Windows PowerShell. Run this command with your admin rights.
    This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or via Intune.
#>

# Define Generic Volume License Key for Windows 10/11 Enterprise
# Documentation: https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys?tabs=server2025%2Cwindows1110ltsc%2Cversion1803%2Cwindows81
$kmsKey = "NPPR9-FWDCX-D2C8J-H872K-2YT43"

# Define name of the server (e.g. SCCM-server) that can be pinged only from local network
$internalserver = "internalserver"

# Function to check Windows edition
function Get-WindowsEdition {
    $osEdition = (Get-WmiObject -Class Win32_OperatingSystem).OperatingSystemSKU
    return $osEdition
}

# Check if the device is on the local network
$localNetwork = Test-Connection -ComputerName "$internalserver.example.com" -Count 1 -Quiet

if ($localNetwork) {
    # Get the current Windows edition
    $windowsEdition = Get-WindowsEdition

    # Check if the Windows edition is not Enterprise (4 is the SKU for Enterprise). If not, it will be upgraded to Enterprise using Generic Volume License Key
    if ($windowsEdition -ne 4) {
        # Install the KMS key silently
        cscript C:\Windows\System32\slmgr.vbs -ipk $kmsKey
        Write-Output "KMS key installed successfully. Closing script..."
        # Exit code for SCCM and Intune
        [System.Environment]::Exit(0)
    } else {
        Write-Output "Windows is running Enterprise edition. KMS key installation skipped. Closing script..."
        # Exit code for SCCM and Intune
        [System.Environment]::Exit(0)
    }
} else {
    Write-Output "Device is not on the local network. KMS key installation aborted. Closing script..."
    # Exit code for SCCM and Intune
    [System.Environment]::Exit(1)
}
