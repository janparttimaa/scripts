<#
.SYNOPSIS
    Uninstall MDOP MBAM client from Windows-devices

.DESCRIPTION
    This PowerShell-script will uninstall MDOP MBAM client from Windows-devices.

.VERSION
    1.0

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    1.0 - Initial release

.EXAMPLE
    Run following command with admin rights:
    powershell.exe -ExecutionPolicy Bypass -File .\uninstall-mdop-mbam-client.ps1

    This example is how to run this script running Windows PowerShell. This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or Microsoft Intune.
#>

# Uninstall the "MDOP MBAM" client MSI package if it's installed
Write-Host "Checking if the MDOP MBAM client is installed."

$msiProduct = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "MDOP MBAM" -and $_.Vendor -like "Microsoft Corporation" }

if ($msiProduct) {
Write-Host "MDOP MBAM client installed. Attempting to remove."
$msiProductIdentifyingNumber = $msiProduct.IdentifyingNumber
Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $msiProductIdentifyingNumber /Q" -Wait
}
else {
Write-Host "MDOP MBAM client not installed."
}
