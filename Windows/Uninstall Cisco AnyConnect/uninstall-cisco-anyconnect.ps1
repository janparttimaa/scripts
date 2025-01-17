<#
.SYNOPSIS
    Uninstall Cisco AnyConnect from Windows-devices.

.DESCRIPTION
    This PowerShell-script will uninstall Cisco AnyConnect from Windows-devices.

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
    powershell.exe -ExecutionPolicy Bypass -File .\uninstall-cisco-anyconnect.ps1

    This example is how to run this script running Windows PowerShell. This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or Microsoft Intune.
#>

# Uninstall Cisco AnyConnect if it's installed
Write-Host "Checking if the Cisco AnyConnect is installed."

$msiProduct = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "Cisco AnyConnect*" -and $_.Vendor -like "Cisco*" }

if ($msiProduct) {
Write-Host "Cisco AnyConnect installed. Attempting to close it (if open) and remove it..."
Stop-Process -Name vpnui -Force -Verbose -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
$msiProductIdentifyingNumber = $msiProduct.IdentifyingNumber
Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $msiProductIdentifyingNumber /Q" -Wait
}
else {
Write-Host "Cisco AnyConnect not installed."
}