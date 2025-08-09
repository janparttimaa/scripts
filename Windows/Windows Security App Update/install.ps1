<#
.SYNOPSIS
    Install Windows Security App Update.

.DESCRIPTION
    This PowerShell-script will install Windows Security App Update using offline version of the installer.
    Offline installer can be downloaded here: https://support.microsoft.com/en-us/topic/windows-security-app-update-a6ac7d2e-b1bf-44c0-a028-41720a242da3
    Replace name of the offline installer to the line 35, where placeholdername "installer.exe" is.
    Replace name of your company to the line 37, where placeholdername "Example Company" is.
    Installation will happens per system context.
    Platform: Windows 10 and later.
    NOTE: You need to do some preparations before deploying this script. Please check preparation instructions from GitHub.

.VERSION
    20250809

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20250809 - Initial release

.EXAMPLE
    Run following command with with admin rights:
    powershell.exe -ExecutionPolicy Bypass -File .\install.ps1
    This example is how to run this script running Windows PowerShell. This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or Microsoft Intune.
#>

# Set Variables
$Installer = ".\installer.exe"
$CorporateName = "Example Company"
$ApplicationName = "Windows Security App Update"
$CorporateRegistryPath = "HKLM:\Software\$CorporateName"
$AppicationRegistryPath = "HKLM:\Software\$CorporateName\$ApplicationName"
$ScriptVersion = "20250809"

# Installs Windows Security App Update
Write-Host "Installing Windows Security App Update..."
Start-Process -FilePath $Installer -Wait -Verbose

# Wait for moment
Start-Sleep -Seconds 10

# Let's create registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes and close the script
Write-Host "Creating registry key for Microsoft Intune or Microsoft Configuration Manager detection rule purposes..."
if (-not (Test-Path -Path $CorporateRegistryPath)) {
    New-Item -Path $CorporateRegistryPath -Force -Verbose
}else {
    Write-Host "Registry path '$CorporateRegistryPath' is already created. Let's continue..." 
}

if (-not (Test-Path -Path $AppicationRegistryPath)) {
    New-Item -Path $AppicationRegistryPath -Force -Verbose
}else {
    Write-Host "Registry path '$AppicationRegistryPath' is already created. Let's continue..." 
}

Set-ItemProperty -Path $AppicationRegistryPath -Name "Installed" -Value "Yes" -Type "String" -Force -Verbose
Set-ItemProperty -Path $AppicationRegistryPath -Name "ScriptVersion" -Value "$ScriptVersion" -Type "String" -Force -Verbose

# Wait for moment
Start-Sleep -Seconds 10

# Closing script
Write-Output "All done. Closing script..."

Start-Sleep -Seconds 10
