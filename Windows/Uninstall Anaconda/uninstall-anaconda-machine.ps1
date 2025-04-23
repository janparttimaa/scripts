<#
.SYNOPSIS
    Uninstall Anaconda from Windows-devices (System-context).

.DESCRIPTION
    This PowerShell-script will uninstall Anaconda from Windows-devices (System-context).

.VERSION
    20250417

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20250417 - Initial release

.EXAMPLE
    Run following command with with admin rights:
    powershell.exe -ExecutionPolicy Bypass -File .\uninstall-anaconda-machine.ps1

    This example is how to run this script running Windows PowerShell. This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or Microsoft Intune.
#>

# Set variables
$UninstallAnaconda3="C:\ProgramData\Anaconda3\Uninstall-Anaconda3.exe"
$AnacondaProgramData="C:\ProgramData\Anaconda3"
$AnacondaStartMenu1="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Anaconda3 (64-bit)"
$AnacondaStartMenu2="C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Anaconda (anaconda3)"

# Checking if Anaconda is installed. If yes, it will be uninstalled. Otherwise, we will proceed.
Write-Host "Checking if Anaconda is installed..."
if (Test-Path $UninstallAnaconda3) {
    Write-Host "Anaconda is installed. Uninstalling it..."
    Stop-Process -Name pythonw -Force -Verbose -ErrorAction SilentlyContinue
    Start-Process -FilePath $UninstallAnaconda3 -ArgumentList "/S" -Wait -Verbose
    Start-Sleep -Seconds 60
} else {
    Write-Host "Anaconda is not installed. Let's proceed..."
}

# Double-check if Anaconda is uninstalled. If yes, we can proceed. If not, we will exit the script.
Write-Host "Double-checking if Anaconda is indeed still installed..."
if (-Not (Test-Path $UninstallAnaconda3)) {
    Write-Host "Anaconda is not installed. Let's proceed..."
} else {
    Write-Host "Anaconda uninstallation failed. Exiting script..."
    exit 1
}

# Checking if Anaconda files and folders are on Program Data. If yes, those will be deleted. Otherwise, we will proceed.
Write-Host "Checking if files anf folders of Anaconda are on Program Data..."
if (Test-Path $AnacondaProgramData) {
    Write-Host "Anaconda files and folders identified from Program Data. Deleting those now..."
    Remove-Item -Path $AnacondaProgramData -Recurse -Force -Verbose
} else {
    Write-Host "Anaconda files and folders not identified from Program Data. Let's proceed..."
}

# Checking if Anaconda short is still on Start menu. If yes, that will be deleted. Otherwise, we will proceed.
Write-Host "Checking Anaconda shortcut (Option 1) is still on Start menu..."
if (Test-Path $AnacondaStartMenu1) {
    Write-Host "Anaconda shortcut (Option 1) identified from Start menu. Deleting that now..."
    Remove-Item -Path $AnacondaStartMenu1 -Recurse -Force -Verbose
} else {
    Write-Host "Anaconda shortcut (Option 1) not identified from Start menu. Let's proceed..."
}

Write-Host "Checking Anaconda shortcut (Option 2) is still on Start menu..."
if (Test-Path $AnacondaStartMenu2) {
    Write-Host "Anaconda shortcut (Option 2) identified from Start menu. Deleting that now..."
    Remove-Item -Path $AnacondaStartMenu2 -Recurse -Force -Verbose
} else {
    Write-Host "Anaconda shortcut (Option 2) not identified from Start menu. Let's proceed..."
}

Write-Host "All done. Closing script..."
Start-Sleep -Seconds 10
