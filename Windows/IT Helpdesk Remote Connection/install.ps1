<#
.SYNOPSIS
    IT Helpdesk Remote Connection Installer.

.DESCRIPTION
    This PowerShell script automates the installation and setup of the IT Helpdesk Remote Connection tool for a company. It ensures the necessary support files are deployed to the correct directory and that a Start Menu shortcut is created for easy access by all users.
    NOTE: You need to do some preparations before deploying this script. Please check preparation instructions from GitHub.

.VERSION
    20251102

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASENOTES
    20251102 - Initial release.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\install.ps1
    This example is how to run this script running Windows PowerShell. Run this command with your admin rights.
#>

# Replace "Example" with your company name e.g. "Contoso"
$CorporateName = "Example"

# Other variables
$ApplicationName = "IT Helpdesk Remote Connection"
$CorporateRegistryPath = "HKLM:\Software\$CorporateName"
$AppicationRegistryPath = "HKLM:\Software\$CorporateName\$ApplicationName"
$ScriptVersion = "20251102"

# Define source and destination paths
$BasePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceFolder = Join-Path $BasePath "Support Files"
$TargetFolder = "C:\Program Files\$CorporateName\$ApplicationName"

# Define files
$Ps1File = Join-Path $SourceFolder "Create-RemoteAssistanceInvitation.ps1"
$BatFile = Join-Path $SourceFolder "Create-RemoteAssistanceInvitation.bat"

# Ensure target directory exists
if (!(Test-Path -Path $TargetFolder)) {
    New-Item -ItemType Directory -Path $TargetFolder -Force | Out-Null
    Write-Host "Created directory: $TargetFolder"
}

# Copy files
$FilesToMove = @($Ps1File, $BatFile)
foreach ($file in $FilesToMove) {
    if (Test-Path $file) {
        Copy-Item -Path $file -Destination $TargetFolder -Force
        Write-Host "Copied $file to $TargetFolder"
    } else {
        Write-Warning "File not found: $file"
    }
}

# Create Start Menu shortcut (All Users)
$ShortcutName = "$CorporateName $ApplicationName.lnk"
$StartMenuPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
$ShortcutPath = Join-Path $StartMenuPath $ShortcutName
$ShortcutTarget = Join-Path $TargetFolder "Create-RemoteAssistanceInvitation.bat"

# Icon source (Windows tree icon)
$IconPath = "$env:SystemRoot\System32\shell32.dll"
$IconIndex = 41

# Create shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $ShortcutTarget
$Shortcut.WorkingDirectory = $TargetFolder
$Shortcut.IconLocation = "$IconPath,$IconIndex"
$Shortcut.Description = "Launch $CorporateName $ApplicationName"
$Shortcut.Save()

Write-Host "Shortcut created: $ShortcutPath"
Start-Sleep -Seconds 5

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
exit 0
