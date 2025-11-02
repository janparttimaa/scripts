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
$Company = "Example"

# Define source and destination paths
$BasePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$SourceFolder = Join-Path $BasePath "Support Files"
$TargetFolder = "C:\Program Files\$Company\IT Helpdesk Remote Connection"

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
$ShortcutName = "$Company IT Helpdesk Remote Connection.lnk"
$StartMenuPath = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
$ShortcutPath = Join-Path $StartMenuPath $ShortcutName
$ShortcutTarget = Join-Path $TargetFolder "msra.bat"

# Icon source (Windows tree icon)
$IconPath = "$env:SystemRoot\System32\shell32.dll"
$IconIndex = 41

# Create shortcut
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut($ShortcutPath)
$Shortcut.TargetPath = $ShortcutTarget
$Shortcut.WorkingDirectory = $TargetFolder
$Shortcut.IconLocation = "$IconPath,$IconIndex"
$Shortcut.Description = "Launch $Company IT Helpdesk Remote Connection"
$Shortcut.Save()

Write-Host "Shortcut created: $ShortcutPath"
Write-Host "Installation is now done. Closing installation script..."
Start-Sleep -Seconds 10
exit 0