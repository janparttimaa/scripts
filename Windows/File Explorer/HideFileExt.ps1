<#
.SYNOPSIS
    Shows file name extensions for the current user.

.DESCRIPTION
    This PowerShell script configures File Explorer to show
    file name extensions by setting the HideFileExt registry value
    to 0 under the current user hive.

    This setting applies per-user and does not require administrative
    privileges.

.VERSION
    20251224

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20251224 - Initial release

.EXAMPLE
    Run the following command with your non administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\HideFileExt.ps1

    This is the recommended execution method when deploying the script via
    Microsoft Intune or Microsoft Configuration Manager.
#>

# Registry path and value
$RegPath       = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
$ValueName     = "HideFileExt"
$ExpectedValue = 0

# Create the registry key if it does not exist
If (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the DWORD value to show file extensions
New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $ExpectedValue -Force | Out-Null

# Final verification check
Try {
    $ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName

    If ($ActualValue -eq $ExpectedValue) {
        Write-Output "SUCCESS: $ValueName is set to $ActualValue (File extensions are visible)."
        Exit 0
    }
    Else {
        Write-Error "FAILURE: $ValueName is set to $ActualValue, expected $ExpectedValue."
        Exit 1
    }
}
Catch {
    Write-Error "FAILURE: Unable to read registry value. $_"
    Exit 1
}
