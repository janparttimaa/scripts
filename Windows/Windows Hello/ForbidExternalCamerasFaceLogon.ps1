<#
.SYNOPSIS
    Forbids the use of external cameras for Windows Hello Face sign-in.

.DESCRIPTION
    This PowerShell script disables the use of external cameras for
    Windows Hello Face by setting the ShouldForbidExternalCameras
    registry value to 1.

    This setting enforces that only built-in cameras can be used
    for Windows Hello Face authentication.

    More information:
    https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication

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
    Run the following command with administrative privileges:

    powershell.exe -ExecutionPolicy Bypass -File .\ForbidExternalCamerasFaceLogon.ps1
#>

# Ensure the script is running as Administrator
If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

# Registry path and value
$RegPath       = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\FaceLogon"
$ValueName     = "ShouldForbidExternalCameras"
$ExpectedValue = 1

# Create the registry key if it does not exist
If (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the DWORD value
New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $ExpectedValue -Force | Out-Null

# Final verification check
Try {
    $ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName

    If ($ActualValue -eq $ExpectedValue) {
        Write-Output "SUCCESS: $ValueName is set to $ActualValue (External cameras forbidden for Face Logon)."
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