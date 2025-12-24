<#
.SYNOPSIS
    Disables WinHTTP WPAD (Web Proxy Auto-Discovery) on Windows devices.

.DESCRIPTION
    This PowerShell script disables WinHTTP WPAD by setting the
    DisableWpad registry value to 1.

    This helps prevent unwanted proxy auto-discovery behavior and
    is commonly used as a security hardening measure.

    This setting applies per-device and does require administrative
    privileges to run.

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

    powershell.exe -ExecutionPolicy Bypass -File .\Computer-DisableWinHttpWpad.ps1

    This is the recommended execution method when deploying the script via
    Microsoft Intune or Microsoft Configuration Manager.
#>

# Ensure the script is running as Administrator
If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

# Registry path and value
$RegPath       = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp"
$ValueName     = "DisableWpad"
$ExpectedValue = 1

# Create the registry key if it does not exist
If (-not (Test-Path $RegPath)) {
    New-Item -Path $RegPath -Force | Out-Null
}

# Set the DWORD value to disable WPAD
New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType DWord -Value $ExpectedValue -Force | Out-Null

# Final verification check
Try {
    $ActualValue = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName

    If ($ActualValue -eq $ExpectedValue) {
        Write-Output "SUCCESS: $ValueName is set to $ActualValue (WinHTTP WPAD disabled)."
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
