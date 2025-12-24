<#
.SYNOPSIS
    Enables RpcAuthnLevelPrivacyEnabled for Windows Print subsystem via registry policy.

.DESCRIPTION
    This PowerShell script configures the RpcAuthnLevelPrivacyEnabled value in the Windows registry under the Print key.

    Registry Mapping:
        HKLM\SYSTEM\CurrentControlSet\Control\Print
        RpcAuthnLevelPrivacyEnabled (DWORD)

    Policy Behavior:
        1 = Enabled  -> Enforces RPC authentication level privacy for printing
        0 = Disabled -> Disables RPC authentication level privacy for printing

    More information:
        https://support.microsoft.com/en-us/topic/kb5005652-manage-new-point-and-print-default-driver-installation-behavior-cve-2021-34481-873642bf-2634-49c5-a23b-6d8e9a302872

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

    powershell.exe -ExecutionPolicy Bypass -File .\RpcAuthnLevelPrivacyEnabled.ps1

    This is the recommended execution method when deploying the script via
    Microsoft Intune, or Microsoft Configuration Manager.
#>

# Ensure the script is running as Administrator
If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

# Registry path and value
$RegPath       = "HKLM:\SYSTEM\CurrentControlSet\Control\Print"
$ValueName     = "RpcAuthnLevelPrivacyEnabled"
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
        Write-Output "SUCCESS: $ValueName is set to $ActualValue."
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
