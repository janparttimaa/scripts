<#
.SYNOPSIS
    Disables programmatic access for DNF for the current user via registry policy.

.DESCRIPTION
    This PowerShell script configures the DisableProgrammaticAccessForDNF registry value under the
    Office 16.0 Common DRM key in HKCU.

    Registry:
    - Key Path:   HKCU\Software\Office\16.0\Common\DRM
    - Value name: DisableProgrammaticAccessForDNF
    - Value type: REG_DWORD
    - Value data: 1

    This is required for Microsoft Purview Information Protection.
    Addresses a security issue where, if this registry key is not set, users can bypass Purview Information Protection when the Recipients Only label is applied to content.
    If the key is missing, end users can save labeled/protected content as a PDF, and the saved file may have the protection removed.

.VERSION
    20260124

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20260124 - Modified to set DisableProgrammaticAccessForDNF

.EXAMPLE
    Run the following command with your non administrative user rights:

    %windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "User-DisableProgrammaticAccessForDNF.ps1"

    This is the recommended execution method when deploying the script via
    Microsoft Intune or Microsoft Configuration Manager.
#>

# Registry path and value
$RegPath = "HKCU:\Software\Office\16.0\Common\DRM"
$ValueName = "DisableProgrammaticAccessForDNF"
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
        Write-Output "SUCCESS: $ValueName is set to $ActualValue (DisableProgrammaticAccessForDNF enabled for current user)."
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