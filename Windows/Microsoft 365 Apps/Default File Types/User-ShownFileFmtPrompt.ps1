<#
.SYNOPSIS
    Sets Microsoft 365 Apps default file format to Office Open XML formats for the current user via registry policy.

.DESCRIPTION
    This PowerShell script configures the ShownFileFmtPrompt registry value under the
    Microsoft 365 Apps (Office 16.0) Common\General key in HKCU.

    Registry:
    - Key Path:   HKCU\Software\Microsoft\Office\16.0\Common\General
    - Value name: ShownFileFmtPrompt
    - Value type: REG_DWORD
    - Value data: 1

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
    20260124 - Initial release

.EXAMPLE
    Run the following command with your non administrative user rights:

    %windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "User-ShownFileFmtPrompt.ps1"

    This is the recommended execution method when deploying the script via
    Microsoft Intune or Microsoft Configuration Manager.
#>

# Registry path and value
$RegPath = "HKCU:\Software\Microsoft\Office\16.0\Common\General"
$ValueName = "ShownFileFmtPrompt"
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
        Write-Output "SUCCESS: $ValueName is set to $ActualValue (Default file type set to Office Open XML formats for current user)."
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