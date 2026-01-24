<#
.SYNOPSIS
    Configures PowerShell 7+ to opt into updating through Microsoft Update (MU), WSUS, or Configuration Manager.

.DESCRIPTION
    This PowerShell script sets the UseMU registry value under HKLM\SOFTWARE\Microsoft\PowerShellCore.
    Value behavior:
        1 (default) = Opts into updating through Microsoft Update, WSUS, or Configuration Manager
        0           = Does not opt into updating through Microsoft Update, WSUS, or Configuration Manager

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
    Run the following command with administrative privileges:

    powershell.exe -ExecutionPolicy Bypass -File .\Computer-PowerShellCoreUseMU.ps1

    This is the recommended execution method when deploying the script via
    Microsoft Intune or Microsoft Configuration Manager.
    
    Note:
    If you deploy this as an application via Microsoft Intune, use this installation command instead:
    
    %windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "Computer-PowerShellCoreUseMU.ps1"
    
#>

# Ensure the script is running as Administrator
If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

# Registry path and value
$RegPath       = "HKLM:\SOFTWARE\Microsoft\PowerShellCore"
$ValueName     = "UseMU"
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
        Write-Output "SUCCESS: $ValueName is set to $ActualValue (PowerShellCore is opted into Microsoft Update/WSUS/ConfigMgr updates)."
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