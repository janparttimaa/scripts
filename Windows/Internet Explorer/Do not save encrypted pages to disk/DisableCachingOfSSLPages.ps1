<#
.SYNOPSIS
    Allows caching of SSL (encrypted) pages on Windows devices via policy registry.

.DESCRIPTION
    This PowerShell script configures the DisableCachingOfSSLPages policy in the Windows registry under Internet Settings. 
    You may need to deploy this script via Microsoft Intune to managed Windows devices if users are unable to view embedded images in emails in the classic Microsoft Outlook application.

    NOTE:
    This script directly implements the following Group Policy setting:
        - "Do not save encrypted pages to disk"

    GPO Path:
        Administrative Templates/Windows Components/Internet Explorer/Internet Control Panel/Advanced Page

    Registry Mapping:
        HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings
        DisableCachingOfSSLPages (DWORD)

    Policy Behavior:
        1 = Enabled  -> Do NOT save encrypted pages to disk
        0 = Disabled -> Allow saving encrypted pages to disk (Recommended)

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

    powershell.exe -ExecutionPolicy Bypass -File .\DisableCachingOfSSLPages.ps1

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
$RegPath       = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"
$ValueName     = "DisableCachingOfSSLPages"
$ExpectedValue = 0

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
        Write-Output "SUCCESS: $ValueName is set to $ActualValue (Encrypted pages can be saved to disk)."
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