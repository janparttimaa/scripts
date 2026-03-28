<#
.SYNOPSIS
    Detection script: checks that Windows Defender Advanced Threat Protection Service (Sense) is Running.

.DESCRIPTION
    Exits 0 if compliant, otherwise exits 1.
    
    This script is intended as a detection method for the installation script "Services - Windows Defender Advanced Threat Protection Service (Sense)",
    for use when deploying it as a Win32 application through Intune.

    More information:
    https://github.com/janparttimaa/scripts/tree/main/Windows/Services/Windows%20Defender%20Advanced%20Threat%20Protection%20Service%20(Sense)

.VERSION
    20260328

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20260328 - File name renamed and updated detection logic to only check if service is running
    20260324 - Initial release

.EXAMPLE
    Run the following command with your administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Detect-WindowsDefenderAdvacedThreatProtectionServiceSense.ps1

    When using this on Microsoft Intune, use this as a detection method.
    
    More information:
    https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add

#>

$ServiceName   = "Sense"
$DisplayName   = "Windows Defender Advanced Threat Protection Service"
$ExpectedState = "Running"

Try {
    # Verify service exists
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop

    $ActualState = $svc.Status.ToString() # "Running", "Stopped", etc.
    $StateOk = ($ActualState -eq $ExpectedState)

    If ($StateOk) {
        Write-Output "COMPLIANT: '$DisplayName' ($ServiceName) state is Running."
        Exit 0
    }
    Else {
        Write-Output "NON-COMPLIANT: '$DisplayName' ($ServiceName) state is '$ActualState' (expected: Running)."
        Exit 1
    }
}
Catch {
    Write-Output "NON-COMPLIANT: Unable to query '$DisplayName' ($ServiceName). $($_.Exception.Message)"
    Exit 1
}