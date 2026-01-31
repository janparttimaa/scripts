<#
.SYNOPSIS
    Detection script: checks that Application Identity (AppIDSvc) is Automatic and Running.

.DESCRIPTION
    Exits 0 if compliant, otherwise exits 1.
    
    This script is intended as a detection method for the installation script "Services-EnableApplicationIdentity.ps1",
    for use when deploying it as a Win32 application through Intune.

    More information:
    https://github.com/janparttimaa/scripts/tree/main/Windows/Services/Application%20Identity%20(AppIDSvc)

.VERSION
    20260131

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20260131 - Initial release

.EXAMPLE
    Run the following command with your administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Detect-EnableApplicationIdentity.ps1

    When using this on Microsoft Intune, use this as a detection method.
    
    More information:
    https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add

#>

$ServiceName   = "AppIDSvc"
$DisplayName   = "Application Identity"
$ExpectedState = "Running"

Try {
    # Verify service exists
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop

    # Verify startup type via CIM (Get-Service doesn't reliably expose it)
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop

    $ActualStart = $cim.StartMode         # "Auto", "Manual", "Disabled"
    $ActualState = $svc.Status.ToString() # "Running", "Stopped", etc.

    $StartOk = ($ActualStart -eq "Auto")
    $StateOk = ($ActualState -eq $ExpectedState)

    If ($StartOk -and $StateOk) {
        Write-Output "COMPLIANT: '$DisplayName' ($ServiceName) start mode is Auto and state is Running."
        Exit 0
    }
    Else {
        Write-Output "NON-COMPLIANT: '$DisplayName' ($ServiceName) start mode is '$ActualStart' and state is '$ActualState' (expected: Auto + Running)."
        Exit 1
    }
}
Catch {
    Write-Output "NON-COMPLIANT: Unable to query '$DisplayName' ($ServiceName). $($_.Exception.Message)"
    Exit 1
}