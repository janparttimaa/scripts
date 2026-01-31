<#
.SYNOPSIS
    Sets the Application Identity (AppIDSvc) service to Automatic and starts it.

.DESCRIPTION
    This PowerShell script configures the Application Identity service (AppIDSvc)
    to start automatically and ensures it is running.

    This setting applies per-device and does require administrative
    privileges to run.

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
    Run the following command with administrative privileges:

    powershell.exe -ExecutionPolicy Bypass -File .\Services-EnableApplicationIdentity.ps1

    Note:
    If you deploy this as an application via Microsoft Intune, use this installation command instead:

    %windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "Services-EnableApplicationIdentity.ps1"
#>

# Ensure the script is running as Administrator
If (-not ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    Exit 1
}

# Service details
$ServiceName   = "AppIDSvc"
$DisplayName   = "Application Identity"
$ExpectedStart = "Automatic"
$ExpectedState = "Running"

Try {
    # Ensure service exists
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop

    # Set startup type to Automatic
    Set-Service -Name $ServiceName -StartupType Automatic -ErrorAction Stop

    # Start the service if it isn't running
    $svc.Refresh()
    If ($svc.Status -ne "Running") {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }

    # Final verification check
    $svc = Get-Service -Name $ServiceName -ErrorAction Stop

    # Verify startup type (requires CIM/WMI because Get-Service doesn't expose it reliably)
    $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop

    $ActualStart = $cim.StartMode       # "Auto", "Manual", "Disabled"
    $ActualState = $svc.Status.ToString()

    $StartOk = ($ActualStart -eq "Auto")
    $StateOk = ($ActualState -eq $ExpectedState)

    If ($StartOk -and $StateOk) {
        Write-Output "SUCCESS: '$DisplayName' ($ServiceName) is set to Automatic and is Running."
        Exit 0
    }
    Else {
        Write-Error "FAILURE: '$DisplayName' ($ServiceName) start mode is '$ActualStart' and state is '$ActualState' (expected: Auto + Running)."
        Exit 1
    }
}
Catch {
    Write-Error "FAILURE: Unable to configure '$DisplayName' ($ServiceName). $_"
    Exit 1
}