<#
.SYNOPSIS
    Detection script: Reports whether Windows Subsystem for Linux (WSL) is installed.

.DESCRIPTION
    Exits 0 if WSL is not installed, otherwise exits 1.

    Checks the Windows Subsystem for Linux (WSL) installation status using
    the 'wsl.exe --status' command.

    If WSL is installed and the command completes successfully, the script
    exits with code 1. If WSL is not installed or the status check fails,
    the script exits with code 0.

    This script is intended exclusively for reporting purposes using
    Microsoft Intune Remediations. It does not perform any remediation
    actions or modify the device configuration.

    More information:
    https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations

.VERSION
    20261020

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20261020 - Initial release

.EXAMPLE
    Run the following command with your administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Detect-WSL.ps1

    When using this in Microsoft Intune, configure it as a detection
    script under Remediations for reporting purposes only.

#>

# Check WSL installation status and suppress command output
wsl.exe --status *> $null

# Check the exit code returned by WSL
if ($LASTEXITCODE -eq 0) {
    # WSL is installed - report detection
    Write-Output "WSL is installed"
    exit 1
}
else {
    # WSL is not installed or the status check failed
    Write-Output "WSL is not installed"
    exit 0
}
