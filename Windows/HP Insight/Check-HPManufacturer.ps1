<#
.SYNOPSIS
    Requirement script: Checks if device manufacturer is HP or Hewlett-Packard.

.DESCRIPTION
    Exits 0 if the device manufacturer is supported, otherwise exits 1.

    This script is intended for use as a requirement rule when deploying
    Win32 applications via Microsoft Intune. It ensures the application
    only installs on supported HP devices.

    Supported manufacturer values:
    - HP
    - HP Inc. / HP.inc
    - Hewlett-Packard
    - Hewlett Packard

    More information:
    https://github.com/janparttimaa/scripts/tree/main/Windows/HP%20Insight

.VERSION
    20260426

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20260426 - Initial release

.EXAMPLE
    Run manually:

    powershell.exe -ExecutionPolicy Bypass -File .\Check-HPManufacturer.ps1

    When using this in Microsoft Intune, configure it as a requirement rule.
#>

# Stop script execution on any error
$ErrorActionPreference = 'Stop'

try {
    # Retrieve manufacturer information from the system
    $Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem).Manufacturer

    # Normalize the value:
    # - Trim whitespace
    # - Convert to lowercase for consistent comparison
    # - Remove dots to handle "HP.inc" vs "HP Inc."
    $Normalized = $Manufacturer.Trim().ToLower() -replace '\.', ''

    Write-Output "Detected manufacturer: $Manufacturer"
    Write-Output "Normalized value: $Normalized"

    # Check if manufacturer matches allowed values
    if (
        $Normalized -eq "hp" -or
        $Normalized -eq "hp inc" -or
        $Normalized -eq "hewlett-packard" -or
        $Normalized -eq "hewlett packard"
    ) {
        Write-Output "Requirement satisfied: Supported manufacturer"
        exit 0
    }
    else {
        Write-Output "Requirement not met: Unsupported manufacturer"
        exit 1
    }
}
catch {
    # Handle unexpected errors
    Write-Output "Requirement check failed: $($_.Exception.Message)"
    exit 1
}