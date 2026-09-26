<#
.SYNOPSIS
    Detection script: checks that Microsoft Teams is installed and meets the required minimum version.

.DESCRIPTION
    Exits 0 if Microsoft Teams is installed and the installed version is equal to or newer than the required version.
    Otherwise exits 1.

    This script is intended as a detection method for Microsoft Teams,
    for use when deploying it as a Win32 application through Intune.

    More information:
    https://learn.microsoft.com/en-us/microsoftteams/new-teams-bulk-install-client
    https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add

.VERSION
    20260926

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20260926 - Initial release

.EXAMPLE
    Run the following command with your administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Detect-MicrosoftTeams.ps1

    When using this on Microsoft Intune, use this as a detection method.

    More information:
    https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add

#>

# Microsoft Teams MSIX package name.
# The new Microsoft Teams client uses the package name "MSTeams".
$PackageName = "MSTeams"

# Friendly application name used in detection output.
$DisplayName = "Microsoft Teams"

# Define the minimum acceptable Microsoft Teams version.
# The installed version must be equal to or newer than this version.
$RequiredVersion = [Version]"25153.1000.3727.1006"

Try {

    # Query Microsoft Teams packages installed for all users.
    # Intune Win32 detection scripts normally run in SYSTEM context,
    # so using -AllUsers allows the script to detect Teams packages
    # registered for users on the device.
    $Packages = Get-AppxPackage -AllUsers -Name $PackageName -ErrorAction Stop

    # If no matching Teams package was found, detection fails.
    If (-not $Packages) {
        Write-Output "NON-COMPLIANT: '$DisplayName' ($PackageName) is not installed."
        Exit 1
    }

    # Get all detected Microsoft Teams package versions.
    #
    # Multiple package registrations may exist on the device,
    # so each returned version is converted to a System.Version object.
    #
    # The versions are sorted from newest to oldest and the newest
    # installed version is selected for comparison.
    $InstalledVersion = $Packages | ForEach-Object { [Version]$_.Version } | Sort-Object -Descending | Select-Object -First 1

    # Compare the newest installed Teams version with the
    # minimum required version.
    #
    # Examples:
    # Installed: 25153.1000.3727.1006
    # Required:  25153.1000.3727.1006
    # Result:    Compliant
    #
    # Installed: 25154.1000.1000.1000
    # Required:  25153.1000.3727.1006
    # Result:    Compliant
    #
    # Installed: 25152.1000.1000.1000
    # Required:  25153.1000.3727.1006
    # Result:    Non-compliant
    $VersionOk = ($InstalledVersion -ge $RequiredVersion)

    # Teams is installed and the detected version meets
    # or exceeds the required minimum version.
    If ($VersionOk) {
        Write-Output "COMPLIANT: '$DisplayName' ($PackageName) version is '$InstalledVersion' (required: $RequiredVersion or newer)."
        Exit 0
    }
    Else {

        # Teams was found, but the installed version is older
        # than the configured minimum version.
        Write-Output "NON-COMPLIANT: '$DisplayName' ($PackageName) version is '$InstalledVersion' (required: $RequiredVersion or newer)."
        Exit 1
    }
}
Catch {

    # Detection failed because the package information could not
    # be queried successfully.
    #
    # Returning exit code 1 tells Intune that the application
    # does not satisfy the detection requirements.
    Write-Output "NON-COMPLIANT: Unable to query '$DisplayName' ($PackageName). $($_.Exception.Message)"
    Exit 1
}