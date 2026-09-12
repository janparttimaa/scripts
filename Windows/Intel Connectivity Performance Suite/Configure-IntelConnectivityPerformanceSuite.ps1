<#
.SYNOPSIS
    Disables Intel Connectivity Performance Suite from Startup Apps for the current user.

.DESCRIPTION
    This PowerShell script checks whether Intel Connectivity Performance Suite
    is installed for the currently logged-on user and whether its Startup Apps
    registry configuration already exists.

    If the application is enabled in Startup Apps, the script disables it by
    ensuring that the following existing registry values are configured as
    REG_DWORD with data 0:

        State                  = 0
        UserEnabledStartupOnce = 0

    The script does not create the registry key or registry values if they
    are missing.

    Script output is written to both the PowerShell output stream and:

        C:\ProgramData\Logs\Software

    Each log entry includes:
        - Date and time
        - Current user account
        - Processing step
        - Status message

    The log filename also includes the current user account.

    This script is intended for deployment through Microsoft Intune and
    should run in the logged-on user's context.

.VERSION
    20260912

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASENOTES
    20260912 - Initial release.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\Configure-IntelConnectivityPerformanceSuite.ps1
#>


# Script configuration
$ErrorActionPreference = 'Stop'
$RegistryKey = $null

$ScriptName = 'Configure-IntelConnectivityPerformanceSuite'
$AppxName = 'AppUp.IntelConnectivityPerformanceSuite'
$RegistryPath = 'Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\AppUp.IntelConnectivityPerformanceSuite_8j3eq9eme6ctt\ICMTask'

$RequiredValues = @(
    'State',
    'UserEnabledStartupOnce'
)

# Required data used to disable the application from Startup Apps.
$RequiredData = 0


# User information

# Get the actual Windows security identity running the script.
$CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

# Keep only the user account portion.
# Examples:
#   CONTOSO\jdoe             -> jdoe
#   AzureAD\jdoe@contoso.com -> jdoe@contoso.com
#   COMPUTER01\jdoe          -> jdoe
$CurrentUser = ($CurrentIdentity -split '\\')[-1]

# Create a filename-safe version of the user account.
$SafeUserName = $CurrentUser -replace '[\\/:*?"<>|]', '_'


# Logging configuration
$LogDirectory = 'C:\ProgramData\Logs\Software'
$LogFileName = "$ScriptName-$SafeUserName.log"
$LogFile = Join-Path -Path $LogDirectory -ChildPath $LogFileName


# Initialize logging
try {
    if (-not (Test-Path -Path $LogDirectory -PathType Container)) {
        New-Item -Path $LogDirectory -ItemType Directory -Force | Out-Null
    }

    if (-not (Test-Path -Path $LogFile -PathType Leaf)) {
        New-Item -Path $LogFile -ItemType File -Force | Out-Null
    }
}
catch {
    Write-Error "Unable to initialize log file '$LogFile'. $($_.Exception.Message)"
    exit 1
}


# Logging function
function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Step,

        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $Timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $LogEntry = "[$Timestamp] [$CurrentUser] [$Step] $Message"

    # Write output to Intune / PowerShell console.
    Write-Output $LogEntry

    # Write output to persistent log file.
    Add-Content -Path $LogFile -Value $LogEntry -Encoding UTF8
}


try {

    # Script start
    Write-Log -Step 'Start' -Message 'Starting Intel Connectivity Performance Suite Startup Apps configuration.'
    Write-Log -Step 'Start' -Message "Running as user '$CurrentUser'."
    Write-Log -Step 'Start' -Message "Computer name: '$env:COMPUTERNAME'."
    Write-Log -Step 'Start' -Message "Log file: '$LogFile'."


    # Step 1
    # Check whether Intel Connectivity Performance Suite is installed
    # for the current user.
    Write-Log -Step 'Step 1' -Message "Checking whether '$AppxName' is installed."

    $AppxPackage = Get-AppxPackage -Name $AppxName -ErrorAction SilentlyContinue

    if (-not $AppxPackage) {
        Write-Log -Step 'Step 1' -Message "AppX package '$AppxName' is not installed."
        Write-Log -Step 'Exit' -Message 'No action required. Exiting with code 0.'
        exit 0
    }

    Write-Log -Step 'Step 1' -Message "AppX package '$AppxName' is installed."


    # Step 2
    # Check whether the required Startup Apps registry key exists.
    Write-Log -Step 'Step 2' -Message 'Checking required Startup Apps registry key.'

    $RegistryKey = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey($RegistryPath, $true)

    if (-not $RegistryKey) {
        Write-Log -Step 'Step 2' -Message "Registry key does not exist: HKCU\$RegistryPath"
        Write-Log -Step 'Exit' -Message 'No action required. Exiting with code 0.'
        exit 0
    }

    Write-Log -Step 'Step 2' -Message "Registry key exists: HKCU\$RegistryPath"


    # Step 3
    # Check whether the required Startup Apps registry values exist.
    #
    # The script intentionally does not create missing values.
    Write-Log -Step 'Step 3' -Message 'Checking required Startup Apps registry values.'

    $ExistingValueNames = $RegistryKey.GetValueNames()

    foreach ($ValueName in $RequiredValues) {

        if ($ValueName -notin $ExistingValueNames) {
            Write-Log -Step 'Step 3' -Message "Registry value '$ValueName' does not exist."

            $RegistryKey.Close()
            $RegistryKey = $null

            Write-Log -Step 'Exit' -Message 'No action required. Exiting with code 0.'
            exit 0
        }

        Write-Log -Step 'Step 3' -Message "Registry value '$ValueName' exists."
    }


    # Step 4
    # Check whether Intel Connectivity Performance Suite is already disabled
    # from Startup Apps.
    #
    # Required configuration:
    #   State                  = 0 (REG_DWORD)
    #   UserEnabledStartupOnce = 0 (REG_DWORD)
    #
    # If either value is different, update it to REG_DWORD 0.
    Write-Log -Step 'Step 4' -Message 'Checking Startup Apps configuration.'

    foreach ($ValueName in $RequiredValues) {

        $CurrentValue = $RegistryKey.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $CurrentKind = $RegistryKey.GetValueKind($ValueName)

        Write-Log -Step 'Step 4' -Message "'$ValueName' current configuration: Type=$CurrentKind, Data=$CurrentValue"

        if (($CurrentValue -ne $RequiredData) -or ($CurrentKind -ne [Microsoft.Win32.RegistryValueKind]::DWord)) {

            Write-Log -Step 'Step 4' -Message "Intel Connectivity Performance Suite is not configured as disabled in Startup Apps for '$ValueName'."
            Write-Log -Step 'Step 4' -Message "Updating '$ValueName' to REG_DWORD $RequiredData."

            $RegistryKey.SetValue($ValueName, $RequiredData, [Microsoft.Win32.RegistryValueKind]::DWord)

            Write-Log -Step 'Step 4' -Message "Registry value '$ValueName' updated successfully."
        }
        else {
            Write-Log -Step 'Step 4' -Message "Registry value '$ValueName' is already configured correctly."
        }
    }


    # Step 5
    # Verify that Intel Connectivity Performance Suite is disabled
    # from Startup Apps.
    Write-Log -Step 'Step 5' -Message 'Verifying final Startup Apps configuration.'

    foreach ($ValueName in $RequiredValues) {

        $FinalValue = $RegistryKey.GetValue($ValueName, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $FinalKind = $RegistryKey.GetValueKind($ValueName)

        if (($FinalValue -ne $RequiredData) -or ($FinalKind -ne [Microsoft.Win32.RegistryValueKind]::DWord)) {
            throw "Verification failed for '$ValueName'. Expected REG_DWORD $RequiredData, found Type=$FinalKind, Data=$FinalValue."
        }

        Write-Log -Step 'Step 5' -Message "Verified '$ValueName': Type=$FinalKind, Data=$FinalValue"
    }


    # Close registry handle.
    $RegistryKey.Close()
    $RegistryKey = $null

    Write-Log -Step 'Success' -Message 'Intel Connectivity Performance Suite is disabled from Startup Apps for the current user.'
    Write-Log -Step 'Exit' -Message 'Exiting with code 0.'

    exit 0
}
catch {

    # Close the registry handle if it is still open.
    if ($RegistryKey) {
        try {
            $RegistryKey.Close()
            $RegistryKey = $null
        }
        catch {
            # Ignore cleanup errors and retain the original error.
        }
    }

    Write-Log -Step 'Error' -Message "Failed to disable Intel Connectivity Performance Suite from Startup Apps: $($_.Exception.Message)"
    Write-Log -Step 'Exit' -Message 'Exiting with code 1.'

    exit 1
}