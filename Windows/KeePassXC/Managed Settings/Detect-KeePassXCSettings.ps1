<#
.SYNOPSIS
    Detection script: Checks if required KeePassXC settings have been implemented.

.DESCRIPTION
    Exits 0 if compliant, otherwise exits 1.

    This script is intended as a detection method for an installation script that enforces
    required settings in KeePassXC's configuration file, for use when deploying it as a
    Win32 application through Intune.

    More information:
    

.VERSION
    20260418

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT


.RELEASE NOTES
    20260418 - Initial release

.EXAMPLE
    Run the following command with your non administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Detect-KeePassXCSettings.ps1

    When using this on Microsoft Intune, use this as a detection method.

    More information:
    https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add
    
#>

$ErrorActionPreference = 'Stop'

$IniPath = Join-Path $env:APPDATA 'KeePassXC\keepassxc.ini'

# Required settings to detect
# Add, remove, or modify entries here as needed
$RequiredSettings = @(
    @{ Section = 'General'; Key = 'UpdateCheckMessageShown'; Value = 'true'  }
    @{ Section = 'GUI';     Key = 'Language';                Value = 'en_US' }
    @{ Section = 'GUI';     Key = 'ColorPasswords';          Value = 'true'  }
    @{ Section = 'GUI';     Key = 'CheckForUpdates';         Value = 'false' }
)

function Get-IniContent {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "INI file missing: $Path"
    }

    $ini = @{}
    $currentSection = $null

    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $trimmed = $line.Trim()

        if ([string]::IsNullOrWhiteSpace($trimmed)) {
            continue
        }

        if ($trimmed -match '^[;#]') {
            continue
        }

        if ($trimmed -match '^\[(.+)\]$') {
            $currentSection = $matches[1].Trim()

            if (-not $ini.ContainsKey($currentSection)) {
                $ini[$currentSection] = @{}
            }

            continue
        }

        if (($null -ne $currentSection) -and ($trimmed -match '^(.*?)=(.*)$')) {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()

            if (-not $ini.ContainsKey($currentSection)) {
                $ini[$currentSection] = @{}
            }

            $ini[$currentSection][$key] = $value
        }
    }

    return $ini
}

try {
    $iniContent = Get-IniContent -Path $IniPath

    foreach ($rule in $RequiredSettings) {
        $section = [string]$rule.Section
        $key = [string]$rule.Key
        $expectedValue = [string]$rule.Value

        if (-not $iniContent.ContainsKey($section)) {
            Write-Output "Not compliant: section missing [$section]"
            exit 1
        }

        if (-not $iniContent[$section].ContainsKey($key)) {
            Write-Output "Not compliant: key missing [$section] $key"
            exit 1
        }

        $actualValue = [string]$iniContent[$section][$key]

        Write-Output "[$section] $key"
        Write-Output "Expected: $expectedValue"
        Write-Output "Actual:   $actualValue"

        if ($actualValue -ne $expectedValue) {
            Write-Output "Not compliant: value mismatch for [$section] $key"
            exit 1
        }
    }

    Write-Output 'Compliant: all required KeePassXC settings match'
    exit 0
}
catch {
    Write-Output "Not compliant: $($_.Exception.Message)"
    exit 1
}