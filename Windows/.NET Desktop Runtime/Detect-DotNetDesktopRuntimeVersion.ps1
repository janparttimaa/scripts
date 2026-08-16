<#
.SYNOPSIS
    Detection script: Checks if .NET Desktop Runtime is installed within a configured version range
    and architecture.

.DESCRIPTION
    Exits 0 if compliant, otherwise exits 1.

    Enumerates the installed Microsoft.WindowsDesktop.App shared runtime versions for the configured
    architecture ($Architecture) and reports compliant if at least one installed version satisfies the
    configured version range ($MinVersion / $MaxVersion, each with a configurable inclusive/exclusive
    bound).

    This script is intended as a detection method for a .NET Desktop Runtime installation, for use
    when deploying it as a Win32 application through Intune.

    More information:
    https://github.com/janparttimaa/scripts/tree/main/Windows/.NET%20Desktop%20Runtime

.VERSION
    20260816

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20260816 - Initial release

.EXAMPLE
    Run the following command with your non administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Detect-DotNetDesktopRuntimeVersion.ps1

    When using this on Microsoft Intune, use this as a detection method.

    More information:
    https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add

#>

# Turns non-terminating errors into terminating ones so any failure is caught by the try/catch
# below instead of being silently swallowed and falsely reported as compliant.
$ErrorActionPreference = "Stop"

# ------------------------------------------------------------------------------------------------
# Configuration - edit these variables to match the requirement being detected
# ------------------------------------------------------------------------------------------------

# Lowest acceptable version, e.g. "10.0.0". Mandatory.
$MinVersion = "10.0.0"

# $true  = min version itself is acceptable (>=)
# $false = min version itself is NOT acceptable (>)
$MinVersionInclusive = $true

# Highest acceptable version, e.g. "11.0.0". Leave as "" for no upper bound.
$MaxVersion = "11.0.0"

# $true  = max version itself is acceptable (<=)
# $false = max version itself is NOT acceptable (<)
$MaxVersionInclusive = $false

# Architecture of the .NET Desktop Runtime to check. Valid values: "x64", "x86", "arm64"
$Architecture = "x64"

# ------------------------------------------------------------------------------------------------

# Resolves the "shared\Microsoft.WindowsDesktop.App" folder that holds the installed runtime
# version directories for the requested architecture. Returns $null when the folder cannot exist
# on this OS/architecture combination (e.g. arm64 requested on a non-Arm64 OS) or when the
# relevant Program Files environment variable isn't set.
function Get-DesktopRuntimeSharedPath {
    param(
        [Parameter(Mandatory)]
        [ValidateSet("x64", "x86", "arm64")]
        [string]$Architecture
    )

    # Starting with .NET 6, on Arm64 Windows the natively-installed runtime (Arm64) lives directly
    # under Program Files\dotnet, while the x64 runtime (installed for x64-under-emulation apps) is
    # relocated to Program Files\dotnet\x64 to avoid colliding with the Arm64 install. Because of
    # this, resolving the correct path for "x64" and "arm64" depends on the actual OS architecture,
    # not just the architecture being checked for.
    # More information:
    # https://learn.microsoft.com/en-us/dotnet/core/compatibility/sdk/6.0/path-x64-emulated
    $osArchitecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()

    switch ($Architecture) {
        "x86" {
            # x86 always lives under the 32-bit Program Files folder; no OS-architecture
            # redirection applies here (unlike the x64/arm64 cases above).
            $programFiles = ${env:ProgramFiles(x86)}
            if ([string]::IsNullOrWhiteSpace($programFiles)) {
                return $null
            }
            return Join-Path $programFiles "dotnet\shared\Microsoft.WindowsDesktop.App"
        }
        "arm64" {
            # The Arm64 runtime can only exist on an Arm64 OS.
            if ($osArchitecture -ne "Arm64") {
                return $null
            }
            if ([string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
                return $null
            }
            return Join-Path $env:ProgramFiles "dotnet\shared\Microsoft.WindowsDesktop.App"
        }
        "x64" {
            # On an Arm64 OS the x64 runtime is relocated under "dotnet\x64"; on an x64 OS it
            # lives directly under "dotnet" like normal.
            if ([string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
                return $null
            }
            if ($osArchitecture -eq "Arm64") {
                return Join-Path $env:ProgramFiles "dotnet\x64\shared\Microsoft.WindowsDesktop.App"
            }
            return Join-Path $env:ProgramFiles "dotnet\shared\Microsoft.WindowsDesktop.App"
        }
    }
}

# Lists installed runtime versions found under $SharedPath. Each subfolder of the shared runtime
# path is named after the version it contains (e.g. "8.0.11"), so this just parses each subfolder
# name as a [version] and returns the ones that parse successfully. Returns an empty array if the
# path is missing/inaccessible rather than throwing, so callers can treat "no path" the same as
# "no versions installed".
function Get-InstalledDesktopRuntimeVersions {
    param(
        [string]$SharedPath
    )

    if ([string]::IsNullOrWhiteSpace($SharedPath) -or -not (Test-Path -LiteralPath $SharedPath)) {
        return @()
    }

    foreach ($dir in Get-ChildItem -LiteralPath $SharedPath -Directory -ErrorAction SilentlyContinue) {
        $parsed = $null
        if ([version]::TryParse($dir.Name, [ref]$parsed)) {
            $parsed
        }
    }
}

try {
    # Discover what's actually installed for the configured architecture.
    $sharedPath = Get-DesktopRuntimeSharedPath -Architecture $Architecture
    $installedVersions = @(Get-InstalledDesktopRuntimeVersions -SharedPath $sharedPath)

    # Parse the configured bounds once up front; $maxVersionParsed stays $null when no upper
    # bound is configured, which the range check below treats as "no max".
    $minVersionParsed = [version]$MinVersion
    $maxVersionParsed = $null
    if (-not [string]::IsNullOrWhiteSpace($MaxVersion)) {
        $maxVersionParsed = [version]$MaxVersion
    }

    # Diagnostic context surfaced to Intune's app detection log for troubleshooting.
    Write-Output "Architecture: $Architecture"
    Write-Output "Shared path:  $(if ($sharedPath) { $sharedPath } else { 'n/a' })"
    Write-Output "Min version:  $MinVersion ($(if ($MinVersionInclusive) { 'inclusive' } else { 'exclusive' }))"
    if ($maxVersionParsed) {
        Write-Output "Max version:  $MaxVersion ($(if ($MaxVersionInclusive) { 'inclusive' } else { 'exclusive' }))"
    } else {
        Write-Output "Max version:  none"
    }
    Write-Output "Installed:    $(if ($installedVersions.Count -gt 0) { (($installedVersions | Sort-Object) -join ', ') } else { 'none found' })"

    # Compliant if at least one installed version falls within [$MinVersion, $MaxVersion],
    # honoring the configured inclusive/exclusive bounds.
    $matchingVersion = $installedVersions | Where-Object {
        $meetsMin = if ($MinVersionInclusive) { $_ -ge $minVersionParsed } else { $_ -gt $minVersionParsed }
        $meetsMax = if ($null -eq $maxVersionParsed) {
            $true
        } elseif ($MaxVersionInclusive) {
            $_ -le $maxVersionParsed
        } else {
            $_ -lt $maxVersionParsed
        }
        $meetsMin -and $meetsMax
    } | Select-Object -First 1

    # Intune's custom detection script contract: exit 0 + STDOUT output means "detected"/compliant,
    # any non-zero exit code means "not detected" regardless of what was written to STDOUT.
    if ($matchingVersion) {
        Write-Output "Compliant: found .NET Desktop Runtime $matchingVersion ($Architecture) within range"
        exit 0
    }

    Write-Output "Not compliant: no installed .NET Desktop Runtime ($Architecture) version within range"
    exit 1
}
catch {
    # Any unexpected error (e.g. inaccessible path) is treated as non-compliant rather than
    # surfacing as an unhandled exception, which Intune would otherwise log as a script failure.
    Write-Output "Not compliant: $($_.Exception.Message)"
    exit 1
}
