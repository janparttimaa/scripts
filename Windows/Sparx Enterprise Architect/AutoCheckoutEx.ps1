<#
.SYNOPSIS
    Configures EA64 AutoCheckoutEx per-user registry value

.DESCRIPTION
    Writes REG_BINARY AutoCheckoutEx under:
    HKCU\SOFTWARE\Sparx Systems\EA64\EA\OPTIONS

    AutoCheckoutEx indicates which product keys Enterprise Architect should automatically try to obtain on start-up. Each key is represented by 4 bytes; for example:
    
    hex:02,00,00,00
    
    Where bytes 1-2 are the license code (0200) and bytes 3-4 are the license type flag (0000).

    The setting applies per user and does not require administrative privileges.

    More information:
    https://sparxsystems.com/downloads/whitepapers/EA_Deployment.pdf

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
    Run the following command with your non administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\AutoCheckoutEx.ps1

    This is the recommended execution method when deploying the script via
    Microsoft Intune, or Microsoft Configuration Manager.

#>

$ErrorActionPreference = "Stop"

# Target registry path and value
$RegPath   = "HKCU:\SOFTWARE\Sparx Systems\EA64\EA\OPTIONS"
$ValueName = "AutoCheckoutEx"

# REG_BINARY data (Example: hex:02,00,00,00)
$ExpectedData = [byte[]](0x02, 0x00, 0x00, 0x00)

try {
    # Ensure key exists
    if (-not (Test-Path $RegPath)) {
        New-Item -Path $RegPath -Force | Out-Null
    }

    # Write REG_BINARY
    New-ItemProperty -Path $RegPath -Name $ValueName -PropertyType Binary -Value $ExpectedData -Force | Out-Null

    # Verify: length + byte-for-byte compare
    $ActualData = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName

    $sameLength = ($ActualData.Length -eq $ExpectedData.Length)
    $sameBytes  = $sameLength

    if ($sameLength) {
        for ($i = 0; $i -lt $ExpectedData.Length; $i++) {
            if ($ActualData[$i] -ne $ExpectedData[$i]) { $sameBytes = $false; break }
        }
    }

    if ($sameBytes) {
        Write-Output "SUCCESS: '$ValueName' written to $RegPath (REG_BINARY, $($ActualData.Length) bytes)."
        exit 0
    } else {
        Write-Error "FAILURE: '$ValueName' data mismatch. Expected $($ExpectedData.Length) bytes, got $($ActualData.Length) bytes."
        exit 1
    }
}
catch {
    Write-Error "FAILURE: $($_.Exception.Message)"
    exit 1
}
