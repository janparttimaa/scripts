<#
.SYNOPSIS
  Intune Detection Script: EA64 AutoCheckoutEx (per-user)

.DESCRIPTION
  Detects whether REG_BINARY AutoCheckoutEx under:
  HKCU\SOFTWARE\Sparx Systems\EA64\EA\OPTIONS
  matches the expected bytes.

  Intune logic:
    - Exit 0 => Detected / Compliant
    - Exit 1 => Not detected / Non-compliant

  Manual run:
    - Writes a clear compliance message to output.

.VERSION
  20260125

.AUTHOR
  Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20260125 - Initial release

.EXAMPLE
    Run the following command with your non administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Detect-AutoCheckoutEx.ps1

    When using this on Microsoft intune, use this as a detection method.
    
    More information:
    https://learn.microsoft.com/en-us/intune/intune-service/apps/apps-win32-add

#>

$ErrorActionPreference = "Stop"

# Target registry path and value
$RegPath   = "HKCU:\SOFTWARE\Sparx Systems\EA64\EA\OPTIONS"
$ValueName = "AutoCheckoutEx"

# Expected REG_BINARY data
$ExpectedData = [byte[]](0x02, 0x00, 0x00, 0x00)

function Write-ComplianceResult {
    param(
        [bool]$Compliant,
        [string]$Message
    )

    if ($Compliant) {
        Write-Output "COMPLIANT: $Message"
        exit 0
    } else {
        Write-Output "NON-COMPLIANT: $Message"
        exit 1
    }
}

try {
    # Key must exist
    if (-not (Test-Path $RegPath)) {
        Write-ComplianceResult -Compliant:$false -Message "Registry key not found: $RegPath"
    }

    # Value must exist
    $prop = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
    if ($null -eq $prop) {
        Write-ComplianceResult -Compliant:$false -Message "Registry value not found: '$ValueName' under $RegPath"
    }

    # Ensure the value is actually Binary (REG_BINARY)
    # (PowerShell can read the bytes regardless, but Intune detection should be strict.)
    $valueKind = (Get-Item -Path $RegPath).GetValueKind($ValueName)
    if ($valueKind -ne [Microsoft.Win32.RegistryValueKind]::Binary) {
        Write-ComplianceResult -Compliant:$false -Message "Value '$ValueName' is not REG_BINARY (found: $valueKind)."
    }

    # Read actual bytes
    $ActualData = (Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction Stop).$ValueName

    if ($null -eq $ActualData) {
        Write-ComplianceResult -Compliant:$false -Message "Value '$ValueName' exists but is empty/null."
    }

    # Compare length
    if ($ActualData.Length -ne $ExpectedData.Length) {
        Write-ComplianceResult -Compliant:$false -Message "Byte length mismatch. Expected $($ExpectedData.Length), got $($ActualData.Length)."
    }

    # Compare bytes
    for ($i = 0; $i -lt $ExpectedData.Length; $i++) {
        if ($ActualData[$i] -ne $ExpectedData[$i]) {
            $expectedHex = ($ExpectedData | ForEach-Object { '{0:X2}' -f $_ }) -join ','
            $actualHex   = ($ActualData   | ForEach-Object { '{0:X2}' -f $_ }) -join ','
            Write-ComplianceResult -Compliant:$false -Message "Data mismatch at index $i. Expected [$expectedHex], got [$actualHex]."
        }
    }

    # All good
    $hex = ($ActualData | ForEach-Object { '{0:X2}' -f $_ }) -join ','
    Write-ComplianceResult -Compliant:$true -Message "'$ValueName' matches expected REG_BINARY ($($ActualData.Length) bytes): [$hex] under $RegPath"
}
catch {
    Write-ComplianceResult -Compliant:$false -Message "Detection error: $($_.Exception.Message)"
}