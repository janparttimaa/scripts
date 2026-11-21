```powershell
# ====================== USER CONFIGURATION: EDIT THESE VALUES ======================
# Configure this list with the exact saved Wi-Fi profile names to remove.
# These are usually the network SSIDs. Keep names in quotes, especially when
# they contain spaces, and uncomment each entry that should be removed.
$ProfilesToForget = @(
    # Examples only: replace them with your actual saved profile names.
    # "Office Wi-Fi",
    # "Guest Network",
    # "Warehouse Wi-Fi"
)
# Replace Contoso with your organization's registry key name.
$CompanyName = "Contoso"
# =========================== END USER CONFIGURATION ================================

# =========================== SCRIPT LOGIC: DO NOT EDIT =============================

# Remove blank entries from the list before validating it or looping over it.
$ProfilesToForget = @($ProfilesToForget | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })

# The certificate must include the Client Authentication EKU used by EAP-TLS.
$ClientAuthenticationOID = "1.3.6.1.5.5.7.3.2"
# Use one timestamp for certificate validity checks and the install-age check.
$Now = Get-Date
# This flag controls whether the script is allowed to make changes.
$CanProcessWifiProfiles = $true
# Initialize results before running checks so the variables are defined up front.
$WindowsInstallDate = $null
$HasWifiClientCertificate = $null
$NetshResult = $null
$NetshExitCode = $null
# Intune can detect successful completion by checking the configured HKCU values.
# Intune should map 1618 to Retry. Use 1 for a processing or detection error.
$HasDeploymentError = $false

# Check Windows' recorded installation date. A failed query also blocks changes
# because the script cannot safely verify the 48-hour minimum.
try {
    $WindowsInstallDate = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop).InstallDate
} catch {
    Write-ADTLogEntry -Message "Could not determine the Windows installation date. No Wi-Fi profiles were changed." -Severity Warning
    $CanProcessWifiProfiles = $false
}

# If Windows is younger than 48 hours, leave profiles untouched and request retry.
if ($CanProcessWifiProfiles -and (-not $WindowsInstallDate -or (($Now - $WindowsInstallDate) -lt [TimeSpan]::FromDays(2)))) {
    Write-ADTLogEntry -Message "Windows has been installed for less than 2 days. No Wi-Fi profiles were changed." -Severity Info
    $CanProcessWifiProfiles = $false
}

# Check the signed-in user's Personal store, not the Local Computer store. This
# script should run in user context so this store and HKCU refer to that user.
if ($CanProcessWifiProfiles) {
    $HasWifiClientCertificate = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.HasPrivateKey -and $_.NotBefore -le $Now -and $_.NotAfter -gt $Now -and $_.EnhancedKeyUsageList.ObjectId -contains $ClientAuthenticationOID } | Select-Object -First 1

    if (-not $HasWifiClientCertificate) {
        Write-ADTLogEntry -Message "No valid user Client Authentication certificate with a private key was found. No Wi-Fi profiles were changed." -Severity Info
        $CanProcessWifiProfiles = $false
    }
}

# Treat an empty configured list as a prerequisite failure so Intune retries
# instead of creating the detection key for a run that removed no profiles.
if ($CanProcessWifiProfiles -and $ProfilesToForget.Count -eq 0) {
    Write-ADTLogEntry -Message "A suitable user certificate was found, but no Wi-Fi profile names are configured. No profiles were changed" -Severity Info
    $CanProcessWifiProfiles = $false
}

if (-not $CanProcessWifiProfiles) {
    Write-ADTLogEntry -Message "Prerequisites are not met. Ending deployment with retry exit code 1618." -Severity Warning
    # Close the PSADT session with the code Intune is configured to retry.
    Close-ADTSession -ExitCode 1618
}

# Remove each configured saved profile. Ignore the PSADT process exit code so
# this script can inspect it and choose the deployment result itself.
foreach ($ProfileName in $ProfilesToForget) {
    try {
        $NetshResult = Start-ADTProcess -FilePath "$envSystem32Directory\netsh.exe" -ArgumentList @('wlan', 'delete', 'profile', "name=$ProfileName") -IgnoreExitCodes "*" -PassThru
        $NetshExitCode = $NetshResult.ExitCode

        if ($NetshExitCode -eq 0) {
            Write-ADTLogEntry -Message "Removed saved Wi-Fi profile (if existed): $ProfileName" -Severity Success
        } else {
            Write-ADTLogEntry -Message "Could not remove Wi-Fi profile '$ProfileName' (netsh exit code $NetshExitCode)" -Severity Warning
            $HasDeploymentError = $true
        }
    } catch {
        Write-ADTLogEntry -Message "Error while removing Wi-Fi profile '$ProfileName': $($_.Exception.Message)" -Severity Error
        $HasDeploymentError = $true
    }
}

# Write Intune detection values only after every profile removal command succeeds.
# Configure detection for the completion DWORD and, optionally, the version string.
if (-not $HasDeploymentError) {
    try {
        Set-ADTRegistryKey -LiteralPath "HKEY_CURRENT_USER\SOFTWARE\$CompanyName\WiFiProfileCleanup" -Name "Version" -Type "String" -Value $adtSession.AppVersion -ErrorAction Stop
        Set-ADTRegistryKey -LiteralPath "HKEY_CURRENT_USER\SOFTWARE\$CompanyName\WiFiProfileCleanup" -Name "WifiProfilesCleanupComplete" -Type "DWord" -Value 1 -ErrorAction Stop
        Write-ADTLogEntry -Message "Intune detection registry values created under HKEY_CURRENT_USER\SOFTWARE\$CompanyName\WiFiProfileCleanup." -Severity Success
    } catch {
        Write-ADTLogEntry -Message "Could not create Intune detection registry values: $($_.Exception.Message)" -Severity Error
        $HasDeploymentError = $true
    }
}

# Return success (0) or failure (1) to the deployment system and close PSADT.
if ($HasDeploymentError) {
    Close-ADTSession -ExitCode 1
} else {
    Close-ADTSession -ExitCode 0
}

```
