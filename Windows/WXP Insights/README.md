# WXP Insights

> [!NOTE]  
> Additional requirement rule script for Intune is here: [Check-DeviceManufacturerHP.ps1](./Check-DeviceManufacturerHP.ps1)
> This script will make sure, that WXP Insight will be deployed only to HP-devices.
> Screenshot of deployment settings:
> <tr>
> <kbd><img src= "./img/screenshot01.png" alt="Screenshot of Microsoft Intune requirement rule settings for the additional requirements script used by the WXP Insights app."/> </kbd>

## PSAppDeployToolkit (PSADT)

### Pre-Installation
```powershell
    ## <Perform Pre-Installation tasks here>

    # Checking if device manufacturer is HP or Hewlett-Packard. If not, we will inform this and cancel the installation. 
    # This is because WXP Insight is only for HP-devices. 
    # If device manufacturer is HP or Hewlett-Packard, we can proceed.
    # For close the installation if devcie manufacturer is not HP or Hewlett-Packard, we will use custom exit code 69000 recommended by PSAppDeployToolkit.
    
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

        Write-ADTLogEntry -Message "Detected device manufacturer: $Manufacturer" -Source "Info"
        Write-ADTLogEntry -Message "Normalized value: $Normalized" -Source "Info"

        # Check if manufacturer matches allowed values
        if (
            $Normalized -eq "hp" -or
            $Normalized -eq "hp inc" -or
            $Normalized -eq "hewlett-packard" -or
            $Normalized -eq "hewlett packard"
        ) {
            Write-ADTLogEntry -Message "Requirement satisfied: Supported device manufacturer" -Source "Info"
        }
        else {
            Write-ADTLogEntry -Message "Requirement not met: Unsupported device manufacturer" -Source "Info"
            Show-ADTInstallationPrompt -Title "$($adtSession.AppName)" -Message "Requirement not met: Unsupported device manufacturer. This application can be only installed to HP-devices. We cannot proceed installation of $($adtSession.AppName)." -MessageAlignment "Left" -ButtonRightText "OK" -NoWait
            Close-ADTSession -ExitCode 69000
        }
    }
    catch {
        # Handle unexpected errors
        Write-ADTLogEntry -Message "Requirement check failed: $($_.Exception.Message)" -Source "Info"
        Show-ADTInstallationPrompt -Title "$($adtSession.AppName)" -Message "Requirement check failed: $($_.Exception.Message). We cannot proceed installation of $($adtSession.AppName)." -MessageAlignment "Left" -ButtonRightText "OK" -NoWait
        Close-ADTSession -ExitCode 69000
    }

    # Checking if prerequired application is installed (1/2): Microsoft Visual C++ 2015-2022 Redistributable (x86).
    # If not, it will be installed. Otherwise, we don't need to install anything before installing WXP Insights.
    Write-ADTLogEntry -Message "Checking does device have following prerequisite application installed (1/2): Microsoft Visual C++ 2015-2022 Redistributable (x86)" -Source "Info"

    $VCRedistx86 = Get-ADTApplication -Name "Microsoft Visual C++ 2015-2022 Redistributable (x86)" -NameMatch "Contains"

    if($VCRedistx86) {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x86) already installed. No need to install it. Let's continue..." -Source "Info"
    } else {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x86) not installed. This is pre-requirement (1/2) for WXP Insights. Installing it now..." -Source "Info"
        Start-ADTProcess -FilePath "vc_redist.x86.exe" -ArgumentList "/install /quiet /norestart"
    }

    # Checking if prerequired application is installed (2/2): Microsoft Visual C++ 2015-2022 Redistributable (x64).
    # If not, it will be installed. Otherwise, we don't need to install anything before installing WXP Insights.
    Write-ADTLogEntry -Message "Checking does device have following prerequisite application installed (2/2): Microsoft Visual C++ 2015-2022 Redistributable (x64)" -Source "Info"

    $VCRedistx64 = Get-ADTApplication -Name "Microsoft Visual C++ 2015-2022 Redistributable (x64)" -NameMatch "Contains"

    if($VCRedistx64) {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x64) already installed. No need to install it. Let's continue..." -Source "Info"
    } else {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x64) not installed. This is pre-requirement (2/2) for WXP Insights. Installing it now..." -Source "Info"
        Start-ADTProcess -FilePath "vc_redist.x64.exe" -ArgumentList "/install /quiet /norestart"
    }

    # Uninstallation of previous installation of WXP Insights, WXP Insights Analytics and WXP Insights Analytics - Dependencies
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Uninstallation process of previous 'WXP Insights', 'WXP Insights Analytics Client' and 'WXP Insights Analytics - Dependencies' application installations started..." -Source "Info"

    # Reset the consent to unknown
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Resetting Consent to unknown..." -Source "Info"
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowMarketing" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowNecessary" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowProductEnhancement" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowSupport" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AnyConsentWasAccepted" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowTransferOutOfCountry" -Value "Unknown" -Type String
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Consent has set to unknown." -Source "Info"

    # Disable the services
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabling HP Service Scan Service..." -Source "Info"
    Stop-ADTServiceAndDependencies -Name "hpsvcsscan"
    Set-ADTServiceStartMode -Service "hpsvcsscan" -StartMode "Disabled"
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabled HP Service Scan Service." -Source "Info"

    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabling hptpsmarthealthservice..." -Source "Info"
    Stop-ADTServiceAndDependencies -Name "hptpsmarthealthservice"
    Set-ADTServiceStartMode -Service "hptpsmarthealthservice" -StartMode "Disabled"
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabled hptpsmarthealthservice." -Source "Info"

    # Uninstall the applications
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Uninstalling the applications..." -Source "Info"
    Stop-ADTServiceAndDependencies -Name "HPTouchpointManagerTray"
    Uninstall-ADTApplication -Name "WXP Insights" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "HP Insights" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "WXP Insights Analytics" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "HP Insights Analytics" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "WXP Insights Analytics - Dependencies" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "HP Insights Analytics - Dependencies" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"

    # Remove the folders
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Removing the folders..." -Source "Info"
    Remove-ADTFolder -Path "$envProgramFilesX86\Hewlett-Packard\HP Touchpoint Manager"
    Remove-ADTFolder -Path "$envProgramFiles\HP\HP Touchpoint Analytics Client"
    Remove-ADTFolder -Path "$envProgramFilesX86\HP\HP Touchpoint Analytics Client"

```

### Install
```powershell
    ## <Perform Installation tasks here>

    # Variable: Define Company PIN
    $CompanyPIN = "<COMPANY PIN CODE>"

    # Installation command for WXP Insight Analytics - Dependencies
    Start-ADTMsiProcess -Action "Install" -FilePath "WXPInsightsAnalyticsDependencies.msi" -ArgumentList "/quiet /norestart"

    # Installation command for WXP Insight Analytics
    Start-ADTMsiProcess -Action "Install" -FilePath "WXPInsightsAnalytics.msi" -ArgumentList "/quiet /norestart"

    # Installation command for WXP Insights
    Start-ADTMsiProcess -Action "Install" -FilePath "WXPInsights.msi" -ArgumentList "CPIN=$CompanyPIN HIDETRAY=True /quiet /norestart"
```

### Uninstall
```powershell
    ## <Perform Uninstallation tasks here>

    # Uninstallation of WXP Insights, WXP Insights Analytics and WXP Insights Analytics - Dependencies
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Uninstallation process of 'WXP Insights', 'WXP Insights Analytics Client' and 'WXP Insights Analytics - Dependencies' applications installation started..." -Source "Info"

    # Reset the consent to unknown
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Resetting Consent to unknown..." -Source "Info"
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowMarketing" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowNecessary" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowProductEnhancement" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowSupport" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AnyConsentWasAccepted" -Value "Unknown" -Type String
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\HP\Consent" -Name "AllowTransferOutOfCountry" -Value "Unknown" -Type String
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Consent has set to unknown." -Source "Info"

    # Disable the services
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabling HP Service Scan Service..." -Source "Info"
    Stop-ADTServiceAndDependencies -Name "hpsvcsscan"
    Set-ADTServiceStartMode -Service "hpsvcsscan" -StartMode "Disabled"
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabled HP Service Scan Service." -Source "Info"

    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabling hptpsmarthealthservice..." -Source "Info"
    Stop-ADTServiceAndDependencies -Name "hptpsmarthealthservice"
    Set-ADTServiceStartMode -Service "hptpsmarthealthservice" -StartMode "Disabled"
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Disabled hptpsmarthealthservice." -Source "Info"

    # Uninstall the applications
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Uninstalling the applications..." -Source "Info"
    Stop-ADTServiceAndDependencies -Name "HPTouchpointManagerTray"
    Uninstall-ADTApplication -Name "WXP Insights" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "HP Insights" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "WXP Insights Analytics" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "HP Insights Analytics" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "WXP Insights Analytics - Dependencies" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"
    Uninstall-ADTApplication -Name "HP Insights Analytics - Dependencies" -NameMatch "Exact" -FilterScript { $_.Publisher -match "HP Inc." } -IgnoreExitCodes "*"

    # Remove the folders
    Write-ADTLogEntry -Message "[WXP Insights Uninstallation] Removing the folders..." -Source "Info"
    Remove-ADTFolder -Path "$envProgramFilesX86\Hewlett-Packard\HP Touchpoint Manager"
    Remove-ADTFolder -Path "$envProgramFiles\HP\HP Touchpoint Analytics Client"
    Remove-ADTFolder -Path "$envProgramFilesX86\HP\HP Touchpoint Analytics Client"
```