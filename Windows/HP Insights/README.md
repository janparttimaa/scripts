# HP Insights

> [!NOTE]  
> Additional requirement rule script for Intune is here: [Check-DeviceManufacturerHP.ps1](./Check-DeviceManufacturerHP.ps1)
> This script will make sure, that HP Insight will be deployed only to HP-devices.
> Screenshot of deployment settings:
> <kbd><img src= "../img/screenshot01.png" alt="Screenshot of Microsoft Intune requirement rule settings for the additional requirements script used by the HP Insights app."> </kbd>

## PSAppDeployToolkit (PSADT)

### Pre-Installation
```powershell
    ## <Perform Pre-Installation tasks here>

    # Variable: Define Company PIN
    $CompanyPIN = "<COMPANY PIN CODE>"

    # Checking if device manufacturer is HP or Hewlett-Packard. If not, we will inform this and cancel the installation. 
    # This is because HP Insight is only for HP-devices. 
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

        Write-ADTLogEntry -Message "Detected device manufacturer: $Manufacturer" -Source 'Info'
        Write-ADTLogEntry -Message "Normalized value: $Normalized" -Source 'Info'

        # Check if manufacturer matches allowed values
        if (
            $Normalized -eq "hp" -or
            $Normalized -eq "hp inc" -or
            $Normalized -eq "hewlett-packard" -or
            $Normalized -eq "hewlett packard"
        ) {
            Write-ADTLogEntry -Message "Requirement satisfied: Supported device manufacturer" -Source 'Info'
        }
        else {
            Write-ADTLogEntry -Message "Requirement not met: Unsupported device manufacturer" -Source 'Info'
            Show-ADTInstallationPrompt -Title "$($adtSession.AppName)" -Message "Requirement not met: Unsupported device manufacturer. This application can be only installed to HP-devices. We cannot proceed installation of $($adtSession.AppName)." -MessageAlignment 'Left' -ButtonRightText 'OK' -NoWait
            Close-ADTSession -ExitCode 69000
        }
    }
    catch {
        # Handle unexpected errors
        Write-ADTLogEntry -Message "Requirement check failed: $($_.Exception.Message)" -Source 'Info'
        Show-ADTInstallationPrompt -Title "$($adtSession.AppName)" -Message "Requirement check failed: $($_.Exception.Message). We cannot proceed installation of $($adtSession.AppName)." -MessageAlignment 'Left' -ButtonRightText 'OK' -NoWait
        Close-ADTSession -ExitCode 69000
    }

    # Checking if prerequired application is installed (1/4): Microsoft Visual C++ 2015-2022 Redistributable (x86).
    # If not, it will be installed. Otherwise, we don't need to install anything before installing HP Insights.
    Write-ADTLogEntry -Message "Checking does device have following prerequisite application installed (1/4): Microsoft Visual C++ 2015-2022 Redistributable (x86)" -Source 'Info'

    $VCRedistx86 = Get-ADTApplication -Name 'Microsoft Visual C++ 2015-2022 Redistributable (x86)' -NameMatch 'Contains'

    if($VCRedistx86) {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x86) already installed. No need to install it. Let's continue..." -Source 'Info'
    } else {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x86) not installed. This is pre-requirement (1/4) for HP Insights. Installing it now..." -Source 'Info'
        Start-ADTProcess -FilePath 'vc_redist.x86.exe' -ArgumentList '/install /quiet /norestart'
    }

    # Checking if prerequired application is installed (2/4): Microsoft Visual C++ 2015-2022 Redistributable (x64).
    # If not, it will be installed. Otherwise, we don't need to install anything before installing HP Insights.
    Write-ADTLogEntry -Message "Checking does device have following prerequisite application installed (2/4): Microsoft Visual C++ 2015-2022 Redistributable (x64)" -Source 'Info'

    $VCRedistx64 = Get-ADTApplication -Name 'Microsoft Visual C++ 2015-2022 Redistributable (x64)' -NameMatch 'Contains'

    if($VCRedistx64) {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x64) already installed. No need to install it. Let's continue..." -Source 'Info'
    } else {
        Write-ADTLogEntry -Message "Microsoft Visual C++ 2015-2022 Redistributable (x64) not installed. This is pre-requirement (2/4) for HP Insights. Installing it now..." -Source 'Info'
        Start-ADTProcess -FilePath 'vc_redist.x64.exe' -ArgumentList '/install /quiet /norestart'
    }

    # Checking if prerequired application is installed (3/4): HP Insights Analytics - Dependencies.
    # If not, it will be installed. Otherwise, we don't need to install anything before installing HP Insights.
    Write-ADTLogEntry -Message "Checking does device have following prerequisite application installed (3/4): HP Insights Analytics - Dependencies" -Source 'Info'

    $HPInsightsAnalyticsDependencies = Get-ADTApplication -Name 'HP Insights Analytics - Dependencies' -NameMatch 'Exact'

    if($HPInsightsAnalyticsDependencies) {
        Write-ADTLogEntry -Message "HP Insights Analytics - Dependencies already installed. No need to install it. Let's continue..." -Source 'Info'
    } else {
        Write-ADTLogEntry -Message "HP Insights Analytics - Dependencies not installed. This is pre-requirement (3/4) for HP Insights. Installing it now..." -Source 'Info'
        Start-ADTMsiProcess -Action 'Install' -FilePath 'HPInsightsAnalyticsDependencies.msi' -ArgumentList '/quiet /norestart'
    }

    # Checking if prerequired application is installed (4/4): HP Insights Analytics.
    # If not, it will be installed. Otherwise, we don't need to install anything before installing HP Insights.
    Write-ADTLogEntry -Message "Checking does device have following prerequisite application installed (4/4): HP Insights Analytics" -Source 'Info'

    $HPInsightsAnalytics = Get-ADTApplication -Name 'HP Insights Analytics' -NameMatch 'Exact'

    if($HPInsightsAnalytics) {
        Write-ADTLogEntry -Message "HP Insights Analytics already installed. No need to install it. Let's continue..." -Source 'Info'
    } else {
        Write-ADTLogEntry -Message "HP Insights Analytics not installed. This is pre-requirement (4/4) for HP Insights. Installing it now..." -Source 'Info'
        Start-ADTMsiProcess -Action 'Install' -FilePath 'HPInsightsAnalytics.msi' -ArgumentList '/quiet /norestart /l*v ta-log.txt'
    }
```

### Install
```powershell
    ## <Perform Installation tasks here>

    # Installation command for HP Insights
    Start-ADTMsiProcess -Action 'Install' -FilePath 'HPInsights.msi' -ArgumentList "CPIN=$CompanyPIN HIDETRAY=True /quiet /l*v tm-log.txt /norestart"
```

### Uninstall
```powershell
    ## <Perform Uninstallation tasks here>

    # Uninstallation command for HP Insights
    Uninstall-ADTApplication -Name 'HP Insights' -NameMatch 'Exact' -FilterScript { $_.Publisher -match 'HP Inc.' } -IgnoreExitCodes '*'
```

### Post-Uninstallation
```powershell
    # Uninstallation command for HP Insights Analytics
    Uninstall-ADTApplication -Name 'HP Insights Analytics' -NameMatch 'Exact' -FilterScript { $_.Publisher -match 'HP Inc.' } -IgnoreExitCodes '*'

    # Uninstallation command for HP Insights Analytics - Dependencies
    Uninstall-ADTApplication -Name 'HP Insights Analytics - Dependencies' -NameMatch 'Exact' -FilterScript { $_.Publisher -match 'HP Inc.' } -IgnoreExitCodes '*'
```
