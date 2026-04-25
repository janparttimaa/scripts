# KeePassXC - Baseline

> [!NOTE]  
> Detection method script for Intune is here: [Detect-KeePassXCSettings.ps1](./Detect-KeePassXCSettings.ps1)

Ensures, that baseline settings are deployed and enforced to all employees.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    # Starting deployment of Baseline
    Write-ADTLogEntry -Message "Applying baseline settings to KeePassXC..." -Source 'Info'

    # Set required keys and values to 'General' section
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'General' -Key 'UpdateCheckMessageShown' -Value 'true' -Force

    # Set required keys and values to 'GUI' section
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'GUI' -Key 'Language' -Value 'en_US' -Force
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'GUI' -Key 'ColorPasswords' -Value 'true' -Force
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'GUI' -Key 'CheckForUpdates' -Value 'false' -Force

    # Finishing deployment of Baseline
    Write-ADTLogEntry -Message "Baseline settings has been deployed to KeePassXC" -Source 'Info'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    # Informing that uninstallation is not required
    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
