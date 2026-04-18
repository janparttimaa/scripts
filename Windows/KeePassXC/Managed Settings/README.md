# KeePassXC - Managed Settings

Ensures, that managed settings are deployed and enforced to all employees.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    # Starting deployment of managed settings
    Write-ADTLogEntry -Message "Applying managed settings to KeePassXC..." -Source 'Info'

    # Set required keys and values to 'General' section
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'General' -Key 'UpdateCheckMessageShown' -Value 'true' -Force

    # Set required keys and values to 'GUI' section
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'GUI' -Key 'Language' -Value 'en_US' -Force
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'GUI' -Key 'ColorPasswords' -Value 'true' -Force
    Set-ADTIniValue -FilePath "$envAppData\KeePassXC\keepassxc.ini" -Section 'GUI' -Key 'CheckForUpdates' -Value 'false' -Force

    # Finishing deployment of managed settings
    Write-ADTLogEntry -Message "Managed settings has been deployed to KeePassXC" -Source 'Info'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
