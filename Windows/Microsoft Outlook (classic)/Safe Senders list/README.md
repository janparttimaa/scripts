# Microsoft Outlook (classic) - Safe Senders list

This example deploys a Safe Senders list (text file) to managed Windows devices. The text file ontaining a list of e-mail addresses to append to or overwrite the Safe Senders list. This text file only works on Microsoft Outlook (classic).

## PSAppDeployToolkit (PSADT)

### Pre-Install
```
    ## <Perform Pre-Installation tasks here>

    # Replace "Example" with your company name e.g. "Contoso"
    $CorporateName = "Example"
```

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Deploying Safe Senders list to Microsoft Outlook (classic)..." -Source 'Info'
    New-ADTFolder -LiteralPath "$envProgramFiles\$CorporateName\Microsoft Outlook (classic) - Safe Senders list"
    Copy-ADTFile -Path "$($adtSession.DirSupportFiles)\SafeSenders.txt" -Destination "$envProgramFiles\$CorporateName\Microsoft Outlook (classic) - Safe Senders list\SafeSenders.txt"
```

### Post-Install
```
    ## <Perform Post-Installation tasks here>

    # Let's create registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Creating registry key for Microsoft Intune or Microsoft Configuration Manager detection rule purposes..." -Source 'Info'
    
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Outlook (classic) - Safe Senders list" -Name 'Status' -Type 'String' -Value "Implemented"
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Outlook (classic) - Safe Senders list" -Name 'AppVersion' -Type 'String' -Value $($adtSession.AppVersion)

    Write-ADTLogEntry -Message "All done" -Source 'Info'
```

### Pre-Uninstall
```
    ## <Perform Pre-Installation tasks here>

    # Replace "Example" with your company name e.g. "Contoso"
    $CorporateName = "Example"
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    # Removing Safe Senders list from Microsoft Outlook (classic)
    Write-ADTLogEntry -Message "Removing Safe Senders list from Microsoft Outlook (classic)..." -Source 'Info'

    Remove-ADTFolder -Path "$envProgramFiles\$CorporateName\Microsoft Outlook (classic) - Safe Senders list"
```

### Post-Uninstall
```
    ## <Perform Post-Uninstallation tasks here>

    # Registry paths
    $RegistryPath = "HKLM:\SOFTWARE\$CorporateName\Microsoft Outlook (classic) - Safe Senders list"

    # Let's remove registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Removing registry key used for Microsoft Intune or Configuration Manager detection rules..." -Source 'Info'
    
    Remove-ADTRegistryKey -LiteralPath $RegistryPath
```