# Microsoft 365 Apps - Safe Recipients list for Microsoft Outlook (classic)

This example deploys a Safe Recipients list (text file) to managed Windows devices. The text file contains a list of email addresses that are appended to or used to overwrite the Safe Recipients list. This text file only works on Microsoft Outlook (classic).

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

    Write-ADTLogEntry -Message "Deploying Safe Recipients list to Microsoft Outlook (classic)..." -Source 'Info'
    New-ADTFolder -LiteralPath "$envProgramFiles\$CorporateName\Safe Recipients list for Microsoft Outlook (classic)"
    Copy-ADTFile -Path "$($adtSession.DirSupportFiles)\SafeSenders.txt" -Destination "$envProgramFiles\$CorporateName\Safe Recipients list for Microsoft Outlook (classic)\SafeSenders.txt"
```

### Post-Install
```
    ## <Perform Post-Installation tasks here>

    # Let's create registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Creating registry key for Microsoft Intune or Microsoft Configuration Manager detection rule purposes..." -Source 'Info'
    
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Safe Recipients list for Microsoft Outlook (classic)" -Name 'Status' -Type 'String' -Value "Implemented"

    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Safe Recipients list for Microsoft Outlook (classic)" -Name 'AppVersion' -Type 'String' -Value $($adtSession.AppVersion)

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

    # Inform to the log that policy of allowed extensions from Visual Studio Code will be removed
    Write-ADTLogEntry -Message "Removing Safe Recipients list from Microsoft Outlook (classic)..." -Source 'Info'

    Remove-ADTFolder -Path "$envProgramFiles\$CorporateName\Safe Recipients list for Microsoft Outlook (classic)"
```

### Post-Uninstall
```
    ## <Perform Post-Uninstallation tasks here>

    # Registry paths
    $regPath = "HKLM:\SOFTWARE\$CorporateName\Safe Recipients list for Microsoft Outlook (classic)"

    # Let's remove registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Removing registry key used for Microsoft Intune or Configuration Manager detection rules..." -Source 'Info'
    
    Remove-ADTRegistryKey -LiteralPath $regPath
```