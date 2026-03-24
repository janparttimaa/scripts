# Services - Windows Defender Advanced Threat Protection Service (Sense)

## PSAppDeployToolkit (PSADT)

### Install
```
   ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Setting startup type of Windows Defender Advanced Threat Protection Service (Sense) to Automatic..." -Source 'Info'
    Set-ADTServiceStartMode -Service 'Sense' -StartMode 'Automatic'
    Write-ADTLogEntry -Message "Starting Windows Defender Advanced Threat Protection Service (Sense)..." -Source 'Info'
    Start-ADTServiceAndDependencies -Name 'Sense'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
