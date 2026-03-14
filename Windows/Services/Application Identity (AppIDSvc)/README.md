# Services - Application Identity (AppIDSvc)

## PSAppDeployToolkit (PSADT)

### Install
```
   ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Setting the Application Identity (AppIDSvc) service to Automatic to enable AppLocker..." -Source 'Info'
    Set-ADTServiceStartMode -Service 'AppIDSvc' -StartMode 'Automatic'
    Write-ADTLogEntry -Message "Starting the Application Identity (AppIDSvc) service to enable AppLocker..." -Source 'Info'
    Start-ADTServiceAndDependencies -Name 'AppIDSvc'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
