# Services - DataSnipperStartupService (DataSnipperStartupService.exe)

More information: https://knowledge.datasnipper.com/en/articles/694337-install-datasnipper-for-users-in-a-terminal-or-citrix-environment

## PSAppDeployToolkit (PSADT)

### Install
```
   ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Setting the DataSnipperStartupService (DataSnipperStartupService.exe) service to Disabled..." -Source 'Info'
    Set-ADTServiceStartMode -Service 'DataSnipperStartupService.exe' -StartMode 'Disabled'
    Write-ADTLogEntry -Message "Stopping the DataSnipperStartupService (DataSnipperStartupService.exe) service..." -Source 'Info'
    Stop-ADTServiceAndDependencies -Name 'DataSnipperStartupService.exe'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
