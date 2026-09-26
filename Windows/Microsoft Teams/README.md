# Microsoft Teams

Installs offline installer of Microsoft Teams

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Start-ADTProcess -FilePath "teamsbootstrapper.exe" -ArgumentList "-p -o `"$($adtSession.DirFiles)\MSTeams-x64.msix`"" -WindowStyle "Hidden"
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
