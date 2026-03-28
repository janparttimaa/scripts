# File Explorer - Create directory "C:\Temp"

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Creating directory C:\Temp if it does not exist" -Source 'Info'
    New-ADTFolder -LiteralPath "C:\Temp"
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "Removing directory C:\Temp if it does exist" -Source 'Info'
    Remove-ADTFolder -Path "C:\Temp"
```
