# Microsoft 365 Apps - Default File Type

Sets Microsoft 365 Apps default file format to Office Open XML formats.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Set Microsoft 365 Apps default file format to Office Open XML formats..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common\General' -Name 'ShownFileFmtPrompt' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
