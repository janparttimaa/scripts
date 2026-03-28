# File Explorer - Show file name extensions

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Show file name extensions in File Explorer..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type 'DWord' -Value '0'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "Restoring default File Explorer setting: Hide file name extensions..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt' -Type 'DWord' -Value '1'
```
