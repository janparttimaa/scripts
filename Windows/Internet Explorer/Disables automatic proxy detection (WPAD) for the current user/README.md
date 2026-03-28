# Internet Explorer - Disable automatic proxy detection (WPAD) for the current user

Disables automatic proxy detection (WPAD) for the current user. This helps prevent unwanted proxy auto-discovery behavior and is commonly used as a security hardening measure.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Disable automatic proxy detection (WPAD) for the current user..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'AutoDetect' -Type 'DWord' -Value '0'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "Restoring default policy: Enable automatic proxy detection (WPAD) for the current user..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'AutoDetect' -Type 'DWord' -Value '1'
```
