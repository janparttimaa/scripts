# Microsoft 365 Apps - Accept all EULAs

Accepts all Microsoft 365 Apps EULAs for the current user via registry policy.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Accept all Microsoft 365 Apps EULAs..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Registration' -Name 'AcceptAllEulas' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
