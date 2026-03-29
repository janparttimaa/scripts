# Workplace Join - Allow

Allow Azure AD / Entra ID Workplace Join on Windows devices.

More information: https://learn.microsoft.com/en-us/entra/identity/devices/hybrid-join-plan

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Allow Azure AD / Entra ID Workplace Join on Windows devices..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WorkplaceJoin' -Name 'BlockAADWorkplaceJoin' -Type 'DWord' -Value '0'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
