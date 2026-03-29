# Windows 1x - Turn off "Notify when apps request location" setting

Turns off "Notify when apps request location" setting in Windows 1x.

More information: https://www.elevenforum.com/t/turn-on-or-off-notify-when-apps-request-location-in-windows-11.18578/

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Turn off 'Notify when apps request location' setting in Windows 1x..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location' -Name 'ShowGlobalPrompts' -Type 'DWord' -Value '0'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
