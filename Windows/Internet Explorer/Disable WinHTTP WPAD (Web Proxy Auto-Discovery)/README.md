# Internet Explorer - Disable WinHTTP WPAD (Web Proxy Auto-Discovery)

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Disable WinHTTP WPAD (Web Proxy Auto-Discovery)..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "Restoring default policy: Enable WinHTTP WPAD (Web Proxy Auto-Discovery)..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name 'DisableWpad' -Type 'DWord' -Value '0'
```
