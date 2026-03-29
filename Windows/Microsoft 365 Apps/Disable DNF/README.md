# Microsoft 365 Apps - Disable "Do Not Forward"

Turns off "Do Not Forward" option from Outlook (classic). Recommended for Microsoft Purview Information Protection.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Turn off 'Do Not Forward' option from Outlook (classic)..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common\DRM' -Name 'DisableDNF' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```