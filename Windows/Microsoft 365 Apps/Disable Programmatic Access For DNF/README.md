# Microsoft 365 Apps - Disable programmatic access for "Do Not Forward"

Disable programmatic access for "Do Not Forward". Recommended for Microsoft Purview Information Protection. Addresses a security issue where, if this registry key is not set, users can bypass Purview Information Protection when the Recipients Only label is applied to content. If the key is missing, end users can save labeled/protected content as a PDF, and the saved file may have the protection removed.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Disable programmatic access for 'Do Not Forward'..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_CURRENT_USER\Software\Microsoft\Office\16.0\Common\DRM' -Name 'DisableProgrammaticAccessForDNF' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
