# Admin control for SSO prompts in Windows

Automtically accept "Continue to sign in?" prompts.

More information: 
- https://learn.microsoft.com/en-us/entra/identity/devices/sso-admin-control
- https://techcommunity.microsoft.com/blog/windows-itpro-blog/now-available-admin-control-for-sso-prompts-in-windows/4534613

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Admin control for SSO prompts..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AAD' -Name 'AutoAcceptSsoPermission' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
