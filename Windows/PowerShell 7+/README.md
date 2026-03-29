# PowerShell 7+ - UseMU

Configures PowerShell 7+ to opt into updating through Microsoft Update (MU), WSUS, or Configuration Manager.

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Opts into updating PowerShell 7+ through Microsoft Update, WSUS, or Configuration Manager..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShellCore' -Name 'UseMU' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
