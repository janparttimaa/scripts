# Microsoft Copilot - Uninstallation

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "No installation required" -Source 'Info'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "Uninstalling application: Copilot" -Source 'Info'
    Uninstall-ADTApplication -Name 'Copilot' -NameMatch "Exact" -FilterScript { $_.Publisher -eq "Microsoft Corporation" } -IgnoreExitCodes "*"
```

## Microsoft Intune

### Detection Method
Use either these file paths:
- C:\Program Files (x86)\Microsoft\Copilot\Application\mscopilot.exe
- C:\Program Files (x86)\Microsoft\Copilot\Application\mscopilot_proxy.exe

or following registry key:
- HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Copilot