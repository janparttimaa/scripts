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
    Remove-ADTFolder -Path "$envProgramFilesX86\Microsoft\Copilot"
```
