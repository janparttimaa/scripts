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

    # Uninstallation command for Microsoft Copilot.
    Write-ADTLogEntry -Message "Uninstalling application: Copilot" -Source 'Info'
    Uninstall-ADTApplication -Name 'Copilot' -NameMatch "Exact" -FilterScript { $_.Publisher -eq "Microsoft Corporation" } -IgnoreExitCodes "*"
    
    # Checking that Copilot have been uninstalled successfully.
    # If yes, we can proceed. If not, we cannot proceed and uninstallation is closed with exit code 6900 recommended by PSAppDeployToolkit.
    $copilot = Get-ADTApplication -Name 'Copilot' -NameMatch "Exact" -FilterScript { $_.Publisher -eq "Microsoft Corporation" }

    if ($copilot) {
        Write-ADTLogEntry -Message "Copilot not uninstalled successfully. We cannot proceed. Terminating uninstallation..." -Source 'Info'
        Close-ADTSession -ExitCode 69000
    } else {
        Write-ADTLogEntry -Message "Copilot uninstalled successfully or it was not previously installed. We can continue forward." -Source 'Info'
    }
```

### Post-Uninstall
```
    ## <Perform Post-Uninstallation tasks here>
    
    # Setting variables.
    $runKey = 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
    $wildcard = 'MicrosoftCopilotAutoLaunch*'

    # Removing Microsoft Copilot remainer from startup apps.
    Invoke-ADTAllUsersRegistryAction -ScriptBlock {
        $registryValues = Get-ADTRegistryKey -Key $runKey -SID $_.SID

        if ($null -eq $registryValues) {
            Write-ADTLogEntry -Message "Run key not found or contains no values for SID [$($_.SID)]." -Source 'Info'
            return
        }

        $matchingValueNames = $registryValues.PSObject.Properties | Where-Object { $_.Name -like $wildcard -and $_.Name -notlike 'PS*' } | Select-Object -ExpandProperty Name

        foreach ($valueName in $matchingValueNames) {
            Write-ADTLogEntry -Message "Removing registry value [$valueName] from [$runKey] for SID [$($_.SID)]." -Source 'Info'
            Remove-ADTRegistryKey -Key $runKey -Name $valueName -SID $_.SID
        }
    }

    # Remove Copilot folder if existed.
    Remove-ADTFolder -Path "$envProgramFilesX86\Microsoft\Copilot"
```

## Microsoft Intune

### Detection Method
Use either these file paths:
- C:\Program Files (x86)\Microsoft\Copilot\Application\mscopilot.exe
- C:\Program Files (x86)\Microsoft\Copilot\Application\mscopilot_proxy.exe

or following registry key:
- HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Copilot