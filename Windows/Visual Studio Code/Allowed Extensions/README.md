# Visual Studio Code - Allowed Extensions
## PSAppDeployToolkit (PSADT)

### Pre-Install
```
    ## <Perform Pre-Installation tasks here>

    # Replace "Example" with your company name e.g. "Contoso"
    $CorporateName = "Example"

    # JSON string for AllowedExtensions (stored as REG_MULTI_SZ with a single entry)
    $AllowedExtensionsJson = '{"github.vscode-pull-request-github": true, "ms-vscode.powershell": true, "ms-vscode-remote.remote-wsl": true, "hediet.vscode-drawio": true, "openai.chatgpt": true, "github.copilot": true}'
```

### Install
```
    ## <Perform Pre-Installation tasks here>

    # Inform to the log that policy of allowed extensions to Microsoft Visual Studio Code will be implemented
    Write-ADTLogEntry -Message "Starting deploying policy of allowed extensions to Microsoft Visual Studio Code..." -Source 'Info'

    # Specify which extensions can be installed
    # More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-allowed-extensions
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'AllowedExtensions' -Type 'MultiString' -Value $AllowedExtensionsJson
```

### Post-Install
```
    ## <Perform Post-Installation tasks here>

    # Let's create registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Creating registry key for Microsoft Intune or Microsoft Configuration Manager detection rule purposes..." -Source 'Info'
    
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Visual Studio Code" -Name 'AllowedExtensionsStatus' -Type 'String' -Value "Implemented"

    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Visual Studio Code" -Name 'AllowedExtensionsAppVersion' -Type 'String' -Value $($adtSession.AppVersion)

    Write-ADTLogEntry -Message "All done" -Source 'Info'
```

### Pre-Uninstall
```
    ## <Perform Pre-Installation tasks here>

    # Replace "Example" with your company name e.g. "Contoso"
    $CorporateName = "Example"
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    # Inform to the log that policy of allowed extensions from Microsoft Visual Studio Code will be removed
    Write-ADTLogEntry -Message "Removing policy of allowed extensions from Microsoft Visual Studio Code..." -Source 'Info'

    # Removing following policy: Specify which extensions can be installed
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'AllowedExtensions'
```

### Post-Uninstall
```
    ## <Perform Post-Uninstallation tasks here>

    # Registry paths
    $regPath1 = "HKLM:\SOFTWARE\$CorporateName\Microsoft Visual Studio Code"
    $regPath2 = "HKLM:\SOFTWARE\$CorporateName"
    $regPath3 = "HKLM:\SOFTWARE\Policies\Microsoft\VSCode"

    # Let's remove registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Removing registry key used for Microsoft Intune or Configuration Manager detection rules..." -Source 'Info'
    
    Remove-ADTRegistryKey -LiteralPath $regPath1 -Name 'AllowedExtensionsStatus'

    Remove-ADTRegistryKey -LiteralPath $regPath1 -Name 'AllowedExtensionsAppVersion'

    # Check if the registry key exists
    if (Test-Path $regPath1) {

        $key1 = Get-Item $regPath1
        $subKeys1 = $key1.GetSubKeyNames()
        $values1 = $key1.GetValueNames()

        # Check if both subkeys and values are empty
        if ($subKeys1.Count -eq 0 -and $values1.Count -eq 0) {
            Remove-ADTRegistryKey -LiteralPath $regPath1
            Write-ADTLogEntry -Message "Registry key was empty and has been deleted: $regPath1" -Source 'Info'
        }
        else {
            Write-ADTLogEntry -Message "Registry key $regPath1 is not empty. No action taken." -Source 'Info'
        }

    }
    else {
        Write-ADTLogEntry -Message "Registry key $regPath1 does not exist." -Source 'Info'
    }

    # Check if the registry key exists
    if (Test-Path $regPath2) {

        $key2 = Get-Item $regPath2
        $subKeys2 = $key2.GetSubKeyNames()
        $values2 = $key2.GetValueNames()

        # Check if both subkeys and values are empty
        if ($subKeys2.Count -eq 0 -and $values2.Count -eq 0) {
            Remove-ADTRegistryKey -LiteralPath $regPath2
            Write-ADTLogEntry -Message "Registry key was empty and has been deleted: $regPath2" -Source 'Info'
        }
        else {
            Write-ADTLogEntry -Message "Registry key $regPath2 is not empty. No action taken." -Source 'Info'
        }

    }
    else {
        Write-ADTLogEntry -Message "Registry key $regPath2 does not exist." -Source 'Info'
    }

    # Check if the registry key exists
    if (Test-Path $regPath3) {

        $key3 = Get-Item $regPath3
        $subKeys3 = $key3.GetSubKeyNames()
        $values3 = $key3.GetValueNames()

        # Check if both subkeys and values are empty
        if ($subKeys3.Count -eq 0 -and $values3.Count -eq 0) {
            Remove-ADTRegistryKey -LiteralPath $regPath3
            Write-ADTLogEntry -Message "Registry key was empty and has been deleted: $regPath3" -Source 'Info'
        }
        else {
            Write-ADTLogEntry -Message "Registry key $regPath3 is not empty. No action taken." -Source 'Info'
        }

    }
    else {
        Write-ADTLogEntry -Message "Registry key $regPath3 does not exist." -Source 'Info'
    }

    Write-ADTLogEntry -Message "All done" -Source 'Info'
```