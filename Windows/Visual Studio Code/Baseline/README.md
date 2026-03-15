# Visual Studio Code - Baseline
## PSAppDeployToolkit (PSADT)

### Pre-Install
```
    ## <Perform Pre-Installation tasks here>

    # Replace "Example" with your company name e.g. "Contoso"
    $CorporateName = "Example"

    # JSON string for ChatToolsEligibleForAutoApproval (stored as REG_MULTI_SZ with a single entry). Set value '' keep the value empty.
    # $ChatToolsEligibleForAutoApproval = ''
```

### Install
```
    ## <Perform Installation tasks here>

    # Inform to the log that baseline settings of Microsoft Visual Studio Code will be implemented
    Write-ADTLogEntry -Message "Starting deploying baseline settings of Microsoft Visual Studio Code..." -Source 'Info'

    # Configure the Marketplace service URL to connect to
    # Defined URL e.g. 'https://extension.example.com/'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ExtensionGalleryServiceUrl' -Type 'String' -Value ''

    # Enable the rule-based auto-approval for the terminal tool
    # 0 - disabled / 1 - enabled
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatToolsTerminalEnableAutoApprove' -Type 'DWord' -Value '0'

    # Enable global auto-approval for agent mode tools
    # Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatToolsEligibleForAutoApproval' -Type 'MultiString' -Value $ChatToolsEligibleForAutoApproval

    # Controls which tools are eligible for automatic approval
    # 0 - disabled / 1 - enabled
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatToolsAutoApprove' -Type 'DWord' -Value '0'

    # Enable Model Context Protocol (MCP) servers support and which sources are allowed
    # none - MCP server support is disabled. More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-mcp-server-access
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatMCP' -Type 'String' -Value "none"
    
    # Enable using tools contributed by third-party extensions
    # 0 - disabled / 1 - enabled
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatAgentExtensionTools' -Type 'DWord' -Value '0'

    # Enable agent mode
    # 0 - disabled / 1 - enabled
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatAgentMode' -Type 'DWord' -Value '1'

    # Configure the MCP Gallery service URL to connect to
    # Defined URL e.g. 'https://mcp.example.com/'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'McpGalleryServiceUrl' -Type 'String' -Value ''

    # Specify telemetry data level
    # off - disables all product telemetry. More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-telemetry-level
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'TelemetryLevel' -Type 'String' -Value 'off'

    # Configure feedback mechanisms (issue reporter and surveys)
    # 0 - disabled / 1 - enabled
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'EnableFeedback' -Type 'DWord' -Value '0'

    # Enable automatic installation of VS Code updates
    # default - automatic checking for updates is enabled and runs in the background periodically
    # More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-automatic-updates
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'UpdateMode' -Type 'String' -Value 'default'
```

### Post-Install
```
    ## <Perform Post-Installation tasks here>

    # Let's create registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Creating registry key for Microsoft Intune or Microsoft Configuration Manager detection rule purposes..." -Source 'Info'
    
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Visual Studio Code" -Name 'BaselineSettingsStatus' -Type 'String' -Value "Implemented"

    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Visual Studio Code" -Name 'BaselineSettingsAppVersion' -Type 'String' -Value $($adtSession.AppVersion)

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
    ## <Perform Pre-Uninstallation tasks here>

    # Inform to the log that baseline settings of Microsoft Visual Studio Code will be removed
    Write-ADTLogEntry -Message "Removing baseline settings of Microsoft Visual Studio Code..." -Source 'Info'

    # Removing following policy: Configure the Marketplace service URL to connect to
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ExtensionGalleryServiceUrl'

    # Removing following policy: Enable the rule-based auto-approval for the terminal tool
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatToolsTerminalEnableAutoApprove'

    # Removing following policy: Enable global auto-approval for agent mode tools
    # Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatToolsEligibleForAutoApproval'

    # Removing following policy: Controls which tools are eligible for automatic approval
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatToolsAutoApprove'

    # Removing following policy: Enable Model Context Protocol (MCP) servers support and which sources are allowed
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatMCP'
    
    # Removing following policy: Enable using tools contributed by third-party extensions
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatAgentExtensionTools'

    # Removing following policy: Enable agent mode
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'ChatAgentMode'

    # Removing following policy: Configure the MCP Gallery service URL to connect to
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'McpGalleryServiceUrl'

    # Removing following policy: Specify telemetry data level
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'TelemetryLevel'

    # Removing following policy: Configure feedback mechanisms (issue reporter and surveys)
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'EnableFeedback'

    # Removing following policy: Enable automatic installation of VS Code updates
    Remove-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode' -Name 'UpdateMode'
```

### Post-Uninstall
```
    ## <Perform Post-Uninstallation tasks here>

    # Let's remove registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes
    Write-ADTLogEntry -Message "Removing registry key used for Microsoft Intune or Configuration Manager detection rules..." -Source 'Info'
    
    Remove-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Visual Studio Code" -Name 'BaselineSettingsStatus'

    Remove-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\$CorporateName\Microsoft Visual Studio Code" -Name 'BaselineSettingsAppVersion'

    Write-ADTLogEntry -Message "All done" -Source 'Info'
```
