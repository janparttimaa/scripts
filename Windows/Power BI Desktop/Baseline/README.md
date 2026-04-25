# Power BI Desktop - Baseline

Ensures, that baseline settings are deployed and enforced to all employees.

> [!NOTE]  
> This example applies to following types of Power BI Desktop applications:
> | Type                           | URL                                                                          |
> | -------------------------------| ---------------------------------------------------------------------------- |
> | UWP / Microsoft Store (64-bit) | [Hyperlink](https://aka.ms/pbidesktopstore)                                  |
> | EXE (64-bit)                   | [Hyperlink](https://www.microsoft.com/en-us/download/details.aspx?id=58494)  |

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    # Starting deployment of baseline settings
    Write-ADTLogEntry -Message "Applying baseline settings to Power BI Desktop..." -Source 'Info'

    # Enforcing default language to "en-US"
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Power BI Desktop' -Name 'DefaultUICulture' -Value 'en-US' -Type 'String'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Power BI Desktop' -Name 'UICulture' -Value 'en-US' -Type 'String'

    # Disabling multi-language support to prevent users from changing the language in Power BI Desktop. Users should only use enforced default language
    # IMPORTANT: This registry key is not supported on Power BI Desktop originated from Microsoft Store
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Microsoft Power BI Desktop' -Name 'SupportsMultiLanguage' -Value '0' -Type 'DWord'

    # Finishing deployment of baseline settings
    Write-ADTLogEntry -Message "Baseline has been deployed to Power BI Desktop" -Source 'Info'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    # Informing that uninstallation is not required
    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
