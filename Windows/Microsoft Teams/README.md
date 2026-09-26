# Microsoft Teams

Installs offline installer of Microsoft Teams. In this example, we will install offline version "26225.1806.5074.145".

## PSAppDeployToolkit (PSADT)

### Variables
Here is the example of defined variables:
```
    # App variables.
    AppVendor = 'Microsoft Corporation'
    AppName = 'Microsoft Teams'
    AppVersion = '26225.1806.5074.1452'
    AppArch = 'x64'
    AppLang = 'EN'
    AppRevision = '01'
    AppSuccessExitCodes = @(0)
    AppRebootExitCodes = @(1641, 3010)
    AppProcessesToClose = @('ms-teams')  # Example: @('excel', @{ Name = 'winword'; Description = 'Microsoft Word' })
    AppScriptVersion = '1.0.0'
    AppScriptDate = '2026-09-28'
    AppScriptAuthor = 'Jan Parttimaa'
    RequireAdmin = $true

    # Install Titles (Only set here to override defaults set by the toolkit).
    InstallName = ''
    InstallTitle = 'Microsoft Teams'
```

### Pre-Install
Make also sure that following has been set: `DeferTimes = 0`

### Install
```
    ## <Perform Installation tasks here>

    Start-ADTProcess -FilePath "teamsbootstrapper.exe" -ArgumentList "-p -o `"$($adtSession.DirFiles)\MSTeams-x64.msix`"" -WindowStyle "Hidden"
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
