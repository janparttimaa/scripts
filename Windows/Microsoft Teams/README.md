# Microsoft Teams

Installs offline installer of Microsoft Teams

## PSAppDeployToolkit (PSADT)

### Variables
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
```
    ##================================================
    ## MARK: Pre-Install
    ##================================================
    $adtSession.InstallPhase = "Pre-$($adtSession.DeploymentType)"

    ## Show Welcome Message, close processes if specified, allow up to 3 deferrals, verify there is enough disk space to complete the install, and persist the prompt.
    $saiwParams = @{
        AllowDefer = $true
        DeferTimes = 0
        CheckDiskSpace = $true
        PersistPrompt = $true
    }
    if ($adtSession.AppProcessesToClose.Count -gt 0)
    {
        $saiwParams.Add('CloseProcesses', $adtSession.AppProcessesToClose)
    }
    Show-ADTInstallationWelcome @saiwParams

    ## Show Progress Message (with the default message).
    Show-ADTInstallationProgress

    ## <Perform Pre-Installation tasks here>
```

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
