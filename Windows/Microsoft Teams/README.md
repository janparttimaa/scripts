# Microsoft Teams

Installs offline installer of Microsoft Teams. In this example, we will install offline version "26225.1806.5074.1452".

More information how to get offline installer and bootsrapper: [Option 1B: Download and install Teams using an offline installer](https://learn.microsoft.com/en-us/microsoftteams/teams-client-bulk-install)

## Check version of the offline MSIX-installer

Here is script how to check version of the offline MSIX-installer:
```powershell
# Variables
$msix = "C:\Temp\MSTeams-x64.msix"
$temp = Join-Path $env:TEMP "msix-check"
$zip  = Join-Path $env:TEMP "msix-check.zip"

Copy-Item $msix $zip
Expand-Archive $zip -DestinationPath $temp -Force

[xml]$manifest = Get-Content "$temp\AppxManifest.xml"
$manifest.Package.Identity.Version
```
- Make sure, that msix is placed to `C:\Temp`
- Set this version number to version variables for PSADT and Intune detection script.

## Check currently installer version of Microsoft Teams
```powershell
Get-AppxPackage -AllUsers -Name MSTeams -ErrorAction SilentlyContinue
```

## PSAppDeployToolkit (PSADT)

### Variables

Here is the example of defined variables:
```powershell
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
```powershell
    ## <Perform Installation tasks here>

    Start-ADTProcess -FilePath "teamsbootstrapper.exe" -ArgumentList "-p -o `"$($adtSession.DirFiles)\MSTeams-x64.msix`"" -WindowStyle "Hidden"
```

### Uninstall
```powershell
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
