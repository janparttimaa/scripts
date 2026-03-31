# Windows Hello for Business - Forbid the use of external cameras for Windows Hello face sign-in

Ensures that only built-in cameras can be used for Windows Hello facial recognition.

More information: https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/windows-hello-face-authentication

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Forbid the use of external cameras for Windows Hello face sign-in..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\FaceLogon' -Name 'ShouldForbidExternalCameras' -Type 'DWord' -Value '1'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
