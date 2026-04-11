# Internet Explorer - Allow Internet Explorer to use the HTTP2 network protocol

This policy setting determines whether Internet Explorer uses the HTTP2 network protocol. hHTTP2 requests help optimize the latency of network requests through compression, multiplexing, and prioritization.

If you enable this policy setting, Internet Explorer uses the HTTP2 network protocol.

If you disable this policy setting, Internet Explorer won´t use the HTTP2 network protocol.

If you don´t configure this policy setting, users can turn this behavior on or off, using Internet Explorer Advanced Internet Options settings. The default is on.

**In this script example, we will disable HTTP2.**

## PSAppDeployToolkit (PSADT)

### Install
```
    ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Applying policy: Do not allow Internet Explorer to use the HTTP2 network protocol..." -Source 'Info'
    Set-ADTRegistryKey -LiteralPath 'HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' -Name 'EnableHTTP2' -Type 'DWord' -Value '0'
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```
