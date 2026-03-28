# Adobe Acrobat - Fix Acrobat PDF conversion failure

## Prerequisites
1. Read this article: https://helpx.adobe.com/acrobat/kb/fix-pdf-conversion-font-errors.html
2. [Download this registry file](https://helpx.adobe.com/content/dam/help/en/acrobat/kb/error--when-you-create-a-postscript-file-you-must-rely-on-system/jcr_content/root/content/flex/items/position/position-par/procedure_1111576657/proc_par/step_0/step_par/download_section/download-1/registry_fix_txt.zip) provided by Adobe. Unzip the file and replace txt format to reg.

## PSAppDeployToolkit (PSADT)

### Install
```
   ## <Perform Installation tasks here>

    Write-ADTLogEntry -Message "Implementing registry fix for Acrobat PDF conversion failures..." -Source 'Info'
    Start-ADTProcess -FilePath 'C:\Windows\regedit.exe' -ArgumentList "/s `"$(adtSession.DirSupportFiles)\registry_fix.reg`""
```

### Uninstall
```
    ## <Perform Uninstallation tasks here>

    Write-ADTLogEntry -Message "No uninstall required" -Source 'Info'
```