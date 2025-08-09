# Windows Security App Update

## Description 
This PowerShell-script will install Windows Security App Update using offline version of the installer.
This needs to be deployed as application using either Microsoft Intune or Microsoft Configuration Manager. Installation will happens per system context.

**Platform:** Windows 10 and later.

## Prerequisites
Before deploying this script, you need to do following tasks:
1. Download offline installer of Windows Security App Update [here](https://support.microsoft.com/en-us/topic/windows-security-app-update-a6ac7d2e-b1bf-44c0-a028-41720a242da3). Installer must be placed to same folder location where this script was downloaded.
2. Replace name of the offline installer from the line 35, where placeholder "installer.exe" is.
3. Replace name of your company from the line 37, where placeholder "Example Company" is.

## Detection methods for deployment
If your company name is e.g. "Example Company", detection methods would be following ones:

| Registry Key | Value | Type | Data |
| -------- | ------- | ------- |------- |
| HKLM\Software\Example Company\Windows Security App Update | Installed | REG_SZ | Yes
| HKLM\Software\Example Company\Windows Security App Update | ScriptVersion | REG_SZ | 20250809
