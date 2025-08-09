# Windows Security App Update

## Description 
This PowerShell-script will install Windows Security App Update using offline version of the installer.

## Prerequisites
Before deploying this script, you need to do following tasks:
1. Download offline installer of Windows Security App Update [here](https://support.microsoft.com/en-us/topic/windows-security-app-update-a6ac7d2e-b1bf-44c0-a028-41720a242da3).
2. Replace name of the offline installer from the line 35, where placeholder "installer.exe" is.
3. Replace name of your company from the line 37, where placeholder "Example Company" is.

## Detection Methods
If your company name is e.g. "Example Company", detection methods would be following ones:

| Registry Key | Value | Type | Data |
| -------- | ------- | ------- |------- |
| HKLM\Sofware\Example Company\Windows Security App Update | Installed | REG_SZ | Yes
| HKLM\Sofware\Example Company\Windows Security App Update | ScriptVersion | REG_SZ | 20250809
