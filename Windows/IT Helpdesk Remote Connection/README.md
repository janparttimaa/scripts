# IT Helpdesk Remote Desktop Connection
Provide remote support to company employees using the **Windows Remote Assistance** program with an invitation file for Windows 11 devices onboarded through **Windows Autopilot Device Preparation**.  
This approach is a practical alternative when your organization has not yet adopted [**Remote Help with Microsoft Intune**](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remote-help).

## What is this and why use it?
This solution enables IT support staff to remotely assist employees using the built-in Windows Remote Assistance tool without requiring additional paid services or complex configurations.

It’s designed for organizations that:
- Use **Windows Autopilot Device Preparation** for device onboarding.
- Have not yet implemented **Remote Help with Microsoft Intune**.
- Need a **temporary or alternative method** to support users on Windows 11 devices.

To simplify the process, this solution automates much of the connection setup, allowing IT staff to easily connect to a user’s company-managed device using an invitation file and a temporary password.

## Prerequisites
- Windows 11 devices enrolled via **Windows Autopilot Device Preparation**.
- Both technician and user devices connected to the **corporate network or VPN**.
- **Windows Remote Assistance** enabled on both endpoints.
- **User permissions** allowing remote control.

## Security Notes
- Invitations automatically expire after a short time or when the session ends.
- Connections always require **user consent** before the technician can view or control the screen.
- Intended for use **only within trusted, internal network environments**.

## Before Deploying
Some preparation steps are required before deploying this solution:

### Scripts
Update the placeholder company name (`Example`) in the following scripts:

1. **install.ps1** - line 31  
2. **uninstall.ps1** - line 40  
3. **Create-RemoteAssistanceInvitation.ps1** - line 44  
4. **Create-RemoteAssistanceInvitation.bat** - line 6  

Replace each instance of `Example` with your actual company name.

### Microsoft Intune - Device Configuration Profiles
*To be added (TBA)*
