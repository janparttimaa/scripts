# Microsoft Copilot - AppLocker rules for blocking

> [!NOTE]
> This article is only for Microsoft Copilot app.<br> 
> **This article is not for Microsoft 365 Copilot app.**

This article tells you how to block Microsoft Copilot app using AppLocker.

## "New" Microsoft Copilot app
> [!NOTE]
> "New" Microsoft Copilot app is using Microsoft Edge-based wrapper. <br>
> These blocking rules does not prevent uninstalling "New" Microsoft Copilot app.
> News article regarding to this app: [New Copilot for Windows 11 includes a full Microsoft Edge package, uses more RAM](https://www.windowslatest.com/2026/04/05/new-copilot-for-windows-11-includes-a-full-microsoft-edge-package-uses-more-ram/)

In order to block "new" Microsoft Copilot, you need to use following AppLocker rules:

### Executable Rules
| Rule    | Action | User | Name | Condition | Exceptions
| -------- | ------- | ------- | ------- | ------- | ------- |
| Rule 1  | Deny | Everyone | %PROGRAMFILES%\Microsoft\Copilot\Application\mscopilot_proxy.exe | Path | N/A
| Rule 2 | Deny | Everyone | COPILOT, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US | Publisher | N/A
| Rule 3 | Deny | Everyone | STORE INSTALLER, from O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US | Publisher | N/A

#### Rule 1
![Rule 1 - Screenshot 1](./img/Rule%201%20-%20Screenshot%201.png "Rule 1 - Screenshot 1")
![Rule 1 - Screenshot 2](./img/Rule%201%20-%20Screenshot%202.png "Rule 1 - Screenshot 2")
![Rule 1 - Screenshot 3](./img/Rule%201%20-%20Screenshot%203.png "Rule 1 - Screenshot 3")

#### Rule 2
![Rule 2 - Screenshot 1](./img/Rule%202%20-%20Screenshot%201.png "Rule 2 - Screenshot 1")
![Rule 2 - Screenshot 2](./img/Rule%202%20-%20Screenshot%202.png "Rule 2 - Screenshot 2")
![Rule 2 - Screenshot 3](./img/Rule%202%20-%20Screenshot%203.png "Rule 2 - Screenshot 3")

#### Rule 3

> [!NOTE]
> This rule blocks installing applications from the Microsoft Store website, including apps other than Microsoft Copilot.

![Rule 3 - Screenshot 1](./img/Rule%203%20-%20Screenshot%201.png "Rule 3 - Screenshot 1")
![Rule 3 - Screenshot 2](./img/Rule%203%20-%20Screenshot%202.png "Rule 3 - Screenshot 2")
![Rule 3 - Screenshot 3](./img/Rule%203%20-%20Screenshot%203.png "Rule 3 - Screenshot 3")

## "Old" Microsoft Copilot app

Check more information [here](https://learn.microsoft.com/en-us/windows/client-management/manage-windows-copilot#remove-or-prevent-installation-of-the-microsoft-copilot-app).