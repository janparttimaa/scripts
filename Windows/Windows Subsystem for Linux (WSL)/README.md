# Windows Subsystem for Linux (WSL) Detection Script

A PowerShell script that detects whether Windows Subsystem for Linux (WSL) is installed and responds successfully on Windows devices.

The script is intended for **reporting purposes using Microsoft Intune Remediations**. It does not install, uninstall, or modify WSL.

## Description

The script checks the WSL installation status by running `wsl.exe --status`.

Based on the command's exit code, the script reports whether WSL was detected successfully. Command output is suppressed, and only the detection result is displayed.

## Detection Logic

| Condition | Script Output | Intune Detection Status | Exit Code |
|-----------|---------------|-------------------------|-----------|
| WSL status check succeeds | `WSL is installed` | With issues | `1` |
| WSL is not installed or the status check fails | `WSL is not installed` | Without issues | `0` |

**Note:** Detection relies on the successful execution of `wsl.exe --status`. If WSL is installed but the command fails, the script may report that WSL is not installed. A successful status check does not verify that a Linux distribution is installed or functioning.

## Usage

Run the detection script using PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Detect-WSL.ps1
```

The script outputs either `WSL is installed` or `WSL is not installed`, depending on the detection result.

## Microsoft Intune Configuration

1. Open the [Microsoft Intune admin center](https://intune.microsoft.com).
2. Navigate to **Devices > Manage devices > Scripts and remediations**.
3. Create a new Remediations script package.
4. Upload `Detect-WSL.ps1` as the detection script.
5. Leave the remediation script unconfigured.
6. Assign the package to the required device group.

### Recommended Settings

| Setting | Value |
|---------|-------|
| Run this script using the logged-on credentials | No |
| Enforce script signature check | No |
| Run script in 64-bit PowerShell | Yes |

**Note:** Microsoft Intune interprets exit code `1` as an issue detected and exit code `0` as no issue detected. In this script, the issue status is used only to identify devices where WSL was detected successfully. It does not indicate that WSL is malfunctioning.

No remediation actions are performed.

## Viewing Detection Results

Detection results can be viewed in the Microsoft Intune admin center:

1. Navigate to **Devices > Manage devices > Scripts and remediations**.
2. Select the WSL detection package.
3. Open **Device status** to view the detection status for assigned devices.
4. Select **Export** to download the detection results as a CSV file for further analysis.

The **Detection status** indicates whether WSL was detected:

| Detection Status | Meaning |
|------------------|---------|
| With issues | WSL was detected successfully |
| Without issues | WSL was not detected or the status check failed |

The exported results can also include the detection script output, such as `WSL is installed` or `WSL is not installed`.

## Version History

| Version | Description |
|---------|-------------|
| 20261020 | Initial release |

## References

- [Microsoft Intune Remediations](https://learn.microsoft.com/en-us/intune/device-management/tools/deploy-remediations)
- [Windows Subsystem for Linux documentation](https://learn.microsoft.com/en-us/windows/wsl/)
- [Basic commands for WSL](https://learn.microsoft.com/en-us/windows/wsl/basic-commands)