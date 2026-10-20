# Windows Subsystem for Linux (WSL) Detection Script

A PowerShell script that detects whether Windows Subsystem for Linux (WSL) is installed and responding successfully on Windows devices.

The script is designed for **reporting purposes using Microsoft Intune Remediations**. It does not install, uninstall, or modify WSL.

## Description

The script checks the Windows Subsystem for Linux (WSL) installation status using the `wsl.exe --status` command.

Based on the command's exit code, the script reports whether WSL is installed and returns the corresponding exit code.

The script suppresses the command output and displays only the detection result.

## Detection Logic

| Condition | Output | Exit Code |
|-----------|--------|-----------|
| WSL installed and status check succeeds | `WSL is installed` | `1` |
| WSL not installed or status check fails | `WSL is not installed` | `0` |

**Note:** The script relies on the success of `wsl.exe --status`. If WSL is installed but not functioning correctly, the script may report that WSL is not installed.

## Usage

Run the detection script using PowerShell:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Detect-WSL.ps1
```

The script returns one of the following messages:

```text
WSL is installed
```

or

```text
WSL is not installed
```

## Microsoft Intune Configuration

1. Open the [Microsoft Intune admin center](https://intune.microsoft.com).
2. Navigate to **Devices > Scripts and remediations**.
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

### Reporting Behavior

The script is intended exclusively for reporting.

- **Exit code 0:** WSL was not detected or the status check failed.
- **Exit code 1:** WSL was detected successfully.
- No remediation actions are performed.
- No changes are made to the device.

Microsoft Intune uses the detection script's exit code to determine the reported detection status. Exit code `1` indicates an issue in the Remediations reporting model, even though WSL being installed is not necessarily a problem.

## Viewing Detection Results

Detection results can be viewed in the Microsoft Intune admin center:

1. Navigate to **Devices > Scripts and remediations**.
2. Select the WSL detection package.
3. Open **Device status**.
4. Select **Columns** and enable **Pre-remediation detection output**.

The output will display either `WSL is installed` or `WSL is not installed`.

## Version History

| Version | Description |
|---------|-------------|
| 20261020 | Initial release |

## References

- [Microsoft Intune Remediations](https://learn.microsoft.com/en-us/intune/intune-service/fundamentals/remediations)
- [Windows Subsystem for Linux documentation](https://learn.microsoft.com/en-us/windows/wsl/)
- [Basic commands for WSL](https://learn.microsoft.com/en-us/windows/wsl/basic-commands)