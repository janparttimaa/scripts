# Disable Intel Connectivity Performance Suite from Startup Apps

PowerShell script for Microsoft Intune that disables **Intel Connectivity Performance Suite** from **Windows Startup Apps** for the currently logged-on user.

The script is designed to run in the **user context** and does not require administrator rights for the registry changes it performs.

## Purpose

The script checks whether the following AppX package is installed for the current user:

```text
AppUp.IntelConnectivityPerformanceSuite
```

If the package is installed, the script checks the existing Startup Apps registry configuration under:

```text
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData\AppUp.IntelConnectivityPerformanceSuite_8j3eq9eme6ctt\ICMTask
```

The script then verifies that the following existing registry values are configured as `REG_DWORD` with data `0`:

| Registry value | Type | Required data |
| --- | --- | ---: |
| `State` | `REG_DWORD` | `0` |
| `UserEnabledStartupOnce` | `REG_DWORD` | `0` |

If either value is not configured correctly, the script updates it and performs a final verification.

## Behavior

The script follows this logic:

1. Check whether `AppUp.IntelConnectivityPerformanceSuite` is installed for the current user.
2. Check whether the required `HKCU` registry key exists.
3. Check whether both required registry values already exist.
4. Set any incorrectly configured value to `REG_DWORD 0`.
5. Verify the final configuration.
6. Exit with code `0` when successful or when the configuration is not applicable.
7. Exit with code `1` if configuration or verification fails.

The script intentionally **does not create** the registry key or missing registry values.

If the application, registry key, or required values do not exist, the script exits without making changes.

## Microsoft Intune deployment

This script is intended to be deployed as an **Intune Platform PowerShell script**.

Recommended settings:

| Intune setting | Recommended value |
| --- | --- |
| Run this script using the logged-on credentials | **Yes** |
| Enforce script signature check | **No** |
| Run script in 64-bit PowerShell host | **Yes** |

Running in the logged-on user's context is required because the script:

- Uses `Get-AppxPackage` for the current user.
- Reads and modifies `HKEY_CURRENT_USER`.
- Targets a per-user Startup Apps configuration.

> [!IMPORTANT]
> Do not run this script as `SYSTEM` if the intention is to configure the signed-in user's Startup Apps settings.

## Logging

Script output is written both to the PowerShell output stream and to a persistent log file under:

```text
C:\ProgramData\Logs\Software
```

The log filename includes the user account:

```text
Configure-IntelConnectivityPerformanceSuite-<user>.log
```

Examples:

```text
Configure-IntelConnectivityPerformanceSuite-jdoe.log
Configure-IntelConnectivityPerformanceSuite-john.doe@contoso.com.log
```

Each log entry contains:

- Timestamp
- User account
- Processing step
- Status message

Example:

```text
[2026-09-12 17:30:04] [jdoe] [Start] Starting Intel Connectivity Performance Suite Startup Apps configuration.
[2026-09-12 17:30:04] [jdoe] [Step 1] AppX package 'AppUp.IntelConnectivityPerformanceSuite' is installed.
[2026-09-12 17:30:04] [jdoe] [Step 4] Updating 'State' to REG_DWORD 0.
[2026-09-12 17:30:04] [jdoe] [Step 5] Verified 'State': Type=DWord, Data=0
[2026-09-12 17:30:04] [jdoe] [Success] Intel Connectivity Performance Suite is disabled from Startup Apps for the current user.
[2026-09-12 17:30:04] [jdoe] [Exit] Exiting with code 0.
```

The script derives the user account from the actual Windows security identity running the script and removes the provider/domain prefix from the displayed username.

Examples:

```text
CONTOSO\jdoe             -> jdoe
AzureAD\jdoe@contoso.com -> jdoe@contoso.com
COMPUTER01\jdoe          -> jdoe
```

## Exit codes

| Exit code | Meaning |
| ---: | --- |
| `0` | Script completed successfully, no change was required, or the configuration was not applicable |
| `1` | Configuration, verification, or logging initialization failed |

Examples of conditions that return exit code `0` without making changes:

- Intel Connectivity Performance Suite is not installed for the current user.
- The required registry key does not exist.
- One or both required registry values do not exist.
- Both registry values are already correctly configured.

## Requirements

- Windows 10 or Windows 11
- PowerShell 5.1 or later
- Intel Connectivity Performance Suite installed as an AppX/MSIX package for the current user
- Script executed in the logged-on user's context
- Write access to:

```text
C:\ProgramData\Logs\Software
```

## Usage

Run manually:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-IntelConnectivityPerformanceSuite.ps1
```

The script does not require elevation for the `HKCU` registry changes.

## Registry configuration

Target registry location:

```text
HKEY_CURRENT_USER
└── Software
    └── Classes
        └── Local Settings
            └── Software
                └── Microsoft
                    └── Windows
                        └── CurrentVersion
                            └── AppModel
                                └── SystemAppData
                                    └── AppUp.IntelConnectivityPerformanceSuite_8j3eq9eme6ctt
                                        └── ICMTask
```

Expected values:

```text
State                  REG_DWORD    0
UserEnabledStartupOnce REG_DWORD    0
```

## Notes

This script is intentionally conservative.

It only modifies the Startup Apps configuration when:

- The Intel Connectivity Performance Suite AppX package is installed.
- The expected registry key already exists.
- Both expected registry values already exist.

It does not provision the application, create Startup Apps entries, or create missing registry values.

Because Intune Platform PowerShell scripts are not designed as continuously recurring remediation checks, ensure the script is assigned at a point where Intel Connectivity Performance Suite has already been installed and initialized for the user.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

## Author

**Jan Parttimaa**

GitHub: [github.com/janparttimaa](https://github.com/janparttimaa)
