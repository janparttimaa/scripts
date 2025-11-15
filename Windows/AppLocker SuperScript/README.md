# AppLocker Superscript

AppLocker SuperScript removes per-user (AppData-installed) copies of following applications across all local user profiles:
- Google Chrome
- Mozilla Firefox
- GIMP
- Git for Windows
- Refinitiv Workspace / LSEG Workspace

This script also stops only per-user processes, purges per-user data, cleans broken shortcuts in per-user Desktop/Start Menu, and removes per-user uninstall registry entries.

## Description
This script is designed for environments where users may have installed products to their profile (AppData) even when a machine-wide copy exists in Program Files. To avoid disrupting machine-wide installations, the script:
- Identifies and stops ONLY per-user processes (based on executable path patterns under the user profile).
- Invokes each product’s per-user uninstaller when present; otherwise performs best-effort cleanup.
- Optionally removes per-user app data/directories (when ``-PurgeData`` is specified for a product).
- Cleans up broken shortcuts (*.lnk) in the user’s Desktop and Start Menu (NOT public folders).
- Removes per-user uninstall registry keys from each user’s hive (loaded or by temporarily loading NTUSER.DAT).
- Writes per-product logs to ``C:\ProgramData\AppLocker`` with colorized console output for quick scanning.

Execution is controlled by the Boolean switches at the top of the script (e.g. ``$RunChromeCleanup``). Each product has its own function and consistent internal structure for logging, admin verification, process filtering, profile enumeration, shortcut cleanup, and registry cleanup.

## Prerequisites
- Run as local Administrator (the script checks and throws if not).
- PowerShell 5.1+ or PWSh 7+ with access to WScript.Shell COM for shortcut inspection.
- Access to user profile paths and NTUSER.DAT for offline hive loading.
- Write permissions to ``C:\ProgramData\AppLocker`` for logging.

## Safety / Scope
- The script intentionally DOES NOT modify Public Desktop or All Users Start Menu content.
- Only per-user, AppData-based installations are targeted; Program Files installs are left untouched.
- Process termination is constrained to per-user paths, minimizing collateral impact.
- Registry hive load/unload is wrapped in try/finally for safety; failures are logged and skipped.
- Script will not purge data from AppData if application finds same application installation on Program Files as well.

## Logging
- Per-product transcripts are written to ``C:\ProgramData\AppLocker\<Product>Uninstall_yyyyMMdd_HHmmss.log``
- Console output is color-coded (white=info, green=success, red=warnings/errors).

## Known issues
- This script will uninstall LSEG Workspace also when the application is installed to Program Files. This is because script will pick the uninstaller from AppData. If running this script, users of LSEG Workspace must be informed, that they need to re-install the application from Software Center or Company Portal if application will be uninstalled.

## Execution Switches
Before deploying the script, you need to define what execution swithes you are using:

| Variable               | Default Value | Notes |
| ---------------------- | ------------- | ------ |
| ``$RunChromeCleanup``      | ``$true`` | If set to ``$false``, Google Chrome will not be uninstalled. |
| ``$RunFirefoxCleanup``     | ``$true`` | If set to ``$false``, Mozilla Firefox will not be uninstalled. |
| ``$RunGimpCleanup``        | ``$true`` | If set to ``$false``, GIMP will not be uninstalled. |
| ``$RunRefinitivCleanup``   | ``$true`` | If set to ``$false``, Refinitiv Workspace / LSEG Workspace will not be uninstalled. |
