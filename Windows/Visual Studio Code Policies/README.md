# Visual Studio Code Policy Enforcement – Intune Deployment

This package deploys a PowerShell script that enforces required **Visual Studio Code enterprise policy settings** through the registry.

The script performs:

- **Detection**
- **Remediation**
- **Final verification**

All within a **single PowerShell file**, with **no parameters**, and is suitable for Intune Win32 App deployment.


## 📌 Overview

The script:

1. **Reads** all Visual Studio Code policy values from  
   `HKLM\SOFTWARE\Policies\Microsoft\VSCode`
2. **Compares** existing values with the **desired state**
3. **Remediates** any deviations (creates, updates, or deletes values)
4. **Verifies** compliance after remediation
5. Exits with:
   - **0** → Fully compliant  
   - **1** → Not compliant

Because detection and remediation occur in the same script, Intune can use:

- The script itself as the **installer**
- Intune registry-based rules as **detection**

## 📁 Package Contents

| File | Purpose |
|------|---------|
| `vscode-policies.ps1` | Full detection + remediation logic |
| `README.md` | Deployment and operational documentation |

## 🛠 Policies Enforced

All registry values are under:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode
```

### 🔹 Important Behavior  
For all **string** policies (`REG_SZ`):

- If the desired value is **empty (`""`)**, the script will **delete the registry value**.

## Policies

| Policy Name | Type | Desired Value | Description |
|-------------|------|---------------|-------------|
| **AllowedExtensions** | REG_MULTI_SZ | JSON list | Restricts which extensions may be installed. Stored as a single-element REG_MULTI_SZ containing a JSON dictionary. |
| **ChatAgentExtensionTools** | REG_DWORD | `0` | Disables tools contributed by third-party extensions in Chat. |
| **ChatAgentMode** | REG_DWORD | `0` | Disables Chat “agent mode.” |
| **ChatMCP** | REG_SZ | `none` | Disables MCP (Model Context Protocol) servers. (`""` would remove the value.) |
| **ChatToolsAutoApprove** | REG_DWORD | `0` | Disables global automatic Chat tool approval. |
| **ChatToolsTerminalEnableAutoApprove** | REG_DWORD | `0` | Disables auto-approval for terminal Chat tools. |
| **EnableFeedback** | REG_DWORD | `0` | Disables surveys and issue reporter feedback mechanisms. |
| **ExtensionGalleryServiceUrl** | REG_SZ | `""` (deleted) | Custom Marketplace URL — empty desired value means the script removes this registry value. |
| **McpGalleryServiceUrl** | REG_SZ | `""` (deleted) | Custom MCP Gallery URL — value is removed. |
| **TelemetryLevel** | REG_SZ | `off` | Disables product telemetry. |
| **UpdateMode** | REG_SZ | `default` | Enables automatic update checks. |

### Notes
- `AllowedExtensions` is **REG_MULTI_SZ with JSON** → Intune cannot compare content reliably → **Use Exists**.
- `ExtensionGalleryServiceUrl` and `McpGalleryServiceUrl` are **intentionally deleted** → Do **not** detect these.

## Assign the App

Recommended:

- **Required** → Device groups

## Monitor Deployment

Go to:

**Apps → Visual Studio Code – Baseline Policy Enforcement → Device install status**

Results:

- **Installed** → All policies compliant  
- **Failed** → Script returned exit code **1**  

## ✔ Deployment Complete

Visual Studio Code enterprise policy configuration is now fully automated.