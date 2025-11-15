# Visual Studio Code – Baseline Policy Enforcement

This package deploys a single PowerShell script that enforces a defined baseline of [Visual Studio Code enterprise policies](https://code.visualstudio.com/docs/setup/enterprise) via the registry.

The script performs:

- Detection of current policy values
- Remediation of non-compliant values
- Final verification

It is suitable for deployment using Microsoft Intune or Microsoft Configuration Manager (SCCM).


## 1. Before You Package the Script (Required Preparation)

Before creating an Intune Win32 app or deploying the script, you must update the script to match your environment.

### 1.1 Set your corporate name

In the script, update:

```powershell
$CorporateName = "Example"
```

Use your organization’s actual name (for example, `Contoso`).

This variable is used to build the following registry paths:

```
HKLM\Software\<CorporateName>
HKLM\Software\<CorporateName>\Visual Studio Code - Baseline Policy Enforcement
```

These keys are created and updated only when the script has successfully enforced all policies.

### 1.2 Define `AllowedExtensions`

Update the JSON stored in this variable:

```powershell
$AllowedExtensionsJson = '{"github.vscode-pull-request-github": true, "ms-vscode.powershell": true, "ms-vscode-remote.remote-wsl": true, "hediet.vscode-drawio": true}'
```

Modify the JSON object to include the Visual Studio Code extensions that are allowed in your environment.

Notes:

- This value is stored as a single `REG_MULTI_SZ` entry containing the JSON string.
- Because it is JSON inside a multi-string value, it is not practical to use as a direct detection rule in Intune or SCCM.
- More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-allowed-extensions

### 1.3 Review and update policy definitions

All enforced policies are defined in the `$VSCodePolicies` array inside the script. For each entry, review and adjust:

- `Name`
- `ValueKind` (for example `DWord`, `String`, `MultiString`)
- `Value`

Special rule for string policies (REG_SZ):

- If `ValueKind = 'String'` and `Value` is an empty string (`""`), the script will delete that registry value instead of setting it.

See the policy table later in this document for an overview of default values and descriptions.

## 2. Script Overview

The script targets this registry base key for Visual Studio Code policies:

```
HKLM\SOFTWARE\Policies\Microsoft\VSCode
```

The flow is:

1. Read current registry values for all policies defined in `$VSCodePolicies`.
2. Compare current values to the desired values.
3. Remediate non-compliant values:
   - Create missing values
   - Update incorrect values
   - Delete values that should not exist (for empty-string REG_SZ policies)
4. Run detection again after remediation.
5. Exit with:
   - `0` if all policies are compliant
   - `1` if one or more policies are still non-compliant

If the final compliance check passes, the script writes detection marker keys under:

```
HKLM\Software\<CorporateName>\Visual Studio Code - Baseline Policy Enforcement
    Installed     = "Yes"
    ScriptVersion = "<ScriptVersion>"
```

These markers are used as a proxy signal that:

- All registry policies (including `AllowedExtensions`) have been evaluated, and
- The system is considered compliant according to the script.

## 3. Package Contents

| File                                             | Description                                |
|--------------------------------------------------|--------------------------------------------|
| `visualstudiocode-baselinepolicyenforcement.ps1` | Detection and remediation script           |
| `README.md`                                      | Preparation, deployment and detection info |

## 4. Policies Enforced

All policies are configured under:

```
HKLM\SOFTWARE\Policies\Microsoft\VSCode
```

### 4.1 Special behaviour for REG_SZ policies

For any entry in `$VSCodePolicies` where:

- `ValueKind = 'String'`, and
- `Value` is an empty string (`""`),

the script will delete the corresponding registry value instead of setting it.

### 4.2 Policy table (defaults from the example script)

| Policy Name                        | Type         | Default Value  | Description                                                                 |
|------------------------------------|--------------|----------------|-----------------------------------------------------------------------------|
| AllowedExtensions                  | REG_MULTI_SZ | `{"github.vscode-pull-request-github": true, "ms-vscode.powershell": true, "ms-vscode-remote.remote-wsl": true, "hediet.vscode-drawio": true}` | List of allowed VS Code extensions, stored as a single JSON multi-string ([see chapter 1.2](#12-define-allowedextensions)).   |
| ChatAgentExtensionTools            | REG_DWORD    | 0              | Disables tools contributed by third-party Chat extensions. Value `1` enables tools contributed by third-party Chat extensions. |
| ChatAgentMode                      | REG_DWORD    | 0              | Disables Chat agent mode. Value `1` enables Chat agent mode. | 
| ChatMCP                            | REG_SZ       | none           | Disables MCP server support. Set `""` in the script to remove it. [More information and available values.](https://code.visualstudio.com/docs/setup/enterprise#_configure-mcp-server-access)|
| ChatToolsAutoApprove               | REG_DWORD    | 0              | Disables global Chat tool auto-approval. Value `1` enables global Chat tool auto-approval. |
| ChatToolsTerminalEnableAutoApprove | REG_DWORD    | 0              | Disables auto-approval for terminal Chat tools. Value `1` enables auto-approval for terminal Chat tools. |
| EnableFeedback                     | REG_DWORD    | 0              | Disables feedback mechanisms such as surveys and issue reporting. Value `1` enables feedback mechanisms such as surveys and issue reporting. | 
| ExtensionGalleryServiceUrl         | REG_SZ       | `""`           | Desired value is empty, so the script removes this registry value. Define URL if needed e.g. `"https://extension.example.com"`|
| McpGalleryServiceUrl               | REG_SZ       | `""`           | Desired value is empty, so the script removes this registry value. Define URL if needed e.g. `"https://mcp.example.com"`|
| TelemetryLevel                     | REG_SZ       | off            | Disables Visual Studio Code product telemetry. [More information and available values.](https://code.visualstudio.com/docs/setup/enterprise#_configure-telemetry-level)|
| UpdateMode                         | REG_SZ       | default        | Enables automatic background update checks. [More information and available values.](https://code.visualstudio.com/docs/setup/enterprise#_configure-automatic-updates) |

## 5. Detection Method (Intune / SCCM)

The recommended detection strategy combines:

1. Direct detection of registry policy values (excluding `AllowedExtensions`), and  
2. Detection of the corporate marker keys written by the script.

### 5.1 Detect enforced VS Code policies (excluding `AllowedExtensions`)

Create registry-based detection rules for the following values under:

```
HKLM\SOFTWARE\Policies\Microsoft\VSCode
```

- `ChatAgentExtensionTools` = `0` (REG_DWORD)
- `ChatAgentMode` = `0` (REG_DWORD)
- `ChatMCP` = `none` (REG_SZ)
- `ChatToolsAutoApprove` = `0` (REG_DWORD)
- `ChatToolsTerminalEnableAutoApprove` = `0` (REG_DWORD)
- `EnableFeedback` = `0` (REG_DWORD)
- `TelemetryLevel` = `off` (REG_SZ)
- `UpdateMode` = `default` (REG_SZ)

Policies whose desired value is empty (for example `ExtensionGalleryServiceUrl` and `McpGalleryServiceUrl`) are intentionally removed.

`AllowedExtensions` is excluded because it cannot be reliably detected.

### 5.2 Detect corporate marker keys

Use this path:

```
HKLM\Software\<CorporateName>\Visual Studio Code - Baseline Policy Enforcement
```

Check:

- `Installed` = `Yes` (REG_SZ)
- `ScriptVersion` matches the script value (REG_SZ)

These keys confirm full execution and validation of *all* policies.

## 6. Packaging for Intune (Win32)

1. Complete script preparation  
2. Structure files:

```
VSCodePolicy\
    visualstudiocode-baselinepolicyenforcement.ps1
    README.md
```

3. Package with `IntuneWinAppUtil.exe`  
4. Install command:

```
powershell.exe -ExecutionPolicy Bypass -File .\visualstudiocode-baselinepolicyenforcement.ps1
```

5. Configure detection rules as described

## 7. Monitoring Deployment

In Intune:

```
Apps → Visual Studio Code – Baseline Policy Enforcement → Device install status
```

- **Installed** → All detection rules matched  
- **Failed** → One or more detection rules did not match

## 8. Deployment Complete

Visual Studio Code enterprise policies are now centrally enforced, remediated, and verified.