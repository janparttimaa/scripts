# Visual Studio Code -- Baseline Policy Enforcement

This package deploys a **single PowerShell script** that enforces a
defined baseline of **Visual Studio Code enterprise policies** via the
registry.\
It includes **detection**, **remediation**, and **post-validation**,
making it suitable for deployment using **Microsoft Intune** or
**Microsoft Configuration Manager (SCCM)**.

## 🔧 Before You Package the Script (Required Preparation)

Before creating an Intune Win32 app or deploying the script, you **must
update the script** to match your environment.

## 1️⃣ Set your corporate name

Update the variable inside the script:

``` powershell
$CorporateName = "Example"
```

Use your organization's actual name (e.g., `"Contoso"`).\
This value determines where the script stores its detection markers.

## 2️⃣ Define `AllowedExtensions`

Update the JSON stored in this variable:

``` powershell
$AllowedExtensionsJson = '{"github.vscode-pull-request-github": true, "ms-vscode.powershell": true, "ms-vscode-remote.remote-wsl": true, "hediet.vscode-drawio": true, "openai.chatgpt": true}'
```

Modify the list of allowed extensions to match your requirements.

## 3️⃣ Review and update all policy definitions

Adjust the `$VSCodePolicies` array to specify:

-   Policy names\
-   Registry types (`DWord`, `String`, `MultiString`)\
-   Desired values

For **REG_SZ** policies:\
If the desired value is an empty string (`""`), the script will
**delete** the registry value.

Refer to the **Policy Table** in this README for descriptions, types,
and default values.

# 📌 Script Overview

The script performs:

1.  **Detection** of all defined VS Code enterprise policy registry
    values\
2.  **Remediation** of all non-compliant or missing values\
3.  **Final detection**\
4.  Exit codes:
    -   `0` → Fully compliant\
    -   `1` → Not compliant

When fully compliant, the script writes:

    HKLM\Software\<CorporateName>\Visual Studio Code - Baseline Policy Enforcement    Installed     = "Yes"
        ScriptVersion = "<ScriptVersion>"

# 📁 Package Contents

  ---------------------------------------------------------------------------------------------------
  File                                               Description
  -------------------------------------------------- ------------------------------------------------
  `visualstudiocode-baselinepolicyenforcement.ps1`   Full detection + remediation logic

  `README.md`                                        Preparation, deployment, and detection
                                                     instructions
  ---------------------------------------------------------------------------------------------------

# 🛠 Policies Enforced

All Visual Studio Code enterprise configuration is applied under:

    HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode

# ✔ Policy Table (Default Values)

  -----------------------------------------------------------------------------------------------
  Policy Name                          Type           Default Value           Description
  ------------------------------------ -------------- ----------------------- -------------------
  AllowedExtensions                    REG_MULTI_SZ   JSON list               Specifies allowed
                                                                              extensions.

  ChatAgentExtensionTools              REG_DWORD      0                       Disables
                                                                              third-party Chat
                                                                              extension tools.

  ChatAgentMode                        REG_DWORD      0                       Disables Chat agent
                                                                              mode.

  ChatMCP                              REG_SZ         none                    Disables MCP server
                                                                              support.

  ChatToolsAutoApprove                 REG_DWORD      0                       Disables Chat tool
                                                                              auto-approval.

  ChatToolsTerminalEnableAutoApprove   REG_DWORD      0                       Disables
                                                                              auto-approval for
                                                                              Terminal Chat
                                                                              tools.

  EnableFeedback                       REG_DWORD      0                       Disables feedback
                                                                              prompts and
                                                                              surveys.

  ExtensionGalleryServiceUrl           REG_SZ         ""                      Removes custom
                                                                              extension gallery
                                                                              URL.

  McpGalleryServiceUrl                 REG_SZ         ""                      Removes custom MCP
                                                                              gallery URL.

  TelemetryLevel                       REG_SZ         off                     Disables product
                                                                              telemetry.

  UpdateMode                           REG_SZ         default                 Enables background
                                                                              update checks.
  -----------------------------------------------------------------------------------------------

# 🔎 Detection Method (Intune / SCCM)

## 1. Detect ALL enforced VS Code policies (excluding AllowedExtensions)

Multiple registry detection rules must be created.

## 2. Corporate detection keys

These registry keys confirm full compliance including handling of
`AllowedExtensions`.

# 📦 Packaging for Intune (Win32)

1.  Complete required script edits\
2.  Create folder structure\
3.  Package with IntuneWinAppUtil\
4.  Define detection rules

# 🧩 Deployment Monitoring

Use Intune device install status to verify deployment results.

# ✔ Deployment Complete

Visual Studio Code enterprise policies are now centrally defined,
enforced, remediated, and verifiable.
