# VS Code Policy Enforcement – Intune Deployment

This package deploys a PowerShell script that enforces required **Visual Studio Code policy settings** through the registry.  
The script performs detection, remediation, and final compliance verification in a **single file**, with **no parameters required**.

---

## 📌 Overview

The script automatically:

1. **Checks** policy values under  
   `HKLM\SOFTWARE\Policies\Microsoft\VSCode`
2. **Applies missing or incorrect values**  
3. **Verifies compliance**  
4. Returns an exit code:
   - **0** → Compliant  
   - **1** → Not compliant  

This allows the script to act as both:

- The **installer logic** for the Intune Win32 App, and  
- The **compliance verifier** used by Intune detection rules.

---

## 📁 Package Contents

| File | Purpose |
|------|---------|
| `vscode-policies.ps1` | Single-file detection + remediation script |
| `README.md` | Deployment instructions |

---

## 🛠 Policies Enforced

Registry path:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode
```

| Policy | Type | Value |
|--------|-------|--------|
| UpdateMode | REG_SZ | `default` |
| EnableFeedback | REG_DWORD | `0` |
| TelemetryLevel | REG_SZ | `off` |
| ChatToolsTerminalEnableAutoApprove | REG_DWORD | `0` |
| ChatAgentExtensionTools | REG_DWORD | `0` |
| ChatAgentMode | REG_DWORD | `0` |
| ChatToolsAutoApprove | REG_DWORD | `0` |
| AllowedExtensions | REG_MULTI_SZ | JSON list of allowed extensions |

---

# 🚀 Deployment via Intune (Win32 App)

Follow the steps below to package and deploy the script.

---

## 1. Prepare Folder Structure

```
C:\Intune\VSCodePolicies\
│
├── Source\
│   └── VSCode_Policies.ps1
│
└── Output\
```

Place **only the script** inside the `Source` folder.

---

## 2. Create the .intunewin File

Use the Microsoft Win32 Content Prep Tool (`IntuneWinAppUtil.exe`):

```cmd
IntuneWinAppUtil.exe
```

Input:

- **Source folder:** `C:\Intune\VSCodePolicies\Source`
- **Setup file:** `VSCode_Policies.ps1`
- **Output folder:** `C:\Intune\VSCodePolicies\Output`

Result:

```
VSCode_Policies.intunewin
```

---

## 3. Add the App in Intune

1. Go to **Apps → Windows → Add**
2. Select **Windows app (Win32)**
3. Upload `VSCode_Policies.intunewin`

---

## 4. Configure App Information

Example:

- **Name:** VS Code – Policy Enforcement
- **Publisher:** YourOrganization
- **Description:** Enforces Visual Studio Code policy configuration.

---

## 5. Configure Program Settings

### **Install Command**

Use 64-bit PowerShell:

```cmd
C:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -File .\VSCode_Policies.ps1
```

### **Uninstall Command**

Policies do not need uninstalling. Use a no-op command:

```cmd
cmd /c exit 0
```

### Settings

| Setting | Value |
|--------|--------|
| Install behavior | **System** |
| Device restart behavior | No specific action |

---

## 6. Configure Detection Rules (Registry)

Choose:

**Manually configure detection rules**

Add the following **Registry** rules.  
Set **Associated with a 32-bit app… → No**

All rules use **Key path:**

```
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\VSCode
```

### Required Detection Rules

| Value name | Method | Operator | Expected value |
|------------|--------|----------|----------------|
| UpdateMode | String | Equals | default |
| EnableFeedback | Integer | Equals | 0 |
| TelemetryLevel | String | Equals | off |
| ChatToolsTerminalEnableAutoApprove | Integer | Equals | 0 |
| ChatAgentExtensionTools | Integer | Equals | 0 |
| ChatAgentMode | Integer | Equals | 0 |
| ChatToolsAutoApprove | Integer | Equals | 0 |
| AllowedExtensions | Value exists | — | — |

**Note:**  
`AllowedExtensions` is REG_MULTI_SZ; Intune cannot reliably compare its JSON content. Detecting **value exists** is recommended.

---

## 7. Assign the App

Recommended assignment:

- **Required** → Device groups

This ensures all machines receive the policy configuration.

---

## 8. Monitoring Deployment

Navigate to:

**Apps → VS Code – Policy Enforcement → Device install status**

Interpretation:

- **Installed** → Script executed successfully; all policies compliant  
- **Failed** → Exit code 1; policies not compliant after remediation  

---

# ✔ Deployment Complete

The VS Code Policy Enforcement script is successfully prepared for Intune deployment.  
If you need enhanced logging, event log integration, or script extensions, feel free to ask!