<#
.SYNOPSIS
    Visual Studio Code - Baseline Policy Enforcement

.DESCRIPTION
  - Enforces Visual Studio Code policies under: HKLM\SOFTWARE\Policies\Microsoft\VSCode
  - Must be run as Administrator or SYSTEM.
  - Single script: detection + remediation combined.
  - Flow:
      1. Detect current state
      2. Remediate non-compliant values
      3. Detect again
      4. Exit 0 if compliant, 1 otherwise

.VERSION
    20251115

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20251115 - Initial release

.EXAMPLE
    Run following command with with admin rights:
    powershell.exe -ExecutionPolicy Bypass -File .\visualstudiocode-baselinepolicyenforcement.ps1

    This example is how to run this script running Windows PowerShell. This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or Microsoft Intune.
#>

# Replace "Example" with your company name e.g. "Contoso"
$CorporateName = "Example"

# Other variables
$ApplicationName = "Visual Studio Code - Baseline Policy Enforcement"
$CorporateRegistryPath = "HKLM:\Software\$CorporateName"
$AppicationRegistryPath = "HKLM:\Software\$CorporateName\$ApplicationName"
$ScriptVersion = "20251115"

#region Pre-flight: optional elevation check (does not block execution)
try {
    $currentIdentity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)

    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Warning "This script should be run as Administrator or SYSTEM. Current identity: $($currentIdentity.Name)"
    } else {
        Write-Host "Running elevated as: $($currentIdentity.Name)"
    }
} catch {
    Write-Warning "Unable to verify elevation status: $_"
}
#endregion Pre-flight

#region Configuration – desired Visual Studio Code policy state

# Registry base path for VS Code policies
$VSCodePolicyRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\VSCode'

# JSON string for AllowedExtensions (stored as REG_MULTI_SZ with a single entry)
$AllowedExtensionsJson = '{"github.vscode-pull-request-github": true, "ms-vscode.powershell": true, "ms-vscode-remote.remote-wsl": true, "hediet.vscode-drawio": true, "
openai.chatgpt": true}'

# All policies and their desired values live here.
# This block is used by BOTH detection and remediation, so they always match.
# NOTE: For ANY String policy: if Value = '' (empty string), the registry value will be removed.
$VSCodePolicies = @(
    @{
        Name      = 'AllowedExtensions'                     # Specify which extensions can be installed.
        ValueKind = 'MultiString'                           # REG_MULTI_SZ with one element (JSON string)
        Value     = @($AllowedExtensionsJson)               # See line number 37. More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-allowed-extensions
    }
    @{
        Name      = 'ChatAgentExtensionTools'               # Enable using tools contributed by third-party extensions.
        ValueKind = 'DWord'                                 # REG_DWORD
        Value     = 0                                       # 0 - disabled / 1 - enabled.
    }
    @{
        Name      = 'ChatAgentMode'                         # Enable agent mode.
        ValueKind = 'DWord'                                 # REG_DWORD
        Value     = 0                                       # 0 - disabled / 1 - enabled.
    }
    @{
        Name      = 'ChatMCP'                               # Enable Model Context Protocol (MCP) servers support and which sources are allowed.
        ValueKind = 'String'                                # REG_SZ
        Value     = 'none'                                  # none - MCP server support is disabled. More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-mcp-server-access
                                                            # Set to '' if you want to remove this value.
    }
    @{
        Name      = 'ChatToolsAutoApprove'                  # Enable global auto-approval for agent mode tools.
        ValueKind = 'DWord'                                 # REG_DWORD
        Value     = 0                                       # 0 - disabled / 1 - enabled.
    }
    @{
        Name      = 'ChatToolsTerminalEnableAutoApprove'    # Enable the rule-based auto-approval for the terminal tool.
        ValueKind = 'DWord'                                 # REG_DWORD
        Value     = 0                                       # 0 - disabled / 1 - enabled.
    }
    @{
        Name      = 'EnableFeedback'                        # Configure feedback mechanisms (issue reporter and surveys).
        ValueKind = 'DWord'                                 # REG_DWORD
        Value     = 0                                       # 0 - disabled / 1 - enabled.
    }
    @{
        Name      = 'ExtensionGalleryServiceUrl'            # Configure the Marketplace service URL to connect to.
        ValueKind = 'String'                                # REG_SZ
        Value     = ''                                      # Defined URL e.g. 'https://example.com/'
                                                            # Set to '' to delete this registry value.
    }
    @{
        Name      = 'McpGalleryServiceUrl'                  # Configure the MCP Gallery service URL to connect to.
        ValueKind = 'String'                                # REG_SZ
        Value     = ''                                      # Defined URL e.g. 'https://example.com/'
                                                            # Set to '' to delete this registry value.
    }
    @{
        Name      = 'TelemetryLevel'                        # Specify telemetry data level.
        ValueKind = 'String'                                # REG_SZ
        Value     = 'off'                                   # off - disables all product telemetry. More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-telemetry-level
                                                            # Set to '' to delete this registry value.
    }
    @{
        Name      = 'UpdateMode'                            # Enable automatic installation of VS Code updates.
        ValueKind = 'String'                                # REG_SZ
        Value     = 'default'                               # default - automatic checking for updates is enabled and runs in the background periodically.
                                                            # Set to '' to delete this registry value. More information and available values: https://code.visualstudio.com/docs/setup/enterprise#_configure-automatic-updates
    }
)
#endregion Configuration

#region Functions – detection and remediation
function Get-VSCodePolicyState {
    <#
    .SYNOPSIS
        Returns current vs desired state for each Visual Studio Code policy value.
    .OUTPUTS
        [PSCustomObject] per policy with:
        - Name, ValueKind, DesiredValue, CurrentValue, Compliant (bool)
    #>
    [CmdletBinding()]
    param()

    # If key is missing, all policies are non-compliant
    if (-not (Test-Path -LiteralPath $VSCodePolicyRegPath)) {
        return $VSCodePolicies | ForEach-Object {
            [PSCustomObject]@{
                Name         = $_.Name
                ValueKind    = $_.ValueKind
                DesiredValue = $_.Value
                CurrentValue = $null
                Compliant    = $false
            }
        }
    }

    $results = foreach ($policy in $VSCodePolicies) {
        $name      = $policy.Name
        $valueKind = $policy.ValueKind
        $desired   = $policy.Value

        try {
            $item = Get-ItemProperty -Path $VSCodePolicyRegPath -Name $name -ErrorAction Stop
            $current = $item.$name
        } catch {
            $current = $null
        }

        $compliant = $false

        # Generic rule: for ANY String policy, empty desired string means "value should not exist"
        $desiredIsEmptyString = $false
        if ($valueKind -eq 'String' -and $desired -is [string] -and [string]::IsNullOrWhiteSpace($desired)) {
            $desiredIsEmptyString = $true
        }

        if ($null -eq $current) {
            if ($desiredIsEmptyString) {
                # Desired = empty string, registry value missing => compliant
                $compliant = $true
            } else {
                $compliant = $false
            }
        } else {
            if ($valueKind -eq 'MultiString') {
                # Compare as joined string to ensure deterministic match
                $desiredJoined = -join $desired
                $currentJoined = -join $current
                $compliant     = ($desiredJoined -eq $currentJoined)
            } else {
                $compliant = ($current -eq $desired)
            }
        }

        [PSCustomObject]@{
            Name         = $name
            ValueKind    = $valueKind
            DesiredValue = $desired
            CurrentValue = $current
            Compliant    = $compliant
        }
    }

    return $results
}

function Test-VSCodePoliciesCompliant {
    <#
    .SYNOPSIS
        Returns $true if ALL policies are compliant; otherwise $false.
    .OUTPUTS
        [bool]
    #>
    [CmdletBinding()]
    param()

    $state   = Get-VSCodePolicyState
    $allGood = -not ($state.Compliant -contains $false)
    return $allGood
}

function Set-VSCodePolicies {
    <#
    .SYNOPSIS
        Applies/remediates Visual Studio Code policies as defined in $VSCodePolicies.
    #>
    [CmdletBinding()]
    param()

    # Ensure the registry key exists
    if (-not (Test-Path -LiteralPath $VSCodePolicyRegPath)) {
        Write-Host "Creating registry key: $VSCodePolicyRegPath"
        New-Item -Path $VSCodePolicyRegPath -Force | Out-Null
    }

    foreach ($policy in $VSCodePolicies) {
        $name      = $policy.Name
        $valueKind = $policy.ValueKind
        $desired   = $policy.Value

        try {
            $existing = Get-ItemProperty -Path $VSCodePolicyRegPath -Name $name -ErrorAction Stop
            $current  = $existing.$name
        } catch {
            $current = $null
        }

        # Generic rule: for ANY String policy, empty desired string means "delete the registry value"
        if ($valueKind -eq 'String' -and $desired -is [string] -and [string]::IsNullOrWhiteSpace($desired)) {
            if ($null -ne $current) {
                Write-Host "Removing policy '$name' because desired value is empty (deleting registry entry)."
                try {
                    Remove-ItemProperty -Path $VSCodePolicyRegPath -Name $name -ErrorAction Stop
                } catch {
                    Write-Warning "Failed to remove policy '$name': $_"
                }
            } else {
                Write-Host "Policy '$name' not configured and desired value is empty (no action needed)."
            }
            continue
        }

        $needsUpdate = $true

        if ($null -ne $current) {
            if ($valueKind -eq 'MultiString') {
                $desiredJoined = -join $desired
                $currentJoined = -join $current
                $needsUpdate   = -not ($desiredJoined -eq $currentJoined)
            } else {
                $needsUpdate   = -not ($current -eq $desired)
            }
        }

        if ($needsUpdate) {
            Write-Host "Setting policy '$name' to desired value."

            if ($null -eq $current) {
                New-ItemProperty -Path $VSCodePolicyRegPath -Name $name -Value $desired -PropertyType $valueKind -Force | Out-Null
            } else {
                Set-ItemProperty -Path $VSCodePolicyRegPath -Name $name -Value $desired -Force
            }
        } else {
            Write-Host "Policy '$name' already compliant."
        }
    }
}
#endregion Functions

#region Main – Detect > Remediate if needed > Final detect > Exit code
Write-Host "=== Visual Studio Code policy enforcement script starting ==="

Write-Host "`n--- State BEFORE remediation ---"
$stateBefore = Get-VSCodePolicyState
$stateBefore | ForEach-Object {
    Write-Host ("{0} - Compliant: {1}" -f $_.Name, $_.Compliant)
}

$initialCompliant = Test-VSCodePoliciesCompliant

if (-not $initialCompliant) {
    Write-Host "`nNon-compliant settings detected. Applying remediation..."
    Set-VSCodePolicies
} else {
    Write-Host "`nAll Visual Studio Code policies already compliant. No remediation needed."
}

Write-Host "`n--- State AFTER remediation (final check) ---"
$stateAfter = Get-VSCodePolicyState
$stateAfter | ForEach-Object {
    Write-Host ("{0} - Compliant: {1}" -f $_.Name, $_.Compliant)
}

$finalCompliant = Test-VSCodePoliciesCompliant

if ($finalCompliant) {
    Write-Host "`nFinal result: Visual Studio Code policies are compliant."
    # Let's create registry key for Micorosoft Intune or Microsoft Configuration Manager detection rule purposes and close the script
    Write-Host "Creating registry key for Microsoft Intune or Microsoft Configuration Manager detection rule purposes..."
    if (-not (Test-Path -Path $CorporateRegistryPath)) {
        New-Item -Path $CorporateRegistryPath -Force -Verbose
    }else {
        Write-Host "Registry path '$CorporateRegistryPath' is already created. Let's continue..." 
    }

    if (-not (Test-Path -Path $AppicationRegistryPath)) {
        New-Item -Path $AppicationRegistryPath -Force -Verbose
    }else {
        Write-Host "Registry path '$AppicationRegistryPath' is already created. Let's continue..." 
    }

    Set-ItemProperty -Path $AppicationRegistryPath -Name "Installed" -Value "Yes" -Type "String" -Force -Verbose
    Set-ItemProperty -Path $AppicationRegistryPath -Name "ScriptVersion" -Value "$ScriptVersion" -Type "String" -Force -Verbose

    # Wait for moment
    Start-Sleep -Seconds 10

    # Closing script
    Write-Output "All done. Closing script..."
    Start-Sleep -Seconds 10
    
    exit 0
} else {
    Write-Warning "`nFinal result: Visual Studio Code policies are NOT fully compliant."
    exit 1
}
#endregion Main