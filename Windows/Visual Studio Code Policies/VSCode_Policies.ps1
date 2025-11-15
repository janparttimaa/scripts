<#
.SYNOPSIS
  Enforces Visual Studio Code policies under:
  HKLM\SOFTWARE\Policies\Microsoft\VSCode

.DESCRIPTION
  - Must be run as Administrator or SYSTEM.
  - Single script: detection + remediation combined.
  - Flow:
      1. Detect current state
      2. Remediate non-compliant values
      3. Detect again
      4. Exit 0 if compliant, 1 otherwise
#>

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

#region Configuration – desired VS Code policy state

# Registry base path for VS Code policies
$VSCodePolicyRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\VSCode'

# JSON string for AllowedExtensions (stored as REG_MULTI_SZ with a single entry)
# Matches the content of the provided .reg hex value.
$AllowedExtensionsJson = '{"github.vscode-pull-request-github": true, "ms-vscode.powershell": true, "ms-vscode-remote.remote-wsl": true, "hediet.vscode-drawio": true}'

# All policies and their desired values live here.
# This block is used by BOTH detection and remediation, so they always match.
$VSCodePolicies = @(
    @{
        Name      = 'UpdateMode'
        ValueKind = 'String'        # REG_SZ
        Value     = 'default'
    }
    @{
        Name      = 'EnableFeedback'
        ValueKind = 'DWord'         # REG_DWORD
        Value     = 0
    }
    @{
        Name      = 'TelemetryLevel'
        ValueKind = 'String'        # REG_SZ
        Value     = 'off'
    }
    @{
        Name      = 'ChatToolsTerminalEnableAutoApprove'
        ValueKind = 'DWord'         # REG_DWORD
        Value     = 0
    }
    @{
        Name      = 'ChatAgentExtensionTools'
        ValueKind = 'DWord'         # REG_DWORD
        Value     = 0
    }
    @{
        Name      = 'ChatAgentMode'
        ValueKind = 'DWord'         # REG_DWORD
        Value     = 0
    }
    @{
        Name      = 'ChatToolsAutoApprove'
        ValueKind = 'DWord'         # REG_DWORD
        Value     = 0
    }
    @{
        Name      = 'AllowedExtensions'
        ValueKind = 'MultiString'   # REG_MULTI_SZ with one element (JSON string)
        Value     = @($AllowedExtensionsJson)
    }
)
#endregion Configuration

#region Functions – detection and remediation
function Get-VSCodePolicyState {
    <#
    .SYNOPSIS
        Returns current vs desired state for each VS Code policy value.
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

        if ($null -eq $current) {
            $compliant = $false
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
        Applies/remediates VS Code policies as defined in $VSCodePolicies.
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
Write-Host "=== VS Code policy enforcement script starting ==="

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
    Write-Host "`nAll VS Code policies already compliant. No remediation needed."
}

Write-Host "`n--- State AFTER remediation (final check) ---"
$stateAfter = Get-VSCodePolicyState
$stateAfter | ForEach-Object {
    Write-Host ("{0} - Compliant: {1}" -f $_.Name, $_.Compliant)
}

$finalCompliant = Test-VSCodePoliciesCompliant

if ($finalCompliant) {
    Write-Host "`nFinal result: VS Code policies are compliant."
    exit 0
} else {
    Write-Warning "`nFinal result: VS Code policies are NOT fully compliant."
    exit 1
}
#endregion Main
