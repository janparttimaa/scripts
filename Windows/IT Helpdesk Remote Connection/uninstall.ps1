<#
.SYNOPSIS
    IT Helpdesk Remote Connection Uninstaller.

.DESCRIPTION
  Uninstalls the "IT Helpdesk Remote Connection" deployment safely:
  - Removes the All Users Start Menu shortcut
  - Deletes only known files from the install folder
  - Removes the product folder *only if empty* afterward
  - Optionally removes empty parent company folder
  - Logs activity to C:\ProgramData\<Company>\IT Helpdesk Remote Connection\
    
    NOTES: You need to do some preparations before deploying this script. Please check preparation instructions from GitHub.

.VERSION
    20251102

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASENOTES
    20251102 - Initial release.

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\uninstall.ps1
    This example is how to run this script running Windows PowerShell. Run this command with your admin rights.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    # Replace "Example" with your company name e.g. "Contoso"
    [string]$CorporateName = "Example",
    [string]$ApplicationName = "IT Helpdesk Remote Connection",
    [string]$AppicationRegistryPath = "HKLM:\Software\$CorporateName\$ApplicationName",
    [string[]]$ExpectedFiles = @("Create-RemoteAssistanceInvitation.ps1","Create-RemoteAssistanceInvitation.bat")
)

function Test-Admin {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($current)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# --- Logging ---
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logDir = "C:\ProgramData\$CorporateName\$ApplicationName"

# Ensure log directory exists
try {
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
} catch {
    Write-Warning "Could not create log directory '$logDir': $($_.Exception.Message)"
    $logDir = $env:TEMP
}

$logPath = Join-Path $logDir "${CorporateName}-Uninstall-${timestamp}.log"
try {
    Start-Transcript -Path $logPath -Append -ErrorAction Stop | Out-Null
} catch {
    Write-Warning "Could not start transcript: $($_.Exception.Message)"
}

try {
    # --- Constants and paths ---
    $startMenuAllUsers = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs"
    $shortcutName      = "$CorporateName $ApplicationName.lnk"
    $shortcutPath      = Join-Path $startMenuAllUsers $shortcutName

    # Determine possible install locations (covering x64/x86 and hardcoded path)
    $pf64   = $env:ProgramW6432
    $pf32   = ${env:ProgramFiles(x86)}
    $pf     = $env:ProgramFiles

    $candidateDirs = @(
        "C:\Program Files\$CorporateName\$ApplicationName",
        $(if ($pf64) { Join-Path $pf64 "$CorporateName\$ApplicationName" }),
        $(if ($pf32) { Join-Path $pf32 "$CorporateName\$ApplicationName" }),
        $(if ($pf)   { Join-Path $pf   "$CorporateName\$ApplicationName" })
    ) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique

    Write-Verbose "Shortcut path: $shortcutPath"
    Write-Verbose "Candidate install directories:`n - $($candidateDirs -join "`n - ")"
    Write-Verbose "Expected files to remove: $($ExpectedFiles -join ', ')"

    # --- Remove Start Menu shortcut (All Users) ---
    if (Test-Path $shortcutPath) {
        if ($PSCmdlet.ShouldProcess($shortcutPath, "Remove shortcut")) {
            try {
                Remove-Item -LiteralPath $shortcutPath -Force -ErrorAction Stop
                Write-Host "Removed shortcut: $shortcutPath"
            } catch {
                Write-Warning "Failed to remove shortcut '$shortcutPath': $($_.Exception.Message)"
            }
        }
    } else {
        Write-Verbose "Shortcut not found: $shortcutPath"
    }

    # --- Remove only known files, then product folder if empty ---
    foreach ($dir in $candidateDirs) {
        if (-not (Test-Path $dir)) { continue }

        Write-Verbose "Processing install directory: $dir"

        # Remove expected files only
        foreach ($rel in $ExpectedFiles) {
            $target = Join-Path $dir $rel
            if (Test-Path -LiteralPath $target) {
                if ($PSCmdlet.ShouldProcess($target, "Remove expected file")) {
                    try {
                        try { (Get-Item -LiteralPath $target -Force).Attributes = 'Normal' } catch {}
                        Remove-Item -LiteralPath $target -Force -ErrorAction Stop
                        Write-Host "Removed file: $target"
                    } catch {
                        Write-Warning "Failed to remove file '$target': $($_.Exception.Message)"
                    }
                }
            } else {
                Write-Verbose "Expected file not found (skipped): $target"
            }
        }

        # After removals, decide whether to delete the product folder
        $remaining = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) {
            if ($PSCmdlet.ShouldProcess($dir, "Remove empty product folder")) {
                try {
                    Remove-Item -LiteralPath $dir -Force -ErrorAction Stop
                    Write-Host "Removed empty product folder: $dir"
                } catch {
                    Write-Warning "Failed to remove folder '$dir': $($_.Exception.Message)"
                }
            }
        } else {
            Write-Host "Left product folder in place (not empty): $dir"
            Write-Verbose ("Remaining items:`n - {0}" -f ($remaining.FullName -join "`n - "))
        }

        # Attempt to remove empty parent company folder if now empty
        $parent = Split-Path $dir -Parent
        if ($parent -and (Test-Path $parent)) {
            $parentRemaining = @(Get-ChildItem -LiteralPath $parent -Force -ErrorAction SilentlyContinue)
            if ($parentRemaining.Count -eq 0) {
                if ($PSCmdlet.ShouldProcess($parent, "Remove empty parent company folder")) {
                    Remove-Item -LiteralPath $parent -Force -ErrorAction SilentlyContinue
                    Write-Verbose "Removed empty parent folder: $parent"
                }
            } else {
                Write-Verbose "Parent folder not empty; left in place: $parent"
            }
        }
    }

    if (-not $candidateDirs) {
        Write-Host "No matching install directory found under Program Files."
    }

    # Removing registry entries
    Write-Host "Removing registry entries..."
    Remove-Item -Path $ApplicationRegistryPath -Recurse -Force -Verbose
    Write-Host "Uninstallation is now done. Closing script..."
}
finally {
    try { Stop-Transcript | Out-Null } catch {}
    Write-Verbose "Log written to: $logPath"
    if (Test-Path $logPath) { Write-Host "Log: $logPath" }
}

Start-Sleep 10
exit 0