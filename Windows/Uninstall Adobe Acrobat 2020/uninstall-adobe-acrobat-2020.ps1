<#
.SYNOPSIS
    Uninstall Adobe Acrobat 2020 and Adobe Genuine Service from Windows-devices.

.DESCRIPTION
    This PowerShell-script will uninstall Adobe Acrobat 2020 and Adobe Genuine Service from Windows-devices.

.VERSION
    20250903

.AUTHOR
    Jan Parttimaa (https://github.com/janparttimaa)

.COPYRIGHT
    © 2025 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20250903 - Initial release

.EXAMPLE
    Run following command with admin rights:
    powershell.exe -ExecutionPolicy Bypass -File .\uninstall-adobe-acrobat-2020.ps1

    This example is how to run this script running Windows PowerShell. This is also the command that needs to be use when deploying it via Microsoft Configuration Manager or Microsoft Intune.
#>


# ===================== COMPANY VARIABLE =====================
$CompanyName = "Contoso"   # <-- Change it to appropriate one
# ============================================================

# ===================== AGS CLEANER SOURCE (OFFICIAL) =====================
$AgsCleanerZipUrl = "https://helpx.adobe.com/content/dam/help/en/enterprise/using/uninstall-creative-cloud-products/jcr_content/root/content/flex/items/position/position-par/procedure/proc_par/step_0/step_par/download_section/download-1/Win_AdobeGenuineCleaner.zip"
$DownloadRetries  = 3
# ========================================================================

$ErrorActionPreference = 'Stop'

# ---------- Paths ----------
$BaseRoot  = Join-Path "C:\ProgramData" $CompanyName
$WorkRoot  = Join-Path $BaseRoot "Uninstall Adobe Acrobat 2020"
$ToolsRoot = Join-Path $WorkRoot "AGS_Cleaner"
$LogPath   = Join-Path $WorkRoot "uninstall.log"
$ZipPath   = Join-Path $ToolsRoot "Win_AdobeGenuineCleaner.zip"
$CleanerExe = Join-Path $ToolsRoot "AdobeGenuineCleaner.exe"

# Ensure folders
New-Item -ItemType Directory -Path $WorkRoot -Force | Out-Null
New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null

# ---------- Logging ----------
function Write-Log {
    param([string]$Message,[string]$Level='INFO')
    $ts = (Get-Date).ToString('dd.MM.yyyy HH.mm.ss')
    $line = "$ts [$Level] $Message"
    Add-Content -Path $LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

Write-Log "=== Adobe cleanup started ==="

# ---------- Helpers ----------
function Close-Process {
    param([string[]]$Names,[int]$GraceSeconds=5)
    foreach ($name in $Names) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        if ($procs) {
            Write-Log "Found running process $name ($($procs.Count)); attempting graceful close..."
            foreach ($p in $procs) { try { $p.CloseMainWindow() | Out-Null } catch {} }
            Start-Sleep -Seconds $GraceSeconds
            $still = Get-Process -Name $name -ErrorAction SilentlyContinue
            if ($still) { Write-Log "Force-killing lingering $name..."; $still | Stop-Process -Force -ErrorAction SilentlyContinue }
        } else { Write-Log "No running process found for $name." }
    }
}

function Invoke-Proc {
    param([Parameter(Mandatory)][string]$FilePath,[string]$Arguments='',[int]$TimeoutSeconds=3600)
    Write-Log "Running: `"$FilePath`" $Arguments"
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo.FileName = $FilePath
    $p.StartInfo.Arguments = $Arguments
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.RedirectStandardOutput = $true
    $p.StartInfo.RedirectStandardError  = $true
    [void]$p.Start()
    if (-not $p.WaitForExit($TimeoutSeconds*1000)) { try { $p.Kill() } catch {}; Write-Log "Process timed out and was killed." "ERROR"; return 1460 }
    $out = $p.StandardOutput.ReadToEnd(); if ($out) { Write-Log "OUT: $($out.Trim())" }
    $err = $p.StandardError.ReadToEnd();  if ($err) { Write-Log "ERR: $($err.Trim())" }
    Write-Log "ExitCode: $($p.ExitCode)"
    return $p.ExitCode
}

function Get-UninstallEntries {
    param([string[]]$NamePatterns)
    $hives = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    $res = @()
    foreach ($h in $hives) {
        if (Test-Path $h) {
            Get-ChildItem $h | ForEach-Object {
                $p = Get-ItemProperty $_.PSPath
                if ($p.DisplayName) {
                    foreach ($pat in $NamePatterns) {
                        if ($p.DisplayName -like $pat) {
                            $res += [PSCustomObject]@{
                                DisplayName            = $p.DisplayName
                                UninstallString        = $p.UninstallString
                                QuietUninstallString   = $p.QuietUninstallString
                            }
                            break
                        }
                    }
                }
            }
        }
    }
    $res | Sort-Object -Property DisplayName -Unique
}

# Robust Acrobat uninstall parsing
function Split-UninstallCommand {
    param([Parameter(Mandatory)][string]$Raw)
    $Raw = $Raw.Trim()
    Write-Log "Raw uninstall string: $Raw"
    if ($Raw -match '(?i)msiexec(\.exe)?') {
        return @{ IsMsiexec=$true; FilePath="$env:WINDIR\System32\msiexec.exe"; Arguments=($Raw -replace '(?i)^.*?msiexec(\.exe)?\s*',''); Raw=$Raw; Fallback=$false }
    }
    if ($Raw.StartsWith('"')) {
        $end = $Raw.IndexOf('"',1); if ($end -gt 1) { $exe=$Raw.Substring(1,$end-1); $args=$Raw.Substring($end+1).Trim(); return @{ IsMsiexec=$false; FilePath=$exe; Arguments=$args; Raw=$Raw; Fallback=$false } }
    }
    if ($Raw -match '(?i)^\s*(.+?\.(exe|cmd|bat))\s*(.*)$') { return @{ IsMsiexec=$false; FilePath=$matches[1]; Arguments=$matches[3]; Raw=$Raw; Fallback=$false } }
    Write-Log "Could not confidently parse exe path; using cmd.exe /c."
    return @{ IsMsiexec=$false; FilePath="$env:WINDIR\System32\cmd.exe"; Arguments="/c `"$Raw`""; Raw=$Raw; Fallback=$true }
}

function Invoke-AcrobatUninstallFromEntry {
    param([Parameter(Mandatory)][psobject]$Entry)
    $candidate = if ($Entry.QuietUninstallString) { $Entry.QuietUninstallString } else { $Entry.UninstallString }
    if ([string]::IsNullOrWhiteSpace($candidate)) { Write-Log "No uninstall string for $($Entry.DisplayName)" "ERROR"; return 1 }

    if ($candidate -match '(\{[0-9A-Fa-f\-]{36}\})') {
        $guid = $matches[1]; Write-Log "MSI GUID detected: $guid"
        return Invoke-Proc -FilePath "$env:WINDIR\System32\msiexec.exe" -Arguments "/x $guid /qn /norestart"
    }

    $parts = Split-UninstallCommand -Raw $candidate
    $cmd   = $parts.FilePath; $args = $parts.Arguments; $isMsiexec=$parts.IsMsiexec; $fallback=$parts.Fallback
    if ($isMsiexec) { if ($args -notmatch '(?i)(/qn|/quiet)') { $args+=' /qn' }; if ($args -notmatch '(?i)/norestart') { $args+=' /norestart' } }
    elseif (-not $fallback) { $lc=$args.ToLower(); if ($lc -notmatch '\b(/s|/silent|/verysilent|--silent|--quiet|/qn|/q)\b') { $args+=' --silent' }; if ($args -notmatch '(?i)norestart') { $args+=' /norestart' } }
    if (-not $fallback -and -not (Test-Path $cmd)) { Write-Log "Parsed exe missing: $cmd" "ERROR"; $cmd="$env:WINDIR\System32\cmd.exe"; $args="/c `"$($parts.Raw)`"" }
    Write-Log "Uninstalling: $($Entry.DisplayName)"
    return Invoke-Proc -FilePath $cmd -Arguments $args
}

# ---- BITS-first downloader for AGS Cleaner ZIP ----
function Download-AgsCleanerZip {
    <#
      Downloads the AGS Cleaner ZIP to $ZipPath.
      Uses BITS (RetryInterval >= 60), falls back to WebClient.
      Returns: $true on success, $false on failure.
    #>
    if (Test-Path $ZipPath) { try { Remove-Item $ZipPath -Force } catch {} }
    # Try BITS
    $bitsAvailable = $false
    try { Get-Command Start-BitsTransfer -ErrorAction Stop | Out-Null; $bitsAvailable = $true } catch {}
    if ($bitsAvailable) {
        for ($i=1; $i -le $DownloadRetries; $i++) {
            try {
                Write-Log "Downloading AGS Cleaner via BITS (attempt $i/$DownloadRetries) -> $ZipPath"
                Start-BitsTransfer -Source $AgsCleanerZipUrl -Destination $ZipPath -Priority Foreground -RetryInterval 60 -Description "Download AGS Cleaner" -ErrorAction Stop
                if ((Test-Path $ZipPath) -and ((Get-Item $ZipPath).Length -gt 0)) { Write-Log "BITS download complete: $ZipPath"; return $true }
                throw "BITS completed but file missing/empty."
            } catch {
                Write-Log "BITS attempt ${i} failed: $($_.Exception.Message)" "ERROR"
                if ($i -lt $DownloadRetries) { Start-Sleep -Seconds (5*$i) }
            }
        }
        Write-Log "All BITS attempts failed; falling back to WebClient."
    }
    # WebClient fallback
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 } catch {}
    for ($i=1; $i -le $DownloadRetries; $i++) {
        try {
            Write-Log "Downloading AGS Cleaner via WebClient (attempt $i/$DownloadRetries) -> $ZipPath"
            $wc = New-Object System.Net.WebClient
            $wc.DownloadFile($AgsCleanerZipUrl, $ZipPath)
            if ((Test-Path $ZipPath) -and ((Get-Item $ZipPath).Length -gt 0)) { Write-Log "WebClient download complete: $ZipPath"; return $true }
            throw "WebClient completed but file missing/empty."
        } catch {
            Write-Log "WebClient attempt ${i} failed: $($_.Exception.Message)" "ERROR"
            if ($i -lt $DownloadRetries) { Start-Sleep -Seconds (5*$i) }
        }
    }
    Write-Log "Failed to download AGS Cleaner ZIP via both BITS and WebClient." "ERROR"
    return $false
}

function Ensure-AgsCleanerAtToolsRoot {
    <#
      Ensures AdobeGenuineCleaner.exe resides at:
        $CleanerExe  (i.e., C:\ProgramData\<CompanyName>\Uninstall Adobe Acrobat 2020\AGS_Cleaner\AdobeGenuineCleaner.exe)
      Steps:
        - Download ZIP directly to $ZipPath
        - Expand ZIP into $ToolsRoot
        - If EXE ends up in a subfolder, copy it to $CleanerExe
      Returns: [string] full path to EXE, or $null on failure.
    #>
    Write-Log "Target cleaner exe path: $CleanerExe"
    if (Test-Path $CleanerExe) { Write-Log "Cleaner already present."; return [string]$CleanerExe }

    if (-not (Download-AgsCleanerZip)) { return $null }

    try {
        Write-Log "Expanding AGS Cleaner ZIP to $ToolsRoot"
        Expand-Archive -LiteralPath $ZipPath -DestinationPath $ToolsRoot -Force
    } catch {
        Write-Log "Failed to expand ZIP: $($_.Exception.Message)" "ERROR"
        return $null
    }

    # If EXE not directly at ToolsRoot, search for it and copy to canonical path
    if (-not (Test-Path $CleanerExe)) {
        $found = Get-ChildItem -Path $ToolsRoot -Recurse -Filter 'AdobeGenuineCleaner.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) {
            try { Copy-Item -LiteralPath $found.FullName -Destination $CleanerExe -Force } catch { Write-Log "Could not copy cleaner exe to target: $($_.Exception.Message)" "ERROR" }
        }
    }

    if (Test-Path $CleanerExe) { return [string]$CleanerExe }
    Write-Log "AdobeGenuineCleaner.exe not found after extraction." "ERROR"
    return $null
}

function Clean-AgsLeftovers {
    # Kill lingering processes & remove folders after cleaner
    Close-Process -Names @('AdobeGCClient','AGMService','AGMClient','AdobeGCInvoker-1.0','adobe_licutil') -GraceSeconds 2
    $paths = @('C:\Program Files (x86)\Common Files\Adobe\AdobeGCClient','C:\Program Files\Common Files\Adobe\AdobeGCClient')
    foreach ($path in $paths) {
        if (Test-Path $path) {
            try { Write-Log "Removing leftover folder: ${path}"; Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction Stop } catch { Write-Log "Could not remove ${path}: $($_.Exception.Message)" }
        }
    }
}

# ---------- Main ----------
$overallExit = 0
$rebootSuggested = $false

try {
    # Close Acrobat UI if open
    Write-Log "Checking for running Acrobat processes..."
    Close-Process -Names @('Acrobat','acrobat','AcroRd32')

    # === AGS via Cleaner ONLY (download to & extract at the requested path) ===
    Write-Log "Removing Adobe Genuine Service using AGS Cleaner ONLY..."
    $cleanerPath = Ensure-AgsCleanerAtToolsRoot
    Write-Log "Cleaner exe path resolved: $cleanerPath"

    if ([string]::IsNullOrWhiteSpace($cleanerPath) -or -not (Test-Path $cleanerPath)) {
        Write-Log "Cannot run AGS Cleaner (missing executable at requested path)." "ERROR"
        if ($overallExit -eq 0) { $overallExit = 1 }
    } else {
        $cleanCode = Invoke-Proc -FilePath $cleanerPath -Arguments '--UninstallUserDriven'
        if ($cleanCode -in @(3010,1641)) { $rebootSuggested = $true }
        Clean-AgsLeftovers
    }

    # === Acrobat 2020 ===
    Write-Log "Handling Adobe Acrobat 2020..."
    $acroEntries = Get-UninstallEntries -NamePatterns @('Adobe Acrobat 2020*','Adobe Acrobat Pro 2020*','Adobe Acrobat Standard 2020*')
    foreach ($entry in $acroEntries) {
        $code = Invoke-AcrobatUninstallFromEntry -Entry $entry
        if ($code -in @(3010,1641)) { $rebootSuggested = $true }
        if ($code -notin @(0,1605,1614,3010,1641) -and $overallExit -eq 0) { $overallExit = $code }
    }

    # === Final Cleanup (dynamic CompanyName) ===
    $cleanupPaths = @(
        'C:\Program Files (x86)\Adobe',
        'C:\Program Files (x86)\Common Files\Adobe',
        'C:\ProgramData\Adobe',
        (Join-Path (Join-Path "C:\ProgramData" $CompanyName) "Uninstall Adobe Acrobat 2020\AGS_Cleaner")
    )

    foreach ($cPath in $cleanupPaths) {
        if (Test-Path $cPath) {
            try {
                Write-Log "Removing leftover folder: $cPath"
                Remove-Item -LiteralPath $cPath -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Log "Could not remove ${cPath}: $($_.Exception.Message)" "ERROR"
            }
        } else {
            Write-Log "Cleanup folder not found: $cPath"
        }
    }

} catch {
    Write-Log "Unhandled error: $($_.Exception.Message)" "ERROR"
    if ($overallExit -eq 0) { $overallExit = 1 }
}

# ---------- Finalize ----------
$finalExit = if ($rebootSuggested) { 3010 } else { $overallExit }
Write-Log "Final exit code to Intune: $finalExit"
Write-Output "INTUNE_EXIT_CODE=$finalExit"
[Environment]::Exit($finalExit)