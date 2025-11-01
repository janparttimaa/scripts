# Requires -RunAsAdministrator
<#
.SYNOPSIS
    Removes per-user (AppData-installed) copies of Chrome, Firefox, GIMP, Git for Windows, and Refinitiv Workspace
    across all local user profiles. Optionally stops only per-user processes, purges per-user data, cleans broken
    shortcuts in per-user Desktop/Start Menu, and removes per-user uninstall registry entries.

.DESCRIPTION
    This script is designed for environments where users may have installed products to their profile (AppData)
    even when a machine-wide copy exists in Program Files. To avoid disrupting machine-wide installations,
    the script:
      - Identifies and stops ONLY per-user processes (based on executable path patterns under the user profile).
      - Invokes each product’s per-user uninstaller when present; otherwise performs best-effort cleanup.
      - Optionally removes per-user app data/directories (when -PurgeData is specified for a product).
      - Cleans up broken shortcuts (*.lnk) in the user’s Desktop and Start Menu (NOT public folders).
      - Removes per-user uninstall registry keys from each user’s hive (loaded or by temporarily loading NTUSER.DAT).
      - Writes per-product logs to C:\ProgramData\AppLocker with colorized console output for quick scanning.

    Execution is controlled by the Boolean switches at the top of the script (e.g. $RunChromeCleanup).
    Each product has its own function and consistent internal structure for logging, admin verification,
    process filtering, profile enumeration, shortcut cleanup, and registry cleanup.

PREREQUISITES
    - Run as local Administrator (the script checks and throws if not).
    - PowerShell 5.1+ or PWSh 7+ with access to WScript.Shell COM for shortcut inspection.
    - Access to user profile paths and NTUSER.DAT for offline hive loading.
    - Write permissions to C:\ProgramData\AppLocker for logging.

SAFETY / SCOPE
    - The script intentionally DOES NOT modify Public Desktop or All Users Start Menu content.
    - Only per-user, AppData-based installations are targeted; Program Files installs are left untouched.
    - Process termination is constrained to per-user paths, minimizing collateral impact.
    - Registry hive load/unload is wrapped in try/finally for safety; failures are logged and skipped.

LOGGING
    - Per-product transcripts are written to C:\ProgramData\AppLocker\<Product>Uninstall_yyyyMMdd_HHmmss.log
    - Console output is color-coded (white=info, green=success, red=warnings/errors).

EXAMPLES
    # Run all cleanups with process stop + data purge (default script behavior)
    # (toggle the switches below to include/exclude products)
    .\PerUserAppCleanup.ps1

    # Run only Firefox without data purge:
    $RunChromeCleanup = $false
    $RunFirefoxCleanup = $true
    $RunGimpCleanup = $false
    $RunGitCleanup = $false
    $RunRefinitivCleanup = $false
    .\PerUserAppCleanup.ps1
#>

# ========================================================
#  EXECUTION SWITCHES - toggle individual product cleanups
#  NOTE: These control which product functions are invoked at the bottom.
#        They do not alter the behavior of those functions internally.
# ========================================================
$RunChromeCleanup      = $true   # TRUE => run Uninstall-ChromeFromAllUsers
$RunFirefoxCleanup     = $true   # TRUE => run Uninstall-FirefoxFromAllUsers
$RunGimpCleanup        = $true   # TRUE => run Uninstall-GimpFromAllUsers
$RunGitCleanup         = $true   # TRUE => run Uninstall-GitFromAllUsers
$RunRefinitivCleanup   = $true   # TRUE => run Uninstall-RefinitivWorkspaceFromAllUsers

# ========================================================
#  COLORIZED LOGGING HELPERS
#  - Centralized mapping of message content/level to console colors.
#  - Kept generic so each product logger can reuse the decision.
# ========================================================
function Get-LogForegroundColor {
    <#
    .SYNOPSIS
        Maps a message + level to a friendly console color.
    .DESCRIPTION
        Explicit level names take precedence; otherwise pattern-matches the message body.
        Defaults to White for neutral informational messages.
    .PARAMETER Message
        The message to colorize.
    .PARAMETER Level
        Optional level hint (e.g., SUCCESS/WARN/ERROR).
    .OUTPUTS
        [string] - A valid ConsoleColor name (e.g., 'Green', 'Red', 'White').
    #>
    param(
        [string]$Message,
        [string]$Level
    )

    # Normalize level for simple switch comparisons.
    $levelUpper = if ($Level) { $Level.ToUpperInvariant() } else { "" }

    switch ($levelUpper) {
        "SUCCESS" { return "Green" }
        "WARN"    { return "Red"   }
        "ERROR"   { return "Red"   }
    }

    # Fall back to scanning the message when no explicit level is provided.
    $normalizedMessage = if ($Message) { $Message } else { "" }

    if ($normalizedMessage -match '(?i)(success|completed|succeeded)') { return "Green" }
    if ($normalizedMessage -match '(?i)(fail|unable|error|denied|not found|missing)') { return "Red" }

    return "White"  # Default neutral
}

# --------------------------------------------------------
# Helper: build candidate paths under Program Files roots.
# --------------------------------------------------------
function Get-ProgramFilesCandidates {
    <#
    .SYNOPSIS
        Returns concrete Program Files paths for one or more relative subpaths.
    .PARAMETER RelativePaths
        Relative subpaths (can include wildcards) to append to Program Files roots.
    .OUTPUTS
        [string[]] with unique, fully-qualified candidate paths.
    #>
    param(
        [string[]]$RelativePaths
    )

    $roots = @(
        [Environment]::GetEnvironmentVariable('ProgramFiles'),
        [Environment]::GetEnvironmentVariable('ProgramW6432'),
        [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    ) | Where-Object { $_ }

    $candidates = @()
    foreach ($root in ($roots | Sort-Object -Unique)) {
        if (-not $RelativePaths) {
            $candidates += $root
            continue
        }

        foreach ($relative in $RelativePaths) {
            if (-not $relative) { continue }
            $candidates += (Join-Path -Path $root -ChildPath $relative)
        }
    }

    return $candidates | Sort-Object -Unique
}

# --------------------------------------------------------
# Helper: return the first existing path from a candidate set.
# --------------------------------------------------------
function Get-FirstExistingPath {
    <#
    .SYNOPSIS
        Returns the first resolved filesystem path that exists.
    .PARAMETER CandidatePaths
        One or more fully-qualified paths (optionally with wildcards).
    .OUTPUTS
        [string] - first matching path, or $null when none exist.
    #>
    param(
        [string[]]$CandidatePaths
    )

    foreach ($candidate in $CandidatePaths) {
        if (-not $candidate) { continue }

        try {
            $resolved = Resolve-Path -Path $candidate -ErrorAction Stop
            if ($resolved) {
                return ($resolved | Select-Object -First 1).Path
            }
        } catch {
            # No match for this pattern; continue scanning.
        }
    }

    return $null
}

# ========================================================
#  CHROME CLEANUP WORKFLOW
#  Targets per-user Chrome under: %LocalAppData%\Google\Chrome\Application
#  Leaves Program Files copies untouched.
# ========================================================
function Uninstall-ChromeFromAllUsers {
    <#
    .SYNOPSIS
        Removes per-user Google Chrome installs and related artifacts from all user profiles.
    .DESCRIPTION
        - Optionally terminates ONLY AppData-based chrome.exe.
        - Locates and runs the per-user setup.exe uninstaller if present.
        - Optionally deletes per-user Chrome data under %LocalAppData%\Google\Chrome.
        - Cleans broken per-user shortcuts (Desktop + Start Menu).
        - Removes per-user uninstall registry key from each user's hive.
        - Writes a detailed log under C:\ProgramData\AppLocker.
    .PARAMETER PurgeData
        When supplied, removes user data/config folders after uninstall (skipped automatically if a machine-wide Chrome install is detected).
    .PARAMETER KillProcesses
        When supplied, stops ONLY chrome.exe instances whose path indicates a per-user installation.
    .NOTES
        Does NOT modify public shortcuts or Program Files installations.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$PurgeData,
        [switch]$KillProcesses
    )

    # ----------------------------
    # Logging setup
    # ----------------------------
    $LogFolder = "C:\ProgramData\AppLocker"
    $LogFile   = Join-Path $LogFolder ("ChromeUninstall_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not (Test-Path $LogFolder)) {
        # Ensure the log directory exists before first write
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    function Write-ChromeLog {
        <#
        .SYNOPSIS
            Write Chrome-specific log entry to file and mirror to console with color.
        .PARAMETER Message
            Message text.
        .PARAMETER Level
            Optional hint for colorization (INFO/SUCCESS/WARN/ERROR).
        #>
        param([string]$Message, [string]$Level = "INFO")
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $entry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $LogFile -Value $entry
        $color = Get-LogForegroundColor -Message $Message -Level $Level
        if ($color) { Write-Host $entry -ForegroundColor $color } else { Write-Host $entry }
    }

    Write-ChromeLog "=== Starting Chrome uninstallation for all users ==="
    Write-ChromeLog ("Log file: {0}" -f $LogFile)

    # ----------------------------
    # Verify admin rights
    #   - Required for enumerating other users’ profiles and loading their hives.
    # ----------------------------
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "This function must be run as Administrator."
    }

    # ----------------------------
    # Helper: remove broken Chrome shortcuts (per-user only)
    #   - Uses WScript.Shell to read .lnk targets and icon hints.
    #   - Deletes ONLY when target does not exist.
    # ----------------------------
    function Remove-BrokenChromeShortcuts {
        param([string[]]$PathsToScan)

        try {
            $wshell = New-Object -ComObject WScript.Shell
        } catch {
            Write-ChromeLog ("Failed to initialize WScript.Shell COM to inspect shortcuts: {0}" -f $_.Exception.Message) "WARN"
            return
        }

        foreach ($scanPath in $PathsToScan) {
            if (-not $scanPath -or -not (Test-Path $scanPath)) { continue }

            Write-ChromeLog ("Scanning for broken Chrome shortcuts in: {0}" -f $scanPath)

            # Recurse for *.lnk; ignore access errors to keep going.
            Get-ChildItem -Path $scanPath -Recurse -Include '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
                $lnk = $_
                $targetPath = $null
                $iconInfo   = $null

                try {
                    $sc         = $wshell.CreateShortcut($lnk.FullName)
                    $targetPath = $sc.TargetPath
                    $iconInfo   = $sc.IconLocation
                } catch {
                    Write-ChromeLog ("Unable to read shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    return
                }

                # Heuristics to decide whether it's a Chrome shortcut.
                $nameLooksChrome   = ($lnk.BaseName -match '(?i)chrome')
                $targetLooksChrome = ($targetPath -and ($targetPath -match '(?i)\\Google\\Chrome\\Application\\chrome\.exe$'))
                $iconLooksChrome   = ($iconInfo -and ($iconInfo -match '(?i)\\Google\\Chrome\\'))

                if (-not ($nameLooksChrome -or $targetLooksChrome -or $iconLooksChrome)) { return }

                # Delete only if the target no longer exists.
                $targetExists = $false
                if ([string]::IsNullOrWhiteSpace($targetPath)) {
                    $targetExists = $false
                } else {
                    try { $targetExists = Test-Path -LiteralPath $targetPath } catch { $targetExists = $false }
                }

                if (-not $targetExists) {
                    try {
                        Write-ChromeLog ("Deleting broken Chrome shortcut: '{0}' (target: '{1}')" -f $lnk.FullName, $targetPath)
                        Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction Stop
                    } catch {
                        Write-ChromeLog ("Failed to delete shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    }
                } else {
                    Write-ChromeLog ("Keeping Chrome shortcut (target exists): '{0}' -> '{1}'" -f $lnk.FullName, $targetPath)
                }
            }
        }
    }

    # ----------------------------
    # Helper: delete per-user uninstall registry key for Chrome
    #   - Works if the hive is already loaded (user logged in) or
    #     loads NTUSER.DAT into a temp HKU\ mount, removes, then unloads.
    # ----------------------------
    function Remove-ChromeUninstallKeyFromUser {
        param(
            [Parameter(Mandatory)][string]$Sid,
            [Parameter(Mandatory)][string]$ProfilePath
        )
        $relKey = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'

        # Branch 1: User hive already loaded => operate directly.
        $loadedHivePath = "Registry::HKEY_USERS\$Sid"
        if (Test-Path $loadedHivePath) {
            $fullKey = Join-Path $loadedHivePath $relKey
            if (Test-Path -LiteralPath $fullKey) {
                try {
                    Write-ChromeLog ("Removing uninstall key for SID {0} (loaded hive): {1}" -f $Sid, $fullKey)
                    Remove-Item -LiteralPath $fullKey -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-ChromeLog ("Failed to remove uninstall key for SID {0} (loaded hive): {1}" -f $Sid, $_.Exception.Message) "WARN"
                }
            } else {
                Write-ChromeLog ("Uninstall key not present for SID {0} (loaded hive)." -f $Sid)
            }
            return
        }

        # Branch 2: User hive NOT loaded => mount NTUSER.DAT temporarily.
        $ntUserDat = Join-Path $ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path $ntUserDat)) {
            Write-ChromeLog ("NTUSER.DAT not found for SID {0} at {1}; skipping registry cleanup." -f $Sid, $ntUserDat) "WARN"
            return
        }

        $tempName = "TempChrome_{0}" -f ($Sid -replace '[^A-Za-z0-9_]', '_')
        $tempHive = "HKU\$tempName"
        try {
            Write-ChromeLog ("Loading hive for SID {0} from {1} to {2}" -f $Sid, $ntUserDat, $tempHive)
            & reg.exe load $tempHive $ntUserDat | Out-Null
            $mountedPath = "Registry::HKEY_USERS\$tempName"
            $fullKey = Join-Path $mountedPath $relKey

            if (Test-Path -LiteralPath $fullKey) {
                try {
                    Write-ChromeLog ("Removing uninstall key for SID {0} (temporary hive): {1}" -f $Sid, $fullKey)
                    Remove-Item -LiteralPath $fullKey -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-ChromeLog ("Failed to remove uninstall key for SID {0} (temporary hive): {1}" -f $Sid, $_.Exception.Message) "WARN"
                }
            } else {
                Write-ChromeLog ("Uninstall key not present for SID {0} (temporary hive)." -f $Sid)
            }
        } catch {
            Write-ChromeLog ("Failed to load user hive for SID {0}: {1}" -f $Sid, $_.Exception.Message) "WARN"
        } finally {
            # Always attempt to unload the mounted hive to avoid handle leaks.
            try {
                Write-ChromeLog ("Unloading hive {0} for SID {1}" -f $tempHive, $Sid)
                & reg.exe unload $tempHive | Out-Null
            } catch {
                Write-ChromeLog ("Failed to unload hive {0} for SID {1}: {2}" -f $tempHive, $Sid, $_.Exception.Message) "WARN"
            }
        }
    }

    # ----------------------------
    # Optional: stop ONLY per-user Chrome processes
    #   - Pattern matches chrome.exe paths under %LocalAppData% to avoid touching machine-wide installs.
    # ----------------------------
    if ($KillProcesses) {
        Write-ChromeLog "Evaluating running chrome.exe processes. Will only close AppData-based Chrome."

        $appDataChromeRegex = '\\Users\\[^\\]+\\AppData\\Local\\Google\\Chrome\\Application\\chrome\.exe$'
        $allChrome = Get-Process chrome -ErrorAction SilentlyContinue
        if (-not $allChrome) {
            Write-ChromeLog "No running chrome.exe processes detected."
        } else {
            $targets = @(); $skipped = @()

            foreach ($p in $allChrome) {
                # Accessing MainModule can throw on protected/system processes; guard with try/catch.
                $exePath = $null
                try {
                    $exePath = $p.Path
                    if (-not $exePath) { $exePath = $p.MainModule.FileName }
                } catch { $exePath = $null }

                if ($exePath -and ($exePath -match $appDataChromeRegex)) {
                    $targets += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
                } else {
                    $skipped += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
                }
            }

            if ($targets.Count -gt 0) {
                $targets | ForEach-Object {
                    Write-ChromeLog ("Stopping AppData Chrome PID {0} at '{1}'..." -f $_.Id, $_.Path)
                    try {
                        Stop-Process -Id $_.Id -Force -ErrorAction Stop
                        Write-ChromeLog ("Stopped PID {0} successfully." -f $_.Id)
                    } catch {
                        Write-ChromeLog ("Failed to stop PID {0}: {1}" -f $_.Id, $_.Exception.Message) "WARN"
                    }
                }
            } else { Write-ChromeLog "No AppData-based Chrome processes found to stop." }

            # Log skipped processes so operators can see why some remained running.
            if ($skipped.Count -gt 0) {
                foreach ($s in $skipped) {
                    if ($s.Path) {
                        Write-ChromeLog ("Skipping chrome.exe PID {0} (not AppData install): '{1}'" -f $s.Id, $s.Path)
                    } else {
                        Write-ChromeLog ("Skipping chrome.exe PID {0} (path unknown / access denied)" -f $s.Id) "WARN"
                    }
                }
            }
        }
    }

    $chromeMachineInstall = $null
    if ($PurgeData) {
        $chromeCandidates      = Get-ProgramFilesCandidates -RelativePaths @('Google\Chrome\Application\chrome.exe')
        $chromeMachineInstall  = Get-FirstExistingPath -CandidatePaths $chromeCandidates
        if ($chromeMachineInstall) {
            Write-ChromeLog ("Detected machine-wide Chrome at '{0}'. PurgeData will be skipped to preserve shared data directories." -f $chromeMachineInstall)
        }
    }

    # ----------------------------
    # Enumerate user profiles (collect SID + Path)
    #   - Filters out .bak hives and non-user SIDs.
    # ----------------------------
    $profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profiles = Get-ChildItem $profileListKey | Where-Object {
        $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '\.bak$'
    } | ForEach-Object {
        $sid  = $_.PSChildName
        $path = (Get-ItemProperty $_.PsPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path -and (Test-Path $path)) { [PSCustomObject]@{ Sid = $sid; Path = $path } }
    }

    foreach ($prof in $profiles) {
        $sid = $prof.Sid
        $profilePath = $prof.Path
        $userName = Split-Path $profilePath -Leaf
        Write-ChromeLog ("Processing user: {0} (SID: {1})" -f $userName, $sid)

        $appDir = Join-Path $profilePath 'AppData\Local\Google\Chrome\Application'
        if (Test-Path $appDir) {
            # Locate Chrome per-user uninstaller: setup.exe under \Application\<ver>\Installer\setup.exe
            $setup = Get-ChildItem -Path (Join-Path $appDir '*\Installer\setup.exe') -File -ErrorAction SilentlyContinue |
                     Sort-Object FullName -Descending | Select-Object -First 1

            if ($setup) {
                Write-ChromeLog ("Running uninstaller for {0}..." -f $userName)
                # --force-uninstall avoids prompts and ensures removal of per-user binaries.
                Start-Process -FilePath $setup.FullName -ArgumentList '--uninstall','--force-uninstall' -Wait -WindowStyle Hidden
            } else {
                Write-ChromeLog ("No setup.exe found for {0}. Performing cleanup." -f $userName)
            }

            if ($PurgeData -and -not $chromeMachineInstall) {
                # Remove residual per-user data/configuration if requested.
                $chromeBase = Join-Path $profilePath 'AppData\Local\Google\Chrome'
                if (Test-Path $chromeBase) {
                    Remove-Item $chromeBase -Recurse -Force -ErrorAction SilentlyContinue
                    Write-ChromeLog ("Removed leftover data for {0}." -f $userName)
                }
            } elseif ($PurgeData -and $chromeMachineInstall) {
                Write-ChromeLog ("Skipping PurgeData for {0}; machine-wide Chrome detected at '{1}'." -f $userName, $chromeMachineInstall)
            }
        } else {
            Write-ChromeLog ("No Chrome installation found for {0}." -f $userName)
        }

        # --- Per-user shortcut cleanup for this profile (ONLY) ---
        $userDesktop = Join-Path $profilePath 'Desktop'
        $userStart   = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
        Remove-BrokenChromeShortcuts -PathsToScan @($userDesktop, $userStart)

        # --- Per-user registry uninstall key cleanup (HKCU for this user) ---
        Remove-ChromeUninstallKeyFromUser -Sid $sid -ProfilePath $profilePath
    }

    # NOTE: Intentionally NOT touching Public Desktop or All Users Start Menu per request.

    Write-ChromeLog "=== Uninstallation, per-user shortcut cleanup, and registry cleanup completed ==="
}

# ========================================================
#  FIREFOX CLEANUP WORKFLOW
#  Targets per-user Firefox under: %LocalAppData%\Mozilla Firefox
# ========================================================
function Uninstall-FirefoxFromAllUsers {
    <#
    .SYNOPSIS
        Removes per-user Firefox installations and artifacts from all user profiles.
    .DESCRIPTION
        - Optionally terminates ONLY AppData-based firefox.exe.
        - Uses helper.exe uninstaller when available.
        - Optionally purges per-user Mozilla\Firefox data (Local and Roaming).
        - Cleans broken per-user shortcuts.
        - Removes per-user uninstall keys named "Mozilla Firefox*" under Uninstall.
        - Logs to C:\ProgramData\AppLocker.
    .PARAMETER PurgeData
        Also remove Local/Roaming Firefox data directories for each user (skipped automatically when a machine-wide Firefox install exists).
    .PARAMETER KillProcesses
        Stop ONLY AppData-based Firefox processes before uninstall.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$PurgeData,
        [switch]$KillProcesses
    )

    # ----------------------------
    # Logging setup
    # ----------------------------
    $LogFolder = "C:\ProgramData\AppLocker"
    $LogFile   = Join-Path $LogFolder ("FirefoxUninstall_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    function Write-FirefoxLog {
        param([string]$Message, [string]$Level = "INFO")
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $entry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $LogFile -Value $entry
        $color = Get-LogForegroundColor -Message $Message -Level $Level
        if ($color) { Write-Host $entry -ForegroundColor $color } else { Write-Host $entry }
    }

    Write-FirefoxLog "=== Starting Firefox uninstallation for all users ==="
    Write-FirefoxLog ("Log file: {0}" -f $LogFile)

    # ----------------------------
    # Verify admin rights
    # ----------------------------
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "This function must be run as Administrator."
    }

    # ----------------------------
    # Helper: remove broken Firefox shortcuts (per-user only)
    # ----------------------------
    function Remove-BrokenFirefoxShortcuts {
        param([string[]]$PathsToScan)

        try {
            $wshell = New-Object -ComObject WScript.Shell
        } catch {
            Write-FirefoxLog ("Failed to initialize WScript.Shell COM to inspect Firefox shortcuts: {0}" -f $_.Exception.Message) "WARN"
            return
        }

        foreach ($scanPath in $PathsToScan) {
            if (-not $scanPath -or -not (Test-Path $scanPath)) { continue }

            Write-FirefoxLog ("Scanning for broken Firefox shortcuts in: {0}" -f $scanPath)
            Get-ChildItem -Path $scanPath -Recurse -Include '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
                $lnk = $_
                $targetPath = $null
                $iconInfo   = $null

                try {
                    $sc         = $wshell.CreateShortcut($lnk.FullName)
                    $targetPath = $sc.TargetPath
                    $iconInfo   = $sc.IconLocation
                } catch {
                    Write-FirefoxLog ("Unable to read shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    return
                }

                # Identify Firefox shortcuts by name/target/icon.
                $nameLooksFirefox   = ($lnk.BaseName -match '(?i)firefox')
                $targetLooksFirefox = ($targetPath -and ($targetPath -match '(?i)\\Mozilla Firefox\\firefox\.exe$'))
                $iconLooksFirefox   = ($iconInfo -and ($iconInfo -match '(?i)\\Mozilla Firefox\\'))

                if (-not ($nameLooksFirefox -or $targetLooksFirefox -or $iconLooksFirefox)) { return }

                $targetExists = $false
                if ([string]::IsNullOrWhiteSpace($targetPath)) {
                    $targetExists = $false
                } else {
                    try { $targetExists = Test-Path -LiteralPath $targetPath } catch { $targetExists = $false }
                }

                if (-not $targetExists) {
                    try {
                        Write-FirefoxLog ("Deleting broken Firefox shortcut: '{0}' (target: '{1}')" -f $lnk.FullName, $targetPath)
                        Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction Stop
                    } catch {
                        Write-FirefoxLog ("Failed to delete Firefox shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    }
                } else {
                    Write-FirefoxLog ("Keeping Firefox shortcut (target exists): '{0}' -> '{1}'" -f $lnk.FullName, $targetPath)
                }
            }
        }
    }

    # ----------------------------
    # Helper: delete per-user uninstall registry key(s) for Firefox
    #   - Removes keys whose name starts with 'Mozilla Firefox'
    # ----------------------------
    function Remove-FirefoxUninstallKeyFromUser {
        param(
            [Parameter(Mandatory)][string]$Sid,
            [Parameter(Mandatory)][string]$ProfilePath
        )
        $relRoot = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'

        $removeFirefoxKeys = {
            param(
                [string]$BasePath,
                [string]$Context,
                [string]$Sid
            )

            if (-not (Test-Path -LiteralPath $BasePath)) {
                Write-FirefoxLog ("Firefox uninstall root not present for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            $targets = Get-ChildItem -LiteralPath $BasePath -ErrorAction SilentlyContinue |
                       Where-Object { $_.PSChildName -like 'Mozilla Firefox*' }

            if (-not $targets) {
                Write-FirefoxLog ("No Firefox uninstall keys starting with 'Mozilla Firefox' found for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            foreach ($key in @($targets)) {
                $targetPath = $key.PSPath
                try {
                    Write-FirefoxLog ("Removing Firefox uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $targetPath)
                    Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-FirefoxLog ("Failed to remove Firefox uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $_.Exception.Message) "WARN"
                }
            }
        }

        $loadedHivePath = "Registry::HKEY_USERS\$Sid"
        if (Test-Path $loadedHivePath) {
            $fullRoot = Join-Path $loadedHivePath $relRoot
            & $removeFirefoxKeys $fullRoot "loaded hive" $Sid
            return
        }

        $ntUserDat = Join-Path $ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path $ntUserDat)) {
            Write-FirefoxLog ("NTUSER.DAT not found for SID {0} at {1}; skipping Firefox registry cleanup." -f $Sid, $ntUserDat) "WARN"
            return
        }

        $tempName = "TempFirefox_{0}" -f ($Sid -replace '[^A-Za-z0-9_]', '_')
        $tempHive = "HKU\$tempName"
        try {
            Write-FirefoxLog ("Loading hive for SID {0} from {1} to {2}" -f $Sid, $ntUserDat, $tempHive)
            & reg.exe load $tempHive $ntUserDat | Out-Null
            $mountedPath = "Registry::HKEY_USERS\$tempName"
            $fullRoot = Join-Path $mountedPath $relRoot

            & $removeFirefoxKeys $fullRoot "temporary hive" $Sid
        } catch {
            Write-FirefoxLog ("Failed to load user hive for SID {0}: {1}" -f $Sid, $_.Exception.Message) "WARN"
        } finally {
            try {
                Write-FirefoxLog ("Unloading hive {0} for SID {1}" -f $tempHive, $Sid)
                & reg.exe unload $tempHive | Out-Null
            } catch {
                Write-FirefoxLog ("Failed to unload hive {0} for SID {1}: {2}" -f $tempHive, $Sid, $_.Exception.Message) "WARN"
            }
        }
    }

    # ----------------------------
    # Optional: stop per-user Firefox processes
    # ----------------------------
    if ($KillProcesses) {
        Write-FirefoxLog "Evaluating running firefox.exe processes. Will only close AppData-based Firefox."

        $appDataFirefoxRegex = '\\Users\\[^\\]+\\AppData\\Local\\Mozilla Firefox\\firefox\.exe$'
        $allFirefox = Get-Process firefox -ErrorAction SilentlyContinue
        if (-not $allFirefox) {
            Write-FirefoxLog "No running firefox.exe processes detected."
        } else {
            $targets = @(); $skipped = @()

            foreach ($p in $allFirefox) {
                $exePath = $null
                try {
                    $exePath = $p.Path
                    if (-not $exePath) { $exePath = $p.MainModule.FileName }
                } catch { $exePath = $null }

                if ($exePath -and ($exePath -match $appDataFirefoxRegex)) {
                    $targets += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
                } else {
                    $skipped += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
                }
            }

            if ($targets.Count -gt 0) {
                $targets | ForEach-Object {
                    Write-FirefoxLog ("Stopping AppData Firefox PID {0} at '{1}'..." -f $_.Id, $_.Path)
                    try {
                        Stop-Process -Id $_.Id -Force -ErrorAction Stop
                        Write-FirefoxLog ("Stopped PID {0} successfully." -f $_.Id)
                    } catch {
                        Write-FirefoxLog ("Failed to stop PID {0}: {1}" -f $_.Id, $_.Exception.Message) "WARN"
                    }
                }
            } else { Write-FirefoxLog "No AppData-based Firefox processes found to stop." }

            if ($skipped.Count -gt 0) {
                foreach ($s in $skipped) {
                    if ($s.Path) {
                        Write-FirefoxLog ("Skipping firefox.exe PID {0} (not AppData install): '{1}'" -f $s.Id, $s.Path)
                    } else {
                        Write-FirefoxLog ("Skipping firefox.exe PID {0} (path unknown / access denied)" -f $s.Id) "WARN"
                    }
                }
            }
        }
    }

    $firefoxMachineInstall = $null
    if ($PurgeData) {
        $firefoxCandidates     = Get-ProgramFilesCandidates -RelativePaths @('Mozilla Firefox\firefox.exe')
        $firefoxMachineInstall = Get-FirstExistingPath -CandidatePaths $firefoxCandidates
        if ($firefoxMachineInstall) {
            Write-FirefoxLog ("Detected machine-wide Firefox at '{0}'. PurgeData will be skipped to preserve shared data directories." -f $firefoxMachineInstall)
        }
    }

    # ----------------------------
    # Enumerate user profiles (SID + Path)
    # ----------------------------
    $profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profiles = Get-ChildItem $profileListKey | Where-Object {
        $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '\.bak$'
    } | ForEach-Object {
        $sid  = $_.PSChildName
        $path = (Get-ItemProperty $_.PsPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path -and (Test-Path $path)) { [PSCustomObject]@{ Sid = $sid; Path = $path } }
    }

    foreach ($prof in $profiles) {
        $sid = $prof.Sid
        $profilePath = $prof.Path
        $userName = Split-Path $profilePath -Leaf
        Write-FirefoxLog ("Processing user: {0} (SID: {1})" -f $userName, $sid)

        $appDir = Join-Path $profilePath 'AppData\Local\Mozilla Firefox'
        if (Test-Path $appDir) {
            # Locate helper.exe (primary uninstaller)
            $helperCandidate = Join-Path $appDir 'uninstall\helper.exe'
            $helperPath = $null
            if (Test-Path $helperCandidate) {
                $helperPath = $helperCandidate
            } else {
                # Fallback: search recursively in case structure differs
                $helperPath = Get-ChildItem -Path $appDir -Filter 'helper.exe' -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
                if ($helperPath) { $helperPath = $helperPath.FullName }
            }

            if ($helperPath) {
                Write-FirefoxLog ("Running Firefox uninstaller for {0} using helper '{1}'..." -f $userName, $helperPath)
                Start-Process -FilePath $helperPath -ArgumentList '/S' -Wait -WindowStyle Hidden
            } else {
                Write-FirefoxLog ("No Firefox helper.exe found for {0}. Performing cleanup." -f $userName)
            }

            if ($PurgeData -and -not $firefoxMachineInstall) {
                # Remove both Local and Roaming data + the application directory if needed.
                $localFirefox    = Join-Path $profilePath 'AppData\Local\Mozilla\Firefox'
                $roamingFirefox  = Join-Path $profilePath 'AppData\Roaming\Mozilla\Firefox'
                $appDirCleanup   = $appDir
                foreach ($pathToRemove in @($localFirefox, $roamingFirefox, $appDirCleanup)) {
                    if (Test-Path $pathToRemove) {
                        try {
                            Remove-Item $pathToRemove -Recurse -Force -ErrorAction Stop
                            Write-FirefoxLog ("Removed leftover Firefox data for {0} at '{1}'." -f $userName, $pathToRemove)
                        } catch {
                            Write-FirefoxLog ("Failed to remove Firefox data for {0} at '{1}': {2}" -f $userName, $pathToRemove, $_.Exception.Message) "WARN"
                        }
                    }
                }
            } elseif ($PurgeData -and $firefoxMachineInstall) {
                Write-FirefoxLog ("Skipping PurgeData for {0}; machine-wide Firefox detected at '{1}'." -f $userName, $firefoxMachineInstall)
            }
        } else {
            Write-FirefoxLog ("No Firefox AppData installation found for {0}." -f $userName)
        }

        # Shortcut cleanup (per-user only)
        $userDesktop = Join-Path $profilePath 'Desktop'
        $userStart   = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
        Remove-BrokenFirefoxShortcuts -PathsToScan @($userDesktop, $userStart)

        # Registry cleanup
        Remove-FirefoxUninstallKeyFromUser -Sid $sid -ProfilePath $profilePath
    }

    Write-FirefoxLog "=== Firefox uninstallation, shortcut cleanup, and registry cleanup completed ==="
}

# ========================================================
#  GIMP CLEANUP WORKFLOW
#  Targets per-user GIMP under: %LocalAppData%\Programs\GIMP*
# ========================================================
function Uninstall-GimpFromAllUsers {
    <#
    .SYNOPSIS
        Removes per-user GIMP installations across all user profiles.
    .DESCRIPTION
        - Optionally stops ONLY per-user GIMP processes.
        - Attempts to run per-user uninstaller (various filenames) if present.
        - Optionally purges Local/Roaming GIMP data and residual program folders.
        - Cleans broken per-user shortcuts.
        - Removes per-user uninstall registry keys starting with 'GIMP'.
        - Logs to C:\ProgramData\AppLocker.
    .PARAMETER PurgeData
        Also delete per-user GIMP data (Local/Roaming) and program remnants (skipped when a machine-wide GIMP install is detected).
    .PARAMETER KillProcesses
        Stop ONLY AppData-based GIMP processes.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$PurgeData,
        [switch]$KillProcesses
    )

    $LogFolder = "C:\ProgramData\AppLocker"
    $LogFile   = Join-Path $LogFolder ("GimpUninstall_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    function Write-GimpLog {
        param([string]$Message, [string]$Level = "INFO")
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $entry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $LogFile -Value $entry
        $color = Get-LogForegroundColor -Message $Message -Level $Level
        if ($color) { Write-Host $entry -ForegroundColor $color } else { Write-Host $entry }
    }

    Write-GimpLog "=== Starting GIMP uninstallation for all users ==="
    Write-GimpLog ("Log file: {0}" -f $LogFile)

    # Admin required for hive loading/profile traversal.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "This function must be run as Administrator."
    }

    function Remove-BrokenGimpShortcuts {
        param([string[]]$PathsToScan)

        try {
            $wshell = New-Object -ComObject WScript.Shell
        } catch {
            Write-GimpLog ("Failed to initialize WScript.Shell COM to inspect GIMP shortcuts: {0}" -f $_.Exception.Message) "WARN"
            return
        }

        foreach ($scanPath in $PathsToScan) {
            if (-not $scanPath -or -not (Test-Path $scanPath)) { continue }

            Write-GimpLog ("Scanning for broken GIMP shortcuts in: {0}" -f $scanPath)
            Get-ChildItem -Path $scanPath -Recurse -Include '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
                $lnk = $_
                $targetPath = $null
                $iconInfo   = $null

                try {
                    $sc         = $wshell.CreateShortcut($lnk.FullName)
                    $targetPath = $sc.TargetPath
                    $iconInfo   = $sc.IconLocation
                } catch {
                    Write-GimpLog ("Unable to read shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    return
                }

                $nameLooksGimp   = ($lnk.BaseName -match '(?i)gimp')
                $targetLooksGimp = ($targetPath -and ($targetPath -match '(?i)\\GIMP[^\\]*\\bin\\gimp-.*\.exe$'))
                $iconLooksGimp   = ($iconInfo -and ($iconInfo -match '(?i)\\GIMP'))

                if (-not ($nameLooksGimp -or $targetLooksGimp -or $iconLooksGimp)) { return }

                $targetExists = $false
                if ([string]::IsNullOrWhiteSpace($targetPath)) {
                    $targetExists = $false
                } else {
                    try { $targetExists = Test-Path -LiteralPath $targetPath } catch { $targetExists = $false }
                }

                if (-not $targetExists) {
                    try {
                        Write-GimpLog ("Deleting broken GIMP shortcut: '{0}' (target: '{1}')" -f $lnk.FullName, $targetPath)
                        Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction Stop
                    } catch {
                        Write-GimpLog ("Failed to delete GIMP shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    }
                } else {
                    Write-GimpLog ("Keeping GIMP shortcut (target exists): '{0}' -> '{1}'" -f $lnk.FullName, $targetPath)
                }
            }
        }
    }

    function Remove-GimpUninstallKeyFromUser {
        param(
            [Parameter(Mandatory)][string]$Sid,
            [Parameter(Mandatory)][string]$ProfilePath
        )
        $relRoot = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'

        $removeKeys = {
            param(
                [string]$BasePath,
                [string]$Context,
                [string]$Sid
            )

            if (-not (Test-Path -LiteralPath $BasePath)) {
                Write-GimpLog ("GIMP uninstall root not present for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            $targets = Get-ChildItem -LiteralPath $BasePath -ErrorAction SilentlyContinue |
                       Where-Object { $_.PSChildName -like 'GIMP*' }

            if (-not $targets) {
                Write-GimpLog ("No GIMP uninstall keys found for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            foreach ($key in @($targets)) {
                $targetPath = $key.PSPath
                try {
                    Write-GimpLog ("Removing GIMP uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $targetPath)
                    Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-GimpLog ("Failed to remove GIMP uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $_.Exception.Message) "WARN"
                }
            }
        }

        $loadedHivePath = "Registry::HKEY_USERS\$Sid"
        if (Test-Path $loadedHivePath) {
            $fullRoot = Join-Path $loadedHivePath $relRoot
            & $removeKeys $fullRoot "loaded hive" $Sid
            return
        }

        $ntUserDat = Join-Path $ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path $ntUserDat)) {
            Write-GimpLog ("NTUSER.DAT not found for SID {0} at {1}; skipping GIMP registry cleanup." -f $Sid, $ntUserDat) "WARN"
            return
        }

        $tempName = "TempGimp_{0}" -f ($Sid -replace '[^A-Za-z0-9_]', '_')
        $tempHive = "HKU\$tempName"
        try {
            Write-GimpLog ("Loading hive for SID {0} from {1} to {2}" -f $Sid, $ntUserDat, $tempHive)
            & reg.exe load $tempHive $ntUserDat | Out-Null
            $mountedPath = "Registry::HKEY_USERS\$tempName"
            $fullRoot = Join-Path $mountedPath $relRoot

            & $removeKeys $fullRoot "temporary hive" $Sid
        } catch {
            Write-GimpLog ("Failed to load user hive for SID {0}: {1}" -f $Sid, $_.Exception.Message) "WARN"
        } finally {
            try {
                Write-GimpLog ("Unloading hive {0} for SID {1}" -f $tempHive, $Sid)
                & reg.exe unload $tempHive | Out-Null
            } catch {
                Write-GimpLog ("Failed to unload hive {0} for SID {1}: {2}" -f $tempHive, $Sid, $_.Exception.Message) "WARN"
            }
        }
    }

    if ($KillProcesses) {
        Write-GimpLog "Evaluating running GIMP processes. Will only close AppData-based GIMP."

        $appDataGimpRegex = '\\Users\\[^\\]+\\AppData\\Local\\Programs\\GIMP[^\\]*\\bin\\gimp-.*\.exe$'
        $allGimp = Get-Process -Name gimp* -ErrorAction SilentlyContinue
        if (-not $allGimp) {
            Write-GimpLog "No running GIMP processes detected."
        } else {
            $targets = @(); $skipped = @()

            foreach ($p in $allGimp) {
                $exePath = $null
                try {
                    $exePath = $p.Path
                    if (-not $exePath) { $exePath = $p.MainModule.FileName }
                } catch { $exePath = $null }

                if ($exePath -and ($exePath -match $appDataGimpRegex)) {
                    $targets += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
                } else {
                    $skipped += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
                }
            }

            if ($targets.Count -gt 0) {
                $targets | ForEach-Object {
                    Write-GimpLog ("Stopping AppData GIMP PID {0} at '{1}'..." -f $_.Id, $_.Path)
                    try {
                        Stop-Process -Id $_.Id -Force -ErrorAction Stop
                        Write-GimpLog ("Stopped PID {0} successfully." -f $_.Id)
                    } catch {
                        Write-GimpLog ("Failed to stop PID {0}: {1}" -f $_.Id, $_.Exception.Message) "WARN"
                    }
                }
            } else { Write-GimpLog "No AppData-based GIMP processes found to stop." }

            if ($skipped.Count -gt 0) {
                foreach ($s in $skipped) {
                    if ($s.Path) {
                        Write-GimpLog ("Skipping GIMP PID {0} (not AppData install): '{1}'" -f $s.Id, $s.Path)
                    } else {
                        Write-GimpLog ("Skipping GIMP PID {0} (path unknown / access denied)" -f $s.Id) "WARN"
                    }
                }
            }
        }
    }

    $gimpMachineInstall = $null
    if ($PurgeData) {
        $gimpCandidates     = Get-ProgramFilesCandidates -RelativePaths @('GIMP*\bin\gimp-*.exe')
        $gimpMachineInstall = Get-FirstExistingPath -CandidatePaths $gimpCandidates
        if ($gimpMachineInstall) {
            Write-GimpLog ("Detected machine-wide GIMP at '{0}'. PurgeData will be skipped to preserve shared data directories." -f $gimpMachineInstall)
        }
    }

    # Enumerate user profiles and perform uninstalls/cleanup
    $profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profiles = Get-ChildItem $profileListKey | Where-Object {
        $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '\.bak$'
    } | ForEach-Object {
        $sid  = $_.PSChildName
        $path = (Get-ItemProperty $_.PsPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path -and (Test-Path $path)) { [PSCustomObject]@{ Sid = $sid; Path = $path } }
    }

    foreach ($prof in $profiles) {
        $sid = $prof.Sid
        $profilePath = $prof.Path
        $userName = Split-Path $profilePath -Leaf
        Write-GimpLog ("Processing user: {0} (SID: {1})" -f $userName, $sid)

        $programsRoot = Join-Path $profilePath 'AppData\Local\Programs'
        $gimpDirs = @()
        if (Test-Path $programsRoot) {
            $gimpDirs = Get-ChildItem -Path $programsRoot -Directory -Filter 'GIMP*' -ErrorAction SilentlyContinue
        }

        if ($gimpDirs -and $gimpDirs.Count -gt 0) {
            foreach ($gimpDir in $gimpDirs) {
                Write-GimpLog ("Inspecting GIMP install for {0}: '{1}'" -f $userName, $gimpDir.FullName)

                # GIMP has historically used InnoSetup uninstallers (unins*.exe) but name can vary.
                $uninstaller = Get-ChildItem -Path $gimpDir.FullName -Include 'uninst.exe','unins*.exe','uninstall.exe' -File -Recurse -ErrorAction SilentlyContinue |
                               Sort-Object FullName -Descending | Select-Object -First 1

                if ($uninstaller) {
                    Write-GimpLog ("Running uninstaller for {0} using '{1}'..." -f $userName, $uninstaller.FullName)
                    try {
                        # InnoSetup switches: /VERYSILENT avoids UI; /SILENT acceptable too.
                        Start-Process -FilePath $uninstaller.FullName -ArgumentList '/VERYSILENT' -Wait -WindowStyle Hidden
                        Write-GimpLog ("Uninstaller completed for {0}." -f $userName)
                    } catch {
                        Write-GimpLog ("Failed to run uninstaller for {0}: {1}" -f $userName, $_.Exception.Message) "WARN"
                    }
                } else {
                    Write-GimpLog ("No GIMP uninstaller found for {0} in '{1}'. Performing cleanup." -f $userName, $gimpDir.FullName) "WARN"
                }
            }
        } else {
            Write-GimpLog ("No GIMP AppData installation found for {0}." -f $userName)
        }

        if ($PurgeData -and -not $gimpMachineInstall) {
            # Remove known data locations plus any discovered program folders.
            $pathsToRemove = @(
                (Join-Path $profilePath 'AppData\Roaming\GIMP'),
                (Join-Path $profilePath 'AppData\Local\GIMP')
            )
            if ($gimpDirs) { $pathsToRemove += ($gimpDirs | ForEach-Object { $_.FullName }) }

            $pathsToRemove | Where-Object { $_ } | Sort-Object -Unique | ForEach-Object {
                $pathToRemove = $_
                if (Test-Path $pathToRemove) {
                    try {
                        Remove-Item $pathToRemove -Recurse -Force -ErrorAction Stop
                        Write-GimpLog ("Removed leftover GIMP data for {0} at '{1}'." -f $userName, $pathToRemove)
                    } catch {
                        Write-GimpLog ("Failed to remove GIMP data for {0} at '{1}': {2}" -f $userName, $pathToRemove, $_.Exception.Message) "WARN"
                    }
                }
            }
        } elseif ($PurgeData -and $gimpMachineInstall) {
            Write-GimpLog ("Skipping PurgeData for {0}; machine-wide GIMP detected at '{1}'." -f $userName, $gimpMachineInstall)
        }

        $userDesktop = Join-Path $profilePath 'Desktop'
        $userStart   = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
        Remove-BrokenGimpShortcuts -PathsToScan @($userDesktop, $userStart)

        Remove-GimpUninstallKeyFromUser -Sid $sid -ProfilePath $profilePath
    }

    Write-GimpLog "=== GIMP uninstallation, shortcut cleanup, and registry cleanup completed ==="
}

# ========================================================
#  GIT CLEANUP WORKFLOW
#  Targets per-user Git for Windows under: %LocalAppData%\Programs\Git
# ========================================================
function Uninstall-GitFromAllUsers {
    <#
    .SYNOPSIS
        Removes per-user Git for Windows installations and artifacts for all users.
    .DESCRIPTION
        - Optionally stops ONLY per-user Git-related processes (by path).
        - Runs the per-user uninstaller when present (InnoSetup variants).
        - Optionally purges per-user Git directories.
        - Cleans broken per-user shortcuts.
        - Removes per-user uninstall entries where DisplayName matches Git patterns.
        - Logs to C:\ProgramData\AppLocker.
    .PARAMETER PurgeData
        Remove residual per-user Git folders (Programs\Git, AppData\Local\Git, AppData\Roaming\Git) unless a machine-wide Git install is detected.
    .PARAMETER KillProcesses
        Stop ONLY AppData-based Git processes (based on executable path).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$PurgeData,
        [switch]$KillProcesses
    )

    $LogFolder = "C:\ProgramData\AppLocker"
    $LogFile   = Join-Path $LogFolder ("GitUninstall_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    function Write-GitLog {
        param([string]$Message, [string]$Level = "INFO")
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $entry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $LogFile -Value $entry
        $color = Get-LogForegroundColor -Message $Message -Level $Level
        if ($color) { Write-Host $entry -ForegroundColor $color } else { Write-Host $entry }
    }

    Write-GitLog "=== Starting Git for Windows uninstallation for all users ==="
    Write-GitLog ("Log file: {0}" -f $LogFile)

    # Admin required to traverse profiles and mount hives.
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "This function must be run as Administrator."
    }

    function Remove-BrokenGitShortcuts {
        param([string[]]$PathsToScan)

        try {
            $wshell = New-Object -ComObject WScript.Shell
        } catch {
            Write-GitLog ("Failed to initialize WScript.Shell COM to inspect Git shortcuts: {0}" -f $_.Exception.Message) "WARN"
            return
        }

        foreach ($scanPath in $PathsToScan) {
            if (-not $scanPath -or -not (Test-Path $scanPath)) { continue }

            Write-GitLog ("Scanning for broken Git shortcuts in: {0}" -f $scanPath)
            Get-ChildItem -Path $scanPath -Recurse -Include '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
                $lnk = $_
                $targetPath = $null
                $iconInfo   = $null

                try {
                    $sc         = $wshell.CreateShortcut($lnk.FullName)
                    $targetPath = $sc.TargetPath
                    $iconInfo   = $sc.IconLocation
                } catch {
                    Write-GitLog ("Unable to read shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    return
                }

                # Identify Git shortcuts by name/target/icon patterns.
                $nameLooksGit   = ($lnk.BaseName -match '(?i)git')
                $targetLooksGit = ($targetPath -and ($targetPath -match '(?i)\\AppData\\Local\\Programs\\Git\\'))
                $iconLooksGit   = ($iconInfo -and ($iconInfo -match '(?i)\\Git'))

                if (-not ($nameLooksGit -or $targetLooksGit -or $iconLooksGit)) { return }

                $targetExists = $false
                if ([string]::IsNullOrWhiteSpace($targetPath)) {
                    $targetExists = $false
                } else {
                    try { $targetExists = Test-Path -LiteralPath $targetPath } catch { $targetExists = $false }
                }

                if (-not $targetExists) {
                    try {
                        Write-GitLog ("Deleting broken Git shortcut: '{0}' (target: '{1}')" -f $lnk.FullName, $targetPath)
                        Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction Stop
                    } catch {
                        Write-GitLog ("Failed to delete Git shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    }
                } else {
                    Write-GitLog ("Keeping Git shortcut (target exists): '{0}' -> '{1}'" -f $lnk.FullName, $targetPath)
                }
            }
        }
    }

    function Remove-GitUninstallKeyFromUser {
        param(
            [Parameter(Mandatory)][string]$Sid,
            [Parameter(Mandatory)][string]$ProfilePath
        )
        $relRoot = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'

        $removeKeys = {
            param(
                [string]$BasePath,
                [string]$Context,
                [string]$Sid
            )

            if (-not (Test-Path -LiteralPath $BasePath)) {
                Write-GitLog ("Git uninstall root not present for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            $targets = Get-ChildItem -LiteralPath $BasePath -ErrorAction SilentlyContinue |
                       Where-Object {
                           try {
                               $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
                               ($props.DisplayName -and (
                                   $props.DisplayName -like 'Git version*' -or
                                   $props.DisplayName -like 'Git for Windows*' -or
                                   $props.DisplayName -eq 'Git'))
                           } catch { $false }
                       }

            if (-not $targets) {
                Write-GitLog ("No Git uninstall keys found for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            foreach ($key in @($targets)) {
                $targetPath = $key.PSPath
                try {
                    Write-GitLog ("Removing Git uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $targetPath)
                    Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-GitLog ("Failed to remove Git uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $_.Exception.Message) "WARN"
                }
            }
        }

        $loadedHivePath = "Registry::HKEY_USERS\$Sid"
        if (Test-Path $loadedHivePath) {
            $fullRoot = Join-Path $loadedHivePath $relRoot
            & $removeKeys $fullRoot "loaded hive" $Sid
            return
        }

        $ntUserDat = Join-Path $ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path $ntUserDat)) {
            Write-GitLog ("NTUSER.DAT not found for SID {0} at {1}; skipping Git registry cleanup." -f $Sid, $ntUserDat) "WARN"
            return
        }

        $tempName = "TempGit_{0}" -f ($Sid -replace '[^A-Za-z0-9_]', '_')
        $tempHive = "HKU\$tempName"
        try {
            Write-GitLog ("Loading hive for SID {0} from {1} to {2}" -f $Sid, $ntUserDat, $tempHive)
            & reg.exe load $tempHive $ntUserDat | Out-Null
            $mountedPath = "Registry::HKEY_USERS\$tempName"
            $fullRoot = Join-Path $mountedPath $relRoot

            & $removeKeys $fullRoot "temporary hive" $Sid
        } catch {
            Write-GitLog ("Failed to load user hive for SID {0}: {1}" -f $Sid, $_.Exception.Message) "WARN"
        } finally {
            try {
                Write-GitLog ("Unloading hive {0} for SID {1}" -f $tempHive, $Sid)
                & reg.exe unload $tempHive | Out-Null
            } catch {
                Write-GitLog ("Failed to unload hive {0} for SID {1}: {2}" -f $tempHive, $Sid, $_.Exception.Message) "WARN"
            }
        }
    }

    if ($KillProcesses) {
        Write-GitLog "Evaluating running Git-related processes. Will only close AppData-based Git."

        $appDataGitRegex = '\\Users\\[^\\]+\\AppData\\Local\\Programs\\Git\\'
        $allProcesses = @()
        try {
            $allProcesses = Get-Process -ErrorAction Stop
        } catch {
            Write-GitLog ("Failed to enumerate processes: {0}" -f $_.Exception.Message) "WARN"
        }

        $targets = @(); $skipped = @()
        foreach ($p in $allProcesses) {
            $exePath = $null
            try {
                $exePath = $p.Path
                if (-not $exePath) { $exePath = $p.MainModule.FileName }
            } catch { $exePath = $null }

            if (-not $exePath) { continue }

            if ($exePath -match $appDataGitRegex) {
                $targets += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
            } elseif ($p.Name -match '^(git|git-bash|git-cmd|git-gui|gitk|bash|sh|mintty)$') {
                $skipped += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
            }
        }

        if ($targets.Count -gt 0) {
            foreach ($proc in $targets) {
                Write-GitLog ("Stopping AppData Git PID {0} at '{1}'..." -f $proc.Id, $proc.Path)
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-GitLog ("Stopped PID {0} successfully." -f $proc.Id)
                } catch {
                    Write-GitLog ("Failed to stop PID {0}: {1}" -f $proc.Id, $_.Exception.Message) "WARN"
                }
            }
        } else {
            Write-GitLog "No AppData-based Git processes found to stop."
        }

        if ($skipped.Count -gt 0) {
            foreach ($s in $skipped) {
                Write-GitLog ("Skipping process PID {0} (path does not match per-user Git): '{1}'" -f $s.Id, $s.Path)
            }
        }
    }

    $gitMachineInstall = $null
    if ($PurgeData) {
        $gitCandidates     = Get-ProgramFilesCandidates -RelativePaths @('Git\cmd\git.exe','Git\bin\git.exe')
        $gitMachineInstall = Get-FirstExistingPath -CandidatePaths $gitCandidates
        if ($gitMachineInstall) {
            Write-GitLog ("Detected machine-wide Git at '{0}'. PurgeData will be skipped to preserve shared data directories." -f $gitMachineInstall)
        }
    }

    $profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profiles = Get-ChildItem $profileListKey | Where-Object {
        $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '\.bak$'
    } | ForEach-Object {
        $sid  = $_.PSChildName
        $path = (Get-ItemProperty $_.PsPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path -and (Test-Path $path)) { [PSCustomObject]@{ Sid = $sid; Path = $path } }
    }

    foreach ($prof in $profiles) {
        $sid = $prof.Sid
        $profilePath = $prof.Path
        $userName = Split-Path $profilePath -Leaf
        Write-GitLog ("Processing user: {0} (SID: {1})" -f $userName, $sid)

        $programsRoot = Join-Path $profilePath 'AppData\Local\Programs'
        $gitDirs = @()
        if (Test-Path $programsRoot) {
            $gitDirs = Get-ChildItem -Path $programsRoot -Directory -Filter 'Git*' -ErrorAction SilentlyContinue
        }

        if ($gitDirs -and $gitDirs.Count -gt 0) {
            foreach ($gitDir in $gitDirs) {
                Write-GitLog ("Inspecting Git install for {0}: '{1}'" -f $userName, $gitDir.FullName)
                $uninstaller = Get-ChildItem -Path $gitDir.FullName -Include 'unins*.exe','uninstall.exe','uninst.exe' -File -Recurse -ErrorAction SilentlyContinue |
                               Sort-Object FullName -Descending | Select-Object -First 1

                if ($uninstaller) {
                    Write-GitLog ("Running uninstaller for {0} using '{1}'..." -f $userName, $uninstaller.FullName)
                    try {
                        Start-Process -FilePath $uninstaller.FullName -ArgumentList '/VERYSILENT','/NORESTART','/SUPPRESSMSGBOXES' -Wait -WindowStyle Hidden
                        Write-GitLog ("Uninstaller completed for {0}." -f $userName)
                    } catch {
                        Write-GitLog ("Failed to run uninstaller for {0}: {1}" -f $userName, $_.Exception.Message) "WARN"
                    }
                } else {
                    Write-GitLog ("No Git uninstaller found for {0} in '{1}'. Performing cleanup." -f $userName, $gitDir.FullName) "WARN"
                }
            }
        } else {
            Write-GitLog ("No Git AppData installation found for {0}." -f $userName)
        }

        if ($PurgeData -and -not $gitMachineInstall) {
            $pathsToRemove = @(
                (Join-Path $profilePath 'AppData\Local\Programs\Git'),
                (Join-Path $profilePath 'AppData\Local\Git'),
                (Join-Path $profilePath 'AppData\Roaming\Git')
            )

            if ($gitDirs) {
                $pathsToRemove += ($gitDirs | ForEach-Object { $_.FullName })
            }

            $pathsToRemove | Where-Object { $_ } | Sort-Object -Unique | ForEach-Object {
                $pathToRemove = $_
                if (Test-Path $pathToRemove) {
                    try {
                        Remove-Item $pathToRemove -Recurse -Force -ErrorAction Stop
                        Write-GitLog ("Removed leftover Git data for {0} at '{1}'." -f $userName, $pathToRemove)
                    } catch {
                        Write-GitLog ("Failed to remove Git data for {0} at '{1}': {2}" -f $userName, $pathToRemove, $_.Exception.Message) "WARN"
                    }
                }
            }
        } elseif ($PurgeData -and $gitMachineInstall) {
            Write-GitLog ("Skipping PurgeData for {0}; machine-wide Git detected at '{1}'." -f $userName, $gitMachineInstall)
        }

        $userDesktop = Join-Path $profilePath 'Desktop'
        $userStart   = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
        Remove-BrokenGitShortcuts -PathsToScan @($userDesktop, $userStart)

        Remove-GitUninstallKeyFromUser -Sid $sid -ProfilePath $profilePath
    }

    Write-GitLog "=== Git for Windows uninstallation, shortcut cleanup, and registry cleanup completed ==="
}

# ========================================================
#  REFINITIV WORKSPACE CLEANUP WORKFLOW
#  Targets per-user Refinitiv Workspace under %AppData% / %LocalAppData%
# ========================================================
function Uninstall-RefinitivWorkspaceFromAllUsers {
    <#
    .SYNOPSIS
        Removes per-user Refinitiv Workspace installations and related artifacts.
    .DESCRIPTION
        - Optionally stops ONLY per-user Refinitiv processes by path pattern.
        - Invokes per-user uninstaller entry point (RefinitivWorkspace.exe --uninstall --silent).
        - Optionally deletes per-user Refinitiv data under AppData/Local/Roaming.
        - Cleans broken per-user shortcuts.
        - Removes per-user uninstall keys with DisplayName like 'Refinitiv Workspace*'.
        - Logs to C:\ProgramData\AppLocker.
    .PARAMETER PurgeData
        Delete per-user Refinitiv data trees after uninstall (skipped automatically when a machine-wide Refinitiv Workspace install exists).
    .PARAMETER KillProcesses
        Stop ONLY AppData-based Refinitiv processes prior to uninstalling.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [switch]$PurgeData,
        [switch]$KillProcesses
    )

    $LogFolder = "C:\ProgramData\AppLocker"
    $LogFile   = Join-Path $LogFolder ("RefinitivUninstall_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

    if (-not (Test-Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force | Out-Null
    }

    function Write-RefinitivLog {
        param([string]$Message, [string]$Level = "INFO")
        $timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $entry = "[$timestamp] [$Level] $Message"
        Add-Content -Path $LogFile -Value $entry
        $color = Get-LogForegroundColor -Message $Message -Level $Level
        if ($color) { Write-Host $entry -ForegroundColor $color } else { Write-Host $entry }
    }

    Write-RefinitivLog "=== Starting Refinitiv Workspace uninstallation for all users ==="
    Write-RefinitivLog ("Log file: {0}" -f $LogFile)

    # Admin check
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "This function must be run as Administrator."
    }

    function Remove-BrokenRefinitivShortcuts {
        param([string[]]$PathsToScan)

        try {
            $wshell = New-Object -ComObject WScript.Shell
        } catch {
            Write-RefinitivLog ("Failed to initialize WScript.Shell COM to inspect Refinitiv shortcuts: {0}" -f $_.Exception.Message) "WARN"
            return
        }

        foreach ($scanPath in $PathsToScan) {
            if (-not $scanPath -or -not (Test-Path $scanPath)) { continue }

            Write-RefinitivLog ("Scanning for broken Refinitiv shortcuts in: {0}" -f $scanPath)
            Get-ChildItem -Path $scanPath -Recurse -Include '*.lnk' -ErrorAction SilentlyContinue | ForEach-Object {
                $lnk = $_
                $targetPath = $null
                $iconInfo   = $null

                try {
                    $sc         = $wshell.CreateShortcut($lnk.FullName)
                    $targetPath = $sc.TargetPath
                    $iconInfo   = $sc.IconLocation
                } catch {
                    Write-RefinitivLog ("Unable to read shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    return
                }

                $nameLooksRefinitiv   = ($lnk.BaseName -match '(?i)refinitiv')
                $targetLooksRefinitiv = ($targetPath -and ($targetPath -match '(?i)\\Refinitiv Workspace\\'))
                $iconLooksRefinitiv   = ($iconInfo -and ($iconInfo -match '(?i)\\Refinitiv'))

                if (-not ($nameLooksRefinitiv -or $targetLooksRefinitiv -or $iconLooksRefinitiv)) { return }

                $targetExists = $false
                if ([string]::IsNullOrWhiteSpace($targetPath)) {
                    $targetExists = $false
                } else {
                    try { $targetExists = Test-Path -LiteralPath $targetPath } catch { $targetExists = $false }
                }

                if (-not $targetExists) {
                    try {
                        Write-RefinitivLog ("Deleting broken Refinitiv shortcut: '{0}' (target: '{1}')" -f $lnk.FullName, $targetPath)
                        Remove-Item -LiteralPath $lnk.FullName -Force -ErrorAction Stop
                    } catch {
                        Write-RefinitivLog ("Failed to delete Refinitiv shortcut '{0}': {1}" -f $lnk.FullName, $_.Exception.Message) "WARN"
                    }
                } else {
                    Write-RefinitivLog ("Keeping Refinitiv shortcut (target exists): '{0}' -> '{1}'" -f $lnk.FullName, $targetPath)
                }
            }
        }
    }

    function Remove-RefinitivUninstallKeyFromUser {
        param(
            [Parameter(Mandatory)][string]$Sid,
            [Parameter(Mandatory)][string]$ProfilePath
        )
        $relRoot = 'Software\Microsoft\Windows\CurrentVersion\Uninstall'

        $removeKeys = {
            param(
                [string]$BasePath,
                [string]$Context,
                [string]$Sid
            )

            if (-not (Test-Path -LiteralPath $BasePath)) {
                Write-RefinitivLog ("Refinitiv uninstall root not present for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            $targets = Get-ChildItem -LiteralPath $BasePath -ErrorAction SilentlyContinue |
                       Where-Object {
                           try {
                               $props = Get-ItemProperty -LiteralPath $_.PSPath -ErrorAction Stop
                               ($props.DisplayName -and ($props.DisplayName -like 'Refinitiv Workspace*'))
                           } catch { $false }
                       }

            if (-not $targets) {
                Write-RefinitivLog ("No Refinitiv uninstall keys found for SID {0} ({1})." -f $Sid, $Context)
                return
            }

            foreach ($key in @($targets)) {
                $targetPath = $key.PSPath
                try {
                    Write-RefinitivLog ("Removing Refinitiv uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $targetPath)
                    Remove-Item -LiteralPath $targetPath -Recurse -Force -ErrorAction Stop
                } catch {
                    Write-RefinitivLog ("Failed to remove Refinitiv uninstall key for SID {0} ({1}): {2}" -f $Sid, $Context, $_.Exception.Message) "WARN"
                }
            }
        }

        $loadedHivePath = "Registry::HKEY_USERS\$Sid"
        if (Test-Path $loadedHivePath) {
            $fullRoot = Join-Path $loadedHivePath $relRoot
            & $removeKeys $fullRoot "loaded hive" $Sid
            return
        }

        $ntUserDat = Join-Path $ProfilePath 'NTUSER.DAT'
        if (-not (Test-Path $ntUserDat)) {
            Write-RefinitivLog ("NTUSER.DAT not found for SID {0} at {1}; skipping Refinitiv registry cleanup." -f $Sid, $ntUserDat) "WARN"
            return
        }

        $tempName = "TempRefinitiv_{0}" -f ($Sid -replace '[^A-Za-z0-9_]', '_')
        $tempHive = "HKU\$tempName"
        try {
            Write-RefinitivLog ("Loading hive for SID {0} from {1} to {2}" -f $Sid, $ntUserDat, $tempHive)
            & reg.exe load $tempHive $ntUserDat | Out-Null
            $mountedPath = "Registry::HKEY_USERS\$tempName"
            $fullRoot = Join-Path $mountedPath $relRoot

            & $removeKeys $fullRoot "temporary hive" $Sid
        } catch {
            Write-RefinitivLog ("Failed to load user hive for SID {0}: {1}" -f $Sid, $_.Exception.Message) "WARN"
        } finally {
            try {
                Write-RefinitivLog ("Unloading hive {0} for SID {1}" -f $tempHive, $Sid)
                & reg.exe unload $tempHive | Out-Null
            } catch {
                Write-RefinitivLog ("Failed to unload hive {0} for SID {1}: {2}" -f $tempHive, $Sid, $_.Exception.Message) "WARN"
            }
        }
    }

    if ($KillProcesses) {
        Write-RefinitivLog "Evaluating running Refinitiv Workspace processes. Will only close AppData-based instances."

        # Path-based allowlist of folders that indicate a per-user install.
        $patternList = @(
            '\\Users\\[^\\]+\\AppData\\Refinitiv\\Refinitiv Workspace\\',
            '\\Users\\[^\\]+\\AppData\\Local\\Refinitiv\\Refinitiv Workspace\\'
        )

        $allProcesses = @()
        try {
            $allProcesses = Get-Process -ErrorAction Stop
        } catch {
            Write-RefinitivLog ("Failed to enumerate processes: {0}" -f $_.Exception.Message) "WARN"
        }

        $targets = @(); $skipped = @()
        foreach ($p in $allProcesses) {
            $exePath = $null
            try {
                $exePath = $p.Path
                if (-not $exePath) { $exePath = $p.MainModule.FileName }
            } catch { $exePath = $null }

            if (-not $exePath) { continue }

            if ($patternList | Where-Object { $exePath -match $_ }) {
                $targets += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
            } elseif ($p.Name -match '(?i)refinitiv') {
                $skipped += [PSCustomObject]@{ Id = $p.Id; Path = $exePath }
            }
        }

        if ($targets.Count -gt 0) {
            foreach ($proc in $targets) {
                Write-RefinitivLog ("Stopping Refinitiv Workspace PID {0} at '{1}'..." -f $proc.Id, $proc.Path)
                try {
                    Stop-Process -Id $proc.Id -Force -ErrorAction Stop
                    Write-RefinitivLog ("Stopped PID {0} successfully." -f $proc.Id)
                } catch {
                    Write-RefinitivLog ("Failed to stop PID {0}: {1}" -f $proc.Id, $_.Exception.Message) "WARN"
                }
            }
        } else {
            Write-RefinitivLog "No AppData-based Refinitiv Workspace processes found to stop."
        }

        if ($skipped.Count -gt 0) {
            foreach ($s in $skipped) {
                Write-RefinitivLog ("Skipping process PID {0} (path does not match per-user Refinitiv): '{1}'" -f $s.Id, $s.Path)
            }
        }
    }

    $refinitivMachineInstall = $null
    if ($PurgeData) {
        $refinitivCandidates     = Get-ProgramFilesCandidates -RelativePaths @(
            'Refinitiv Workspace\RefinitivWorkspace.exe',
            'Refinitiv*\RefinitivWorkspace.exe'
        )
        $refinitivMachineInstall = Get-FirstExistingPath -CandidatePaths $refinitivCandidates
        if ($refinitivMachineInstall) {
            Write-RefinitivLog ("Detected machine-wide Refinitiv Workspace at '{0}'. PurgeData will be skipped to preserve shared data directories." -f $refinitivMachineInstall)
        }
    }

    # Enumerate user profiles and remove per-user Refinitiv.
    $profileListKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profiles = Get-ChildItem $profileListKey | Where-Object {
        $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notmatch '\.bak$'
    } | ForEach-Object {
        $sid  = $_.PSChildName
        $path = (Get-ItemProperty $_.PsPath -Name ProfileImagePath -ErrorAction SilentlyContinue).ProfileImagePath
        if ($path -and (Test-Path $path)) { [PSCustomObject]@{ Sid = $sid; Path = $path } }
    }

    foreach ($prof in $profiles) {
        $sid = $prof.Sid
        $profilePath = $prof.Path
        $userName = Split-Path $profilePath -Leaf
        Write-RefinitivLog ("Processing user: {0} (SID: {1})" -f $userName, $sid)

        # Try fixed known locations first (fast path) then recursive search as fallback.
        $candidatePaths = @(
            (Join-Path $profilePath 'AppData\Refinitiv\Refinitiv Workspace\RefinitivWorkspace.exe'),
            (Join-Path $profilePath 'AppData\Local\Refinitiv\Refinitiv Workspace\RefinitivWorkspace.exe')
        )

        $exeCandidates = @()
        foreach ($candidate in $candidatePaths) { if (Test-Path $candidate) { $exeCandidates += $candidate } }

        if (-not $exeCandidates) {
            $fallbackRoot = Join-Path $profilePath 'AppData'
            if (Test-Path $fallbackRoot) {
                # One recursive pass to catch non-standard layouts.
                $exeCandidates = Get-ChildItem -Path $fallbackRoot -Filter 'RefinitivWorkspace.exe' -File -Recurse -ErrorAction SilentlyContinue |
                                 Sort-Object FullName -Descending | Select-Object -ExpandProperty FullName -ErrorAction SilentlyContinue
            }
        }

        if ($exeCandidates -and $exeCandidates.Count -gt 0) {
            foreach ($exePath in $exeCandidates | Sort-Object -Unique) {
                Write-RefinitivLog ("Running Refinitiv Workspace uninstaller for {0} using '{1}'..." -f $userName, $exePath)
                try {
                    Start-Process -FilePath $exePath -ArgumentList '--uninstall --silent' -Wait -WindowStyle Hidden
                    Write-RefinitivLog ("Uninstaller completed for {0}." -f $userName)
                } catch {
                    Write-RefinitivLog ("Failed to run uninstaller for {0}: {1}" -f $userName, $_.Exception.Message) "WARN"
                }
            }
        } else {
            Write-RefinitivLog ("No Refinitiv Workspace executable found for {0}." -f $userName)
        }

        if ($PurgeData -and -not $refinitivMachineInstall) {
            $pathsToRemove = @(
                (Join-Path $profilePath 'AppData\Refinitiv'),
                (Join-Path $profilePath 'AppData\Local\Refinitiv'),
                (Join-Path $profilePath 'AppData\Roaming\Refinitiv')
            )

            $pathsToRemove | Where-Object { $_ } | Sort-Object -Unique | ForEach-Object {
                $pathToRemove = $_
                if (Test-Path $pathToRemove) {
                    try {
                        Remove-Item $pathToRemove -Recurse -Force -ErrorAction Stop
                        Write-RefinitivLog ("Removed leftover Refinitiv data for {0} at '{1}'." -f $userName, $pathToRemove)
                    } catch {
                        Write-RefinitivLog ("Failed to remove Refinitiv data for {0} at '{1}': {2}" -f $userName, $pathToRemove, $_.Exception.Message) "WARN"
                    }
                }
            }
        } elseif ($PurgeData -and $refinitivMachineInstall) {
            Write-RefinitivLog ("Skipping PurgeData for {0}; machine-wide Refinitiv Workspace detected at '{1}'." -f $userName, $refinitivMachineInstall)
        }

        $userDesktop = Join-Path $profilePath 'Desktop'
        $userStart   = Join-Path $profilePath 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs'
        Remove-BrokenRefinitivShortcuts -PathsToScan @($userDesktop, $userStart)

        Remove-RefinitivUninstallKeyFromUser -Sid $sid -ProfilePath $profilePath
    }

    Write-RefinitivLog "=== Refinitiv Workspace uninstallation, shortcut cleanup, and registry cleanup completed ==="
}

# ========================================================
#  CONDITIONAL EXECUTION (green = running, yellow = skipped)
#  - These blocks merely orchestrate which product functions run.
#  - Each function handles its own logging and options (-KillProcesses, -PurgeData).
# ========================================================
if ($RunChromeCleanup) {
    Write-Host "Variable 'RunChromeCleanup' is TRUE - executing Chrome uninstall function..." -ForegroundColor Green
    Uninstall-ChromeFromAllUsers -KillProcesses -PurgeData
} else {
    Write-Host "Variable 'RunChromeCleanup' is FALSE - skipping Chrome uninstall function." -ForegroundColor Yellow
}

if ($RunFirefoxCleanup) {
    Write-Host "Variable 'RunFirefoxCleanup' is TRUE - executing Firefox uninstall function..." -ForegroundColor Green
    Uninstall-FirefoxFromAllUsers -KillProcesses -PurgeData
} else {
    Write-Host "Variable 'RunFirefoxCleanup' is FALSE - skipping Firefox uninstall function." -ForegroundColor Yellow
}

if ($RunGimpCleanup) {
    Write-Host "Variable 'RunGimpCleanup' is TRUE - executing GIMP uninstall function..." -ForegroundColor Green
    Uninstall-GimpFromAllUsers -KillProcesses -PurgeData
} else {
    Write-Host "Variable 'RunGimpCleanup' is FALSE - skipping GIMP uninstall function." -ForegroundColor Yellow
}

if ($RunGitCleanup) {
    Write-Host "Variable 'RunGitCleanup' is TRUE - executing Git uninstall function..." -ForegroundColor Green
    Uninstall-GitFromAllUsers -KillProcesses -PurgeData
} else {
    Write-Host "Variable 'RunGitCleanup' is FALSE - skipping Git uninstall function." -ForegroundColor Yellow
}

if ($RunRefinitivCleanup) {
    Write-Host "Variable 'RunRefinitivCleanup' is TRUE - executing Refinitiv Workspace uninstall function..." -ForegroundColor Green
    Uninstall-RefinitivWorkspaceFromAllUsers -KillProcesses -PurgeData
} else {
    Write-Host "Variable 'RunRefinitivCleanup' is FALSE - skipping Refinitiv Workspace uninstall function." -ForegroundColor Yellow
}
