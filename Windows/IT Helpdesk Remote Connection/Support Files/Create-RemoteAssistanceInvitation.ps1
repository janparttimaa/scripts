<#
.SYNOPSIS
    IT Helpdesk Remote Assistance Invitation Creator.

.DESCRIPTION
    Creates a Microsoft Remote Assistance invitation (.msrcIncident) file on the current user's Desktop.
    The script:
      - Removes any existing .msrcIncident files from the Desktop
      - Generates a new invitation file named "RemoteConnection-dd-MM-YYYY.msrcIncident"
      - Creates a random alphanumeric password for session security
      - Opens Windows Remote Assistance automatically after 10 seconds
      - Closes itself automatically after 3 minutes
      - Displays clear user instructions in the PowerShell window

    NOTES: You must have Windows Remote Assistance (msra.exe) available on the system (default on Windows).
           Users should share the generated invitation file and password with an authorized IT Helpdesk representative.

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
    Create-RemoteAssistanceInvitation.bat
    Creates a new Remote Assistance invitation file on the Desktop, waits 10 seconds, then launches msra.exe.
#>

param(
    [int]$PasswordLength = 12
)

# Replace "Example" with your company name e.g. "Contoso"
$company = "Example"

# Function to generate a random alphanumeric password
function New-RandomPassword {
    param([int]$Length = 12)
    $chars = ([char[]](48..57 + 65..90 + 97..122))
    $sb = New-Object System.Text.StringBuilder
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        for ($i = 0; $i -lt $Length; $i++) {
            $b = New-Object 'byte[]' 4
            $rng.GetBytes($b)
            $idx = [Math]::Abs([BitConverter]::ToInt32($b,0)) % $chars.Length
            [void]$sb.Append($chars[$idx])
        }
        return $sb.ToString()
    } finally {
        $rng.Dispose()
    }
}

# Paths
$desktop = [Environment]::GetFolderPath('Desktop')
$msraPath = Join-Path $env:windir 'System32\msra.exe'

# Remove existing .msrcIncident files
Write-Host "Cleaning up existing invitation files from Desktop..."
Get-ChildItem -Path $desktop -Filter '*.msrcIncident' -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        Remove-Item $_.FullName -Force -ErrorAction Stop
    } catch {
        # Ignore errors
    }
}

# Build output filename (RemoteConnection-dd-MM-YYYY)
$dateStamp = Get-Date -Format 'dd-MM-yyyy'
$outFile = Join-Path $desktop ("RemoteConnection-{0}.msrcIncident" -f $dateStamp)

# Generate random password
$password = New-RandomPassword -Length $PasswordLength

# Create the invitation file
$argList = @('/saveasfile', $outFile, $password)
$fileName = [System.IO.Path]::GetFileName($outFile)
Write-Host "New invitation file: " -NoNewline
Write-Host $fileName -ForegroundColor Yellow
Write-Host ""
Write-Host "INSTRUCTIONS:" -ForegroundColor Cyan
Write-Host "- Please share new invitation file from your desktop to your $company IT Helpdesk representative." -ForegroundColor Green
Write-Host "- When Windows Remote Assistance opens, share the displayed password with your $company IT Helpdesk representative." -ForegroundColor Green
Write-Host ""
Write-Host "Windows Remote Assistance will open after 10 seconds..."
Start-Sleep -Seconds 10
Start-Process -FilePath $msraPath -ArgumentList $argList
Start-Sleep -Seconds 180
exit 0
