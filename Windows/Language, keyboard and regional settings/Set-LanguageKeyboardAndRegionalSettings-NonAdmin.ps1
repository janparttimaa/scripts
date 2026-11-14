<#
.SYNOPSIS
    Configures Windows 1x language, keyboard, and regional settings.

.DESCRIPTION
    Configures the current user's Windows language and regional preferences.

    The script sets the following settings:
    - Preferred language: English (United States)
    - Keyboard layout: Finnish
    - Regional format: Finnish (Finland)
    - Country or region: Finland
    - Windows display language override: English (United States)

    Existing preferred languages and keyboard layouts are replaced with
    the configured language and keyboard layout.

    The configured Windows display language pack must already be installed.

    A Windows restart may be required for all settings to take effect.

.VERSION
    20261114

.AUTHOR
    Jan Parttimaa

.COPYRIGHT
    © 2026 Jan Parttimaa. All rights reserved.

.LICENSE
    This script is licensed under the MIT License.
    You may obtain a copy of the License at https://opensource.org/licenses/MIT

.RELEASE NOTES
    20261114 - Initial release.

.EXAMPLE
    Run the following command with your non administrative user rights:

    powershell.exe -ExecutionPolicy Bypass -File .\Set-LanguageKeyboardAndRegionalSettings-NonAdmin.ps1

    The script configures language and regional settings for the current user.

    More information:
    https://learn.microsoft.com/en-us/powershell/module/international/

#>

# Configuration
$Language = "en-US"           # Preferred language: English (United States)
$Keyboard = "0409:0000040B"   # Keyboard layout: Finnish
$Culture  = "fi-FI"           # Regional format: Finnish (Finland)
$GeoID    = 77                # Country or region: Finland

Write-Host "Configuring Windows 1x language settings..." -ForegroundColor Cyan

# 1. Create a new language list containing only the configured preferred language
$LanguageList = New-WinUserLanguageList -Language $Language

# 2. Remove existing keyboard layouts from the new language list and add the configured keyboard
$LanguageList[0].InputMethodTips.Clear()
$LanguageList[0].InputMethodTips.Add($Keyboard)

# 3. Replace the current user's language list with the configured language and keyboard layout
Set-WinUserLanguageList -LanguageList $LanguageList -Force

# 4. Set the configured keyboard layout as the default input method
Set-WinDefaultInputMethodOverride -InputTip $Keyboard

# 5. Set the Windows display language override to the configured language
# The corresponding Windows display language pack must already be installed
Set-WinUILanguageOverride -Language $Language

# 6. Set the current user's regional format to the configured culture
Set-Culture -CultureInfo $Culture

# 7. Set the current user's country or region to the configured geographical location
Set-WinHomeLocation -GeoId $GeoID

# 8. Verify the current user's language and regional configuration
Write-Host "Preferred languages:" -ForegroundColor Cyan
Get-WinUserLanguageList

Write-Host "Default input method:" -ForegroundColor Cyan
Get-WinDefaultInputMethodOverride

Write-Host "Windows UI language override:" -ForegroundColor Cyan
Get-WinUILanguageOverride

Write-Host "Regional format:" -ForegroundColor Cyan
Get-Culture

Write-Host "Country or region:" -ForegroundColor Cyan
Get-WinHomeLocation

# 9. Display configuration completion and restart notification
Write-Host "Configuration completed successfully." -ForegroundColor Green
Write-Host "Restart Windows to apply all settings." -ForegroundColor Yellow