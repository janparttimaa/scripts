```powershell
# Setting variables and values
$Language = 'en-US'           # Preferred language: English (United States)
$Keyboard = '0409:0000040B'   # Keyboard layout: Finnish
$Culture = 'fi-FI'            # Regional format: Finnish (Finland)
$GeoID = 77                   # Country or region: Finland

Write-ADTLogEntry -Message "Starting Windows 1x language configuration..." -Source "Info"

# 1. Set English (US) as the only preferred language
$LanguageList = New-WinUserLanguageList -Language $Language

# 2. Remove other keyboard layouts and add Finnish only
$LanguageList[0].InputMethodTips.Clear()
$LanguageList[0].InputMethodTips.Add($Keyboard)

# 3. Apply preferred language list
Set-WinUserLanguageList -LanguageList $LanguageList -Force

# 4. Set Finnish keyboard as default input method
Set-WinDefaultInputMethodOverride -InputTip $Keyboard

# 5. Set Windows display language to English (US)
# English (US) language pack must already be installed
Set-WinUILanguageOverride -Language $Language

# 6. Set regional format to Finnish (Finland)
Set-Culture -CultureInfo $Culture

# 7. Set country or region to Finland
Set-WinHomeLocation -GeoId $GeoID

# 8. Apply settings to system and new user accounts
Write-ADTLogEntry -Message "Copying international settings to system and new users..." -Source "Info"
Copy-UserInternationalSettingsToSystem -WelcomeScreen $true -NewUser $true

# 9. Apply settings to the current user
Write-ADTLogEntry -Message "Applying international settings to the current user..." -Source "Info"
Start-ADTProcessAsUser -FilePath "$envSystemRoot\system32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -File $($adtSession.DirSupportFiles)\Set-LanguageKeyboardAndRegionalSettings-NonAdmin.ps1" -WindowStyle Hidden -CreateNoWindow

# 10. Mark the configuration as completed
Write-ADTLogEntry -Message "Creating registry key for Intune or Configuration Manager detection rule purposes..." -Source "Info"
Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\Fix-LangKbdRegion" -Name "Version" -Type "String" -Value $($adtSession.AppVersion)
```