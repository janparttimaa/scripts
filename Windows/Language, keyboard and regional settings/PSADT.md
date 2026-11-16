## 1. Admin (Welcome screen and New User)
```powershell

# Setting variables and values
$Language = 'en-US'                                                                 # Preferred language: English (United States)
$Keyboard = '0409:0000040B'                                                         # Keyboard layout: Finnish
$Culture = 'fi-FI'                                                                  # Regional format: Finnish (Finland)
$GeoID = 77                                                                         # Country or region: Finland
$SafetyCheckFile = "$envProgramData\Contoso\Fix-LangKbdRegion\SafetyCheck.flag"     # Safety check file to check if we have configured these values during Autopilot enrollment

# Check if safety check file existed. If yes, we don't need to proceed.
Write-ADTLogEntry -Message "Checking if safety check file existed..." -Source "Info"

if (Test-Path -Path $SafetyCheckFile -PathType Leaf) {
    Write-ADTLogEntry -Message "Safety check file identified. We don't need to proceed further for configuration." -Source "Info"
    Write-ADTLogEntry -Message "Creating registry key for Intune or Configuration Manager detection rule purposes..." -Source "Info"
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\Fix-LangKbdRegion" -Name "Version" -Type "String" -Value $($adtSession.AppVersion)
    Close-ADTSession -ExitCode 0
}
else {
    Write-ADTLogEntry -Message "Safety check file not existed. We can proceed forward..." -Source "Info"
}

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

# 11. Completion
Write-ADTLogEntry -Message "The changes have been made and will take effect after a reboot." -Source "Info"
```

## 2. Non-Admin (Current User)
```powershell

# Setting variables and values
$Language = 'en-US'                                                                 # Preferred language: English (United States)
$Keyboard = '0409:0000040B'                                                         # Keyboard layout: Finnish
$Culture = 'fi-FI'                                                                  # Regional format: Finnish (Finland)
$GeoID = 77                                                                         # Country or region: Finland
$SafetyCheckFile = "$envProgramData\Contoso\Fix-LangKbdRegion\SafetyCheck.flag"     # Safety check file to check if we have configured these values during Autopilot enrollment

# Check if safety check file existed. If yes, we don't need to proceed.
Write-ADTLogEntry -Message "Checking if safety check file existed..." -Source "Info"

if (Test-Path -Path $SafetyCheckFile -PathType Leaf) {
    Write-ADTLogEntry -Message "Safety check file identified. We don't need to proceed further for configuration." -Source "Info"
    Write-ADTLogEntry -Message "Creating registry key for Intune or Configuration Manager detection rule purposes..." -Source "Info"
    Set-ADTRegistryKey -LiteralPath "HKEY_LOCAL_MACHINE\SOFTWARE\Contoso\Fix-LangKbdRegion" -Name "Version" -Type "String" -Value $($adtSession.AppVersion)
    Close-ADTSession -ExitCode 0
}
else {
    Write-ADTLogEntry -Message "Safety check file not existed. We can proceed forward..." -Source "Info"
}

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

# 8. Mark the configuration as completed
Write-ADTLogEntry -Message "Creating registry key for Intune or Configuration Manager detection rule purposes..." -Source "Info"
Set-ADTRegistryKey -LiteralPath "HKEY_CURRENT_USER\SOFTWARE\Contoso\Fix-LangKbdRegion" -Name "Version" -Type "String" -Value $($adtSession.AppVersion)
```