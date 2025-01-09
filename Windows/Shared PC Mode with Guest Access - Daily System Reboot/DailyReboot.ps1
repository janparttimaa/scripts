$TaskName = "Shared PC Mode with Guest Access - Daily System Reboot"
$Description = "This task is only for devices running Shared PC Mode with Guest Access. This task reboots the system daily at 03:00 to make sure that no one will be kept as signed in."
$Action = New-ScheduledTaskAction -Execute "shutdown.exe" -Argument "/r /f /t 0"
$Author = "Jan Parttimaa"

# Create a daily trigger at 03:00
$Trigger = New-ScheduledTaskTrigger -Daily -At 03:00

# Define task settings, ensuring it will start on batteries and continue even if not idle
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable:$false -AllowStartIfOnBatteries:$true -DontStopOnIdleEnd:$true -DisallowHardTerminate:$false -DontStopIfGoingOnBatteries:$true -ExecutionTimeLimit (New-TimeSpan -Hours 1)

# Register the task
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "SYSTEM" -Description $Description -Force

$taskObject = Get-ScheduledTask $TaskName
$taskObject.Author = $Author
$taskObject | Set-ScheduledTask
