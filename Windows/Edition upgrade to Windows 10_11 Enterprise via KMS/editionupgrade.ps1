# Define Generic Volume License Key for Windows 10/11 Enterprise
# Documentation: https://learn.microsoft.com/en-us/windows-server/get-started/kms-client-activation-keys?tabs=server2025%2Cwindows1110ltsc%2Cversion1803%2Cwindows81
$kmsKey = "NPPR9-FWDCX-D2C8J-H872K-2YT43"

# Function to check Windows edition
function Get-WindowsEdition {
    $osEdition = (Get-WmiObject -Class Win32_OperatingSystem).OperatingSystemSKU
    return $osEdition
}

# Check if the device is on the local network
$localNetwork = Test-Connection -ComputerName "fihelsms02.fi.kworld.kpmg.com" -Count 1 -Quiet

if ($localNetwork) {
    # Get the current Windows edition
    $windowsEdition = Get-WindowsEdition

    # Check if the Windows edition is not Enterprise (4 is the SKU for Enterprise)
    if ($windowsEdition -ne 4) {
        # Install the KMS key silently
        cscript C:\Windows\System32\slmgr.vbs -ipk $kmsKey
        Write-Output "KMS key installed successfully."
        [System.Environment]::Exit(0)
    } else {
       Write-Output "Windows is running Enterprise edition. KMS key installation skipped."
       [System.Environment]::Exit(0)
    }
} else {
    Write-Output "Device is not on the local network. KMS key installation aborted."
}
