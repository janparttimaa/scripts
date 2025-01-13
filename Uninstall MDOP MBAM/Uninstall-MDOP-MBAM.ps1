# Uninstall the "MDOP MBAM" MSI package if it's installed
Write-Host "Checking if the MDOP MBAM client is installed."
$msiProduct = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "MDOP MBAM" -and $_.Vendor -like "Microsoft Corporation" }
if ($msiProduct) {
Write-Host "MDOP MBAM client installed. Attempting to remove."
$msiProductIdentifyingNumber = $msiProduct.IdentifyingNumber
Start-Process -FilePath "msiexec.exe" -ArgumentList "/x $msiProductIdentifyingNumber /Q" -Wait
}
else {
Write-Host "MDOP MBAM client not installed."
}