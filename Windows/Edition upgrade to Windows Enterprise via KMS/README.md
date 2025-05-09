# Edition Upgrade to Windows 10/11 Enterprise via KMS
If you came across situation where your KMS-activated Windows 10/11 Enterprise have been somhow downgraded to e.g. Windows 10/11 Pro, this script is for you!
This script upgrade your company-managed device back to KMS-activated Windows 10/11 Enterprise silently without any user interruption.

> [!NOTE]  
> Please note that before deploying the script "remediation.ps1", you need to define the server address (e.g. SCCM-server) that can be pinged only from local network so effected device with wrong OS edition can ping it to make sure that effected device is in local network. This can be found from line 39. Just replace the current placeholder address to appropriate server address.

## Screenshots for Configuration Manager deployments
Here are the screenshots, that are helpful when deploying these to Configuration Manager.

### Configuration Items
![Screenshot](img/screenshot1.png)
![Screenshot](img/screenshot2.png)
![Screenshot](img/screenshot3.png)
![Screenshot](img/screenshot4.png)
![Screenshot](img/screenshot5.png)
![Screenshot](img/screenshot6.png)
![Screenshot](img/screenshot7.png)
![Screenshot](img/screenshot8.png)
![Screenshot](img/screenshot9.png)

## Configuration Baselines
![Screenshot](img/screenshot10.png)
![Screenshot](img/screenshot11.png)
![Screenshot](img/screenshot12.png)
![Screenshot](img/screenshot13.png)
![Screenshot](img/screenshot14.png)
