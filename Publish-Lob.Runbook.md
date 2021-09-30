# Publish-Lob.Runbook.ps1

The **Publish-Lob.Runbook.ps1** file is imported into the Azure Automation Account as a PowerShell Runbook.  

It has no parameters, and executes just the script, but does utilize several automation variables in the code which are created along with all other resources by **[New-MobileAppWorkstream](./NewMobileApp.md)**.

```powershell
Publish-Lob.Runbook.ps1
```

- The code begins via a webhook to the automation account from the Event Grid, both created by **New-MobileAppWorkstream**.
- Once the webhook is fired, the script grabs the files from the storage account (again created by **New-MobileAppWorkstream**.
- A simple validation occurs on the .IPA file against a pre-determined expiration date (given in a separate .PS1 file uploaded to the same storage account).
- The .ipa file is then encrypted, and the encrypted file and encryption information are submitted to Intune, and an Azure upload location is provided back to the script.
- The script then chunks the encrypted file for upload to the Azure Storage URI and begins the upload.
- Once the file upload is completed, the code is then committed for publishing, and the publish action takes place.
