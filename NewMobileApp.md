# New-MobileAppWorkstream

To create a new mobile application, execute the **New-MobileAppWorkstream** script, providing an application name as parameter

```powershell
New-MobileAppWorkstream -ApplicationName "AnthemPulseV30"
```

The New-MobileAppWorkstream script will perform the following actions in Azure:

- Authenticate the user using Connect-AzAccount
- Register the Microsoft.EventGrid provider using Register-AzResourceProvider
- Create a Resource Group using the Application Name as base using New-AzResourceGroup
- Deploy the JSON templates, template.json and parameters.`<ApplicationName`>.json using New.AzResourceGroupDeployment
- *Note: The JSON template deploys the Automation Account, Storage Account, and Event Grid resources*
- Create the Service Principal for the Automation Account
- Import the Automation Runbook from the accompanying file Publish-LOB.Runbook.ps1
- Create the necessary variables for the Automation Account
- Create the Event Grid subscription for the storage account
- Add required modules to the Automation Account from the PowerShell Gallery
- Remove outdated modules from the Automation Account

At this point, the required Azure resources have been created and configured and are available for use
