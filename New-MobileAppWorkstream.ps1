#Requires -RunAsAdministrator
#Requires -Modules ("Az.Accounts", "Az.Automation", "Az.Storage", "AzureADPreview", "Microsoft.Graph.Intune")

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$ApplicationName
)

#region Functions
function Get-RandomPassword {
    #CODE COMPLETE

    [CmdletBinding()]
    param (
        [Parameter()][switch]$AsSecureString
    )

    $seedLength = Get-Random -Minimum 6 -Maximum 16
    $password = [string]::Empty
    for ($i = 0; $i -lt $seedLength; $i++) {
        $password = $password + [char]$(Get-Random -Minimum 48 -Maximum 57 )
        $password = $password + [char]$(Get-Random -Minimum 97 -Maximum 122)
    }
    if ($AsSecureString) {
        $password = ConvertTo-SecureString -String $password -AsPlainText -Force
    }
    return $password
}

function Import-ModulesFromPSGalleryToModuleShare {
    # CODE COMPLETE
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$ModuleName)
    $moduleURI = "https://www.powershellgallery.com/api/v2/package/$ModuleName"
    Write-Output "Installing $ModuleName"
    New-AzAutomationModule -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $ModuleName -ContentLinkUri $moduleURI -Verbose
    do {
        Write-Output "Installing $ModuleName"; Start-Sleep -Seconds 15
    } while ((Get-AzAutomationModule -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $ModuleName).Status -eq "Importing")
}

function CreateServicePrincipal {
    # CODE COMPLETE
    $keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())
    $keyId = (New-Guid).Guid

    # Create an Azure AD application, AD App Credential, AD ServicePrincipal
    # Requires Application Developer Role, but works with Application administrator or GLOBAL ADMIN
    if (Get-AzADApplication -DisplayName $ApplicationName) {
        Remove-AzADApplication -DisplayName $ApplicationName -Force -Verbose
    }
    else {
        $Application = New-AzADApplication -DisplayName $aaAccountName -HomePage ("http://" + $aaAccountName) -IdentifierUris ("http://" + $keyId) -Verbose -Password $ClientSecret
        
    }
    

    # Requires Application administrator or GLOBAL ADMIN
    if (Get-AzADAppCredential -DisplayName $ApplicationName -ErrorAction SilentlyContinue) {
        Remove-AzADAppCredential -DisplayName $ApplicationName -Force -Verbose
    }
    else {
        New-AzADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter -Verbose

    }

    # Requires Application administrator or GLOBAL ADMIN
    switch ((Get-AzADServicePrincipal -DisplayNameBeginsWith $aaAccountName -ErrorAction SilentlyContinue).Count) {
        { $PSItem -gt 0 } {
            $existingAzADServicePrincipals = Get-AzADServicePrincipal -DisplayNameBeginsWith $aaAccountName
            foreach ($existingAzADServicePrincipal in $existingAzADServicePrincipals) {
                Write-Warning "You are about to delete an service principal which may be associated with one or more Azure resources"
                Remove-AzADServicePrincipal -ObjectId $existingAzADServicePrincipal.ObjectId -Force -Confirm -Verbose
            }
            New-AzADServicePrincipal -ApplicationId $Application.ApplicationId -OutVariable ServicePrincipal -Verbose
        }
        Default { New-AzADServicePrincipal -ApplicationId $Application.ApplicationId -OutVariable ServicePrincipal -Verbose }
    }

    # Grant the DeviceManagementApps.ReadWrite.All role to the service principal
    #*#*#* WIP #*#*#*
    #$deviceManagementAppsRole = New-Object "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList @("78145de6-330d-4800-a6ce-494ff2d33d07", "Role")
    $requiredResourceAccess = New-Object "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $requiredResourceAccess.ResourceAppId = $(Get-AzADServicePrincipal -ApplicationId $Application.ApplicationId).ApplicationId
    $requiredResourceAccess.ResourceAccess = $(New-Object "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList @("78145de6-330d-4800-a6ce-494ff2d33d07", "Role"))
    Set-AzureADApplication -ObjectId $Application.ObjectId -RequiredResourceAccess $requiredResourceAccess
    #Invoke-RestMethod -Uri "https://login.microsoftonline.com/$tenantID/adminconsent?client_id=$($Application.ObjectId)" -Method Get

    # Sleep here for a few seconds to allow the service principal application to become active (ordinarily takes a few seconds)
    Start-Sleep -Seconds 15

    # Requires User Access Administrator or Owner.
    #$NewRole = New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue -Verbose
    $Retries = 0
    while ($null -eq $NewRole -and $Retries -le 6) {
        Start-Sleep -Seconds 15
        New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -Verbose -ErrorAction SilentlyContinue
        $NewRole = Get-AzRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue -Verbose
        $Retries++
    }
    return $Application.ApplicationId.ToString()
}

function New-AzAutomationRunAsAccount {
    # Create a self signed certificate
    $Cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation $certStore -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter (Get-Date).AddMonths($selfSignedCertNoOfMonthsUntilExpired) -HashAlgorithm SHA256 -Verbose
    Export-PfxCertificate -Cert $(Join-Path $certStore $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $certPWGlobal -Force -Verbose
    Export-Certificate -Cert $(Join-Path $certStore $Cert.Thumbprint) -FilePath $CerCertPathForRunAsAccount -Type CERT -Verbose
    Remove-Item -Path $(Join-Path $certStore $Cert.Thumbprint) -Verbose
    $PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $certPWGlobal)

    # Create a service principal
    switch ((Get-AzADApplication -DisplayName $aaAccountName).Count) {
        { $PSItem -gt 0 } {
            Write-Warning "You are about to delete an application which may be associated with one or more Azure resources"
            $existingAzADApplications = Get-AzADApplication -DisplayName $aaAccountName
            foreach ($existingAzADApplication in $existingAzADApplications) {
                Remove-AzADApplication -ObjectId $existingAzADApplication.ObjectId -Force -Confirm -Verbose
            }
            $ApplicationId = CreateServicePrincipal
        }
        Default { $ApplicationId = CreateServicePrincipal }
    }   

    # Create the Automation certificate asset
    Remove-AzAutomationCertificate -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $CertificateAssetName -ErrorAction SilentlyContinue -Verbose
    New-AzAutomationCertificate -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Path $PfxCertPathForRunAsAccount -Name $CertificateAssetName -Password $certPWGlobal -Exportable -Verbose

    # Populate the ConnectionFieldValues
    $ConnectionFieldValues = @{"ApplicationId" = $ApplicationId.ApplicationId; "TenantId" = $tenantID; "CertificateThumbprint" = $PfxCert.Thumbprint; "SubscriptionId" = $subscriptionID }

    # Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
    Remove-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue -Verbose
    New-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues

    #Remove-Item $PfxCertPathForRunAsAccount
    #Remove-Item $CerCertPathForRunAsAccount

    return $ApplicationId
}
#endregion Functions

#region Main body
. .\Globals.ps1 -ApplicationName $ApplicationName

[string[]]$AzResourceProviders = @("Microsoft.EventGrid")
[string[]]$ModulesList = @("Az.Accounts", "Az.Automation", "Az.Storage", "AzureADPreview", "Microsoft.Graph.Intune")
$certPWGlobal = Get-RandomPassword -AsSecureString
$ClientSecret = Get-RandomPassword -AsSecureString

# Prepare the PowerShell runspace
$ModulesList | ForEach-Object { Import-Module $PSItem }

# Authenticate to Azure
if (((Get-AzContext).Subscription.Id -ne $subscriptionID) -or (Get-AzContext).Tenant.Id -ne $tenantID) {
    Connect-AzAccount -Tenant $tenantName -SubscriptionId $subscriptionID -Verbose
}

# Prepare the Azure subscription
foreach ($AzResourceProvider in $AzResourceProviders) {
    if ((Get-AzResourceProvider -ProviderNamespace $AzResourceProvider).RegistrationState -ne "Registered") {
        Register-AzResourceProvider -ProviderNamespace $AzResourceProvider
    }
}

# Build the required resources using JSON template and parameters files 
# Uncomment when testing second app
(Get-Content .\parameters.json).Replace("IOSLOBAPPNAME", $ApplicationName.ToLower()) | Set-Content .\parameters.$ApplicationName.json -Force
New-AzResourceGroup -Name $("rg", $ApplicationName -join $null) -Location $location
New-AzResourceGroupDeployment -ResourceGroupName $("rg", $ApplicationName -join $null) -Mode Complete -Name "Deployment_$ApplicationName" -DeploymentDebugLogLevel All -TemplateFile .\template.json -TemplateParameterFile .\parameters.$ApplicationName.json
#

$ApplicationServicePrincipal = New-AzAutomationRunAsAccount
#endregion Main body

#region Prepare the storage account
### Rights for application/service principal to storage account, or use storageaccount keys?
$storageContext = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storacctName).Context
if (!$(Get-AzStorageContainer -Context $storageContext -Name $storacctBlobName -ErrorAction SilentlyContinue).Name -contains $storacctBlobName) {
    New-AzStorageContainer -Name $storacctBlobName -Context $storageContext -OutVariable storacctContainer -Verbose
}
$storageAccountKeys = Get-AzStorageAccountKey -ResourceGroupName $resourceGroupName -Name $storacctName -ListKerbKey
#endregion Prepare the storage account

#region Prepare the automation account
Import-AzAutomationRunbook -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Path ".\Publish-Lob.Runbook.ps1" -Type PowerShell -Name $aaRunbookName -Description "Publishing pipeline" -Published
$aaRunbookWebhook = New-AzAutomationWebhook -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $aaRunbookWebhookName -RunbookName $aaRunbookName -IsEnabled $true -ExpiryTime ([datetime]::Now).AddYears(3)
<#$automationVariables = @{
    "StorageAccountKey1" = $storageAccountKeys[0].Value
    "StorageAccountKey2" = $storageAccountKeys[1].Value
    "ApplicationID"      = $ApplicationServicePrincipal
    "LOBType"            = "microsoft.graph.iosLOBApp"
    "CloudBlobContainer" = $storacctContainer.Name
    "ApplicationName"    = $ApplicationName
    "ClientSecret"       = $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)))
}
#>

New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name "StorageAccountKey1" -Value $storageAccountKeys[0].Value -Encrypted $false -Verbose
New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name "StorageAccountKey2" -Value $storageAccountKeys[1].Value -Encrypted $false -Verbose
New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name "ApplicationID" -Value $ApplicationServicePrincipal -Encrypted $false -Verbose
New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name "LOBType" -Value "microsoft.graph.iosLOBApp" -Encrypted $false -Verbose
New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name "CloudBlobContainer" -Value $storacctContainer.Name -Encrypted $false -Verbose
New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name "ApplicationName" -Value $ApplicationName -Encrypted $false -Verbose
New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name "ClientSecret" -Value $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))) -Encrypted $false -Verbose
#endregion Prepare the automation account

#region Prepare the event grid
New-AzEventGridSubscription -ResourceId $(Get-AzResource -ResourceGroupName $resourceGroupName -Name $storacctName).ResourceId -EventSubscriptionName $eventGridSubscriptionName -Endpoint $aaRunbookWebhook.WebhookURI -EndpointType webhook -IncludedEventType @("Microsoft.Storage.BlobCreated")
#endregion Prepare the event grid


#region Prepare the automation runbook
# Uncomment when testing second app
$aaModulesList = @("Az.Accounts", "AzureAD", "Microsoft.Graph.Intune", "Az.Automation", "Az.Storage")
$aaModulesRemoveList = @("Azure", "Azure.Storage", "AzureRM.Automation", "AzureRM.Compute", "AzureRM.Profile", "AzureRM.Resources", "AzureRM.SQL", "AzureRM.Storage")
Write-Output "Updating Azure modules on Automation Account"
Write-Warning "Allowing time for module import to process; please be patient"
$aaModulesList | ForEach-Object { Import-ModulesFromPSGalleryToModuleShare $PSItem }
$aaModulesRemoveList | ForEach-Object { Remove-AzAutomationModule -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $PSItem -Force -ErrorAction SilentlyContinue }
#endregion Prepare the automation runbook


# force in RG deployment line, removing application line, webhook line
# No -EndDate for application?
# DisplayName defaulting to azure-powershell-????

# RBAC
# Azure AD role assignments
# ApplicationID to AutomationVariable
# LOBType to AutomationVariable