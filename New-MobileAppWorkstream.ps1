#Requires -RunAsAdministrator
#Requires -Modules ("Az.Accounts", "Az.Automation", "Az.Storage", "AzureAD", "Microsoft.Graph.Intune")

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)][string]$ApplicationName
)

#region Links
# https://github.com/microsoftgraph/powershell-intune-samples/tree/master/LOB_Application
#endregion Links

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
        Write-Output "Creating application credential object"
        New-AzADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter -Verbose
    }

    # Requires Application administrator or GLOBAL ADMIN
    switch ((Get-AzADServicePrincipal -DisplayNameBeginsWith $aaAccountName -ErrorAction SilentlyContinue).Count) {
        { $PSItem -gt 0 } {
            $existingAzADServicePrincipals = Get-AzADServicePrincipal -DisplayName $aaAccountName -ErrorAction SilentlyContinue
            foreach ($existingAzADServicePrincipal in $existingAzADServicePrincipals) {
                Write-Warning "You are about to delete an service principal which may be associated with one or more Azure resources"
                Remove-AzADServicePrincipal -ObjectId $existingAzADServicePrincipal.ObjectId -Force -Confirm -Verbose
            }
            Write-Output "Creating service principal object"
            New-AzADServicePrincipal -ApplicationId $Application.ApplicationId -OutVariable ServicePrincipal -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter -Verbose
        }
        Default { 
            Write-Output "Creating service principal object"
            New-AzADServicePrincipal -ApplicationId $Application.ApplicationId -OutVariable ServicePrincipal -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter -Verbose 
        }
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
    Write-Output "Pausing to allow the service principal application to become active"
    Start-Sleep -Seconds 15

    # Requires User Access Administrator or Owner.
    $NewRole = New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue -Verbose
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
    Write-Output "Removing default automation certificate"
    Remove-AzAutomationCertificate -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $CertificateAssetName -ErrorAction SilentlyContinue -Verbose
    Write-Output "Creating correct automation certificate"
    New-AzAutomationCertificate -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Path $PfxCertPathForRunAsAccount -Name $CertificateAssetName -Password $certPWGlobal -Exportable -Verbose

    # Populate the ConnectionFieldValues
    $ConnectionFieldValues = @{"ApplicationId" = $ApplicationId.ApplicationId; "TenantId" = $tenantID; "CertificateThumbprint" = $PfxCert.Thumbprint; "SubscriptionId" = $subscriptionID }

    # Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
    Write-Output "Removing default automation connection"
    Remove-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue -Verbose
    Write-Output "Creating correct automation connection using service principal"
    New-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues

    Remove-Item $PfxCertPathForRunAsAccount
    Remove-Item $CerCertPathForRunAsAccount

    return $ApplicationId
}

function CreateUploadScript {
$scriptBody = "
Import-Module @(`"Az.Accounts`", `"Az.Storage`")
if (((Get-AzContext).Subscription.Id -ne `"$subscriptionID`") -or (Get-AzContext).Tenant.Id -ne `"$tenantID`") { 
    Connect-AzAccount -Tenant `"$tenantName`" -SubscriptionId `"$subscriptionID`" -Verbose
}
if (!(Test-Path `"$ApplicationName.ipa`") -or (!(Test-Path `"$ApplicationName.ipa.ps1`"))) { 
    Write-Error `"Path specified not valid`"; exit 
}
`$storageContext = (Get-AzStorageAccount -ResourceGroupName `"$resourceGroupName`" -Name `"$storacctName`").Context
`$storacctContainer = Get-AzStorageContainer -Context `$storageContext -Name `"$storacctBlobName`"
# Upload the .ipa and .ps1 files
Get-ChildItem -Filter `"$ApplicationName.*`" | ForEach-Object { Set-AzStorageBlobContent -File `$PSItem -Container `$(`$storacctContainer.Name) -Context `$storageContext -Force -BlobType Block }
"
return $scriptBody
} 
#endregion Functions

#region Main body

Clear-Host
$Error.Clear()

New-Variable -Name "tenantName" -Value "azinwcb089outlook.onmicrosoft.com" -Force
New-Variable -Name "tenantID" -Value "40116f04-90e9-4f3d-a895-152754654561" -Force
New-Variable -Name "subscriptionName" -Value "ES-CE-CUS-EXT-seharper" -Force
New-Variable -Name "subscriptionID" -Value "709272e4-8b76-40d9-9a8a-00731f51eb83" -Force
New-Variable -Name "location" -Value "eastus" -Force
New-Variable -Name "azureEnvironment" -Value "AzureCloud" -Force

New-Variable -Name "resourceGroupName" -Value $("rg", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "storacctName" -Value $("sa", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "storacctBlobName" -Value $("blob", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "aaAccountName" -Value $("aa", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "eventGridSubscriptionName" -Value $("es", $ApplicationName.ToLower() -join $null) -Force

New-Variable -Name "aaRunbookName" -Value $("Publish", $ApplicationName.ToLower() -join "_") -Force
New-Variable -Name "aaRunbookWebhookName" -Value "ExecutePipeline" -Force
New-Variable -Name "CertificateAssetName" -Value  "AzureRunAsCertificate" -Force
New-Variable -Name "ConnectionAssetName" -Value  "AzureRunAsConnection" -Force
New-Variable -Name "ConnectionTypeName" -Value  "AzureServicePrincipal" -Force
New-Variable -Name "certStore" -Value "cert:\LocalMachine\My" -Force
New-Variable -Name "selfSignedCertNoOfMonthsUntilExpired" -Value 36 -Force
New-Variable -Name "CertificateName" -Value $($aaAccountName, $CertificateAssetName -join $null) -Force
New-Variable -Name "PfxCertPathForRunAsAccount" -Value $(Join-Path $env:TEMP ($CertificateName + ".pfx")) -Force
New-Variable -Name "CerCertPathForRunAsAccount" -Value $(Join-Path $env:TEMP ($CertificateName + ".cer")) -Force

$transcriptPath = ".\NewMobileAppWorkstream.$ApplicationName.log"
if (Test-Path $transcriptPath) {
    Remove-Item $transcriptPath
}
Start-Transcript -Path $transcriptPath -Verbose

[string[]]$AzResourceProviders = @("Microsoft.EventGrid")
[string[]]$ModulesList = @("Az.Accounts", "Az.Automation", "Az.Storage", "AzureAD", "Microsoft.Graph.Intune")
$certPWGlobal = Get-RandomPassword -AsSecureString
$ClientSecret = Get-RandomPassword -AsSecureString

# Prepare the PowerShell runspace
$ModulesList | ForEach-Object { Import-Module $PSItem }

# Authenticate to Azure
if (((Get-AzContext).Subscription.Id -ne $subscriptionID) -or (Get-AzContext).Tenant.Id -ne $tenantID) {
    Connect-AzAccount -Tenant $tenantName -SubscriptionId $subscriptionID -Verbose
}
Connect-AzureAD -AzureEnvironmentName $azureEnvironment -TenantId $tenantID

# Prepare the Azure subscription
foreach ($AzResourceProvider in $AzResourceProviders) {
    if ((Get-AzResourceProvider -ProviderNamespace $AzResourceProvider).RegistrationState -ne "Registered") {
        Register-AzResourceProvider -ProviderNamespace $AzResourceProvider
    }
}

# Build the required resources using JSON template and parameters files
# Uncomment when testing second app
(Get-Content .\parameters.json).Replace("IOSLOBAPPNAME", $ApplicationName.ToLower()) | Set-Content .\parameters.$ApplicationName.json -Force
if ($null -ne $(Get-AzResourceGroup -Name $("rg", $ApplicationName -join $null) -Location $location -ErrorAction SilentlyContinue)) {
    Write-Error "Duplicate Azure Resource Group detected.  Exiting script"; Exit
}
New-AzResourceGroup -Name $("rg", $ApplicationName -join $null) -Location $location
New-AzResourceGroupDeployment -ResourceGroupName $("rg", $ApplicationName -join $null) -Mode Complete -Name "Deployment_$ApplicationName" -TemplateFile .\template.json -TemplateParameterFile .\parameters.$ApplicationName.json
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
$automationVariables = @{
    "StorageAccountKey1" = $storageAccountKeys[0].Value
    "StorageAccountKey2" = $storageAccountKeys[1].Value
    "ApplicationID"      = $ApplicationServicePrincipal.ApplicationId
    "LOBType"            = "microsoft.graph.iosLOBApp"
    "CloudBlobContainer" = $("blob", $ApplicationName.ToLower() -join $null)
    "ApplicationName"    = $ApplicationName
    "ClientSecret"       = $([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret)))
}

$automationVariables.GetEnumerator().ForEach({ New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $PSItem.Key -Value $PSItem.Value -Encrypted $false -Verbose })
#endregion Prepare the automation account

#region Prepare the event grid
$advFilter1 = @{
    operator = "StringEndsWith"
    key = "Subject"
    Values = ".ps1"
}
$advFilters = $advFilter1
New-AzEventGridSubscription -ResourceId $(Get-AzResource -ResourceGroupName $resourceGroupName -Name $storacctName).ResourceId -EventSubscriptionName $eventGridSubscriptionName -Endpoint $aaRunbookWebhook.WebhookURI -EndpointType webhook -IncludedEventType @("Microsoft.Storage.BlobCreated") -AdvancedFilter $advFilters
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

#region Create the Upload script file (Upload-FileToAzBlob.ps1)
Add-Content -Path .\Upload-FileToAzBlob.ps1 -Value $(CreateUploadScript)
#endregion Create the Upload script file (Upload-FileToAzBlob.ps1)

Stop-Transcript -Verbose

# force in RG deployment line, removing application line, webhook line
# No -EndDate for application?
# DisplayName defaulting to azure-powershell-????

# RBAC
# Azure AD role assignments
# ApplicationID to AutomationVariable
# LOBType to AutomationVariable