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
    [CmdletBinding()]
    [OutputType([SecureString])]

    $seedLength = Get-Random -Minimum 6 -Maximum 16
    $password = [string]::Empty
    for ($i = 0; $i -lt $seedLength; $i++) {
        $password = $password + [char]$(Get-Random -Minimum 48 -Maximum 57 )
        $password = $password + [char]$(Get-Random -Minimum 97 -Maximum 122 )
    }
    $password = ConvertTo-SecureString -String $password -AsPlainText -Force
    return $password
} # End function Get-RandomPassword

function Import-ModulesFromPSGalleryToModuleShare {
    # CODE COMPLETE
    [CmdletBinding()]
    param ([Parameter(Mandatory = $true)][string]$ModuleName)
    $moduleURI = "https://www.powershellgallery.com/api/v2/package/$ModuleName"
    Write-Verbose "Installing $ModuleName"
    New-AzAutomationModule -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $ModuleName -ContentLinkUri $moduleURI -Verbose
    do {
        Write-Verbose "Installing $ModuleName"; Start-Sleep -Seconds 15
    } while ((Get-AzAutomationModule -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $ModuleName).Status -eq "Importing")
} # End function Import-ModulesFromPSGalleryToModuleShare

function New-LOBAzADApplication {
    [CmdletBinding()]
    param (
        [Parameter()][string]$ApplicationName
    )

    $keyId = (New-Guid).Guid

    # Create the Azure AD application
    switch ((Get-AzADApplication -DisplayName $aaAccountName).Count) {
        { $PSItem -gt 0 } {
            Write-Warning "You are about to delete an application which may be associated with one or more Azure resources"
            $existingAzADApplications = Get-AzADApplication -DisplayName $aaAccountName
            foreach ($existingAzADApplication in $existingAzADApplications) {
                Remove-AzADApplication -ObjectId $existingAzADApplication.ObjectId -Force -Verbose
            }
        }
        Default { Write-Verbose "No existing applications were found matching $aaAccountName" }
    }
    Write-Verbose "Creating application object"
    $LOBAzADApplication = New-AzADApplication -DisplayName $aaAccountName -HomePage ("http://" + $aaAccountName) -IdentifierUris ("http://" + $keyId) -Verbose -Password $ClientSecret -StartDate $resourceBeginDate -EndDate $resourceEndDate

    return $LOBAzADApplication
}

function New-LOBAzADAppCredential {
    [CmdletBinding()]
    param (
        [Parameter()]$Application
    )

    $keyValue = [System.Convert]::ToBase64String($PfxCert.GetRawCertData())

    # Create the AzADAppCredential
    if (Get-AzADAppCredential -DisplayName $ApplicationName -ErrorAction SilentlyContinue -Verbose) {
        Remove-AzADAppCredential -DisplayName $ApplicationName -Force -Verbose
    }
    Write-Verbose "Creating application credential object"
    $LOBAzADAppCredential = New-AzADAppCredential -ApplicationId $Application.ApplicationId -CertValue $keyValue -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter -Verbose

    return $LOBAzADAppCredential
}

function New-LOBAzADServicePrincipal {
    [CmdletBinding()]
    param (
        [Parameter()]$Application
    )

    # Create the AzADServicePrincipal
    $existingAzADServicePrincipals = Get-AzADServicePrincipal -DisplayName $aaAccountName -ErrorAction SilentlyContinue
    if ($existingAzADServicePrincipals.Count -gt 0) {
        foreach ($existingAzADServicePrincipal in $existingAzADServicePrincipals) {
            Write-Warning "You are about to delete an service principal which may be associated with one or more Azure resources"
            Remove-AzADServicePrincipal -ObjectId $existingAzADServicePrincipal.ObjectId -Force -Verbose
        }
    }
    Write-Verbose "Creating service principal object"
    $LOBAzADServicePrincipal = New-AzADServicePrincipal -ApplicationId $Application.ApplicationId -StartDate $PfxCert.NotBefore -EndDate $PfxCert.NotAfter -Verbose 

    return $LOBAzADServicePrincipal
}

function CreateServicePrincipal {
    # Requires Application administrator or GLOBAL ADMIN  
    New-LOBAzADApplication -OutVariable lobApplicationObject
    New-LOBAzADAppCredential -Application $lobApplicationObject -OutVariable lobAppCredentialObject
    New-LOBAzADServicePrincipal -Application $lobApplicationObject -OutVariable lobAppServicePrincipal
    
    # Sleep here for a few seconds to allow the service principal application to become active (ordinarily takes a few seconds)
    Write-Verbose "Pausing to allow the service principal application to become active"
    Start-Sleep -Seconds 15

    # Grant the DeviceManagementApps.ReadWrite.All role to the service principal
    # Requires User Access Administrator or Owner
    $requiredResourceAccess = New-Object "Microsoft.Open.AzureAD.Model.RequiredResourceAccess"
    $requiredResourceAccess.ResourceAppId = $(Get-AzADServicePrincipal -ApplicationId $lobAppServicePrincipal.ApplicationId).ApplicationId
    $requiredResourceAccess.ResourceAccess = $(New-Object "Microsoft.Open.AzureAD.Model.ResourceAccess" -ArgumentList @("78145de6-330d-4800-a6ce-494ff2d33d07", "Role"))
    Set-AzureADApplication -ObjectId $lobApplicationObject.ObjectId -RequiredResourceAccess $requiredResourceAccess

    # Requires User Access Administrator or Owner
    New-AzRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $lobApplicationObject.ApplicationId -ErrorAction SilentlyContinue -Verbose
    do {
        Write-Verbose "Waiting for role assignment to be effective"
        Start-Sleep -Seconds 15
    } until ($(Get-AzRoleAssignment -ServicePrincipalName $lobApplicationObject.ApplicationId).RoleDefinitionName -eq "Contributor")
    
    return $lobApplicationObject
} # End function CreateServicePrincipal

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
    return $scriptBody.Trim()
} # End function CreateUploadScript
#endregion Functions

#region Main body

Clear-Host
$Error.Clear()
$script:ConfirmPreference = [System.Management.Automation.ConfirmImpact]::None

$presetsSpecific = @{
    tenantName           = "azinwcb089outlook.onmicrosoft.com"
    tenantID             = "40116f04-90e9-4f3d-a895-152754654561"
    subscriptionName     = "ES-CE-CUS-EXT-seharper"
    subscriptionID       = "709272e4-8b76-40d9-9a8a-00731f51eb83"
    location             = "eastus"
    azureEnvironment     = "AzureCloud"

    ModulesList          = @("Az.Accounts", "Az.Automation", "Az.Storage", "AzureAD", "Microsoft.Graph.Intune")
    aaModulesList        = @("AzureAD", "Microsoft.Graph.Intune")
    aaRunbookWebhookName = "ExecutePipeline"
    CertificateAssetName = "AzureRunAsCertificate"
    ConnectionAssetName  = "AzureRunAsConnection"
    ConnectionTypeName   = "AzureServicePrincipal"
    certStore            = "cert:\LocalMachine\My"
    applicationLifecycle = 36
    uploadScriptName = "Upload-FileToAzBlob.ps1"
}

$presetsConstructed = @{
    transcriptPath            = ".\NewMobileAppWorkstream.$ApplicationName.$([datetime]::Now.GetDateTimeFormats()[5]).log"
    resourceGroupName         = $("rg", $ApplicationName.ToLower() -join $null)
    storacctName              = $("sa", $ApplicationName.ToLower() -join $null)
    storacctBlobName          = $("blob", $ApplicationName.ToLower() -join $null)
    aaAccountName             = $("aa", $ApplicationName.ToLower() -join $null)
    eventGridSubscriptionName = $("es", $ApplicationName.ToLower() -join $null)
    keyVaultName              = $("kv", $ApplicationName.ToLower() -join $null)
    aaRunbookName             = $("Publish", $ApplicationName.ToLower() -join "_")
}

foreach ($presetSpecific in $presetsSpecific.GetEnumerator()) {
    New-Variable -Name $presetSpecific.Key -Value $presetSpecific.Value -Force -Verbose
}

foreach ($presetConstructed in $presetsConstructed.GetEnumerator()) {
    New-Variable -Name $presetConstructed.Key -Value $presetConstructed.Value -Force -Verbose
}

# Start the session transcript
if (Test-Path $transcriptPath) { 
    Remove-Item $transcriptPath -Force -Verbose 
}
Start-Transcript -Path $transcriptPath -Verbose

# Variables constructed from the constructed presets :)
$certificateName = $($aaAccountName, $CertificateAssetName -join $null)
$PfxCertPathForRunAsAccount = $(Join-Path $env:TEMP ($CertificateName + ".pfx"))
$CerCertPathForRunAsAccount = $(Join-Path $env:TEMP ($CertificateName + ".cer"))

# Generate passwords for certificate and client secret
$certPWGlobal = Get-RandomPassword
$ClientSecret = Get-RandomPassword

# Prepare the PowerShell runspace
$ModulesList | ForEach-Object { Import-Module $PSItem }

# Define the lifecycle boundaries for all time bound resources
$resourceBeginDate = [datetime]::Now
$resourceEndDate = [datetime]::Now.AddMonths($applicationLifecycle)

# Create a self signed certificate
$Cert = New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation $certStore -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -NotAfter (Get-Date).AddMonths($applicationLifecycle) -HashAlgorithm SHA256 -Verbose
Export-PfxCertificate -Cert $(Join-Path $certStore $Cert.Thumbprint) -FilePath $PfxCertPathForRunAsAccount -Password $certPWGlobal -Force -Verbose
Export-Certificate -Cert $(Join-Path $certStore $Cert.Thumbprint) -FilePath $CerCertPathForRunAsAccount -Type CERT -Verbose
Remove-Item -Path $(Join-Path $certStore $Cert.Thumbprint) -Verbose
$PfxCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @($PfxCertPathForRunAsAccount, $certPWGlobal)

#region Create the Upload script file (Upload-FileToAzBlob.ps1)
if (Test-Path .\$uploadScriptName) {
    Remove-Item -Path .\Upload-FileToAzBlob.ps1
}
Add-Content -Path .\$uploadScriptName -Value $(CreateUploadScript) -Force
#endregion Create the Upload script file (Upload-FileToAzBlob.ps1)

# Authenticate to Azure
if (((Get-AzContext).Subscription.Id -ne $subscriptionID) -or (Get-AzContext).Tenant.Id -ne $tenantID) {
    Connect-AzAccount -Tenant $tenantName -SubscriptionId $subscriptionID -Verbose
}
Connect-AzureAD -AzureEnvironmentName $azureEnvironment -TenantId $tenantID -Verbose

# Creating the service principal and all of its moving parts
$ApplicationServicePrincipal = CreateServicePrincipal

# Prepare the Azure subscription
Register-AzResourceProvider -ProviderNamespace "Microsoft.EventGrid" -Verbose

# Build the required resources using JSON template and parameters files
$paramsFile = Get-Content .\parameters.json
$paramsFile = $paramsFile.Replace("IOSLOBAPPNAME", $ApplicationName.ToLower())
$paramsFile = $paramsFile.Replace('APPOBJECTIDREPLACE', $ApplicationServicePrincipal.objectID[0])
$paramsFile = $paramsFile.Replace('APPLICATIONIDREPLACE', $ApplicationServicePrincipal.ApplicationId[0])
$paramsFile = $paramsFile.Replace('ADMINOBJECTIDREPLACE', $((Get-AzContext).Account.ExtendedProperties.HomeAccountId.Split(".")[0])) 
Set-Content .\parameters.$ApplicationName.json -Value $paramsFile -Force -Verbose

# Create the resource group; NOTE: The script will stop if a duplicate resource name is detected
if ($null -ne $(Get-AzResourceGroup -Name $resourceGroupName -Location $location -ErrorAction SilentlyContinue)) {
    Write-Error "Duplicate Azure Resource Group detected.  Exiting script"; Exit
}
New-AzResourceGroup -Name $resourceGroupName -Location $location
New-AzResourceGroupDeployment -ResourceGroupName $resourceGroupName -Mode Complete -Name "Deployment_$ApplicationName" -TemplateFile .\template.json -TemplateParameterFile .\parameters.$ApplicationName.json

# Enter ClientSecret into KeyVault and set policy for service principal to access it
Set-AzKeyVaultSecret -VaultName $keyVaultName -Name "SPClientSecret" -SecretValue $ClientSecret -Expires $resourceEndDate -NotBefore $resourceBeginDate -Verbose
Set-AzKeyVaultAccessPolicy -VaultName $keyVaultName -ResourceGroupName $resourceGroupName -ServicePrincipalName $((Get-AzADServicePrincipal -DisplayName $aaAccountName).ServicePrincipalNames[0]) -PermissionsToSecrets @("Get", "List") -Verbose 

#region Prepare the storage account
$storageContext = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storacctName).Context
New-AzStorageContainerStoredAccessPolicy -Context $storageContext -Container $storacctBlobName -Policy "$aaAccountName Policy" -Permission "rld" -StartTime $resourceBeginDate -ExpiryTime $resourceEndDate -Verbose
#endregion Prepare the storage account

#region Prepare the automation account
Write-Verbose "Removing default automation certificate"
Remove-AzAutomationCertificate -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $CertificateAssetName -ErrorAction SilentlyContinue -Verbose
Write-Verbose "Creating correct automation certificate"
New-AzAutomationCertificate -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Path $PfxCertPathForRunAsAccount -Name $CertificateAssetName -Password $certPWGlobal -Exportable -Verbose

# Populate the ConnectionFieldValues
$ConnectionFieldValues = @{"ApplicationId" = $ApplicationServicePrincipal.ApplicationId[0]; "TenantId" = $tenantID; "CertificateThumbprint" = $PfxCert.Thumbprint; "SubscriptionId" = $subscriptionID }

# Create an Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.
Write-Verbose "Removing default automation connection"
Remove-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $connectionAssetName -Force -ErrorAction SilentlyContinue -Verbose
Write-Verbose "Creating correct automation connection using service principal"
New-AzAutomationConnection -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $connectionAssetName -ConnectionTypeName $connectionTypeName -ConnectionFieldValues $connectionFieldValues -Verbose

# Import the runbook file into the automation account
Import-AzAutomationRunbook -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Path ".\Publish-Lob.Runbook.ps1" -Type PowerShell -Name $aaRunbookName -Description "Publishing pipeline" -Published
$aaRunbookWebhook = New-AzAutomationWebhook -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $aaRunbookWebhookName -RunbookName $aaRunbookName -IsEnabled $true -ExpiryTime $resourceEndDate -Confirm:$false
$automationVariables = @{
    "ApplicationID"      = $ApplicationServicePrincipal.ApplicationId
    #"LOBType"            = "microsoft.graph.iosLOBApp"
    "CloudBlobContainer" = $storacctBlobName
    "ApplicationName"    = $ApplicationName
}

$automationVariables.GetEnumerator().ForEach({ New-AzAutomationVariable -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $PSItem.Key -Value $PSItem.Value -Encrypted $false -Verbose })

Remove-Item $PfxCertPathForRunAsAccount, $CerCertPathForRunAsAccount
#endregion Prepare the automation account

#region Prepare the automation runbook
Write-Verbose "Updating Azure modules on Automation Account"
Write-Warning "Allowing time for module import to process; please be patient"
$aaModulesRemoveList = $(Get-AzAutomationModule -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName) | Where-Object { $PSItem.Name -like "Azure*" } | Select-Object -Property Name
$aaModulesRemoveList | ForEach-Object { Remove-AzAutomationModule -ResourceGroupName $resourceGroupName -AutomationAccountName $aaAccountName -Name $PSItem -Force -ErrorAction SilentlyContinue }
$aaModulesList | ForEach-Object { Import-ModulesFromPSGalleryToModuleShare $PSItem }
#endregion Prepare the automation runbook

#region Prepare the event grid
New-AzEventGridSubscription -ResourceId $(Get-AzResource -ResourceGroupName $resourceGroupName -Name $storacctName).ResourceId -EventSubscriptionName $eventGridSubscriptionName -Endpoint $aaRunbookWebhook.WebhookURI -EndpointType webhook -IncludedEventType @("Microsoft.Storage.BlobCreated") -AdvancedFilter @{operator = "StringEndsWith"; key = "Subject"; Values = @(".ps1") }
#endregion Prepare the event grid

Stop-Transcript -Verbose