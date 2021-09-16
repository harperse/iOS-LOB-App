[CmdletBinding()]
param (
    [Parameter()][string]$ApplicationName = "AnthemPulseV30"
)

. .\Globals.ps1
@("Az.Accounts", "Az.Storage") | ForEach-Object { Import-Module $PSItem }
if (((Get-AzContext).Subscription.Id -ne $subscriptionID) -or (Get-AzContext).Tenant.Id -ne $tenantID) { Connect-AzAccount -Tenant $tenantName -SubscriptionId $subscriptionID -Verbose }
if (!(Test-Path "$ApplicationName.ipa") -or (!(Test-Path "$ApplicationName.ipa.ps1"))) { Write-Error "Path specified not valid"; exit }
$storageContext = (Get-AzStorageAccount -ResourceGroupName $resourceGroupName -Name $storacctName).Context
$storacctContainer = Get-AzStorageContainer -Context $storageContext -Name $storacctBlobName
Get-ChildItem -Filter "$ApplicationName.*" | ForEach-Object { Set-AzStorageBlobContent -File $PSItem -Container $storacctContainer.Name -Context $storageContext -Force -BlobType Block }

# Upload the .ipa and .ps1 files
Set-AzStorageBlobContent -File "$ApplicationName.ipa" -Container $storacctContainer.Name -Context $storageContext -Force -BlobType Block
Set-AzStorageBlobContent -File "$ApplicationName.ipa.ps1" -Container $storacctContainer.Name -Context $storageContext -Force -BlobType Block

#under globals . "$pwd\$ApplicationName.ipa.ps1"
#GetiOSAppBody @appProperties | ConvertTo-Json | Set-Content .\$ApplicationName.ipa.json