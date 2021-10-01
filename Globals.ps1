
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)][string]$ApplicationName
)


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
# New-Variable -Name "storacctBlobName" -Value $("blob", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "aaAccountName" -Value $("aa", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "keyVaultName" -Value $("kv", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "eventGridTopicName" -Value $("bm", $ApplicationName.ToLower() -join $null) -Force
New-Variable -Name "eventGridSubscriptionName" -Value $("es", $ApplicationName.ToLower() -join $null) -Force

#region Create-AzAutomationAccount.ps1
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
#endregion Create-AzAutomationAccount.ps1

#region Links
# https://github.com/microsoftgraph/powershell-intune-samples/tree/master/LOB_Application
#endregion Links