#region Functions
function GetiOSAppBody {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)][string]$displayName,
        [Parameter(Mandatory = $true)][string]$publisher,
        [Parameter(Mandatory = $true)][string]$description,
        [Parameter(Mandatory = $true)][string]$sourceFile,
        [Parameter(Mandatory = $true)][string]$bundleId,
        [Parameter(Mandatory = $true)][string]$identityVersion,
        [Parameter(Mandatory = $true)][string]$versionNumber,
        [Parameter(Mandatory = $true)][string]$expirationDateTime,
        [Parameter(Mandatory = $false)][string]$minimumSupportedOperatingSystem = @{"12_0" = $true}
    )

    $body = @{ "@odata.type" = "#microsoft.graph.iosLOBApp" }
    $body.applicableDeviceType = @{ "iPad" = $true; "iPhoneAndIPod" = $true }
    $body.categories = @()
    $body.informationUrl = $null
    $body.isFeatured = $false
    $body.privacyInformationUrl = $null
    $body.developer = ""
    $body.notes = ""
    $body.owner = ""

    $body.displayName = $displayName
    $body.publisher = $publisher
    $body.description = $description
    $body.fileName = $sourceFile
    $body.bundleId = $bundleId
    $body.expirationDateTime = $expirationDateTime
    $body.versionNumber = $versionNumber
    $body.identityVersion = $identityVersion
    $body.minimumSupportedOperatingSystem = $minimumSupportedOperatingSystem

    return $body;
}
#endregion Functions

@("Az.Storage", "Az.Accounts", "Microsoft.Graph.Authentication") | ForEach-Object { Import-Module $PSItem }

# Ensure that the runbook does not inherit an AzContext
Disable-AzContextAutosave -Scope Process | Out-Null

# Connect to Azure with Run As account
$ServicePrincipalConnection = Get-AutomationConnection -Name 'AzureRunAsConnection' -ErrorAction Stop
Connect-AzAccount -ServicePrincipal -Tenant $ServicePrincipalConnection.TenantId -ApplicationId $ServicePrincipalConnection.ApplicationId -CertificateThumbprint $ServicePrincipalConnection.CertificateThumbprint | Out-Null
Set-AzContext -SubscriptionId $ServicePrincipalConnection.SubscriptionID -OutVariable AzureContext | Out-Null

# Get the files from the storage account
$storageContext = $(Get-AzStorageAccount -ResourceGroupName $("rg", $(Get-AutomationVariable -Name "ApplicationName") -join $null) -Name $("sa", $(Get-AutomationVariable -Name "ApplicationName").ToLower() -join $null)).Context
Get-AzStorageBlobContent -Context $storageContext -Blob "$(Get-AutomationVariable -Name "ApplicationName").ipa" -Container $(Get-AutomationVariable -Name "CloudBlobContainer") -Destination $pwd\$(Get-AutomationVariable -Name "ApplicationName").ipa | Out-Null
Get-AzStorageBlobContent -Context $storageContext -Blob "$(Get-AutomationVariable -Name "ApplicationName").ipa.ps1" -Container $(Get-AutomationVariable -Name "CloudBlobContainer") -Destination $pwd\$(Get-AutomationVariable -Name "ApplicationName").ipa.ps1 | Out-Null

if ((Get-ChildItem -Path $pwd).Count -eq 2) {
    Write-Output "Files acquired"
}
else {"Unable to get files from Azure storage"; exit}

# Disconnect from Azure
Disconnect-AzAccount

# Get the access token from AzureAD for Graph
$TokenRequestBody = @{
    'Grant_Type' = 'client_credentials'
    'client_Id' = $ServicePrincipalConnection.ApplicationId
    'client_Secret' = $(Get-AutomationVariable -Name "ClientSecret")
    'scope' = "https://graph.microsoft.com/.default"
}

$TokenResponse = Invoke-RestMethod -Uri  "https://login.microsoftonline.com/$($ServicePrincipalConnection.TenantId)/oauth2/v2.0/token" -Method Post -Body $TokenRequestBody
Connect-MgGraph -AccessToken $TokenResponse.access_token


# Prepare the files for upload
. $pwd\"$(Get-AutomationVariable -Name "ApplicationName").ipa.ps1"
$appBody = GetIOSAppBody -displayName $appProperties.displayName -publisher $appProperties.publisher -description $appProperties.description -sourceFile $appProperties.sourceFile -bundleId $appProperties.bundleId -identityVersion $appProperties.identityVersion -versionNumber $appProperties.versionNumber -expirationDateTime $appProperties.expirationDateTime| ConvertTo-Json
$headers = @{
    'Authorization'  = $TokenResponse.access_token
    'Content-Length' = $appBody.Length
}

$mgGraphOutput = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" -Headers $headers -Body $appBody -SkipHeaderValidation -Verbose
Write-output $mgGraphOutput

<#
if (!([datetime]::Now) -gt [datetime]$appProperties.expirationDateTime) {
    Write-Error "$($appProperties.SourceFile) has expired. Resign the package with a valid signing certificate; then try adding the app again"; exit
}
#>

### Validate the variables