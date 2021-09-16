#region Functions
function EncryptFileWithIV($sourceFile, $targetFile, $encryptionKey, $hmacKey, $initializationVector) {
    
    $bufferBlockSize = 1024 * 4;
    $computedMac = $null;
    
    $aes = [System.Security.Cryptography.Aes]::Create();
    $hmacSha256 = New-Object System.Security.Cryptography.HMACSHA256;
    $hmacSha256.Key = $hmacKey;
    $hmacLength = $hmacSha256.HashSize / 8;
    
    $buffer = New-Object byte[] $bufferBlockSize;
    $bytesRead = 0;
    
    $targetStream = [System.IO.File]::Open($targetFile, [System.IO.FileMode]::Create)#, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read);
    $targetStream.Write($buffer, 0, $hmacLength + $initializationVector.Length);
    
    $encryptor = $aes.CreateEncryptor($encryptionKey, $initializationVector);
    $sourceStream = [System.IO.File]::Open($sourceFile, [System.IO.FileMode]::Open)#, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read);
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream -ArgumentList @($targetStream, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write);
    
    $targetStream = $null;
    while (($bytesRead = $sourceStream.Read($buffer, 0, $bufferBlockSize)) -gt 0) {
        $cryptoStream.Write($buffer, 0, $bytesRead);
        $cryptoStream.Flush();
    }
    $cryptoStream.FlushFinalBlock();
    $cryptoStream.Close()
    $sourceStream.Close()
    
    $finalStream = [System.IO.File]::Open($targetFile, [System.IO.FileMode]::Open) #, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::Read)
        
    $finalStream.Seek($hmacLength, [System.IO.SeekOrigin]::Begin) | Out-Null;
    $finalStream.Write($initializationVector, 0, $initializationVector.Length);
    $finalStream.Seek($hmacLength, [System.IO.SeekOrigin]::Begin) | Out-Null;
    

    $hmac = $hmacSha256.ComputeHash([System.IO.Stream]$finalStream);
    $computedMac = $hmac;
    
    $finalStream.Seek(0, [System.IO.SeekOrigin]::Begin) > $null;
    $finalStream.Write($hmac, 0, $hmac.Length);
    $finalStream.Close()
    
    return $computedMac;
}

function EncryptFile($sourceFile, $targetFile) {
    
    $encryptionKey = [System.Security.Cryptography.AesCryptoServiceProvider]::New().Key
    $hmacKey = [System.Security.Cryptography.HMACSHA256]::New().Key
    $initializationVector = [System.Security.Cryptography.AesCryptoServiceProvider]::New().IV
    
    # Create the encrypted target file and compute the HMAC value.
    $mac = EncryptFileWithIV $sourceFile $targetFile $encryptionKey $hmacKey $initializationVector;
    
    # Compute the SHA256 hash of the source file and convert the result to bytes.
    $fileDigest = (Get-FileHash $sourceFile -Algorithm SHA256).Hash;
    $fileDigestBytes = New-Object byte[] ($fileDigest.Length / 2);
    for ($i = 0; $i -lt $fileDigest.Length; $i += 2) {
        $fileDigestBytes[$i / 2] = [System.Convert]::ToByte($fileDigest.Substring($i, 2), 16);
    }
        
    # Return an object that will serialize correctly to the file commit Graph API.
    $encryptionInfo = @{};
    $encryptionInfo.encryptionKey = [System.Convert]::ToBase64String($encryptionKey);
    $encryptionInfo.macKey = [System.Convert]::ToBase64String($hmacKey);
    $encryptionInfo.initializationVector = [System.Convert]::ToBase64String($initializationVector);
    $encryptionInfo.mac = [System.Convert]::ToBase64String($mac);
    $encryptionInfo.profileIdentifier = "ProfileVersion1";
    $encryptionInfo.fileDigest = [System.Convert]::ToBase64String($fileDigestBytes);
    $encryptionInfo.fileDigestAlgorithm = "SHA256";
    
    $fileEncryptionInfo = @{};
    $fileEncryptionInfo.fileEncryptionInfo = $encryptionInfo;
    
    return $fileEncryptionInfo;
    
}

function ConvertTo-DateTimeOffset {
    [CmdletBinding()]
    param (
        [Parameter()][datetime]$inputDate
    )

    #01/01/2017 03:02:43
    $dt = [datetimeoffset]::Parse($inputDate)
    $datetimeoffset = "{0:d2}-{1:d2}-{2:d2}T{3:d2}:{4:d2}:{5}.{6}{7}" -f $dt.Year, $dt.Month, $dt.Day, $dt.Hour, $dt.Minute, $dt.Second, $(Get-Random -Minimum 1000000 -Maximum 9999999), $dt.Offset
    return $datetimeoffset
}
#endregion Functions

$Error.Clear()

. .\AnthemPulseV30.ipa.ps1

#$applicationIdGuid = New-Guid

$appBody = [ordered]@{ 
    "@odata.type"                     = "#microsoft.graph.iosLOBApp" 
    "displayName"                     = $appProperties.displayName
    "description"                     = $appProperties.description
    "publisher"                       = $appProperties.publisher
    "isFeatured"                      = $false
    "privacyInformationUrl"           = $null
    "informationUrl"                  = $null
    "owner"                           = ""
    "developer"                       = ""
    "notes"                           = ""
    "publishingState"                 = "notPublished"
    "committedContentVersion"         = $appProperties.versionNumber
    "fileName"                        = $(Split-Path $appProperties.sourceFile -Leaf)
    "bundleId"                        = $appProperties.bundleId
    "applicableDeviceType"            = [ordered]@{ "@odata.type" = "#microsoft.graph.iosDeviceType"; "iPad" = $true; "iPhoneAndIPod" = $true }
    "minimumSupportedOperatingSystem" = [ordered]@{ "@odata.type" = "#microsoft.graph.iosMinimumOperatingSystem"; "v12_0" = $true }
    "expirationDateTime"              = $appProperties.expirationDateTime
    "versionNumber"                   = $appProperties.versionNumber
    "buildNumber"                     = $appProperties.versionNumber
    "identityVersion"                 = $appProperties.identityVersion
    #"largeIcon"                       = @{}
    #"size"                            = 1 #$((Get-Item $sourceFile).Length)
    #categories = @()
    #createdDateTime = [string]$((Get-Item $sourceFile).CreationTimeUtc | Get-Date -UFormat %Y-%m-%dT%H:%M:%SZ)
    #lastModifiedDateTime = [string]$((Get-Item $sourceFile).LastWriteTimeUtc | Get-Date -UFormat %Y-%m-%dT%H:%M:%SZ)
}

$TokenRequestBody = @{
    'Grant_Type'    = 'client_credentials'
    'client_Id'     = "191bdd6b-3e9a-440f-92a1-af06b3e73b55"
    'client_Secret' = "1x3p8g5u2q1o4i4k2t2d6b2n"
    'scope'         = "https://graph.microsoft.com/.default"
}

$TokenResponse = Invoke-RestMethod -Uri  "https://login.microsoftonline.com/40116f04-90e9-4f3d-a895-152754654561/oauth2/v2.0/token" -Method Post -Body $TokenRequestBody
Connect-MgGraph -AccessToken $TokenResponse.access_token

$headers = @{
    'Authorization' = $TokenResponse.access_token
    'Accept'        = 'application/json'
}

# Check for already existing versions based on displayName or bundleId
$getResults = Invoke-MgGraphRequest -Method Get -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" -Headers $headers
$getResultsMatches = $getResults.value | Where-Object { $_."@odata.type" -eq "#microsoft.graph.iosLobApp" }
if (($getResultsMatches.displayName -eq $appBody.displayName) -or ($getResultsMatches.bundleId -eq $appBody.bundleId)) {
    Write-Warning "Found a matching application already existing:"
    $getResultsMatches; exit
}

# Define the LOB App to Intune
$mgGraphOutputCreate = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps" -Headers $headers -Body $($appBody | ConvertTo-Json) -Verbose
$lobApplicationId = $mgGraphOutputCreate.id
$lobAppType = "microsoft.graph.iosLOBApp"

# increment a content version
$mgGraphOutputContentVersion = Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$lobApplicationId/$lobAppType/contentVersions " -Headers $headers -Body $(@{'id' = $lobApplicationId } | ConvertTo-Json) -Verbose
$lobApplicationContentVersion = $mgGraphOutputContentVersion.id

$encryptionInfo = EncryptFile -sourceFile "$PWD\$($appProperties.sourceFile)" -targetFile "$PWD\$($appProperties.sourceFile).bin"

[string]$manifestXML = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>items</key><array><dict><key>assets</key><array><dict><key>kind</key><string>software-package</string><key>url</key><string>{UrlPlaceHolder}</string></dict></array><key>metadata</key><dict><key>AppRestrictionPolicyTemplate</key> <string>http://management.microsoft.com/PolicyTemplates/AppRestrictions/iOS/v1</string><key>AppRestrictionTechnology</key><string>Windows Intune Application Restrictions Technology for iOS</string><key>IntuneMAMVersion</key><string></string><key>CFBundleSupportedPlatforms</key><array><string>iPhoneOS</string></array><key>MinimumOSVersion</key><string>9.0</string><key>bundle-identifier</key><string>bundleid</string><key>bundle-version</key><string>bundleversion</string><key>kind</key><string>software</string><key>subtitle</key><string>LaunchMeSubtitle</string><key>title</key><string>bundletitle</string></dict></dict></array></dict></plist>'
$manifestXML = $manifestXML.replace("bundleid", "$($appProperties.bundleId)").replace("bundleversion", "$($appProperties.identityVersion)").replace("bundletitle", "$($appProperties.displayName)")

$blobFile = Get-AzStorageBlob -Container "blobanthempulsev30" -Blob "AnthemPulseV30.ipa" -Context $((Get-AzStorageAccount -ResourceGroupName "rgAnthemPulseV30" -Name "saanthempulsev30").Context)

$appFileBody = [ordered]@{ 
    "@odata.type"                       = "#microsoft.graph.mobileAppContentFile"
    "name"                              = $blobFile.Name
    "size "                             = 0 #$blobFile.Length
    "sizeEncrypted"                     = 0 #$(Get-Item "$PWD\$($appProperties.sourceFile).bin").Length
    "manifest"                          = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48IURPQ1RZUEUgcGxpc3QgUFVCTElDICItLy9BcHBsZS8vRFREIFBMSVNUIDEuMC8vRU4iICJodHRwOi8vd3d3LmFwcGxlLmNvbS9EVERzL1Byb3BlcnR5TGlzdC0xLjAuZHRkIj48cGxpc3QgdmVyc2lvbj0iMS4wIj48ZGljdD48a2V5Pml0ZW1zPC9rZXk+PGFycmF5PjxkaWN0PjxrZXk+YXNzZXRzPC9rZXk+PGFycmF5PjxkaWN0PjxrZXk+a2luZDwva2V5PjxzdHJpbmc+c29mdHdhcmUtcGFja2FnZTwvc3RyaW5nPjxrZXk+dXJsPC9rZXk+PHN0cmluZz57VXJsUGxhY2VIb2xkZXJ9PC9zdHJpbmc+PC9kaWN0PjwvYXJyYXk+PGtleT5tZXRhZGF0YTwva2V5PjxkaWN0PjxrZXk+QXBwUmVzdHJpY3Rpb25Qb2xpY3lUZW1wbGF0ZTwva2V5PiA8c3RyaW5nPmh0dHA6Ly9tYW5hZ2VtZW50Lm1pY3Jvc29mdC5jb20vUG9saWN5VGVtcGxhdGVzL0FwcFJlc3RyaWN0aW9ucy9pT1MvdjE8L3N0cmluZz48a2V5PkFwcFJlc3RyaWN0aW9uVGVjaG5vbG9neTwva2V5PjxzdHJpbmc+V2luZG93cyBJbnR1bmUgQXBwbGljYXRpb24gUmVzdHJpY3Rpb25zIFRlY2hub2xvZ3kgZm9yIGlPUzwvc3RyaW5nPjxrZXk+SW50dW5lTUFNVmVyc2lvbjwva2V5PjxzdHJpbmc+PC9zdHJpbmc+PGtleT5DRkJ1bmRsZVN1cHBvcnRlZFBsYXRmb3Jtczwva2V5PjxhcnJheT48c3RyaW5nPmlQaG9uZU9TPC9zdHJpbmc+PC9hcnJheT48a2V5Pk1pbmltdW1PU1ZlcnNpb248L2tleT48c3RyaW5nPjkuMDwvc3RyaW5nPjxrZXk+YnVuZGxlLWlkZW50aWZpZXI8L2tleT48c3RyaW5nPmNvbS5hbnRoZW0ucHVsc2UuZGV2PC9zdHJpbmc+PGtleT5idW5kbGUtdmVyc2lvbjwva2V5PjxzdHJpbmc+MzAuMDwvc3RyaW5nPjxrZXk+a2luZDwva2V5PjxzdHJpbmc+c29mdHdhcmU8L3N0cmluZz48a2V5PnN1YnRpdGxlPC9rZXk+PHN0cmluZz5MYXVuY2hNZVN1YnRpdGxlPC9zdHJpbmc+PGtleT50aXRsZTwva2V5PjxzdHJpbmc+QW50aGVtIFB1bHNlPC9zdHJpbmc+PC9kaWN0PjwvZGljdD48L2FycmF5PjwvZGljdD48L3BsaXN0Pg=="
    "azureStorageUri"                   = $blobFile.BlobClient.Uri.AbsoluteUri
    "azureStorageUriExpirationDateTime" = $blobFile.BlobProperties.ExpiresOn | Get-Date -UFormat %Y-%m-%dT%H:%M:%SZ
    "isCommitted"                       = $true
    #"isDependency"                      = $false
    #"isFramework"                       = $false
    "id"                                = $lobApplicationId
    #"uploadState"                        = "success"
    "createdDateTime"                    = $blobFile.BlobProperties.CreatedOn | Get-Date -UFormat %Y-%m-%dT%H:%M:%SZ
}

#$letstryaget = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$lobApplicationId/$lobAppType/contentVersions/$lobApplicationContentVersion/files" -Headers $headers -Verbose
#$updatePublishingState = Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$lobApplicationId" -Headers $headers -Body $(@{'id' = $lobApplicationId; 'publishingState' = 'processing'} | ConvertTo-Json)


Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$lobApplicationId/$lobAppType/contentVersions/$lobApplicationContentVersion/files" -Headers $headers -Body $($appFileBody | ConvertTo-Json) -Verbose

$mgGraphOutputFilePrepare
#Write-Output $mgGraphOutputFilePrepare
