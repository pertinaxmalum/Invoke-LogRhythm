$onServer = $env:COMPUTERNAME -like "s*"

if ($onServer) {
    $proxy = '{{redacted}}'

    [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy($proxy)
    [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
    [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
}

$Base_URL = "{{redacted}}"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Get-Lists($pageSize, $pageNumber)  {
    $URL = $Base_URL + "lists"

    $header = @{Authorization = "Bearer $($env:LRAPIKEY)"}
    $header.Add("pageSize", $pageSize)
    $header.Add("pageNumber", $pageNumber)

    $response = Invoke-RestMethod -uri $url -Method get -ContentType "application/json" -headers $header

    $response
}

function Get-ListContent($GUID, $maxItemsThreshold) {
    $URL = $Base_URL + "lists/" + $guid

    $header = @{
        Authorization = "Bearer $($env:LRAPIKEY)"
        maxItemsThreshold = $maxItemsThreshold
    }

    $response = Invoke-RestMethod -uri $url -Method get -ContentType "application/json" -headers $header

    return $response
}

function Update-List {

    [CmdletBinding()]
    Param (

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $Name, 

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $GUID, 

    [Parameter(Mandatory = $false, Position = 0)]
    [Int] $id, 

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("enabled","usePatterns","replaceExisting", IgnoreCase = $true)]
    [String[]] $autoImportOption,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("Private","PublicAll","PublicGlobalAdmin","PublicGlobalAnalyst","PublicRestrictedAnalyst","PublicRestrictedAdmin", IgnoreCase = $true)]
    [String] $readAccess = "PublicRestrictedAnalyst",

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("Private","PublicAll","PublicGlobalAdmin","PublicGlobalAnalyst","PublicRestrictedAnalyst","PublicRestrictedAdmin", IgnoreCase = $true)]
    [String] $writeAccess = "PublicRestrictedAnalyst",

    [Parameter(Mandatory = $false, Position = 0)]
    [bool] $restrictedRead = $false,

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $entityName, # .e.g SCOTS ON-PREM

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $shortDescription,

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $longDescription,

    [Parameter(Mandatory = $false, Position = 0)]
    [bool] $needToNotify = $false,

    [Parameter(Mandatory = $false, Position = 0)]
    [bool] $doesExpire = $false,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("Active","Retried", IgnoreCase = $true)]
    [String] $Status = "Active",

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("Application","Classification","CommonEvent","Host","Location","MsgSource","MsgSourceType","MPERule","Network","User","GeneralValue","Entity","RootEntity","IP","IPRange","Identity", IgnoreCase = $true)]
    [String] $listType,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('None','Address','DomainImpacted','Group','HostName','Message','Object','Process','Session','Subject','URL','User','VendorMsgID','DomainOrigin','Hash','Policy','VendorInfo','Result','ObjectType','CVE','UserAgent','ParentProcessId','ParentProcessName','ParentProcessPath','SerialNumber','Reason','Status','ThreatId','ThreatName','SessionType','Action','ResponseCode','MACAddress',"ObjectName","UserAgent","Command",ignorecase=$true)]
    [String[]] $UseContext,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateRange(1, 7862400)]
    [Int] $TimeToLiveSeconds = $null


    )

    if ($autoImportOption) {
        
        $autoImportOption_hash = @{}

        if ($autoImportOption -contains "enabled") {$autoImportOption_hash.enabled = $true}
        if ($autoImportOption -contains "usePatterns") {$autoImportOption_hash.usePatterns = $true}
        if ($autoImportOption -contains "replaceExisting") {$autoImportOption_hash.replaceExisting = $true}

    } else {
        $autoImportOption_hash = @{
            enabled = $false
            usePatterns = $false
            replaceExisting = $false
        }
    }

    $body = @{
        
        listType = $listType
        name = $Name
        autoImportOption = $autoImportOption_hash
        readAccess = $readAccess
        writeAccess= $writeAccess
        needToNotify = $needToNotify
        shortDescription = $ShortDescription
        longDescription = $LongDescription
        doesExpire = $doesExpire
        restrictedRead = $restrictedRead
        entityName = $entityName
        owner = 17 # must stay as this
        entryCount = 0
        status= $Status
    
    }

    if ($listType -eq 'GeneralValue') {$body['useContext'] = $UseContext} else {$body['useContext'] = @('None')}
    if ($id) { $body['id'] = $id }
    if ($GUID) {$body['guid'] = $GUID.toupper()} # could populate this via name and getting lists
    # if you want to update an existing list it needs to find the GUID

    $body = $body | ConvertTo-Json
    
    # Make Call

    $URL = $Base_URL + "lists"

    $header = @{Authorization = "Bearer $($env:LRAPIKEY)"}

    $response = Invoke-RestMethod -uri $url -Method post -ContentType "application/json" -headers $header -Body $body

    return $response
}

function Add-ListContent {

    [CmdletBinding()]
    Param (

    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateSet("List","KnownService","Classification","CommonEvent","KnownHost","IP","IPRange","Location","MsgSource","MsgSourceType","MPERule","Network","StringValue","Port","PortRange","Protocol","HostName","ADGroup","Entity","RootEntity","DomainOrigin","Hash","Policy","VendorInfo","Result","ObjectType","CVE","UserAgent","ParentProcessId","ParentProcessName","ParentProcessPath","SerialNumber","Reason","Status","ThreatId","ThreatName","SessionType","Action","ResponseCode","Identity")]
    [string]$listItemType,

    [Parameter(Mandatory = $false, Position = 2)]
    [String]$displayValue,

    [Parameter(Mandatory = $false, Position = 3)]
    [Bool]$isExpired = $false,

    [Parameter(Mandatory = $false, Position = 4)]
    [Bool]$isListItem = $false,

    [Parameter(Mandatory = $false, Position = 5)]
    [Bool]$isPattern = $false,

    [Parameter(Mandatory = $false, Position = 5)]
    [Bool]$loadListItems = $false,

    [Parameter(Mandatory = $true, Position = 6)]
    [ValidateSet("List","Int32","String","PortRange","IP","IPRange")]
    [String]$listItemDataType, # default to string

    [Parameter(Mandatory = $false, Position = 7)]
    [Array]$Value,

    [Parameter(Mandatory = $false, Position = 8)]
    [String]$GUID,

    [Parameter(Mandatory = $false, Position = 9)]
    [String]$expirationDate

    )

    if ($expirationDate) { $_expirationDate = $expirationDate }

    $ItemValues = @()

    foreach ($entry in $Value) {
        
        $ItemValue = [PSCustomObject]@{
        displayValue = $Entry
        expirationDate = $_expirationDate
        isExpired =  $isExpired
        isListItem = $isListItem
        isPattern = $isPattern
        listItemDataType = $ListItemDataType
        listItemType = $ListItemType
        value = $Entry

        }

        $ItemValues += $ItemValue
 

    }

    $additional_url = "lists/$GUID/items/"

    $URL = $Base_URL + $additional_url

    $header = @{
        Authorization = "Bearer $($env:LRAPIKEY)"
        loadListItems = $loadListItems
        }

    $response = @()
    
    $chunkSize = 1000

    for ($counter = 0; $counter -lt $ItemValues.count ; $counter += $chunkSize) {

        $chunked_ItemValues = $ItemValues[$counter..($counter + $chunkSize - 1)]

        $body = @{items = @($chunked_ItemValues)}

        $json_body = $body | ConvertTo-Json
        
        $response += Invoke-RestMethod -uri $url -Method post -ContentType "application/json" -headers $header -Body $json_body

    }
    
    return $response

}

function Remove-ListContent {

    [CmdletBinding()]
    Param (

    [Parameter(Mandatory = $false, Position = 1)]
    [ValidateSet("List","KnownService","Classification","CommonEvent","KnownHost","IP","IPRange","Location","MsgSource","MsgSourceType","MPERule","Network","StringValue","Port","PortRange","Protocol","HostName","ADGroup","Entity","RootEntity","DomainOrigin","Hash","Policy","VendorInfo","Result","ObjectType","CVE","UserAgent","ParentProcessId","ParentProcessName","ParentProcessPath","SerialNumber","Reason","Status","ThreatId","ThreatName","SessionType","Action","ResponseCode","Identity")]
    [string]$listItemType,

    [Parameter(Mandatory = $false, Position = 2)]
    [String]$displayValue,

    [Parameter(Mandatory = $false, Position = 3)]
    [Bool]$isExpired = $false,

    [Parameter(Mandatory = $false, Position = 4)]
    [Bool]$isListItem = $false,

    [Parameter(Mandatory = $false, Position = 5)]
    [Bool]$isPattern = $false,

    [Parameter(Mandatory = $false, Position = 5)]
    [Bool]$loadListItems = $false,

    [Parameter(Mandatory = $true, Position = 6)]
    [ValidateSet("List","Int32","String","PortRange","IP","IPRange")]
    [String]$listItemDataType, # default to string

    [Parameter(Mandatory = $false, Position = 7)]
    [Array]$Value,

    [Parameter(Mandatory = $false, Position = 8)]
    [String]$GUID,

    [Parameter(Mandatory = $false, Position = 9)]
    [String]$expirationDate

    )

    if ($expirationDate) { $_expirationDate = $expirationDate }

    $ItemValues = @()

    foreach ($entry in $Value) {
        
        $ItemValue = [PSCustomObject]@{
        displayValue = $Entry
        expirationDate = $_expirationDate
        isExpired =  $isExpired
        isListItem = $isListItem
        isPattern = $isPattern
        listItemDataType = $ListItemDataType
        listItemType = $ListItemType
        value = $Entry

        }

        $ItemValues += $ItemValue
 

    }

    $additional_url = "lists/$GUID/items/"

    $URL = $Base_URL + $additional_url

    $header = @{
        Authorization = "Bearer $($env:LRAPIKEY)"
        loadListItems = $loadListItems
        }

    $response = @()
    
    $chunkSize = 1000

    for ($counter = 0; $counter -lt $ItemValues.count ; $counter += $chunkSize) {

        $chunked_ItemValues = $ItemValues[$counter..($counter + $chunkSize - 1)]

        $body = @{items = @($chunked_ItemValues)}

        $json_body = $body | ConvertTo-Json
        
        $response += Invoke-RestMethod -uri $url -Method Delete -ContentType "application/json" -headers $header -Body $json_body

    }
    
    return $response
}
