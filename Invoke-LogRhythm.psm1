function Invoke-LogRhythm {

    [CmdletBinding()]
    Param (

    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $GetLists,
    
    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $GetListContent,

    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $UpdateList,

    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $AddListContent,

    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $RemoveListContent,

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
    [ValidateSet("Application","Classification","CommonEvent","Host","Location","MsgSource","MsgSourceType","MPERule","Network","User","GeneralValue","Entity","RootEntity","IP","IPRange","Identity", IgnoreCase = $true)]
    [String] $listType,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('None','Address','DomainImpacted','Group','HostName','Message','Object','Process','Session','Subject','URL','User','VendorMsgID','DomainOrigin','Hash','Policy','VendorInfo','Result','ObjectType','CVE','UserAgent','ParentProcessId','ParentProcessName','ParentProcessPath','SerialNumber','Reason','Status','ThreatId','ThreatName','SessionType','Action','ResponseCode','MACAddress',"ObjectName","UserAgent","Command",ignorecase=$true)]
    [String[]] $UseContext,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateRange(1, 7862400)]
    [Int] $TimeToLiveSeconds = $null,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("List","KnownService","Classification","CommonEvent","KnownHost","IP","IPRange","Location","MsgSource","MsgSourceType","MPERule","Network","StringValue","Port","PortRange","Protocol","HostName","ADGroup","Entity","RootEntity","DomainOrigin","Hash","Policy","VendorInfo","Result","ObjectType","CVE","UserAgent","ParentProcessId","ParentProcessName","ParentProcessPath","SerialNumber","Reason","Status","ThreatId","ThreatName","SessionType","Action","ResponseCode","Identity")]
    [string]$listItemType,

    [Parameter(Mandatory = $false, Position = 0)]
    [String]$displayValue,

    [Parameter(Mandatory = $false, Position = 0)]
    [Bool]$isExpired = $false,

    [Parameter(Mandatory = $false, Position = 0)]
    [Bool]$isListItem = $false,

    [Parameter(Mandatory = $false, Position = 0)]
    [Bool]$isPattern = $false,

    [Parameter(Mandatory = $false, Position = 0)]
    [Bool]$loadListItems = $true,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("List","Int32","String","PortRange","IP","IPRange")]
    [String]$listItemDataType, # default to string

    [Parameter(Mandatory = $false, Position = 0)]
    [Array]$Value,

    [Parameter(Mandatory = $false, Position = 0)]
    [Int]$maxItemsThreshold = 150000,

    [Parameter(Mandatory = $false, Position = 0)]
    [Int]$listPageSize = 1000,

    [Parameter(Mandatory = $false, Position = 0)]
    [Int]$listPageNumber = 1,

    [Parameter(Mandatory = $false, Position = 0)]
    [System.IO.FileInfo]$cliXML

    )

    Import-Module "$PSScriptRoot\LogRhythm Utils.psm1"

    if (!$cliXML) { $cliXML = "$PSScriptRoot\details.xml" }

    function Get-Cred ($cliXML) {
    
        $cred = Import-Clixml $cliXML

        $cred_securestring = $cred | ConvertTo-SecureString

        $secure_token = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred_securestring)

        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($secure_token)

    }

    # Variarables
    $env:LRAPIKEY = Get-Cred -cliXML $cliXML
    
    # Proxy awareness - if needed
    $onServer = $env:COMPUTERNAME -like "s*"

    if ($onServer) {
        $proxy = '{{redacted}}'

        [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy($proxy)
        [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
    }

    $Base_URL = "{{redacted}}"

    if ($GetLists) {
        Get-Lists -pageSize $listPageSize -pageNumber $listPageNumber
    }

    if ($GetListContent) {
        Get-ListContent -GUID $GUID -maxItemsThreshold $maxItemsThreshold

    }
    
    if ($UpdateList) {
        
        Update-List `
        -listType  $listType `
        -name  $Name `
        -autoImportOption  $autoImportOption_hash `
        -readAccess  $readAccess `
        -writeAccess $writeAccess `
        -needToNotify  $needToNotify `
        -shortDescription  $ShortDescription `
        -longDescription  $LongDescription `
        -doesExpire  $doesExpire `
        -restrictedRead  $restrictedRead `
        -entityName  $entityName `
        -owner  17 `
        -status $Status `
        -GUID $GUID
    }

    if ($AddListContent) {
        Add-ListContent `
        -expirationDate $ExpDate `
        -isExpired  $isExpired `
        -isListItem $isListItem `
        -isPattern $isPattern `
        -listItemDataType $ListItemDataType `
        -listItemType $ListItemType `
        -value $Value `
        -loadListItems $loadListItems `
        -GUID $GUID
    }

    if ($RemoveListContent) {
        Remove-ListContent `
        -expirationDate $ExpDate `
        -isExpired  $isExpired `
        -isListItem $isListItem `
        -isPattern $isPattern `
        -listItemDataType $ListItemDataType `
        -listItemType $ListItemType `
        -loadListItems $loadListItems `
        -value $Value `
        -GUID $GUID
    }

    $env:LRAPIKEY = $null
}
