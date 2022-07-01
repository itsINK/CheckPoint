
<#


.SYNOPSIS
This Powershell Script authenticates users to the Check Point API of specific SmartCenter Servers or domains.

.DESCRIPTION
The script allows users to authenticate themselves to some specific Check Point SmartCenter or Domain. 
Users can enter parameters (username, password, domain, server address) in advance or interactively, when running the scripts. 
If Authenthe script leaves behind in the shell environment two objects, $myCPHeader and $mySmartCenterAddress, that can be used to create additional calls to the APIs. 
The script also outputs the contents of the reply from the server, if authentication succeeds.

.EXAMPLE
PS C:\Users\lebowits\Documents\GitHub\powershellscripts> .\CPAPI-Authenticate.ps1 -username user  -mySmartCenterAddress 1.1.1.1:8080

.NOTES
Entering the password in cleartext is optional. If you don't enter that parameter, you'll be prompted to enter the password into a secured string


.LINK
https://github.com/jlebowitsch/powershellscripts


#>


param(

    [Parameter(Mandatory=$true, HelpMessage="username")]
     [String]$username,
	[Parameter(Mandatory=$false, HelpMessage="clear text password")]
     [String]$ClearTextPassword,
	[Parameter(Mandatory=$true, HelpMessage="IP Addess of Management Server")]
     [String]$mySmartCenterAddress,
	[Parameter(Mandatory=$false, HelpMessage="If connecting to a domain in an MDS, specify it")][AllowNull()] 
     [String]$DomainName
	
	 

)


#resetting variables that may have lingered from previous runs
$myresponse=""
$mysid=""
$myaddhostresponse=""
$mypublishresponse=""




# securely prompt for password if none was provided

if ($ClearTextPassword -eq "")
	{	$credential=get-credential -message "Please enter your SmartCenter username and password" -username $username
		$password=$credential.GetNetworkCredential().password
	}
	else {$password=$ClearTextPassword}

#create credential json
$myCredentialhash=@{user=$username;password=$password}

if($DomainName.length -gt 0){$myCredentialhash.add("domain", $DomainName) }
$myjson=$myCredentialhash | convertto-json -compress

# create login URI
$loginURI="https://${mySmartCenterAddress}/web_api/login"


#allow self signed certs
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }

#log in and capture response

$myresponse=Invoke-WebRequest -Uri $loginURI -Body $myjson -ContentType application/json -Method POST
 
   

#remove objects with password
rv "password"
rv "myjson"
if ($ClearTextPassword.Length -gt 0) {rv "ClearTextPassword"}
if ($credential.password.Length -gt 0) {rv "credential"}


#make the content of the response a powershell object
$myresponsecontent=$myresponse.Content | ConvertFrom-Json

#get the sid of the response into its own object

$mysid=$myresponsecontent.sid

#create an x-chkp-sid header
$global:myCPHeader=@{"x-chkp-sid"=$mysid}
$myresponsecontent

## make the SmartCenter Address a Global Parameter
$global:myCPSmartCenterIPAddress=$mySmartCenterAddress


# add access rule
$addURI="https://${mySmartCenterAddress}/web_api/add-access-rule"

$myjson=@{layer="Network";position=1;name="Rule 1"} 
$myrequestbodyjson=$myjson | convertto-json -compress

#add rule and capture response

$myaddresponse=Invoke-WebRequest -Uri $addURI -Body $myrequestbodyjson -ContentType application/json -Method POST -headers $myCPHeader
#make the content of the response a powershell object
$myresponsecontent=$myaddresponse.Content | ConvertFrom-Json
$myresponsecontent





# set access rule
$setURI="https://${mySmartCenterAddress}/web_api/set-access-rule"

$myjson=@{name="Rule 1";action="Accept"} 
$myrequestbodyjson=$myjson | convertto-json -compress

#set rule and capture response

$mysetresponse=Invoke-WebRequest -Uri $setURI -Body $myrequestbodyjson -ContentType application/json -Method POST -headers $myCPHeader
#make the content of the response a powershell object
$myresponsecontent=$mysetresponse.Content | ConvertFrom-Json
$myresponsecontent


# del access rule
$delURI="https://${mySmartCenterAddress}/web_api/delete-access-rule"

$myjson=@{name="Rule 1";layer="Network"} 
$myrequestbodyjson=$myjson | convertto-json -compress

#del rule and capture response

#$mydelresponse=Invoke-WebRequest -Uri $delURI -Body $myrequestbodyjson -ContentType application/json -Method POST -headers $myCPHeader
#make the content of the response a powershell object
#$myresponsecontent=$mydelresponse.Content | ConvertFrom-Json
#$myresponsecontent


# publish result
$publURI="https://${mySmartCenterAddress}/web_api/publish"

$myjson=@{} 
$myrequestbodyjson=$myjson | convertto-json -compress

# publish result and capture response

$mypublresponse=Invoke-WebRequest -Uri $publURI -Body $myrequestbodyjson -ContentType application/json -Method POST -headers $myCPHeader
#make the content of the response a powershell object
$myresponsecontent=$mypublresponse.Content | ConvertFrom-Json
$myresponsecontent




# new policy package
$policyURI="https://${mySmartCenterAddress}/web_api/install-policy"

$myjson=@{"policy-package"="standard";access=True;"threat-prevention"=True;targets="SG"}
$myrequestbodyjson=$myjson | convertto-json -compress

# publish result and capture response

$mypublresponse=Invoke-WebRequest -Uri $publURI -Body $myrequestbodyjson -ContentType application/json -Method POST -headers $myCPHeader
#make the content of the response a powershell object
$myresponsecontent=$mypublresponse.Content | ConvertFrom-Json
$myresponsecontent




# create logout URI
$logoutURI="https://${mySmartCenterAddress}/web_api/logout"

$myjson=@{} 
$myrequestbodyjson=$myjson | convertto-json -compress

#log out and capture response

$mylogoutresponse=Invoke-WebRequest -Uri $logoutURI -Body $myrequestbodyjson -ContentType application/json -Method POST -headers $myCPHeader
#make the content of the response a powershell object
$myresponsecontent=$mylogoutresponse.Content | ConvertFrom-Json
$myresponsecontent