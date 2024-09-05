<#
.SYNOPSIS
    Invokes the AWS Tools for PowerShell Security Hub cmdlets to retrieve Nash Testing (Tenable.sc/Nessus) scan findings from Security Hub.
.DESCRIPTION
    This script is used to retrieve Nash Testing (Tenable.sc/Nessus) scan findings from Security Hub across all environments for the specified System.  The current findings are assigned due dates based on severity and the date the finding was first observed.  Further, the script retrieves the User-Defined Field "Jira", which will contain the Jira ticket associated therewith when the "SecHub-Findings-Update" script is used.  The output of this script is a tab-delimited .csv file that can be imported into Excel for review.  The output file is saved to c:\temp\
.PARAMETER System Acronym (i.e. APS, UCM)
    The system acronym
.PARAMETER EUAID
    Your CMS Enterprise User ID
.PARAMETER SecurePassword
	Your EUA password
.EXAMPLE
    C:\PS> 
    <Description of example>
.NOTES
    Author: Brian Edwards
    Date:   March 14, 2023
	4/12/23 - Version 2 - Added processing of findings to omit anything that does not apply to an EC2 instance by filtering on the Finding ID for only those with an instance prefix (i-).  Added PSCreds parameter being passed to arrayBuilder.
	Version 1 - Initial script created to pull Nash findings for evaluation/analysis.  These will include records in an archived state, as Nash tags resolved findings as "Passed" and changes the record state to ARCHIVED.
	
	
#>


Param (
	[Parameter(Mandatory)][ValidateSet("APS","UCM")][Alias("Org")][String]${System Acronym (i.e. APS, UCM)},
    [Parameter(Mandatory=$True)][string]$EUAID,
	[System.Security.SecureString][Parameter(Mandatory)]$SecurePassword
)

$Org=${System Acronym (i.e. APS, UCM)}
#assign role based on org chosen
switch ($Org)
{
    "APS" {$role="APS ReadOnly"}
    "UCM" {$role="UCM Application Admin"}
}
#convert password for later use
$Password = (New-Object System.Management.Automation.PSCredential('dummy',$SecurePassword)).getnetworkcredential().password

#Initialization Section Start
#set default region and import necessary modules
set-defaultawsregion us-east-1
import-module aws.tools.common
import-module aws.tools.securityHub
import-module PSScriptFunctions.psm1

#initialize static variables
$OuterArray=@()
$ts=get-date -Format "yyyyMMdd"
$fn='c:\temp\'+$Org+'_Nash_Testing_Findings_'+$ts+'.csv'
$GID="cms.tenable"
$ProdName="Nash Testing"

#build filter using get-filter function in the psscriptfunctions module
$Filter=get-AWSfilter -WFStatus NewNotified -ProdName $ProdName -type Vulnerability


#Pre-script authentication check to avoid account lockout
$Auth=get-AuthToken -EUAID $EUAID -password $password
if($Auth.StatusCode -ne 200){
	write-host "Authentication failed, please check your EUAID or password and try again."
	break
}else{
	$Token=($Auth.content | convertfrom-json).data.access.token
	write-host "Authentication successful, retrieving data..."

	#Main Body Start
	#obtain cloudtamer projects for iterative retrieval of SecHub findings.  Retrieve the account_number/environment/role table to lookup values for each to use in the commands that follow
	$PSProjects=get-projects $Token -org $org

	#iterate through each project for the chosen org
	$PSProjects | %{
		
		$env=$_.name
		write-host $env
		$ProjId=$_.id
		#retrieve short-term access keys
		$PSCreds=get-EnvCreds -Token $Token -ProjId $ProjId -Role $Role

		#assign the short-term access keys to individual variables
		$AccessKey=$PSCreds.access_key
		$SecretKey=$PSCreds.secret_access_key
		$SessionToken=$PSCreds.session_token
		#run the cmdlet to retrieve Security Hub findings...
		$Findings = get-shubfinding -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -filter $Filter
		#if no findings exist, display a message on the screen and continue to next environment, otherwise continue processing
		if($Findings.count -eq 0){
			write-host "No Nash Findings in $env.  Congratulations!"
		}Else{
			#remove findings that are not associated with an instance (i.e. only assigned an IP address to the finding).  
			$Findings=$Findings | ?{$_.Id -like "*/i-*"}
			#display message with the total count of findings before passing to ArrayBuilder
			$message=($Findings.Count).toString()+" findings in "+$env
			write-host $message
			#Call the ArrayBuilder to parse the findings into the inner array (i.e. for the current environment)
			$InnerArray=ArrayBuilder -Findings $Findings -product $ProdName -env $env -PSCreds $PSCreds
		#add individual account findings processed to the external array
		$OuterArray+=$InnerArray
		}
	}

#export the fully populated array in tab-delimited format for analysis in Excel.
$OuterArray | Export-CSV -Delimiter "`t" -Path $fn -NoTypeInformation
write-host "Findings can be imported to Excel from $fn"
#Main Body End

}