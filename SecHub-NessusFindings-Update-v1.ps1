<#
.SYNOPSIS
    Version 1
.DESCRIPTION
    This script is used to update Tenable/Nessus findings in Security Hub findings in the following ways:  Update Workflow Status from NEW to NOTIFIED, Add a UserDefinedField to track the Jira Ticket assigned to the finding, Update the UserDefinedField text when a Jira ticket changes (i.e. Cloud Support, AWS Tech Support, etc.).
.PARAMETER Org
    The system acronym
.PARAMETER EUAID
    Your CMS Enterprise User ID
.PARAMETER WFStatus
	The AWS Security Hub Workflow Status to pull from.  Choose "NEW" to only pull down NEW finding, "NOTIFIED" to pull down previously updated findings, and "NEWNOTIFIED" to pull both.
.EXAMPLE
    C:\PS> 
    <Description of example>
.NOTES
    Author: Brian Edwards
    Date:   December 12, 2022
	
	12/12/22 - Initial Version - modified the SecHub-Findings-Update-v4 script to accommodate Tenable/Nessus findings.  Eventually these two should be merged with an input paramter to differentiate between finding type, etc.  
#>

Param (
	[Parameter(Mandatory)][ValidateSet("APS","UCM")][Alias("Org")][String]${System Acronym (i.e. APS, UCM)},
	[Parameter(Mandatory)][ValidateSet("NEW","NEWNOTIFIED","NOTIFIED")][Alias("WFStatus")][String]${Workflow Status (i.e. New, NewNotified, Notified)},
	[Parameter(Mandatory)][ValidateSet("C","H","M","L","I","CHML","HMLI")][String]$Severity,
    [Parameter(Mandatory=$True)][string]$EUAID,
	[System.Security.SecureString][Parameter(Mandatory)]$SecurePassword
)
$Password = (New-Object System.Management.Automation.PSCredential('dummy',$SecurePassword)).getnetworkcredential().password
$Org=${System Acronym (i.e. APS, UCM)}
switch ($Org)
{
    "APS" {$role="APS Operations"}
    "UCM" {$role="UCM Application Admin"}
}
$WFStatus=${Workflow Status (i.e. New, NewNotified, Notified)}

write-host "Initialization section starting"
#Initialization Section Start
#set default region and import necessary modules
import-module aws.tools.common
import-module aws.tools.securityHub
import-module PSScriptFunctions
set-defaultawsregion us-east-1

#initialize static variables
$OuterArray=@()
$GID="cms.tenable"

write-host "initializing filter..."
#build filter from PSScriptFunctions module
$Filter=get-AWSFilter -GID $GID -Severity $Severity -Type Vulnerability -WFStatus $WFStatus

write-host "initializing auth check..."
#Pre-script authentication check to avoid account lockout
$Auth=get-AuthToken -EUAID $EUAID -password $password
if($Auth.StatusCode -ne 200){
	write-host "Authentication failed, please check your EUAID or password and try again."
	break
}else{
	$Token=($Auth.content | convertfrom-json).data.access.token
	write-host "Authentication successful, retrieving data..."
	
	#obtain short-term access credentials
	$PSCreds,$env=get-CloudTamerCredsWithPrompt -Token $Token -Role $role
	write-host "obtaining information for $env"
	
	$AccessKey=$PSCreds.access_key
	$SecretKey=$PSCreds.secret_access_key
	$SessionToken=$PSCreds.session_token

	#Main Body Start

	#initialize index
	$index=1
	#run the cmdlet to retrieve Security Hub findings...
	$Findings = get-shubfinding -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -filter $filter
	$count=$Findings.Count
	#if no findings exist, display a message on the screen
	if($Count -eq 0){
		write-host "No Security Hub Findings in $env.  Congratulations!"
	}Else{
		$message=$Count.toString()+" NEW Security Hub findings in "+$env
		write-host $message
		$Updates=$Findings | select Title,ProductArn,Id | out-gridview -passthru -title "Select Finding(s) to Update"
		#Prompt User to enter Jira ID for the ticket created for the finding.
		$Jira=read-host "Enter Jira Ticket#"
		#convert the user input to string
		$Jira=$Jira.ToString()
		#initialize the UserDefinedFields hashtable
		$UDF=@{}
		#assign the user-provided Jira Ticket# to the key "Jira"
		$UDF.Jira=$Jira
		$Updates | %{
			#initialize FindingID variable to populate with unique finding identifers
			$FindingID = new-object Amazon.SecurityHub.Model.AwsSecurityFindingIdentifier
			$FindingID.Id=$_.Id
			$FindingID.ProductArn=$_.ProductArn
			$ProcessedFindings=Update-SHUBFindingsBatch -FindingIdentifier $FindingID -Workflow_Status NOTIFIED -UserDefinedField $UDF -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken
			write-host $ProcessedFindings.ProcessedFindings.Id
		}
	}
	#Main Body End
}
	