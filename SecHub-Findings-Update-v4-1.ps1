<#
.SYNOPSIS
    Version 4
.DESCRIPTION
    This script is used to update AWS Security Hub findings in the following ways:  Update Workflow Status from NEW to NOTIFIED, Add a UserDefinedField to track the Jira Ticket assigned to the finding, Update the UserDefinedField text when a Jira ticket changes (i.e. Cloud Support, AWS Tech Support, etc.).
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
    Date:   June 9, 2022
	5/8/23 - updated out-gridview to display jira # and workflow status.
	12/6/22 - Version 4 update - stop using "Notes" field to store Jira ticket# - start using "user defined fields" property in SHUBBatchFindingUpdate to record Jira ticket#.  The getsechubfinding script will need to be modified to retrieve the new field
	6/9/22 - version 3 update - modified APS role to "APS Operations", added get-help context
	6/2/22 update modified APS role to "APS Application Admin", WFStatus to NewNotified to facilitate changing a previous update
	5/12/22 - Version 2 update - moving several functions to the psscriptfunctions.psm1 module
	5/5/22 - this is the initial script to update Security Hub findings to add the Jira ID to the "notes" parameter of the finding while at the same time updating the workflow status to NOTIFIED.  This script no longer relies on the ctkey executable for access key retrieval - everything is contained in API calls.
#>

Param (
	[Parameter(Mandatory)][ValidateSet("APS","UCM")][Alias("Org")][String]${System Acronym (i.e. APS, UCM)},
	[Parameter(Mandatory)][ValidateSet("NEW","NEWNOTIFIED","NOTIFIED")][Alias("WFStatus")][String]${Workflow Status (i.e. New, NewNotified, Notified)},
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

write-host "initializing filter..."
#build filter from PSScriptFunctions module
$Filter=get-AWSFilter -Compliance Failed -WFStatus $WFStatus -ProdName "Security Hub"

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
		$Updates=$Findings | select `
		GeneratorID,
		@{Name="WFStatus"; Expression={ $_.Workflow.Status.Value}},
		@{Name="Jira"; Expression={ $_.UserDefinedFields.Jira}},ProductArn,
		Id `
		| out-gridview -passthru -title "Select Finding(s) to Update"
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
	