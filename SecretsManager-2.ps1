<#
.SYNOPSIS
    Invokes various AWS Tools for PowerShell cmdlets to suppress SecretsManager.2 Security Hub findings, as these are Low severity findings that are typcially the result of an anomaly with AWS Config/SSM - the findings often self-resolve and those that don't do not survive past a maintenance cycle, as the Instances are re-created during maintenance.
.DESCRIPTION
    This script is used to retrieve and suppress SecretsManager.2 findings from Security Hub across all environments for the specified System.
.PARAMETER Org
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
    Date:   March 1, 2023
	
	
#>

Param (
	[Parameter(Mandatory)][ValidateSet("APS","UCM")][Alias("Org")][String]${System Acronym (i.e. APS, UCM)},
    [Parameter(Mandatory=$True)][string]$EUAID,
	[System.Security.SecureString][Parameter(Mandatory)]$SecurePassword
)

$Org=${System Acronym (i.e. APS, UCM)}
#set the role based on the System selected
switch ($Org)
{
    "APS" {$role="APS Operations"}
    "UCM" {$role="UCM Application Admin"}
}
#convert password to pass to other functions
$Password = (New-Object System.Management.Automation.PSCredential('dummy',$SecurePassword)).getnetworkcredential().password

#Initialization Section Start
#set default region and import necessary modules
set-defaultawsregion us-east-1
import-module aws.tools.common
import-module aws.tools.EC2
import-module aws.tools.securityhub
import-module PSScriptFunctions.psm1

#initialize static variables
$NoteText="SecretsManager.2 Findings: RotationOccurringAsScheduled is set to true but we force autorotation to kickoff during maintenance. Due to avoid impact on application and application account dependency, we cannot let autorotate run every 60days. Also, our schedule maintenance is not at exactly on 60 days for password rotation. So we need the findings to be suppressed as no action will be taken by the team."
$GID="aws-foundational-security-best-practices/v/1.0.0/SecretsManager.2"

#build filter using PSScriptFunctions module
$Filter=get-AWSFilter -Compliance Failed -WFStatus NewNotified -ProdName "Security Hub" -GID $GID

#Pre-script authentication check to avoid account lockout
$Auth=get-AuthToken -EUAID $EUAID -password $Password
if($Auth.StatusCode -ne 200){
	write-host "Authentication failed, please check your EUAID or password and try again."
	break
}else{
	$Token=($Auth.content | convertfrom-json).data.access.token
	write-host "Authentication successful, retrieving data..."
	
	#Main Body Start

	#obtain cloudtamer projects for iterative retrieval of SecHub findings.Retrieve the account_number/environment/role table to lookup values for each to use in the commands that follow
	$PSProjects=get-projects $Token -org $org

	#iterate through each project for the chosen org
	$PSProjects | %{
		#retrieve the friendly environment name for the account being processed
		$env=$_.name
		$ProjId=$_.id
		#retrieve short-term access keys
		$PSCreds=get-EnvCreds -Token $Token -ProjId $ProjId -Role $Role
		#assign the temporary credentials to individual variables
		$AccessKey=$PSCreds.access_key
		$SecretKey=$PSCreds.secret_access_key
		$SessionToken=$PSCreds.session_token

		#initialize index
		$index=1
		#run the cmdlet to retrieve Security Hub findings...
		$Findings = get-shubfinding -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -filter $Filter
		$count=$Findings.Count
		#if no findings exist, display a message on the screen and continue to next environment, otherwise continue processing
		if($Count -eq 0){
			write-host "No SecretsManager.2 Findings in $env.  Congratulations!"
		}Else{
			$message=$Count.toString()+" SecretsManager.2 findings in "+$env
			write-host $message
			$Findings | %{
				$region=$_.Region
				$FID=$_.Id
				$Arn=$_.ProductArn
				#initialize FindingID variable to populate with unique finding identifers
				$FindingID = new-object Amazon.SecurityHub.Model.AwsSecurityFindingIdentifier
				$FindingID.Id=$FID
				$FindingID.ProductArn=$Arn
				$ProgressMsg="Suppressing finding "+$index+" of "+$count
				#write-host $ProgressMsg
				$ProcessedFindings=Update-SHUBFindingsBatch -FindingIdentifier $FindingID -Workflow_Status SUPPRESSED -Note_Text $NoteText -Note_UpdatedBy $EUAID -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken
				$FindingId=$ProcessedFindings.ProcessedFindings.Id
				$StatusMsg="Finding "+$index+"of "+$count+": "+$FindingId+"."
				write-progress -Activity "Suppressing finding...." -Status $StatusMsg
				
				$index++
			}
		}
	}
#Main Body End
}