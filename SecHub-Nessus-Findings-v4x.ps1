<#
.SYNOPSIS
    Invokes the AWS Tools for PowerShell Security Hub cmdlets to retrieve Tenable.sc/Nessus scan findings from Security Hub.
.DESCRIPTION
    This script is used to retrieve Tenable.sc/Nessus scan findings from Security Hub across all environments for the specified System.  The current findings are assigned due dates based on severity and the date the finding was first observed.  Further, the script retrieves the Notes text from the finding json, which will contain the Jira ticket associated therewith when the "SecHub-Findings-Update" script is used.  The output of this script is a tab-delimited .csv file that can be imported into Excel for review.  The output file is saved to c:\temp\
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
    Date:   October 19, 2022
	
	Version 4 (5/26/23) - updated to include calls to batch update function to change workflow status to "RESOLVED" on findings that have an "updatedAt" timestamp earlier than the most recent scan date, as Nessus isn't marking existing findings resolved once they are remediated, it just stops updating the finding. This will constrain the report to only the latest findings.  $Role needed to be changed to "APS Operations" in order to have sufficient privileges to perform the batch updates.
	Version 3 (5/25/23) - update call to arrayBuilder to pass PSCreds for resourceName retrieval
	Version 2 (12/2/22) - update filter creation to differentiate between vulnerability and compliance scans...
	Version 1 - Initial script created to pull Nessus findings for evaluation/analysis for the migration from Inspector to Nessus per CMS' initiative.
	
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
    "APS" {$role="APS Operations"}
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
$fn='c:\temp\'+$Org+'_Tenable_Nessus_Findings_'+$ts+'.csv'
$GID="cms.tenable"

#build filter using get-filter function in the psscriptfunctions module
$Filter=get-AWSfilter -WFStatus NewNotified -GID $GID -Type Vulnerability

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
		#run the cmdlet to retrieve Security Hub Nessus findings...
		$Findings = get-shubfinding -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -filter $Filter
		#if no findings exist, display a message on the screen and continue to next environment, otherwise continue processing
		if($Findings.count -eq 0){
			write-host "No Tenable Nessus Findings in $env.  Congratulations!"
		}Else{
			#sort the findings in descending UpdatedAt timestamp order
			$Findings = $Findings | sort-object UpdatedAt -descending
		
			#display message to let user know that the script is running
			$progressmsg="Retrieving instance names for findings..."
			write-host $progressmsg

			#Call the ArrayBuilder to parse the findings into the inner array (i.e. for the current environment)
			$InnerArray=ArrayBuilder -Findings $Findings -product tenable -env $env -PSCreds $PSCreds
		
			#Set the latest scan date to the newest UpdatedAtShort value in the array
			$LatestScanDate=$InnerArray[0].UpdatedAtShort
			
			#split the findings into "current" and "older" arrays
#			$CurrentArray=$InnerArray | ?{($_.UpdatedAtShort -eq $LatestScanDate)}
#			$OlderArray=$InnerArray | ?{($_.UpdatedAtShort -lt $LatestScanDate)}
#			$OlderCount=$OlderArray.count
			
			#check how many older findings before proceeding and display a message accordingly
#			If($OlderCount -lt 1){
#				write-host "No older findings to resolve."
#			}else{
#				$OlderFindingsMessage="$OlderCount findings being resolved..."
#				Write-host $OlderFindingsMessage
				
				#Iterate through the older findings to update the Workflow Status to RESOLVED
#				$OlderArray | %{
					#initialize FindingID variable to populate with unique finding identifers
#					$FindingID = new-object Amazon.SecurityHub.Model.AwsSecurityFindingIdentifier
#					$FindingID.Id=$_.FindingId
#					$FindingID.ProductArn=$_.ProdArn
#					$ProcessedFindings=Update-SHUBFindingsBatch -FindingIdentifier $FindingID -Workflow_Status RESOLVED -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken
#					write-host $ProcessedFindings.ProcessedFindings.Id
#				}
#			}
		
		#compose message to display the final count of findings (current)
#		$message=($CurrentArray.Count).toString()+" findings in "+$env
#		write-host $message
			
		#add individual account findings processed to the external array
		#$OuterArray+=$CurrentArray   # Abdallah removed
		$InnerArray | ?{($_.UpdatedAtShort -eq $LatestScanDate)} # Abdallah - Added
		$OuterArray+=$InnerArray # Abdallah Added
		}
	}

#export the fully populated array in tab-delimited format for analysis in Excel.
$OuterArray | Export-CSV -Delimiter "`t" -Path $fn -NoTypeInformation
write-host "Findings can be imported to Excel from $fn"
#Main Body End

}