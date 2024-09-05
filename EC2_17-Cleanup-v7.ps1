<#
.SYNOPSIS
    Invokes various AWS Tools for PowerShell cmdlets to retrieve EC2.17 Security Hub findings, analyze to determine if the instance is an EKS cluster node, and suppress findings on those that are (per AWS Foundational Security Best Pratices Standard).
.DESCRIPTION
    This script is used to retrieve EC2.17 findings from Security Hub across all environments for the specified System.  The current EC2.17 findings are analylzed based on a system-generated field that indicates the instance is an EKS cluster node.  If the instance is an EKS cluster node, the finding is suppressed and the Note text is updated with the rationale.  If not, the script will prompt the user to investiage the instance in question.
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
    Date:   June 9, 2022
#>
#Version 6 - adjusted output to display the suppressing actions as a progress status and only write-host for anomalies.
#Version 5 - changed APS role to "APS Operations" from "APS Application Admin"
#Version 4 added get-help context
#Version 3 update removed dependency on CTKey.exe and incorporated PSScriptFunctions module to directly query CloudTamer for access keys

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
$NoteText="EC2 Instance is part of an EKS cluster, suppressing finding as allowed in AWS Foundational Security Best Practices Standard -  https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards-fsbp-controls.html#fsbp-ec2-17"
$GID="aws-foundational-security-best-practices/v/1.0.0/EC2.17"

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
			write-host "No EC2.17 Findings in $env.  Congratulations!"
		}Else{
			$message=$Count.toString()+" EC2.17 findings in "+$env
			write-host $message
			$Findings | %{
				$FID=$_.Id
				$Arn=$_.ProductArn
				$InstanceID=$_.Resources.Id
				#extract the instance ID from the full ID
				$InstanceID=$InstanceID.substring($InstanceID.Length-19,19)
				#evaluate the tags on the Instance to determine if there is a "kubernetes.io/cluster" value, which indicates the instance is a cluster node.  Per AWS Security Hub documentation, multiple ENIs are allowed when an instance is part of an EKS Cluster.
				if(((Get-EC2Instance -InstanceId $InstanceID -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -region us-east-1).instances.tags | ?{$_.key -like "*kubernetes.io/cluster/*"}) -ne $null){
					#write-host "Instance is a K8 Node..."
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
				}Else{
				$NoClusterMsg="Instance "+$InstanceID+" is not part of EKS Cluster - need to investigate"
				write-host $NoClusterMsg
				}
				$index++
			}
		}
	}
#Main Body End
}