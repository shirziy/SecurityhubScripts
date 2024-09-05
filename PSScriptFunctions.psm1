<#
.SYNOPSIS
    The PSScriptFunctions module contains various Functions that are used repeatedly across various scripts.  The primary purpose was to ensure consistency with the scripts as well as to reduce the in-script code to make them more readable and easier to troubleshoot.
.DESCRIPTION
    This module is used as a repository for functions that are used frequently or across multipel scripts.  Updates to this module are reflected in the .NOTES section.
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
    5/24/24 Modified CADateFormat to fix parseExact timestamp warnings
    Date:   June 16, 2022
	5/25/23 Update - modified arrayBuilder to retrieve ResourceName (same as SecHub) for tenable findings and re-ordered Jira field to beginning of row
	4/14/23 Update - modified arrayBuilder to retrieve resource name tags for Security Hub findings - incorporates a separate API call during the processing of findings, as the Name tag is not included in the Security Hub findings json.  Also added $PSCreds param to arrayBuilder as an input
	4/10/23 Update - modified arrayBuilder function to retrieve the "name" field from the Resources.Tags as well as process the Findings to remove those attributed to the load balancers (i.e. those with "//" in the FindingId.  
	3/14/23 Update - modified arrayBuilder function to retrieve fields added by Nash, modified get-Filter function to not specify record state for Nash findings, since Nash uses archived records for resolved findings.
	12/6/22 Update - modified arrayBuilder function to retrieve the UserDefinedField "Jira", which will now be used for recording the Jira ticket created for a finding.
	12/2/22 Update - modifield get-filter function to refine the output of Nessus scan results from SecurityHub by adding the ProductFieldType values for Vulnerability versus Compliance scans
	11/29/22 Update - added fields to the ArrayBuilder switch statement for "tenable" output to include UpdatedAt date (to reflect the most recent Nessus scan date.
	10/21/22 Update - commented out the start-sleep function to elminiate the .5 second delay in between batch processing to speed up the script.
	10/14/22 Update - changed GID filter option in get-AWSFilter function to use the comparison "PREFIX" to identify findings that "start with" the value passed in the $GID parameter.
	7/19/22 Update - added $EUAID input parameter for BatchUpdateSecHubFindings, as the AWS BatchUpdate cmdlet requires an "updated by" value.
	6/23/22 - added ArrayBuilder function to modularize the parsing of findings into an array for ease of data manipulation and analysis.
	6/16/22 - added BatchUpdateSecHubFindings function to modularize the batch update proecess.  This increases efficiency of updating large number of findings by an order of magnitude.
	5/11/22 - This module is for reuse of functions across various scripts.  This module must be saved in a folder bearing the same name within any of the module paths (use this command to locate:  $env:PSModulePath -split ';').  Use the "import-module PSScriptFunctions.psm1" to enable use of the functions.
#>

function get-AuthToken{
	#takes in EUAID and Password, returns the full token response object
	Param ($EUAID,$password)
	#retrieve authentication token using EUA credentials
	$TokenBody='{"idms":2,"password":"'+$password+'","username":"'+$EUAID+'"}'
	$TokenURI='https://cloudtamer.cms.gov/api/v3/token'
	$TokenResponse=iwr -method POST -URI $TokenURI -contentType "application/json" -body $TokenBody
	return $TokenResponse
}

function get-CloudTamerCredsWithPrompt{
	#takes in the auth token, prompts the user to pick a project and returns an object "PSCreds" for the chosen environment
	Param ($Token,$role)

	$headers=@{Authorization = "Bearer $Token"}
	#Obtain projects from KION and pipe to out-gridview to select the environment
	$ProjectURI="https://cloudtamer.cms.gov/api/v3/project"
	$ProjectResponse=iwr -method GET -headers $headers -uri $ProjectURI -contentType "application/json"
	$ProjID=($ProjectResponse.content | convertfrom-json).data  | out-gridview -Title "Select Project" -outputmode single
	$env=$ProjID.name
	#obtain accounts from KION
	$CloudAccessRoleURI="https://cloudtamer.cms.gov/api/v3/me/cloud-access-role"
	$CloudAccessRoleResponse=iwr -method GET -headers $headers -uri $CloudAccessRoleURI -contentType "application/json"
	#take the output from gridview to retrieve the account number based on Project ID and the appropriate role (in this case, UCM Application Admin)
	$Profiles=($CloudAccessRoleResponse.content | convertfrom-json).data
	$Profile=$Profiles.where({$_.project_id -eq $ProjId.id})
	$Profile=$Profile.where({$_.name -eq $role})
	$Account=$Profile.account_number
	#$Role=$Profile.name
	
	#Pass auth token and environment parameters (account & role) to retrieve short-term access keys
	$CredentialBody='{"account_number":"'+$account+'", "cloud_access_role_name":"'+$role+'"}'
	$CredentialURI="https://cloudtamer.cms.gov/api/v3/temporary-credentials/cloud-access-role"
		#retrieve short-term access keys from CloudTamer and assign them to appropriate variables
	$CredentialResponse=iwr -method POST -headers $headers -uri $CredentialURI -contentType "application/json" -body $CredentialBody
	$PSCreds=($CredentialResponse.Content|convertfrom-json).data
	$AccessKey=$PSCreds.access_key
	$SecretKey=$PSCreds.secret_access_key
	$SessionToken=$PSCreds.session_token
	
	return $PSCreds,$env
}

function get-Projects{
	#takes in EUAID, Password and Org (UCM, APS) and returns an object "PSProjects" containing the Project Names as displayed in Cloud Tamer, along with the project ID to then feed into get-CloudTamerCredsEnv
	Param ($Token,$org)
	$headers=@{Authorization = "Bearer $Token"}
	#Obtain projects from KION and pipe to out-gridview to select the environment
	$ProjectURI="https://cloudtamer.cms.gov/api/v3/project"
	$ProjectResponse=iwr -method GET -headers $headers -uri $ProjectURI -contentType "application/json"
	$PSProjects=($ProjectResponse.content | convertfrom-json).data  | ?{$_.name -like "$org*"}
		
	return $PSProjects
}

function get-EnvCreds{
	#takes in Token, role and projectID and returns an object "PSCreds" for the chosen environment
	#to use in scripts, first get the $PSProjects object from get-Projects, then iterate through each pulling $ProjId from $PSProjects.id, and $role based on $org
	Param ($Token,$ProjId,$Role)
	
	$headers=@{Authorization = "Bearer $Token"}
	#obtain accounts from KION
	$CloudAccessRoleURI="https://cloudtamer.cms.gov/api/v3/me/cloud-access-role"
	$CloudAccessRoleResponse=iwr -method GET -headers $headers -uri $CloudAccessRoleURI -contentType "application/json"
	#take the output from gridview to retrieve the account number based on Project ID and the appropriate role (in this case, UCM Application Admin)
	$Profiles=($CloudAccessRoleResponse.content | convertfrom-json).data
	$Profile=$Profiles.where({$_.project_id -eq $ProjId})
	$Profile=$Profile.where({$_.name -eq $Role})
	$Account=$Profile.account_number
	
	#Pass auth token and environment parameters (account & role) to retrieve short-term access keys
	$CredentialBody='{"account_number":"'+$account+'", "cloud_access_role_name":"'+$role+'"}'
	$CredentialURI="https://cloudtamer.cms.gov/api/v3/temporary-credentials/cloud-access-role"

	#retrieve short-term access keys from CloudTamer and assign them to appropriate variables
	$CredentialResponse=iwr -method POST -headers $headers -uri $CredentialURI -contentType "application/json" -body $CredentialBody
	$PSCreds=($CredentialResponse.Content|convertfrom-json).data
	
	return $PSCreds
}

function get-AWSFilter{
	#takes in the following parameters:
	#Compliance, a variable to select failed or passed compliance checks
	#WFStatus, a variable to select which workflow status combinations to include in the filter
	#Name, a variable to select which provider to query (Inspector, SecurityHub, etc.)
	#GID, an optional variable to select the unique rule that generated the finding
	param ($Compliance,$WFStatus,$ProdName,$GID,$Severity,$Type)

	#initialize the filter
	$Filter = new-object Amazon.SecurityHub.Model.AwsSecurityFindingFilters
	
	#for input parameters that are not null, set the values to feed into the appropriate filter parameters
		
	if($Compliance -ne $null){
		$Failed=new-object amazon.securityhub.model.stringfilter
		$Failed.Comparison="EQUALS"
		$Failed.Value="FAILED"
		
		$Passed=new-object amazon.securityhub.model.stringfilter
		$Passed.Comparison="EQUALS"
		$Passed.Value="PASSED"
		
		Switch($Compliance){
			"Failed" {$Filter.ComplianceStatus=$Failed}
			"Passed" {$Filter.ComplianceStatus=$Passed}
		}
	}
	if($WFStatus -ne $null){
		$New=new-object amazon.securityhub.model.stringfilter
		$New.Comparison="EQUALS"
		$New.Value="NEW"

		$Notified=new-object amazon.securityhub.model.stringfilter
		$Notified.Comparison="EQUALS"
		$Notified.Value="NOTIFIED"
		
		$Suppressed=new-object amazon.securityhub.model.stringfilter
		$Suppressed.Comparison="EQUALS"
		$Suppressed.Value="SUPPRESSED"
		
		$Resolved=new-object amazon.securityhub.model.stringfilter
		$Resolved.Comparison="EQUALS"
		$Resolved.Value="RESOLVED"
	
		Switch($WFStatus){
			"New"	{$Filter.workflowstatus=$New}
			"Notified"	{$Filter.WorkflowStatus=$Notified}
			"NewNotified"	{
				$Filter.workflowstatus=$New
				$Filter.WorkflowStatus+=$Notified
			}
			"Suppressed"	{$Filter.workflowstatus=$Suppressed}
			"Resolved"	{$Filter.workflowstatus=$Resolved}
			default		{
				$Filter.workflowstatus=$New
				$Filter.workflowstatus+=$Notified
				$Filter.workflowstatus+=$Resolved
				$Filter.workflowstatus+=$Suppressed
				
			}
		}
	}
	
	if($ProdName -ne $null){
		$ProductName=new-object amazon.securityhub.model.stringfilter
		$ProductName.Comparison="EQUALS"
		$ProductName.Value="$ProdName"
		$Filter.ProductName=$ProductName
	}

	if($GID -ne $null){
		$GeneratorID=new-object amazon.securityhub.model.stringfilter
		$GeneratorID.Comparison="PREFIX"
		$GeneratorID.Value="$GID"
		$Filter.GeneratorID=$GeneratorID
	}
	
	#If no severity label submitted, all severities will be added to the filter.  Otherwise, only specified severity levels will be added
	$Critical=new-object amazon.securityhub.model.stringfilter
	$Critical.Comparison="EQUALS"
	$Critical.Value="CRITICAL"
	
	$High=new-object amazon.securityhub.model.stringfilter
	$High.Comparison="EQUALS"
	$High.Value="HIGH"

	$Medium=new-object amazon.securityhub.model.stringfilter
	$Medium.Comparison="EQUALS"
	$Medium.Value="MEDIUM"
			
	$Low=new-object amazon.securityhub.model.stringfilter
	$Low.Comparison="EQUALS"
	$Low.Value="LOW"

	$Informational=new-object amazon.securityhub.model.stringfilter
	$Informational.Comparison="EQUALS"
	$Informational.Value="INFORMATIONAL"

	switch($Severity){
		"C" {$Filter.SeverityLabel=$Critical}
		"H" {$Filter.SeverityLabel=$High}
		"M" {$Filter.SeverityLabel=$Medium}
		"L" {$Filter.SeverityLabel=$Low}
		"I" {$Filter.SeverityLabel=$Informational}
		"HMLI" {
			$Filter.SeverityLabel=$High
			$Filter.SeverityLabel+=$Medium
			$Filter.SeverityLabel+=$Low
			$Filter.SeverityLabel+=$Informational
		}
		"CHML" {
			$Filter.SeverityLabel=$Critical
				$Filter.SeverityLabel+=$High
				$Filter.SeverityLabel+=$Medium
				$Filter.SeverityLabel+=$Low
		}
		Default {
				$Filter.SeverityLabel=$Critical
				$Filter.SeverityLabel+=$High
				$Filter.SeverityLabel+=$Medium
				$Filter.SeverityLabel+=$Low
				$Filter.SeverityLabel+=$Informational
		}
	}

	#Set the ProductFieldType (PFT) as Active or Compliance to differentiate between Vulnerability and Compliance Scan Findings.
	if($Type -ne $null){
		$PFTActive=new-object amazon.securityhub.model.mapfilter
		$PFTActive.Comparison="EQUALS"
		if($ProdName -eq "Nash Testing"){
			$PFTActive.Key="type"
		}else{
		$PFTActive.Key="Type"
		}
		$PFTActive.Value="active"
		
		$PFTCompliance=new-object amazon.securityhub.model.mapfilter
		$PFTCompliance.Comparison="EQUALS"
		$PFTCompliance.Key="Type"
		$PFTCompliance.Value="compliance"
		
		Switch($Type){
			"Vulnerability" {$Filter.ProductFields=$PFTActive}
			"Compliance" {$Filter.ProductFields=$PFTCompliance}
		}
	}
	
	$Active=new-object amazon.securityhub.model.stringfilter
	$Active.Comparison="EQUALS"
	$Active.Value="ACTIVE"
	$Filter.RecordState=$Active
	
	#Nash queries, add Archived record state to retrieve resolved findings.
	if($ProdName -eq "Nash Testing"){
	$Archived=new-object amazon.securityhub.model.stringfilter
	$Archived.Comparison="EQUALS"
	$Archived.Value="ARCHIVED"
	$Filter.RecordState+=$Archived
	}
	#Initializaton Section End
	
	Return $Filter
}

#6/16/22 Additional Function
function BatchUpdateSecHubFindings{
	#takes in the Array of findings,new Workflow Status and PSCreds object
	Param($Array,$WFStatus,$NoteText,$PSCreds,$EUAID)
	#Assign the individual keys/tokens to variables
	$AccessKey=$PSCreds.access_key
	$SecretKey=$PSCreds.secret_access_key
	$SessionToken=$PSCreds.session_token
	
	#Initializations
	$Batch=1
	$ArrayCount=$Array.count

	$TotalProcessed=0
	$TotalUnprocessed=0

	#Iterate through the entire array and update in batches of 100
	for($index=0;$index -lt $ArrayCount){
	$BatchUpdateRequest = new-object Amazon.SecurityHub.Model.BatchUpdateFindingsRequest
		for($counter=0;$counter -lt 100;$counter++){
			#ensure there's a value in the array at the current index, otherwise break out of current for loop.
			if($Array[$index] -ne $null){
			$FindingID = new-object Amazon.SecurityHub.Model.AwsSecurityFindingIdentifier
			write-progress -id 1 -activity "Index: " $index
			$FindingID.Id=$Array[$index].FindingId
			$FindingID.ProductArn=$Array[$index].ProdArn
			if($counter -eq 0){
				$BatchUpdateRequest.FindingIdentifiers=$FindingID
			}else{
				$BatchUpdateRequest.FindingIdentifiers+=$FindingId
			}
			$index++
			}else{
				write-host $index
				break
			}	
		}
		#invoke the batch update cmdlet to submit the current batch of findings to update.  
		$ProcessedFindings=Update-SHUBFindingsBatch -FindingIdentifiers $BatchUpdateRequest.FindingIdentifiers -Workflow_Status $WFStatus -Note_Text $NoteText -Note_UpdatedBy $EUAID -AccessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -region us-east-1
		$ProcessedCount=$ProcessedFindings.ProcessedFindings.count
		$UnprocessedCount=$ProcessedFindings.UnprocessedFindings.count
		#display progress status on screen with number of findings processed per batch
		write-progress -parentId 1 -activity "Batch Number $batch Processed: $ProcessedCount, Unprocessed: $UnprocessedCount."
		#start-sleep .5
		$batch++
		$TotalProcessed+=$ProcessedCount
		$TotalUnprocessed+=$UnprocessedCount
	}
	write-host "Processed: $TotalProcessed, Unprocessed: $TotalUnprocessed."
}

function ArrayBuilder{
	#takes in the Findings object (from Security Hub) and parses out details for analysis and processing
	#Findings - the findings object returned by the Security Hub query
	#product - the product generating the findings being retrieved, which will determine certain details for parsing (e.g. "Chef", "Inspector", "SecHub", "Config")
	param ($Findings,$product,$env,$PSCreds)
	
	#set short-term creds for later use if provided in args
	if($PSCreds -ne $null){
		$AccessKey=$PSCreds.access_key
		$SecretKey=$PSCreds.secret_access_key
		$SessionToken=$PSCreds.session_token
	}
	#set region based on $env variable passed in
	if($env -eq "PROD WEST"){$Region="US-WEST-2"}
	else{$Region="US-EAST-1"}
	
	#initialize product-specific varables/rules
	#Date format for converting FirstObserved, CreatedAt,UpdatedAt
	Switch($product){
		"tenable"	{
			$FODateFormat="yyyy-MM-ddTHH:mm:ss+00:00"
			$CADateFormat="yyyy-MM-ddTHH:mm:ss+00:00"
			$UADateFormat="yyyy-MM-ddTHH:mm:ss.ffffff+00:00"
		}
		"SecHub"	{
			$FODateFormat="yyyy-MM-ddTHH:mm:ss.fffZ"
			$CADateFormat="yyyy-MM-ddTHH:mm:ss.fffZ"
			$UADateFormat="yyyy-MM-ddTHH:mm:ss.fffZ"
		}
		"Nash Testing"	{
			$FODateFormat="yyyy-MM-ddTHH:mm:ss.fffZ"
			$CADateFormat="yyyy-MM-ddTHH:mm:ss.fffZ"
			$UADateFormat="yyyy-MM-ddTHH:mm:ss.fff+00:00"
		}
		"Chef"	{
			$FODateFormat="yyyy-MM-ddTHH:mm:ss.ffffff+00:00"
			$CADateFormat="yyyy-MM-ddTHH:mm:ss.ffffff+00:00"
			$UADateFormat="yyyy-MM-ddTHH:mm:ss.ffffff+00:00"			
		}
		"Inspector"	{
			#$FODateFormat="yyyy-MM-ddTHH:mm:ss.fffZ"
			$CADateFormat="yyyy-MM-ddTHH:mm:ss.ffffff+00:00"
			$UADateFormat="yyyy-MM-ddTHH:mm:ss.ffffff+00:00"
		}
		default	{
			$FODateFormat="yyyy-MM-ddTHH:mm:ss.fffZ"
			$CADateFormat="yyyy-MM-ddTHH:mm:ss+00:00"
			$UADateFormat="yyyy-MM-ddTHH:mm:ss.ffffff+00:00"			
		}
	}
	
	#Sort the findings by UpdatedAt before piping to the Array builder
	$Findings=$Findings | sort-object UpdatedAt -descending
	
	#Remove findings where the FindingId contains IP address followed by //.  These are findings attributed to the load balancers and are duplicates of findings against certain instances.
	$Findings=$Findings | ?{$_.Id -notlike "*//*"}

	#initialize the Array for ingestion of finding details
	$Array=@()
	
	#Parse out relevant items from the Findings...
	$Findings | %{
		#Step 1 - parse out elements from the Findings object
		$CCType=$_.ProductFields.'aws/config/ConfigComplianceType'
		$CVE=$_.Vulnerabilities.Id
		if($_.Resources.Tags.name -eq $null){
			$Hostname="Unknown"
		}else{
			$Hostname=$_.Resources.Tags.name
		}
		
		$Note=$_.Note.Text
		$Jira=$_.UserDefinedFields.Jira
		#convert FirstObservedAt timestamp, except for Inspector which doesn't include that field.
		if($product -eq "Inspector"){
			$FirstObserved=""			
		}else{
			$FirstObserved=[datetime]::parseexact($_.FirstObservedAt, $FODateFormat,$null).toshortdatestring()
		}
		#Convert CreatedAt and UpdatedAt timestamps
		$CreatedAtShort=[datetime]::parseexact($_.CreatedAt, $CADateFormat,$null).toshortdatestring()
		$CreatedAtLong=[datetime]::parseexact($_.CreatedAt, $CADateFormat,$null)
		$UpdatedAtShort=[datetime]::parseexact($_.UpdatedAt, $UADateFormat,$null).toshortdatestring()
		$UpdatedAtLong=[datetime]::parseexact($_.UpdatedAt, $UADateFormat,$null)
		$FindingID=$_.Id
		$ProdArn=$_.ProductArn
		$Compliance=$_.compliance.status.value

		$Severity=$_.Severity.Label
		#due date calculation based on date first observed or created and severity rating:
		switch($Severity){
			"CRITICAL" {$SLA=15}
			"HIGH" {$SLA=30}
			"MEDIUM" {$SLA=90}
			"LOW" {$SLA=365}
			default {$SLA=0}
		}
		switch($product){
			"SecHub" {$DueDate=(([DateTime]($FirstObserved)).adddays($SLA)).toShortDateString()}
			
			"tenable" {$DueDate=(([DateTime]($FirstObserved)).adddays($SLA)).toShortDateString()}
			
			"Nash Testing" {$DueDate=(([DateTime]($FirstObserved)).adddays($SLA)).toShortDateString()}
			
			default {$DueDate=(([DateTime]($CreatedAtShort)).adddays($SLA)).toShortDateString()}
		}
		$Description=$_.Description
		$FixText=$_.Remediation.Recommendation.text
		
		if($product -eq "Inspector"){
			$FixText=$_.Remediation.Recommendation.text
			if($FixText.indexof("For more") -lt 0){
				$FixText=$FixText
			}else{
				#If the recommendation contains a "For more" section, only parse out the content before that.
				$FixText=$FixText.Substring(0,($FixText.indexof("For more")))
			}
		}
		
		#ProductFields.plugin_output is being added as Nash pulls the latest plugin output into this field.
		if($product -eq "Nash Testing"){
			$PluginOutput=$_.ProductFields.plugin_output
			#cleanup the text for import to excel
			$PluginOutput=$PluginOutput -replace "`n","; " -replace "`r","; "
		}
		
		$FixURL=$_.Remediation.Recommendation.Url
				
		#Clean up the Description text and the Remediation text to remove carriage return and new line occurrences, as those interfere with Excel importing
		$Description=$Description -replace "`n","; " -replace "`r","; "
		$FixText=$FixText -replace "`n","; " -replace "`r","; "
		#Note: SecHub Findings and Inspector scripts need to be updated - change $InstanceId to $ResourceId for consistency
		$ResourceId=$_.Resources.Id
		$Title=$_.Title
		
		#For Security Hub findings, depending on the resource type, retrive the name tag for the resource to facilitate remediation efforts.
		if(($product -eq "SecHub") -or ($product -eq "tenable") -or ($product -eq "Security Hub")){
			$ResourceType=$_.Resources.Type
			switch -wildcard ($ResourceType){
				"AwsCloudFrontDistribution" {
					$CFTags=get-CFResourceTag -resource $ResourceId -accessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Region $Region
					$ResourceName=$CFTags.Items | ?{$_.Key -eq "Name"} | %{$_.Value}
				}
				"AwsLambdaFunction" {
					$ResourceName=$ResourceId.Split(":")[6]
					$ResourceName=Get-LambdaFunction -accessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Region $Region -filter @{name="resource-id";Values=$ResId} | ?{$_.Key -eq "Name"}|%{$_.Value}
				}
				"AwsEksCluster" {
					$ResourceName=$ResourceId.Split(":")[5].Split("/")[1]
					$ResourceName=Get-EKSCluster -accessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Region $Region -filter @{name="resource-id";Values=$ResId} | ?{$_.Key -eq "Name"}|%{$_.Value}
				}
				"AwsSnsTopic" {
					$ResourceName=$ResourceId.Split(":")[5]
				}
				"AwsS3Bucket" {
					$ResourceName=$ResourceId.Split(":")[5]
				}
				"AwsEC2*" {
					$ResId=($ResourceId.Split(":")[5]).Split("/")[1]
					$ResourceName=Get-EC2Tag -accessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Region $Region -filter @{name="resource-id";Values=$ResId} | ?{$_.Key -eq "Name"}|%{$_.Value}
				}
				"AwsRds*" {
					$ResourceName=$ResourceId.Split(":")[6]
				}
				"AwsEfsFileSystem" {
					$ResId=($ResourceId.Split(":")[5]).Split("/")[1]
					$ResourceName=(Get-EFSFileSystem -accessKey $AccessKey -SecretKey $SecretKey -SessionToken $SessionToken -Region $Region -FileSystemId $ResId).Tags | ?{$_.Key -eq "Name"}|%{$_.Value}
				}	
				default {
					$ResourceName="Unknown"
				}
			}
		}
		

		#Step 2 - create a row of data for each Finding
		$obj=New-Object psobject -Property @{
			"CCType"=$CCType;
			"CVE"=$CVE;
			"Hostname" = $Hostname;
			"ResourceName"=$ResourceName;
			"HostVuln"=$Hostname+$CVE;
			#vulnstat is placeholder for analysis processing
			"VulnStat"="";
			"Environment"=$env;
			"Note"=$Note;
			"Jira"=$Jira;
			"First_Observed" = $FirstObserved;
			"FindingId"=$FindingID;
			"ProdArn"=$ProdArn;
			"Compliance"=$Compliance;
			"CreatedAtShort"=$CreatedAtShort;
			"CreatedAtLong"=$CreatedAtLong;
			"UpdatedAtShort"=$UpdatedAtShort;
			"UpdatedAtLong"=$UpdatedAtLong;
			"Severity"=$Severity;
			"DueDate" = $DueDate;
			"Description"=$Description;
			"Remediation"=$FixText;
			"FixURL"=$FixURL;
			"ResourceId"=$ResourceId;
			"Title"=$Title;
			"PluginOutput"=$PluginOutput
		}

		#Step 3 - add row of data to the Array based on the finding type...
		switch($product){
			"Config"	{$Array+= $obj | select ResourceId,CreatedAtShort,CreatedAtLong,UpdatedAtShort,UpdatedAtLong,Severity,Compliance,CCType,Description,DueDate,FindingId,ProdArn,Title}
			"Inspector"	{$Array+= $obj | select FindingID,ProdArn,Hostname,CVE,HostVuln,CreatedAtShort,CreatedAtLong,UpdatedAtShort,UpdatedAtLong,VulnStat,DueDate,Severity,ResourceId,Description,Remediation}
			"Chef"	{$Array+= $obj | select Environment,ResourceId,CreatedAtShort,CreatedAtLong,UpdatedAtShort,UpdatedAtLong,Severity,Compliance,Description,DueDate,FindingId,ProdArn,Title}
			"SecHub"	{$Array+= $obj | select Environment,Jira,ResourceName,Title,Severity,First_Observed,ResourceId,DueDate,Note}
			"tenable"	{$Array+= $obj | select Environment,Jira,ResourceName,Title,Severity,First_Observed,UpdatedAtShort,DueDate,ResourceId,Description,Remediation,FixURL,Note,FindingId,ProdArn
			}
			"Nash Testing"	{$Array+= $obj | select Environment,Jira,Hostname,Title,Severity,Compliance,First_Observed,UpdatedAtShort,DueDate,ResourceId,Description,Remediation,FixURL,Note,PluginOutput,FindingId,ProdArn
			}			
			default	{}
		}
	}
	Return $Array
}