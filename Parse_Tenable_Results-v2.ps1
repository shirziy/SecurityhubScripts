<#
.SYNOPSIS
    Parses the Tenable/Nesssu results exported from Splunk (from special search parameters) into a tab-delimited file that can be imported into Excel for review and analysis.
.DESCRIPTION
    Parses the Tenable Nesssu results exported from Splunk into a tab-delimited file that can be imported into Excel for review and analysis.
.PARAMETER filename
    The name of the exported report from Splunk, which has been saved to the c:\temp directory...
.EXAMPLE
    C:\PS> 
    <Description of example>
.NOTES
    Author: Brian Edwards
    Date:   November 9, 2022
	
	11/21/22 - version 2 update:  added OpenFileDialog to select the .csv file that was exported from Splunk
#>

#Function to launch OpenFileDialog to select the file that was exported from Splunk for parsing...
Function Get-File(){
	Add-Type -AssemblyName System.Windows.Forms
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
		InitialDirectory="c:\temp\"
		Filter='SplunkExport (*.csv)|*.csv'
	}
	$null = $FileBrowser.ShowDialog()
	if ($FileBrowser.CheckPathExists -eq "True"){
		return $FileBrowser.FileName
	}else{
		break
	}  
}

$path=get-file
$ts=get-date -Format "yyyyMMdd"
$fn='C:\temp\Nessus_Results-'+$filename+$ts+'.csv'
$NessusResults=import-csv -path $path
$Array=@()
$NessusResults | %{
	$time=$_._time
	$account=$_.AwsAccountID
	switch($account){
		"094310297205" {$env="APS PROD"}
		"508300490120" {$env="APS IMPL"}
		"962822876314" {$env="APS MGMT"}
		"203649618876" {$env="APS TEST"}
		"858087243182" {$env="APS IAT"}
		"443841623847" {$env="APS DEV"}
		"880459142958" {$env="UCM DEV"}
		"701061157464" {$env="UCM DM"}
		"678153623622" {$env="UCM IMPL"}
		"137850127813" {$env="UCM MNGT"}
		"023478216046" {$env="UCM PERF"}
		"135042808539" {$env="UCM TEST"}
		"056917353687" {$env="UCM PROD"}
		"655713441757" {$env="UCM TRNG"}
		"356237190563" {$env="UCM POC"}
		"608973273400" {$env="UCM DR"}
		"145001547331" {$env="UCM UAT"}
		"336110063492" {$env="UCM MNT"}
		default {$env="Unknown"}
	}
	#$PluginID=$_.pluginID
	#$PluginName=$_.pluginName
	$PluginText=$_.pluginText -replace "`n","; " -replace "`r","; " -replace ",",";"
	$Severity=$_."severity.name"
	#Compliance conversion from Nessus splunk "severity" values
	switch($Severity){
		"High" {$Compliance="FAILED"}
		"Medium" {$Compliance="WARNING"}
		"Info" {$Compliance="PASSED"}
		default {$Compliance="UNKNOWN"}
	}
	$DNSName=$_.dnsName
	$InstanceID=$_.InstanceID
	$OS=$_.operatingSystem
	$pluginInfo=$_.pluginInfo
	$description=$_.description -replace "`n","; " -replace "`r","; " -replace ",",";"
	#create a row of data for each Finding
	$obj=New-Object psobject -Property @{
		"Time"=$time;
		"Environment"=$env;
		#"PluginID" = $PluginID;
		#"PluginName" = $PluginName;
		"PluginText" = $PluginText;
		"Severity"=$Severity;
		"Compliance"=$Compliance;
		"InstanceID"=$InstanceID;
		"OS"=$OS;
		"pluginInfo"=$pluginInfo;
		"description"=$description;
		"DNSName"=$DNSName
	}
	#add row of data to the Array...
	$Array+= $obj | select Time,Environment,Severity,DNSName,InstanceID,OS,pluginInfo,description,PluginText,Compliance
}

#Export the Parsed results to a file for import to Excel
$Array | export-csv -delimiter "`t" -Path $fn -NoTypeInformation

write-host "Parsing complete - report can be imported to Excel from $fn"