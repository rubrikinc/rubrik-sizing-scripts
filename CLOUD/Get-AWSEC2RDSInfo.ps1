#requires -modules AWSPowerShell.NetCore

# https://build.rubrik.com

<#
.SYNOPSIS
Gets all EC2 instances and RDS instances with the # of attached volumes and provisioned sizes.

.DESCRIPTION
The 'Get-AWSEC2RDSInfo.ps1' script gets all EC2 instance and RDS info in the specified region(s).
For each EC2 instance it grabs the total number of volumes and total size for all volumes.
For each RDS instance it grabs the total provisioned size.
A summary of the total # of instances, # of volumes, RDS instance, and capacity will be output to console.

A CSV file will be exported with the details.
You should copy/paste the console output to send along with the CSV.

This script requires the AWSPowerShell.NetCore PowerShell module. Install the module prior to running this
script by running:

"Install-Module AWSPowerShell.NetCore"

Run in AWS CloudShell or use 'Set-AWSCredential' to set the AWS credentials to run with.
See: https://docs.aws.amazon.com/powershell/latest/userguide/pstools-getting-started.html

This script uses AWS's stored Profiles to collect data from multiple AWS accounts. More information
about how to store multiple credentials in the AWS PowerShell tools can be found in AWS' documentation.
see: https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html

Use the -AccountProfile name parameter to limit what accounts the script collects data from. Otherwise
the script will collect data from every profile in the current users's configuration.

Use the -Regions parameter to limit what regions that the script collects data from. Otherwise it will
collect data from all regions that are enabled for the specified AWS account.

For reference here are some common AWS region identifier based on geo:

United States: 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
US Top Secret ISO: 'us-iso-east-1', 'us-isob-east-1'
Europe:  'eu-central-1', 'eu-north-1', 'eu-south-1', 'eu-west-1', 'eu-west-2', 'eu-west-3'
Asia Pacific: 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2'
Canada: 'ca-central-1' 
Middle East: 'me-south-1'
South America: 'sa-east-1'

This script can work with other AWS partitions such as AWS GovCLoud. Use the -Partition parameter to select a different partition. 
Otherwise the script will use the standard commercial partition for AWS. 

.NOTES
Written by Steven Tong for community usage
GitHub: stevenctong
Date: 11/8/21
Updated: 2/24/21
Updated: 10/20/22

.PARAMETER Regions
A comma separated list of AWS regions in which to gather data. If omitted, all regions will be queried. 

.PARAMETER Partition
The AWS partition other than the standard commercial partition to query. Currently only the GovCloud partition has
been tested and supported. 

.PARAMETER ProfileAccounts
A comma separated list of AWS Account Profiles stored on the local system to query. If omitted and -AllProfileAccounts is
not specified, only the current (default) account will be queried. 

.PARAMETER AllProfileAccounts
When set all AWS accounts found in the local profiles will be queried. 

.PARAMETER CurrentProfileAccount
When set only the current (default) profile will be used to query it's AWS account. This behavior also takes place if
-AllProfileAccounts and -ProfileAccounts are not set. 

.EXAMPLE
./Get-AWSEC2RDSInfo.ps1
Runs the script to get all EC2 and RDS instance info and output to a CSV file. Uses the current 
AWS account profile and searches all regions.

.EXAMPLE
./Get-AWSEC2RDSInfo.ps1 -AllProfileAccounts
Runs the script to get all EC2 and RDS instance info and output to a CSV file. Uses all of the  
AWS account profiles in the user environment. 

.EXAMPLE
./Get-AWSEC2RDSInfo.ps1 -AccountProfiles "aws_account_profile1,aws_account_profile2" -Regions "us-west-1,us-west-2"
Runs the script to get all EC2 and RDS instance info and output to a CSV file. Uses the selected 
account profiles "aws_account_profile1" and "aws_account_profile2" and limits the query to the "us-west-1" and 
"us-west-2" regions. 

.EXAMPLE
./Get-AWSEC2RDSInfo.ps1 -AccountProfiles aws_gov_cloud_account_profile -Regions us-gov-east-1 -Partition GovCloud
Runs the script to get all EC2 and RDS instance info and output to a CSV file. Uses the selected 
account profiles "aws_gov_account_profile", limits the query to the "us-gov-east-1" region and 
queries the AWS GovCloud partition. 


#>

param (
  [CmdletBinding(DefaultParameterSetName = 'CurrentAccount')]

  # Limit search for data to specific regions.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$Regions = '',
  # Get data from AWS GovCloud region.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [ValidateSet("GovCloud","")]
  [string]$Partition = '',
  # Choose to get info for only specific AWS accounts
  [Parameter(ParameterSetName='UserAccounts',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$ProfileAccounts = '',
  # Choose to get info for all detected AWS accounts.
  [Parameter(ParameterSetName='AllSubscriptions',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [switch]$AllProfileAccounts,
  # Choose to get info for only the current profile account (default option.)
  [Parameter(ParameterSetName='CurrentAccount',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$CurrentProfileAccount
)

# Set default regions for queries
$defaultQueryRegion = "us-east-1"
$defaultGovCloudQueryRegion = "us-gov-east-1"

$date = Get-Date

Write-Host "Importing AWS Powershell module" -foregroundcolor green
Import-Module AWSPowerShell.NetCore

# Filenames of the CSVs output
$outputEc2Disk = "aws_vol_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputRDS = "aws_rds_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"


# Contains list of EC2 instances and RDS with capacity info
$ec2list = @()
$rdsList = @()

if ($AllProfileAccounts -eq $true) {
  $profiles = $(Get-AWSCredential -ListProfileDetail).ProfileName
}
elseif ($ProfileAccounts -eq '') {
  $profiles = "rk_current_profile_account"
}
else {
  [string[]]$profiles = $ProfileAccounts.split(',')
}

if ($Partition -eq 'GovCloud') {
  $queryRegion = $defaultGovCloudQueryRegion
}
else {
  $queryRegion = $defaultQueryRegion
}

foreach ($profile in $profiles) {
  if ($profile -ne "rk_current_profile_account") {
    Set-AWSCredential -ProfileName $profile
  }

  # Set the regions that you want to get EC2 instance and volume details for
  if ($Regions -ne "") {
    [string[]]$awsRegions = $Regions.split(',')
  }
  else {
    $awsRegions = @()
    # This adds all enabled regions to the list
    if ($profile -ne "rk_current_profile_account") {
      Write-Debug "Profile name is $profile and queryRegion name is $queryRegion"
      foreach ($ec2region in Get-EC2Region -Region $queryRegion -ProfileName $profile) {
        $awsRegions += $ec2region.RegionName
      }
    }
    else {
      foreach ($ec2region in Get-EC2Region -Region $queryRegion) {
        $awsRegions += $ec2region.RegionName
      } 
    }
  }

  
  Write-Host "Current identity:" -foregroundcolor green
  if ($profile -ne "rk_current_profile_account") {
    Write-Debug "Profile name is $profile and queryRegion name is $queryRegion"
    $awsaccountinfo = Get-STSCallerIdentity  -ProfileName $profile -Region $queryRegion
  }
  else {
    $awsaccountinfo = Get-STSCallerIdentity
  }
  $awsaccountinfo | format-table

  # For all specified regions get the EC2 instance and RDS info
  foreach ($awsRegion in $awsRegions) {
    Write-Host "Getting EC2 instance info for region: $awsRegion" -foregroundcolor green
    $ec2instances = (Get-EC2Instance -region $awsRegion).instances

    foreach ($ec2 in $ec2instances) {
      $volSize = 0
      # Contains list of attached volumes to the current EC2 instance
      $volumes = $ec2.BlockDeviceMappings.ebs

      # Iterate through each volume and sum up the volume size
      foreach ($vol in $volumes) {
        $volSize += (Get-EC2Volume -VolumeId $vol.VolumeId -region $awsRegion).size
      }

      $ec2obj = [PSCustomObject] @{
        "AwsAccountId" = $awsaccountinfo.Account
        "InstanceId" = $ec2.InstanceId
        "Name" = $ec2.tags.name
        "Volumes" = $volumes.count
        "SizeGiB" = $volSize
        "SizeGB" = [math]::round($($volSize * 1.073741824), 3)
        "Region" = $awsRegion
        "InstanceType" = $ec2.InstanceType
        "Platform" = $ec2.Platform
      }

      $ec2list += $ec2obj
    }

    Write-Host "Getting RDS info for region: $awsRegion" -foregroundcolor green
    $rdsDBs = Get-RDSDBInstance -region $awsRegion

    foreach ($rds in $rdsDBs) {
      $rdsObj = [PSCustomObject] @{
        "AwsAccountId" = $awsaccountinfo.Account
        "RDSInstance" = $rds.DBInstanceIdentifier
        "SizeGiB" = $rds.AllocatedStorage
        "SizeGB" = [math]::round($($rds.AllocatedStorage * 1.073741824), 3)
        "RDSInstanceARN" = $rds.DBInstanceArn
        "Region" = $awsRegion
        "InstanceType" = $rds.DBInstanceClass
        "Platform" = $rds.Engine
      }

      $rdsList += $rdsObj
    }
  }
}
$ec2TotalGiB = ($ec2list.sizeGiB | Measure-Object -Sum).sum
$ec2TotalGB = ($ec2list.sizeGB | Measure-Object -Sum).sum

$rdsTotalGiB = ($rdsList.sizeGiB | Measure-Object -Sum).sum
$rdsTotalGB = ($rdsList.sizeGB | Measure-Object -Sum).sum

Write-Host
Write-Host "Total # of EC2 instances: $($ec2list.count)" -foregroundcolor green
Write-Host "Total # of volumes: $(($ec2list.volumes | Measure-Object -Sum).sum)" -foregroundcolor green
Write-Host "Total capacity of all volumes: $ec2TotalGiB GiB or $ec2TotalGB GB" -foregroundcolor green

Write-Host
#  Write-Host "Total # of RDS instances: $(($rdsList.Database -ne '').count)" -foregroundcolor green
Write-Host "Total # of RDS instances: $($rdsList.count)" -foregroundcolor green
Write-Host "Total provisioned capacity of all RDS instances: $rdsTotalGiB GiB or $rdsTotalGB GB" -foregroundcolor green


# Export to CSV
Write-Host ""
Write-Host "CSV file output to: $outputRDS" -foregroundcolor green
$rdsList | Export-CSV -path $outputRDS
Write-Host "CSV file output to: $outputEc2Disk" -foregroundcolor green
$ec2List | Export-CSV -path $outputEc2Disk
