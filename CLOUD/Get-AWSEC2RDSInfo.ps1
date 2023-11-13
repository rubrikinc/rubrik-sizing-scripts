#requires -Version 7.0
#requires -Modules AWS.Tools.Common, AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.RDS, AWS.Tools.SecurityToken, AWS.Tools.Organizations, AWS.Tools.IdentityManagement, AWS.Tools.CloudWatch

# https://build.rubrik.com

<#
  .SYNOPSIS
    Gets all EC2 instances and RDS instances with the # of attached volumes and provisioned sizes.

  .DESCRIPTION
    The 'Get-AWSEC2RDSInfo.ps1' script gets all EC2 instances, EC2 unattached volumes and RDS databases
    in the specified region(s). For each EC2 instance it grabs the total number of volumes and total 
    size for all volumes. For each EC2 unattached volume it grabs the size of the volume, ID and type.
    For each RDS instance it grabs the provisioned size, name, and type of database.
    A summary of the total # of instances, # of attached volumes, #  of unattached volumes, RDS instances, 
    and capacity will be output to console.

    A set of CSV files will be exported with the details. When sending the data from this script data back
    to Rubrik, copy/paste the console output along with attaching the CSV files.

    Installation/Setup:

    This script is designed to run either from a system with Powershell or from AWS CloudShell. When 
    running this script from AWS CloudShell, after opening the AWS CloudShell, run "pwsh" to start 
    PowerShell.  All needed Powershell modules are pre-installed in the AWS Cloud shell, so no
    additional steps are required. 

    If this script will be run from a system with PowerShell, it requires several Powershell Modules. 
    Install these modules prior to running this script locally by issuing the commands:

    Install-Module AWS.Tools.Common,AWS.Tools.EC2,AWS.Tools.S3,AWS.Tools.RDS,AWS.Tools.SecurityToken,AWS.Tools.Organizations,AWS.Tools.IdentityManagement,AWS.Tools.CloudWatch

    For both cases the source/default AWS credentials that the script will use to query AWS can be set 
    by using  using the 'Set-AWSCredential' command. For the AWS CloudShell this usually won't be required
    as the credentials that were used to login to the AWS console are the same as what the script will use.
    See: https://docs.aws.amazon.com/powershell/latest/userguide/pstools-getting-started.html

    This script also can use AWS's stored Profiles to collect data from multiple AWS accounts. More information
    about how to store multiple credentials in the AWS PowerShell tools can be found in AWS' documentation.
    see: https://docs.aws.amazon.com/powershell/latest/userguide/specifying-your-aws-credentials.html

    The following permissions policy is needed on the IAM entity that is being used to query each account.
    This includes any cross account roles that are used to query multiple accounts:

    {
      "Version": "2012-10-17",
      "Statement": [
          {
              "Sid": "VisualEditor0",
              "Effect": "Allow",
              "Action": [
                  "sts:AssumeRole",
                  "organizations:ListAccounts",
                  "ec2:DescribeInstances",
                  "ec2:DescribeVolumes",
                  "rds:DescribeDBInstances",
                  "iam:ListAccountAliases"
              ],
              "Resource": "*"
          }
      ]
    }

  .NOTES
    Written by Steven Tong for community usage
    GitHub: stevenctong
    Date: 11/8/21
    Updated: 2/24/21
    Updated: 10/20/22
    Updated: 5/5/2023

  .PARAMETER Regions
    A comma separated list of AWS regions in which to gather data. If omitted, all regions will be queried. The list of regions
    must be surrounded by quotes. Ex. -Regions "us-west-1,us-west-2".

    For reference here are some common AWS region identifier based on geo:

    United States: 'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2'
    US Top Secret ISO: 'us-iso-east-1', 'us-isob-east-1'
    Europe:  'eu-central-1', 'eu-north-1', 'eu-south-1', 'eu-west-1', 'eu-west-2', 'eu-west-3'
    Asia Pacific: 'ap-east-1', 'ap-northeast-1', 'ap-northeast-2', 'ap-northeast-3', 'ap-south-1', 'ap-southeast-1', 'ap-southeast-2'
    Canada: 'ca-central-1' 
    Middle East: 'me-south-1'
    South America: 'sa-east-1'

  .PARAMETER Partition
    The AWS partition other than the standard commercial partition to query. Currently the only non-commercial partition to be 
    tested ahs been the GovCloud partition. 

  .PARAMETER DefaultProfile
    Collect data from the account the account listed in the 'default' profile or what ever credentials were specified when
    running the 'Set-AWSCredential' command.

  .PARAMETER UserSpecifiedProfileNames
    A comma separated list of AWS Account Profiles stored on the local system to query. The list must be encased in quotes.

  .PARAMETER AllLocalProfiles
    When set all AWS accounts found in the local profiles will be queried. 

  .PARAMETER OrgCrossAccountRoleName
    When set the AWS Organization that the default account or account specified by 'Set-AWSCredential' will be queried to find all
    of the accounts in the organization. This script will then query all of the accounts that were found using the AWS cross
    account role that is specified.

  .PARAMETER UserSpecifiedAccounts
    A comma separated list of AWS account numbers to query. The list must be enclosed in quotes. 

  .EXAMPLE  
    >>>

    Run the script in AWS CloudShell to get all EC2 and RDS instance info and output to a CSV file. Uses the current 
    AWS account profile and searches all regions.

    [cloudshell-user@ip ~]$ pwsh
    PowerShell 7.3.3

    A new PowerShell stable release is available: v7.3.4 
    Upgrade now, or check out the release page at:       
      https://aka.ms/PowerShell-Release?tag=v7.3.4       

    PS /home/cloudshell-user> ./Get-AWSEC2RDSInfo.ps1        

  .EXAMPLE
    >>>

    Run the script in Powershell to get all EC2 and RDS instance info and output to a CSV file. Uses the  
    AWS account specified by and searches all regions.

    PS > Set-AWSCredential -ProfileName MyAwsProfile
    PS > ./Get-AWSEC2RDSInfo.ps1        

  .EXAMPLE
    >>>
    
    Run the script in PowerShell to get all EC2 and RDS instance info and output to a CSV file. Use the selected 
    account profiles "aws_account_profile1" and "aws_account_profile2". Limit the query to the "us-west-1" and 
    "us-west-2" regions. 

    PS > ./Get-AWSEC2RDSInfo.ps1 -UserSpecifiedProfileNames "aws_account_profile1,aws_account_profile2" -Regions "us-west-1,us-west-2"

  .EXAMPLE
    >>>
    
    Run the script in Powershell to get all EC2 and RDS instance info and output to a CSV file. Uses all of the  
    AWS account profiles in the user environment. Limits the query to the "us-gov-east-1" region and 
    queries the AWS GovCloud partition.

    PS> ./Get-AWSEC2RDSInfo.ps1 -AllLocalProfiles -Regions us-gov-east-1 -Partition GovCloud

  .EXAMPLE
    >>>

    Run the script in PowerShell to get all EC2 and RDS instance info and output to a CSV file. Query the AWS Organization
    for a list of accounts and search all found accounts. 

    PS > Set-AWSCredential -ProfileName MyAwsSourceOrgProfile
    PS > ./Get-AWSEC2RDSInfo.ps1 -OrgCrossAccountRoleName OrganizationAccountAccessRole

.EXAMPLE
    >>>

    Run the script in AWS CloudShell to get all EC2 and RDS instance info and output to a CSV file. Query a 
    user provided list of AWS accounts.

    [cloudshell-user@ip ~]$ pwsh
    PowerShell 7.3.3

    A new PowerShell stable release is available: v7.3.4 
    Upgrade now, or check out the release page at:       
      https://aka.ms/PowerShell-Release?tag=v7.3.4       

    PS /home/cloudshell-user> ./Get-AWSEC2RDSInfo.ps1  -UserSpecifiedAccounts "123456789012,098765432109,123456098765" -CrossAccountRoleName MyCrossAccountRole

#>

param (
  [CmdletBinding(DefaultParameterSetName = 'DefaultProfile')]

  # Limit search for data to specific regions.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$Regions,
  # Get data from AWS GovCloud region.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [ValidateSet("GovCloud","")]
  [string]$Partition,
  # Choose to get info for only the default profile account (default option).
  [Parameter(ParameterSetName='DefaultProfile',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$DefaultProfile,
  # Choose to get info for only specific AWS accounts based on user supplied list of profiles
  [Parameter(ParameterSetName='UserSpecifiedProfiles',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$UserSpecifiedProfileNames,
  # Choose to get info for all detected AWS accounts in locally defined profiles.
  [Parameter(ParameterSetName='AllLocalProfiles',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [switch]$AllLocalProfiles,
  # Get info from all accounts in an AWS Organization
  [Parameter(ParameterSetName='AWSOrganization',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$OrgCrossAccountRoleName = "OrganizationAccountAccessRole",
  [Parameter(ParameterSetName='UserSpecifiedAccounts',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$CrossAccountRoleName,
  # Get info from a comma separated list of user supplied accounts
  [Parameter(ParameterSetName='UserSpecifiedAccounts',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$UserSpecifiedAccounts
)

# Print Powershell Version
Write-Debug $PSVersionTable | Format-List

# Set default regions for queries
$defaultQueryRegion = "us-east-1"
$defaultGovCloudQueryRegion = "us-gov-east-1"

$date = Get-Date
$utcEndTime = $date.ToUniversalTime()
$utcStartTime = $utcEndTime.AddDays(-7)

# Filenames of the CSVs output
$outputEc2Instance = "aws_ec2_instance_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputEc2UnattachedVolume = "aws_ec2_unattached_volume_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputRDS = "aws_rds_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"
$outputS3 = "aws_s3_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"

# Function to do the work

function getAWSData($cred) {
  # Set the regions that you want to get EC2 instance and volume details for
  if ($Regions -ne '') {
    [string[]]$awsRegions = $Regions.split(',')
  }
  else {
    $awsRegions = @()
    # This adds all enabled regions to the list
    Write-Debug "Profile name is $awsProfile and queryRegion name is $queryRegion"
    foreach ($ec2region in Get-EC2Region -Region $queryRegion -Credential $cred) {
      $awsRegions += $ec2region.RegionName
    }
  }

  
  Write-Host "Current identity:"  -ForegroundColor Green
  Write-Debug "Profile name is $awsProfile and queryRegion name is $queryRegion"
  $awsAccountInfo = Get-STSCallerIdentity  -Credential $cred -Region $queryRegion
  $awsAccountInfo | format-table
  $awsAccountAlias = Get-IAMAccountAlias -Credential $cred -Region $queryRegion

  # For all specified regions get the S3 bucket, EC2 instance, EC2 Unattached disk and RDS info
  foreach ($awsRegion in $awsRegions) {
    Write-Host "Getting S3 bucket information for region $awsRegion."  -ForegroundColor Green
    $cwBucketInfo = Get-CWmetriclist -namespace AWS/S3 -Region $awsRegion -Credential $cred
    $s3Buckets = $($cwBucketInfo | Select-Object -ExpandProperty Dimensions | Where-Object -Property Name -eq "BucketName" | select-object -Property Value -Unique).value
    Write-Host "Found" $s3Buckets.Count "S3 bucket(s)."  -ForegroundColor Green
    $counter = 0
    foreach ($s3Bucket in $s3Buckets) {
      $counter++
      Write-Progress -Activity 'Processing bucket:' -Status $s3Bucket -PercentComplete (($counter / $s3Buckets.Count) * 100)
      $filter = [Amazon.CloudWatch.Model.DimensionFilter]::new() 
      $filter.Name = 'BucketName'
      $filter.Value = $s3Bucket
      $bytesStorageTypes = $(Get-CWmetriclist -Dimension $filter -Credential $cred -Region $awsRegion | Where-Object -Property MetricName -eq 'BucketSizeBytes' `
                        | Select-Object -ExpandProperty Dimensions | where-object -Property Name -eq StorageType).Value  
      $numObjStorageTypes = $(Get-CWmetriclist -Dimension $filter -Credential $cred -Region $awsRegion | Where-Object -Property MetricName -eq 'NumberOfObjects' `
                        | Select-Object -ExpandProperty Dimensions | where-object -Property Name -eq StorageType).Value  
      $bucketNameDim = [Amazon.CloudWatch.Model.Dimension]::new()
      $bucketNameDim.Name = "BucketName"
      $bucketNameDim.Value = $s3Bucket
      $bytesStorages = @{}
      foreach ($bytesStorageType in $bytesStorageTypes) {
        $bucketBytesStorageDim = [Amazon.CloudWatch.Model.Dimension]::new()
        $bucketBytesStorageDim.Name = "StorageType"
        $bucketBytesStorageDim.Value = $bytesStorageType
        $maxBucketSizes = $(Get-CWMetricStatistic  -Statistic Maximum `
                          -Namespace AWS/S3 -MetricName BucketSizeBytes `
                          -UtcStartTime $utcStartTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -UtcEndTime $utcEndTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -Period 86400  `
                          -Credential $cred -Region $awsRegion `
                          -Dimension $bucketNameDim, $bucketBytesStorageDim `
                          | Select-Object -ExpandProperty Datapoints).Maximum
        $maxBucketSize = $($maxBucketSizes | Measure-Object -Maximum).Maximum
        $bytesStorages.Add($bytesStorageType, $maxBucketSize)
      }
      $numObjStorages = @{}
      foreach ($numObjStorageType in $numObjStorageTypes) {
        $bucketNumObjStorageDim = [Amazon.CloudWatch.Model.Dimension]::new()
        $bucketNumObjStorageDim.Name = "StorageType"
        $bucketNumObjStorageDim.Value = $numObjStorageType
        $maxBucketObjects = $(Get-CWMetricStatistic  -Statistic Maximum `
                          -Namespace AWS/S3 -MetricName NumberOfObjects `
                          -UtcStartTime $utcStartTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -UtcEndTime $utcEndTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -Period 86400  `
                          -Credential $cred -Region $awsRegion `
                          -Dimension $bucketNameDim, $bucketNumObjStorageDim `
                          | Select-Object -ExpandProperty Datapoints).Maximum
        $maxBucketObjs = $($maxBucketObjects | Measure-Object -Maximum).Maximum
        $numObjStorages.Add($numObjStorageType, $maxBucketObjs)
      }

      $s3obj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "BucketName" = $s3Bucket
        "Region" = $awsRegion
      }
      foreach ($bytesStorage in $bytesStorages.GetEnumerator()) {
        if ($($bytesStorage.Value) -eq $null) {
          $bytesStorageSize = 0
          $s3SizeGB = 0
          $s3SizeGiB = 0
        } else {
          $bytesStorageSize = $($bytesStorage.Value)
          $s3SizeGB = $($bytesStorage.Value) / 1073741824
          $s3SizeGiB = $s3SizeGB / 1.073741824
        }
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeGB") -NotePropertyValue $([math]::round($s3SizeGB, 3))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeGiB") -NotePropertyValue $([math]::round($s3SizeGiB, 3))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeBytes") -NotePropertyValue $bytesStorageSize
      }
      foreach ($numObjStorage in $numObjStorages.GetEnumerator()) {
        if ($($numObjStorage.Value) -eq $null) {
          $numObjStorageNum = 0
        } else {
          $numObjStorageNum = $($numObjStorage.Value)
        }
        Add-Member -InputObject $s3obj -MemberType NoteProperty -Name ("NumberOfObjects-" + $($numObjStorage.Name)) -Value $numObjStorageNum
      }

      $s3List.Add($s3obj) | Out-Null
    }  
    Write-Progress -Activity 'Processing bucket:' -PercentComplete 100 -Completed

    Write-Host "Getting EC2 instance info for region: $awsRegion"  -ForegroundColor Green
    $ec2Instances = $null
    $ec2Instances = (Get-EC2Instance -Credential $cred -region $awsRegion).instances    

    Write-Host "Found" $ec2Instances.Count "EC2 instance(s)."  -ForegroundColor Green

    $counter = 0
    foreach ($ec2 in $ec2Instances) {
      $counter++
      Write-Progress -Activity 'Processing EC2 Instances:' -Status $ec2.InstanceId -PercentComplete (($counter / $ec2Instances.Count) * 100)
      $volSize = 0
      # Contains list of attached volumes to the current EC2 instance
      $volumes = $ec2.BlockDeviceMappings.ebs

      # Iterate through each volume and sum up the volume size
      foreach ($vol in $volumes) {
        $volSize += (Get-EC2Volume -VolumeId $vol.VolumeId -Credential $cred -region $awsRegion).size
      }

      $ec2obj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "InstanceId" = $ec2.InstanceId
        "Name" = $ec2.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
        "Volumes" = $volumes.count
        "SizeGiB" = $volSize
        "SizeGB" = [math]::round($($volSize * 1.073741824), 3)
        "Region" = $awsRegion
        "InstanceType" = $ec2.InstanceType
        "Platform" = $ec2.Platform
      }

      $ec2List.Add($ec2obj) | Out-Null
    }
    Write-Progress -Activity 'Processing EC2 Instances:' -PercentComplete 100 -Completed

    Write-Host "Getting unattached EC2 volume info for region: $awsRegion"  -ForegroundColor Green
    $ec2UnattachedVolumes = $null
    $ec2UnattachedVolumes = (Get-EC2Volume  -Credential $cred -region $awsRegion -Filter @{ Name="status"; Values="available" })
    Write-Host "Found" $ec2UnattachedVolumes.Count "unattached EC2 volume(s)."  -ForegroundColor Green

    $counter = 0
    foreach ($ec2UnattachedVolume in $ec2UnattachedVolumes) {
      $counter++
      Write-Progress -Activity 'Processing unattached EC2 volumes:' -Status $ec2UnattachedVolume.VolumeId -PercentComplete (($counter / $ec2UnattachedVolumes.Count) * 100)

      $volSize = 0

      $ec2UnVolObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "VolumeId" = $ec2UnattachedVolume.VolumeId
        "Name" = $ec2UnattachedVolume.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
        "SizeGiB" = $ec2UnattachedVolume.Size
        "SizeGB" = [math]::round($($ec2UnattachedVolume.Size * 1.073741824), 3)
        "Region" = $awsRegion
        "VolumeType" = $ec2UnattachedVolume.VolumeType
      }

      $ec2UnattachedVolList.Add($ec2UnVolObj) | Out-Null
      Write-Progress -Activity 'Processing unattached EC2 volumes:' -PercentComplete 100 -Completed
    }
    
    Write-Host "Getting RDS info for region: $awsRegion"  -ForegroundColor Green
    $rdsDBs = $null
    $rdsDBs = Get-RDSDBInstance -Credential $cred -region $awsRegion
    Write-Host "Found" $rdsDBs.Count "RDS database(s)."  -ForegroundColor Green

    $counter = 0
    foreach ($rds in $rdsDBs) {
      $counter++
      Write-Progress -Activity 'Processing RDS databases:' -Status $$rds.DBInstanceIdentifier -PercentComplete (($counter / $rdsDBs.Count) * 100)
      $rdsObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "RDSInstance" = $rds.DBInstanceIdentifier
        "DBInstanceIdentifier" = $rds.DBInstanceIdentifier
        "SizeGiB" = $rds.AllocatedStorage
        "SizeGB" = [math]::round($($rds.AllocatedStorage * 1.073741824), 3)
        "Region" = $awsRegion
        "InstanceType" = $rds.DBInstanceClass
        "Platform" = $rds.Engine
      }

      $rdsList.Add($rdsObj) | Out-Null
    }
    Write-Progress -Activity 'Processing RDS databases:' -PercentComplete 100 -Completed
  }  
}

# Contains list of EC2 instances and RDS with capacity info

$ec2List = New-Object collections.arraylist
$ec2UnattachedVolList = New-Object collections.arraylist
$rdsList = New-Object collections.arraylist
$s3List = New-Object collections.arraylist

if ($Partition -eq 'GovCloud') {
  $queryRegion = $defaultGovCloudQueryRegion
}
else {
  $queryRegion = $defaultQueryRegion
}


if ($PSCmdlet.ParameterSetName -eq 'DefaultProfile') {
# Verify that there is a credential/profile to work with.
  try {
    $caller = $(Get-STSCallerIdentity).arn
  } catch {
    Write-Error $_
    Write-Error "Default credential/profile not set."
    Write-Error "Run Set-AWSCredential to set."
    exit 1
  }
  Write-Host
  Write-Host "Source Profile/Credential is: $caller"  -ForegroundColor Green
  $cred = Get-AWSCredential
  getAWSData $cred
}
elseif ($PSCmdlet.ParameterSetName -eq 'UserSpecifiedProfiles') {
  # Get AWS Info based on user supplied list of profiles
  [string[]]$awsProfiles = $UserSpecifiedProfileNames.split(',')
  foreach ($awsProfile in $awsProfiles) {
    Write-Host
    Write-Host "Using profile: $awsProfile"  -ForegroundColor Green
    $cred = Get-AWSCredential -ProfileName $awsProfile
    getAWSData $cred
  }
} 
elseif ($PSCmdlet.ParameterSetName -eq 'AllLocalProfiles') {
  $awsProfiles = $(Get-AWSCredential -ListProfileDetail).ProfileName
  foreach ($awsProfile in $awsProfiles) {
    Write-Host
    Write-Host "Using profile: $awsProfile"  -ForegroundColor Green
    Set-AWSCredential -ProfileName $awsProfile
    $cred = Get-AWSCredential -ProfileName $awsProfile
    getAWSData $cred
  }
}
elseif ($PSCmdlet.ParameterSetName -eq 'AWSOrganization') {
# Verify that there is a credential/profile to work with.
  try {
    $caller = $(Get-STSCallerIdentity).arn
  } catch {
    Write-Error $_
    Write-Error "Credential/profile to query the AWS AOrganization and be the source credential/profile for the cross account role not set."
    Write-Error "Run Set-AWSCredential to set."
    exit 1
  } 
  Write-Host "Source Profile/Credential is: $caller"
  $awsAccounts = Get-ORGAccountList

  foreach ($awsAccount in $awsAccounts) {
    Write-Host
    Write-Host "Searching account id: $($awsAccount.ID) account name: $($awsAccount.Name)"
    $roleArn = "arn:aws:iam::" + $awsAccount.Id + ":role/" + $OrgCrossAccountRoleName
    try {
      $cred = (Use-STSRole -RoleArn $roleArn -RoleSessionName $MyInvocation.MyCommand.Name).Credentials
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to gather data from AWS account $($awsAccount.Id)."
      continue
    }
    getAWSData $cred
  }
} 
elseif ($PSCmdlet.ParameterSetName -eq 'UserSpecifiedAccounts') {
# Verify that there is a credential/profile to work with.
  try {
    $caller = $(Get-STSCallerIdentity).arn
  } catch {
    Write-Error $_
    Write-Error "Credential/profile be the source profile for the cross account role not set."
    Write-Error "Run Set-AWSCredential to set."
    exit 1
  }
  Write-Host "Source Profile/Credential is: $caller"
  [string[]]$awsAccounts = $UserSpecifiedAccounts.split(',')

  foreach ($awsAccount in $awsAccounts) {
    Write-Host
    Write-Host "Searching account: $awsAccount"
    $roleArn = "arn:aws:iam::" + $awsAccount + ":role/" + $CrossAccountRoleName
    try {
      $cred = (Use-STSRole -RoleArn $roleArn -RoleSessionName $MyInvocation.MyCommand.Name).Credentials
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to gather data from AWS account $awsAccount."
      continue
    }
    getAWSData $cred
  }
} 

$ec2TotalGiB = ($ec2list.sizeGiB | Measure-Object -Sum).sum
$ec2TotalGB = ($ec2list.sizeGB | Measure-Object -Sum).sum

$ec2UnVolTotalGiB = ($ec2UnattachedVolList.sizeGiB | Measure-Object -Sum).sum
$ec2UnVolTotalGB = ($ec2UnattachedVolList.sizeGB | Measure-Object -Sum).sum

$rdsTotalGiB = ($rdsList.sizeGiB | Measure-Object -Sum).sum
$rdsTotalGB = ($rdsList.sizeGB | Measure-Object -Sum).sum

$s3Props = $s3List.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
$s3ByteProps = $s3Props | Select-String -Pattern "_SizeBytes"
$s3GBProps = $s3Props | Select-String -Pattern "_SizeGB"
$s3GiBProps = $s3Props | Select-String -Pattern "_SizeGiB"
$s3ListAg = $s3List | Select-Object $s3Props
$s3TotalGBs = @{}

foreach ($s3GBProp in $s3GBProps) {
  $s3TotalGBs.Add($s3GBProp, ($s3ListAg.$s3GBProp | Measure-Object -Sum).Sum)
}

$s3TotalGBsFormatted  = $s3TotalGBs.GetEnumerator() |
  ForEach-Object {
    [PSCustomObject]@{
      StorageType = $_.Key
      Size_GB = "{0:n0}" -f $_.Value
    }
  }

# Export to CSV
Write-Host ""
Write-Host "CSV file output to: $outputEc2Instance"  -ForegroundColor Green
$ec2List | Export-CSV -path $outputEc2Instance
Write-Host "CSV file output to: $outputEc2UnattachedVolume"  -ForegroundColor Green
$ec2UnattachedVolList | Export-CSV -path $outputEc2UnattachedVolume
Write-Host "CSV file output to: $outputRDS"  -ForegroundColor Green
$rdsList | Export-CSV -path $outputRDS
Write-Host "CSV file output to: $outputS3"  -ForegroundColor Green
$s3ListAg | Export-CSV -path $outputS3

# Print Summary
Write-Host
Write-Host "Total # of EC2 instances: $($ec2list.count)"  -ForegroundColor Green
Write-Host "Total # of volumes: $(($ec2list.volumes | Measure-Object -Sum).sum)"  -ForegroundColor Green
Write-Host "Total capacity of all volumes: $ec2TotalGiB GiB or $ec2TotalGB GB"  -ForegroundColor Green
Write-Host

Write-Host
Write-Host "Total # of EC2 unattached volumes: $($ec2UnattachedVolList.count)"  -ForegroundColor Green
Write-Host "Total capacity of all unattached volumes: $ec2UnVolTotalGiB GiB or $ec2UnVolTotalGB GB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of RDS instances: $($rdsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all RDS instances: $rdsTotalGiB GiB or $rdsTotalGB GB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of S3 buckets: $($s3List.count)"  -ForegroundColor Green
Write-Host "Total used capacity of all S3 buckets:"   -ForegroundColor Green
Write-Output $s3TotalGBsFormatted 

