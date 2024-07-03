#requires -Version 7.0
#requires -Modules AWS.Tools.Common, AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.RDS, AWS.Tools.SecurityToken, AWS.Tools.Organizations, AWS.Tools.IdentityManagement, AWS.Tools.CloudWatch, AWS.Tools.ElasticFileSystem, AWS.Tools.SSO, AWS.Tools.SSOOIDC

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

    Install-Module AWS.Tools.Common,AWS.Tools.EC2,AWS.Tools.S3,AWS.Tools.RDS,AWS.Tools.SecurityToken,AWS.Tools.Organizations,AWS.Tools.IdentityManagement,AWS.Tools.CloudWatch,AWS.Tools.ElasticFileSystem,AWS.Tools.SSO,AWS.Tools.SSOOIDC

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
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "ec2:DescribeInstances",
                    "ec2:DescribeRegions",
                    "ec2:DescribeVolumes",
                    "elasticfilesystem:DescribeFileSystems",
                    "iam:ListAccountAliases",
                    "organizations:ListAccounts",
                    "rds:DescribeDBInstances",
                    "s3:GetBucketLocation",
                    "s3:ListAllMyBuckets",
                    "sts:AssumeRole"
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

  .PARAMETER RegionToQuery
    The AWS region to use for query. If not specified, the script will default to 'us-east-1' in commercial AWS and us-gov-east-1
    in AWS GovCloud.

  .PARAMETER Partition
    The AWS partition other than the standard commercial partition to query. Currently the only non-commercial partition to be 
    tested ahs been the GovCloud partition. 

  .PARAMETER DefaultProfile
    Collect data from the account the account listed in the 'default' profile or what ever credentials were specified when
    running the 'Set-AWSCredential' command.

  .PARAMETER AllLocalProfiles
    When set all AWS accounts found in the local profiles will be queried. 

  .PARAMETER CrossAccountRole
    When set, the script will query the AWS accounts specified in the 'UserSpecifiedAccounts' parameter using the cross account
    role specified in the 'CrossAccountRoleName' parameter. Requires the 'UserSpecifiedAccounts' parameter to be set.

  .PARAMETER OrgCrossAccountRoleName
    When set, the script will query the AWS Organization that the default profile or profile specified by 'Set-AWSCredential'
    is in to get a list of all AWS accounts to gather data on. This script will then query all of the accounts that were 
    found using the AWS cross account role that is specified.

  .PARAMETER SSORegion
    When set, the script will authenticate AWS using AWS SSO. -SSORegion is used to specify the region in which to authenticate
    with AWS SSO. Also requires the 'SSORoleName' and 'SSOStartURL' parameters.

  .PARAMETER SSORoleName
    When set , the script will authenticate with AWS using AWS SSO. The script will use the SSO Role specified by -SSORoleName
    to access the AWS accounts. Also requires the 'SSORegion' and 'SSOStartURL' parameters.

  .PARAMETER SSOStartURL
    When set, the script will authenticate with AWS using AWS SSO. The script will use the SSO URL specified by SSOStartURL
    to access the AWS accounts. Also requires the 'SSORegion' and 'SSORoleName' parameters.

  .PARAMETER UserSpecifiedAccounts
    A comma separated list of AWS account numbers to query. The list must be enclosed in quotes. 

  .PARAMETER UserSpecifiedProfileNames
    A comma separated list of AWS Account Profiles stored on the local system to query. The list must be encased in quotes.

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

    PS /home/cloudshell-user> ./Get-AWSEC2RDSInfo.ps1  -UserSpecifiedAccounts "123456789012,098765432109,123456098765" -CrossAccountRoleName MyCrossAccountRole

.EXAMPLE
    >>>

    Run the script in AWS CloudShell to get all AWS account details using AWS SSO.

    [cloudshell-user@ip ~]$ pwsh
    PowerShell 7.3.4

    PS /home/cloudshell-user> ./Get-AWSEC2RDSInfo.ps1 -SSORoleName AdministratorAccess -SSOStartURL "https://mycompany.awsapps.com/start#/"

#>
[CmdletBinding(DefaultParameterSetName = 'DefaultProfile')]
param (

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
  # Get info from a comma separated list of user supplied accounts
  [Parameter(ParameterSetName='CrossAccountRole',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$CrossAccountRoleName,
  # Choose to get info for only the default profile account (default option).
  [Parameter(ParameterSetName='DefaultProfile',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$DefaultProfile,
  # Get Info from AWS SSO
  [Parameter(ParameterSetName='AWSSSO',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$SSORoleName,
  [Parameter(ParameterSetName='AWSSSO',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$SSOStartURL,
  [Parameter(ParameterSetName='AWSSSO',
    Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$SSORegion = "us-east-1",
  # Choose to get info for only specific AWS accounts based on user supplied list of profiles
  [Parameter(ParameterSetName='UserSpecifiedProfiles',
    Mandatory=$true)]
  [ValidateNotNullOrEmpty()]
  [string]$UserSpecifiedProfileNames,
  # Get info from a comma separated list of user supplied accounts when using a cross account role.
  [Parameter(ParameterSetName='AWSSSO')]
  [Parameter(ParameterSetName='CrossAccountRole',
    Mandatory=$true)]
  [Parameter(ParameterSetName='OrganizationAccountAccessRole')]
  [ValidateNotNullOrEmpty()]
  [string]$UserSpecifiedAccounts,
  # Limit search for data to specific regions.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$Regions,
  # Get data from AWS GovCloud region.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [ValidateSet("GovCloud","")]
  [string]$Partition,
  # Region to use to for querying AWS.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$RegionToQuery
)

# Print Powershell Version
Write-Debug "$($PSVersionTable | Out-String)"

# Print Powershell CMDLet Parameter Set
Write-Debug "$($PSCmdlet | Out-String)"

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
$outputEFS = "aws_efs_info-$($date.ToString("yyyy-MM-dd_HHmm")).csv"

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
          $s3SizeTB = 0
          $s3SizeGiB = 0
          $s3SizeTiB = 0
        } else {
          $bytesStorageSize = $($bytesStorage.Value)
          $s3SizeGB = $($bytesStorage.Value) / 1073741824
          $s3SizeTB = $s3SizeGB / 1000
          $s3SizeGiB = $s3SizeGB / 1.073741824
          $s3SizeTiB = $s3SizeGiB / 1024
        }
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeGB") -NotePropertyValue $([math]::round($s3SizeGB, 3))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeTB") -NotePropertyValue $([math]::round($s3SizeTB, 7))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeGiB") -NotePropertyValue $([math]::round($s3SizeGiB, 3))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeTiB") -NotePropertyValue $([math]::round($s3SizeTiB, 7))
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
        "SizeTiB" = [math]::round($($volSize / 1024), 7)
        "SizeGB" = [math]::round($($volSize * 1.073741824), 3)
        "SizeTB" = [math]::round($($volSize * 0.001073741824), 7)
        "Region" = $awsRegion
        "InstanceType" = $ec2.InstanceType
        "Platform" = $ec2.Platform
        "ProductCode" = $ec2.ProductCodes.ProductCodeType
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
        "SizeTiB" = [math]::round($($ec2UnattachedVolume.Size / 1024), 7)
        "SizeGB" = [math]::round($($ec2UnattachedVolume.Size * 1.073741824), 3)
        "SizeTB" = [math]::round($($ec2UnattachedVolume.Size * 0.001073741824), 7)
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
        "SizeTiB" = [math]::round($($rds.AllocatedStorage / 1024), 7)
        "SizeGB" = [math]::round($($rds.AllocatedStorage * 1.073741824), 3)
        "SizeTB" = [math]::round($($rds.AllocatedStorage * 0.001073741824), 7)
        "Region" = $awsRegion
        "InstanceType" = $rds.DBInstanceClass
        "Platform" = $rds.Engine
      }

      $rdsList.Add($rdsObj) | Out-Null
    }
    Write-Progress -Activity 'Processing RDS databases:' -PercentComplete 100 -Completed

    Write-Host "Getting EFS info for region: $awsRegion"  -ForegroundColor Green
    $efsListFromAPI = $null
    $efsListFromAPI = Get-EFSFileSystem -Credential $cred -region $awsRegion
    Write-Host "Found" $efsListFromAPI.Count "EFS file systems."  -ForegroundColor Green

    $counter = 0
    foreach ($efs in $efsListFromAPI) {
      $counter++
      Write-Progress -Activity 'Processing EFS file systems:' -Status $$efs.FileSystemId -PercentComplete (($counter / $efsListFromAPI.Count) * 100)
      $efsObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "FileSystemId" = $efs.FileSystemId
        "FileSystemProtection" = $efs.FileSystemProtection.ReplicationOverwriteProtection.Value
        "Name" = $efs.Name
        "SizeInBytes" = $efs.SizeInBytes.Value
        "SizeGiB" = [math]::round($($efs.SizeInBytes.Value / 1073741824), 7)
        "SizeTiB" = [math]::round($($efs.SizeInBytes.Value / 1073741824 / 1024), 7)
        "SizeGB" = [math]::round($($efs.SizeInBytes.Value / 1000000000), 7)
        "SizeTB" = [math]::round($($efs.SizeInBytes.Value / 1000000000000), 7)
        "NumberOfMountTargets" = $efs.NumberOfMountTargets
        "OwnerId" = $efs.OwnerId
        "PerformanceMode" = $efs.PerformanceMode
        "ProvisionedThroughputInMibps" = $efs.ProvisionedThroughputInMibps
        "DBInstanceIdentifier" = $efs.DBInstanceIdentifier
        "Region" = $awsRegion
        "ThroughputMode" = $efs.ThroughputMode
      }

      $efsList.Add($efsObj) | Out-Null
    }
    Write-Progress -Activity 'Processing EFS:' -PercentComplete 100 -Completed
  }  
}

# Contains list of EC2 instances and RDS with capacity info

$ec2List = New-Object collections.arraylist
$ec2UnattachedVolList = New-Object collections.arraylist
$rdsList = New-Object collections.arraylist
$s3List = New-Object collections.arraylist
$efsList = New-Object collections.arraylist

if ($RegionToQuery) {
  $queryRegion = $RegionToQuery
  write-host "Set region to query"
}
elseif ($Partition -eq 'GovCloud') {
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
  if ($UserSpecifiedAccounts) {
    $awsAccounts = Get-ORGAccountList | Where-Object {$_.ID -in $UserSpecifiedAccounts.split(',')}
  } else {
    $awsAccounts = Get-ORGAccountList
  }

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
elseif ($PSCmdlet.ParameterSetName -eq 'AWSSSO') {
  $SSOOIDCClient = $(Register-SSOOIDCClient -ClientName $MyInvocation.MyCommand -ClientType 'public' -Region $SSORegion)
  $DevAuth = $(Start-SSOOIDCDeviceAuthorization -ClientId $SSOOIDCClient.ClientId `
                                                -ClientSecret $SSOOIDCClient.ClientSecret `
                                                -StartUrl $SSOStartURL `
                                                -Region $SSORegion)
  $CodeExpiry = (Get-Date) + (New-TimeSpan -Seconds $DevAuth.ExpiresIn)
  Set-Clipboard $DevAuth.VerificationUriComplete
  Write-Host "Please visit the link below (also copied to the clipboard) and verify the user code is:"
  Write-Host ""
  Write-Host "URL: $($DevAuth.VerificationUriComplete)"
  Write-Host ""
  Write-Host "User Verification Code: $($DevAuth.UserCode)"
  Write-Host ""
  Write-Host "The authorization session will expire at: $($CodeExpiry)"
  Write-Host "Please follow the instructions on the web page to authenticate."
  Write-Host "Waiting for user to authenticate..."

  while ((Get-Date) -le $CodeExpiry) {
      Start-Sleep $DevAuth.Interval
      try {
          $Token = $(New-SSOOIDCToken -ClientId $SSOOIDCClient.ClientId `
                                      -ClientSecret $SSOOIDCClient.ClientSecret `
                                      -DeviceCode $DevAuth.DeviceCode `
                                      -GrantType 'urn:ietf:params:oauth:grant-type:device_code' `
                                      -Region $SSORegion)
          break
      }
      catch [Amazon.SSOOIDC.Model.AuthorizationPendingException] {
          continue #Awaiting auth to be given
      }
  }

  if ($UserSpecifiedAccounts) {
    $awsAccounts = Get-SSOAccountList -AccessToken $Token.AccessToken -Region $SSORegion | Where-Object {$_.AccountId -in $UserSpecifiedAccounts.split(',')}
  } else {
    $awsAccounts = Get-SSOAccountList -AccessToken $Token.AccessToken -Region $SSORegion
  }

  foreach ($awsAccount in $awsAccounts) {
    Write-Host
    Write-Host "Searching account id: $($awsAccount.AccountId) account name: $($awsAccount.AccountName)"
    try {
      $ssoCred = Get-SSORoleCredential -AccessToken $Token.AccessToken -AccountId $awsAccount.AccountId -RoleName $SSORoleName -region $SSORegion
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to get SSO Credentials for AWS account $($awsAccount.AccountId) using SSO Role $($SSORoleName)."
      continue
    }
    try {
      $cred = Set-AWSCredential -AccessKey $ssoCred.AccessKeyId `
                                -SecretKey $ssoCred.SecretAccessKey `
                                -SessionToken $ssoCred.SessionToken
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to get SSO session for AWS account $($awsAccount.Id)."
      continue
    }
    getAWSData $cred
  }
} 
elseif ($PSCmdlet.ParameterSetName -eq 'CrossAccountRole') {
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
$ec2TotalTiB = ($ec2list.sizeTiB | Measure-Object -Sum).sum 
$ec2TotalGB = ($ec2list.sizeGB | Measure-Object -Sum).sum
$ec2TotalTB = ($ec2list.sizeTB | Measure-Object -Sum).sum

$ec2UnVolTotalGiB = ($ec2UnattachedVolList.sizeGiB | Measure-Object -Sum).sum
$ec2UnVolTotalTiB = ($ec2UnattachedVolList.sizeTiB | Measure-Object -Sum).sum
$ec2UnVolTotalGB = ($ec2UnattachedVolList.sizeGB | Measure-Object -Sum).sum
$ec2UnVolTotalTB = ($ec2UnattachedVolList.sizeTB | Measure-Object -Sum).sum

$rdsTotalGiB = ($rdsList.sizeGiB | Measure-Object -Sum).sum
$rdsTotalTiB = ($rdsList.sizeTiB | Measure-Object -Sum).sum 
$rdsTotalGB = ($rdsList.sizeGB | Measure-Object -Sum).sum
$rdsTotalTB = ($rdsList.sizeTB | Measure-Object -Sum).sum

$s3Props = $s3List.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
$s3TBProps = $s3Props | Select-String -Pattern "_SizeTB"
$s3ListAg = $s3List | Select-Object $s3Props
$s3TotalTBs = @{}

foreach ($s3TBProp in $s3TBProps) {
  $s3TotalTBs.Add($s3TBProp, ($s3ListAg.$s3TBProp | Measure-Object -Sum).Sum)
}

$s3TotalTBsFormatted  = $s3TotalTBs.GetEnumerator() |
  ForEach-Object {
    [PSCustomObject]@{
      StorageType = $_.Key
      Size_TB = "{0:n7}" -f $_.Value
    }
  }

$efsTotalGiB = ($efsList.sizeGiB | Measure-Object -Sum).sum
$efsTotalTiB = ($efsList.sizeTiB | Measure-Object -Sum).sum 
$efsTotalGB = ($efsList.sizeGB | Measure-Object -Sum).sum
$efsTotalTB = ($efsList.sizeTB | Measure-Object -Sum).sum

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
Write-Host "CSV file output to: $outputEFS"  -ForegroundColor Green
$efsList | Export-CSV -path $outputEFS

# Print Summary
Write-Host
Write-Host "Total # of EC2 instances: $($ec2list.count)"  -ForegroundColor Green
Write-Host "Total # of volumes: $(($ec2list.volumes | Measure-Object -Sum).sum)"  -ForegroundColor Green
Write-Host "Total capacity of all volumes: $ec2TotalGiB GiB or $ec2TotalGB GB or $ec2TotalTiB TiB or $ec2TotalTB TB"  -ForegroundColor Green
Write-Host

Write-Host
Write-Host "Total # of EC2 unattached volumes: $($ec2UnattachedVolList.count)"  -ForegroundColor Green
Write-Host "Total capacity of all unattached volumes: $ec2UnVolTotalGiB GiB or $ec2UnVolTotalGB GB or $ec2UnVolTotalTiB TiB or $ec2UnVolTotalTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of RDS instances: $($rdsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all RDS instances: $rdsTotalGiB GiB or $rdsTotalGB GB or $rdsTotalTiB TiB or $rdsTotalTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of EFS file systems: $($efsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all EFS file systems: $efsTotalGiB GiB or $efsTotalGB GB or $efsTotalTiB TiB or $efsTotalTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of S3 buckets: $($s3List.count)"  -ForegroundColor Green
Write-Host "Total used capacity of all S3 buckets:"   -ForegroundColor Green
Write-Output $s3TotalTBsFormatted