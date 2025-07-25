#requires -Version 7.0
<#requires -Modules AWS.Tools.Common, AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.RDS, AWS.Tools.SecurityToken, AWS.Tools.Organizations, AWS.Tools.IdentityManagement, AWS.Tools.CloudWatch, AWS.Tools.ElasticFileSystem, AWS.Tools.SSO, AWS.Tools.SSOOIDC, AWS.Tools.FSX, AWS.Tools.Backup, AWS.Tools.CostExplorer, AWS.Tools.DynamoDBv2, AWS.Tools.SQS, AWS.Tools.SecretsManager, AWS.Tools.KeyManagementService, AWS.Tools.EKS
#>
# https://build.rubrik.com

<#
  .SYNOPSIS
    Gets all EC2 instances and RDS instances with the # of attached volumes and provisioned sizes.

  .DESCRIPTION
    The 'Get-AWSSizingInfo.ps1' script gets all EC2 instances, EC2 unattached volumes and RDS databases
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

    Install-Module AWS.Tools.Common,AWS.Tools.EC2,AWS.Tools.S3,AWS.Tools.RDS,AWS.Tools.SecurityToken,AWS.Tools.Organizations,AWS.Tools.IdentityManagement,AWS.Tools.CloudWatch,AWS.Tools.ElasticFileSystem,AWS.Tools.SSO,AWS.Tools.SSOOIDC,AWS.Tools.FSX,AWS.Tools.Backup,AWS.Tools.CostExplorer,AWS.Tools.DynamoDBv2,AWS.Tools.SQS,AWS.Tools.SecretsManager,AWS.Tools.KeyManagementService,AWS.Tools.EKS

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
                    "backup:ListBackupPlans",
                    "backup:ListBackupSelections",
                    "backup:GetBackupPlan",
                    "backup:GetBackupSelection",
                    "ce:GetCostAndUsage",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "dynamodb:ListTables",
                    "dynamodb:DescribeTable",
                    "ec2:DescribeInstances",
                    "ec2:DescribeRegions",
                    "ec2:DescribeVolumes",
                    "eks:DescribeCluster",
                    "eks:ListClusters",
                    "eks:ListNodegroups",
                    "elasticfilesystem:DescribeFileSystems",
                    "fsx:DescribeFileSystems",
                    "fsx:DescribeVolumes",
                    "iam:ListAccountAliases",
                    "kms:ListKeys",
                    "organizations:ListAccounts",
                    "rds:DescribeDBInstances",
                    "s3:GetBucketLocation",
                    "s3:ListAllMyBuckets",
                    "secretsmanager:ListSecrets",
                    "sts:AssumeRole",
                    "sqs:ListQueues"
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

  .PARAMETER AllLocalProfiles
    When set all AWS accounts found in the local profiles will be queried. 

  .PARAMETER Anonymize
    Anonymize data collected.

  .PARAMETER AnonymizeFields
    A comma separated list of fields in resulting csvs and JSONs to anonymize. The list must be encased in
    quotes, with no spaces between fields.

  .PARAMETER CrossAccountRole
    When set, the script will query the AWS accounts specified in the 'UserSpecifiedAccounts' parameter using the cross account
    role specified in the 'CrossAccountRoleName' parameter. Requires the 'UserSpecifiedAccounts' parameter to be set.

  .PARAMETER DefaultProfile
    Collect data from the account the account listed in the 'default' profile or what ever credentials were specified when
    running the 'Set-AWSCredential' command.

  .PARAMETER NotAnonymizeFields
    A comma separated list of fields in resulting CSVs and JSONs to not anonymize (only required for fields which are by default being 
    anonymized). The list must be encased in quotes, with no spaces between fields.
    Note that we currently anonymize the following fields:
    "AwsAccountId", "AwsAccountAlias", "BucketName", "Name", 
    "InstanceId", "VolumeId", "RDSInstance", "DBInstanceIdentifier",
    "FileSystemId", "FileSystemDNSName", "FileSystemOwnerId", "OwnerId",
    "RuleId", "RuleName", "BackupPlanArn", "BackupPlanId", "VersionId",
    "RequestId", "TableName", "TableId", "TableArn"

  .PARAMETER OrgCrossAccountRoleName
    When set, the script will query the AWS Organization that the default profile or profile specified by 'Set-AWSCredential'
    is in to get a list of all AWS accounts to gather data on. This script will then query all of the accounts that were 
    found using the AWS cross account role that is specified.

  .PARAMETER Partition
    The AWS partition other than the standard commercial partition to query. Currently the only non-commercial partition to be 
    tested ahs been the GovCloud partition. 

  .PARAMETER ProfileLocation
    The location of the AWS profile to use. This is the location of the AWS profile file that contains the credentials to use
    to query AWS.

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

  .PARAMETER SSOParameterSetName
    When set , the script will authenticate with AWS using AWS SSO. The script will use the SSO Parameter Set specified by -SSOParameterSetName
    to access the AWS accounts. Also requires the 'SSORegion' and 'SSOStartURL' parameters.

  .PARAMETER SSORegion
    When set, the script will authenticate AWS using AWS SSO. -SSORegion is used to specify the region in which to authenticate
    with AWS SSO. Also requires the 'SSOParameterSetName' and 'SSOStartURL' parameters.

  .PARAMETER SSOStartURL
    When set, the script will authenticate with AWS using AWS SSO. The script will use the SSO URL specified by SSOStartURL
    to access the AWS accounts. Also requires the 'SSORegion' and 'SSOParameterSetName' parameters.

  .PARAMETER SkipBucketTags
    When set, the script will not collect tags for S3 buckets.

  .PARAMETER UserSpecifiedAccounts
    A comma separated list of AWS account numbers to query. The list must be enclosed in quotes. 

  .PARAMETER UserSpecifiedAccountsFile
    A file containing a list of AWS account numbers to query. The file must be enclosed in quotes.
    
  .PARAMETER UserSpecifiedProfileNames
    A comma separated list of AWS Account Profiles stored on the local system to query. The list must be encased in quotes.
  
  .EXAMPLE  
    >>>

    Run the script in AWS CloudShell to get all AWS information and output to a CSV file. Uses the current 
    AWS account profile and searches all regions.

    [cloudshell-user@ip ~]$ pwsh
    PowerShell 7.3.3

    A new PowerShell stable release is available: v7.3.4 
    Upgrade now, or check out the release page at:       
      https://aka.ms/PowerShell-Release?tag=v7.3.4       

    PS /home/cloudshell-user> ./Get-AWSSizingInfo.ps1        

  .EXAMPLE
    >>>

    Run the script in Powershell to get all AWS information and output to a CSV file. Uses the  
    AWS account specified by and searches all regions.

    PS > Set-AWSCredential -ProfileName MyAwsProfile
    PS > ./Get-AWSSizingInfo.ps1        

  .EXAMPLE
    >>>

    Run the script in PowerShell to get all AWS information and output to a CSV file. Use the selected Profile Location.

    PS > ./Get-AWSSizingInfo.ps1 -ProfileLocation "C:\Users\user\Documents\AWS\credentials" -ProfileName MyAwsProfile

  .EXAMPLE
    >>>
    
    Run the script in PowerShell to get all AWS information and output to a CSV file. Use the selected 
    account profiles "aws_account_profile1" and "aws_account_profile2". Limit the query to the "us-west-1" and 
    "us-west-2" regions. 

    PS > ./Get-AWSSizingInfo.ps1 -UserSpecifiedProfileNames "aws_account_profile1,aws_account_profile2" -Regions "us-west-1,us-west-2"

  .EXAMPLE
    >>>
    
    Run the script in Powershell to get all AWS information and output to a CSV file. Uses all of the  
    AWS account profiles in the user environment. Limits the query to the "us-gov-east-1" region and 
    queries the AWS GovCloud partition.

    PS> ./Get-AWSSizingInfo.ps1 -AllLocalProfiles -Regions us-gov-east-1 -Partition GovCloud

  .EXAMPLE
    >>>

    Run the script in PowerShell to get all AWS information and output to a CSV file. Query the AWS Organization
    for a list of accounts and search all found accounts. 

    PS > Set-AWSCredential -ProfileName MyAwsSourceOrgProfile
    PS > ./Get-AWSSizingInfo.ps1 -OrgCrossAccountRoleName OrganizationAccountAccessRole

.EXAMPLE
    >>>

    Run the script in AWS CloudShell to get all AWS information and output to a CSV file. Query a 
    user provided list of AWS accounts.

    [cloudshell-user@ip ~]$ pwsh
    PowerShell 7.3.3

    PS > Set-AWSCredential -ProfileName MyAwsSourceProfile
    PS /home/cloudshell-user> ./Get-AWSSizingInfo.ps1  -UserSpecifiedAccounts "123456789012,098765432109,123456098765" -CrossAccountRoleName MyCrossAccountRole

.EXAMPLE
    >>>

    Run the script in AWS CloudShell to get all AWS account details using AWS SSO.

    [cloudshell-user@ip ~]$ pwsh
    PowerShell 7.3.4

    PS > Set-AWSCredential -ProfileName MyAwsSourceProfile
    PS /home/cloudshell-user> ./Get-AWSSizingInfo.ps1 -SSOParameterSetName AdministratorAccess -SSOStartURL "https://mycompany.awsapps.com/start#/"

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
  [string]$SSOParameterSetName,
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
  # Get list of user supplied AWS accounts from a comma separated list on the command line.
  [Parameter(ParameterSetName='AWSSSO')]
  [Parameter(ParameterSetName='CrossAccountRole')]
  [Parameter(ParameterSetName='AWSOrganization')]
  [ValidateNotNullOrEmpty()]
  [string]$UserSpecifiedAccounts,
  # Get list of user supplied AWS accounts from a file.
  [Parameter(ParameterSetName='AWSSSO')]
  [Parameter(ParameterSetName='CrossAccountRole')]
  [Parameter(ParameterSetName='AWSOrganization')]
  [ValidateNotNullOrEmpty()]
  [string]$UserSpecifiedAccountsFile,
  # Option to anonymize the output files.
  [Parameter(Mandatory=$false)]
  [switch]$Anonymize,
  # Choose to anonymize additional fields
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$AnonymizeFields,
  # Choose to not anonymize certain fields
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$NotAnonymizeFields,
  # Get data from AWS GovCloud region.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [ValidateSet("GovCloud","")]
  [string]$Partition,
  # Use specific ProfileLocation.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$ProfileLocation,
  # Limit search for data to specific regions.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$Regions,
  # Region to use to for querying AWS.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [string]$RegionToQuery,
  # Skip Collecting Bucket Tags.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$SkipBucketTags,
  # Grab output for debugging Bucket Tags.
  [Parameter(Mandatory=$false)]
  [ValidateNotNullOrEmpty()]
  [switch]$DebugBucketTags
)

# Save the current culture so it can be restored later
$CurrentCulture = [System.Globalization.CultureInfo]::CurrentCulture

# Set the culture to en-US; this is to ensure that output to CSV is formatted properly
[System.Threading.Thread]::CurrentThread.CurrentCulture = 'en-US'
[System.Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'

# Print Powershell Version
Write-Debug "$($PSVersionTable | Out-String)"

# Print Powershell CMDLet Parameter Set
Write-Debug "$($PSCmdlet | Out-String)"

# Set default regions for queries
$defaultQueryRegion = "us-east-1"
$defaultGovCloudQueryRegion = "us-gov-east-1"

$date = Get-Date
$date_string = $($date.ToString("yyyy-MM-dd_HHmmss"))
$utcEndTime = $date.ToUniversalTime()
$utcStartTime = $utcEndTime.AddDays(-7)

$output_log = "output_aws_$date_string.log"

if (Test-Path "./$output_log") {
  Remove-Item -Path "./$output_log"
}
#Handle Anonymized Log
if ($Anonymize){
  "Anonymized file; customer has original. Request customer to sanitize and provide output log if needed" > $output_log
  $log_for_anon_customers = "output_aws_not_anonymized_$date_string.log"
  Start-Transcript -Path "./$log_for_anon_customers"
} else{
  Start-Transcript -Path "./$output_log"
}

Write-Host "Arguments passed to $($MyInvocation.MyCommand.Name):" -ForeGroundColor Green
$PSBoundParameters | Format-Table

$profileLocationOpt = @{}
if ($ProfileLocation) {
  $profileLocationOpt = @{ProfileLocation = $($ProfileLocation)}
  Write-Host "Using Profile Location: $ProfileLocation"
}

# Filenames of the CSVs output
$outputEc2Instance = "aws_ec2_instance_info-$date_string.csv"
#unattached volumes are less important and we can probably ignore these. We should be tracking orphaned snapshots or those not created by AWS Backup
$outputEc2UnattachedVolume = "aws_ec2_unattached_volume_info-$date_string.csv"
$outputRDS = "aws_rds_info-$date_string.csv"
$outputS3 = "aws_s3_info-$date_string.csv"
$outputEFS = "aws_efs_info-$date_string.csv"
$outputFSXfilesystems = "aws_fsx_filesystem_info-$date_string.csv"
$outputFSX = "aws_fsx_volume_info-$date_string.csv"
$outputDDB = "aws_DynamoDB_info-$date_string.csv"
#We are not backing up KMS keys at this point
$outputKMS = "aws_kms_numbers-$date_string.csv"
#We can ignore SQS queues
$outputSQS = "aws_sqs_numbers-$date_string.csv"
#We are not backing up Secrets Manager Secrets at this point
$outputSecrets = "aws_secrets_numbers-$date_string.csv"
$outputEKSClusters = "aws_eks_clusters_info-$date_string.csv"
$outputEKSNodegroups = "aws_eks_nodegroups_info-$date_string.csv"
#AWS Backup will require much additional processing
$outputBackupCosts = "aws_backup_costs-$date_string.csv"
$outputBackupPlansJSON = "aws-backup-plans-info-$date_string.json"
$archiveFile = "aws_sizing_results_$date_string.zip"

# List of output files
$outputFiles = @(
    $outputEc2Instance,
    $outputEc2UnattachedVolume,
    $outputRDS,
    $outputS3,
    $outputEFS,
    $outputFSXfilesystems,
    $outputFSX,
    $outputDDB,
    $outputKMS,
    $outputSecrets,
    $outputSQS,
    $outputEKSClusters,
    $outputEKSNodegroups,
    $outputBackupCosts,
    $outputBackupPlansJSON,
    $output_log
)

function getEC2Inventory($qregion, $cred,$awsAccountInfo) {
  try {
    $ec2Instances = (Get-EC2Instance -Credential $cred -region $qregion -ErrorAction Stop).Instances;
  } catch {
    Write-Host "Failed to get EC2 Info for region $qregion in account $($awsAccountInfo.Account)" -ForegroundColor Red;
    Write-Host "Error $_" -ForegroundColor Red;
  }
  $counter = 1;
  foreach ($ec2 in $ec2Instances) {
    Write-Progress -ID 4 -Activity "Processing EC2 Instance: $($ec2.InstanceId)" -Status "Instance $($counter) of $($ec2Instances.Count)" -PercentComplete (($counter / $ec2Instances.Count) *100);
    $counter++;
    $volSize = 0;
    #containes list of attached volumes to the current EC2 instance
    $volumes = $ec2.BlockDeviceMappings.ebs;
    #Iterate through each volume and sum up the volume size
    foreach ($vol in $volumes) {
      try {
        $volSize += (Get-EC2Volume -VolumeId $vol.VolumeId -Credential $cred -region $qregion -ErrorAction Stop).size;
      } catch {
        Write-Host "Failed to get size of EC2 Volume $($vol.VolumeId) in $($ec2.InstanceId) for region $qregion in account $($awsAccountInfo.Account)" -ForegroundColor Red;
        Write-Host "Error: $_" -ForegroundColor Red;
      }
    }
    $ec2obj = [PSCustomObject] @{
      "AwsAccountId" = $awsAccountInfo.Account;
      "AwsAccountAlias" = $awsAccountAlias;
      "InstanceId" = $ec2.InstanceId;
      "Name" = $ec2.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
      "Volumes" = $volumes.count;
      "SizeGiB" = $volSize;
      "SizeTiB" = [math]::round($($volSize / 1024), 4);
      "SizeGB" = [math]::round($($volSize * 1.073741824), 3);
      "SizeTB" = [math]::round($($volSize * 0.001073741824), 4);
      "Region" = $awsRegion;
      #We do not need instance type
      "InstanceType" = $ec2.InstanceType;
      #we do not need platform
      "Platform" = $ec2.Platform;
      #We do not need product code
      "ProductCode" = $ec2.ProductCodes.ProductCodeType;
      #Backup Plans is something we need to evaluate
      "BackupPlans" = "";
      "InBackupPlan" = $false;
    }

    foreach ($tag in $ec2.Tags) { 
      # Powershell objects have restrictions on key names, 
      # so I use Regular Expressions to substitute non valid parts 
      # like ' ' or '-' to '_' 
      # This may cause small subtle changes from the tagname in AWS 
      # Same applies to all other types of objects
      $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
      if($key -ne "Name"){ 
        $ec2obj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force 
      } 
    }

    $ec2List.Add($ec2obj) | Out-Null

  }
}
# Monolithic Function to do the work
function getAWSData($cred) {
  # Set the regions that you want to get EC2 instance and volume details for
  if ($Regions -ne '') {
    [string[]]$awsRegions = $Regions.split(',')
  }
  else {
    try {
      Write-Debug "Profile name is $awsProfile and queryRegion name is $queryRegion"
      $awsRegions = Get-EC2Region @profileLocationOpt -Region $queryRegion -Credential $cred | Select-Object -ExpandProperty RegionName
    } catch {
      Write-Host "Failed to get EC2 Regions for profile name $awsProfile in region $queryRegion" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
  }

  
  Write-Host "Current identity:"  -ForegroundColor Green
  Write-Debug "Profile name is $awsProfile and queryRegion name is $queryRegion"
  try{
    $awsAccountInfo = Get-STSCallerIdentity  -Credential $cred -Region $queryRegion -ErrorAction Stop
  } catch {
    Write-Host "Failed to get AWS Account Info for region $queryRegion for profile name $awsProfile" -ForeGroundColor Red
    Write-Host "Error: $_" -ForeGroundColor Red
  }
  $awsAccountInfo | format-table
  try{
    $awsAccountAlias = Get-IAMAccountAlias -Credential $cred -Region $queryRegion -ErrorAction Stop
  } catch {
    Write-Host "Failed to get IAM Account Alias Info for region $queryRegion for profile name $awsProfile in account $($awsAccountInfo.Account)" -ForeGroundColor Red
    Write-Host "Error: $_" -ForeGroundColor Red
  }

  # For all specified regions get the S3 bucket, EC2 instance, EC2 Unattached disk and RDS info
  $awsRegionCounter = 1
  foreach ($awsRegion in $awsRegions) {
    Write-Progress -ID 2 -Activity "Processing region: $($awsRegion)" -Status "Region $($awsRegionCounter) of $($awsRegions.Count)" -PercentComplete (($awsRegionCounter / $awsRegions.Count) * 100)
    $awsRegionCounter++
    try{
      $cwBucketInfo = Get-CWmetriclist -namespace AWS/S3 -Region $awsRegion -Credential $cred -ErrorAction Stop
    } catch {
      Write-Host "Failed to get S3 Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Start Ingesting information on S3 Buckets
    try{ 
      $s3Buckets = $(Get-S3Bucket -Credential $cred -Region $awsRegion -BucketRegion $awsRegion -ErrorAction Stop).BucketName
    } catch {
      Write-Host "Failed to get S3 Info for region $awsRegion in account $($awsAccountInfo.Account) using Get-S3Bucket" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
  $counter = 1
    foreach ($s3Bucket in $s3Buckets) {
      Write-Progress -ID 3 -Activity "Processing bucket: $($s3Bucket)" -Status "Bucket $($counter) of $($s3Buckets.Count)" -PercentComplete (($counter / $s3Buckets.Count) * 100)
      $counter++
      #This needs to be simplified. We only need the total bucket size, not the size per storage category
      $filter = [Amazon.CloudWatch.Model.DimensionFilter]::new() 
      $filter.Name = 'BucketName'
      $filter.Value = $s3Bucket
      try{
        $bytesStorageTypes = $(Get-CWmetriclist -Dimension $filter -Credential $cred -Region $awsRegion -ErrorAction Stop `
                                | Where-Object -Property MetricName -eq 'BucketSizeBytes' `
                                | Select-Object -ExpandProperty Dimensions `
                                | Where-Object -Property Name -eq StorageType).Value  
        $numObjStorageTypes = $(Get-CWmetriclist -Dimension $filter -Credential $cred -Region $awsRegion -ErrorAction Stop `
                                | Where-Object -Property MetricName -eq 'NumberOfObjects' `
                                | Select-Object -ExpandProperty Dimensions `
                                | Where-Object -Property Name -eq StorageType).Value 
      } catch {
        Write-Host "Failed to get S3 Info for bucket $s3Bucket in region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $bucketNameDim = [Amazon.CloudWatch.Model.Dimension]::new()
      $bucketNameDim.Name = "BucketName"
      $bucketNameDim.Value = $s3Bucket
      $bytesStorages = @{}
      foreach ($bytesStorageType in $bytesStorageTypes) {
        $bucketBytesStorageDim = [Amazon.CloudWatch.Model.Dimension]::new()
        $bucketBytesStorageDim.Name = "StorageType"
        $bucketBytesStorageDim.Value = $bytesStorageType
        try{
          $maxBucketSizes = $(Get-CWMetricStatistic  -Statistic Maximum `
                          -Namespace AWS/S3 -MetricName BucketSizeBytes `
                          -UtcStartTime $utcStartTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -EndTime $utcEndTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -Period 86400  `
                          -Credential $cred -Region $awsRegion `
                          -Dimension $bucketNameDim, $bucketBytesStorageDim -ErrorAction Stop `
                          | Select-Object -ExpandProperty Datapoints).Maximum
        } catch {
          Write-Host "Failed to get S3 Info for StorageType $bytesStorageType in bucket $s3Bucket in region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $maxBucketSize = $($maxBucketSizes | Measure-Object -Maximum).Maximum
        $bytesStorages.Add($bytesStorageType, $maxBucketSize)
      }
      $numObjStorages = @{}
      foreach ($numObjStorageType in $numObjStorageTypes) {
        $bucketNumObjStorageDim = [Amazon.CloudWatch.Model.Dimension]::new()
        $bucketNumObjStorageDim.Name = "StorageType"
        $bucketNumObjStorageDim.Value = $numObjStorageType
        try{
          $maxBucketObjects = $(Get-CWMetricStatistic  -Statistic Maximum `
                          -Namespace AWS/S3 -MetricName NumberOfObjects `
                          -StartTime $utcStartTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -EndTime $utcEndTime.ToString("yyyy-MM-dd" + "T" + "HH:mm:ss" +"Z") `
                          -Period 86400  `
                          -Credential $cred -Region $awsRegion `
                          -Dimension $bucketNameDim, $bucketNumObjStorageDim -ErrorAction Stop `
                          | Select-Object -ExpandProperty Datapoints).Maximum
        } catch {
          Write-Host "Failed to get S3 Info for StorageType $numObjStorageType in bucket $s3Bucket in region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $maxBucketObjs = $($maxBucketObjects | Measure-Object -Maximum).Maximum
        $numObjStorages.Add($numObjStorageType, $maxBucketObjs)
      }

      if ($SkipBucketTags) {
        $bucketTags = @()
      } else {
        try {
          $bucketTags = Get-S3BucketTagging -BucketName $s3Bucket -Credential $cred -Region $awsRegion 
        } catch {
          Write-Host "Failed to get S3 tag info for bucket $s3Bucket in region $awsRegion in account $($awsAccountInfo.Account)." -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
      }

      $s3obj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "BucketName" = $s3Bucket
        "Region" = $awsRegion
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      foreach ($bytesStorage in $bytesStorages.GetEnumerator()) {
        if ($null -eq $($bytesStorage.Value)) {
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
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeTB") -NotePropertyValue $([math]::round($s3SizeTB, 4))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeGiB") -NotePropertyValue $([math]::round($s3SizeGiB, 3))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeTiB") -NotePropertyValue $([math]::round($s3SizeTiB, 4))
        Add-Member -InputObject $s3obj -NotePropertyName ($($bytesStorage.Name) + "_SizeBytes") -NotePropertyValue $bytesStorageSize        
      }
      foreach ($numObjStorage in $numObjStorages.GetEnumerator()) {
        if ($null -eq $($numObjStorage.Value)) {
          $numObjStorageNum = 0
        } else {
          $numObjStorageNum = $($numObjStorage.Value)
        }
        Add-Member -InputObject $s3obj -MemberType NoteProperty -Name ("NumberOfObjects-" + $($numObjStorage.Name)) -Value $numObjStorageNum
      }

      foreach ($tag in $bucketTags) { 

        # Powershell objects have restrictions on key names, 
        # so I use Regular Expressions to substitute non valid parts 
        # like ' ' or '-' to '_' 
        # This may cause small subtle changes from the tagname in AWS 
        # Same applies to all other types of objects
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
        Add-Member -InputObject $s3obj -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force  
      }

      $s3List.Add($s3obj) | Out-Null
    }  
    Write-Progress -ID 3 -Activity "Processing bucket: $($s3Bucket)" -Completed
#Start Ingesting EC2 instances
    $ec2Instances = $null
    try{
      $ec2Instances = (Get-EC2Instance -Credential $cred -region $awsRegion -ErrorAction Stop).instances    
    } catch {
      Write-Host "Failed to get EC2 Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    $counter = 1
    foreach ($ec2 in $ec2Instances) {
      Write-Progress -ID 4 -Activity "Processing EC2 Instance: $($ec2.InstanceId)" -Status "Instance $($counter) of $($ec2Instances.Count)" -PercentComplete (($counter / $ec2Instances.Count) * 100)
      $counter++
      $volSize = 0
      # Contains list of attached volumes to the current EC2 instance
      $volumes = $ec2.BlockDeviceMappings.ebs

      # Iterate through each volume and sum up the volume size
      foreach ($vol in $volumes) {
        try{
          $volSize += (Get-EC2Volume -VolumeId $vol.VolumeId -Credential $cred -region $awsRegion -ErrorAction Stop).size   
        } catch {
          Write-Host "Failed to get size of EC2 Volume $($vol.VolumeId) in $($ec2.InstanceId) for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
      }

      $ec2obj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "InstanceId" = $ec2.InstanceId
        "Name" = $ec2.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
        "Volumes" = $volumes.count
        "SizeGiB" = $volSize
        "SizeTiB" = [math]::round($($volSize / 1024), 4)
        "SizeGB" = [math]::round($($volSize * 1.073741824), 3)
        "SizeTB" = [math]::round($($volSize * 0.001073741824), 4)
        "Region" = $awsRegion
        "InstanceType" = $ec2.InstanceType
        "Platform" = $ec2.Platform
        "ProductCode" = $ec2.ProductCodes.ProductCodeType
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }

      foreach ($tag in $ec2.Tags) { 
        # Powershell objects have restrictions on key names, 
        # so I use Regular Expressions to substitute non valid parts 
        # like ' ' or '-' to '_' 
        # This may cause small subtle changes from the tagname in AWS 
        # Same applies to all other types of objects
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
        if($key -ne "Name"){ 
          $ec2obj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force 
        } 
      }

      $ec2List.Add($ec2obj) | Out-Null
    }
    Write-Progress -ID 4 -Activity "Processing EC2 Instance: $($ec2.InstanceId)" -Completed

    $ec2UnattachedVolumes = $null
    try{
      $ec2UnattachedVolumes = (Get-EC2Volume  -Credential $cred -region $awsRegion -Filter @{ Name="status"; Values="available" } -ErrorAction Stop)
    } catch {
      Write-Host "Failed to get EC2 Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Counter for unattached volumes. Do we need to include these?
    $counter = 1
    foreach ($ec2UnattachedVolume in $ec2UnattachedVolumes) {
      Write-Progress -ID 5 -Activity "Processing unattached EC2 volume: $($ec2UnattachedVolume.VolumeId)" -Status "Unattached EC2 volume $($counter) of $($ec2UnattachedVolumes.Count)" -PercentComplete (($counter / $ec2UnattachedVolumes.Count) * 100)
      $counter++
      $volSize = 0

      $ec2UnVolObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "VolumeId" = $ec2UnattachedVolume.VolumeId
        "Name" = $ec2UnattachedVolume.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
        "SizeGiB" = $ec2UnattachedVolume.Size
        "SizeTiB" = [math]::round($($ec2UnattachedVolume.Size / 1024), 4)
        "SizeGB" = [math]::round($($ec2UnattachedVolume.Size * 1.073741824), 3)
        "SizeTB" = [math]::round($($ec2UnattachedVolume.Size * 0.001073741824), 4)
        "Region" = $awsRegion
        "VolumeType" = $ec2UnattachedVolume.VolumeType
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }

      foreach ($tag in $ec2UnattachedVolume.Tags) { 
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
        if($key -ne "Name"){ 
          $ec2UnVolObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force 
        } 
      }

      $ec2UnattachedVolList.Add($ec2UnVolObj) | Out-Null
      Write-Progress -ID 5 -Activity "Processing unattached EC2 volume: $($ec2UnattachedVolume.VolumeId)" -Completed
    }
    
    $rdsDBs = $null
    try{
      $rdsDBs = Get-RDSDBInstance -Credential $cred -region $awsRegion -ErrorAction Stop
    } catch {
      Write-Host "Failed to get RDS Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Ingest RDS Databases
    $counter = 1
    foreach ($rds in $rdsDBs) {
      Write-Progress -ID 6 -Activity "Processing RDS database: $($rds.DBInstanceIdentifier)" -Status "RDS database $($counter) of $($rdsDBs.Count)" -PercentComplete (($counter / $rdsDBs.Count) * 100)
      $counter++
      $rdsObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "DBName" = $rds.DBName
        "DBInstanceIdentifier" = $rds.DBInstanceIdentifier
        "SizeGiB" = $rds.AllocatedStorage
        "SizeTiB" = [math]::round($($rds.AllocatedStorage / 1024), 4)
        "SizeGB" = [math]::round($($rds.AllocatedStorage * 1.073741824), 3)
        "SizeTB" = [math]::round($($rds.AllocatedStorage * 0.001073741824), 4)
        "Region" = $awsRegion
        "InstanceType" = $rds.DBInstanceClass
        "Engine" = $rds.Engine
        "EngineVersion" = $rds.EngineVersion
        "DBInstanceStatus" = $rds.DBInstanceStatus
        "BackupPlans" = ""
        "InBackupPlan" = $false
        "BackupRetentionPeriod" = $rds.BackupRetentionPeriod
        "PreferredBackupWindow" = $rds.PreferredBackupWindow
        "StorageType" = $rds.StorageType
      }

      foreach ($tag in $rds.TagList) { 
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
        if($key -ne "Name"){ 
          $rdsObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force 
        } 
      }

      $rdsList.Add($rdsObj) | Out-Null
    }
    Write-Progress -ID 6 -Activity "Processing RDS database: $($rds.DBInstanceIdentifier)" -Completed

    $efsListFromAPI = $null
    try{
      $efsListFromAPI = Get-EFSFileSystem -Credential $cred -region $awsRegion -ErrorAction Stop
    } catch {
      Write-Host "Failed to get EFS Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }    
#Ingest EFS Filesystems
    $counter = 1
    foreach ($efs in $efsListFromAPI) {
      Write-Progress -ID 7 -Activity "Processing EFS file system: $($efs.Name)" -Status "EFS file system $($counter) of $($efsListFromAPI.Count)" -PercentComplete (($counter / $efsListFromAPI.Count) * 100)
      $counter++
      $efsObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "FileSystemId" = $efs.FileSystemId
        "FileSystemProtection" = $efs.FileSystemProtection.ReplicationOverwriteProtection.Value
        "Name" = $efs.Name
        "SizeInBytes" = $efs.SizeInBytes.Value
        "SizeGiB" = [math]::round($($efs.SizeInBytes.Value / 1073741824), 4)
        "SizeTiB" = [math]::round($($efs.SizeInBytes.Value / 1073741824 / 1024), 4)
        "SizeGB" = [math]::round($($efs.SizeInBytes.Value / 1000000000), 4)
        "SizeTB" = [math]::round($($efs.SizeInBytes.Value / 1000000000000), 4)
        "NumberOfMountTargets" = $efs.NumberOfMountTargets
        "OwnerId" = $efs.OwnerId
        "PerformanceMode" = $efs.PerformanceMode
        "ProvisionedThroughputInMibps" = $efs.ProvisionedThroughputInMibps
        "DBInstanceIdentifier" = $efs.DBInstanceIdentifier
        "Region" = $awsRegion
        "ThroughputMode" = $efs.ThroughputMode
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }

      foreach ($tag in $efs.Tags) { 
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
        if($key -ne "Name"){ 
          $efsObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force 
        } 
      }

      $efsList.Add($efsObj) | Out-Null
    }
    Write-Progress -ID 7 -Activity "Processing EFS file system: $($efs.Name)" -Completed

    $eksListFromAPI = $null
    try{
      $eksListFromAPI = Get-EKSClusterList -Credential $cred -region $awsRegion -ErrorAction Stop
    } catch {
      Write-Host "Failed to get EKS Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }    
#Ingest EKS clusters. Do we need this information at all?
    $counter = 1
    foreach ($eks in $eksListFromAPI) {
      try{
        $eks = Get-EKSCluster -Credential $cred -region $awsRegion -Name $eks -ErrorAction Stop
      } catch {
        Write-Host "Failed to get EKS node group for node group $($nodeGroup.NodegroupName) in cluster $($eks.Name) for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }  
      Write-Progress -ID 8 -Activity "Processing EKS Cluster: $($eks.Name)" -Status "EKS Cluster $($counter) of $($eksListFromAPI.Count)" -PercentComplete (($counter / $eksListFromAPI.Count) * 100)
      $counter++
      $eksObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "Name" = $eks.Name
        "Version" = $eks.Version
        "PlatformVersion" = $eks.PlatformVersion
        "Status" = $eks.Status.Value
        "Arn" = $eks.Arn
        "RoleArn" = $eks.RoleArn
        "Region" = $awsRegion
      }
      # Note: As of August 2024, cannot add EKS to a backup plan, hence those fields are not here

      $tagCounter = 0
      foreach($key in $eks.Tags.Keys){
        $value = $eks.Tags.Values.Split('\n')[$tagCounter]
        $key = $key -replace '[^a-zA-Z0-9]', '_' 
        $eksObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $value -Force 
        $tagCounter++
      }
      
      $eksList.Add($eksObj) | Out-Null

      $eksNodeGroupListFromCluster = $null
      try{
        $eksNodeGroupListFromCluster = Get-EKSNodegroupList -Credential $cred -region $awsRegion -ClusterName $eks.Name -ErrorAction Stop
      } catch {
        Write-Host "Failed to get EKS Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }    

      foreach($nodeGroup in $eksNodeGroupListFromCluster){
        try{
          $eksNodeGroup = Get-EKSNodegroup -Credential $cred -region $awsRegion -ClusterName $eks.Name -NodegroupName $nodeGroup -ErrorAction Stop
        } catch {
          Write-Host "Failed to get EKS node group for node group $($nodeGroup.NodegroupName) in cluster $($eks.Name) for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }   
        $eksNodeGroupObj = [PSCustomObject] @{
          "AwsAccountId" = $awsAccountInfo.Account
          "AwsAccountAlias" = $awsAccountAlias
          "NodegroupName" = $eksNodeGroup.NodegroupName
          "ClusterName" = $eksNodeGroup.ClusterName
          "DiskSize" = $eksNodeGroup.DiskSize
          "CapacityType" = $eksNodeGroup.CapacityType
          "AmiType" = $eksNodeGroup.AmiType
          "NodegroupArn" = $eksNodeGroup.NodegroupArn
          "NodeRole" = $eksNodeGroup.NodeRole
          "Status" = $eksNodeGroup.Status
          "ReleaseVersion" = $eksNodeGroup.ReleaseVersion
          "Version" = $eksNodeGroup.Version
          "Region" = $awsRegion
        }

        $tagCounter = 0
        foreach($key in $eksNodeGroup.Tags.Keys){
          $value = $eksNodeGroup.Tags.Values.Split('\n')[$tagCounter]
          $key = $key -replace '[^a-zA-Z0-9]', '_' 
          $eksNodeGroupObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $value -Force  
          $tagCounter++
        }
  
        $eksNodeGroupList.Add($eksNodeGroupObj) | Out-Null
      }

    }
    Write-Progress -ID 8 -Activity "Processing EKS Cluster: $($eks.Name)" -Completed
    
    $fsxFileSystemListFromAPI = $null
    try{
      $fsxFileSystemListFromAPI = Get-FSXFileSystem -Credential $cred -region $awsRegion -ErrorAction Stop
    } catch {
      Write-Host "Failed to get FSX File System Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Ingest FSX File systems
    $counter = 1
    foreach ($fileSystem in $fsxFileSystemListFromAPI) {
      Write-Progress -ID 9 -Activity "Processing FSx file system: $($fileSystem.DNSName)" -Status "FSx file system $($counter) of $($fsxFileSystemListFromAPI.Count)" -PercentComplete (($counter / $fsxFileSystemListFromAPI.Count) * 100)
      $counter++
      $fsxObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "Region" = $awsRegion
        "FileSystemId" = $filesystem.FileSystemId
        "FileSystemDNSName" = $filesystem.DNSName
        "FileSystemType" = $filesystem.FileSystemType.Value
        "FileSystemTypeVersion" = $filesystem.FileSystemTypeVersion
        "FileSystemOwnerId" = $filesystem.OwnerId
        "FileSystemStorageType" = $filesystem.StorageType
        "Name" = $filesystem.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
        "OnTapType" = ($null -ne $filesystem.OntapConfiguration)
        "WindowsType" = ($null -ne $filesystem.WindowsConfiguration)
        "LustreType" = ($null -ne $filesystem.LustreConfiguration)
        "OpenZFSType" = ($null -ne $filesystem.OpenZFSConfiguration)
        "StorageCapacityBytes" = $filesystem.StorageCapacity * 1073741824
        "StorageCapacityGiB" = $filesystem.StorageCapacity
        "StorageCapacityTiB" = [math]::round($($filesystem.StorageCapacity / 1024), 4)
        "StorageCapacityGB" = [math]::round($($filesystem.StorageCapacity * 1073741824 / 1000000000), 4)
        "StorageCapacityTB" = [math]::round($($filesystem.StorageCapacity * 1073741824 / 1000000000000), 4)
      }
      $namespace = "AWS/FSx"
      $dimensions = @(
        @{
          Name = "FileSystemId"
          Value = $filesystem.FileSystemId
        }
      )
      $metrics = $null
      if($fsxObj.OnTapType -eq $true){
        $metricName = "StorageUsed"
        $metrics = $null
        try{
          $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $storageUsed = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
        $maxStorageUsed = $storageUsed.Maximum

        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedBytes" -Value $maxStorageUsed -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedGiB" -Value $([math]::round($($maxStorageUsed / 1073741824), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedTiB" -Value $([math]::round($($maxStorageUsed / 1073741824 / 1024), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedGB" -Value $([math]::round($($maxStorageUsed / 1000000000), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedTB" -Value $([math]::round($($maxStorageUsed / 1000000000000), 4)) -Force

      } elseif($fsxObj.WindowsType -eq $true){
        $metricName = "StorageCapacityUtilization"
        try{
          $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $storageCapacityUtil = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
        $maxStorageCapacityUtil = $storageCapacityUtil.Maximum
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageCapacityUtilizationPercentage" -Value $maxStorageCapacityUtil -Force

      } elseif($fsxObj.LustreType -eq $true){

        # Getting Sum instead of Maximum for these statistics as Maximum is max for any disk,
        # whereas sum sums the space across all disks
        $metricName = "PhysicalDiskUsage"
        
        $metrics = $null
        try{
          $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Sum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $physicalDiskUsage = $metrics.Datapoints | Sort-Object -Property Sum -Descending | Select-Object -Index 0
        $maxPhysicalDiskUsage = $storageUsed.Sum

        $metricName = "LogicalDiskUsage"
        
        $metrics = $null
        try{
          $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Sum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $logicalDiskUsage = $metrics.Datapoints | Sort-Object -Property Sum -Descending | Select-Object -Index 0
        $maxLogicalDiskUsage = $storageUsed.Sum

        $metricName = "FreeDataStorageCapacity"
        $metrics = $null
        try{
          $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -UtcStartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Sum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
#        $freeDataStorageCapacity = $metrics.Datapoints | Sort-Object -Property Sum -Descending | Select-Object -Index 0
        $minFreeDataStorageCapacity = $storageUsed.Sum

        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageBytes" -Value $maxPhysicalDiskUsage -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageGiB" -Value $([math]::round($($maxPhysicalDiskUsage / 1073741824), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageTiB" -Value $([math]::round($($maxPhysicalDiskUsage / 1073741824 / 1024), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageGB" -Value $([math]::round($($maxPhysicalDiskUsage / 1000000000), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageTB" -Value $([math]::round($($maxPhysicalDiskUsage / 1000000000000), 4)) -Force

        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageBytes" -Value $maxLogicalDiskUsage -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageGiB" -Value $([math]::round($($maxLogicalDiskUsage / 1073741824), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageTiB" -Value $([math]::round($($maxLogicalDiskUsage / 1073741824 / 1024), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageGB" -Value $([math]::round($($maxLogicalDiskUsage / 1000000000), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageTB" -Value $([math]::round($($maxLogicalDiskUsage / 1000000000000), 4)) -Force

        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityBytes" -Value $minFreeDataStorageCapacity -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityGiB" -Value $([math]::round($($minFreeDataStorageCapacity / 1073741824), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityTiB" -Value $([math]::round($($minFreeDataStorageCapacity / 1073741824 / 1024), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityGB" -Value $([math]::round($($minFreeDataStorageCapacity / 1000000000), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityTB" -Value $([math]::round($($minFreeDataStorageCapacity / 1000000000000), 4)) -Force

      } elseif($fsxObj.OpenZFSType -eq $true) {
        $metricName = "UsedStorageCapacity"
        $metrics = $null
        try{
          $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -UtcStartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $storageUsed = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
        $maxStorageUsed = $storageUsed.Maximum

        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityBytes" -Value $maxStorageUsed -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityGiB" -Value $([math]::round($($maxStorageUsed / 1073741824), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityTiB" -Value $([math]::round($($maxStorageUsed / 1073741824 / 1024), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityGB" -Value $([math]::round($($maxStorageUsed / 1000000000), 4)) -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityTB" -Value $([math]::round($($maxStorageUsed / 1000000000000), 4)) -Force

      }

      foreach ($tag in $fileSystem.Tags) { 
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
        if($key -ne "Name"){ 
          $fsxObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force 
        } 
      }
      $fsxFileSystemList.Add($fsxObj) | Out-Null
    }
    Write-Progress -ID 9 -Activity "Processing FSx file system: $($fileSystem.DNSName)" -Completed

    $fsxListFromAPI = $null
    try{
      $fsxListFromAPI = Get-FSXVolume -Credential $cred -region $awsRegion -ErrorAction Stop
    } catch {
      Write-Host "Failed to get FSX Volume Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    $counter = 1
    foreach ($fsx in $fsxListFromAPI) {
      Write-Progress -ID 10 -Activity "Processing FSx volume: $($fsx.VolumeId)" -Status "FSx volume $($counter) of $($fsxListFromAPI.Count)" -PercentComplete (($counter / $fsxListFromAPI.Count) * 100)
      $counter++
      $namespace = "AWS/FSx"
      $metricName = "StorageUsed"
      $dimensions = @(
        @{
          Name = "FileSystemId"
          Value = $fsx.FileSystemId
        }
        @{
            Name = "VolumeId"
            Value = $fsx.VolumeId
          }
      )
      $metrics = $null
      try{
        $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -UtcStartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
      } catch {
        Write-Host "Failed to get FSX File Volume $($fsx.VolumeId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $storageUsed = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
      $maxStorageUsed = $storageUsed.Maximum

      $metricName = "StorageCapacity"
      $metrics = $null
      try{
        $metrics = Get-CWMetricStatistics -Region $awsRegion -Credential $cred -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -UtcStartTime $utcStartTime -EndTime $utcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
      } catch {
        Write-Host "Failed to get FSX File Volume $($fsx.VolumeId) Size Info for region $awsRegion in account $($awsAccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $storageCapacity = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
      $maxStorageCapacity = $storageCapacity.Maximum

      $filesystem = $null
      try{
        $filesystem = Get-FSXFileSystem -Credential $cred -region $awsRegion -FileSystemId $fsx.FileSystemId -ErrorAction Stop
      } catch {
        Write-Host "Failed to get FSX File System $($fsx.FileSystemId) Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }

      $fsxObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "Region" = $awsRegion
        "FileSystemId" = $fsx.FileSystemId
        "FileSystemDNSName" = $filesystem.DNSName
        "FileSystemType" = $filesystem.FileSystemType
        "FileSystemTypeVersion" = $filesystem.FileSystemTypeVersion
        "FileSystemOwnerId" = $filesystem.OwnerId
        "FileSystemStorageType" = $filesystem.StorageType
        "Name" = $fsx.Name
        "VolumeId" = $fsx.VolumeId
        "VolumeType" = $fsx.VolumeType
        "LifeCycle" = $fsx.LifeCycle
        "StorageUsedBytes" = $maxStorageUsed
        "StorageUsedGiB" = [math]::round($($maxStorageUsed / 1073741824), 4)
        "StorageUsedTiB" = [math]::round($($maxStorageUsed / 1073741824 / 1024), 4)
        "StorageUsedGB" = [math]::round($($maxStorageUsed / 1000000000), 4)
        "StorageUsedTB" = [math]::round($($maxStorageUsed / 1000000000000), 4)
        "StorageCapacityBytes" = $maxStorageCapacity
        "StorageCapacityGiB" = [math]::round($($maxStorageCapacity / 1073741824), 4)
        "StorageCapacityTiB" = [math]::round($($maxStorageCapacity / 1073741824 / 1024), 4)
        "StorageCapacityGB" = [math]::round($($maxStorageCapacity / 1000000000), 4)
        "StorageCapacityTB" = [math]::round($($maxStorageCapacity / 1000000000000), 4)
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }

      foreach ($tag in $fsx.Tags) { 
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_' 
        if($key -ne "Name"){ 
          $fsxObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force 
        } 
      }

      $fsxList.Add($fsxObj) | Out-Null
    }
    Write-Progress -ID 10 -Activity "Processing FSx volume: $($fsx.VolumeId)" -Status "FSx volume $($counter) of $($fsxListFromAPI.Count)" -Completed
#Start ingesting KMS key information
    try{
      $numberOfKMS = (Get-KMSKeyList -Region $awsRegion -ErrorAction Stop).Count
      $keyObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "Region" = $awsRegion
        "Keys" = $numberOfKMS
      }
      $kmsList.Add($keyObj) | Out-Null
    } catch{
      Write-Host "Failed to get # of KMS keys for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Start ingesting SecretsManager information
    try{
      $numberOfSecrets = (Get-SECSecretList -Region $awsRegion -ErrorAction Stop).Count
      $secretsObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "Region" = $awsRegion
        "Secrets" = $numberOfSecrets
      }
      $secretsList.Add($secretsObj) | Out-Null
    } catch{
      Write-Host "Failed to get # of secrets for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
  #Ingest SQS Queues
    try{
      $numberOfSQSQueues = (Get-SQSQueue -Region $awsRegion -ErrorAction Stop).Count
      $sqsObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "Region" = $awsRegion
        "Queues" = $numberOfSQSQueues
      }
      $sqsList.Add($sqsObj) | Out-Null
    } catch{
      Write-Host "Failed to get # of SQS Queues for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Ingest DynamoDB Databases
    $ddbListFromAPI = $null
    try{
      $ddbListFromAPI = Get-DDBTableList -Credential $cred -region $awsRegion -ErrorAction Stop
    } catch {
      Write-Host "Failed to get DynamoDB Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    foreach($ddbName in $ddbListFromAPI){

      $ddbItem = $null
      try{
        $ddbItem = Get-DDBTable -TableName $ddbName -Credential $cred -region $awsRegion -ErrorAction Stop
      } catch {
        Write-Host "Failed to get DynamoDB Table $($ddbName) Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }

      $ddbObj = [PSCustomObject] @{
        "AwsAccountId" = $awsAccountInfo.Account
        "AwsAccountAlias" = $awsAccountAlias
        "Region" = $awsRegion
        "TableName" = $ddbItem.TableName
        "TableId" = $ddbItem.TableId
        "TableArn" = $ddbItem.TableArn
        "TableSizeBytes" = $ddbItem.TableSizeBytes
        "TableStatus" = $ddbItem.TableStatus.Value
        "TableSizeGiB" = [math]::round($($ddbItem.TableSizeBytes / 1073741824), 4)
        "TableSizeTiB" = [math]::round($($ddbItem.TableSizeBytes / 1073741824 / 1024), 4)
        "TableSizeGB" = [math]::round($($ddbItem.TableSizeBytes/ 1000000000), 4)
        "TableSizeTB" = [math]::round($($ddbItem.TableSizeBytes / 1000000000000), 4)
        "ItemCount" = $ddbItem.ItemCount
        "DeletionProtectionEnabled" = $ddbItem.DeletionProtectionEnabled
        "GlobalTableVersion" = $ddbItem.GlobalTableVersion
        "ProvisionedThroughputLastDecreaseDateTime" = $ddbItem.ProvisionedThroughput.LastDecreaseDateTime
        "ProvisionedThroughputLastIncreaseDateTime" = $ddbItem.ProvisionedThroughput.LastIncreaseDateTime
        "ProvisionedThroughput.NumberOfDecreasesToday" = $ddbItem.ProvisionedThroughput.NumberOfDecreasesToday
        "ProvisionedThroughputReadCapacityUnits" = $ddbItem.ProvisionedThroughput.ReadCapacityUnits
        "ProvisionedThroughputWriteCapacityUnits" = $ddbItem.ProvisionedThroughput.WriteCapacityUnits
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      $ddbList.add($ddbObj) | Out-Null

    }
#Ingest AWS Backup Plans and evaluate protected resources
    $BackupPlans = $null
    try{
      $BackupPlans = Get-BAKBackupPlanList -Credential $cred -region $awsRegion -ErrorAction Stop;
      
    } catch {
      Write-Host "Failed to get Backup Plans Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Custom Object for Protected Backup Objects
<# $protectedBAKobjs = [PSCustomObject] @{
  "AwsAccountId" = $awsAccountInfo.Account
  "AwsAccountAlias" = $awsAccountAlias
  "ResourceName" = $s3Bucket
  "Resource" = "undefined"
  "ResourceType" = "undefined"
  "Region" = $awsRegion
  "RuleName" = "undefined"
  "BackupPlans" = ""
  "BackupVault" = "Default"
  "InBackupPlan" = $false
} #>try {
$protectedBAKobjs = @();
    $counter = 1
    foreach ($plan in $BackupPlans) {
      Write-Progress -ID 11 -Activity "Processing Backup Plan: $($plan.BackupPlanId)" -Status "Plan $($counter) of $($BackupPlans.Count)" -PercentComplete (($counter / $BackupPlans.Count) * 100)
      $counter++
      #Traverse Backup Vaults for protected items
      $backupPlanRules = (Get-BAKBackupPlan -BackupPlanId $plan.BackupPlanId -Credential $cred -region $awsRegion ).BackupPlan.Rules;
      foreach($rule in $backupPlanRules) {
        $vault = Get-BAKBackupVault -BackupVaultName $rule.TargetBackupVaultName -Credential $cred -region $awsRegion ;
        $protectedResourceList = Get-BAKProtectedResourceList -Credential $cred -region $awsRegion  | Where-Object {$_.LastBackupVaultArn -eq $vault.BackupVaultArn }
        #add resource to array .resourceName, .resourcetype
        foreach($resource in $protectedResourceList) {
          $recoveryPointInfo = Get-BAKRecoveryPoint -RecoveryPointArn $resource.LastRecoveryPointArn -BackupVaultName $rule.TargetBackupVaultName -Credential $cred -region $awsRegion ;
          $protectedBAKobjs += [PSCustomObject]@{
            "AWSAccountId" = $awsAccountInfo.Account
            "AWSAccountAlias" = $awsAccountAlias
            "ResourceName" = $resource.ResourceName
            "Resource" = $resource.resourceArn
            "ResourceType" = $resource.ResourceType
            "Region" = $awsRegion
            "RuleName" = $rule.RuleName
            "BackupPlans" = $plan.BackupPlanName
            "BackupVault" = $rule.TargetBackupVaultName
            "BackupSchedule" = $rule.ScheduleExpression
            "LifecycleDelete" = $rule.Lifecycle.DeleteAfterDays
            "LifecycleToColdStorageAfterDays" = $rule.Lifecycle.MoveToColdStorageAfterDays
            "BackupSizeInGiB" = [math]::round($($recoveryPointInfo.BackupSizeInBytes / 1073741824), 4)
            }
        }
      }
      $protectedBAKobjs | export-csv -path ./protected_objects.csv;
      #instance ID from ProtectedObjects List
      #Get-EC2instances will only provide the instance ID



      #Continue remaineder of primary script
      try{
        $BackupPlanObject = (Get-BAKBackupPlan -Credential $cred -region $awsRegion -BackupPlanId $plan.BackupPlanId) | ConvertTo-Json -Depth 10 | ConvertFrom-Json
      } catch {
        Write-Host "Failed to get Backup Plans $($plan.BackupPlanId) for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $BackupPlanObject | Add-Member -MemberType NoteProperty -Name "Resources" -Value @()
      $selections = $null
      try{
        $selections = Get-BAKBackupSelectionList -Credential $cred -region $awsRegion -BackupPlanId $plan.BackupPlanId -ErrorAction Stop
      } catch {
        Write-Host "Failed to get Backup Selections for Plan $($plan.BackupPlanId) for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $selectionCounter = 1
      foreach ($selection in $selections) {
        Write-Progress -ID 12 -Activity "Processing Backup Plan/Selection: $($selection.SelectionId)" -Status "Backup Plan/Selection $($selectionCounter) of $($selections.Count)" -PercentComplete (($selectionCounter / $selections.Count) * 100)
        $selectionCounter++
        try{
          $foundSelection = Get-BakBackupSelection -Credential $cred -region $awsRegion -BackupPlanId $plan.BackupPlanId -SelectionId $selection.SelectionId
        } catch {
          Write-Host "Failed to get Backup Selection $($selection.SelectionId) for Plan $($plan.BackupPlanId) for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $resources = $foundSelection.BackupSelection.Resources
        foreach ($resource in $resources) {
          $BackupPlanObject.Resources += $resource
          $type = ($resource -split ':')[2]
          switch ($type) {
            "ec2" {
              $EC2Id = ($resource -split ':')[5] -split '/' # format: volume/vol-0000 or instance/i-0000
              switch ($EC2Id[0]) {
                "instance" {
                  $instanceId = $EC2Id[1]
                  foreach ($ec2Obj in $ec2List) {
                    # Instance id will be fetched as * if all instances are backed up
                    if (($ec2Obj.InstanceId -eq $instanceId -or "*" -eq $instanceId) -and $awsRegion -eq $ec2Obj.Region -and $awsAccountInfo.Account -eq $ec2Obj.AwsAccountId) {
                      if ("" -eq $ec2Obj.BackupPlans) {
                          $ec2Obj.BackupPlans = "$($plan.BackupPlanName)"
                      }
                      else {
                          $ec2Obj.BackupPlans += ", $($plan.BackupPlanName)"
                      }
                      $ec2Obj.InBackupPlan = $true
                    }
                  }
                }
                "volume" {
                  $volId = $EC2Id[1]
                  foreach ($ec2Obj in $ec2UnattachedVolumes) {
                    # Volume id will be fetched as * if all ebs volumes are backed up
                    if (($ec2Obj.VolumeId -eq $volId -or "*" -eq $volId) -and $awsRegion -eq $ec2Obj.Region -and $awsAccountInfo.Account -eq $ec2Obj.AwsAccountId) {
                      if ("" -eq $ec2Obj.BackupPlans) {
                          $ec2Obj.BackupPlans = "$($plan.BackupPlanName)"
                      }
                      else {
                          $ec2Obj.BackupPlans += ", $($plan.BackupPlanName)"
                      }
                      $ec2Obj.InBackupPlan = $true
                    }
                  }
                }
              }
            }
            "rds" {
                $RDSId = ($resource -split ':')[6]
                foreach ($rdsObj in $rdsList) {
                  if (($rdsObj.DBInstanceIdentifier -eq $RDSId -or "*" -eq $RDSId) -and $awsRegion -eq $rdsObj.Region -and $awsAccountInfo.Account -eq $rdsObj.AwsAccountId) {
                    if ("" -eq $rdsObj.BackupPlans) {
                        $rdsObj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $rdsObj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $rdsObj.InBackupPlan = $true
                  }
                }
            } 
            "elasticfilesystem" {
              $EFSId = ($resource -split '/')[1]
                foreach ($efsObj in $efsList) {
                  if (($efsObj.FileSystemId -eq $EFSId -or "*" -eq $EFSId) -and $awsRegion -eq $efsObj.Region -and $awsAccountInfo.Account -eq $efsObj.AwsAccountId) {
                    if ("" -eq $efsObj.BackupPlans) {
                        $efsObj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $efsObj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $efsObj.InBackupPlan = $true
                  }
                }
            }
            "fsx" {
              # arn:*:fsx:* in the case of 'all fsx's'
              if(($resource -split ':')[-1] -eq "*") {
                foreach ($fsxObj in $fsxList) {
                  if ($awsRegion -eq $fsxObj.Region -and $awsAccountInfo.Account -eq $fsxObj.AwsAccountId) {
                    if ("" -eq $fsxObj.BackupPlans) {
                        $fsxObj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $fsxObj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $fsxObj.InBackupPlan = $true
                  }
                }
              } else {
                $FSXInfo = ($resource -split '/')
                $FileSystemId = $FSXInfo[1]
                $VolumeId = $FSXInfo[2]
                foreach ($fsxObj in $fsxList) {
                  if ($fsxObj.VolumeId -eq $VolumeId -and $fsxObj.FileSystemId -eq $FileSystemId -and $awsRegion -eq $fsxObj.Region -and $awsAccountInfo.Account -eq $fsxObj.AwsAccountId) {
                    if ("" -eq $fsxObj.BackupPlans) {
                        $fsxObj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $fsxObj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $fsxObj.InBackupPlan = $true
                  }
                }
              }
            }
            "s3" {
              # arn:aws:s3:::* in the case of 'all s3's'
              if(($resource -split ':')[-1] -eq "*") {
                foreach ($s3Obj in $s3List) {
                  if ($awsRegion -eq $s3Obj.Region -and $awsAccountInfo.Account -eq $s3Obj.AwsAccountId) {
                    if ("" -eq $s3Obj.BackupPlans) {
                        $s3Obj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $s3Obj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $s3Obj.InBackupPlan = $true
                  }
                }
              } else {
                $S3Name = ($resource -split '/')[1]
                foreach ($s3Obj in $s3List) {
                  if ($s3Obj.BucketName -eq $S3Name -and $awsRegion -eq $s3Obj.Region -and $awsAccountInfo.Account -eq $s3Obj.AwsAccountId) {
                    if ("" -eq $s3Obj.BackupPlans) {
                        $s3Obj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $s3Obj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $s3Obj.InBackupPlan = $true
                  }
                }
              }
            }
            "dynamodb" {
              if(($resource -split ':')[-1] -eq "*") {
                foreach ($ddbObj in $ddbList) {
                  if ($awsRegion -eq $ddbObj.Region -and $awsAccountInfo.Account -eq $ddbObj.AwsAccountId) {
                    if ("" -eq $ddbObj.BackupPlans) {
                        $ddbObj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $ddbObj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $ddbObj.InBackupPlan = $true
                  }
                }
              } else {
                $ddbName = ($resource -split '/')[1]
                foreach ($ddbObj in $ddbList) {
                  if ($ddbObj.BucketName -eq $ddbName -and $awsRegion -eq $ddbObj.Region -and $awsAccountInfo.Account -eq $ddbObj.AwsAccountId) {
                    if ("" -eq $ddbObj.BackupPlans) {
                        $ddbObj.BackupPlans = "$($plan.BackupPlanName)"
                    }
                    else {
                        $ddbObj.BackupPlans += ", $($plan.BackupPlanName)"
                    }
                    $ddbObj.InBackupPlan = $true
                  }
                }
              }
            }
          }
        }
      }
      Write-Progress -ID 12 -Activity "Processing Backup Plan/Selection: $($selection.SelectionId)" -Completed
      $backupPlanList.Add($BackupPlanObject) | Out-Null
    }
  } catch { 
    Write-Host "Failed to query backup vaults for region $awsRegion";
  }
    Write-Progress -ID 11 -Activity "Processing Backup Plan: $($plan.BackupPlanId)" -Completed
  }
  
  $filter = @{
    Dimensions = @{
        Key = "SERVICE"
        Values = @("AWS Backup")
    }
  }

  # Create a date interval for past 12 months
  $startDate = (Get-Date).AddMonths(-12).ToString("yyyy-MM-01")
  $endDate = (Get-Date).ToString("yyyy-MM-dd")
  $timePeriod = @{
      Start = $startDate
      End = $endDate
  }

  $metrics = @("AmortizedCost", "BlendedCost", "NetAmortizedCost", "NetUnblendedCost", "NormalizedUsageAmount", "UnblendedCost", "UsageQuantity")

  $result = @{ResultsByTime = @()}
  try{
    $result = Get-CECostAndUsage `
      -TimePeriod $timePeriod `
      -Granularity MONTHLY `
      -Metrics $metrics `
      -Filter $filter -Credential $cred -Region $awsRegion -ErrorAction Stop
  } catch {
    Write-Host "Failed to get Backup Plans Info for region $awsRegion in account $($awsAccountInfo.Account)" -ForeGroundColor Red
    Write-Host "Error: $_" -ForeGroundColor Red
  }

  $counter = 1
  foreach ($resultItem in $result.ResultsByTime) {
    Write-Progress -ID 13 -Activity "Processing Cost and Usage of Backup for Month: $($resultItem.TimePeriod.Start)" -Status "Item $($counter) of $($result.ResultsByTime.Count)" -PercentComplete (($counter / $result.ResultsByTime.count) * 100)
    $counter++
    $monthCostObj = [PSCustomObject] @{
      "AwsAccountId" = $awsAccountInfo.Account
      "AwsAccountAlias" = $awsAccountAlias
      "Time-Period-Start" = $resultItem.TimePeriod.Start
      "Time-Period-End" = $resultItem.TimePeriod.End
    }
    foreach ($metric in $metrics) {
        if ($metric -like "*Cost") {
          $cost = "$" + "$([math]::round($resultItem.Total[$metric].Amount, 2))"
        } else {
          $cost = "$([math]::round($resultItem.Total[$metric].Amount, 3))"
        }
        $monthCostObj | Add-Member -MemberType NoteProperty -Name "AWSBackup${metric}" -Value "$cost"
    }
    $backupCostsList.Add($monthCostObj) | Out-Null
  }
  Write-Progress -ID 13 -Activity "Processing Cost and Usage of Backup for Month: $($resultItem.TimePeriod.Start)" -Completed 
}
Write-Progress -ID 2 -Activity "Processing region: $($awsRegion)" -Completed


# Contains list of EC2 instances and RDS with capacity info

$ec2List = New-Object collections.arraylist
$ec2UnattachedVolList = New-Object collections.arraylist
$rdsList = New-Object collections.arraylist
$s3List = New-Object collections.arraylist
$efsList = New-Object collections.arraylist
$fsxFileSystemList = New-Object collections.arraylist
$fsxList = New-Object collections.arraylist
$ddbList = New-Object collections.arraylist
$secretsList = New-Object collections.arraylist
$kmsList = New-Object collections.arraylist
$sqsList = New-Object collections.arraylist
$backupCostsList = New-Object collections.arraylist
$backupPlanList = New-Object collections.arraylist
$eksNodeGroupList = New-Object collections.arraylist
$eksList = New-Object collections.arraylist

try{
if ($RegionToQuery) {
  $queryRegion = $RegionToQuery
  write-host "Set region to query"
}
elseif ($Partition -eq 'GovCloud') {
  $queryRegion = $defaultGovCloudQueryRegion
  $partitionId = 'aws-us-gov'
}
else {
  $queryRegion = $defaultQueryRegion
  $partitionId = 'aws'
}


if ($PSCmdlet.ParameterSetName -eq 'DefaultProfile') {
# Verify that there is a credential/profile to work with.
  try {
    $caller = $(Get-STSCallerIdentity @profileLocationOpt -Region $queryRegion).arn
  } catch {
    Write-Error $_
    Write-Error "Default credential/profile not set."
    Write-Error "Run Set-AWSCredential to set."
    exit 1
  }
  Write-Host
  Write-Host "Source Profile/Credential is: $caller"  -ForegroundColor Green
  try {
    $cred = Get-AWSCredential @profileLocationOpt
  } catch {
    Write-Error $_
    Write-Error "Unable to gather credential data from AWS."
    exit 1
  }
  getAWSData $cred
}
elseif ($PSCmdlet.ParameterSetName -eq 'UserSpecifiedProfiles') {
  # Get AWS Info based on user supplied list of profiles
  [string[]]$awsProfiles = $UserSpecifiedProfileNames.split(',')
  $accountCounter = 1
  foreach ($awsProfile in $awsProfiles) {
    Write-Host
    Write-Host "Using profile: $awsProfile"  -ForegroundColor Green
    try {
      $cred = Get-AWSCredential @profileLocationOpt -ProfileName $awsProfile
    } catch {
      Write-Error $_
      Write-Error "Unable to gather credential data from AWS for profile $($awsProfile)."
      exit 1
    }

    Write-Progress -ID 1 -Activity "Processing profile: $($awsProfile)" -Status "Profile: $($accountCounter) of $($awsProfiles.Count)"  -PercentComplete (($accountCounter / $awsProfiles.Count) * 100)
    $accountCounter++

    getAWSData $cred
  }
  Write-Progress -ID 1 -Activity "Processing profile: $($awsProfile)" -Completed
} 
elseif ($PSCmdlet.ParameterSetName -eq 'AllLocalProfiles') {
  $awsProfiles = $(Get-AWSCredential @profileLocationOpt -ListProfileDetail).ProfileName
  $accountCounter = 1
  foreach ($awsProfile in $awsProfiles) {
    Write-Host
    Write-Host "Using profile: $awsProfile"  -ForegroundColor Green
    Set-AWSCredential @profileLocationOpt -ProfileName $awsProfile
    $cred = Get-AWSCredential @profileLocationOpt -ProfileName $awsProfile

    Write-Progress -ID 1 -Activity "Processing profile: $($awsProfile)" -Status "Profile: $($accountCounter) of $($awsProfiles.Count)" -PercentComplete (($accountCounter / $awsProfiles.Count) * 100)
    $accountCounter++

    getAWSData $cred
  }
  Write-Progress -ID 1 -Activity "Processing profile: $($awsProfile)" -Completed
}
elseif ($PSCmdlet.ParameterSetName -eq 'AWSOrganization') {
# Verify that there is a credential/profile to work with.
  try {
    $caller = $(Get-STSCallerIdentity @profileLocationOpt -Region $queryRegion).arn
  } catch {
    Write-Error $_
    Write-Error "Credential/profile to query the AWS Organization in $($queryRegion) not set."
    Write-Error "Run Set-AWSCredential to set the credential and verify that the correct Partition or RegionToQuery is set."
    exit 1
  } 
  Write-Host "Source Profile/Credential is: $caller"
  if ($UserSpecifiedAccounts -and $UserSpecifiedAccountsFile) {
    Write-Error "Only -UserSpecifiedAccounts or -UserSpecifiedAccountsFile can be specified, not both."
    exit 1
  }
  if ($UserSpecifiedAccountsFile) {
    $userAwsAccounts = Get-Content -Path $UserSpecifiedAccountsFile
    try {
      $awsAccounts = Get-ORGAccountList @profileLocationOpt -Region $queryRegion | Where-Object {$_.ID -in $($userAwsAccounts)}
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to gather data from AWS Organization for user specified accounts from file."
      exit 1
    }
  } elseif ($UserSpecifiedAccounts) {
    try {
      $awsAccounts = Get-ORGAccountList @profileLocationOpt -Region $queryRegion | Where-Object {$_.ID -in $UserSpecifiedAccounts.split(',')}
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to gather data from AWS Organization for user specified accounts."
      exit 1
    }
  } else {
    try {
      $awsAccounts = Get-ORGAccountList @profileLocationOpt -Region $queryRegion
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to gather data from AWS Organization."
      exit 1
    }
  }

  $accountCounter = 1
  foreach ($awsAccount in $awsAccounts) {
    Write-Progress -ID 1 -Activity "Processing account: $($awsAccount.Id):$($awsAccount.Name)" -Status "Account: $($accountCounter) of $($awsAccounts.Count)" -PercentComplete (($accountCounter / $awsAccounts.Count) * 100)
    $accountCounter++

    $roleArn = "arn:$($partitionId):iam::" + $awsAccount.Id + ":role/" + $OrgCrossAccountRoleName
    try {
      $cred = (Use-STSRole @profileLocationOpt -RoleArn $roleArn -RoleSessionName $MyInvocation.MyCommand.Name -Region $queryRegion).Credentials
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to gather data from AWS account $($awsAccount.Id)."
      continue
    }

    getAWSData $cred
  }
  Write-Progress -ID 1 -Activity "Processing account: $($awsAccount.Id):$($awsAccount.Name)" -Completed
}
elseif ($PSCmdlet.ParameterSetName -eq 'AWSSSO') {
  try {
    $SSOOIDCClient = $(Register-SSOOIDCClient @profileLocationOpt -ClientName $MyInvocation.MyCommand -ClientType 'public' -Region $SSORegion)
  } catch {
    Write-Host ""
    Write-Error "An error occurred:"
    Write-Error $_
    Write-Error "Unable to register SSO OIDC Client."
    exit 1
  }

  try {
  $DevAuth = $(Start-SSOOIDCDeviceAuthorization @profileLocationOpt `
                                                -ClientId $SSOOIDCClient.ClientId `
                                                -ClientSecret $SSOOIDCClient.ClientSecret `
                                                -StartUrl $SSOStartURL `
                                                -Region $SSORegion)
  } catch {
    Write-Host ""
    Write-Error "An error occurred:"
    Write-Error $_
    Write-Error "Unable to start with SSO OIDC Authorization for $($SSOStartURL) in region $($SSORegion)."
    exit 1
  }
                                        
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
          $Token = $(New-SSOOIDCToken @profileLocationOpt `
                                      -ClientId $SSOOIDCClient.ClientId `
                                      -ClientSecret $SSOOIDCClient.ClientSecret `
                                      -DeviceCode $DevAuth.DeviceCode `
                                      -GrantType 'urn:ietf:params:oauth:grant-type:device_code' `
                                      -Region $SSORegion)
          break
      } catch [Amazon.SSOOIDC.Model.AuthorizationPendingException] {
          continue #Awaiting auth to be given
      } catch {
        Write-Host ""
        Write-Error "An error occurred:"
        Write-Error $_
        Write-Error "Unable to authenticate with SSO $($SSOStartURL) using SSO parameter set $($SSOParameterSetName) in region $($SSORegion)."
        exit 1
      }
  }

  if ($UserSpecifiedAccounts -and $UserSpecifiedAccountsFile) {
    Write-Error "Only -UserSpecifiedAccounts or -UserSpecifiedAccountsFile can be specified, not both."
    exit 1
  }
  if ($UserSpecifiedAccountsFile) {
    $userAwsAccounts = Get-Content -Path $UserSpecifiedAccountsFile
    $awsAccounts = Get-SSOAccountList @profileLocationOpt `
                                      -AccessToken $Token.AccessToken `
                                      -Region $SSORegion `
                                      | Where-Object {$_.AccountId -in  $($userAwsAccounts)}
  } elseif ($UserSpecifiedAccounts) {
    $awsAccounts = Get-SSOAccountList @profileLocationOpt `
                                      -AccessToken $Token.AccessToken `
                                      -Region $SSORegion `
                                      | Where-Object {$_.AccountId -in $UserSpecifiedAccounts.split(',')}
  } else {
    $awsAccounts = Get-SSOAccountList @profileLocationOpt -AccessToken $Token.AccessToken -Region $SSORegion
  }

  $accountCounter = 1
  foreach ($awsAccount in $awsAccounts) {
    Write-Progress -ID 1 -Activity "Processing account: $($awsAccount.AccountId):$($awsAccount.AccountName)" -Status "Account: $($accountCounter) of $($awsAccounts.Count)" -PercentComplete (($accountCounter / $awsAccounts.Count) * 100)
    $accountCounter++
    try {
      $ssoCred = Get-SSORoleCredential @profileLocationOpt `
                                        -AccessToken $Token.AccessToken `
                                        -AccountId $awsAccount.AccountId `
                                        -RoleName $SSOParameterSetName `
                                        -Region $SSORegion
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to get SSO Credentials for AWS account $($awsAccount.AccountId):$($awsAccount.AccountName) using SSO parameter set: $($SSOParameterSetName)."
      continue
    }
    try {
      $cred = Set-AWSCredential @profileLocationOpt `
                                -AccessKey $ssoCred.AccessKeyId `
                                -SecretKey $ssoCred.SecretAccessKey `
                                -SessionToken $ssoCred.SessionToken
    } catch {
      Write-Host ""
      Write-Error "An error occurred:"
      Write-Error $_
      Write-Error "Unable to get SSO session for AWS account $($awsAccount.AccountId):$($awsAccount.AccountName)."
      continue
    }

    getAWSData $cred
  }
  Write-Progress -ID 1 -Activity "Processing account: $($awsAccount.AccountId):$($awsAccount.AccountName)" -Completed
} 
elseif ($PSCmdlet.ParameterSetName -eq 'CrossAccountRole') {
  # Verify that there is a credential/profile to work with.
    try {
      $caller = $(Get-STSCallerIdentity @profileLocationOpt -Region $queryRegion).arn
    } catch {
      Write-Error $_
      Write-Error "Credential/profile be the source profile for the cross account role not set."
      Write-Error "Run Set-AWSCredential to set."
      exit 1
    }
    Write-Host "Source Profile/Credential is: $caller"

    if ($UserSpecifiedAccounts -and $UserSpecifiedAccountsFile) {
      Write-Error "Only -UserSpecifiedAccounts or -UserSpecifiedAccountsFile can be specified, not both."
      exit 1
    }
    if ($UserSpecifiedAccountsFile) {
      $awsAccounts = Get-Content -Path $UserSpecifiedAccountsFile
    } elseif ($UserSpecifiedAccounts) {
      [string[]]$awsAccounts = $UserSpecifiedAccounts.split(',')
    }
    else {
      Write-Error "-UserSpecifiedAccounts or -UserSpecifiedAccountsFile parameter must be specified."
      exit 1
    }
    $accountCounter = 1
    foreach ($awsAccount in $awsAccounts) {
      Write-Progress -ID 1 -Activity "Processing account: $($awsAccount)" -Status "Account: $($accountCounter) of $($awsAccounts.Count)" -PercentComplete (($accountCounter / $awsAccounts.Count) * 100)
      $accountCounter++
      $roleArn = "arn:$($partitionId):iam::" + $awsAccount + ":role/" + $CrossAccountRoleName
      try {
        $cred = (Use-STSRole @profileLocationOpt -RoleArn $roleArn -RoleSessionName $MyInvocation.MyCommand.Name -Region $queryRegion).Credentials
      } catch {
        Write-Host ""
        Write-Error "An error occurred:"
        Write-Error $_
        Write-Error "Unable to gather data from AWS account $awsAccount."
        continue
      }

      getAWSData $cred
    }
    Write-Progress -ID 1 -Activity "Processing account: $($awsAccount)" -Completed
  }

$ec2TotalGiB = ($ec2list.sizeGiB | Measure-Object -Sum).sum
$ec2TotalTiB = ($ec2list.sizeTiB | Measure-Object -Sum).sum 
$ec2TotalGB = ($ec2list.sizeGB | Measure-Object -Sum).sum
$ec2TotalTB = ($ec2list.sizeTB | Measure-Object -Sum).sum
$ec2InBackupPolicyList = $ec2List | Where-Object { $_.InBackupPlan }
$ec2TotalBackupGiB = ($ec2InBackupPolicyList.sizeGiB | Measure-Object -Sum).sum
$ec2TotalBackupTiB = ($ec2InBackupPolicyList.sizeTiB | Measure-Object -Sum).sum 
$ec2TotalBackupGB = ($ec2InBackupPolicyList.sizeGB | Measure-Object -Sum).sum
$ec2TotalBackupTB = ($ec2InBackupPolicyList.sizeTB | Measure-Object -Sum).sum


$ec2UnVolTotalGiB = ($ec2UnattachedVolList.sizeGiB | Measure-Object -Sum).sum
$ec2UnVolTotalTiB = ($ec2UnattachedVolList.sizeTiB | Measure-Object -Sum).sum
$ec2UnVolTotalGB = ($ec2UnattachedVolList.sizeGB | Measure-Object -Sum).sum
$ec2UnVolTotalTB = ($ec2UnattachedVolList.sizeTB | Measure-Object -Sum).sum
$ec2UnVolInBackupPolicyList = $ec2UnattachedVolList | Where-Object { $_.InBackupPlan }
$ec2UnVolTotalBackupGiB = ($ec2UnVolInBackupPolicyList.sizeGiB | Measure-Object -Sum).sum
$ec2UnVolTotalBackupTiB = ($ec2UnVolInBackupPolicyList.sizeTiB | Measure-Object -Sum).sum 
$ec2UnVolTotalBackupGB = ($ec2UnVolInBackupPolicyList.sizeGB | Measure-Object -Sum).sum
$ec2UnVolTotalBackupTB = ($ec2UnVolInBackupPolicyList.sizeTB | Measure-Object -Sum).sum

$rdsTotalGiB = ($rdsList.sizeGiB | Measure-Object -Sum).sum
$rdsTotalTiB = ($rdsList.sizeTiB | Measure-Object -Sum).sum 
$rdsTotalGB = ($rdsList.sizeGB | Measure-Object -Sum).sum
$rdsTotalTB = ($rdsList.sizeTB | Measure-Object -Sum).sum
$rdsInBackupPolicyList = $rdsList | Where-Object { $_.InBackupPlan }
$rdsTotalBackupGiB = ($rdsInBackupPolicyList.sizeGiB | Measure-Object -Sum).sum
$rdsTotalBackupTiB = ($rdsInBackupPolicyList.sizeTiB | Measure-Object -Sum).sum 
$rdsTotalBackupGB = ($rdsInBackupPolicyList.sizeGB | Measure-Object -Sum).sum
$rdsTotalBackupTB = ($rdsInBackupPolicyList.sizeTB | Measure-Object -Sum).sum

# Grab only unique properties
$s3Props = $s3List.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
# Move the Tag properties to the end of the list and sort
$s3PropsOrdered = $s3Props | Where-Object {$_ -notmatch "Tag:.*"}
$s3PropsOrdered += $s3Props | Where-Object {$_ -match "Tag:.*"} | Sort-Object -Unique

# Normalize the properties to have a consistent format
$s3PropsHash = @{}
foreach($s3PropOrdered in $s3PropsOrdered) {
    $s3PropsHash[$s3PropOrdered] = @{Expression={$_.$s3PropOrdered}}
}
$s3ListNormalized = [System.Collections.ArrayList]@($s3List | Select-Object $s3PropsOrdered)

# Set blank sizes and object counts to 0 for specific properties
foreach($item in $s3ListNormalized) {
  foreach($s3PropOrdered in $s3PropsOrdered) {
      if(($s3PropOrdered -like "*_Size*" -or $s3PropOrdered -like "NumberOfObjects*") -and [string]::IsNullOrEmpty($item.$s3PropOrdered)) {
          $item.$s3PropOrdered = 0
      }
  }
}
if ($DebugBucketTags) {
  $s3Props | Out-File -FilePath "aws_s3Props-$date_string.log"
  $s3ListNormalized | Out-File -FilePath "aws_s3ListsNormalized-$date_string.log"
  $s3List | Out-File -FilePath "aws_s3List-$date_string.log"
}
$s3TBProps = $s3PropsOrdered | Select-String -Pattern "_SizeTB"
if ($DebugBucketTags) {
  $s3PropsOrdered | Out-File -FilePath "aws_s3PropsOrdered-$date_string.log"
}
$s3ListAg = $s3ListNormalized | Select-Object $s3PropsOrdered -CaseInsensitive
if ($DebugBucketTags) {
  $s3ListAg | Out-File -FilePath "aws_s3ListAg-$date_string.log"
}
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

  $s3InBackupPolicyList = $s3List | Where-Object { $_.InBackupPlan }

  $s3BackupProps = $s3InBackupPolicyList.ForEach{ $_.PSObject.Properties.Name } | Select-Object -Unique
  $s3BackupTBProps = $s3BackupProps | Select-String -Pattern "_SizeTB"
  $s3BackupListAg = $s3InBackupPolicyList | Select-Object $s3BackupProps
  $s3BackupTotalTBs = @{}
  
  foreach ($s3TBProp in $s3BackupTBProps) {
    $s3BackupTotalTBs.Add($s3TBProp, ($s3BackupListAg.$s3TBProp | Measure-Object -Sum).Sum)
  }
  
  $s3BackupTotalTBsFormatted  = $s3BackupTotalTBs.GetEnumerator() |
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
  $efsInBackupPolicyList = $efsList | Where-Object { $_.InBackupPlan }
  $efsTotalBackupGiB = ($efsInBackupPolicyList.sizeGiB | Measure-Object -Sum).sum
  $efsTotalBackupTiB = ($efsInBackupPolicyList.sizeTiB | Measure-Object -Sum).sum 
  $efsTotalBackupGB = ($efsInBackupPolicyList.sizeGB | Measure-Object -Sum).sum
  $efsTotalBackupTB = ($efsInBackupPolicyList.sizeTB | Measure-Object -Sum).sum

  $fsxFileSystemTotalCapacityGiB = ($fsxFileSystemList.StorageCapacityGiB | Measure-Object -Sum).sum
  $fsxFileSystemTotalCapacityTiB = ($fsxFileSystemList.StorageCapacityTiB | Measure-Object -Sum).sum 
  $fsxFileSystemTotalCapacityGB = ($fsxFileSystemList.StorageCapacityGB | Measure-Object -Sum).sum
  $fsxFileSystemTotalCapacityTB = ($fsxFileSystemList.StorageCapacityTB | Measure-Object -Sum).sum

  $fsxTotalUsedGiB = ($fsxList.StorageUsedGiB | Measure-Object -Sum).sum
  $fsxTotalUsedTiB = ($fsxList.StorageUsedTiB | Measure-Object -Sum).sum 
  $fsxTotalUsedGB = ($fsxList.StorageUsedGB | Measure-Object -Sum).sum
  $fsxTotalUsedTB = ($fsxList.StorageUsedTB | Measure-Object -Sum).sum
  $fsxTotalCapacityGiB = ($fsxList.StorageCapacityGiB | Measure-Object -Sum).sum
  $fsxTotalCapacityTiB = ($fsxList.StorageCapacityTiB | Measure-Object -Sum).sum 
  $fsxTotalCapacityGB = ($fsxList.StorageCapacityGB | Measure-Object -Sum).sum
  $fsxTotalCapacityTB = ($fsxList.StorageCapacityTB | Measure-Object -Sum).sum
  $fsxInBackupPolicyList = $fsxList | Where-Object { $_.InBackupPlan }
  $fsxTotalBackupUsedGiB = ($fsxInBackupPolicyList.StorageUsedGiB | Measure-Object -Sum).sum
  $fsxTotalBackupUsedTiB = ($fsxInBackupPolicyList.StorageUsedTiB | Measure-Object -Sum).sum 
  $fsxTotalBackupUsedGB = ($fsxInBackupPolicyList.StorageUsedGB | Measure-Object -Sum).sum
  $fsxTotalBackupUsedTB = ($fsxInBackupPolicyList.StorageUsedTB | Measure-Object -Sum).sum
  $fsxTotalBackupCapacityGiB = ($fsxInBackupPolicyList.StorageCapacityGiB | Measure-Object -Sum).sum
  $fsxTotalBackupCapacityTiB = ($fsxInBackupPolicyList.StorageCapacityTiB | Measure-Object -Sum).sum 
  $fsxTotalBackupCapacityGB = ($fsxInBackupPolicyList.StorageCapacityGB | Measure-Object -Sum).sum
  $fsxTotalBackupCapacityTB = ($fsxInBackupPolicyList.StorageCapacityTB | Measure-Object -Sum).sum

  $ddbTotalGiB = ($ddbList.TableSizeGiB | Measure-Object -Sum).sum
  $ddbTotalTiB = ($ddbList.TableSizeTiB | Measure-Object -Sum).sum 
  $ddbTotalGB = ($ddbList.TableSizeGB | Measure-Object -Sum).sum
  $ddbTotalTB = ($ddbList.TableSizeTB | Measure-Object -Sum).sum

  $totalSecrets = ($secretsList.Secrets | Measure-Object -Sum).sum
  $totalKeys = ($kmsList.Keys | Measure-Object -Sum).sum
  $totalQueues = ($sqsList.Queues | Measure-Object -Sum).sum

  # If statement is a workaround for error when getting backup plans when payer account 
  # does not allow access for linked accounts
  if ($null -eq $backupCostsList.AWSBackupNetUnblendedCost) {
    Write-Error "No AWS Backup costs found."
    Write-Error "AWS Cost data not reported"
  } else {
    $backupTotalNetUnblendedCost = ($backupCostsList.AWSBackupNetUnblendedCost | ForEach-Object { [decimal]($_.TrimStart('$')) } | Measure-Object -Sum).sum
  }

function addTagsToAllObjectsInList($list) {
  # Determine all unique tag keys
  $allTagKeys = @{}
  foreach ($obj in $list) {
      $properties = $obj.PSObject.Properties
      foreach ($property in $properties) {
          if (-not $allTagKeys.ContainsKey($property.Name)) {
              $allTagKeys[$property.Name] = $true
          }
      }
  }
  
  $allTagKeys = $allTagKeys.Keys
  
  # Ensure each object has all possible tag keys
  foreach ($obj in $list) {
      foreach ($key in $allTagKeys) {
          if (-not $obj.PSObject.Properties.Name.Contains($key)) {
              $obj | Add-Member -MemberType NoteProperty -Name $key -Value $null -Force
          }
      }
  }
}

if ($Anonymize) {
  Write-Host
  Write-Host "Anonymizing..." -ForegroundColor Green

  $global:anonymizeProperties = @("Arn", "AwsAccountAlias", "AwsAccountId", "BackupPlanArn", "BackupPlanId", "BackupPlanName",   
                                  "BucketName", "ClusterName", "CreatorRequestId", "DBInstanceIdentifier", "DestinationBackupVaultArn", 
                                  "FileSystemDNSName", "FileSystemId", "FileSystemOwnerId", "InstanceId", "Name", "NodegroupArn", 
                                  "NodegroupName", "NodeRole", "OwnerId", "Project", "RDSInstance", "RequestId", "Resources", 
                                  "RoleArn", "RuleId", "RuleName", "TableArn", "TableId", "TableName", "TargetBackupVaultName",
                                  "VersionId", "VolumeId")
  if($AnonymizeFields){
    [string[]]$anonFieldsList = $AnonymizeFields.split(',')
    foreach($field in $anonFieldsList){
      if (-not $global:anonymizeProperties.Contains($field)) {
        $global:anonymizeProperties += $field
      }
    }
  }
  if($NotAnonymizeFields){
    [string[]]$notAnonFieldsList = $NotAnonymizeFields.split(',')
    $global:anonymizeProperties = $global:anonymizeProperties | Where-Object { $_ -notin $notAnonFieldsList }
  }

  $global:anonymizeDict = @{}
  $global:anonymizeCounter = @{}

  function Get-NextAnonymizedValue ($anonField) {
      $charSet = "0123456789"
      $base = $charSet.Length
      $newValue = ""
      if (-not $global:anonymizeCounter.ContainsKey($anonField)) {
        $global:anonymizeCounter[$anonField] = 0
      }
      $global:anonymizeCounter[$anonField]++

      $counter = $global:anonymizeCounter[$anonField]
      while ($counter -gt 0) {
          $counter--
          $newValue = $charSet[$counter % $base] + $newValue
          $counter = [math]::Floor($counter / $base)
      }
      
      $paddedValue = $newValue.PadLeft(5, '0')

      return "$($anonField)-$($paddedValue)"
  }

  function AnonymizeData {
      param (
          [PSObject]$DataObject
      )

      foreach ($property in $DataObject.PSObject.Properties) {
          $propertyName = $property.Name
          $shouldAnonymize = $global:anonymizeProperties -contains $propertyName

          if ($shouldAnonymize) {
              $originalValue = $DataObject.$propertyName

              if ($null -ne $originalValue) {
                if(($originalValue -is [System.Collections.IEnumerable] -and -not ($originalValue -is [string])) ){
                  # This is to handle the anonymization of lists, such as Resources in the AWS backup plans JSON
                  $anonymizedCollection = @()
                  foreach ($item in $originalValue) {
                      if (-not $global:anonymizeDict.ContainsKey("$item")) {
                          $global:anonymizeDict["$item"] = Get-NextAnonymizedValue($propertyName)
                      }
                      $anonymizedCollection += $global:anonymizeDict["$item"]
                  }
                  $DataObject.$propertyName = $anonymizedCollection
                } else{
                  if (-not $global:anonymizeDict.ContainsKey("$($originalValue)")) {
                      $global:anonymizeDict[$originalValue] = Get-NextAnonymizedValue($propertyName)
                  }
                  $DataObject.$propertyName = $global:anonymizeDict[$originalValue]
                }
              }
          } elseif ($propertyName -like "Tag:*") {
            # Must anonymize both the tag name and value

            $tagValue = $DataObject.$propertyName
            $anonymizedTagKey = ""
            
            $tagName = $propertyName.Substring(4)
            
            if (-not $global:anonymizeDict.ContainsKey("$tagName")) {
                $global:anonymizeDict["$tagName"] = Get-NextAnonymizedValue("TagName")
            }
            $anonymizedTagKey = 'Tag:' + $global:anonymizeDict["$tagName"]
            
            $anonymizedTagValue = $null
            if ($null -ne $tagValue) {
                if (-not $global:anonymizeDict.ContainsKey("$($tagValue)")) {
                    $global:anonymizeDict[$tagValue] = Get-NextAnonymizedValue("TagValue")#$anonymizedTagKey
                }
                $anonymizedTagValue = $global:anonymizeDict[$tagValue]
            }
            $DataObject.PSObject.Properties.Remove($propertyName)
            $DataObject | Add-Member -MemberType NoteProperty -Name $anonymizedTagKey -Value $anonymizedTagValue -Force
        } elseif($propertyName -eq "BackupPlans") {
            $originalValue = $DataObject.$propertyName
            if($null -ne $originalValue -and $originalValue -ne ""){
              $plans = $originalValue.split(', ')
              $newVal = ""
              $count = 0
              foreach($plan in $plans){
                if (-not $global:anonymizeDict.ContainsKey("$plan")) {
                  $global:anonymizeDict[$plan] = Get-NextAnonymizedValue("BackupPlanName")
                }
                if($count -ne 0){
                  $newVal += " ,"
                }
                $newVal += $global:anonymizeDict[$plan]
                $count++
              }
              $DataObject.$propertyName = $newVal
            }
          }
          elseif ($property.Value -is [PSObject]) {
              $DataObject.$propertyName = AnonymizeData -DataObject $property.Value
          }
          elseif ($property.Value -is [System.Collections.IEnumerable] -and -not ($property.Value -is [string])) {
              $anonymizedCollection = @()
              foreach ($item in $property.Value) {
                  if ($item -is [PSObject]) {
                      $anonymizedItem = AnonymizeData -DataObject $item
                      $anonymizedCollection += $anonymizedItem
                  } else {
                      $anonymizedCollection += $item
                  }
              }
              $DataObject.$propertyName = $anonymizedCollection
          }
      }

      return $DataObject
  }

  function AnonymizeCollection {
      param (
          [System.Collections.IEnumerable]$Collection
      )

      $anonymizedCollection = @()
      foreach ($item in $Collection) {
          if ($item -is [PSObject]) {
              $anonymizedItem = AnonymizeData -DataObject $item
              $anonymizedCollection += $anonymizedItem
          } else {
              $anonymizedCollection += $item
          }
      }

      return $anonymizedCollection
  }

  # Anonymize each list
  $backupPlanList = AnonymizeCollection -Collection $backupPlanList
  $backupCostsList = AnonymizeCollection -Collection $backupCostsList
  $ddbList = AnonymizeCollection -Collection $ddbList
  $ec2List = AnonymizeCollection -Collection $ec2List
  $ec2UnattachedVolList = AnonymizeCollection -Collection $ec2UnattachedVolList
  $efsList = AnonymizeCollection -Collection $efsList
  $eksList = AnonymizeCollection -Collection $eksList
  $eksNodeGroupList = AnonymizeCollection -Collection $eksNodeGroupList
  $fsxFileSystemList = AnonymizeCollection -Collection $fsxFileSystemList
  $fsxList = AnonymizeCollection -Collection $fsxList
  $kmsList = AnonymizeCollection -Collection $kmsList
  $rdsList = AnonymizeCollection -Collection $rdsList
  $s3List = AnonymizeCollection -Collection $s3List
  $s3ListAg = AnonymizeCollection -Collection $s3ListAg
  $secretsList = AnonymizeCollection -Collection $secretsList
  $sqsList = AnonymizeCollection -Collection $sqsList
}

# Export to CSV
Write-Host ""

addTagsToAllObjectsInList($ec2List)
Write-Host "CSV file output to: $outputEc2Instance"  -ForegroundColor Green
$ec2List | Export-CSV -path $outputEc2Instance

addTagsToAllObjectsInList($ec2UnattachedVolList)
Write-Host "CSV file output to: $outputEc2UnattachedVolume"  -ForegroundColor Green
$ec2UnattachedVolList | Export-CSV -path $outputEc2UnattachedVolume

addTagsToAllObjectsInList($rdsList)
Write-Host "CSV file output to: $outputRDS"  -ForegroundColor Green
$rdsList | Export-CSV -path $outputRDS

Write-Host "CSV file output to: $outputS3"  -ForegroundColor Green
$s3ListAg | Export-CSV -path $outputS3

addTagsToAllObjectsInList($efsList)
Write-Host "CSV file output to: $outputEFS"  -ForegroundColor Green
$efsList | Export-CSV -path $outputEFS

addTagsToAllObjectsInList($fsxFileSystemList)
Write-Host "CSV file output to: $outputFSXfilesystems"  -ForegroundColor Green
$fsxFileSystemList | Export-CSV -path $outputFSXfilesystems

addTagsToAllObjectsInList($fsxList)
Write-Host "CSV file output to: $outputFSX"  -ForegroundColor Green
$fsxList | Export-CSV -path $outputFSX

Write-Host "CSV file output to: $outputDDB"  -ForegroundColor Green
$ddbList | Export-CSV -path $outputDDB

Write-Host "CSV file output to: $outputSecrets"  -ForegroundColor Green
$secretsList | Export-CSV -path $outputSecrets

Write-Host "CSV file output to: $outputSQS"  -ForegroundColor Green
$sqsList | Export-CSV -path $outputSQS

Write-Host "CSV file output to: $outputKMS"  -ForegroundColor Green
$kmsList | Export-CSV -path $outputKMS

# If statement is a workaround for error when getting backup plans when payer account
# does not allow access for linked accounts
if ($null -eq $backupCostsList.AWSBackupNetUnblendedCost) {
  Write-Error "AWS Cost data file not saved."
} else {
  Write-Host "CSV file output to: $outputBackupCosts"  -ForegroundColor Green
  $backupCostsList | Export-CSV -path $outputBackupCosts
}

Write-Host "CSV file output to: $outputEKSClusters"  -ForegroundColor Green
$eksList | Export-CSV -path $outputEKSClusters

Write-Host "CSV file output to: $outputEKSNodegroups"  -ForegroundColor Green
$eksNodeGroupList | Export-CSV -path $outputEKSNodegroups

# Export to JSON
Write-Host "JSON file output to: $outputBackupPlansJSON"  -ForegroundColor Green
$backupPlanList | ConvertTo-Json -Depth 10 > $outputBackupPlansJSON

# Print Summary
Write-Host
Write-Host "Total # of EC2 instances: $($ec2list.count)"  -ForegroundColor Green
Write-Host "Total # of volumes: $(($ec2list.volumes | Measure-Object -Sum).sum)"  -ForegroundColor Green
Write-Host "Total capacity of all volumes: $ec2TotalGiB GiB or $ec2TotalGB GB or $ec2TotalTiB TiB or $ec2TotalTB TB"  -ForegroundColor Green
Write-Host "Capacity of backed up volumes: $ec2TotalBackupGiB GiB or $ec2TotalBackupGB GB or $ec2TotalBackupTiB TiB or $ec2TotalBackupTB TB"  -ForegroundColor Green
Write-Host

Write-Host
Write-Host "Total # of EC2 unattached volumes: $($ec2UnattachedVolList.count)"  -ForegroundColor Green
Write-Host "Total capacity of all unattached volumes: $ec2UnVolTotalGiB GiB or $ec2UnVolTotalGB GB or $ec2UnVolTotalTiB TiB or $ec2UnVolTotalTB TB"  -ForegroundColor Green
Write-Host "Capacity of all backed up unattached volumes: $ec2UnVolTotalBackupGiB GiB or $ec2UnVolTotalBackupGB GB or $ec2UnVolTotalBackupTiB TiB or $ec2UnVolTotalBackupTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of RDS instances: $($rdsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all RDS instances: $rdsTotalGiB GiB or $rdsTotalGB GB or $rdsTotalTiB TiB or $rdsTotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned capacity of all backed up RDS instances: $rdsTotalBackupGiB GiB or $rdsTotalBackupGB GB or $rdsTotalBackupTiB TiB or $rdsTotalBackupTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of EFS file systems: $($efsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all EFS file systems: $efsTotalGiB GiB or $efsTotalGB GB or $efsTotalTiB TiB or $efsTotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned capacity of all backed up EFS file systems: $efsTotalBackupGiB GiB or $efsTotalBackupGB GB or $efsTotalBackupTiB TiB or $efsTotalBackupTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of FSx FileSystems: $($fsxFileSystemList.count)"  -ForegroundColor Green
Write-Host "Total storage capacity of all FSx File Systems: $fsxFileSystemTotalCapacityGiB GiB or $fsxFileSystemTotalCapacityGB GB or $fsxFileSystemTotalCapacityTiB TiB or $fsxFileSystemTotalCapacityTB TB"  -ForegroundColor Green

Write-Host
Write-Host "This volume data is a subset of FSX FileSystem Data above" -ForegroundColor Green
Write-Host "Total # of FSx volumes: $($fsxList.count)"  -ForegroundColor Green
Write-Host "Total used storage of all FSx volumes: $fsxTotalUsedGiB GiB or $fsxTotalUsedGB GB or $fsxTotalUsedTiB TiB or $fsxTotalUsedTB TB"  -ForegroundColor Green
Write-Host "Total storage capacity of all FSx volumes: $fsxTotalCapacityGiB GiB or $fsxTotalCapacityGB GB or $fsxTotalCapacityTiB TiB or $fsxTotalCapacityTB TB"  -ForegroundColor Green
Write-Host "Used storage of all backed up FSx volumes: $fsxTotalBackupUsedGiB GiB or $fsxTotalBackupUsedGB GB or $fsxTotalBackupUsedTiB TiB or $fsxTotalBackupUsedTB TB"  -ForegroundColor Green
Write-Host "Storage capacity of all backed up FSx volumes: $fsxTotalBackupCapacityGiB GiB or $fsxTotalBackupCapacityGB GB or $fsxTotalBackupCapacityTiB TiB or $fsxTotalBackupCapacityTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of KMS Keys: $($totalKeys)"  -ForegroundColor Green
Write-Host "Total # of Secrets: $($totalSecrets)"  -ForegroundColor Green
Write-Host "Total # of SQS Queues: $($totalQueues)"  -ForegroundColor Green

Write-Host
Write-Host "Total # of DynamoDB Tables: $($ddbList.count)"  -ForegroundColor Green
Write-Host "Total table size of all DynamoDB Tables: $ddbTotalGiB GiB or $ddbTotalGB GB or $ddbTotalTiB TiB or $ddbTotalTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of S3 buckets: $($s3List.count)"  -ForegroundColor Green
Write-Host "Total used capacity of all S3 buckets:"   -ForegroundColor Green
# Write-Output $s3TotalTBsFormatted
if($s3TotalTBs.count -eq 0) {
  Write-Host "No S3 Buckets" -ForegroundColor Green
}

# Ensure Write-Output is captured by writing the formatted data to Host
$s3TotalTBsFormatted  = $s3TotalTBs.GetEnumerator() |
  ForEach-Object {
    [PSCustomObject]@{
      StorageType = $_.Key
      Size_TB = "{0:n7}" -f $_.Value
    }
  }

$s3TotalTBsFormatted | ForEach-Object {
    Write-Host ("StorageType: {0}, Size_TB: {1}" -f $_.StorageType, $_.Size_TB) -ForegroundColor Green
}

Write-Host
Write-Host ("NOTE: S3 allows multiple tags on the same bucket with the same key,") -ForegroundColor Yellow 
Write-Host ("      but different cases. Example:") -ForegroundColor Yellow
Write-Host
Write-Host ("        'Owner = Rubrik' and 'owner = Rubrik' are two different tags in S3.") -ForegroundColor Yellow
Write-Host
Write-Host ("      This script will randomly pick one of these keys to use. It") -ForegroundColor Yellow
Write-Host ("      will also randomly pick a value between these keys to use.") -ForegroundColor Yellow
Write-Host ("      This random key/value pair will be used in the script's output.") -ForegroundColor Yellow 
Write-Host ("      Ensure that all S3 tags that use the same name and use the same case.") -ForegroundColor Yellow
Write-Host
Write-Host "# of Backed Up S3 buckets: $($s3InBackupPolicyList.count)"  -ForegroundColor Green
Write-Host "Used capacity of all backed up S3 buckets:"   -ForegroundColor Green
# Write-Output $s3BackupTotalTBsFormatted
if($s3BackupTotalTBs.count -eq 0) {
  Write-Host "No S3 Buckets backed up" -ForegroundColor Green
}

# Ensure Write-Output is captured by writing the formatted data to Host
$s3BackupTotalTBsFormatted  = $s3BackupTotalTBs.GetEnumerator() |
  ForEach-Object {
    [PSCustomObject]@{
      StorageType = $_.Key
      Size_TB = "{0:n7}" -f $_.Value
    }
  }

$s3BackupTotalTBsFormatted | ForEach-Object {
    Write-Host ("StorageType: {0}, Size_TB: {1}" -f $_.StorageType, $_.Size_TB) -ForegroundColor Green
}

Write-Host
Write-Host "Net unblended cost of AWS Backup for past 12 months + this month so far: $("$")$backupTotalNetUnblendedCost"  -ForegroundColor Green
Write-Host "See CSV for further breakdown of cost for Backup"  -ForegroundColor Green

Write-Host
Write-Host
Write-Host "Results will be compressed into $archiveFile and original files will be removed." -ForegroundColor Green

if($Anonymize){
  # Exporting as rows as new value - old value
  $transformedDict = $global:anonymizeDict.GetEnumerator() | ForEach-Object {
    [PSCustomObject]@{
      AnonymizedValue = $_.Value
      ActualValue   = $_.Key
    } 
  } | Sort-Object -Property AnonymizedValue

  $anonKeyValuesFileName = "aws_anonymized_keys_to_actual_values-$date_string.csv"

  $transformedDict | Export-CSV -Path $anonKeyValuesFileName
  Write-Host
  Write-Host "Provided anonymized keys to actual values in the CSV: $anonKeyValuesFileName" -ForeGroundColor Cyan
  Write-Host "Provided log file here: $log_for_anon_customers" -ForegroundColor Cyan
  Write-Host "These files are not part of the zip file generated" -ForegroundColor Cyan
  Write-Host
}

} catch{
  Write-Error "An error occurred and the script has exited prematurely:"
  Write-Error $_
  Write-Error $_.ScriptStackTrace
} finally{
  Stop-Transcript
}

# In the case of an early exit/error, this filters only the files which exist
$existingFiles = $outputFiles | Where-Object { Test-Path $_ }

# Compress the files into a zip archive
Compress-Archive -Path $existingFiles -DestinationPath $archiveFile

# Remove the original files
foreach ($file in $outputFiles) {
    Remove-Item -Path $file -ErrorAction SilentlyContinue
}

Write-Host
Write-Host
Write-Host "Results have been compressed into $archiveFile and original files have been removed." -ForegroundColor Green

[System.Threading.Thread]::CurrentThread.CurrentCulture = $CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $CurrentCulture

Write-Host
Write-Host
Write-Host "Please send $archiveFile to your Rubrik representative" -ForegroundColor Cyan
Write-Host