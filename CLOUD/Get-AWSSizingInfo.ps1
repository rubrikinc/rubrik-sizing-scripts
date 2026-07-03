#requires -Version 7.0
<#requires -Modules AWS.Tools.Common, AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.RDS, AWS.Tools.SecurityToken, AWS.Tools.Organizations, AWS.Tools.IdentityManagement, AWS.Tools.CloudWatch, AWS.Tools.ElasticFileSystem, AWS.Tools.ElasticLoadBalancing, AWS.Tools.ElasticLoadBalancingV2, AWS.Tools.SSO, AWS.Tools.SSOOIDC, AWS.Tools.FSX, AWS.Tools.Backup, AWS.Tools.CostExplorer, AWS.Tools.DynamoDBv2, AWS.Tools.Route53, AWS.Tools.SQS, AWS.Tools.SecretsManager, AWS.Tools.KeyManagementService, AWS.Tools.EKS, AWS.Tools.S3Control, AWS.Tools.Redshift
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

    Install-Module AWS.Tools.Common,AWS.Tools.EC2,AWS.Tools.S3,AWS.Tools.RDS,AWS.Tools.SecurityToken,AWS.Tools.Organizations,AWS.Tools.IdentityManagement,AWS.Tools.CloudWatch,AWS.Tools.ElasticFileSystem,AWS.Tools.ElasticLoadBalancing,AWS.Tools.ElasticLoadBalancingV2,AWS.Tools.SSO,AWS.Tools.SSOOIDC,AWS.Tools.FSX,AWS.Tools.Backup,AWS.Tools.CostExplorer,AWS.Tools.DynamoDBv2,AWS.Tools.Route53,AWS.Tools.SQS,AWS.Tools.SecretsManager,AWS.Tools.KeyManagementService,AWS.Tools.EKS,AWS.Tools.Redshift

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
                    "backup:GetBackupPlan",
                    "backup:GetBackupSelection",
                    "backup:ListBackupPlans",
                    "backup:ListBackupSelections",
                    "backup:ListBackupVaults",
                    "backup:ListRecoveryPointsByBackupVault",
                    "ce:GetCostAndUsage",
                    "ce:GetDimensionValues",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics",
                    "dynamodb:DescribeContinuousBackups",
                    "dynamodb:DescribeTable",
                    "dynamodb:ListBackups",
                    "dynamodb:ListTables",
                    "ec2:DescribeImages",
                    "ec2:DescribeInstances",
                    "ec2:DescribeRegions",
                    "ec2:DescribeSnapshots",
                    "ec2:DescribeVolumes",
                    "ec2:DescribeVpcs",
                    "eks:DescribeCluster",
                    "eks:ListClusters",
                    "eks:ListNodegroups",
                    "elasticloadbalancing:DescribeLoadBalancers",
                    "elasticloadbalancing:DescribeTags",
                    "elasticfilesystem:DescribeFileSystems",
                    "fsx:DescribeBackups",
                    "fsx:DescribeFileSystems",
                    "fsx:DescribeVolumes",
                    "iam:ListAccountAliases",
                    "iam:ListPolicies",
                    "iam:ListRoles",
                    "iam:ListUsers",
                    "kms:DescribeKey",
                    "kms:ListAliases",
                    "kms:ListKeys",
                    "organizations:ListAccounts",
                    "rds:DescribeDBClusterSnapshots",
                    "rds:DescribeDBClusters",
                    "rds:DescribeDBInstances",
                    "rds:DescribeDBSnapshots",
                    "redshift:DescribeClusters",
                    "redshift:DescribeClusterSnapshots",
                    "route53:ListHostedZones",
                    "s3:GetBucketLocation",
                    "s3:GetBucketTagging",
                    "s3:ListAllMyBuckets",
                    "s3:GetStorageLensConfiguration",
                    "s3:ListStorageLensConfigurations",
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
    Additionally, you can specify "Tags" to exclude all tag fields (properties starting with "Tag:") from anonymization.

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
  [switch]$DebugBucketTags,
  # Per-region time budget (minutes) for AWS Backup recovery-point enumeration.
  # On expiry the region's RP capacity numbers become lower bounds and affected
  # workload rows are flagged BackupEnumerationTruncated.
  [Parameter(Mandatory=$false)]
  [int]$BackupRecoveryPointTimeoutMinutes = 60,
  # Skip the entire AWS Backup recovery-point enumeration + every native-snapshot collector.
  # New per-row backup columns are still emitted (defaults), so column order is
  # stable for downstream consumers.
  [Parameter(Mandatory=$false)]
  [switch]$SkipBackupCapacity,
  # Skip both Cost Explorer cost cmdlets. Capacity outputs unchanged; the cost
  # CSVs are written header-only so the canonical filenames still exist.
  [Parameter(Mandatory=$false)]
  [switch]$SkipBackupCosts
)

# Script version — update this with every PR that modifies this script.
$scriptVersion = "1.2.0"

# Provider-specific anonymization configuration
$script:tagPrefix = "Tag:"
$script:tagPrefixLength = 4
$script:tagKeyAnonField = "TagName"
$script:tagValueAnonField = "TagValue"

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

# Detect AWS.Tools.CloudWatch version to determine correct parameter names
# V4 uses -UtcStartTime/-UtcEndTime, V5 renamed them to -StartTime/-EndTime
# See: https://docs.aws.amazon.com/powershell/v5/userguide/migrating-v5.html#migrating-v5-utc-datetime
$useUTCPrefix = $false
$cwModule = Get-Module -ListAvailable AWS.Tools.CloudWatch | Select-Object -First 1
if ($cwModule) {
  $cwVersion = $cwModule.Version
  Write-Host "Detected AWS.Tools.CloudWatch version: $cwVersion" -ForegroundColor Cyan

  if ($cwVersion.Major -lt 5) {
    # V4 and earlier: Use -UtcStartTime/-UtcEndTime
    Write-Host "Using V4 parameter names: -UtcStartTime/-UtcEndTime" -ForegroundColor Cyan
    $useUTCPrefix = $true
  } else {
    # V5 and later: Use -StartTime/-EndTime (renamed from Utc*)
    Write-Host "Using V5 parameter names: -StartTime/-EndTime" -ForegroundColor Cyan
    $useUTCPrefix = $false
  }
} else {
  Write-Host "WARNING: Could not detect AWS.Tools.CloudWatch version, defaulting to V5 parameter names" -ForegroundColor Yellow
  $useUTCPrefix = $false
}

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

Write-Host "Script version: $scriptVersion" -ForeGroundColor Cyan
Write-Host "Arguments passed to $($MyInvocation.MyCommand.Name):" -ForeGroundColor Green
$PSBoundParameters | Format-Table

$profileLocationOpt = @{}
if ($ProfileLocation) {
  $profileLocationOpt = @{ProfileLocation = $($ProfileLocation)}
  Write-Host "Using Profile Location: $ProfileLocation"
}

# Filenames of the CSVs output
$outputEc2Instance = "aws_ec2_instance_info-$date_string.csv"
$outputEc2AttachedVolume = "aws_ec2_attached_volume_info-$date_string.csv"
#unattached volumes are less important and we can probably ignore these. We should be tracking orphaned snapshots or those not created by AWS Backup
$outputEc2UnattachedVolume = "aws_ec2_unattached_volume_info-$date_string.csv"
$outputRDS = "aws_rds_info-$date_string.csv"
$outputVPC = "aws_vpc_info-$date_string.csv"
$outputLB = "aws_lb_info-$date_string.csv"
$outputRoute53 = "aws_route53_info-$date_string.csv"
$outputIAM = "aws_iam_info-$date_string.csv"
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
# Canonical per-RP CSV. Registered in $outputFiles below; emitted by the
# recovery-point cmdlet via the streaming merge.
$outputBackupRecoveryPoints = "aws_backup_recovery_points-$date_string.csv"
# Native (non-AWS-Backup) snapshot detail CSVs for the two high-volume sources.
$outputEBSAndAMI = "aws_ebs_and_ami_info-$date_string.csv"
$outputRDSSnapshots = "aws_rds_snapshot_info-$date_string.csv"
# Redshift cluster workload inventory (new CSV; clusters were never enumerated).
$outputRedshiftClusters = "aws_redshift_info-$date_string.csv"
# Snapshot-storage USAGE_TYPE cost CSV. Captures EBS/EC2/RDS/Aurora/DocDB/Neptune/
# FSx-non-OpenZFS/StorageGateway/Redshift/DDB-standard-PITR -- the resources that
# bill snapshot storage to the source service rather than the AWS Backup service.
$outputSnapshotStorageCosts = "aws_snapshot_storage_costs-$date_string.csv"
$outputBackupPlansJSON = "aws-backup-plans-info-$date_string.json"
$archiveFile = "aws_sizing_results_$date_string.zip"

# List of output files
$outputFiles = @(
    $outputEc2Instance,
    $outputEc2AttachedVolume,
    $outputEc2UnattachedVolume,
    $outputRDS,
    $outputVPC,
    $outputLB,
    $outputRoute53,
    $outputIAM,
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
    $outputBackupRecoveryPoints,
    $outputEBSAndAMI,
    $outputRDSSnapshots,
    $outputRedshiftClusters,
    $outputSnapshotStorageCosts,
    $outputBackupPlansJSON,
    $output_log
)

function Get-CWMetricStatisticsForAllVersion {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [string]$Namespace,

    [Parameter(Mandatory=$true)]
    [string]$MetricName,

    # Match AWS.Tools CloudWatch cmdlet: parameter is -Dimension with alias -Dimensions
    [Parameter(Mandatory=$true)]
    [Alias('Dimensions')]
    $Dimension,

    [Parameter(Mandatory=$true)]
    [datetime]$StartTime,

    [Parameter(Mandatory=$true)]
    [datetime]$EndTime,

    [Parameter(Mandatory=$true)]
    [int]$Period,

    # Match AWS.Tools CloudWatch cmdlet: parameter is -Statistic with alias -Statistics
    [Parameter(Mandatory=$true)]
    [Alias('Statistics')]
    [string[]]$Statistic,

    [Parameter(Mandatory=$true)]
    $Region,

    [Parameter(Mandatory=$true)]
    [AllowNull()]
    $Credential
  )

  # Base arguments that are common regardless of version
  $invocationArgs = @{
    MetricName  = $MetricName
    Namespace   = $Namespace
    Period      = $Period
    Dimension   = $Dimension
    Statistic   = $Statistic
    Region      = $Region
    Credential  = $Credential
    ErrorAction = 'Stop'
  }

  # Decide which time parameter names to use based on $useUTCPrefix
  if ($useUTCPrefix) {
    return & Get-CWMetricStatistics @invocationArgs -UtcStartTime $StartTime -UtcEndTime $EndTime
  } else {
    return & Get-CWMetricStatistics @invocationArgs -StartTime $StartTime -EndTime $EndTime
  }
}

function Invoke-AWSWithRetry {
    param(
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [int]$MaxAttempts     = 5,
        [string]$Context      = '',       # used in warning text only
        [int]$InitialDelayMs  = 1000      # exposed so tests can shorten the backoff
    )
    $attempt = 0; $delayMs = $InitialDelayMs
    while ($true) {
        $attempt++
        try { return & $ScriptBlock }
        catch {
            # AWS Tools for PowerShell wraps the underlying AmazonServiceException
            # inside a RuntimeException, so ErrorCode / StatusCode may live on an
            # InnerException rather than the outer wrapper. Walk the chain and
            # check all three throttle surfaces (type name, ErrorCode, HTTP status)
            # at every level so retries fire whichever wrapping layer bubbled up.
            $throttle = $false
            $ex = $_.Exception
            while ($null -ne $ex) {
                $byType   = $ex.GetType().Name -match 'Throttl|RequestLimit|TooManyRequests|SlowDown'
                $byCode   = ($ex.PSObject.Properties['ErrorCode']  -and $ex.ErrorCode  -match 'Throttl|RequestLimit|TooManyRequests|SlowDown')
                $byStatus = ($ex.PSObject.Properties['StatusCode'] -and ($ex.StatusCode -in 429, 503))
                if ($byType -or $byCode -or $byStatus) { $throttle = $true; break }
                $ex = $ex.InnerException
            }
            if (-not $throttle -or $attempt -ge $MaxAttempts) { throw }
            $jitter = Get-Random -Minimum 0 -Maximum ([int]($delayMs * 0.3))
            Start-Sleep -Milliseconds ($delayMs + $jitter)
            $delayMs = [int]($delayMs * 2)
        }
    }
}

# AWS.Tools v4/v5 compatibility verification for the backup-sizing cmdlets.
#
# Verified against AWS.Tools v5.0.106 (signatures inspected via Get-Command on the
# installed modules). The pagination-token and page-size parameter NAMES differ
# from the generic "-MaxResults / -NextToken" assumption, so callers in later
# sections MUST use the exact names listed here rather than copying the canonical
# pagination snippet verbatim:
#
#   Get-BAKBackupVaultList                  -> page with -NextToken,  size -MaxResult (singular)
#   Get-BAKRecoveryPointsByBackupVaultList  -> page with -NextToken,  size -MaxResult (singular)
#       NOTE: the v5 cmdlet is "...ByBackupVaultList" (List suffix), NOT the
#       "Get-BAKRecoveryPointsByBackupVault" name used in some AWS API docs.
#   Get-CEDimensionValue                    -> size -MaxResult (CE auto-pages by default)
#   Get-FSXBackup                           -> page with -NextToken,  size -MaxResult (singular)
#   Get-RDSDBSnapshot / Get-RDSDBClusterSnapshot -> page with -Marker, size -MaxRecord
#       (RDS uses the Marker/MaxRecord idiom, not NextToken/MaxResult)
#   Get-DDBBackupList / Get-DDBContinuousBackup / Get-DDBTable -> no explicit page
#       params surfaced by the cmdlet; rely on the cmdlet's built-in auto-paging.
#   Get-RSCluster / Get-RSClusterSnapshot   -> AWS.Tools.Redshift (newly added module;
#       not installable in this sandbox). Redshift cmdlets historically use
#       -Marker; verify -Marker vs -NextToken at implementation time in Task 9.
#
# All inspected read cmdlets keep stable parameter names across v4 and v5 (only the
# CloudWatch time-parameter rename required the existing Get-CWMetricStatisticsForAllVersion
# shim). Since no cmdlet difference was found that needs runtime adaptation for the
# parameters used by this script, no additional "*ForAllVersion" wrappers are added in
# this task. If a future AWS.Tools major release renames any page-size parameter, add a
# wrapper following the Get-CWMetricStatisticsForAllVersion pattern above.

function Add-TagsToAllObjectsInList($list) {
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

function ConvertTo-SizeUnits {
    param(
        [double]$Value,
        [string]$Prefix,
        [ValidateSet('Bytes', 'GiB')]
        [string]$InputUnit = 'Bytes',
        [int]$GiBPrecision = 4,
        [int]$TiBPrecision = 4,
        [int]$GBPrecision = 4,
        [int]$TBPrecision = 4
    )
    if ($InputUnit -eq 'Bytes') {
        $gib = $Value / 1073741824
        $tib = $gib / 1024
        $gb  = $Value / 1000000000
        $tb  = $gb / 1000
    } else {
        $gib = $Value
        $tib = $Value / 1024
        $gb  = $Value * 1.073741824
        $tb  = $Value * 0.001073741824
    }
    @{
        "${Prefix}GiB" = [math]::round($gib, $GiBPrecision)
        "${Prefix}TiB" = [math]::round($tib, $TiBPrecision)
        "${Prefix}GB"  = [math]::round($gb, $GBPrecision)
        "${Prefix}TB"  = [math]::round($tb, $TBPrecision)
    }
}

function Compress-SizingArchive {
    param(
        [string[]]$OutputFiles,
        [string]$ArchiveFile
    )
    $existingFiles = $OutputFiles | Where-Object { Test-Path $_ }
    if ($existingFiles) {
        Compress-Archive -Path $existingFiles -DestinationPath $ArchiveFile
    }
    foreach ($file in $OutputFiles) {
        Remove-Item -Path $file -ErrorAction SilentlyContinue
    }
}

function Get-AWSStorageLensConfigs {
    param(
        $Credential,
        $AccountInfo,
        [string[]]$Regions
    )
    $storageLensConfigsWithCloudWatch = @()
    foreach ($slRegion in $Regions) {
        try {
            # List all Storage Lens configurations for this account in this region
            $storageLensConfigs = Get-S3CStorageLensConfigurationList -AccountId $AccountInfo.Account -Credential $Credential -Region $slRegion -ErrorAction Stop
            # Check each configuration and collect all with CloudWatch publishing enabled
            foreach ($slConfig in $storageLensConfigs) {
                try {
                    $slConfigDetails = Get-S3CStorageLensConfiguration -AccountId $AccountInfo.Account -ConfigId $slConfig.Id -Credential $Credential -Region $slRegion -ErrorAction Stop
                    if ($slConfigDetails.DataExport.CloudWatchMetrics.IsEnabled -eq $true -and $slConfigDetails.IsEnabled -eq $true) {
                        # Store configuration with its Include/Exclude settings
                        # Buckets are stored as ARNs like "arn:aws:s3:::bucket-name"
                        # Also store the dashboard's home region (where CloudWatch metrics are published)
                        $configInfo = @{
                            ConfigId = $slConfig.Id
                            DashboardRegion = $slRegion
                            IncludeBuckets = $slConfigDetails.Include.Buckets
                            ExcludeBuckets = $slConfigDetails.Exclude.Buckets
                            IncludeRegions = $slConfigDetails.Include.Regions
                            ExcludeRegions = $slConfigDetails.Exclude.Regions
                        }
                        $storageLensConfigsWithCloudWatch += $configInfo
                    }
                } catch {
                    Write-Host "Could not get details for Storage Lens config $($slConfig.Id) in region ${slRegion}: $_"
                }
            }
        } catch {
            Write-Host "Could not list Storage Lens configurations for account $($AccountInfo.Account) in region ${slRegion}: $_"
        }
    }
    return $storageLensConfigsWithCloudWatch
}

function Get-AWSS3Inventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        $StorageLensConfigs,
        [switch]$SkipBucketTags,
        [datetime]$UtcStartTime,
        [datetime]$UtcEndTime
    )

    $s3Result = New-Object collections.arraylist

    $cwBucketInfo = $null
    try{
      $cwBucketInfo = Get-CWmetriclist -namespace AWS/S3 -Region $Region -Credential $Credential -ErrorAction Stop
    } catch {
      Write-Host "Failed to get S3 Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    $s3Buckets = $null
    try{
      $s3Buckets = $(Get-S3Bucket -Credential $Credential -Region $Region -BucketRegion $Region -ErrorAction Stop).BucketName
    } catch {
      Write-Host "Failed to get S3 Info for region $Region in account $($AccountInfo.Account) using Get-S3Bucket" -ForeGroundColor Red
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
        $bytesStorageTypes = $(Get-CWmetriclist -Dimension $filter -Credential $Credential -Region $Region -ErrorAction Stop `
                                | Where-Object -Property MetricName -eq 'BucketSizeBytes' `
                                | Select-Object -ExpandProperty Dimensions `
                                | Where-Object -Property Name -eq StorageType).Value
        $numObjStorageTypes = $(Get-CWmetriclist -Dimension $filter -Credential $Credential -Region $Region -ErrorAction Stop `
                                | Where-Object -Property MetricName -eq 'NumberOfObjects' `
                                | Select-Object -ExpandProperty Dimensions `
                                | Where-Object -Property Name -eq StorageType).Value
      } catch {
        Write-Host "Failed to get S3 Info for bucket $s3Bucket in region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
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
          $maxBucketSizes = $(Get-CWMetricStatisticsForAllVersion  -Statistic Maximum `
                          -Namespace AWS/S3 -MetricName BucketSizeBytes `
                          -StartTime $UtcStartTime `
                          -EndTime $UtcEndTime `
                          -Period 86400  `
                          -Credential $Credential -Region $Region `
                          -Dimensions $bucketNameDim, $bucketBytesStorageDim -ErrorAction Stop `
                          | Select-Object -ExpandProperty Datapoints).Maximum
        } catch {
          Write-Host "Failed to get S3 Info for StorageType $bytesStorageType in bucket $s3Bucket in region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
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
          $maxBucketObjects = $(Get-CWMetricStatisticsForAllVersion  -Statistic Maximum `
                          -Namespace AWS/S3 -MetricName NumberOfObjects `
                          -StartTime $UtcStartTime `
                          -EndTime $UtcEndTime `
                          -Period 86400  `
                          -Credential $Credential -Region $Region `
                          -Dimensions $bucketNameDim, $bucketNumObjStorageDim -ErrorAction Stop `
                          | Select-Object -ExpandProperty Datapoints).Maximum
        } catch {
          Write-Host "Failed to get S3 Info for StorageType $numObjStorageType in bucket $s3Bucket in region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $maxBucketObjs = $($maxBucketObjects | Measure-Object -Maximum).Maximum
        $numObjStorages.Add($numObjStorageType, $maxBucketObjs)
      }

      # Query CurrentVersionStorageBytes and CurrentVersionObjectCount from Storage Lens CloudWatch metrics if enabled
      $currentVersionBytesStorages = @{}
      $currentVersionObjectStorages = @{}
      if ($StorageLensConfigs.Count -gt 0) {
        # Find a Storage Lens configuration that covers this bucket
        # Storage Lens configs can include/exclude specific buckets and regions
        $bucketArn = "arn:aws:s3:::$s3Bucket"
        $matchingConfigId = $null

        foreach ($slConfig in $StorageLensConfigs) {
          $bucketCoveredByConfig = $true

          # If Include.Buckets is set, bucket must be in the list
          if ($null -ne $slConfig.IncludeBuckets -and $slConfig.IncludeBuckets.Count -gt 0) {
            if ($bucketArn -notin $slConfig.IncludeBuckets) {
              $bucketCoveredByConfig = $false
            }
          }
          # If Include.Regions is set, region must be in the list
          if ($bucketCoveredByConfig -and $null -ne $slConfig.IncludeRegions -and $slConfig.IncludeRegions.Count -gt 0) {
            if ($Region -notin $slConfig.IncludeRegions) {
              $bucketCoveredByConfig = $false
            }
          }
          # If Exclude.Buckets is set, bucket must NOT be in the list
          if ($bucketCoveredByConfig -and $null -ne $slConfig.ExcludeBuckets -and $slConfig.ExcludeBuckets.Count -gt 0) {
            if ($bucketArn -in $slConfig.ExcludeBuckets) {
              $bucketCoveredByConfig = $false
            }
          }
          # If Exclude.Regions is set, region must NOT be in the list
          if ($bucketCoveredByConfig -and $null -ne $slConfig.ExcludeRegions -and $slConfig.ExcludeRegions.Count -gt 0) {
            if ($Region -in $slConfig.ExcludeRegions) {
              $bucketCoveredByConfig = $false
            }
          }

          if ($bucketCoveredByConfig) {
            $matchingConfigId = $slConfig.ConfigId
            $matchingDashboardRegion = $slConfig.DashboardRegion
            break
          }
        }

        if ($null -ne $matchingConfigId) {
          try {
            # Set up base dimensions for Storage Lens CloudWatch metrics
            # CloudWatch requires ALL dimensions to match exactly
            $configIdDim = [Amazon.CloudWatch.Model.Dimension]::new()
            $configIdDim.Name = "configuration_id"
            $configIdDim.Value = $matchingConfigId

            $accountDim = [Amazon.CloudWatch.Model.Dimension]::new()
            $accountDim.Name = "aws_account_number"
            $accountDim.Value = $AccountInfo.Account

            # aws_region dimension is the bucket's region (where the bucket is located)
            $regionDim = [Amazon.CloudWatch.Model.Dimension]::new()
            $regionDim.Name = "aws_region"
            $regionDim.Value = $Region

            $bucketDim = [Amazon.CloudWatch.Model.Dimension]::new()
            $bucketDim.Name = "bucket_name"
            $bucketDim.Value = $s3Bucket

            $metricsVersionDim = [Amazon.CloudWatch.Model.Dimension]::new()
            $metricsVersionDim.Name = "metrics_version"
            $metricsVersionDim.Value = "1.0"

            $recordTypeDim = [Amazon.CloudWatch.Model.Dimension]::new()
            $recordTypeDim.Name = "record_type"
            $recordTypeDim.Value = "BUCKET"

            # Get available storage classes for CurrentVersionStorageBytes metric for this bucket
            # CloudWatch API call uses dashboard's home region (where metrics are published)
            $slMetricFilter = @(
              @{ Name = "configuration_id"; Value = $matchingConfigId },
              @{ Name = "bucket_name"; Value = $s3Bucket }
            )
            $availableStorageClasses = $(Get-CWMetricList -Namespace "AWS/S3/Storage-Lens" -MetricName "CurrentVersionStorageBytes" `
                            -Dimension $slMetricFilter -Credential $Credential -Region $matchingDashboardRegion -ErrorAction Stop `
                            | Select-Object -ExpandProperty Dimensions `
                            | Where-Object -Property Name -eq "storage_class").Value | Select-Object -Unique

            # Query CurrentVersionStorageBytes for each storage class
            foreach ($storageClass in $availableStorageClasses) {
              $storageClassDim = [Amazon.CloudWatch.Model.Dimension]::new()
              $storageClassDim.Name = "storage_class"
              $storageClassDim.Value = $storageClass

              try {
                # Storage Lens CloudWatch metrics are published to the dashboard's home region
                # Must include ALL 7 dimensions
                $storageLensMetrics = Get-CWMetricStatisticsForAllVersion -Statistic Maximum `
                                -Namespace "AWS/S3/Storage-Lens" -MetricName "CurrentVersionStorageBytes" `
                                -StartTime $UtcStartTime `
                                -EndTime $UtcEndTime `
                                -Period 86400 `
                                -Credential $Credential -Region $matchingDashboardRegion `
                                -Dimensions $configIdDim, $accountDim, $regionDim, $bucketDim, $metricsVersionDim, $recordTypeDim, $storageClassDim -ErrorAction Stop

                $currentVersionBytesValue = ($storageLensMetrics.Datapoints | Sort-Object -Property Timestamp -Descending | Select-Object -First 1).Maximum
                $currentVersionBytesStorages.Add($storageClass, $currentVersionBytesValue)
              } catch {
                Write-Debug "Failed to get CurrentVersionStorageBytes for storage class $storageClass in bucket ${s3Bucket}: $_"
              }
            }

            # Query CurrentVersionObjectCount for each storage class (same classes as CurrentVersionStorageBytes)
            foreach ($storageClass in $availableStorageClasses) {
              $storageClassDim = [Amazon.CloudWatch.Model.Dimension]::new()
              $storageClassDim.Name = "storage_class"
              $storageClassDim.Value = $storageClass

              try {
                $storageLensObjMetrics = Get-CWMetricStatisticsForAllVersion -Statistic Maximum `
                                -Namespace "AWS/S3/Storage-Lens" -MetricName "CurrentVersionObjectCount" `
                                -StartTime $UtcStartTime `
                                -EndTime $UtcEndTime `
                                -Period 86400 `
                                -Credential $Credential -Region $matchingDashboardRegion `
                                -Dimensions $configIdDim, $accountDim, $regionDim, $bucketDim, $metricsVersionDim, $recordTypeDim, $storageClassDim -ErrorAction Stop

                $currentVersionObjValue = ($storageLensObjMetrics.Datapoints | Sort-Object -Property Timestamp -Descending | Select-Object -First 1).Maximum
                $currentVersionObjectStorages.Add($storageClass, $currentVersionObjValue)
              } catch {
                Write-Debug "Failed to get CurrentVersionObjectCount for storage class $storageClass in bucket ${s3Bucket}: $_"
              }
            }
          } catch {
            Write-Debug "Failed to get CurrentVersionStorageBytes/CurrentVersionObjectCount for bucket $s3Bucket in region $Region using config '$matchingConfigId': $_"
          }
        } else {
          Write-Debug "Bucket $s3Bucket in region $Region is not covered by any Storage Lens configuration with CloudWatch publishing"
        }
      }

      if ($SkipBucketTags) {
        $bucketTags = @()
      } else {
        try {
          $bucketTags = Get-S3BucketTagging -BucketName $s3Bucket -Credential $Credential -Region $Region
        } catch {
          Write-Host "Failed to get S3 tag info for bucket $s3Bucket in region $Region in account $($AccountInfo.Account)." -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
      }

      $s3obj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "BucketName" = $s3Bucket
        "ResourceArn" = "arn:$($partitionId):s3:::$($s3Bucket)"
        "Region" = $Region
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      Add-BackupColumnsToRow -Row $s3obj -ResourceArn "arn:$($partitionId):s3:::$($s3Bucket)"
      # S3 size conversions have swapped GB/GiB labels (existing behavior preserved as-is)
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

      # Add CurrentVersionBytes properties from Storage Lens metrics (per storage class)
      foreach ($cvStorage in $currentVersionBytesStorages.GetEnumerator()) {
        if ($null -eq $($cvStorage.Value)) {
          $cvBytesStorageSize = 0
          $cvSizeGB = 0
          $cvSizeTB = 0
          $cvSizeGiB = 0
          $cvSizeTiB = 0
        } else {
          $cvBytesStorageSize = $($cvStorage.Value)
          $cvSizeGB = $($cvStorage.Value) / 1073741824
          $cvSizeTB = $cvSizeGB / 1000
          $cvSizeGiB = $cvSizeGB / 1.073741824
          $cvSizeTiB = $cvSizeGiB / 1024
        }
        Add-Member -InputObject $s3obj -NotePropertyName ("CurrentVersion_" + $($cvStorage.Name) + "_SizeBytes") -NotePropertyValue $cvBytesStorageSize
        Add-Member -InputObject $s3obj -NotePropertyName ("CurrentVersion_" + $($cvStorage.Name) + "_SizeGB") -NotePropertyValue $([math]::round($cvSizeGB, 3))
        Add-Member -InputObject $s3obj -NotePropertyName ("CurrentVersion_" + $($cvStorage.Name) + "_SizeTB") -NotePropertyValue $([math]::round($cvSizeTB, 4))
        Add-Member -InputObject $s3obj -NotePropertyName ("CurrentVersion_" + $($cvStorage.Name) + "_SizeGiB") -NotePropertyValue $([math]::round($cvSizeGiB, 3))
        Add-Member -InputObject $s3obj -NotePropertyName ("CurrentVersion_" + $($cvStorage.Name) + "_SizeTiB") -NotePropertyValue $([math]::round($cvSizeTiB, 4))
      }

      # Add CurrentVersionObjectCount properties from Storage Lens metrics (per storage class)
      foreach ($cvObjStorage in $currentVersionObjectStorages.GetEnumerator()) {
        if ($null -eq $($cvObjStorage.Value)) {
          $cvObjCount = 0
        } else {
          $cvObjCount = $($cvObjStorage.Value)
        }
        Add-Member -InputObject $s3obj -NotePropertyName ("CurrentVersionObjectCount_" + $($cvObjStorage.Name)) -NotePropertyValue $cvObjCount
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

      $s3Result.Add($s3obj) | Out-Null
    }
    Write-Progress -ID 3 -Activity "Processing bucket: $($s3Bucket)" -Completed

    return ,$s3Result
}

function Get-AWSEC2Inventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $ec2InstanceResult = New-Object collections.arraylist
    $ec2AttachedVolResult = New-Object collections.arraylist
    $ec2UnattachedVolResult = New-Object collections.arraylist

    $ec2Instances = $null
    try{
      $ec2Instances = (Get-EC2Instance -Credential $Credential -region $Region -ErrorAction Stop).instances
    } catch {
      Write-Host "Failed to get EC2 Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    $counter = 1
    foreach ($ec2 in $ec2Instances) {
      Write-Progress -ID 4 -Activity "Processing EC2 Instance: $($ec2.InstanceId)" -Status "Instance $($counter) of $($ec2Instances.Count)" -PercentComplete (($counter / $ec2Instances.Count) * 100)
      $counter++
      $volSize = 0
      # Contains list of attached volumes to the current EC2 instance
      $blockDeviceMappings = $ec2.BlockDeviceMappings
      $volumes = $blockDeviceMappings.ebs

      # Get EC2 instance name for reference in attached volumes
      $ec2InstanceName = $ec2.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}

      # Iterate through each volume and sum up the volume size, also collect individual volume details
      foreach ($blockDevice in $blockDeviceMappings) {
        $vol = $blockDevice.ebs
        if ($null -eq $vol) { continue }

        try{
          $volumeDetails = Get-EC2Volume -VolumeId $vol.VolumeId -Credential $Credential -region $Region -ErrorAction Stop
          $volSize += $volumeDetails.Size

          # Create attached volume object with full details and tags
          $volSizes = ConvertTo-SizeUnits -Value $volumeDetails.Size -Prefix "Size" -InputUnit GiB -GBPrecision 3
          $attachedVolObj = [PSCustomObject] @{
            "AwsAccountId" = $AccountInfo.Account
            "AwsAccountAlias" = $AccountAlias
            "VolumeId" = $volumeDetails.VolumeId
            "ResourceArn" = "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):volume/$($volumeDetails.VolumeId)"
            "InstanceId" = $ec2.InstanceId
            "InstanceName" = $ec2InstanceName
            "Name" = $volumeDetails.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
            "DeviceName" = $blockDevice.DeviceName
            "SizeGiB" = $volSizes["SizeGiB"]
            "SizeTiB" = $volSizes["SizeTiB"]
            "SizeGB" = $volSizes["SizeGB"]
            "SizeTB" = $volSizes["SizeTB"]
            "Region" = $Region
            "AvailabilityZone" = $volumeDetails.AvailabilityZone
            "VolumeType" = $volumeDetails.VolumeType
            "State" = $volumeDetails.State
            "Iops" = $volumeDetails.Iops
            "Throughput" = $volumeDetails.Throughput
            "Encrypted" = $volumeDetails.Encrypted
            "BackupPlans" = ""
            "InBackupPlan" = $false
          }
          Add-BackupColumnsToRow -Row $attachedVolObj `
            -ResourceArn "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):volume/$($volumeDetails.VolumeId)"

          # Add volume-level tags
          foreach ($tag in $volumeDetails.Tags) {
            $key = $tag.Key -replace '[^a-zA-Z0-9]', '_'
            if($key -ne "Name"){
              $attachedVolObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
            }
          }

          $ec2AttachedVolResult.Add($attachedVolObj) | Out-Null
        } catch {
          Write-Host "Failed to get size of EC2 Volume $($vol.VolumeId) in $($ec2.InstanceId) for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
      }

      $instSizes = ConvertTo-SizeUnits -Value $volSize -Prefix "Size" -InputUnit GiB -GBPrecision 3
      $ec2obj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "InstanceId" = $ec2.InstanceId
        "ResourceArn" = "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):instance/$($ec2.InstanceId)"
        "Name" = $ec2InstanceName
        "Volumes" = $volumes.count
        "SizeGiB" = $instSizes["SizeGiB"]
        "SizeTiB" = $instSizes["SizeTiB"]
        "SizeGB" = $instSizes["SizeGB"]
        "SizeTB" = $instSizes["SizeTB"]
        "Region" = $Region
        "InstanceType" = $ec2.InstanceType
        "Platform" = $ec2.Platform
        "ProductCode" = $ec2.ProductCodes.ProductCodeType
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      Add-BackupColumnsToRow -Row $ec2obj `
        -ResourceArn "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):instance/$($ec2.InstanceId)"

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

      $ec2InstanceResult.Add($ec2obj) | Out-Null
    }
    Write-Progress -ID 4 -Activity "Processing EC2 Instance: $($ec2.InstanceId)" -Completed

    $ec2UnattachedVolumes = $null
    try{
      $ec2UnattachedVolumes = (Get-EC2Volume  -Credential $Credential -region $Region -Filter @{ Name="status"; Values="available" } -ErrorAction Stop)
    } catch {
      Write-Host "Failed to get EC2 Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    $counter = 1
    foreach ($ec2UnattachedVolume in $ec2UnattachedVolumes) {
      Write-Progress -ID 5 -Activity "Processing unattached EC2 volume: $($ec2UnattachedVolume.VolumeId)" -Status "Unattached EC2 volume $($counter) of $($ec2UnattachedVolumes.Count)" -PercentComplete (($counter / $ec2UnattachedVolumes.Count) * 100)
      $counter++

      $unVolSizes = ConvertTo-SizeUnits -Value $ec2UnattachedVolume.Size -Prefix "Size" -InputUnit GiB -GBPrecision 3
      $ec2UnVolObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "VolumeId" = $ec2UnattachedVolume.VolumeId
        "ResourceArn" = "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):volume/$($ec2UnattachedVolume.VolumeId)"
        "Name" = $ec2UnattachedVolume.Tags | ForEach-Object {if ($_.Key -ceq "Name") {Write-Output $_.Value}}
        "SizeGiB" = $unVolSizes["SizeGiB"]
        "SizeTiB" = $unVolSizes["SizeTiB"]
        "SizeGB" = $unVolSizes["SizeGB"]
        "SizeTB" = $unVolSizes["SizeTB"]
        "Region" = $Region
        "VolumeType" = $ec2UnattachedVolume.VolumeType
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      Add-BackupColumnsToRow -Row $ec2UnVolObj `
        -ResourceArn "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):volume/$($ec2UnattachedVolume.VolumeId)"

      foreach ($tag in $ec2UnattachedVolume.Tags) {
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_'
        if($key -ne "Name"){
          $ec2UnVolObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
        }
      }

      $ec2UnattachedVolResult.Add($ec2UnVolObj) | Out-Null
      Write-Progress -ID 5 -Activity "Processing unattached EC2 volume: $($ec2UnattachedVolume.VolumeId)" -Completed
    }

    return @{
      Instances = $ec2InstanceResult
      AttachedVolumes = $ec2AttachedVolResult
      UnattachedVolumes = $ec2UnattachedVolResult
      UnattachedVolumesRaw = $ec2UnattachedVolumes
    }
}

function Get-AWSRDSInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        [datetime]$UtcStartTime,
        [datetime]$UtcEndTime
    )

    $rdsResult = New-Object collections.arraylist

    $rdsDBs = $null
    try{
      $rdsDBs = Get-RDSDBInstance -Credential $Credential -region $Region -ErrorAction Stop
    } catch {
      Write-Host "Failed to get RDS Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    $counter = 1
    foreach ($rds in $rdsDBs) {
      Write-Progress -ID 6 -Activity "Processing RDS database: $($rds.DBInstanceIdentifier)" -Status "RDS database $($counter) of $($rdsDBs.Count)" -PercentComplete (($counter / $rdsDBs.Count) * 100)
      $counter++
      if($rds.Engine -like "*aurora*") {
        Write-Debug "Skipping Aurora database $($rds.DBInstanceIdentifier)"
        continue
      }
      $rdsSizes = ConvertTo-SizeUnits -Value $rds.AllocatedStorage -Prefix "Size" -InputUnit GiB -GBPrecision 3
      $rdsObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "DBName" = $rds.DBName
        "DBInstanceIdentifier" = $rds.DBInstanceIdentifier
        "DBClusterIdentifier" = $rds.DBClusterIdentifier
        "ResourceArn" = "arn:$($partitionId):rds:$($Region):$($AccountInfo.Account):db:$($rds.DBInstanceIdentifier)"
        "SizeGiB" = $rdsSizes["SizeGiB"]
        "SizeTiB" = $rdsSizes["SizeTiB"]
        "SizeGB" = $rdsSizes["SizeGB"]
        "SizeTB" = $rdsSizes["SizeTB"]
        "Region" = $Region
        "InstanceType" = $rds.DBInstanceClass
        "Engine" = $rds.Engine
        "EngineVersion" = $rds.EngineVersion
        "DBInstanceStatus" = $rds.DBInstanceStatus
        "BackupPlans" = ""
        "InBackupPlan" = $false
        "BackupRetentionPeriod" = $rds.BackupRetentionPeriod
        "PreferredBackupWindow" = $rds.PreferredBackupWindow
        "StorageType" = $rds.StorageType
        "EngineMode" = $null
        "InstanceCount" = 1
      }
      Add-BackupColumnsToRow -Row $rdsObj `
        -ResourceArn "arn:$($partitionId):rds:$($Region):$($AccountInfo.Account):db:$($rds.DBInstanceIdentifier)"

      foreach ($tag in $rds.TagList) {
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_'
        if($key -ne "Name"){
          $rdsObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
        }
      }

      $rdsResult.Add($rdsObj) | Out-Null
    }
    Write-Progress -ID 6 -Activity "Processing RDS database: $($rds.DBInstanceIdentifier)" -Completed

    try {
      $rdsDBClusters = Get-RDSDBCluster -Credential $Credential -region $Region -ErrorAction Stop
    }
    catch {
      Write-Host "Failed to get DB Clusters Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    $clusterList = New-Object collections.arraylist

    $counter = 1
    foreach ($cluster in $rdsDBClusters) {
      Write-Progress -ID 6 -Activity "Processing DB Cluster: $($cluster.DBClusterIdentifier)" -Status "DB Cluster $($counter) of $($rdsDBClusters.Count)" -PercentComplete (($counter / $rdsDBClusters.Count) * 100)
      $counter++
      if($cluster.Engine -notlike "*aurora*") {
        Write-Debug "Skipping non-Aurora cluster $($cluster.DBClusterIdentifier)"
        continue
      }

      $dimensions = @(
        @{
          Name = "DBClusterIdentifier"
          Value = $cluster.DBClusterIdentifier
        }
      )
      $storageGiB = 0
      try {
        $metrics = Get-CWMetricStatisticsForAllVersion -MetricName VolumeBytesUsed `
                    -Namespace "AWS/RDS" -Dimension $dimensions -StartTime $UtcStartTime `
                    -EndTime $UtcEndTime -Period 600 -Statistics Maximum `
                    -Region $Region -Credential $Credential -ErrorAction Stop
        $storageUsed = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
        $storageGiB = [math]::round($($storageUsed.Maximum / 1073741824), 4)
      }
      catch {
        Write-Host "Failed to get AuroraDB storage Info for $($cluster.DBClusterIdentifier) in region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
        $storageGiB = $rds.AllocatedStorage
      }

      $clusterSizes = ConvertTo-SizeUnits -Value $storageGiB -Prefix "Size" -InputUnit GiB -GBPrecision 3
      $clusterObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "DBName" = $cluster.DatabaseName
        "DBInstanceIdentifier" = $cluster.DBClusterIdentifier
        "DBClusterIdentifier" = $cluster.DBClusterIdentifier
        "ResourceArn" = "arn:$($partitionId):rds:$($Region):$($AccountInfo.Account):cluster:$($cluster.DBClusterIdentifier)"
        "SizeGiB" = $clusterSizes["SizeGiB"]
        "SizeTiB" = $clusterSizes["SizeTiB"]
        "SizeGB" = $clusterSizes["SizeGB"]
        "SizeTB" = $clusterSizes["SizeTB"]
        "Region" = $Region
        "InstanceType" = $cluster.DBClusterInstanceClass
        "Engine" = $cluster.Engine
        "EngineVersion" = $cluster.EngineVersion
        "DBInstanceStatus" = $cluster.Status
        "BackupPlans" = ""
        "InBackupPlan" = $false
        "BackupRetentionPeriod" = $cluster.BackupRetentionPeriod
        "PreferredBackupWindow" = $cluster.PreferredBackupWindow
        "StorageType" = $cluster.StorageType
        "EngineMode" = $cluster.EngineMode
        "InstanceCount" = if ($cluster.DBClusterMembers) { $cluster.DBClusterMembers.Count } else { 0 }
      }
      Add-BackupColumnsToRow -Row $clusterObj `
        -ResourceArn "arn:$($partitionId):rds:$($Region):$($AccountInfo.Account):cluster:$($cluster.DBClusterIdentifier)"

      foreach ($tag in $cluster.TagList) {
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_'
        if($key -ne "Name"){
          $clusterObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
        }
      }

      $clusterList.Add($clusterObj) | Out-Null
    }

    $rdsResult.AddRange($clusterList)

    return ,$rdsResult
}

function Get-AWSEFSInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $efsResult = New-Object collections.arraylist

    $efsListFromAPI = $null
    try{
      $efsListFromAPI = Get-EFSFileSystem -Credential $Credential -region $Region -ErrorAction Stop
    } catch {
      Write-Host "Failed to get EFS Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
    $counter = 1
    foreach ($efs in $efsListFromAPI) {
      Write-Progress -ID 7 -Activity "Processing EFS file system: $($efs.Name)" -Status "EFS file system $($counter) of $($efsListFromAPI.Count)" -PercentComplete (($counter / $efsListFromAPI.Count) * 100)
      $counter++

      $efsSizes = ConvertTo-SizeUnits -Value $efs.SizeInBytes.Value -Prefix "Size" -InputUnit Bytes
      $efsObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "FileSystemId" = $efs.FileSystemId
        "ResourceArn" = "arn:$($partitionId):elasticfilesystem:$($Region):$($AccountInfo.Account):file-system/$($efs.FileSystemId)"
        "FileSystemProtection" = $efs.FileSystemProtection.ReplicationOverwriteProtection.Value
        "Name" = $efs.Name
        "SizeInBytes" = $efs.SizeInBytes.Value
        "SizeGiB" = $efsSizes["SizeGiB"]
        "SizeTiB" = $efsSizes["SizeTiB"]
        "SizeGB" = $efsSizes["SizeGB"]
        "SizeTB" = $efsSizes["SizeTB"]
        "NumberOfMountTargets" = $efs.NumberOfMountTargets
        "OwnerId" = $efs.OwnerId
        "PerformanceMode" = $efs.PerformanceMode
        "ProvisionedThroughputInMibps" = $efs.ProvisionedThroughputInMibps
        "DBInstanceIdentifier" = $efs.DBInstanceIdentifier
        "Region" = $Region
        "ThroughputMode" = $efs.ThroughputMode
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      Add-BackupColumnsToRow -Row $efsObj `
        -ResourceArn "arn:$($partitionId):elasticfilesystem:$($Region):$($AccountInfo.Account):file-system/$($efs.FileSystemId)"

      foreach ($tag in $efs.Tags) {
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_'
        if($key -ne "Name"){
          $efsObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
        }
      }

      $efsResult.Add($efsObj) | Out-Null
    }
    Write-Progress -ID 7 -Activity "Processing EFS file system: $($efs.Name)" -Completed

    return ,$efsResult
}

function Get-AWSEKSInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $eksClusterResult = New-Object collections.arraylist
    $eksNodeGroupResult = New-Object collections.arraylist

    $eksListFromAPI = $null
    try{
      $eksListFromAPI = Get-EKSClusterList -Credential $Credential -region $Region -ErrorAction Stop
    } catch {
      Write-Host "Failed to get EKS Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Ingest EKS clusters. Do we need this information at all?
    $counter = 1
    foreach ($eks in $eksListFromAPI) {
      try{
        $eks = Get-EKSCluster -Credential $Credential -region $Region -Name $eks -ErrorAction Stop
      } catch {
        Write-Host "Failed to get EKS node group for node group $($nodeGroup.NodegroupName) in cluster $($eks.Name) for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      Write-Progress -ID 8 -Activity "Processing EKS Cluster: $($eks.Name)" -Status "EKS Cluster $($counter) of $($eksListFromAPI.Count)" -PercentComplete (($counter / $eksListFromAPI.Count) * 100)
      $counter++
      $eksObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "Name" = $eks.Name
        "Version" = $eks.Version
        "PlatformVersion" = $eks.PlatformVersion
        "Status" = $eks.Status.Value
        "Arn" = $eks.Arn
        "RoleArn" = $eks.RoleArn
        "Region" = $Region
      }
      # Note: As of August 2024, cannot add EKS to a backup plan, hence those fields are not here

      $tagCounter = 0
      foreach($key in $eks.Tags.Keys){
        $value = $eks.Tags.Values.Split('\n')[$tagCounter]
        $key = $key -replace '[^a-zA-Z0-9]', '_'
        $eksObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $value -Force
        $tagCounter++
      }

      $eksClusterResult.Add($eksObj) | Out-Null

      $eksNodeGroupListFromCluster = $null
      try{
        $eksNodeGroupListFromCluster = Get-EKSNodegroupList -Credential $Credential -region $Region -ClusterName $eks.Name -ErrorAction Stop
      } catch {
        Write-Host "Failed to get EKS Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }

      foreach($nodeGroup in $eksNodeGroupListFromCluster){
        try{
          $eksNodeGroup = Get-EKSNodegroup -Credential $Credential -region $Region -ClusterName $eks.Name -NodegroupName $nodeGroup -ErrorAction Stop
        } catch {
          Write-Host "Failed to get EKS node group for node group $($nodeGroup.NodegroupName) in cluster $($eks.Name) for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $eksNodeGroupObj = [PSCustomObject] @{
          "AwsAccountId" = $AccountInfo.Account
          "AwsAccountAlias" = $AccountAlias
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
          "Region" = $Region
        }

        $tagCounter = 0
        foreach($key in $eksNodeGroup.Tags.Keys){
          $value = $eksNodeGroup.Tags.Values.Split('\n')[$tagCounter]
          $key = $key -replace '[^a-zA-Z0-9]', '_'
          $eksNodeGroupObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $value -Force
          $tagCounter++
        }

        $eksNodeGroupResult.Add($eksNodeGroupObj) | Out-Null
      }

    }
    Write-Progress -ID 8 -Activity "Processing EKS Cluster: $($eks.Name)" -Completed

    return @{ Clusters = $eksClusterResult; NodeGroups = $eksNodeGroupResult }
}

function Get-AWSVPCInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $vpcResult = New-Object collections.arraylist
    try {
        $vpcs = Get-EC2Vpc -Credential $Credential -Region $Region -ErrorAction Stop
    } catch {
        Write-Host "Failed to get VPC info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
        return $vpcResult
    }

    foreach ($vpc in $vpcs) {
        $vpcObj = [PSCustomObject] @{
            "AwsAccountId"    = $AccountInfo.Account
            "AwsAccountAlias" = $AccountAlias
            "Region"          = $Region
            "VpcId"           = $vpc.VpcId
            "OwnerId"         = $vpc.OwnerId
            "CidrBlock"       = $vpc.CidrBlock
            "State"           = $vpc.State
            "IsDefault"       = $vpc.IsDefault
        }
        foreach ($tag in $vpc.Tags) {
            $key = $tag.Key -replace '[^a-zA-Z0-9-]', '_'
            # -Force is required because PSCustomObject rejects duplicate
            # property names. True key collisions after sanitization are
            # rare (only if a resource has tags whose names differ only
            # in non-alphanumeric characters, e.g. "cost-center" and
            # "cost_center").
            $vpcObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
        }
        $vpcResult.Add($vpcObj) | Out-Null
    }
    return $vpcResult
}

function Get-AWSLoadBalancerInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $lbResult = New-Object collections.arraylist

    try {
        Get-ELBLoadBalancer -Credential $Credential -Region $Region -ErrorAction Stop | ForEach-Object {
            $lb = $_
            $lbObj = [PSCustomObject] @{
                "AwsAccountId"     = $AccountInfo.Account
                "AwsAccountAlias"  = $AccountAlias
                "Region"           = $Region
                "LoadBalancerName" = $lb.LoadBalancerName
                "Type"             = "classic"
                "Scheme"           = $lb.Scheme
                "VpcId"            = $lb.VPCId
                "DNSName"          = $lb.DNSName
                "Arn"              = "arn:$($partitionId):elasticloadbalancing:${Region}:$($AccountInfo.Account):loadbalancer/$($lb.LoadBalancerName)"
            }
            try {
                $tagDescriptions = Get-ELBLoadBalancerTag -LoadBalancerName $lb.LoadBalancerName `
                    -Credential $Credential -Region $Region -ErrorAction Stop
                foreach ($desc in $tagDescriptions) {
                    foreach ($tag in $desc.Tags) {
                        $key = $tag.Key -replace '[^a-zA-Z0-9-]', '_'
                        if ($key -ne "Name") {
                            $lbObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
                        }
                    }
                }
            } catch {
                Write-Host "Failed to get tags for Classic LB $($lb.LoadBalancerName) in region $Region account $($AccountInfo.Account)" -ForeGroundColor Yellow
                Write-Host "Error: $_" -ForeGroundColor Yellow
            }
            $lbResult.Add($lbObj) | Out-Null
        }
    } catch {
        Write-Host "Failed to get Classic LBs for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
    }

    try {
        Get-ELB2LoadBalancer -Credential $Credential -Region $Region -ErrorAction Stop | ForEach-Object {
            $lb = $_
            $lbObj = [PSCustomObject] @{
                "AwsAccountId"     = $AccountInfo.Account
                "AwsAccountAlias"  = $AccountAlias
                "Region"           = $Region
                "LoadBalancerName" = $lb.LoadBalancerName
                "Type"             = $lb.Type
                "Scheme"           = $lb.Scheme
                "VpcId"            = $lb.VpcId
                "DNSName"          = $lb.DNSName
                "Arn"              = $lb.LoadBalancerArn
            }
            try {
                $tagDescriptions = Get-ELB2Tag -ResourceArn $lb.LoadBalancerArn `
                    -Credential $Credential -Region $Region -ErrorAction Stop
                foreach ($desc in $tagDescriptions) {
                    foreach ($tag in $desc.Tags) {
                        $key = $tag.Key -replace '[^a-zA-Z0-9-]', '_'
                        if ($key -ne "Name") {
                            $lbObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
                        }
                    }
                }
            } catch {
                Write-Host "Failed to get tags for v2 LB $($lb.LoadBalancerArn) in region $Region account $($AccountInfo.Account)" -ForeGroundColor Yellow
                Write-Host "Error: $_" -ForeGroundColor Yellow
            }
            $lbResult.Add($lbObj) | Out-Null
        }
    } catch {
        Write-Host "Failed to get v2 LBs for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
    }

    return $lbResult
}

function Get-AWSRoute53Inventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $r53Result = New-Object collections.arraylist
    try {
        $zones = Get-R53HostedZoneList -Credential $Credential -Region $Region -ErrorAction Stop
    } catch {
        Write-Host "Failed to get Route53 zones for account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
        return $r53Result
    }

    foreach ($zone in $zones) {
        $r53Result.Add([PSCustomObject] @{
            "AwsAccountId"           = $AccountInfo.Account
            "AwsAccountAlias"        = $AccountAlias
            "HostedZoneId"           = $zone.Id
            "Name"                   = $zone.Name
            "PrivateZone"            = $zone.Config.PrivateZone
            "ResourceRecordSetCount" = $zone.ResourceRecordSetCount
        }) | Out-Null
    }
    return $r53Result
}

function Get-AWSIAMInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $userCount = 0
    $roleCount = 0
    $policyCount = 0

    # Track per-cmdlet success so we can distinguish "real empty account" (all 3
    # succeed, return zeros) from "missing all 3 IAM permissions" (all 3 throw,
    # return $null so the orchestrator skips the row entirely). Without this,
    # the CSV would write Users=0/Roles=0/Policies=0 for both cases and the
    # Incubator App could not tell them apart.
    $userListSucceeded = $false
    $roleListSucceeded = $false
    $policyListSucceeded = $false

    try {
        $userCount = @(Get-IAMUserList -Credential $Credential -Region $Region -ErrorAction Stop).Count
        $userListSucceeded = $true
    } catch {
        Write-Host "Failed to get IAM users for account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
    }

    try {
        $roleCount = @(Get-IAMRoleList -Credential $Credential -Region $Region -ErrorAction Stop).Count
        $roleListSucceeded = $true
    } catch {
        Write-Host "Failed to get IAM roles for account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
    }

    try {
        $policyCount = @(Get-IAMPolicyList -Credential $Credential -Region $Region -Scope Local -ErrorAction Stop).Count
        $policyListSucceeded = $true
    } catch {
        Write-Host "Failed to get IAM policies for account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
    }

    if (-not $userListSucceeded -and -not $roleListSucceeded -and -not $policyListSucceeded) {
        # All three IAM permissions missing — return $null so the orchestrator skips
        # this account's IAM row entirely. Matches the KMS/Secrets/SQS pattern in
        # Get-AWSSimpleServiceCounts (line 1930). Per-cmdlet failures above already
        # surface to SEs via red Write-Host output (consistent with EC2/S3/RDS),
        # which is the failure-visibility mechanism for the script.
        return $null
    }

    return [PSCustomObject] @{
        "AwsAccountId"            = $AccountInfo.Account
        "AwsAccountAlias"         = $AccountAlias
        "Users"                   = $userCount
        "Roles"                   = $roleCount
        "CustomerManagedPolicies" = $policyCount
    }
}

function Get-AWSFSxInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        $UtcStartTime,
        $UtcEndTime
    )

    $fsxFileSystemResult = New-Object collections.arraylist
    $fsxVolumeResult = New-Object collections.arraylist

    $fsxFileSystemListFromAPI = $null
    try{
      $fsxFileSystemListFromAPI = Get-FSXFileSystem -Credential $Credential -region $Region -ErrorAction Stop
    } catch {
      Write-Host "Failed to get FSX File System Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Ingest FSX File systems
    $counter = 1
    foreach ($fileSystem in $fsxFileSystemListFromAPI) {
      Write-Progress -ID 9 -Activity "Processing FSx file system: $($fileSystem.DNSName)" -Status "FSx file system $($counter) of $($fsxFileSystemListFromAPI.Count)" -PercentComplete (($counter / $fsxFileSystemListFromAPI.Count) * 100)
      $counter++

      $fsxCapSizes = ConvertTo-SizeUnits -Value $fileSystem.StorageCapacity -Prefix "StorageCapacity" -InputUnit GiB
      $fsxObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "Region" = $Region
        "FileSystemId" = $filesystem.FileSystemId
        "ResourceArn" = "arn:$($partitionId):fsx:$($Region):$($AccountInfo.Account):file-system/$($filesystem.FileSystemId)"
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
        "StorageCapacityGiB" = $fsxCapSizes["StorageCapacityGiB"]
        "StorageCapacityTiB" = $fsxCapSizes["StorageCapacityTiB"]
        "StorageCapacityGB" = $fsxCapSizes["StorageCapacityGB"]
        "StorageCapacityTB" = $fsxCapSizes["StorageCapacityTB"]
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      Add-BackupColumnsToRow -Row $fsxObj `
        -ResourceArn "arn:$($partitionId):fsx:$($Region):$($AccountInfo.Account):file-system/$($filesystem.FileSystemId)"
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
          $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $storageUsed = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
        $maxStorageUsed = $storageUsed.Maximum

        $usedSizes = ConvertTo-SizeUnits -Value $maxStorageUsed -Prefix "StorageUsed" -InputUnit Bytes
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedBytes" -Value $maxStorageUsed -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedGiB" -Value $usedSizes["StorageUsedGiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedTiB" -Value $usedSizes["StorageUsedTiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedGB" -Value $usedSizes["StorageUsedGB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "StorageUsedTB" -Value $usedSizes["StorageUsedTB"] -Force

      } elseif($fsxObj.WindowsType -eq $true){
        $metricName = "StorageCapacityUtilization"
        try{
          $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
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
          $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Sum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $physicalDiskUsage = $metrics.Datapoints | Sort-Object -Property Sum -Descending | Select-Object -Index 0
        $maxPhysicalDiskUsage = $storageUsed.Sum

        $metricName = "LogicalDiskUsage"

        $metrics = $null
        try{
          $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Sum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $logicalDiskUsage = $metrics.Datapoints | Sort-Object -Property Sum -Descending | Select-Object -Index 0
        $maxLogicalDiskUsage = $storageUsed.Sum

        $metricName = "FreeDataStorageCapacity"
        $metrics = $null
        try{
          $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Sum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
#        $freeDataStorageCapacity = $metrics.Datapoints | Sort-Object -Property Sum -Descending | Select-Object -Index 0
        $minFreeDataStorageCapacity = $storageUsed.Sum

        $physicalSizes = ConvertTo-SizeUnits -Value $maxPhysicalDiskUsage -Prefix "PhysicalDiskUsage" -InputUnit Bytes
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageBytes" -Value $maxPhysicalDiskUsage -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageGiB" -Value $physicalSizes["PhysicalDiskUsageGiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageTiB" -Value $physicalSizes["PhysicalDiskUsageTiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageGB" -Value $physicalSizes["PhysicalDiskUsageGB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "PhysicalDiskUsageTB" -Value $physicalSizes["PhysicalDiskUsageTB"] -Force

        $logicalSizes = ConvertTo-SizeUnits -Value $maxLogicalDiskUsage -Prefix "LogicalDiskUsage" -InputUnit Bytes
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageBytes" -Value $maxLogicalDiskUsage -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageGiB" -Value $logicalSizes["LogicalDiskUsageGiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageTiB" -Value $logicalSizes["LogicalDiskUsageTiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageGB" -Value $logicalSizes["LogicalDiskUsageGB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "LogicalDiskUsageTB" -Value $logicalSizes["LogicalDiskUsageTB"] -Force

        $freeSizes = ConvertTo-SizeUnits -Value $minFreeDataStorageCapacity -Prefix "FreeDataStorageCapacity" -InputUnit Bytes
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityBytes" -Value $minFreeDataStorageCapacity -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityGiB" -Value $freeSizes["FreeDataStorageCapacityGiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityTiB" -Value $freeSizes["FreeDataStorageCapacityTiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityGB" -Value $freeSizes["FreeDataStorageCapacityGB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "FreeDataStorageCapacityTB" -Value $freeSizes["FreeDataStorageCapacityTB"] -Force

      } elseif($fsxObj.OpenZFSType -eq $true) {
        $metricName = "UsedStorageCapacity"
        $metrics = $null
        try{
          $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
        } catch {
          Write-Host "Failed to get FSX FileSystem $($filesystem.FileSystemId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
          Write-Host "Error: $_" -ForeGroundColor Red
        }
        $storageUsed = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
        $maxStorageUsed = $storageUsed.Maximum

        $usedCapSizes = ConvertTo-SizeUnits -Value $maxStorageUsed -Prefix "UsedStorageCapacity" -InputUnit Bytes
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityBytes" -Value $maxStorageUsed -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityGiB" -Value $usedCapSizes["UsedStorageCapacityGiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityTiB" -Value $usedCapSizes["UsedStorageCapacityTiB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityGB" -Value $usedCapSizes["UsedStorageCapacityGB"] -Force
        $fsxObj | Add-Member -MemberType NoteProperty -Name "UsedStorageCapacityTB" -Value $usedCapSizes["UsedStorageCapacityTB"] -Force

      }

      foreach ($tag in $fileSystem.Tags) {
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_'
        if($key -ne "Name"){
          $fsxObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
        }
      }
      $fsxFileSystemResult.Add($fsxObj) | Out-Null
    }
    Write-Progress -ID 9 -Activity "Processing FSx file system: $($fileSystem.DNSName)" -Completed

    $fsxListFromAPI = $null
    try{
      $fsxListFromAPI = Get-FSXVolume -Credential $Credential -region $Region -ErrorAction Stop
    } catch {
      Write-Host "Failed to get FSX Volume Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
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
        $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
      } catch {
        Write-Host "Failed to get FSX File Volume $($fsx.VolumeId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $storageUsed = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
      $maxStorageUsed = $storageUsed.Maximum

      $metricName = "StorageCapacity"
      $metrics = $null
      try{
        $metrics = Get-CWMetricStatisticsForAllVersion -Region $Region -Credential $Credential -MetricName $metricName -Namespace $namespace -Dimensions $dimensions -StartTime $UtcStartTime -EndTime $UtcEndTime -Period 3600 -Statistics Maximum -ErrorAction Stop
      } catch {
        Write-Host "Failed to get FSX File Volume $($fsx.VolumeId) Size Info for region $Region in account $($AccountInfo.Account) using Cloud Watch Metrics" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $storageCapacity = $metrics.Datapoints | Sort-Object -Property Maximum -Descending | Select-Object -Index 0
      $maxStorageCapacity = $storageCapacity.Maximum

      $filesystem = $null
      try{
        $filesystem = Get-FSXFileSystem -Credential $Credential -region $Region -FileSystemId $fsx.FileSystemId -ErrorAction Stop
      } catch {
        Write-Host "Failed to get FSX File System $($fsx.FileSystemId) Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }

      $volUsedSizes = ConvertTo-SizeUnits -Value $maxStorageUsed -Prefix "StorageUsed" -InputUnit Bytes
      $volCapSizes = ConvertTo-SizeUnits -Value $maxStorageCapacity -Prefix "StorageCapacity" -InputUnit Bytes
      $fsxObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "Region" = $Region
        "FileSystemId" = $fsx.FileSystemId
        "FileSystemDNSName" = $filesystem.DNSName
        "FileSystemType" = $filesystem.FileSystemType
        "FileSystemTypeVersion" = $filesystem.FileSystemTypeVersion
        "FileSystemOwnerId" = $filesystem.OwnerId
        "FileSystemStorageType" = $filesystem.StorageType
        "Name" = $fsx.Name
        "VolumeId" = $fsx.VolumeId
        "ResourceArn" = "arn:$($partitionId):fsx:$($Region):$($AccountInfo.Account):volume/$($fsx.VolumeId)"
        "VolumeType" = $fsx.VolumeType
        "LifeCycle" = $fsx.LifeCycle
        "StorageUsedBytes" = $maxStorageUsed
        "StorageUsedGiB" = $volUsedSizes["StorageUsedGiB"]
        "StorageUsedTiB" = $volUsedSizes["StorageUsedTiB"]
        "StorageUsedGB" = $volUsedSizes["StorageUsedGB"]
        "StorageUsedTB" = $volUsedSizes["StorageUsedTB"]
        "StorageCapacityBytes" = $maxStorageCapacity
        "StorageCapacityGiB" = $volCapSizes["StorageCapacityGiB"]
        "StorageCapacityTiB" = $volCapSizes["StorageCapacityTiB"]
        "StorageCapacityGB" = $volCapSizes["StorageCapacityGB"]
        "StorageCapacityTB" = $volCapSizes["StorageCapacityTB"]
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
      Add-BackupColumnsToRow -Row $fsxObj `
        -ResourceArn "arn:$($partitionId):fsx:$($Region):$($AccountInfo.Account):volume/$($fsx.VolumeId)"

      foreach ($tag in $fsx.Tags) {
        $key = $tag.Key -replace '[^a-zA-Z0-9]', '_'
        if($key -ne "Name"){
          $fsxObj | Add-Member -MemberType NoteProperty -Name "Tag: $key" -Value $tag.Value -Force
        }
      }

      $fsxVolumeResult.Add($fsxObj) | Out-Null
    }
    Write-Progress -ID 10 -Activity "Processing FSx volume: $($fsx.VolumeId)" -Status "FSx volume $($counter) of $($fsxListFromAPI.Count)" -Completed

    return @{ FileSystems = $fsxFileSystemResult; Volumes = $fsxVolumeResult }
}

function Get-AWSDynamoDBInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $ddbResult = New-Object collections.arraylist

    $ddbListFromAPI = $null
    try{
      $ddbListFromAPI = Get-DDBTableList -Credential $Credential -region $Region -ErrorAction Stop
    } catch {
      Write-Host "Failed to get DynamoDB Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    foreach($ddbName in $ddbListFromAPI){

      $ddbItem = $null
      try{
        $ddbItem = Get-DDBTable -TableName $ddbName -Credential $Credential -region $Region -ErrorAction Stop
      } catch {
        Write-Host "Failed to get DynamoDB Table $($ddbName) Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }

      $ddbSizes = ConvertTo-SizeUnits -Value $ddbItem.TableSizeBytes -Prefix "TableSize" -InputUnit Bytes
      $ddbObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "Region" = $Region
        "TableName" = $ddbItem.TableName
        "TableId" = $ddbItem.TableId
        "TableArn" = $ddbItem.TableArn
        "ResourceArn" = $ddbItem.TableArn
        "TableSizeBytes" = $ddbItem.TableSizeBytes
        "TableStatus" = $ddbItem.TableStatus.Value
        "TableSizeGiB" = $ddbSizes["TableSizeGiB"]
        "TableSizeTiB" = $ddbSizes["TableSizeTiB"]
        "TableSizeGB" = $ddbSizes["TableSizeGB"]
        "TableSizeTB" = $ddbSizes["TableSizeTB"]
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
        "PITREnabled" = $false
      }
      Add-BackupColumnsToRow -Row $ddbObj -ResourceArn $ddbItem.TableArn
      $ddbResult.add($ddbObj) | Out-Null

    }

    return ,$ddbResult
}

function Get-AWSSimpleServiceCounts {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $secretsObj = $null
    $sqsObj = $null

#Start ingesting SecretsManager information
    try{
      $numberOfSecrets = (Get-SECSecretList -Region $Region -ErrorAction Stop).Count
      $secretsObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "Region" = $Region
        "Secrets" = $numberOfSecrets
      }
    } catch{
      Write-Host "Failed to get # of secrets for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
  #Ingest SQS Queues
    try{
      $numberOfSQSQueues = (Get-SQSQueue -Region $Region -ErrorAction Stop).Count
      $sqsObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "Region" = $Region
        "Queues" = $numberOfSQSQueues
      }
    } catch{
      Write-Host "Failed to get # of SQS Queues for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

    return @{ Secrets = $secretsObj; SQS = $sqsObj }
}

function Get-AWSKMSInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $kmsResult = New-Object collections.arraylist

    $keyList = $null
    try {
        $keyList = Get-KMSKeyList -Credential $Credential -Region $Region -ErrorAction Stop
    } catch {
        Write-Host "Failed to list KMS keys for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
        return ,$kmsResult
    }

    $counter = 1
    $totalKeys = @($keyList).Count
    foreach ($key in $keyList) {
        Write-Progress -ID 8 -Activity "Processing KMS key: $($key.KeyId)" -Status "KMS key $counter of $totalKeys" -PercentComplete (($counter / [Math]::Max($totalKeys,1)) * 100)
        $counter++
        try {
            $meta = Get-KMSKey -KeyId $key.KeyId -Credential $Credential -Region $Region -ErrorAction Stop
        } catch {
            Write-Host "Failed to describe KMS key $($key.KeyId) in region $Region account $($AccountInfo.Account)" -ForeGroundColor Yellow
            Write-Host "Error: $_" -ForeGroundColor Yellow
            continue
        }

        # Emit both AWS-managed and customer-managed keys. The KeyManager column
        # ("AWS" vs "CUSTOMER") is the filter downstream consumers use to slice
        # the inventory; we no longer drop AWS-managed defaults here.
        # Look up the visible alias(es) attached to this key. Customer-managed
        # keys may have user-defined aliases; AWS-managed keys have AWS-generated
        # aliases like alias/aws/<service>. Join multiple aliases with semicolons;
        # missing aliases stay blank.
        $aliasName = $null
        try {
            $aliases = Get-KMSAliasList -KeyId $key.KeyId -Credential $Credential -Region $Region -ErrorAction Stop
            if ($aliases) {
                $aliasName = (@($aliases) | ForEach-Object { $_.AliasName }) -join '; '
            }
        } catch {
            Write-Host "Failed to list aliases for KMS key $($key.KeyId) in region $Region account $($AccountInfo.Account)" -ForeGroundColor Yellow
            Write-Host "Error: $_" -ForeGroundColor Yellow
        }

        # Stringify CreationDate (ISO-8601). Anonymization recurses into PSObject
        # properties; raw [datetime] values trip on the ReadOnly DateTime member.
        $creationDateStr = $null
        if ($null -ne $meta.CreationDate) {
            $creationDateStr = ([datetime]$meta.CreationDate).ToUniversalTime().ToString('o')
        }

        $kmsObj = [PSCustomObject] @{
            "AwsAccountId"    = $AccountInfo.Account
            "AwsAccountAlias" = $AccountAlias
            "Region"          = $Region
            "Alias"           = $aliasName
            "KeyId"           = $meta.KeyId
            "Arn"             = $meta.Arn
            "KeyManager"      = $meta.KeyManager
            "KeyState"        = $meta.KeyState
            "CreationDate"    = $creationDateStr
        }
        $kmsResult.Add($kmsObj) | Out-Null
    }
    Write-Progress -ID 8 -Activity "Processing KMS keys" -Completed

    return ,$kmsResult
}

# Resolve an AWS Backup `aws:ResourceTag/<key>` condition against a workload row.
# Rows expose flattened tags as direct NoteProperties with sanitized keys
# (the existing per-collector tag wire-up replaces non-alphanumeric chars with `_`),
# so we sanitize the condition's tag-key the same way before looking it up.
# Op = Equals -> exact string compare; Op = Like -> PowerShell -like (supports `*`).
function Test-RowTagConditionMatch {
    param($Row, $Cond)
    # AWS Backup selection conditions arrive in two formats:
    #   - BackupSelection.ListOfTags entries carry a BARE tag name as ConditionKey
    #     (e.g. "backup"). This is the format AWS Organizations backup policies
    #     materialize into, used by ~all of the org-managed plans we see in the
    #     field.
    #   - BackupSelection.Conditions.StringEquals/etc. entries carry the IAM-style
    #     fully-qualified key "aws:ResourceTag/<name>" (e.g. "aws:ResourceTag/backup").
    # Normalize both to the bare tag name before lookup.
    $rawKey = "$($Cond.Key)"
    if ($rawKey -match '^aws:ResourceTag/(.+)$') {
        $tagKey = $matches[1]
    } else {
        $tagKey = $rawKey
    }
    $sanitizedKey = $tagKey -replace '[^a-zA-Z0-9]', '_'
    $prop = $Row.PSObject.Properties[$sanitizedKey]
    if ($null -eq $prop) { return $false }
    $rowValue = $prop.Value
    if ($null -eq $rowValue) { return $false }
    switch ($Cond.Op) {
        'Equals' { return ("$rowValue" -eq "$($Cond.Value)") }
        'Like'   { return ("$rowValue" -like "$($Cond.Value)") }
    }
    return $false
}

# Evaluate a workload row against an AWS Backup selection's tag-based criteria.
# Semantics per AWS docs:
#   - ListOfTags: OR across entries (any one match qualifies).
#   - Conditions.StringEquals / StringLike: AND across entries.
#   - Conditions.StringNotEquals / StringNotLike: negation, any match disqualifies.
# An empty criteria set returns $false so the caller can keep ARN-based matching
# as the only path when no tag/condition selection is present.
function Test-RowMatchesSelection {
    param($Row, $OrTags, $AndConds, $NotConds)
    $anyCriteria = ($OrTags.Count + $AndConds.Count + $NotConds.Count) -gt 0
    if (-not $anyCriteria) { return $false }
    if ($OrTags.Count -gt 0) {
        $matched = $false
        foreach ($t in $OrTags) {
            if (Test-RowTagConditionMatch -Row $Row -Cond $t) { $matched = $true; break }
        }
        if (-not $matched) { return $false }
    }
    foreach ($c in $AndConds) {
        if (-not (Test-RowTagConditionMatch -Row $Row -Cond $c)) { return $false }
    }
    foreach ($c in $NotConds) {
        if (Test-RowTagConditionMatch -Row $Row -Cond $c) { return $false }
    }
    return $true
}

function Get-AWSBackupPlanInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        $EC2List,
        $EC2UnattachedVolumesRaw,
        $EC2AttachedVolList,
        $RDSList,
        $EFSList,
        $FSxList,
        $FSxFileSystemList,
        $S3List,
        $DDBList
    )

    $backupPlanResult = New-Object collections.arraylist

# Ingest AWS Backup Plans with explicit NextToken pagination. Without this,
# customers with >100 plans had silent truncation. Get-BAKProtectedResourceList
# is no longer called: the per-resource backup attribution path is now the
# recovery-point enumeration in Get-AWSBackupRecoveryPointInventory, which is a
# strict superset; deleting it also drops the protected_objects.csv leak that
# was never registered in $outputFiles.
    $BackupPlans = New-Object collections.arraylist
    try {
      $bpToken = $null
      do {
        # Page-size parameter omitted: AWS.Tools v4/v5 disagree on -MaxResult vs
        # -MaxResults for the BAK cmdlets, so rely on the cmdlet's default page
        # size (typically 100 or 1000) and use NextToken for termination.
        $bpParams = @{ Credential = $Credential; Region = $Region }
        if ($bpToken) { $bpParams.NextToken = $bpToken }
        $bpPage = Invoke-AWSWithRetry -Context "Get-BAKBackupPlanList-$Region" -ScriptBlock {
          Get-BAKBackupPlanList @bpParams -ErrorAction Stop
        }
        if ($bpPage) { [void]$BackupPlans.AddRange(@($bpPage)) }
        $bpToken = $AWSHistory.LastServiceResponse.NextToken
      } while ($bpToken)
    } catch {
      Write-Host "Failed to get Backup Plans Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
    try {
    $counter = 1
    foreach ($plan in $BackupPlans) {
      Write-Progress -ID 11 -Activity "Processing Backup Plan: $($plan.BackupPlanId)" -Status "Plan $($counter) of $($BackupPlans.Count)" -PercentComplete (($counter / $BackupPlans.Count) * 100)
      $counter++

      try{
        $BackupPlanObject = (Get-BAKBackupPlan -Credential $Credential -region $Region -BackupPlanId $plan.BackupPlanId) | ConvertTo-Json -Depth 10 | ConvertFrom-Json
      } catch {
        Write-Host "Failed to get Backup Plans $($plan.BackupPlanId) for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $BackupPlanObject | Add-Member -MemberType NoteProperty -Name "Resources" -Value @()
      $selections = New-Object collections.arraylist
      try {
        $selToken = $null
        do {
          $selParams = @{ Credential = $Credential; Region = $Region; BackupPlanId = $plan.BackupPlanId }
          if ($selToken) { $selParams.NextToken = $selToken }
          $selPage = Invoke-AWSWithRetry -Context "Get-BAKBackupSelectionList-$($plan.BackupPlanId)" -ScriptBlock {
            Get-BAKBackupSelectionList @selParams -ErrorAction Stop
          }
          if ($selPage) { [void]$selections.AddRange(@($selPage)) }
          $selToken = $AWSHistory.LastServiceResponse.NextToken
        } while ($selToken)
      } catch {
        Write-Host "Failed to get Backup Selections for Plan $($plan.BackupPlanId) for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $selectionCounter = 1
      foreach ($selection in $selections) {
        Write-Progress -ID 12 -Activity "Processing Backup Plan/Selection: $($selection.SelectionId)" -Status "Backup Plan/Selection $($selectionCounter) of $($selections.Count)" -PercentComplete (($selectionCounter / $selections.Count) * 100)
        $selectionCounter++
        try{
          $foundSelection = Get-BakBackupSelection -Credential $Credential -region $Region -BackupPlanId $plan.BackupPlanId -SelectionId $selection.SelectionId
        } catch {
          Write-Host "Failed to get Backup Selection $($selection.SelectionId) for Plan $($plan.BackupPlanId) for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
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
                  foreach ($ec2Obj in $EC2List) {
                    # Instance id will be fetched as * if all instances are backed up
                    if (($ec2Obj.InstanceId -eq $instanceId -or "*" -eq $instanceId) -and $Region -eq $ec2Obj.Region -and $AccountInfo.Account -eq $ec2Obj.AwsAccountId) {
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
                  # Check unattached volumes
                  foreach ($ec2Obj in $EC2UnattachedVolumesRaw) {
                    # Volume id will be fetched as * if all ebs volumes are backed up
                    if (($ec2Obj.VolumeId -eq $volId -or "*" -eq $volId) -and $Region -eq $ec2Obj.Region -and $AccountInfo.Account -eq $ec2Obj.AwsAccountId) {
                      if ("" -eq $ec2Obj.BackupPlans) {
                          $ec2Obj.BackupPlans = "$($plan.BackupPlanName)"
                      }
                      else {
                          $ec2Obj.BackupPlans += ", $($plan.BackupPlanName)"
                      }
                      $ec2Obj.InBackupPlan = $true
                    }
                  }
                  # Check attached volumes
                  foreach ($attachedVolObj in $EC2AttachedVolList) {
                    if (($attachedVolObj.VolumeId -eq $volId -or "*" -eq $volId) -and $Region -eq $attachedVolObj.Region -and $AccountInfo.Account -eq $attachedVolObj.AwsAccountId) {
                      if ("" -eq $attachedVolObj.BackupPlans) {
                          $attachedVolObj.BackupPlans = "$($plan.BackupPlanName)"
                      }
                      else {
                          $attachedVolObj.BackupPlans += ", $($plan.BackupPlanName)"
                      }
                      $attachedVolObj.InBackupPlan = $true
                    }
                  }
                }
              }
            }
            "rds" {
                $RDSId = ($resource -split ':')[6]
                foreach ($rdsObj in $RDSList) {
                  if (($rdsObj.DBInstanceIdentifier -eq $RDSId -or "*" -eq $RDSId) -and $Region -eq $rdsObj.Region -and $AccountInfo.Account -eq $rdsObj.AwsAccountId) {
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
                foreach ($efsObj in $EFSList) {
                  if (($efsObj.FileSystemId -eq $EFSId -or "*" -eq $EFSId) -and $Region -eq $efsObj.Region -and $AccountInfo.Account -eq $efsObj.AwsAccountId) {
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
                foreach ($fsxObj in $FSxList) {
                  if ($Region -eq $fsxObj.Region -and $AccountInfo.Account -eq $fsxObj.AwsAccountId) {
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
                foreach ($fsxObj in $FSxList) {
                  if ($fsxObj.VolumeId -eq $VolumeId -and $fsxObj.FileSystemId -eq $FileSystemId -and $Region -eq $fsxObj.Region -and $AccountInfo.Account -eq $fsxObj.AwsAccountId) {
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
                foreach ($s3Obj in $S3List) {
                  if ($Region -eq $s3Obj.Region -and $AccountInfo.Account -eq $s3Obj.AwsAccountId) {
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
                foreach ($s3Obj in $S3List) {
                  if ($s3Obj.BucketName -eq $S3Name -and $Region -eq $s3Obj.Region -and $AccountInfo.Account -eq $s3Obj.AwsAccountId) {
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
                foreach ($ddbObj in $DDBList) {
                  if ($Region -eq $ddbObj.Region -and $AccountInfo.Account -eq $ddbObj.AwsAccountId) {
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
                foreach ($ddbObj in $DDBList) {
                  if ($ddbObj.BucketName -eq $ddbName -and $Region -eq $ddbObj.Region -and $AccountInfo.Account -eq $ddbObj.AwsAccountId) {
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

        # Tag-based selection: parse ListOfTags (OR) and Conditions (AND/negation),
        # then iterate every workload row in scope to set BackupPlans / InBackupPlan.
        # Tag-matched ARNs are NOT pushed into BackupPlanObject.Resources -- the
        # aws-backup-plans-info-*.json `Resources` array must remain ARN-only
        # (byte-identical for plans whose Resources is empty today).
        $orTags = @()
        if ($foundSelection.BackupSelection.ListOfTags) {
          foreach ($t in $foundSelection.BackupSelection.ListOfTags) {
            if ("$($t.ConditionType)".ToUpperInvariant() -eq 'STRINGEQUALS') {
              $orTags += @{ Op = 'Equals'; Key = $t.ConditionKey; Value = $t.ConditionValue }
            }
          }
        }
        $andConds = @()
        $notConds = @()
        if ($foundSelection.BackupSelection.Conditions) {
          foreach ($c in @($foundSelection.BackupSelection.Conditions.StringEquals)) {
            if ($null -ne $c) { $andConds += @{ Op = 'Equals'; Key = $c.ConditionKey; Value = $c.ConditionValue } }
          }
          foreach ($c in @($foundSelection.BackupSelection.Conditions.StringLike)) {
            if ($null -ne $c) { $andConds += @{ Op = 'Like'; Key = $c.ConditionKey; Value = $c.ConditionValue } }
          }
          foreach ($c in @($foundSelection.BackupSelection.Conditions.StringNotEquals)) {
            if ($null -ne $c) { $notConds += @{ Op = 'Equals'; Key = $c.ConditionKey; Value = $c.ConditionValue } }
          }
          foreach ($c in @($foundSelection.BackupSelection.Conditions.StringNotLike)) {
            if ($null -ne $c) { $notConds += @{ Op = 'Like'; Key = $c.ConditionKey; Value = $c.ConditionValue } }
          }
        }

        $allWorkloadLists = @(
          $EC2List, $EC2UnattachedVolumesRaw, $EC2AttachedVolList, $RDSList,
          $EFSList, $FSxList, $FSxFileSystemList, $S3List, $DDBList
        )

        if ($orTags.Count -gt 0 -or $andConds.Count -gt 0 -or $notConds.Count -gt 0) {
          foreach ($list in $allWorkloadLists) {
            if ($null -eq $list) { continue }
            foreach ($row in $list) {
              if ($null -eq $row) { continue }
              if ("$Region" -ne "$($row.Region)") { continue }
              if ("$($AccountInfo.Account)" -ne "$($row.AwsAccountId)") { continue }
              if (-not (Test-RowMatchesSelection -Row $row -OrTags $orTags -AndConds $andConds -NotConds $notConds)) { continue }
              if ("" -eq $row.BackupPlans) {
                $row.BackupPlans = "$($plan.BackupPlanName)"
              } else {
                $existing = @($row.BackupPlans -split ',\s*' | Where-Object { $_ })
                if ($existing -notcontains $plan.BackupPlanName) {
                  $row.BackupPlans += ", $($plan.BackupPlanName)"
                }
              }
              $row.InBackupPlan = $true
            }
          }
        }

        # NotResources exclusion: applied AFTER all resource/tag/condition rules above
        # have set InBackupPlan=$true. Any row whose ResourceArn matches an excluded ARN
        # for this plan is reverted -- this plan is removed from BackupPlans, and
        # InBackupPlan flips back to $false if no other plan still names the row.
        if ($foundSelection.BackupSelection.NotResources) {
          $excluded = @{}
          foreach ($e in $foundSelection.BackupSelection.NotResources) { $excluded["$e"] = $true }
          foreach ($list in $allWorkloadLists) {
            if ($null -eq $list) { continue }
            foreach ($row in $list) {
              if ($null -eq $row) { continue }
              if ($null -eq $row.PSObject.Properties['ResourceArn']) { continue }
              if (-not $excluded.ContainsKey("$($row.ResourceArn)")) { continue }
              $remaining = @($row.BackupPlans -split ',\s*' | Where-Object { $_ -and $_ -ne $plan.BackupPlanName })
              $row.BackupPlans = $remaining -join ', '
              if ($remaining.Count -eq 0) { $row.InBackupPlan = $false }
            }
          }
        }
      }
      Write-Progress -ID 12 -Activity "Processing Backup Plan/Selection: $($selection.SelectionId)" -Completed
      $backupPlanResult.Add($BackupPlanObject) | Out-Null
    }
  } catch {
    Write-Host "Failed to query backup vaults for region $Region";
  }
  Write-Progress -ID 11 -Activity "Processing Backup Plan: $($plan.BackupPlanId)" -Completed

  return , $backupPlanResult
}

function Get-AWSBackupRecoveryPointInventory {
    # Params are non-mandatory to match the surrounding collectors: getAWSData calls
    # them with whatever account/credential context it resolved, which may be null
    # in degraded runs. The cmdlet returns an empty result rather than hard-failing
    # the whole region loop in that case.
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        [int]$TimeoutMinutes = 60,
        $PlanNameById = $null
    )

    # Enumerates every recovery point in every backup vault in $Region (paged with
    # explicit NextToken loops), streams the per-RP rows to a per-region scratch CSV,
    # and returns a per-(account, region, ResourceArn) aggregate held in memory.
    #
    # Returns PSCustomObject:
    #   .RecoveryPoints      -- arraylist of per-RP rows (also streamed to the tmp CSV)
    #   .ResourceAggregates  -- arraylist of per-(account, region, ARN) aggregate rows
    #   .Truncated           -- bool, true if the region's time budget was hit
    #   .VaultsAccessDenied  -- int, count of vaults where ListRPs threw AccessDenied

    $recoveryPoints   = New-Object collections.arraylist
    $resourceAgg      = @{}   # ResourceArn -> aggregate hashtable
    $truncated        = $false
    $vaultsAccessDenied = 0

    # Degraded-run guard: getAWSData may pass null AccountInfo if STSCallerIdentity
    # failed earlier. Without this, the tmp-filename build + per-row Account field
    # would NRE rather than gracefully degrade.
    if ($null -eq $AccountInfo) {
        return [PSCustomObject]@{
            RecoveryPoints     = $recoveryPoints
            ResourceAggregates = New-Object collections.arraylist
            Truncated          = $false
            VaultsAccessDenied = 0
        }
    }

    # Per-region scratch file. The '.tmp.csv' suffix keeps it distinct from the
    # canonical 'aws_backup_recovery_points-{date}.csv' output; the date string ties
    # orphan globs to a single run. The account id keeps org-run regions from
    # colliding across accounts. (A leading-dot name was avoided because Linux
    # PowerShell hides dotfiles from Get-ChildItem/Remove-Item without -Force,
    # which silently breaks the merge and orphan-cleanup globs.)
    $tmpFile = "aws_backup_recovery_points-$($AccountInfo.Account)-$Region-$date_string.tmp.csv"

    # Buffer of rows pending the next streaming flush (batches of ~1000).
    $flushBuffer = New-Object collections.arraylist
    $flushBatchSize = 1000

    # Streams the pending buffer to the per-region tmp file via Export-Csv -Append.
    $flushBuffered = {
        if ($flushBuffer.Count -gt 0) {
            $flushBuffer | Export-Csv -Path $tmpFile -Append -NoTypeInformation
            $flushBuffer.Clear()
        }
    }

    try {
        # NOTE: orphan tmp-file cleanup (from a prior crashed run) is done ONCE by the
        # caller (getAWSData) before the per-region loop -- NOT here. Globbing at
        # per-region entry would delete sibling regions' freshly-written tmp files
        # in the current run, leaving the post-loop merge with nothing for them.

        try {
            # Enumerate vaults (paged). Missing backup:ListBackupVaults surfaces as
            # AccessDenied here skips the whole region's RP enumeration and emits a single yellow line.
            $vaults = New-Object collections.arraylist
            try {
                $vaultToken = $null
                do {
                    $vaultParams = @{ Credential = $Credential; Region = $Region }
                    if ($vaultToken) { $vaultParams.NextToken = $vaultToken }
                    $vaultPage = Invoke-AWSWithRetry -Context "BAK-vault-list-$Region" -ScriptBlock {
                        Get-BAKBackupVaultList @vaultParams -ErrorAction Stop
                    }
                    if ($vaultPage) { [void]$vaults.AddRange(@($vaultPage)) }
                    $vaultToken = $AWSHistory.LastServiceResponse.NextToken
                } while ($vaultToken)
            } catch {
                if (Test-IsAccessDenied $_) {
                    Write-Host "Access denied listing backup vaults for region $Region in account $($AccountInfo.Account); skipping RP enumeration for this region." -ForegroundColor Yellow
                    return [PSCustomObject]@{
                        RecoveryPoints     = $recoveryPoints
                        ResourceAggregates = New-Object collections.arraylist
                        Truncated          = $false
                        VaultsAccessDenied = 0
                    }
                }
                throw
            }

            # Per-region time budget. Once exceeded we flush partial results and stop.
            $regionDeadline = (Get-Date).AddMinutes($TimeoutMinutes)
            $vaultAccessDeniedWarned = $false

            foreach ($vault in $vaults) {
                if ((Get-Date) -gt $regionDeadline) {
                    $truncated = $true
                    break
                }
                $vaultName = $vault.BackupVaultName

                try {
                    $rpToken = $null
                    do {
                        if ((Get-Date) -gt $regionDeadline) {
                            $truncated = $true
                            break
                        }
                        $rpParams = @{ Credential = $Credential; Region = $Region }
                        if ($rpToken) { $rpParams.NextToken = $rpToken }
                        $rpPage = Invoke-AWSWithRetry -Context "BAK-rp-list-$vaultName" -ScriptBlock {
                            Get-BAKRecoveryPointsByBackupVaultList @rpParams -BackupVaultName $vaultName -ErrorAction Stop
                        }
                        # Empty vault returns null per AWS Tools convention; coerce to empty array.
                        foreach ($rp in @($rpPage)) {
                            if ($null -eq $rp) { continue }
                            $row = New-AWSRecoveryPointRow -RecoveryPoint $rp -Region $Region `
                                -AccountInfo $AccountInfo -AccountAlias $AccountAlias `
                                -PlanNameById $PlanNameById
                            [void]$recoveryPoints.Add($row)
                            [void]$flushBuffer.Add($row)
                            if ($flushBuffer.Count -ge $flushBatchSize) { & $flushBuffered }

                            $sizeWasNull = ($null -eq $rp.BackupSizeInBytes)
                            Add-RecoveryPointToAggregate -Aggregate $resourceAgg -Row $row -SizeWasNull $sizeWasNull
                        }
                        $rpToken = $AWSHistory.LastServiceResponse.NextToken
                    } while ($rpToken)
                } catch {
                    if (Test-IsAccessDenied $_) {
                        $vaultsAccessDenied++
                        if (-not $vaultAccessDeniedWarned) {
                            Write-Host "Access denied listing recovery points for one or more vaults in region $Region in account $($AccountInfo.Account); those vaults are skipped." -ForegroundColor Yellow
                            $vaultAccessDeniedWarned = $true
                        }
                        continue
                    }
                    throw
                }
            }

            if ($truncated) {
                Write-Host "RP enumeration truncated after $TimeoutMinutes min for region $Region; capacity numbers are lower bounds for that region" -ForegroundColor Yellow
            }
        } finally {
            # Always flush whatever is buffered so partial results survive a timeout
            # or a mid-enumeration throw.
            & $flushBuffered
        }
    } catch {
        # On any unexpected failure, drop the region's partial tmp file so a later
        # merge can't pick up a half-written page.
        Remove-Item $tmpFile -ErrorAction SilentlyContinue
        throw
    }

    # Materialize the in-memory aggregate into output rows.
    $resourceAggregates = New-Object collections.arraylist
    foreach ($entry in $resourceAgg.Values) {
        [void]$resourceAggregates.Add((New-AWSRecoveryPointAggregateRow -State $entry))
    }

    return [PSCustomObject]@{
        RecoveryPoints     = $recoveryPoints
        ResourceAggregates = $resourceAggregates
        Truncated          = $truncated
        VaultsAccessDenied = $vaultsAccessDenied
    }
}

# Builds the flat per-RP record (the row schema for aws_backup_recovery_points-*.csv).
function New-AWSRecoveryPointRow {
    param(
        [Parameter(Mandatory)] $RecoveryPoint,
        [Parameter(Mandatory)] [string]$Region,
        [Parameter(Mandatory)] $AccountInfo,
        [string]$AccountAlias,
        $PlanNameById = $null
    )
    $rp = $RecoveryPoint

    $sizeBytes = if ($null -eq $rp.BackupSizeInBytes) { [long]0 } else { [long]$rp.BackupSizeInBytes }
    $sizes = ConvertTo-SizeUnits -Value $sizeBytes -Prefix "BackupSize" -InputUnit Bytes

    # CreatedBy is null on on-demand RPs created via start-backup-job.
    $backupPlanId   = if ($rp.CreatedBy) { $rp.CreatedBy.BackupPlanId } else { "" }
    $backupPlanName = if ($rp.CreatedBy) { $rp.CreatedBy.BackupPlanName } else { "" }
    if ($null -eq $backupPlanId)   { $backupPlanId = "" }
    if ($null -eq $backupPlanName) { $backupPlanName = "" }
    # AWS's ListRecoveryPointsByBackupVault response never populates
    # CreatedBy.BackupPlanName (per the RecoveryPointCreator API schema), so
    # without a side-channel lookup every RP row would read "". Fall back to a
    # caller-provided BackupPlanId -> BackupPlanName map (built from the local
    # Get-BAKBackupPlanList output, which includes org-managed plans).
    if ([string]::IsNullOrEmpty($backupPlanName) -and $backupPlanId -and
        $null -ne $PlanNameById -and $PlanNameById.ContainsKey($backupPlanId)) {
        $backupPlanName = "$($PlanNameById[$backupPlanId])"
    }

    [PSCustomObject]@{
        "AwsAccountId"           = $AccountInfo.Account
        "AwsAccountAlias"        = $AccountAlias
        "Region"                 = $Region
        "BackupVaultName"        = $rp.BackupVaultName
        "BackupVaultArn"         = $rp.BackupVaultArn
        "RecoveryPointArn"       = $rp.RecoveryPointArn
        "ResourceArn"            = $rp.ResourceArn
        "ResourceId"             = Get-ResourceIdFromArn $rp.ResourceArn
        "ResourceName"           = $rp.ResourceName
        "ResourceType"           = $rp.ResourceType
        "BackupSizeBytes"        = $sizeBytes
        "BackupSizeGiB"          = $sizes["BackupSizeGiB"]
        "BackupSizeTiB"          = $sizes["BackupSizeTiB"]
        "CreationDate"           = $rp.CreationDate
        "BackupPlanId"           = $backupPlanId
        "BackupPlanName"         = $backupPlanName
        "Status"                 = $rp.Status
        "IsParent"               = [bool]$rp.IsParent
        "ParentRecoveryPointArn" = $rp.ParentRecoveryPointArn
        "Source"                 = "AWSBackup"
    }
}

# Parses the resource identifier (i-0123, vol-0123, bucket name, ...) out of a
# resource ARN. Returns "" when the ARN is null/empty or has no recognizable id.
function Get-ResourceIdFromArn {
    param([string]$Arn)
    if ([string]::IsNullOrEmpty($Arn)) { return "" }
    # ARN form: arn:partition:service:region:account:resourceType/resourceId
    #        or arn:partition:service:region:account:resourceType:resourceId
    #        or arn:partition:s3:::bucket
    $resourcePart = ($Arn -split ':', 6)[-1]
    if ($resourcePart -match '[/:]') {
        return ($resourcePart -split '[/:]')[-1]
    }
    return $resourcePart
}

# Folds a single per-RP row into the per-(ResourceArn) aggregate state hashtable.
# IsParent rows are excluded from size/count; null sizes (coerced to 0 on the row)
# are tracked via NullSizeRecoveryPointCount.
function Add-RecoveryPointToAggregate {
    param(
        [Parameter(Mandatory)] [hashtable]$Aggregate,
        [Parameter(Mandatory)] $Row,
        [bool]$SizeWasNull = $false
    )

    # Composite parents double-count children's bytes; exclude them entirely.
    if ($Row.IsParent) { return }

    $arn = $Row.ResourceArn
    if ([string]::IsNullOrEmpty($arn)) { return }

    if (-not $Aggregate.ContainsKey($arn)) {
        $Aggregate[$arn] = @{
            AwsAccountId               = $Row.AwsAccountId
            Region                     = $Row.Region
            ResourceArn                = $arn
            ResourceType               = $Row.ResourceType
            ResourceName               = $Row.ResourceName
            RecoveryPointCount         = 0
            NullSizeRecoveryPointCount = 0
            LatestRecoveryPointArn     = $null
            LatestRecoveryPointDate    = $null
            LatestRecoveryPointSizeBytes = [long]0
            BackupPlanNames            = New-Object collections.arraylist
            BackupVaultNames           = New-Object collections.arraylist
        }
    }
    $state = $Aggregate[$arn]
    $state.RecoveryPointCount++

    if ($SizeWasNull) { $state.NullSizeRecoveryPointCount++ }

    if (-not [string]::IsNullOrEmpty($Row.BackupPlanName) -and
        -not $state.BackupPlanNames.Contains($Row.BackupPlanName)) {
        [void]$state.BackupPlanNames.Add($Row.BackupPlanName)
    }
    if (-not [string]::IsNullOrEmpty($Row.BackupVaultName) -and
        -not $state.BackupVaultNames.Contains($Row.BackupVaultName)) {
        [void]$state.BackupVaultNames.Add($Row.BackupVaultName)
    }

    if ($null -eq $state.LatestRecoveryPointDate -or
        ($null -ne $Row.CreationDate -and $Row.CreationDate -gt $state.LatestRecoveryPointDate)) {
        $state.LatestRecoveryPointDate      = $Row.CreationDate
        $state.LatestRecoveryPointArn       = $Row.RecoveryPointArn
        $state.LatestRecoveryPointSizeBytes = $Row.BackupSizeBytes
    }
}

# Converts an aggregate-state hashtable into the per-resource output row.
function New-AWSRecoveryPointAggregateRow {
    param([Parameter(Mandatory)] [hashtable]$State)
    [PSCustomObject]@{
        "AwsAccountId"                 = $State.AwsAccountId
        "Region"                       = $State.Region
        "ResourceArn"                  = $State.ResourceArn
        "ResourceType"                 = $State.ResourceType
        "ResourceName"                 = $State.ResourceName
        "RecoveryPointCount"           = $State.RecoveryPointCount
        "NullSizeRecoveryPointCount"   = $State.NullSizeRecoveryPointCount
        "LatestRecoveryPointArn"       = $State.LatestRecoveryPointArn
        "LatestRecoveryPointDate"      = $State.LatestRecoveryPointDate
        "LatestRecoveryPointSizeBytes" = $State.LatestRecoveryPointSizeBytes
        "BackupPlanNames"              = ($State.BackupPlanNames -join ", ")
        "BackupVaultNames"            = ($State.BackupVaultNames -join ", ")
    }
}

# Classifies an ErrorRecord as an AWS AccessDenied failure. Only this family is a
# graceful (yellow) degradation; everything else stays a hard (red) error.
function Test-IsAccessDenied {
    param([Parameter(Mandatory)] $ErrorRecord)
    # IAM denials surface under different names depending on the AWS service:
    #   - Most services: AccessDenied / AccessDeniedException
    #   - EC2 / EBS / AMI APIs: UnauthorizedOperation (and AuthFailure for
    #     pre-signed-request style failures)
    # All three are operator-actionable in the same way (the SE asks the
    # customer's admin to grant the missing permission), so they should
    # consistently route to the yellow degrade path.
    $denyPattern = 'AccessDenied|UnauthorizedOperation|AuthFailure'
    $ex = $ErrorRecord.Exception
    if ($null -eq $ex) { return $false }
    if ($ex.GetType().Name -match $denyPattern) { return $true }
    if ($ex.PSObject.Properties['ErrorCode'] -and $ex.ErrorCode -match $denyPattern) { return $true }
    return $false
}

# Header row mirroring the per-RP CSV schema. Used for the header-only canonical
# file and to seed the merged output. Hand-written as a literal so the quoting
# matches Export-Csv -Append below (ConvertTo-Csv quoting differs subtly between
# PS 5.1 and 7.x and would produce header/body quote mismatches).
function Get-AWSRecoveryPointCsvHeader {
    '"AwsAccountId","AwsAccountAlias","Region","BackupVaultName","BackupVaultArn","RecoveryPointArn","ResourceArn","ResourceId","ResourceName","ResourceType","BackupSizeBytes","BackupSizeGiB","BackupSizeTiB","CreationDate","BackupPlanId","BackupPlanName","Status","IsParent","ParentRecoveryPointArn","Source"'
}

# Tracks which canonical files this run has already created, so org runs accumulate
# RP rows across accounts (each per-account merge appends) rather than the second
# account's merge clobbering the first account's rows.
$script:RecoveryPointCanonicalSeeded = @{}

# Merges per-region recovery-point tmp files into the single canonical CSV and
# removes the tmp files. On the first call for a canonical path within a run, an
# existing file (e.g. an orphan from a prior crashed run) is removed first;
# subsequent per-account calls append. A merge failure cleans up the tmp files;
# the canonical file is left in whatever consistent state precedes the failing write.
function Merge-AWSRecoveryPointTmpFiles {
    param([Parameter(Mandatory)] [string]$CanonicalPath)

    $tmpGlob = "aws_backup_recovery_points-*-$date_string.tmp.csv"
    $tmpFiles = @(Get-ChildItem -Path $tmpGlob -ErrorAction SilentlyContinue)

    if ($null -eq $script:RecoveryPointCanonicalSeeded) {
        $script:RecoveryPointCanonicalSeeded = @{}
    }
    $firstSeedForRun = -not $script:RecoveryPointCanonicalSeeded.ContainsKey($CanonicalPath)

    try {
        # -Width guards against Out-File wrapping long CSV lines (default width is the
        # host buffer width, which is small/zero under non-interactive hosts).
        if ($firstSeedForRun) {
            if (Test-Path $CanonicalPath) { Remove-Item $CanonicalPath -ErrorAction Stop }
            # Seed the header so even a no-RP account produces a header-only file.
            Get-AWSRecoveryPointCsvHeader | Out-File -FilePath $CanonicalPath -Width 999999
            $script:RecoveryPointCanonicalSeeded[$CanonicalPath] = $true
        }

        foreach ($file in $tmpFiles) {
            $lines = Get-Content -Path $file.FullName
            # Append data rows only; the canonical header was written at seed time.
            if ($lines.Count -gt 1) {
                $lines[1..($lines.Count - 1)] | Out-File -FilePath $CanonicalPath -Append -Width 999999
            }
        }
    } catch {
        Remove-Item $CanonicalPath -ErrorAction SilentlyContinue
        Write-Host "Failed to merge recovery-point tmp files into $CanonicalPath : $_" -ForegroundColor Red
        throw
    } finally {
        Remove-Item $tmpGlob -ErrorAction SilentlyContinue
    }
}

# Native EBS snapshot + AMI enumeration. Two phases inside one cmdlet:
#   1) Get-EC2Image -Owner self -> AMI rows attributed to the instance that owns
#      the AMI's source volume(s); build a HashSet of every snapshot referenced
#      by an AMI so phase 2 can dedup.
#   2) Get-EC2Snapshot -OwnerId self -> EBS native snapshots. Skip any snapshot
#      whose ID was covered by phase 1, and skip any snapshot tagged with
#      `aws:backup:source-resource` or whose ARN appears in the RP list (those
#      are already counted by the AWS Backup recovery-point path).
# Returns @{ Backups = [arraylist of backup objects]; DetailRows = [arraylist
# of per-snapshot detail rows for streaming to aws_ebs_and_ami_info-*.csv] }.
function Get-AWSEBSAndAMIInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        $RecoveryPointArns   # hashtable: ARN -> $true, from the RP enumeration cmdlet
    )

    $backups    = [System.Collections.ArrayList]::new()
    $detailRows = [System.Collections.ArrayList]::new()
    if ($null -eq $AccountInfo) { return [PSCustomObject]@{ Backups = $backups; DetailRows = $detailRows } }
    if ($null -eq $RecoveryPointArns) { $RecoveryPointArns = @{} }

    # Phase 1: AMIs. DescribeImages auto-pages internally on Get-EC2Image, but
    # we still wrap in Invoke-AWSWithRetry for throttle handling.
    $images = New-Object collections.arraylist
    try {
        $page = Invoke-AWSWithRetry -Context "Get-EC2Image-$Region" -ScriptBlock {
            Get-EC2Image -Owner self -Credential $Credential -Region $Region -ErrorAction Stop
        }
        if ($page) { [void]$images.AddRange(@($page)) }
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping AMI enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate AMIs in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }

    # Buffer AMI metadata + referenced-snapshot IDs; defer emit until Phase 3
    # (after snapshot descriptions tell us the source instance).
    $amiSnapshotIds = New-Object 'System.Collections.Generic.HashSet[string]'
    $amiBuffer = New-Object collections.arraylist
    foreach ($image in $images) {
        if ($null -eq $image) { continue }
        $imageSize = 0L
        $imageSnapshotIds = New-Object collections.arraylist
        foreach ($bdm in @($image.BlockDeviceMappings)) {
            if ($null -ne $bdm.Ebs -and $bdm.Ebs.SnapshotId) {
                [void]$amiSnapshotIds.Add("$($bdm.Ebs.SnapshotId)")
                [void]$imageSnapshotIds.Add("$($bdm.Ebs.SnapshotId)")
                if ($null -ne $bdm.Ebs.VolumeSize) { $imageSize += [long]$bdm.Ebs.VolumeSize * 1GB }
            }
        }
        [void]$amiBuffer.Add([PSCustomObject]@{
            Image       = $image
            Size        = $imageSize
            SnapshotIds = $imageSnapshotIds
        })
    }

    # Phase 2: EBS snapshots. Explicit NextToken loop -- accounts
    # with tens of thousands of snapshots would otherwise stall the auto-page path.
    $snapshots = New-Object collections.arraylist
    try {
        $snapToken = $null
        do {
            $snapParams = @{ OwnerId = 'self'; Credential = $Credential; Region = $Region }
            if ($snapToken) { $snapParams.NextToken = $snapToken }
            $page = Invoke-AWSWithRetry -Context "Get-EC2Snapshot-$Region" -ScriptBlock {
                Get-EC2Snapshot @snapParams -ErrorAction Stop
            }
            if ($page) { [void]$snapshots.AddRange(@($page)) }
            $snapToken = $AWSHistory.LastServiceResponse.NextToken
        } while ($snapToken)
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping EBS snapshot enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate EBS snapshots in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }

    # Build snapshotId -> sourceInstanceId map from snapshot descriptions.
    # AWS auto-writes "Created by CreateImage(i-XXX) for ami-YYY" into the
    # description of every EBS snapshot that backs an AMI, so this is the
    # most reliable per-account signal for AMI source attribution.
    $snapToInstance = @{}
    foreach ($snap in $snapshots) {
        if ($null -eq $snap) { continue }
        if ("$($snap.Description)" -match 'CreateImage\((i-[0-9a-f]+)\)') {
            $snapToInstance["$($snap.SnapshotId)"] = $matches[1]
        }
    }

    # Phase 3: emit AMI rows. Attribute to source EC2 instance via snapshot
    # descriptions; fall back to ec2:source-instance-id tag (rarely set by
    # customers); fall back to AMI's own ARN.
    foreach ($entry in $amiBuffer) {
        $image = $entry.Image
        $sourceInstance = $null
        foreach ($snapId in $entry.SnapshotIds) {
            if ($snapToInstance.ContainsKey("$snapId")) {
                $sourceInstance = $snapToInstance["$snapId"]
                break
            }
        }
        if (-not $sourceInstance) {
            foreach ($tag in @($image.Tags)) {
                if ($tag -and $tag.Key -eq 'ec2:source-instance-id' -and
                    $tag.Value -match '^i-[0-9a-f]+$') {
                    $sourceInstance = $tag.Value
                    break
                }
            }
        }
        $sourceArn = if ($sourceInstance) {
            "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):instance/$($sourceInstance)"
        } else {
            "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):image/$($image.ImageId)"
        }
        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = $sourceArn
            Source        = "AMI"
            SizeBytes     = $entry.Size
            CreationDate  = $image.CreationDate
        })
        [void]$detailRows.Add([PSCustomObject]@{
            AwsAccountId    = $AccountInfo.Account
            AwsAccountAlias = $AccountAlias
            Region          = $Region
            Source          = "AMI"
            ImageId         = $image.ImageId
            SnapshotId      = ""
            ResourceArn     = $sourceArn
            SizeBytes       = $entry.Size
            SizeGiB         = [math]::Round($entry.Size / 1GB, 4)
            CreationDate    = $image.CreationDate
            Name            = $image.Name
            Description     = $image.Description
            State           = $image.State
        })
    }

    foreach ($snap in $snapshots) {
        if ($null -eq $snap) { continue }
        if ($amiSnapshotIds.Contains("$($snap.SnapshotId)")) { continue }

        # AWS Backup dedup: filter snapshots that AWS Backup created. AWS Backup
        # tags every snapshot it creates with `aws:backup:source-resource`. There
        # is no public API that maps an AWS Backup recovery-point ARN back to the
        # underlying EBS snapshot ID, so the tag is the only reliable per-snapshot
        # signal -- the RP-ARN set keyed on SOURCE ResourceArn cannot match a
        # snapshot ARN.
        $isAwsBackup = $false
        foreach ($tag in @($snap.Tags)) {
            if ($tag -and $tag.Key -eq 'aws:backup:source-resource') { $isAwsBackup = $true; break }
        }
        if ($isAwsBackup) { continue }
        $snapArn = "arn:$($partitionId):ec2:$($Region)::snapshot/$($snap.SnapshotId)"

        $sizeBytes = 0L
        if ($null -ne $snap.VolumeSize) { $sizeBytes = [long]$snap.VolumeSize * 1GB }
        $volArn = if ($snap.VolumeId) {
            "arn:$($partitionId):ec2:$($Region):$($AccountInfo.Account):volume/$($snap.VolumeId)"
        } else { $snapArn }

        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = $volArn
            Source        = "EBSNative"
            SizeBytes     = $sizeBytes
            CreationDate  = $snap.StartTime
        })
        [void]$detailRows.Add([PSCustomObject]@{
            AwsAccountId    = $AccountInfo.Account
            AwsAccountAlias = $AccountAlias
            Region          = $Region
            Source          = "EBSNative"
            ImageId         = ""
            SnapshotId      = $snap.SnapshotId
            ResourceArn     = $volArn
            SizeBytes       = $sizeBytes
            SizeGiB         = [math]::Round($sizeBytes / 1GB, 4)
            CreationDate    = $snap.StartTime
            Name            = ""
            Description     = $snap.Description
            State           = $snap.State
        })
    }

    return [PSCustomObject]@{
        Backups    = $backups
        DetailRows = $detailRows
    }
}

# Native RDS DB + cluster snapshot enumeration. Filters out AWS-Backup-created
# snapshots (identifier prefix `awsbackup:job-` OR ARN in the RP list -- Section
# 2d rule 3) and shared-from-other-account snapshots (SnapshotOwner != this
# account.
function Get-AWSRDSSnapshotInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        $RecoveryPointArns
    )

    $backups    = [System.Collections.ArrayList]::new()
    $detailRows = [System.Collections.ArrayList]::new()
    if ($null -eq $AccountInfo) { return [PSCustomObject]@{ Backups = $backups; DetailRows = $detailRows } }
    if ($null -eq $RecoveryPointArns) { $RecoveryPointArns = @{} }

    $isAwsBackupName = { param($n) "$n" -match '^awsbackup:job-' }

    # DB instance snapshots. RDS uses Marker/MaxRecord pagination, not NextToken.
    $dbSnaps = New-Object collections.arraylist
    try {
        $dbMarker = $null
        do {
            $dbParams = @{ Credential = $Credential; Region = $Region; MaxRecord = 100 }
            if ($dbMarker) { $dbParams.Marker = $dbMarker }
            $page = Invoke-AWSWithRetry -Context "Get-RDSDBSnapshot-$Region" -ScriptBlock {
                Get-RDSDBSnapshot @dbParams -ErrorAction Stop
            }
            if ($page) { [void]$dbSnaps.AddRange(@($page)) }
            $dbMarker = $AWSHistory.LastServiceResponse.Marker
        } while ($dbMarker)
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping RDS DB snapshot enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate RDS DB snapshots in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }
    foreach ($s in $dbSnaps) {
        if ($null -eq $s) { continue }
        # Cross-account shared snapshots are NOT returned by Get-RDSDBSnapshot
        # unless -IncludeShared $true is passed (default false). We omit the
        # parameter to keep the default. The SnapshotOwner property is not
        # exposed on AWS.Tools v4/v5 snapshot objects, so an explicit filter
        # here would be a no-op.
        $name = "$($s.DBSnapshotIdentifier)"
        $arn  = "$($s.DBSnapshotArn)"
        # AWS Backup tags its RDS snapshots with an `awsbackup:job-*` identifier
        # prefix; that is the only reliable signal (snapshot ARN does not appear
        # in the RP API which keys on source DB ARN).
        if (& $isAwsBackupName $name) { continue }

        $sizeBytes = 0L
        if ($null -ne $s.AllocatedStorage) { $sizeBytes = [long]$s.AllocatedStorage * 1GB }
        $dbArn = "arn:$($partitionId):rds:$($Region):$($AccountInfo.Account):db:$($s.DBInstanceIdentifier)"
        $source = if ("$($s.SnapshotType)" -eq 'automated') { 'RDSAutomated' } else { 'RDSManual' }
        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = $dbArn
            Source        = $source
            SizeBytes     = $sizeBytes
            CreationDate  = $s.SnapshotCreateTime
        })
        [void]$detailRows.Add([PSCustomObject]@{
            AwsAccountId       = $AccountInfo.Account
            AwsAccountAlias    = $AccountAlias
            Region             = $Region
            Source             = $source
            Engine             = $s.Engine
            SnapshotIdentifier = $s.DBSnapshotIdentifier
            ResourceArn        = $dbArn
            SnapshotArn        = $arn
            SizeBytes          = $sizeBytes
            SizeGiB            = [math]::Round($sizeBytes / 1GB, 4)
            CreationDate       = $s.SnapshotCreateTime
            SnapshotType       = $s.SnapshotType
            Status             = $s.Status
            ClusterIdentifier  = ""
        })
    }

    # Cluster (Aurora) snapshots. Same Marker/MaxRecord pagination as DB snapshots.
    $clSnaps = New-Object collections.arraylist
    try {
        $clMarker = $null
        do {
            $clParams = @{ Credential = $Credential; Region = $Region; MaxRecord = 100 }
            if ($clMarker) { $clParams.Marker = $clMarker }
            $page = Invoke-AWSWithRetry -Context "Get-RDSDBClusterSnapshot-$Region" -ScriptBlock {
                Get-RDSDBClusterSnapshot @clParams -ErrorAction Stop
            }
            if ($page) { [void]$clSnaps.AddRange(@($page)) }
            $clMarker = $AWSHistory.LastServiceResponse.Marker
        } while ($clMarker)
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping RDS cluster snapshot enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate RDS cluster snapshots in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }
    foreach ($s in $clSnaps) {
        if ($null -eq $s) { continue }
        # Same as DB snapshots: -IncludeShared default false keeps cross-account
        # snapshots out without us needing to filter.
        $name = "$($s.DBClusterSnapshotIdentifier)"
        $arn  = "$($s.DBClusterSnapshotArn)"
        if (& $isAwsBackupName $name) { continue }

        # Aurora is auto-managed storage: AllocatedStorage on cluster snapshots is
        # always 1 GiB, which would systematically under-report Aurora capacity.
        # Leave size at 0 -- the workload's source-cluster row already carries
        # the real provisioned size, and the RP path (when AWS Backup covers the
        # cluster) reports the accurate logical size.
        $sizeBytes = 0L
        $clArn = "arn:$($partitionId):rds:$($Region):$($AccountInfo.Account):cluster:$($s.DBClusterIdentifier)"
        $source = if ("$($s.SnapshotType)" -eq 'automated') { 'RDSAutomated' } else { 'RDSManual' }
        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = $clArn
            Source        = $source
            SizeBytes     = $sizeBytes
            CreationDate  = $s.SnapshotCreateTime
        })
        [void]$detailRows.Add([PSCustomObject]@{
            AwsAccountId       = $AccountInfo.Account
            AwsAccountAlias    = $AccountAlias
            Region             = $Region
            Source             = $source
            Engine             = $s.Engine
            SnapshotIdentifier = $s.DBClusterSnapshotIdentifier
            ResourceArn        = $clArn
            SnapshotArn        = $arn
            SizeBytes          = $sizeBytes
            SizeGiB            = [math]::Round($sizeBytes / 1GB, 4)
            CreationDate       = $s.SnapshotCreateTime
            SnapshotType       = $s.SnapshotType
            Status             = $s.Status
            ClusterIdentifier  = $s.DBClusterIdentifier
        })
    }

    return [PSCustomObject]@{
        Backups    = $backups
        DetailRows = $detailRows
    }
}

# Native FSx backup enumeration (in-memory only, no detail CSV). Filters out
# AWS-Backup-created backups (Type = AWS_BACKUP), already counted via RP path.
function Get-AWSFSxBackupInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )
    $backups = [System.Collections.ArrayList]::new()
    if ($null -eq $AccountInfo) { return $backups }
    $fsxBackups = New-Object collections.arraylist
    try {
        $fsxToken = $null
        do {
            $fsxParams = @{ Credential = $Credential; Region = $Region }
            if ($fsxToken) { $fsxParams.NextToken = $fsxToken }
            $page = Invoke-AWSWithRetry -Context "Get-FSXBackup-$Region" -ScriptBlock {
                Get-FSXBackup @fsxParams -ErrorAction Stop
            }
            if ($page) { [void]$fsxBackups.AddRange(@($page)) }
            $fsxToken = $AWSHistory.LastServiceResponse.NextToken
        } while ($fsxToken)
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping FSx backup enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate FSx backups in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }
    foreach ($b in $fsxBackups) {
        if ($null -eq $b) { continue }
        $type = "$($b.Type)"
        if ($type -eq 'AWS_BACKUP') { continue }
        $source = switch ($type) {
            'AUTOMATIC'      { 'FSxAutomatic' }
            'USER_INITIATED' { 'FSxUserInitiated' }
            default          { 'FSxUserInitiated' }
        }
        $sizeBytes = 0L
        if ($b.PSObject.Properties['Lifecycle'] -and $b.Lifecycle.PSObject.Properties['StorageCapacity']) {
            $sizeBytes = [long]$b.Lifecycle.StorageCapacity * 1GB
        } elseif ($b.PSObject.Properties['FileSystem'] -and $b.FileSystem.PSObject.Properties['StorageCapacity']) {
            $sizeBytes = [long]$b.FileSystem.StorageCapacity * 1GB
        }
        $arn = if ($b.PSObject.Properties['FileSystem'] -and $b.FileSystem.PSObject.Properties['FileSystemId']) {
            "arn:$($partitionId):fsx:$($Region):$($AccountInfo.Account):file-system/$($b.FileSystem.FileSystemId)"
        } else { "$($b.ResourceARN)" }
        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = $arn
            Source        = $source
            SizeBytes     = $sizeBytes
            CreationDate  = $b.CreationTime
        })
    }
    return $backups
}

# Native DynamoDB backup enumeration: on-demand backups (Get-DDBBackupList) plus
# per-table PITR upper bound (current TableSizeBytes) when continuous backups
# are enabled. In-memory only, no detail CSV (low-volume source).
function Get-AWSDDBBackupInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        $DDBList
    )
    $backups = [System.Collections.ArrayList]::new()
    if ($null -eq $AccountInfo) { return $backups }

    # On-demand backups. DDB uses ExclusiveStartBackupArn / LastEvaluatedBackupArn
    # for pagination on Get-DDBBackupList. AWS Tools auto-pages, so wrap once.
    $onDemand = New-Object collections.arraylist
    try {
        $page = Invoke-AWSWithRetry -Context "Get-DDBBackupList-$Region" -ScriptBlock {
            Get-DDBBackupList -Credential $Credential -Region $Region -ErrorAction Stop
        }
        if ($page) { [void]$onDemand.AddRange(@($page)) }
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping DDB on-demand backup enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate DDB backups in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }
    foreach ($b in $onDemand) {
        if ($null -eq $b) { continue }
        $sizeBytes = 0L
        if ($null -ne $b.BackupSizeBytes) { $sizeBytes = [long]$b.BackupSizeBytes }
        $arn = "$($b.TableArn)"
        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = $arn
            Source        = 'DDBOnDemand'
            SizeBytes     = $sizeBytes
            CreationDate  = $b.BackupCreationDateTime
        })
    }

    # PITR upper bound
    foreach ($ddb in @($DDBList)) {
        if ($null -eq $ddb) { continue }
        if ("$($ddb.Region)" -ne "$Region") { continue }
        if ("$($ddb.AwsAccountId)" -ne "$($AccountInfo.Account)") { continue }
        $tableName = "$($ddb.TableName)"
        if ([string]::IsNullOrEmpty($tableName)) { continue }
        $pitrEnabled = $false
        try {
            $cb = Invoke-AWSWithRetry -Context "Get-DDBContinuousBackup-$tableName" -ScriptBlock {
                Get-DDBContinuousBackup -TableName $tableName -Credential $Credential -Region $Region -ErrorAction Stop
            }
            if ($null -ne $cb -and $cb.PSObject.Properties['PointInTimeRecoveryDescription']) {
                $status = "$($cb.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus)"
                if ($status -eq 'ENABLED') { $pitrEnabled = $true }
            }
        } catch {
            # Distinguish IAM gap from "PITR was never enabled on this table"; the
            # former is operator-actionable so it deserves a yellow line (deduped
            # per account by the existing $script:CEFailureNotedForAccount style:
            # we only print once per account-region pair here).
            if (Test-IsAccessDenied $_) {
                $key = "DDB-PITR-$($AccountInfo.Account)-$Region"
                if (-not $script:DDBContinuousBackupDeniedNoted[$key]) {
                    Write-Host "Access denied calling dynamodb:DescribeContinuousBackups in $Region for account $($AccountInfo.Account); PITR state will read as disabled for all tables in this region." -ForegroundColor Yellow
                    $script:DDBContinuousBackupDeniedNoted[$key] = $true
                }
            }
            $pitrEnabled = $false
        }
        if (-not $pitrEnabled) { continue }

        $tableSize = 0L
        try {
            $tbl = Invoke-AWSWithRetry -Context "Get-DDBTable-$tableName" -ScriptBlock {
                Get-DDBTable -TableName $tableName -Credential $Credential -Region $Region -ErrorAction Stop
            }
            if ($null -ne $tbl -and $null -ne $tbl.TableSizeBytes) { $tableSize = [long]$tbl.TableSizeBytes }
        } catch { $tableSize = 0L }

        # Set PITREnabled on the workload row directly so the flag is visible
        # without going through the merged-aggregate path.
        if ($ddb.PSObject.Properties['PITREnabled']) { $ddb.PITREnabled = $true }

        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = "$($ddb.TableArn)"
            Source        = 'DDBPITR'
            SizeBytes     = $tableSize
            CreationDate  = $null
        })
    }
    return $backups
}

# Native Redshift snapshot enumeration. Filters out shared-from-other-account
# snapshots. No AWS-Backup dedup needed -- AWS Backup does not currently support
# Redshift, so every Redshift snapshot is native.
function Get-AWSRedshiftSnapshotInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )
    $backups = [System.Collections.ArrayList]::new()
    if ($null -eq $AccountInfo) { return $backups }
    # Redshift uses Marker/MaxRecord (RDS-style) pagination.
    $snaps = New-Object collections.arraylist
    try {
        $rsMarker = $null
        do {
            $rsParams = @{ Credential = $Credential; Region = $Region; MaxRecord = 100 }
            if ($rsMarker) { $rsParams.Marker = $rsMarker }
            $page = Invoke-AWSWithRetry -Context "Get-RSClusterSnapshot-$Region" -ScriptBlock {
                Get-RSClusterSnapshot @rsParams -ErrorAction Stop
            }
            if ($page) { [void]$snaps.AddRange(@($page)) }
            $rsMarker = $AWSHistory.LastServiceResponse.Marker
        } while ($rsMarker)
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping Redshift snapshot enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate Redshift snapshots in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }
    foreach ($s in $snaps) {
        if ($null -eq $s) { continue }
        if ($s.PSObject.Properties['OwnerAccount'] -and $s.OwnerAccount -and "$($s.OwnerAccount)" -ne "$($AccountInfo.Account)") { continue }
        $sizeBytes = 0L
        # Redshift API returns MB as decimal megabytes (10^6), not MiB. PowerShell's
        # `1MB` constant is 1048576 (binary) and would over-report by ~4.86%.
        if ($null -ne $s.TotalBackupSizeInMegaBytes) { $sizeBytes = [long]([double]$s.TotalBackupSizeInMegaBytes * 1000000) }
        $arn = "arn:$($partitionId):redshift:$($Region):$($AccountInfo.Account):cluster:$($s.ClusterIdentifier)"
        $source = if ("$($s.SnapshotType)" -eq 'automated') { 'RedshiftAutomated' } else { 'RedshiftManual' }
        [void]$backups.Add([PSCustomObject]@{
            AwsAccountId  = $AccountInfo.Account
            Region        = $Region
            ResourceArn   = $arn
            Source        = $source
            SizeBytes     = $sizeBytes
            CreationDate  = $s.SnapshotCreateTime
        })
    }
    return $backups
}

# Minimal Redshift cluster inventory. Adds the 10 source-agnostic backup columns
# at row construction time (Task 3 contract).
function Get-AWSRedshiftInventory {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )
    $result = [System.Collections.ArrayList]::new()
    if ($null -eq $AccountInfo) { return , $result }
    # Redshift cluster listing is also Marker/MaxRecord paginated.
    $clusters = New-Object collections.arraylist
    try {
        $clToken = $null
        do {
            $clParams = @{ Credential = $Credential; Region = $Region; MaxRecord = 100 }
            if ($clToken) { $clParams.Marker = $clToken }
            $page = Invoke-AWSWithRetry -Context "Get-RSCluster-$Region" -ScriptBlock {
                Get-RSCluster @clParams -ErrorAction Stop
            }
            if ($page) { [void]$clusters.AddRange(@($page)) }
            $clToken = $AWSHistory.LastServiceResponse.Marker
        } while ($clToken)
    } catch {
        if (Test-IsAccessDenied -ErrorRecord $_) {
            Write-Host "Skipping Redshift cluster enumeration in $Region for account $($AccountInfo.Account): access denied." -ForegroundColor Yellow
        } else {
            Write-Host "Failed to enumerate Redshift clusters in $Region for account $($AccountInfo.Account): $_" -ForegroundColor Red
        }
    }
    foreach ($c in $clusters) {
        if ($null -eq $c) { continue }
        $arn = "arn:$($partitionId):redshift:$($Region):$($AccountInfo.Account):cluster:$($c.ClusterIdentifier)"
        $row = [PSCustomObject]@{
            AwsAccountId                     = $AccountInfo.Account
            AwsAccountAlias                  = $AccountAlias
            Region                           = $Region
            ClusterIdentifier                = $c.ClusterIdentifier
            ResourceArn                      = $arn
            NodeType                         = $c.NodeType
            NumberOfNodes                    = $c.NumberOfNodes
            ClusterStatus                    = $c.ClusterStatus
            MasterUsername                   = $c.MasterUsername
            DBName                           = $c.DBName
            ClusterCreateTime                = $c.ClusterCreateTime
            AutomatedSnapshotRetentionPeriod = $c.AutomatedSnapshotRetentionPeriod
            ManualSnapshotRetentionPeriod    = $c.ManualSnapshotRetentionPeriod
        }
        Add-BackupColumnsToRow -Row $row -ResourceArn $arn
        [void]$result.Add($row)
    }
    return , $result
}

# Per-account dedup hash for the inline CE failure warning. Stores the
# first-observed Reason so a second cmdlet hitting the same account stays silent.
$script:CEFailureNotedForAccount = @{}

# Per-(account, region) dedup hash for the DDB DescribeContinuousBackups
# AccessDenied warning so we don't print one line per table when IAM is missing.
$script:DDBContinuousBackupDeniedNoted = @{}

function Write-CEFailureWarningOnce {
    param(
        [Parameter(Mandatory)] $AccountInfo,
        [Parameter(Mandatory)] [ValidateSet('CostExplorerNotEnabled','AccessDenied')] [string]$Reason
    )
    $acct = "$($AccountInfo.Account)"
    if ($script:CEFailureNotedForAccount.ContainsKey($acct)) { return }
    $script:CEFailureNotedForAccount[$acct] = $Reason
    switch ($Reason) {
        'CostExplorerNotEnabled' {
            Write-Host "Cost Explorer is not enabled for account $acct." -ForegroundColor Yellow
            Write-Host "Capacity figures (the primary sizing input) are complete and accurate; dollar figures are unavailable for this account." -ForegroundColor Yellow
            Write-Host "To enable: Billing console -> Cost Explorer -> Launch. Allow ~24h for backfill." -ForegroundColor Yellow
        }
        'AccessDenied' {
            Write-Host "CE access denied for account $acct despite IAM grant." -ForegroundColor Yellow
            Write-Host "Likely cause for org runs: linked-account billing access is disabled at the management account (Billing -> Billing preferences -> 'Linked account access to billing data')." -ForegroundColor Yellow
        }
    }
}

# Inline CE call wrapper. Returns the call's result, or $null if the call hit
# a CE-specific failure mode (DataUnavailable / AccessDenied) -- callers then
# write a header-only CSV. Any other exception still propagates red.
function Invoke-CECall {
    param(
        [Parameter(Mandatory)] [string]$Context,
        [Parameter(Mandatory)] $AccountInfo,
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock
    )
    try {
        return Invoke-AWSWithRetry -Context $Context -ScriptBlock $ScriptBlock
    } catch {
        $name = $_.Exception.GetType().Name
        $code = $null
        if ($_.Exception.PSObject.Properties['ErrorCode']) { $code = "$($_.Exception.ErrorCode)" }
        if ($name -eq 'DataUnavailableException' -or "$($_.Exception.Message)" -match 'DataUnavailable') {
            Write-CEFailureWarningOnce -AccountInfo $AccountInfo -Reason 'CostExplorerNotEnabled'
            return $null
        }
        if ($name -eq 'AccessDeniedException' -or $code -eq 'AccessDenied' -or "$($_.Exception.Message)" -match 'AccessDenied|not authorized') {
            Write-CEFailureWarningOnce -AccountInfo $AccountInfo -Reason 'AccessDenied'
            return $null
        }
        throw
    }
}

# Shared time window helper -- past 12 months + MTD.
function Get-CEDefaultTimeWindow {
    @{
        Start = (Get-Date).AddMonths(-12).ToString("yyyy-MM-01")
        End   = (Get-Date).ToString("yyyy-MM-dd")
    }
}

# Snapshot/backup USAGE_TYPE keyword constants -- substring match against the
# region-prefix-stripped USAGE_TYPE string. Managed exclusions remove the
# overlap with the SERVICE = "AWS Backup" query so the two cost cmdlets stay
# disjoint from the SERVICE="AWS Backup" query (see README "Cost reporting").
$script:SNAPSHOT_KEYWORDS = @(
    'Snapshot','BackupUsage','BackupStorage','ChargedBackup','BackupArchive',
    'Backup-Usage','Backup-Storage','ContinuousBackup'
)
$script:MANAGED_EXCLUSIONS = @(
    '*EFS-Backup*','*FSx-OpenZFS*','*S3-Backup*','*DynamoDB-Backup-Advanced*',
    '*EKS-Backup*','*Timestream-Backup*',
    # AWSBackup-* USAGE_TYPEs are already counted via the SERVICE="AWS Backup"
    # query; excluding here prevents the BackupUsage / BackupStorage substring
    # match from double-counting them.
    '*AWSBackup-*'
)

function Test-IsSnapshotUsageType {
    param([string]$UsageType)
    foreach ($pat in $script:MANAGED_EXCLUSIONS) {
        if ($UsageType -like $pat) { return $false }
    }
    foreach ($kw in $script:SNAPSHOT_KEYWORDS) {
        if ($UsageType -match [regex]::Escape($kw)) { return $true }
    }
    return $false
}

function Get-AWSBackupCosts {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $backupCostsResult = New-Object collections.arraylist
    if ($null -eq $AccountInfo) { return , $backupCostsResult }

    $filter = @{
      Dimensions = @{
          Key = "SERVICE"
          Values = @("AWS Backup")
      }
    }

    $timePeriod = Get-CEDefaultTimeWindow
    $metrics = @("AmortizedCost", "BlendedCost", "NetAmortizedCost", "NetUnblendedCost", "NormalizedUsageAmount", "UnblendedCost", "UsageQuantity")

    # CE GetCostAndUsage paginates on group cardinality. 13 months x N usage types
    # can exceed the 1000-row default page; without a NextPageToken loop the tail
    # months silently truncate. AWS Tools auto-pagination is inconsistent across
    # v4/v5 for CE, so loop explicitly.
    $result = $null
    $ceNextToken = $null
    do {
        $page = Invoke-CECall -Context "Get-AWSBackupCosts" -AccountInfo $AccountInfo -ScriptBlock {
            $ceParams = @{
                TimePeriod  = $timePeriod
                Granularity = 'MONTHLY'
                Metrics     = $metrics
                Filter      = $filter
                Credential  = $Credential
                Region      = $Region
                ErrorAction = 'Stop'
            }
            if ($ceNextToken) { $ceParams.NextPageToken = $ceNextToken }
            Get-CECostAndUsage @ceParams
        }
        if ($null -eq $page) {
            if ($null -eq $result) { return , $backupCostsResult }
            break
        }
        if ($null -eq $result) {
            $result = $page
        } else {
            foreach ($t in @($page.ResultsByTime)) { $result.ResultsByTime += $t }
        }
        $ceNextToken = $page.NextPageToken
    } while ($ceNextToken)

    $counter = 1
    foreach ($resultItem in $result.ResultsByTime) {
      Write-Progress -ID 13 -Activity "Processing Cost and Usage of Backup for Month: $($resultItem.TimePeriod.Start)" -Status "Item $($counter) of $($result.ResultsByTime.Count)" -PercentComplete (($counter / $result.ResultsByTime.count) * 100)
      $counter++
      $monthCostObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
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
      $backupCostsResult.Add($monthCostObj) | Out-Null
    }
    Write-Progress -ID 13 -Activity "Processing Cost and Usage of Backup for Month: $($resultItem.TimePeriod.Start)" -Completed

    return , $backupCostsResult
}

# Per-USAGE_TYPE snapshot/backup cost query. Discovers concrete
# region-prefixed USAGE_TYPE values via Get-CEDimensionValue, substring-filters
# against $SNAPSHOT_KEYWORDS with managed-overlap exclusions, then chunks the
# matched list (200 per call, fallback to 100 on ValidationException) and
# issues one Get-CECostAndUsage per chunk grouped by [SERVICE, USAGE_TYPE].
# Returns per-(month, service, usagetype, unit) rows.
function Get-AWSSnapshotStorageCosts {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias,
        $TimePeriod
    )
    $rows = New-Object collections.arraylist
    if ($null -eq $AccountInfo) { return , $rows }
    if ($null -eq $TimePeriod) { $TimePeriod = Get-CEDefaultTimeWindow }

    # Get-CEDimensionValue paginates at 1000 entries per page per the CE API. Loop
    # explicitly -- AWS Tools auto-pagination is inconsistent for CE across v4/v5,
    # and large accounts can easily exceed 1000 distinct USAGE_TYPEs in a 12-month
    # window across many regions/services.
    $allUsageTypes = @()
    $dimNextToken  = $null
    do {
        $dimPage = Invoke-CECall -Context "Get-AWSSnapshotStorageCosts-Dims" -AccountInfo $AccountInfo -ScriptBlock {
            $dimParams = @{
                TimePeriod  = $TimePeriod
                Dimension   = 'USAGE_TYPE'
                Credential  = $Credential
                Region      = $Region
                ErrorAction = 'Stop'
            }
            if ($dimNextToken) { $dimParams.NextPageToken = $dimNextToken }
            Get-CEDimensionValue @dimParams
        }
        if ($null -eq $dimPage) { return , $rows }
        foreach ($d in @($dimPage.DimensionValues)) {
            if ($d -and $d.Value) { $allUsageTypes += "$($d.Value)" }
        }
        $dimNextToken = $dimPage.NextPageToken
    } while ($dimNextToken)

    $matched     = New-Object collections.arraylist
    $unclassified = 0
    foreach ($ut in $allUsageTypes) {
        # Strip the region prefix (e.g. "USE1-") before classification, but pass
        # the full region-prefixed string to the CE Filter query.
        $bare = $ut -replace '^[A-Z0-9]+-', ''
        if (Test-IsSnapshotUsageType -UsageType $bare) {
            [void]$matched.Add($ut)
        } elseif ($bare -match 'Backup|Snapshot') {
            # Caught by the "literal Backup/Snapshot" runtime detection
            # but excluded from the matched set (conservative: under-report rather
            # than over-report).
            $unclassified++
        }
    }
    if ($unclassified -gt 0) {
        Write-Host "Note: $unclassified USAGE_TYPE line item(s) were not recognized and excluded from the snapshot cost totals. This may indicate an AWS service added since the last sizing-script release." -ForegroundColor Yellow
    }
    if ($matched.Count -eq 0) { return , $rows }

    $metrics = @("AmortizedCost", "BlendedCost", "NetAmortizedCost", "NetUnblendedCost", "NormalizedUsageAmount", "UnblendedCost", "UsageQuantity")

    # Inline per-slice loop: on a ValidationException we drop the chunk size for the
    # CURRENT slice only and retry it, then continue with the smaller size for
    # subsequent slices. Earlier successfully-aggregated months stay put -- no
    # restart from chunk 0 (which would have produced duplicate ResultsByTime rows).
    $aggregated = @{ ResultsByTime = @() }
    $chunkSize  = 200
    $idx        = 0
    while ($idx -lt $matched.Count) {
        $end   = [math]::Min($idx + $chunkSize - 1, $matched.Count - 1)
        $slice = @($matched[$idx..$end])
        $filter = @{
            Dimensions = @{
                Key    = "USAGE_TYPE"
                Values = $slice
            }
        }
        # Per-slice NextPageToken loop. GroupBy = (SERVICE, USAGE_TYPE) over 13 months
        # can exceed CE's 1000-group page size at high cardinality; without this loop
        # the tail months would silently truncate.
        $thisCall    = $null
        $costToken   = $null
        $sliceFailed = $false
        try {
            do {
                $page = Invoke-CECall -Context "Get-AWSSnapshotStorageCosts-Cost" -AccountInfo $AccountInfo -ScriptBlock {
                    $costParams = @{
                        TimePeriod  = $TimePeriod
                        Granularity = 'MONTHLY'
                        Metrics     = $metrics
                        GroupBy     = @(
                            @{ Type = 'DIMENSION'; Key = 'SERVICE' },
                            @{ Type = 'DIMENSION'; Key = 'USAGE_TYPE' }
                        )
                        Filter      = $filter
                        Credential  = $Credential
                        Region      = $Region
                        ErrorAction = 'Stop'
                    }
                    if ($costToken) { $costParams.NextPageToken = $costToken }
                    Get-CECostAndUsage @costParams
                }
                if ($null -eq $page) {
                    if ($null -eq $thisCall) { $sliceFailed = $true }
                    break
                }
                if ($null -eq $thisCall) {
                    $thisCall = $page
                } else {
                    foreach ($t in @($page.ResultsByTime)) { $thisCall.ResultsByTime += $t }
                }
                $costToken = $page.NextPageToken
            } while ($costToken)
        } catch {
            # ValidationException can surface either as the outer exception's type
            # name or buried in an InnerException after AWS Tools wraps it. Walk
            # the chain so the fallback fires reliably.
            $isValidation = $false
            $exChk = $_.Exception
            while ($null -ne $exChk) {
                if ($exChk.GetType().Name -eq 'ValidationException' -or "$($exChk.Message)" -match 'ValidationException') {
                    $isValidation = $true; break
                }
                $exChk = $exChk.InnerException
            }
            if ($chunkSize -gt 100 -and $isValidation) {
                $chunkSize = 100
                continue   # retry the same slice with a smaller window
            }
            throw
        }
        if ($sliceFailed) { return , $rows }   # CE failure already warned inline
        if ($null -eq $thisCall) { $idx = $end + 1; continue }
        foreach ($t in @($thisCall.ResultsByTime)) { $aggregated.ResultsByTime += $t }
        $idx = $end + 1
    }
    $costResult = $aggregated

    foreach ($rt in @($costResult.ResultsByTime)) {
        foreach ($g in @($rt.Groups)) {
            $service   = "$($g.Keys[0])"
            $usageType = "$($g.Keys[1])"
            $row = [PSCustomObject]@{
                AwsAccountId          = $AccountInfo.Account
                AwsAccountAlias       = $AccountAlias
                'Time-Period-Start'   = $rt.TimePeriod.Start
                'Time-Period-End'     = $rt.TimePeriod.End
                Service               = $service
                UsageType             = $usageType
                UsageQuantity         = if ($g.Metrics['UsageQuantity']) { [math]::Round($g.Metrics['UsageQuantity'].Amount, 4) } else { 0 }
                UsageUnit             = if ($g.Metrics['UsageQuantity']) { "$($g.Metrics['UsageQuantity'].Unit)" } else { '' }
                AmortizedCost         = if ($g.Metrics['AmortizedCost'])     { '$' + [math]::Round($g.Metrics['AmortizedCost'].Amount, 2) }     else { '$0' }
                BlendedCost           = if ($g.Metrics['BlendedCost'])       { '$' + [math]::Round($g.Metrics['BlendedCost'].Amount, 2) }       else { '$0' }
                NetAmortizedCost      = if ($g.Metrics['NetAmortizedCost'])  { '$' + [math]::Round($g.Metrics['NetAmortizedCost'].Amount, 2) }  else { '$0' }
                NetUnblendedCost      = if ($g.Metrics['NetUnblendedCost'])  { '$' + [math]::Round($g.Metrics['NetUnblendedCost'].Amount, 2) }  else { '$0' }
                UnblendedCost         = if ($g.Metrics['UnblendedCost'])     { '$' + [math]::Round($g.Metrics['UnblendedCost'].Amount, 2) }     else { '$0' }
                NormalizedUsageAmount = if ($g.Metrics['NormalizedUsageAmount']) { [math]::Round($g.Metrics['NormalizedUsageAmount'].Amount, 3) } else { 0 }
            }
            [void]$rows.Add($row)
        }
    }
    return , $rows
}

# The source-agnostic backup columns added to every workload row. Initialized to
# defaults at row construction time so the column order is identical for rows with
# and without backups (a backup that exists merely overwrites the defaults later,
# in place, via the wire-up step). Keeping these defaults in one ordered hashtable
# is what guarantees the column-position-stability invariant the tests assert.
function Add-BackupColumnsToRow {
    param(
        [Parameter(Mandatory)] $Row,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$ResourceArn
    )
    # ResourceArn is declared inside each row's constructor hashtable so it lands
    # next to other identifier columns. If the property is already present we
    # only overwrite the value, preserving its position; if it's missing we add
    # it here as a fall-back. The other backup columns are pure additions, so
    # -Force is harmless and keeps this helper idempotent if a caller invokes
    # it twice.
    if ($Row.PSObject.Properties['ResourceArn']) {
        $Row.ResourceArn = $ResourceArn
    } else {
        $Row | Add-Member -MemberType NoteProperty -Name "ResourceArn" -Value $ResourceArn
    }
    $Row | Add-Member -MemberType NoteProperty -Name "HasBackups" -Value $false -Force
    $Row | Add-Member -MemberType NoteProperty -Name "HasRecoveryPoints" -Value $false -Force
    $Row | Add-Member -MemberType NoteProperty -Name "BackupCount" -Value 0 -Force
    $Row | Add-Member -MemberType NoteProperty -Name "BackupSources" -Value "" -Force
    $Row | Add-Member -MemberType NoteProperty -Name "LatestBackupDate" -Value $null -Force
    $Row | Add-Member -MemberType NoteProperty -Name "LatestBackupSizeGiB" -Value 0 -Force
    $Row | Add-Member -MemberType NoteProperty -Name "LatestBackupSizeTiB" -Value 0 -Force
    $Row | Add-Member -MemberType NoteProperty -Name "LatestBackupSizeGB" -Value 0 -Force
    $Row | Add-Member -MemberType NoteProperty -Name "LatestBackupSizeTB" -Value 0 -Force
    $Row | Add-Member -MemberType NoteProperty -Name "BackupEnumerationTruncated" -Value $false -Force
}

# Merges per-source backup aggregates (the RP path plus the native-snapshot
# collectors below) into a single per-(account, region, ResourceArn) hashtable.
# Each input descriptor is:
#   @{ Source = '<label>'; Entries = <list of per-resource rows> }
# where each entry exposes AwsAccountId, Region, ResourceArn, plus a count, a latest
# date, and a latest size in bytes. The accessor scriptblocks let each source map its
# own column names (RP uses RecoveryPointCount / LatestRecoveryPointDate / ...).
# Native collectors append a descriptor without any refactor here.
function Merge-BackupAggregates {
    param(
        [Parameter(Mandatory)] $SourceAggregates,
        $NativeBackupLists       # arraylist of native backup objects:
                                 # @(AwsAccountId, Region, ResourceArn, Source, SizeBytes,
                                 # CreationDate). Latest per (account,region,ARN,Source) is
                                 # used; BackupCount sums across all native entries.
    )

    $merged = @{}
    $ensure = {
        param($acct, $reg, $arn)
        $k = "$acct|$reg|$arn"
        if (-not $merged.ContainsKey($k)) {
            $merged[$k] = @{
                AwsAccountId          = $acct
                Region                = $reg
                ResourceArn           = $arn
                HasBackups            = $false
                BackupCount           = 0
                BackupSources         = (New-Object 'System.Collections.Generic.HashSet[string]')
                LatestBackupDate      = $null
                LatestBackupSizeBytes = 0
            }
        }
        return $k
    }

    foreach ($descriptor in $SourceAggregates) {
        $source     = $descriptor.Source
        $getCount   = $descriptor.GetCount
        $getDate    = $descriptor.GetLatestDate
        $getSize    = $descriptor.GetLatestSizeBytes
        foreach ($entry in @($descriptor.Entries)) {
            if ($null -eq $entry) { continue }
            $arn = $entry.ResourceArn
            if ([string]::IsNullOrEmpty($arn)) { continue }
            $key = & $ensure $entry.AwsAccountId $entry.Region $arn

            $count = [int](& $getCount $entry)
            $date  = & $getDate $entry
            $size  = [long](& $getSize $entry)

            $state = $merged[$key]
            $state.HasBackups   = $true
            $state.BackupCount += $count
            [void]$state.BackupSources.Add($source)
            if ($null -ne $date -and ($null -eq $state.LatestBackupDate -or $date -gt $state.LatestBackupDate)) {
                $state.LatestBackupDate      = $date
                $state.LatestBackupSizeBytes = $size
            }
        }
    }

    foreach ($entry in @($NativeBackupLists)) {
        if ($null -eq $entry) { continue }
        $arn = $entry.ResourceArn
        if ([string]::IsNullOrEmpty($arn)) { continue }
        $key = & $ensure $entry.AwsAccountId $entry.Region $arn

        $state = $merged[$key]
        $state.HasBackups   = $true
        $state.BackupCount += 1
        [void]$state.BackupSources.Add("$($entry.Source)")
        $date = $entry.CreationDate
        $size = if ($null -ne $entry.SizeBytes) { [long]$entry.SizeBytes } else { 0L }
        if ($null -ne $date -and ($null -eq $state.LatestBackupDate -or $date -gt $state.LatestBackupDate)) {
            $state.LatestBackupDate      = $date
            $state.LatestBackupSizeBytes = $size
        } elseif ($null -eq $date -and $size -gt $state.LatestBackupSizeBytes) {
            # Sources without CreationDate (e.g. DDBPITR upper-bound) still need to
            # contribute size. Take the max regardless of whether state already has
            # a dated entry -- a PITR upper bound that arrives after a smaller
            # on-demand backup must not be silently dropped, because PITR is the
            # only signal we have for the table's continuous-backup capacity.
            $state.LatestBackupSizeBytes = $size
        }
    }

    # Collapse the controlled-vocabulary source set into a sorted, comma-separated string.
    foreach ($state in $merged.Values) {
        $state.BackupSources = (($state.BackupSources | Sort-Object) -join ", ")
    }
    return $merged
}

# Wires the merged backup aggregate onto each row of a workload list. Rows already
# carry the default backup columns (Add-BackupColumnsToRow), so a missing aggregate
# leaves the defaults untouched; a present one overwrites them in place, preserving
# column order. FSx filesystem and volume rows share an ARN service ("fsx") but differ
# by ResourceType path segment, so the merged hash keys on the full ARN and no extra
# disambiguation is needed here -- each row's own ResourceArn is the lookup key.
function Set-WorkloadBackupColumns {
    param(
        [Parameter(Mandatory)] $WorkloadList,
        [Parameter(Mandatory)] [hashtable]$MergedAggregate,
        [Parameter(Mandatory)] [AllowEmptyString()] [string]$AccountId,
        [hashtable]$RecoveryPointArns,
        [string[]]$TruncatedRegions
    )
    foreach ($row in $WorkloadList) {
        if ("$($row.AwsAccountId)" -ne $AccountId) { continue }
        if ([string]::IsNullOrEmpty($row.ResourceArn)) { continue }
        $key = "$($row.AwsAccountId)|$($row.Region)|$($row.ResourceArn)"

        if ($null -ne $RecoveryPointArns -and $RecoveryPointArns.ContainsKey($key)) {
            $row.HasRecoveryPoints = $true
        }
        if ($null -ne $TruncatedRegions -and $TruncatedRegions -contains $row.Region) {
            $row.BackupEnumerationTruncated = $true
        }
        if (-not $MergedAggregate.ContainsKey($key)) { continue }

        $state = $MergedAggregate[$key]
        $row.HasBackups    = $state.HasBackups
        $row.BackupCount   = $state.BackupCount
        $row.BackupSources = $state.BackupSources
        $row.LatestBackupDate = $state.LatestBackupDate
        $sizes = ConvertTo-SizeUnits -Value $state.LatestBackupSizeBytes -Prefix "LatestBackupSize" -InputUnit Bytes
        $row.LatestBackupSizeGiB = $sizes["LatestBackupSizeGiB"]
        $row.LatestBackupSizeTiB = $sizes["LatestBackupSizeTiB"]
        $row.LatestBackupSizeGB  = $sizes["LatestBackupSizeGB"]
        $row.LatestBackupSizeTB  = $sizes["LatestBackupSizeTB"]
    }
}

# Orchestrator function
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

  # Check for Storage Lens configurations with CloudWatch publishing enabled (account-level check)
  # This is done ONCE per account across ALL regions.
  # Storage Lens dashboards can be in any region but monitor buckets across all regions
  $storageLensConfigsWithCloudWatch = Get-AWSStorageLensConfigs -Credential $cred -AccountInfo $awsAccountInfo -Regions $awsRegions

  if ($storageLensConfigsWithCloudWatch.Count -eq 0) {
    Write-Host "No Storage Lens configuration with CloudWatch publishing found for account $($awsAccountInfo.Account). CurrentVersion storage and object count details will not be collected." -ForegroundColor Yellow
  } else {
    Write-Host "Found $($storageLensConfigsWithCloudWatch.Count) Storage Lens configuration(s) with CloudWatch publishing enabled." -ForegroundColor Green
  }

  # Collect Route53 hosted zones ONCE per account (Route53 is a global service).
  # This deliberately runs BEFORE the per-region loop so the API is called only once.
  $route53Result = Get-AWSRoute53Inventory -Credential $cred -Region $queryRegion `
      -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias
  if ($null -ne $route53Result) {
      foreach ($r53Item in $route53Result) { $route53List.Add($r53Item) | Out-Null }
  }

  # Collect IAM inventory ONCE per account (IAM is a global service).
  # Returns a single row of counts per account, not a list — so wiring is simpler than Route53.
  $iamResult = Get-AWSIAMInventory -Credential $cred -Region $queryRegion `
      -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias
  if ($null -ne $iamResult) {
      $iamList.Add($iamResult) | Out-Null
  }

  # Per-account accumulator for regions whose RP enumeration hit the time budget.
  $truncatedBackupRegions = New-Object collections.arraylist

  # Per-account accumulator for vaults skipped due to AccessDenied on
  # backup:ListRecoveryPointsByBackupVault, summed across every region. The
  # per-region cmdlet returns its own count; we accumulate to avoid the
  # summary line only reflecting the LAST region's value.
  $totalVaultsDenied = 0

  # Remove orphan recovery-point tmp files left by a prior crashed run for this
  # run's date. Done ONCE here (not inside the per-region cmdlet, which would clobber
  # sibling regions' in-progress files for the current run).
  Remove-Item "aws_backup_recovery_points-*-$date_string.tmp.csv" -ErrorAction SilentlyContinue

  # For all specified regions get the S3 bucket, EC2 instance, EC2 Unattached disk and RDS info
  $awsRegionCounter = 1
  foreach ($awsRegion in $awsRegions) {
    Write-Progress -ID 2 -Activity "Processing region: $($awsRegion)" -Status "Region $($awsRegionCounter) of $($awsRegions.Count)" -PercentComplete (($awsRegionCounter / $awsRegions.Count) * 100)
    $awsRegionCounter++
    # Collect S3 inventory for this region
    $s3SkipTagsParam = @{}
    if ($SkipBucketTags) { $s3SkipTagsParam['SkipBucketTags'] = $true }
    $s3Result = Get-AWSS3Inventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias -StorageLensConfigs $storageLensConfigsWithCloudWatch `
        -UtcStartTime $utcStartTime -UtcEndTime $utcEndTime @s3SkipTagsParam
    if ($null -ne $s3Result) {
      foreach ($s3Item in $s3Result) { $s3List.Add($s3Item) | Out-Null }
    }

    # Collect EC2 inventory for this region
    $ec2Result = Get-AWSEC2Inventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    $ec2UnattachedVolumesRaw = $null
    if ($null -ne $ec2Result) {
      foreach ($inst in $ec2Result.Instances) { $ec2List.Add($inst) | Out-Null }
      foreach ($vol in $ec2Result.AttachedVolumes) { $ec2AttachedVolList.Add($vol) | Out-Null }
      foreach ($uvol in $ec2Result.UnattachedVolumes) { $ec2UnattachedVolList.Add($uvol) | Out-Null }
      $ec2UnattachedVolumesRaw = $ec2Result.UnattachedVolumesRaw
    }

    # Collect RDS inventory for this region
    $rdsResult = Get-AWSRDSInventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias -UtcStartTime $utcStartTime -UtcEndTime $utcEndTime
    if ($null -ne $rdsResult) {
      foreach ($rdsItem in $rdsResult) { $rdsList.Add($rdsItem) | Out-Null }
    }

    # Collect EFS inventory for this region
    $efsResult = Get-AWSEFSInventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    if ($null -ne $efsResult) {
      foreach ($efsItem in $efsResult) { $efsList.Add($efsItem) | Out-Null }
    }

    # Collect EKS inventory for this region
    $eksResult = Get-AWSEKSInventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    if ($null -ne $eksResult) {
      foreach ($eksItem in $eksResult.Clusters) { $eksList.Add($eksItem) | Out-Null }
      foreach ($ngItem in $eksResult.NodeGroups) { $eksNodeGroupList.Add($ngItem) | Out-Null }
    }

    # Collect FSx inventory for this region
    $fsxResult = Get-AWSFSxInventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias -UtcStartTime $utcStartTime -UtcEndTime $utcEndTime
    if ($null -ne $fsxResult) {
      foreach ($fsxFsItem in $fsxResult.FileSystems) { $fsxFileSystemList.Add($fsxFsItem) | Out-Null }
      foreach ($fsxVolItem in $fsxResult.Volumes) { $fsxList.Add($fsxVolItem) | Out-Null }
    }

    # Collect VPC inventory for this region
    $vpcResult = Get-AWSVPCInventory -Credential $cred -Region $awsRegion `
        -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias
    if ($null -ne $vpcResult) {
        foreach ($vpcItem in $vpcResult) { $vpcList.Add($vpcItem) | Out-Null }
    }

    # Collect Load Balancer inventory for this region (Classic + v2 ALB/NLB/GWLB)
    $lbResult = Get-AWSLoadBalancerInventory -Credential $cred -Region $awsRegion `
        -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias
    if ($null -ne $lbResult) {
        foreach ($lbItem in $lbResult) { $lbList.Add($lbItem) | Out-Null }
    }

    # Collect simple service counts for this region
    $simpleResult = Get-AWSSimpleServiceCounts -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    if ($null -ne $simpleResult) {
      if ($null -ne $simpleResult.Secrets) { $secretsList.Add($simpleResult.Secrets) | Out-Null }
      if ($null -ne $simpleResult.SQS) { $sqsList.Add($simpleResult.SQS) | Out-Null }
    }

    # Collect KMS customer-managed key inventory for this region
    $kmsResult = Get-AWSKMSInventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    if ($null -ne $kmsResult) {
      foreach ($kmsItem in $kmsResult) { $kmsList.Add($kmsItem) | Out-Null }
    }

    # Collect DynamoDB inventory for this region
    $ddbResult = Get-AWSDynamoDBInventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    if ($null -ne $ddbResult) {
      foreach ($ddbItem in $ddbResult) { $ddbList.Add($ddbItem) | Out-Null }
    }

    # Collect backup plan inventory for this region
    $backupPlanResult = Get-AWSBackupPlanInventory -Credential $cred -Region $awsRegion -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias -EC2List $ec2List -EC2UnattachedVolumesRaw $ec2UnattachedVolumesRaw `
        -EC2AttachedVolList $ec2AttachedVolList -RDSList $rdsList -EFSList $efsList -FSxList $fsxList `
        -FSxFileSystemList $fsxFileSystemList -S3List $s3List -DDBList $ddbList
    if ($null -ne $backupPlanResult) {
      foreach ($bpItem in $backupPlanResult) { $backupPlanList.Add($bpItem) | Out-Null }
    }

    # Build BackupPlanId -> BackupPlanName lookup from the just-collected plans.
    # The AWS ListRecoveryPointsByBackupVault API's CreatedBy payload omits
    # BackupPlanName entirely, so the RP cmdlet has no way to populate the name
    # without this side-channel. The map is rebuilt per region (cheap) so org-
    # managed plans with stable BackupPlanIds across regions remain resolvable.
    $planNameById = @{}
    if ($null -ne $backupPlanResult) {
      foreach ($bpItem in $backupPlanResult) {
        if ($null -eq $bpItem) { continue }
        $bpId   = "$($bpItem.BackupPlanId)"
        $bpName = if ($bpItem.PSObject.Properties['BackupPlan'] -and $bpItem.BackupPlan) {
          "$($bpItem.BackupPlan.BackupPlanName)"
        } else { "" }
        if ($bpId -and $bpName) { $planNameById[$bpId] = $bpName }
      }
    }

    # Collect AWS Backup recovery-point inventory for this region. The cmdlet streams
    # per-RP rows to a per-region tmp file; we accumulate the in-memory aggregate so a
    # later task can attribute backups onto the workload rows.
    #
    # The cmdlet re-throws non-throttle / non-AccessDenied errors (e.g. transient
    # network failures, region SCP blocks, malformed AWS responses). Without this
    # try/catch, such an exception would propagate up to the per-region loop and
    # abort EVERY subsequent collector (native, Redshift, costs, merge) for the
    # current account. Wrap, log red, and continue so one bad region doesn't
    # nuke the rest of the run.
    $rpResult = $null
    if (-not $SkipBackupCapacity) {
      try {
        $rpResult = Get-AWSBackupRecoveryPointInventory -Credential $cred -Region $awsRegion `
            -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias `
            -TimeoutMinutes $BackupRecoveryPointTimeoutMinutes -PlanNameById $planNameById
      } catch {
        Write-Host "RP enumeration failed for region $awsRegion in account $($awsAccountInfo.Account): $_" -ForegroundColor Red
        $rpResult = $null
      }
      if ($null -ne $rpResult) {
        foreach ($rpItem in $rpResult.RecoveryPoints) { $recoveryPointList.Add($rpItem) | Out-Null }
        foreach ($aggItem in $rpResult.ResourceAggregates) { $backupResourceAggregateList.Add($aggItem) | Out-Null }
        if ($rpResult.Truncated) { $truncatedBackupRegions.Add($awsRegion) | Out-Null }
        # Accumulate the per-vault AccessDenied count across regions. $rpResult
        # is reassigned each iteration, so reading the field after the loop
        # would surface only the last region's value.
        $totalVaultsDenied += [int]$rpResult.VaultsAccessDenied
      }
    }

    # Collect Redshift cluster inventory for this region (workload row source for
    # the Redshift snapshot collector below).
    $redshiftResult = Get-AWSRedshiftInventory -Credential $cred -Region $awsRegion `
        -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias
    if ($null -ne $redshiftResult) {
      foreach ($rsItem in $redshiftResult) { $redshiftClusterList.Add($rsItem) | Out-Null }
    }

    # Native (non-AWS-Backup) snapshot enumeration for this region. Each collector
    # dedups against AWS Backup via tag/identifier match (e.g. snapshot's
    # `aws:backup:source-resource` tag, RDS `awsbackup:job-*` identifier prefix,
    # FSx `Type = AWS_BACKUP`). Pass the set of SOURCE ResourceArns from the
    # RP enumeration so collectors can flag any source resource that AWS Backup
    # is already protecting -- useful diagnostics, not used for dedup.
    $regionRPArnSet = @{}
    if ($null -ne $rpResult) {
      foreach ($rpItem in @($rpResult.RecoveryPoints)) {
        if ($rpItem -and $rpItem.ResourceArn) { $regionRPArnSet["$($rpItem.ResourceArn)"] = $true }
      }
    }

    if (-not $SkipBackupCapacity) {
      $ebsAmiResult = Get-AWSEBSAndAMIInventory -Credential $cred -Region $awsRegion `
          -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias `
          -RecoveryPointArns $regionRPArnSet
      if ($null -ne $ebsAmiResult) {
        foreach ($b in $ebsAmiResult.Backups)    { $nativeBackupList.Add($b)  | Out-Null }
        foreach ($d in $ebsAmiResult.DetailRows) { $ebsAndAmiList.Add($d)     | Out-Null }
      }

      $rdsSnapResult = Get-AWSRDSSnapshotInventory -Credential $cred -Region $awsRegion `
          -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias `
          -RecoveryPointArns $regionRPArnSet
      if ($null -ne $rdsSnapResult) {
        foreach ($b in $rdsSnapResult.Backups)    { $nativeBackupList.Add($b)   | Out-Null }
        foreach ($d in $rdsSnapResult.DetailRows) { $rdsSnapshotList.Add($d)    | Out-Null }
      }

      $fsxBackupResult = Get-AWSFSxBackupInventory -Credential $cred -Region $awsRegion `
          -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias
      if ($null -ne $fsxBackupResult) {
        foreach ($b in $fsxBackupResult) { $nativeBackupList.Add($b) | Out-Null }
      }

      $ddbBackupResult = Get-AWSDDBBackupInventory -Credential $cred -Region $awsRegion `
          -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias -DDBList $ddbList
      if ($null -ne $ddbBackupResult) {
        foreach ($b in $ddbBackupResult) { $nativeBackupList.Add($b) | Out-Null }
      }

      $rsSnapResult = Get-AWSRedshiftSnapshotInventory -Credential $cred -Region $awsRegion `
          -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias
      if ($null -ne $rsSnapResult) {
        foreach ($b in $rsSnapResult) { $nativeBackupList.Add($b) | Out-Null }
      }
    }
  }
  Write-Progress -ID 2 -Activity "Processing region: $($awsRegion)" -Completed

  # Merge the per-region recovery-point tmp files into the single canonical CSV once
  # all regions for this account have been enumerated.
  Merge-AWSRecoveryPointTmpFiles -CanonicalPath $outputBackupRecoveryPoints

  # Once per account, summarize any regions whose RP enumeration was time-budget truncated.
  if ($truncatedBackupRegions.Count -gt 0) {
    Write-Host "RP enumeration truncated for region(s): $($truncatedBackupRegions -join ', ') in account $($awsAccountInfo.Account); capacity numbers are lower bounds for those regions." -ForegroundColor Yellow
  }
  # Surface the per-vault AccessDenied count: a partially-failed scan would
  # otherwise read as fully healthy on the canonical output. $totalVaultsDenied
  # was accumulated inside the per-region loop above (reading $rpResult here
  # would only reflect the last region's value).
  if ($totalVaultsDenied -gt 0) {
    Write-Host "AWS Backup vault enumeration: $totalVaultsDenied vault(s) skipped due to AccessDenied on backup:ListRecoveryPointsByBackupVault for account $($awsAccountInfo.Account); capacity is a lower bound." -ForegroundColor Yellow
  }

  # Wire backup aggregates onto this account's workload rows. Done once per account,
  # after all regions (and thus all per-source aggregates) for the account are in hand,
  # and BEFORE the body-level Add-TagsToAllObjectsInList calls so Tag:* still sorts last.
  # Only the RP aggregate (Source = AWSBackup) is folded in here; native collectors
  # (Tasks 5-9) append their own descriptors to $backupSourceAggregates without changing
  # this call site.
  $accountId = "$($awsAccountInfo.Account)"
  $accountRPAggregates = @($backupResourceAggregateList | Where-Object { "$($_.AwsAccountId)" -eq $accountId })

  # Set of account|region|ARN keys that have at least one recovery point -> HasRecoveryPoints.
  $recoveryPointArns = @{}
  foreach ($agg in $accountRPAggregates) {
    $recoveryPointArns["$($agg.AwsAccountId)|$($agg.Region)|$($agg.ResourceArn)"] = $true
  }

  $backupSourceAggregates = @(
    @{
      Source            = "AWSBackup"
      Entries           = $accountRPAggregates
      GetCount          = { param($e) $e.RecoveryPointCount }
      GetLatestDate     = { param($e) $e.LatestRecoveryPointDate }
      GetLatestSizeBytes = { param($e) $e.LatestRecoveryPointSizeBytes }
    }
  )
  # Filter native backups to this account before folding into the merged aggregate.
  $accountNativeBackups = @($nativeBackupList | Where-Object { "$($_.AwsAccountId)" -eq $accountId })
  $mergedBackupAggregate = Merge-BackupAggregates -SourceAggregates $backupSourceAggregates `
    -NativeBackupLists $accountNativeBackups

  $workloadLists = @(
    $ec2List, $ec2AttachedVolList, $ec2UnattachedVolList, $rdsList, $efsList,
    $fsxFileSystemList, $fsxList, $s3List, $ddbList, $redshiftClusterList
  )
  foreach ($wl in $workloadLists) {
    Set-WorkloadBackupColumns -WorkloadList $wl -MergedAggregate $mergedBackupAggregate `
      -AccountId $accountId -RecoveryPointArns $recoveryPointArns `
      -TruncatedRegions @($truncatedBackupRegions)
  }

  # Collect backup costs once per account (Cost Explorer API returns account-level data).
  # Skip when region discovery yielded nothing -- matches master's per-region loop, which
  # would have iterated 0 times in this scenario and never made the call.
  if ($awsRegions.Count -gt 0 -and -not $SkipBackupCosts) {
    $sharedTimePeriod = Get-CEDefaultTimeWindow
    $backupCostsResult = Get-AWSBackupCosts -Credential $cred -Region $awsRegions[0] -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    if ($null -ne $backupCostsResult) {
      foreach ($bcItem in $backupCostsResult) { $backupCostsList.Add($bcItem) | Out-Null }
    }
    $snapStorageResult = Get-AWSSnapshotStorageCosts -Credential $cred -Region $awsRegions[0] `
        -AccountInfo $awsAccountInfo -AccountAlias $awsAccountAlias -TimePeriod $sharedTimePeriod
    if ($null -ne $snapStorageResult) {
      foreach ($sItem in $snapStorageResult) { $snapshotStorageCostsList.Add($sItem) | Out-Null }
    }
  }
}


# Contains list of EC2 instances and RDS with capacity info

$ec2List = New-Object collections.arraylist
$ec2AttachedVolList = New-Object collections.arraylist
$ec2UnattachedVolList = New-Object collections.arraylist
$rdsList = New-Object collections.arraylist
$vpcList = New-Object collections.arraylist
$lbList = New-Object collections.arraylist
$route53List = New-Object collections.arraylist
$iamList = New-Object collections.arraylist
$s3List = New-Object collections.arraylist
$efsList = New-Object collections.arraylist
$fsxFileSystemList = New-Object collections.arraylist
$fsxList = New-Object collections.arraylist
$ddbList = New-Object collections.arraylist
$secretsList = New-Object collections.arraylist
$kmsList = New-Object collections.arraylist
$sqsList = New-Object collections.arraylist
$backupCostsList = New-Object collections.arraylist
$snapshotStorageCostsList = New-Object collections.arraylist
$backupPlanList = New-Object collections.arraylist
$recoveryPointList = New-Object collections.arraylist
$backupResourceAggregateList = New-Object collections.arraylist
$nativeBackupList = New-Object collections.arraylist
$ebsAndAmiList = New-Object collections.arraylist
$rdsSnapshotList = New-Object collections.arraylist
$redshiftClusterList = New-Object collections.arraylist
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


$ec2AttachedVolTotalGiB = ($ec2AttachedVolList.sizeGiB | Measure-Object -Sum).sum
$ec2AttachedVolTotalTiB = ($ec2AttachedVolList.sizeTiB | Measure-Object -Sum).sum
$ec2AttachedVolTotalGB = ($ec2AttachedVolList.sizeGB | Measure-Object -Sum).sum
$ec2AttachedVolTotalTB = ($ec2AttachedVolList.sizeTB | Measure-Object -Sum).sum
$ec2AttachedVolInBackupPolicyList = $ec2AttachedVolList | Where-Object { $_.InBackupPlan }
$ec2AttachedVolTotalBackupGiB = ($ec2AttachedVolInBackupPolicyList.sizeGiB | Measure-Object -Sum).sum
$ec2AttachedVolTotalBackupTiB = ($ec2AttachedVolInBackupPolicyList.sizeTiB | Measure-Object -Sum).sum
$ec2AttachedVolTotalBackupGB = ($ec2AttachedVolInBackupPolicyList.sizeGB | Measure-Object -Sum).sum
$ec2AttachedVolTotalBackupTB = ($ec2AttachedVolInBackupPolicyList.sizeTB | Measure-Object -Sum).sum

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
      if(($s3PropOrdered -like "*_Size*" -or $s3PropOrdered -like "NumberOfObjects*" -or $s3PropOrdered -like "CurrentVersionObjectCount_*") -and [string]::IsNullOrEmpty($item.$s3PropOrdered)) {
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
  # Get-AWSKMSInventory emits both customer-managed and AWS-managed keys; split
  # the count by KeyManager so the summary labels match what's being reported.
  $totalCustomerManagedKeys = (@($kmsList) | Where-Object { $_.KeyManager -eq 'CUSTOMER' }).Count
  $totalAwsManagedKeys = (@($kmsList) | Where-Object { $_.KeyManager -eq 'AWS' }).Count
  $totalQueues = ($sqsList.Queues | Measure-Object -Sum).sum

  # If statement is a workaround for error when getting backup plans when payer account 
  # does not allow access for linked accounts
  if ($null -eq $backupCostsList.AWSBackupNetUnblendedCost) {
    Write-Error "No AWS Backup costs found."
    Write-Error "AWS Cost data not reported"
  } else {
    $backupTotalNetUnblendedCost = ($backupCostsList.AWSBackupNetUnblendedCost | ForEach-Object { [decimal]($_.TrimStart('$')) } | Measure-Object -Sum).sum
  }

if ($Anonymize) {
  Write-Host
  Write-Host "Anonymizing..." -ForegroundColor Green

  $global:anonymizeProperties = @("Alias", "Arn", "AwsAccountAlias", "AwsAccountId", "BackupPlanArn", "BackupPlanId", "BackupPlanName",
                                  "BackupVaultArn", "BackupVaultName", "BucketName", "CidrBlock", "ClusterIdentifier", "ClusterName", "CreatorRequestId",
                                  "DBClusterIdentifier", "DBInstanceIdentifier", "DBName", "Description", "DestinationBackupVaultArn",
                                  "DNSName", "FileSystemDNSName", "FileSystemId", "FileSystemOwnerId", "HostedZoneId",
                                  "ImageId", "InstanceId", "InstanceName", "KeyId", "LoadBalancerName",
                                  "MasterUsername", "Name", "NodegroupArn",
                                  "NodegroupName", "NodeRole", "OwnerId", "ParentRecoveryPointArn", "Project", "RDSInstance",
                                  "RecoveryPointArn", "RequestId", "ResourceArn", "ResourceId", "ResourceName", "Resources",
                                  "RoleArn", "RuleId", "RuleName", "SnapshotArn", "SnapshotId", "SnapshotIdentifier",
                                  "TableArn", "TableId", "TableName", "TargetBackupVaultName",
                                  "VersionId", "VolumeId", "VpcId")
  if($AnonymizeFields){
    [string[]]$anonFieldsList = $AnonymizeFields.split(',')
    foreach($field in $anonFieldsList){
      if (-not $global:anonymizeProperties.Contains($field)) {
        $global:anonymizeProperties += $field
      }
    }
  }
  $global:anonymizeTags = $true
  if($NotAnonymizeFields){
    [string[]]$notAnonFieldsList = $NotAnonymizeFields.split(',')
    $global:anonymizeProperties = $global:anonymizeProperties | Where-Object { $_ -notin $notAnonFieldsList }
    if ($notAnonFieldsList -contains "Tags") {
      $global:anonymizeTags = $false
    }
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

  function Invoke-Anonymization {
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
          } elseif ($propertyName -like "$($script:tagPrefix)*" -and $global:anonymizeTags) {
            # Must anonymize both the tag name and value

            $tagValue = $DataObject.$propertyName
            $anonymizedTagKey = ""

            $tagName = $propertyName.Substring($script:tagPrefixLength)

            if (-not $global:anonymizeDict.ContainsKey("$tagName")) {
                $global:anonymizeDict["$tagName"] = Get-NextAnonymizedValue($script:tagKeyAnonField)
            }
            $anonymizedTagKey = $script:tagPrefix + $global:anonymizeDict["$tagName"]

            $anonymizedTagValue = $null
            if ($null -ne $tagValue) {
                if (-not $global:anonymizeDict.ContainsKey("$($tagValue)")) {
                    $global:anonymizeDict[$tagValue] = Get-NextAnonymizedValue($script:tagValueAnonField)#$anonymizedTagKey
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
              $DataObject.$propertyName = Invoke-Anonymization -DataObject $property.Value
          }
          elseif ($property.Value -is [System.Collections.IEnumerable] -and -not ($property.Value -is [string])) {
              $anonymizedCollection = @()
              foreach ($item in $property.Value) {
                  if ($item -is [PSObject]) {
                      $anonymizedItem = Invoke-Anonymization -DataObject $item
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

  function Invoke-CollectionAnonymization {
      param (
          [System.Collections.IEnumerable]$Collection
      )

      $anonymizedCollection = @()
      foreach ($item in $Collection) {
          if ($item -is [PSObject]) {
              $anonymizedItem = Invoke-Anonymization -DataObject $item
              $anonymizedCollection += $anonymizedItem
          } else {
              $anonymizedCollection += $item
          }
      }

      return $anonymizedCollection
  }

  # Anonymize each list
  $backupPlanList = Invoke-CollectionAnonymization -Collection $backupPlanList
  $backupCostsList = Invoke-CollectionAnonymization -Collection $backupCostsList
  $recoveryPointList = Invoke-CollectionAnonymization -Collection $recoveryPointList
  $ebsAndAmiList = Invoke-CollectionAnonymization -Collection $ebsAndAmiList
  $rdsSnapshotList = Invoke-CollectionAnonymization -Collection $rdsSnapshotList
  $redshiftClusterList = Invoke-CollectionAnonymization -Collection $redshiftClusterList
  $snapshotStorageCostsList = Invoke-CollectionAnonymization -Collection $snapshotStorageCostsList
  $ddbList = Invoke-CollectionAnonymization -Collection $ddbList
  $ec2List = Invoke-CollectionAnonymization -Collection $ec2List
  $ec2AttachedVolList = Invoke-CollectionAnonymization -Collection $ec2AttachedVolList
  $ec2UnattachedVolList = Invoke-CollectionAnonymization -Collection $ec2UnattachedVolList
  $efsList = Invoke-CollectionAnonymization -Collection $efsList
  $eksList = Invoke-CollectionAnonymization -Collection $eksList
  $eksNodeGroupList = Invoke-CollectionAnonymization -Collection $eksNodeGroupList
  $fsxFileSystemList = Invoke-CollectionAnonymization -Collection $fsxFileSystemList
  $fsxList = Invoke-CollectionAnonymization -Collection $fsxList
  $kmsList = Invoke-CollectionAnonymization -Collection $kmsList
  $rdsList = Invoke-CollectionAnonymization -Collection $rdsList
  $s3List = Invoke-CollectionAnonymization -Collection $s3List
  $s3ListAg = Invoke-CollectionAnonymization -Collection $s3ListAg
  $secretsList = Invoke-CollectionAnonymization -Collection $secretsList
  $sqsList = Invoke-CollectionAnonymization -Collection $sqsList
  $vpcList = Invoke-CollectionAnonymization -Collection $vpcList
  $lbList = Invoke-CollectionAnonymization -Collection $lbList
  $route53List = Invoke-CollectionAnonymization -Collection $route53List
  $iamList = Invoke-CollectionAnonymization -Collection $iamList
}

# Export to CSV
Write-Host ""

Add-TagsToAllObjectsInList($ec2List)
Write-Host "CSV file output to: $outputEc2Instance"  -ForegroundColor Green
$ec2List | Export-CSV -path $outputEc2Instance

Add-TagsToAllObjectsInList($ec2AttachedVolList)
Write-Host "CSV file output to: $outputEc2AttachedVolume"  -ForegroundColor Green
$ec2AttachedVolList | Export-CSV -path $outputEc2AttachedVolume

Add-TagsToAllObjectsInList($ec2UnattachedVolList)
Write-Host "CSV file output to: $outputEc2UnattachedVolume"  -ForegroundColor Green
$ec2UnattachedVolList | Export-CSV -path $outputEc2UnattachedVolume

Add-TagsToAllObjectsInList($rdsList)
Write-Host "CSV file output to: $outputRDS"  -ForegroundColor Green
$rdsList | Export-CSV -path $outputRDS

Add-TagsToAllObjectsInList($vpcList)
Write-Host "CSV file output to: $outputVPC" -ForegroundColor Green
$vpcList | Export-CSV -path $outputVPC

Add-TagsToAllObjectsInList($lbList)
Write-Host "CSV file output to: $outputLB" -ForegroundColor Green
$lbList | Export-CSV -path $outputLB

Write-Host "CSV file output to: $outputRoute53" -ForegroundColor Green
$route53List | Export-CSV -path $outputRoute53

Write-Host "CSV file output to: $outputIAM" -ForegroundColor Green
$iamList | Export-CSV -path $outputIAM

Write-Host "CSV file output to: $outputS3"  -ForegroundColor Green
$s3ListAg | Export-CSV -path $outputS3

Add-TagsToAllObjectsInList($efsList)
Write-Host "CSV file output to: $outputEFS"  -ForegroundColor Green
$efsList | Export-CSV -path $outputEFS

Add-TagsToAllObjectsInList($fsxFileSystemList)
Write-Host "CSV file output to: $outputFSXfilesystems"  -ForegroundColor Green
$fsxFileSystemList | Export-CSV -path $outputFSXfilesystems

Add-TagsToAllObjectsInList($fsxList)
Write-Host "CSV file output to: $outputFSX"  -ForegroundColor Green
$fsxList | Export-CSV -path $outputFSX

Write-Host "CSV file output to: $outputDDB"  -ForegroundColor Green
$ddbList | Export-CSV -path $outputDDB

Write-Host "CSV file output to: $outputSecrets"  -ForegroundColor Green
$secretsList | Export-CSV -path $outputSecrets

Write-Host "CSV file output to: $outputSQS"  -ForegroundColor Green
$sqsList | Export-CSV -path $outputSQS

Add-TagsToAllObjectsInList($kmsList)
Write-Host "CSV file output to: $outputKMS"  -ForegroundColor Green
$kmsList | Export-CSV -path $outputKMS

# Write the AWS Backup cost CSV. -NoTypeInformation is intentionally omitted so the
# emitted file matches the pre-PR byte-format (with the leading `#TYPE` line);
# downstream Apps Script consumers depend on the row offset that produces. When CE
# was unavailable we write a header-only row so the canonical filename exists.
Write-Host "CSV file output to: $outputBackupCosts"  -ForegroundColor Green
if ($backupCostsList.Count -gt 0) {
  $backupCostsList | Export-CSV -path $outputBackupCosts
} else {
  "#TYPE System.Management.Automation.PSCustomObject" | Out-File -FilePath $outputBackupCosts -Encoding utf8
  '"AwsAccountId","AwsAccountAlias","Time-Period-Start","Time-Period-End","AWSBackupAmortizedCost","AWSBackupBlendedCost","AWSBackupNetAmortizedCost","AWSBackupNetUnblendedCost","AWSBackupNormalizedUsageAmount","AWSBackupUnblendedCost","AWSBackupUsageQuantity"' | Out-File -FilePath $outputBackupCosts -Encoding utf8 -Append
}

# Snapshot-storage USAGE_TYPE cost CSV. Same header-only fallback as above.
Write-Host "CSV file output to: $outputSnapshotStorageCosts"  -ForegroundColor Green
if ($snapshotStorageCostsList.Count -gt 0) {
  $snapshotStorageCostsList | Export-CSV -path $outputSnapshotStorageCosts -NoTypeInformation
} else {
  "AwsAccountId,AwsAccountAlias,Time-Period-Start,Time-Period-End,Service,UsageType,UsageQuantity,UsageUnit,AmortizedCost,BlendedCost,NetAmortizedCost,NetUnblendedCost,UnblendedCost,NormalizedUsageAmount" | Out-File -FilePath $outputSnapshotStorageCosts -Encoding utf8
}

Write-Host "CSV file output to: $outputEKSClusters"  -ForegroundColor Green
$eksList | Export-CSV -path $outputEKSClusters

Write-Host "CSV file output to: $outputEKSNodegroups"  -ForegroundColor Green
$eksNodeGroupList | Export-CSV -path $outputEKSNodegroups

# Native (non-AWS-Backup) snapshot detail CSVs. Header-only if no rows so the
# canonical filename always exists for downstream tooling.
Write-Host "CSV file output to: $outputEBSAndAMI"  -ForegroundColor Green
if ($ebsAndAmiList.Count -gt 0) {
  $ebsAndAmiList | Export-CSV -path $outputEBSAndAMI -NoTypeInformation
} else {
  "AwsAccountId,AwsAccountAlias,Region,Source,ImageId,SnapshotId,ResourceArn,SizeBytes,SizeGiB,CreationDate,Name,Description,State" | Out-File -FilePath $outputEBSAndAMI -Encoding utf8
}

Write-Host "CSV file output to: $outputRDSSnapshots"  -ForegroundColor Green
if ($rdsSnapshotList.Count -gt 0) {
  $rdsSnapshotList | Export-CSV -path $outputRDSSnapshots -NoTypeInformation
} else {
  "AwsAccountId,AwsAccountAlias,Region,Source,Engine,SnapshotIdentifier,ResourceArn,SnapshotArn,SizeBytes,SizeGiB,CreationDate,SnapshotType,Status,ClusterIdentifier" | Out-File -FilePath $outputRDSSnapshots -Encoding utf8
}

Write-Host "CSV file output to: $outputRedshiftClusters"  -ForegroundColor Green
if ($redshiftClusterList.Count -gt 0) {
  $redshiftClusterList | Export-CSV -path $outputRedshiftClusters -NoTypeInformation
} else {
  "AwsAccountId,AwsAccountAlias,Region,ClusterIdentifier,NodeType,NumberOfNodes,ClusterStatus,MasterUsername,DBName,ClusterCreateTime,AutomatedSnapshotRetentionPeriod,ManualSnapshotRetentionPeriod,ResourceArn,HasBackups,HasRecoveryPoints,BackupCount,BackupSources,LatestBackupDate,LatestBackupSizeGiB,LatestBackupSizeTiB,LatestBackupSizeGB,LatestBackupSizeTB,BackupEnumerationTruncated" | Out-File -FilePath $outputRedshiftClusters -Encoding utf8
}

# Export to JSON
Write-Host "JSON file output to: $outputBackupPlansJSON"  -ForegroundColor Green
$backupPlanList | ConvertTo-Json -Depth 10 > $outputBackupPlansJSON

# Latest-backup logical size totals (any source). These sum LatestBackupSizeGiB over
# rows where HasBackups is true -- the approximate Rubrik first-full bound -- and are
# distinct from the legacy InBackupPlan-filtered provisioned-source totals above.
function Get-LatestBackupSummary($list) {
  $withBackups = @($list | Where-Object { $_.HasBackups })
  # Measure-Object -Sum returns $null on an empty input, which renders as blank in
  # the console output ("sum =  GiB / ..."). Coerce to 0 here so the summary line is
  # always readable even when no rows have backups.
  $sum = { param($prop) $v = ($withBackups.$prop | Measure-Object -Sum).Sum; if ($null -eq $v) { 0 } else { $v } }
  [PSCustomObject]@{
    Count   = $withBackups.Count
    GiB     = & $sum 'LatestBackupSizeGiB'
    TiB     = & $sum 'LatestBackupSizeTiB'
    GB      = & $sum 'LatestBackupSizeGB'
    TB      = & $sum 'LatestBackupSizeTB'
    Sources = (($withBackups.BackupSources | Where-Object { $_ } | ForEach-Object { $_ -split ',\s*' } | Sort-Object -Unique) -join ", ")
  }
}

$ec2LatestBackup           = Get-LatestBackupSummary $ec2List
$ec2AttachedVolLatestBackup = Get-LatestBackupSummary $ec2AttachedVolList
$ec2UnVolLatestBackup      = Get-LatestBackupSummary $ec2UnattachedVolList
$rdsLatestBackup           = Get-LatestBackupSummary $rdsList
$efsLatestBackup           = Get-LatestBackupSummary $efsList

# Print Summary
Write-Host
Write-Host "Total # of EC2 instances: $($ec2list.count)"  -ForegroundColor Green
Write-Host "Total # of volumes: $(($ec2list.volumes | Measure-Object -Sum).sum)"  -ForegroundColor Green
Write-Host "Total capacity of all volumes: $ec2TotalGiB GiB or $ec2TotalGB GB or $ec2TotalTiB TiB or $ec2TotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned source size of EC2 instances in AWS Backup plans: $ec2TotalBackupGiB GiB or $ec2TotalBackupGB GB or $ec2TotalBackupTiB TiB or $ec2TotalBackupTB TB"  -ForegroundColor Green
Write-Host "Latest-backup logical size of EC2 instances with backups (any source): $($ec2LatestBackup.Count) resources, sum = $($ec2LatestBackup.GiB) GiB / $($ec2LatestBackup.TiB) TiB / $($ec2LatestBackup.GB) GB / $($ec2LatestBackup.TB) TB"  -ForegroundColor Green
if ($ec2LatestBackup.Sources) { Write-Host "  Sources observed: $($ec2LatestBackup.Sources)"  -ForegroundColor Green }
Write-Host

Write-Host
Write-Host "Total # of EC2 attached volumes: $($ec2AttachedVolList.count)"  -ForegroundColor Green
Write-Host "Total capacity of all attached volumes: $ec2AttachedVolTotalGiB GiB or $ec2AttachedVolTotalGB GB or $ec2AttachedVolTotalTiB TiB or $ec2AttachedVolTotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned source size of attached EBS volumes in AWS Backup plans: $ec2AttachedVolTotalBackupGiB GiB or $ec2AttachedVolTotalBackupGB GB or $ec2AttachedVolTotalBackupTiB TiB or $ec2AttachedVolTotalBackupTB TB"  -ForegroundColor Green
Write-Host "Latest-backup logical size of attached EBS volumes with backups (any source): $($ec2AttachedVolLatestBackup.Count) resources, sum = $($ec2AttachedVolLatestBackup.GiB) GiB / $($ec2AttachedVolLatestBackup.TiB) TiB / $($ec2AttachedVolLatestBackup.GB) GB / $($ec2AttachedVolLatestBackup.TB) TB"  -ForegroundColor Green
if ($ec2AttachedVolLatestBackup.Sources) { Write-Host "  Sources observed: $($ec2AttachedVolLatestBackup.Sources)"  -ForegroundColor Green }

Write-Host
Write-Host "Total # of EC2 unattached volumes: $($ec2UnattachedVolList.count)"  -ForegroundColor Green
Write-Host "Total capacity of all unattached volumes: $ec2UnVolTotalGiB GiB or $ec2UnVolTotalGB GB or $ec2UnVolTotalTiB TiB or $ec2UnVolTotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned source size of unattached EBS volumes in AWS Backup plans: $ec2UnVolTotalBackupGiB GiB or $ec2UnVolTotalBackupGB GB or $ec2UnVolTotalBackupTiB TiB or $ec2UnVolTotalBackupTB TB"  -ForegroundColor Green
Write-Host "Latest-backup logical size of unattached EBS volumes with backups (any source): $($ec2UnVolLatestBackup.Count) resources, sum = $($ec2UnVolLatestBackup.GiB) GiB / $($ec2UnVolLatestBackup.TiB) TiB / $($ec2UnVolLatestBackup.GB) GB / $($ec2UnVolLatestBackup.TB) TB"  -ForegroundColor Green
if ($ec2UnVolLatestBackup.Sources) { Write-Host "  Sources observed: $($ec2UnVolLatestBackup.Sources)"  -ForegroundColor Green }

Write-Host
Write-Host "Total # of RDS instances: $($rdsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all RDS instances: $rdsTotalGiB GiB or $rdsTotalGB GB or $rdsTotalTiB TiB or $rdsTotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned source size of RDS instances in AWS Backup plans: $rdsTotalBackupGiB GiB or $rdsTotalBackupGB GB or $rdsTotalBackupTiB TiB or $rdsTotalBackupTB TB"  -ForegroundColor Green
Write-Host "Latest-backup logical size of RDS instances with backups (any source): $($rdsLatestBackup.Count) resources, sum = $($rdsLatestBackup.GiB) GiB / $($rdsLatestBackup.TiB) TiB / $($rdsLatestBackup.GB) GB / $($rdsLatestBackup.TB) TB"  -ForegroundColor Green
if ($rdsLatestBackup.Sources) { Write-Host "  Sources observed: $($rdsLatestBackup.Sources)"  -ForegroundColor Green }

Write-Host
Write-Host "Total # of VPCs: $($vpcList.count)" -ForegroundColor Green

Write-Host
Write-Host "Total # of Load Balancers: $($lbList.count)" -ForegroundColor Green

Write-Host
Write-Host "Total # of Route53 hosted zones: $($route53List.count)" -ForegroundColor Green

Write-Host
Write-Host "Total # of IAM accounts profiled: $($iamList.count)" -ForegroundColor Green

Write-Host
Write-Host "Total # of EFS file systems: $($efsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all EFS file systems: $efsTotalGiB GiB or $efsTotalGB GB or $efsTotalTiB TiB or $efsTotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned source size of EFS file systems in AWS Backup plans: $efsTotalBackupGiB GiB or $efsTotalBackupGB GB or $efsTotalBackupTiB TiB or $efsTotalBackupTB TB"  -ForegroundColor Green
Write-Host "Latest-backup logical size of EFS file systems with backups (any source): $($efsLatestBackup.Count) resources, sum = $($efsLatestBackup.GiB) GiB / $($efsLatestBackup.TiB) TiB / $($efsLatestBackup.GB) GB / $($efsLatestBackup.TB) TB"  -ForegroundColor Green
if ($efsLatestBackup.Sources) { Write-Host "  Sources observed: $($efsLatestBackup.Sources)"  -ForegroundColor Green }

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
Write-Host "Total # of customer-managed KMS Keys: $($totalCustomerManagedKeys)"  -ForegroundColor Green
Write-Host "Total # of AWS-managed KMS Keys: $($totalAwsManagedKeys)"  -ForegroundColor Green
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

# Combined cost summary printed underneath the legacy 'Net unblended cost' line.
# The two queries partition spend disjointly so a simple sum gives an upper bound.
$snapshotNetUnblendedCost = 0
foreach ($row in $snapshotStorageCostsList) {
  if ($row.NetUnblendedCost) {
    $val = "$($row.NetUnblendedCost)".TrimStart('$')
    [double]$num = 0
    if ([double]::TryParse($val, [ref]$num)) { $snapshotNetUnblendedCost += $num }
  }
}
$awsBackupCombined = 0
if ($backupTotalNetUnblendedCost) {
  [double]$backupNum = 0
  if ([double]::TryParse("$backupTotalNetUnblendedCost", [ref]$backupNum)) { $awsBackupCombined = $backupNum }
}
$combinedCost = [math]::Round($awsBackupCombined + $snapshotNetUnblendedCost, 2)
Write-Host
Write-Host "AWS Backup cost summary (past 12 months + MTD):"  -ForegroundColor Green
Write-Host ("  AWS Backup service (fully-managed resources)        : `${0}" -f [math]::Round($awsBackupCombined, 2))  -ForegroundColor Green
Write-Host ("  Snapshot/backup USAGE_TYPE (source-service-billed)  : `${0}" -f [math]::Round($snapshotNetUnblendedCost, 2))  -ForegroundColor Green
Write-Host ("  Combined upper bound                                : `${0}" -f $combinedCost)  -ForegroundColor Green
Write-Host "Note: the USAGE_TYPE component includes manual snapshots and native automated backups (DLM, RDS automated, FSx automatic, etc.), not only those created by AWS Backup. The capacity columns in the per-workload CSVs attribute backups to their exact source mechanism (BackupSources column)."  -ForegroundColor Green

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

Compress-SizingArchive -OutputFiles $outputFiles -ArchiveFile $archiveFile

Write-Host
Write-Host
Write-Host "Results have been compressed into $archiveFile and original files have been removed." -ForegroundColor Green

[System.Threading.Thread]::CurrentThread.CurrentCulture = $CurrentCulture
[System.Threading.Thread]::CurrentThread.CurrentUICulture = $CurrentCulture

Write-Host
Write-Host
Write-Host "Please send $archiveFile to your Rubrik representative" -ForegroundColor Cyan
Write-Host