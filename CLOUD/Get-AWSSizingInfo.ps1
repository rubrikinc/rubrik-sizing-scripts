#requires -Version 7.0
<#requires -Modules AWS.Tools.Common, AWS.Tools.EC2, AWS.Tools.S3, AWS.Tools.RDS, AWS.Tools.SecurityToken, AWS.Tools.Organizations, AWS.Tools.IdentityManagement, AWS.Tools.CloudWatch, AWS.Tools.ElasticFileSystem, AWS.Tools.ElasticLoadBalancing, AWS.Tools.ElasticLoadBalancingV2, AWS.Tools.SSO, AWS.Tools.SSOOIDC, AWS.Tools.FSX, AWS.Tools.Backup, AWS.Tools.CostExplorer, AWS.Tools.DynamoDBv2, AWS.Tools.Route53, AWS.Tools.SQS, AWS.Tools.SecretsManager, AWS.Tools.KeyManagementService, AWS.Tools.EKS, AWS.Tools.S3Control
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

    Install-Module AWS.Tools.Common,AWS.Tools.EC2,AWS.Tools.S3,AWS.Tools.RDS,AWS.Tools.SecurityToken,AWS.Tools.Organizations,AWS.Tools.IdentityManagement,AWS.Tools.CloudWatch,AWS.Tools.ElasticFileSystem,AWS.Tools.ElasticLoadBalancing,AWS.Tools.ElasticLoadBalancingV2,AWS.Tools.SSO,AWS.Tools.SSOOIDC,AWS.Tools.FSX,AWS.Tools.Backup,AWS.Tools.CostExplorer,AWS.Tools.DynamoDBv2,AWS.Tools.Route53,AWS.Tools.SQS,AWS.Tools.SecretsManager,AWS.Tools.KeyManagementService,AWS.Tools.EKS

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
                    "ec2:DescribeVpcs",
                    "eks:DescribeCluster",
                    "eks:ListClusters",
                    "eks:ListNodegroups",
                    "elasticloadbalancing:DescribeLoadBalancers",
                    "elasticfilesystem:DescribeFileSystems",
                    "fsx:DescribeFileSystems",
                    "fsx:DescribeVolumes",
                    "iam:ListAccountAliases",
                    "iam:ListPolicies",
                    "iam:ListRoles",
                    "iam:ListUsers",
                    "kms:ListKeys",
                    "organizations:ListAccounts",
                    "rds:DescribeDBInstances",
                    "route53:ListHostedZones",
                    "s3:GetBucketLocation",
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
  [switch]$DebugBucketTags
)

# Script version — update this with every PR that modifies this script.
$scriptVersion = "1.1.0"

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
        "Region" = $Region
        "BackupPlans" = ""
        "InBackupPlan" = $false
      }
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
      }

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
      }

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
            $lbResult.Add([PSCustomObject] @{
                "AwsAccountId"     = $AccountInfo.Account
                "AwsAccountAlias"  = $AccountAlias
                "Region"           = $Region
                "LoadBalancerName" = $_.LoadBalancerName
                "Type"             = "classic"
                "Scheme"           = $_.Scheme
                "VpcId"            = $_.VPCId
                "DNSName"          = $_.DNSName
                "Arn"              = "arn:$($partitionId):elasticloadbalancing:${Region}:$($AccountInfo.Account):loadbalancer/$($_.LoadBalancerName)"
            }) | Out-Null
        }
    } catch {
        Write-Host "Failed to get Classic LBs for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
    }

    try {
        Get-ELB2LoadBalancer -Credential $Credential -Region $Region -ErrorAction Stop | ForEach-Object {
            $lbResult.Add([PSCustomObject] @{
                "AwsAccountId"     = $AccountInfo.Account
                "AwsAccountAlias"  = $AccountAlias
                "Region"           = $Region
                "LoadBalancerName" = $_.LoadBalancerName
                "Type"             = $_.Type
                "Scheme"           = $_.Scheme
                "VpcId"            = $_.VpcId
                "DNSName"          = $_.DNSName
                "Arn"              = $_.LoadBalancerArn
            }) | Out-Null
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
      }
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

    $kmsObj = $null
    $secretsObj = $null
    $sqsObj = $null

#Start ingesting KMS key information
    try{
      $numberOfKMS = (Get-KMSKeyList -Region $Region -ErrorAction Stop).Count
      $kmsObj = [PSCustomObject] @{
        "AwsAccountId" = $AccountInfo.Account
        "AwsAccountAlias" = $AccountAlias
        "Region" = $Region
        "Keys" = $numberOfKMS
      }
    } catch{
      Write-Host "Failed to get # of KMS keys for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
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

    return @{ KMS = $kmsObj; Secrets = $secretsObj; SQS = $sqsObj }
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
        $S3List,
        $DDBList
    )

    $backupPlanResult = New-Object collections.arraylist

#Ingest AWS Backup Plans and evaluate protected resources
    $BackupPlans = $null
    try{
      $BackupPlans = Get-BAKBackupPlanList -Credential $Credential -region $Region -ErrorAction Stop;

    } catch {
      Write-Host "Failed to get Backup Plans Info for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }
#Custom Object for Protected Backup Objects
<# $protectedBAKobjs = [PSCustomObject] @{
  "AwsAccountId" = $AccountInfo.Account
  "AwsAccountAlias" = $AccountAlias
  "ResourceName" = $s3Bucket
  "Resource" = "undefined"
  "ResourceType" = "undefined"
  "Region" = $Region
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
      $backupPlanRules = (Get-BAKBackupPlan -BackupPlanId $plan.BackupPlanId -Credential $Credential -region $Region ).BackupPlan.Rules;
      foreach($rule in $backupPlanRules) {
        $vault = Get-BAKBackupVault -BackupVaultName $rule.TargetBackupVaultName -Credential $Credential -region $Region ;
        $protectedResourceList = Get-BAKProtectedResourceList -Credential $Credential -region $Region  | Where-Object {$_.LastBackupVaultArn -eq $vault.BackupVaultArn }
        #add resource to array .resourceName, .resourcetype
        foreach($resource in $protectedResourceList) {
          $recoveryPointInfo = Get-BAKRecoveryPoint -RecoveryPointArn $resource.LastRecoveryPointArn -BackupVaultName $rule.TargetBackupVaultName -Credential $Credential -region $Region ;
          $protectedBAKobjs += [PSCustomObject]@{
            "AWSAccountId" = $AccountInfo.Account
            "AWSAccountAlias" = $AccountAlias
            "ResourceName" = $resource.ResourceName
            "Resource" = $resource.resourceArn
            "ResourceType" = $resource.ResourceType
            "Region" = $Region
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
        $BackupPlanObject = (Get-BAKBackupPlan -Credential $Credential -region $Region -BackupPlanId $plan.BackupPlanId) | ConvertTo-Json -Depth 10 | ConvertFrom-Json
      } catch {
        Write-Host "Failed to get Backup Plans $($plan.BackupPlanId) for region $Region in account $($AccountInfo.Account)" -ForeGroundColor Red
        Write-Host "Error: $_" -ForeGroundColor Red
      }
      $BackupPlanObject | Add-Member -MemberType NoteProperty -Name "Resources" -Value @()
      $selections = $null
      try{
        $selections = Get-BAKBackupSelectionList -Credential $Credential -region $Region -BackupPlanId $plan.BackupPlanId -ErrorAction Stop
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

function Get-AWSBackupCosts {
    param(
        $Credential,
        [string]$Region,
        $AccountInfo,
        [string]$AccountAlias
    )

    $backupCostsResult = New-Object collections.arraylist

    $filter = @{
      Dimensions = @{
          Key = "SERVICE"
          Values = @("AWS Backup")
      }
    }

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
        -Filter $filter -Credential $Credential -Region $Region -ErrorAction Stop
    } catch {
      Write-Host "Failed to get Backup cost info for account $($AccountInfo.Account)" -ForeGroundColor Red
      Write-Host "Error: $_" -ForeGroundColor Red
    }

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
      if ($null -ne $simpleResult.KMS) { $kmsList.Add($simpleResult.KMS) | Out-Null }
      if ($null -ne $simpleResult.Secrets) { $secretsList.Add($simpleResult.Secrets) | Out-Null }
      if ($null -ne $simpleResult.SQS) { $sqsList.Add($simpleResult.SQS) | Out-Null }
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
        -S3List $s3List -DDBList $ddbList
    if ($null -ne $backupPlanResult) {
      foreach ($bpItem in $backupPlanResult) { $backupPlanList.Add($bpItem) | Out-Null }
    }
  }
  Write-Progress -ID 2 -Activity "Processing region: $($awsRegion)" -Completed

  # Collect backup costs once per account (Cost Explorer API returns account-level data).
  # Skip when region discovery yielded nothing — matches master's per-region loop, which
  # would have iterated 0 times in this scenario and never made the call.
  if ($awsRegions.Count -gt 0) {
    $backupCostsResult = Get-AWSBackupCosts -Credential $cred -Region $awsRegions[0] -AccountInfo $awsAccountInfo `
        -AccountAlias $awsAccountAlias
    if ($null -ne $backupCostsResult) {
      foreach ($bcItem in $backupCostsResult) { $backupCostsList.Add($bcItem) | Out-Null }
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

if ($Anonymize) {
  Write-Host
  Write-Host "Anonymizing..." -ForegroundColor Green

  $global:anonymizeProperties = @("Arn", "AwsAccountAlias", "AwsAccountId", "BackupPlanArn", "BackupPlanId", "BackupPlanName",
                                  "BucketName", "CidrBlock", "ClusterName", "CreatorRequestId", "DBInstanceIdentifier", "DestinationBackupVaultArn",
                                  "DNSName", "FileSystemDNSName", "FileSystemId", "FileSystemOwnerId", "HostedZoneId",
                                  "InstanceId", "InstanceName", "LoadBalancerName", "Name", "NodegroupArn",
                                  "NodegroupName", "NodeRole", "OwnerId", "Project", "RDSInstance", "RequestId", "Resources",
                                  "RoleArn", "RuleId", "RuleName", "TableArn", "TableId", "TableName", "TargetBackupVaultName",
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
Write-Host "Total # of EC2 attached volumes: $($ec2AttachedVolList.count)"  -ForegroundColor Green
Write-Host "Total capacity of all attached volumes: $ec2AttachedVolTotalGiB GiB or $ec2AttachedVolTotalGB GB or $ec2AttachedVolTotalTiB TiB or $ec2AttachedVolTotalTB TB"  -ForegroundColor Green
Write-Host "Capacity of all backed up attached volumes: $ec2AttachedVolTotalBackupGiB GiB or $ec2AttachedVolTotalBackupGB GB or $ec2AttachedVolTotalBackupTiB TiB or $ec2AttachedVolTotalBackupTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of EC2 unattached volumes: $($ec2UnattachedVolList.count)"  -ForegroundColor Green
Write-Host "Total capacity of all unattached volumes: $ec2UnVolTotalGiB GiB or $ec2UnVolTotalGB GB or $ec2UnVolTotalTiB TiB or $ec2UnVolTotalTB TB"  -ForegroundColor Green
Write-Host "Capacity of all backed up unattached volumes: $ec2UnVolTotalBackupGiB GiB or $ec2UnVolTotalBackupGB GB or $ec2UnVolTotalBackupTiB TiB or $ec2UnVolTotalBackupTB TB"  -ForegroundColor Green

Write-Host
Write-Host "Total # of RDS instances: $($rdsList.count)"  -ForegroundColor Green
Write-Host "Total provisioned capacity of all RDS instances: $rdsTotalGiB GiB or $rdsTotalGB GB or $rdsTotalTiB TiB or $rdsTotalTB TB"  -ForegroundColor Green
Write-Host "Provisioned capacity of all backed up RDS instances: $rdsTotalBackupGiB GiB or $rdsTotalBackupGB GB or $rdsTotalBackupTiB TiB or $rdsTotalBackupTB TB"  -ForegroundColor Green

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