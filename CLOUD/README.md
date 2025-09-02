# Cloud Sizing Scripts README

This contains information about Rubrik scripts for collecting sizing information for resources across AWS, Azure, and GCP. Below you will find detailed instructions on setting up prerequisites, running the scripts, and understanding their functionalities, including the anonymization feature.

## Table of Contents

1. [Introduction](#introduction)
2. [AWS](#aws)
    - [Prerequisites](#aws-prerequisites)
    - [Running the Script](#running-the-aws-script)
3. [Azure](#azure)
    - [Prerequisites](#azure-prerequisites)
    - [Running the Script](#running-the-azure-script)
4. [GCP](#gcp)
    - [Prerequisites](#gcp-prerequisites)
    - [Running the Script](#running-the-gcp-script)
5. [Anonymization Feature](#anonymization-feature)
6. [FAQ](#faq)

---

## Introduction

This repository contains scripts designed to collect and report on cloud resources across AWS, Azure, and GCP. These scripts help gather essential sizing data which will be used for scaling and pricing Rubrik solutions.

---

## AWS

### Authenticaition

1. Use the local AWS profile (IAM user) to login to just one account.
1. Use a list of local AWS profiles to login to and query multiple accounts.
1. Use a cross account role with a list of AWS accounts that you provide to assume role into each account.
1. Use a cross account role with an AWS Org and have the script automatically discover all of your accounts and query each one.
1. Have the script query AWS SSO for a list of accounts. Each account will be accessed via the AWS SSO parameter set that is specified. 

<Add examples>

### AWS Prerequisites

To run the AWS sizing script, ensure you have the following:

- PowerShell 7.4.5 or higher
- AWS PowerShell modules installed:
- An AWS account with the necessary permissions.
  - The following AWS permissions are required to run the script:
      ```json
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
                      "eks:DescribeNodegroups",
                      "elasticfilesystem:DescribeFileSystems",
                      "fsx:DescribeFileSystems",
                      "fsx:DescribeVolumes",
                      "iam:ListAccountAliases",
                      "kms:ListKeys",
                      "organizations:ListAccounts",
                      "rds:DescribeDBInstances",
                      "s3:GetBucketLocation",
                      "s3:ListAllMyBuckets",
                      "s3:GetBucketTagging",
                      "secretsmanager:ListSecrets",
                      "sts:AssumeRole",
                      "sqs:ListQueues"
                  ],
                  "Resource": "*"
              }
          ]
      }
      ```
    - These permissions can be installed in a cross account role by using the [Get-AWSSizingInfo-Permissions.cft](Get-AWSSizingInfo-Permissions.cft) CloudFormation template. This cross account role can be installed in multiple AWS accounts by using a [CloudFormation Stack Set](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/what-is-cfnstacksets.html).

### Running the AWS Script

There are two options for running the AWS sizing script. It can run from the AWS Cloud Shell (easiest) or from a local laptop or server (more difficult). For very large environments where the script may run longer than 20-30 minutes, running the script on a laptop or server may be necessary. This is due to the Cloud Shell's default inactivity timeout. 

To run the script from the AWS Cloud Shell do the following:

1. Open [AWS Cloud Shell](https://docs.aws.amazon.com/cloudshell/latest/userguide/welcome.html) in an AWS account with a profile to run the script.
1. Start PowerShell by running:
    ```shell
    pwsh
    ```

To run the script from a local laptop or server do the following:

1. Verify that PowerShell v7.4.5 or higher is installed.
1. Install the AWS modules for PowerShell with the following command:
    ```powershell
    Install-Module AWS.Tools.Common,AWS.Tools.EC2,AWS.Tools.S3,AWS.Tools.RDS,AWS.Tools.SecurityToken,AWS.Tools.Organizations,AWS.Tools.IdentityManagement,AWS.Tools.CloudWatch,AWS.Tools.ElasticFileSystem,AWS.Tools.SSO,AWS.Tools.SSOOIDC,AWS.Tools.FSX,AWS.Tools.Backup,AWS.Tools.CostExplorer,AWS.Tools.DynamoDBv2,AWS.Tools.SQS,AWS.Tools.SecretsManager,AWS.Tools.KeyManagementService,AWS.Tools.EKS

    ```
1. Ensure AWS credentials are set up by using the `Set-AWSCredential` command. For example:
    ```powershell
    Set-AWSCredential -AccessKey 'YourAccessKey' -SecretKey 'YourSecretKey' -Region 'YourRegion'
    ```

In both cases run the sizing script with the appropriate options and send the data back to Rubrik.
1. Execute the script:
    ```powershell
    .\Get-AWSSizingInfo.ps1
    ```
1. The script will output a summary to the console and create a zip file with CSV and JSON files, along with a LOG of the console output. 
1. Please download the ZIP file and send it to your Rubrik representative.


### Troubleshooting

#### Explicit deny in a service control policy

- Problem:

  When running the script against AWS SSO or an AWS Org the following type of error may occur:

  ```
  Failed to get Backup Plans Info for region us-east-2 in account 123456789012
  Error: User: arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_AdministratorAccess_1234567890abcdef/firstname.lastname@company.com is not authorized to perform: backup:ListBackupPlans with an explicit deny in a service control policy
  ```

- Solution:

  An AWS service control policy is in place that prevents running commands in the region that is listed. Use the -Regions parameter to restrict the script to only run in regions that are supported by the organization. 


#### Invalid grant provided

- Problem:

When using AWS SSO the following error may occur while authorizing the script in SSO:

```
Allow access to your data? invalid_grant
Invalid grant provided
```

- Solution:

AWS SSO is not being accessed in the correct region. By default, the script uses `us-east-1` to communicate with AWS SSO. To look up the proper region for AWS SSO select `Access Keys` next to the Parameter Set that is being used. The next screen will specify a region where the access keys can be used. This is the region for the AWS SSO. Next specify the `-SSORegion` flag and use the region that was discovered. 

---

## Azure

### Azure Prerequisites

To run the Azure sizing script, ensure you have the following:

- Azure AD account with "Reader" and "Reader and Data Access" roles on each subscription.
- PowerShell 7 installed if running locally.
- Required Azure PowerShell modules installed:
    ```powershell
    Install-Module Az.Accounts,Az.Compute,Az.Storage,Az.Sql,Az.SqlVirtualMachine,Az.ResourceGraph,Az.Monitor,Az.Resources,Az.RecoveryServices,Az.CostManagement,Az.CosmosDB
    ```

### Running the Azure Script

1. **From Azure Cloud Shell (preferred):**
    - Login to the Azure portal and open [Azure Cloud Shell](https://learn.microsoft.com/en-us/azure/cloud-shell/get-started/classic?source=recommendations&tabs=azurecli).
    - Install the necessary module:
        ```powershell
        Install-Module Az.CostManagement
        ```
    - Upload and run the script:
        ```powershell
        .\Get-AzureSizingInfo.ps1
        ```

2. **From a local system:**
    - Install PowerShell 7 and necessary Azure modules as mentioned above.
    - Login to Azure:
        ```powershell
        Connect-AzAccount
        ```
    - Run the script:
        ```powershell
        .\Get-AzureSizingInfo.ps1
        ```

4. The script will output a summary to the console and create a zip file with CSV and JSON files, along with a LOG of the console output. Please download the ZIP file and send it to your Rubrik representative.

---

## GCP

### GCP Prerequisites

To run the GCP sizing script, ensure you have the following:

- GCP account with necessary IAM permissions: "compute.instances.list", "compute.disks.get", "resourcemanager.projects.get".
- GCP Cloud SDK installed or use GCP Cloud Shell.

### Running the GCP Script

1. **From GCP Cloud Shell:**
    - Login and initialize [GCP Cloud Shell](https://cloud.google.com/shell):
        ```shell
        gcloud init
        ```

2. **Using Cloud Tools for PowerShell:**
    - Login to GCP:
        ```powershell
        gcloud auth list
        gcloud config list
        ```
    - Run the script:
        ```powershell
        .\Get-GCPSizingInfo.ps1
        ```

34. The script will output a summary to the console and create a zip file with a CSV file, along with a LOG of the console output. Please download the ZIP file and send it to your Rubrik representative.

---

## Anonymization Feature

The anonymization feature allows you to anonymize specific fields in the output to protect sensitive information. You can use the flags on any/all the 3 AWS/Azure/GCP scripts.

- Use the tag `-Anonymize`. Fields anonymized by default are as follows:

    - **AWS:** "AwsAccountId", "AwsAccountAlias", "BucketName", "Name", "InstanceId", "VolumeId", "RDSInstance", "DBInstanceIdentifier", "FileSystemId", "FileSystemDNSName", "FileSystemOwnerId", "OwnerId", "RuleId", "RuleName", "BackupPlanArn", "BackupPlanId", "VersionId", "RequestId"
    - **GCP:** "Name", "Project", "VMName", "DiskName", "Id", "DiskEncryptionKey"
    - **Azure:** "SubscriptionId", "Subscription", "Tenant", "Name", "ResourceGroup", "VirtualMachineId", "PolicyId", "ProtectionPolicyName", "Id", "SourceResourceId", "ContainerName", "FriendlyName", "ServerName", "ParentName", "ProtectedItemDataSourceId", "StorageAccount", "Database", "Server", "ElasticPool", "ManagedInstance", "DatabaseID", "vmID"

- To customize anonymization:
    - Anonymize additional fields: `-AnonymizeFields "NewField1,NewField2"`
    - To not anonymize certain fields: `-NotAnonymizeFields "Name,Id"`
 
- A CSV file corresponding each anonymized key to value is outputted when you run any of the 3 scripts. Note this will not be contained in the ZIP file, and is only outside the ZIP file. This will help you correspond the numbers outputted to the resources, even if you choose to send anonymized data to Rubrik.

- The output log will also not be in the ZIP; the output log will be created outside the ZIP, and one can manually 'clean/sanitize' sensitive information from that log before sending it to one's Rubrik representative.

---

## FAQ

### How do I get started with AWS Organizations and AWS SSO?

For detailed instructions on setting up AWS Organizations and AWS SSO, refer to official AWS documentation.

### What IAM permissions are required for running the scripts?

Ensure the respective IAM permissions as outlined in the script prerequisites section for each cloud provider.

### How do I run the script with custom settings, such as using AWS SSO or querying certain regions?

One can read the detailed parameter list and how to interact with them in the documentation at the top of each script. There are also examples provided of how to use these parameters to customize your data query.

### How can I verify my current cloud context?

- **GCP:** 
    ```shell
    gcloud auth list
    gcloud config list
    ```
- **Azure:** 
    ```powershell
    Connect-AzAccount
    ```
- **AWS:** 
    ```powershell
    Set-AWSCredential -AccessKey 'YourAccessKey' -SecretKey 'YourSecretKey' -Region 'YourRegion'
    ```

For any further queries or issues, refer to the detailed documentation at the top of each script or contact your Rubrik representative.
