# Cloud Sizing Scripts — CLAUDE.md

## Overview

Pre-sales cloud sizing toolkit that collects inventory and capacity metadata
from **AWS**, **Azure**, and **GCP** customer environments. Sales engineers run
these PowerShell scripts on customer clouds to gather sizing data for Rubrik
solution pricing and capacity planning.

- **Owner:** Sizing Engineering (`SIZENG` / `Cloud sizing script`)
- **Language:** PowerShell 7+
- **Architecture:** Single self-contained script per cloud provider — no shared
  libraries between them

## Code Map

| File | Lines | Purpose |
|------|-------|---------|
| `Get-AWSSizingInfo.ps1` | ~5,800 | AWS sizing — EC2, S3, S3 Tables, RDS, EFS, FSx, DynamoDB, EKS, VPC, Load Balancers, Route53, IAM, Backup, KMS, SQS, Secrets Manager |
| `Get-AzureSizingInfo.ps1` | ~2,700 | Azure sizing — VMs, Managed Disks, SQL, Storage, Files, Backup Vaults, AKS, CosmosDB, Key Vault |
| `Get-GCPSizingInfo.ps1` | ~900 | GCP sizing — GCE VMs, Disks, Cloud SQL, Spanner |
| `consolidate.ps1` | | Merges multi-region CSV outputs into single files |
| `Get-AWSSizingInfo-Permissions.cft` | | CloudFormation template for cross-account IAM role |
| `EXAMPLES/` | | Sample output CSV/JSON files |
| `README.md` | | User-facing usage guide — keep in sync with this CLAUDE.md |
| `../tests/cloud/` | | Pester tests for AWS, Azure, and GCP scripts |

## How It Works

Each script follows the same pattern:

1. **Authenticate** with the cloud provider (multiple auth modes per script)
2. **Iterate** through regions / subscriptions / projects
3. **Collect** resource metadata via cloud SDK cmdlets
4. **Aggregate** totals and sizing calculations (GiB/TiB/GB/TB)
5. **Export** to timestamped CSVs + JSON, with optional anonymization
6. **Compress** all outputs into a ZIP archive (final deliverable)

### AWS Authentication Modes

| Parameter Set | Description |
|---------------|-------------|
| `DefaultProfile` | Local AWS credentials (default) |
| `AllLocalProfiles` | All profiles in `~/.aws/config` |
| `UserSpecifiedProfiles` | Named comma-separated profile list |
| `CrossAccountRole` | Assume role across multiple accounts |
| `AWSOrganization` | Auto-discover accounts via AWS Org |
| `AWSSSO` | AWS SSO with browser-based device code flow |

### Azure Authentication Modes

| Parameter Set | Description |
|---------------|-------------|
| `AllSubscriptions` | All accessible subscriptions (default) |
| `CurrentSubscription` | Current subscription only |
| `Subscriptions` | Named subscription list |
| `SubscriptionIds` | Comma-separated subscription IDs |
| `ManagementGroups` | Azure Management Groups |

Azure also supports skip flags: `-SkipAzureVMandManagedDisks`, `-SkipAzureSQLandMI`,
`-SkipAzureStorageAccounts`, `-SkipAzureFiles`, `-SkipAzureBackup`, `-SkipAKS`

### GCP Authentication Modes

| Parameter Set | Description |
|---------------|-------------|
| `GetAllProjects` | Auto-discover all accessible projects (default) |
| `Projects` | Comma-separated project IDs |
| `ProjectFile` | File with newline-separated project IDs |

## Key Functions

Each script has an orchestrator, workload collector functions, and shared utilities.

**Workload collectors** follow a naming convention: `Get-<Provider><Service>Inventory`
(e.g., `Get-AWSEC2Inventory`, `Get-AzureSQLInventory`, `Get-GCEInstancesAndDisks`).
Each collector handles one service, returns its results to the orchestrator, and is
independently testable.

### Orchestrators

| Script | Function | Purpose |
|--------|----------|---------|
| AWS | `getAWSData($cred)` | Loops regions, calls all AWS service collectors |
| Azure | main script body | Loops subscriptions, calls all Azure service collectors |
| GCP | main script body | Loops projects, calls all GCP service collectors |

### Shared Utilities (present in all three scripts)

| Function | Purpose |
|----------|---------|
| `Add-TagsToAllObjectsInList($list)` | Normalizes CSV schema (adds null columns for missing tags) |
| `ConvertTo-SizeUnits(...)` | Converts sizes between Bytes/GiB and GiB/TiB/GB/TB |
| `Compress-SizingArchive(...)` | Creates ZIP archive and removes original files |
| `Invoke-Anonymization($DataObject)` | Recursively redacts account IDs, ARNs, resource names, tags |
| `Invoke-CollectionAnonymization($Collection)` | Applies anonymization across a collection |

### AWS-specific Utilities

| Function | Purpose |
|----------|---------|
| `Get-CWMetricStatisticsForAllVersion()` | Adapts CloudWatch API v4/v5 parameter differences at runtime |
| `Get-AWSStorageLensConfigs(...)` | Account-level Storage Lens configuration discovery |

### Azure-specific Utilities

| Function | Purpose |
|----------|---------|
| `GenerateVMKey()` | Stable unique identifier for VM across subscriptions |

## Output Files

All scripts produce timestamped CSVs and a compressed ZIP archive.

**AWS:** `aws_ec2_instance_info-*.csv`, `aws_s3_info-*.csv`, `aws_s3_tables_info-*.csv`, `aws_rds_info-*.csv`,
`aws_efs_info-*.csv`, `aws_fsx_*_info-*.csv`, `aws_DynamoDB_info-*.csv`,
`aws_eks_*_info-*.csv`, `aws_vpc_info-*.csv`, `aws_lb_info-*.csv`,
`aws_route53_info-*.csv`, `aws_iam_info-*.csv`, `aws_backup_costs-*.csv`,
`aws_backup_recovery_points-*.csv`, `aws_ebs_and_ami_info-*.csv`,
`aws_rds_snapshot_info-*.csv`, `aws_redshift_info-*.csv`,
`aws_snapshot_storage_costs-*.csv`, `aws-backup-plans-info-*.json`,
`aws_sizing_results_*.zip`

**Azure:** `azure_vmdisk_info-*.csv`, `azure_sql_info-*.csv`,
`azure_file_share_info-*.csv`, `azure_backup_vault_*-*.csv`,
`azure_sizing_summary-*.csv`, ZIP archive

**GCP:** `gce_vmdisk_info-*.csv`, ZIP archive

## Anonymization

All three scripts support `-Anonymize` flag which redacts sensitive fields
(account IDs, resource names, ARNs, tags) before export. Used when customers
cannot share identifiable infrastructure data.

## Testing

### Test structure

```
tests/
├── Dockerfile                        # Test container with Pester + cloud modules
├── Invoke-PesterWithCoverage.ps1     # Coverage report generator
└── cloud/
    ├── Get-AWSSizingInfo.Tests.ps1   # Pester tests for AWS
    └── Get-GCPSizingInfo.Tests.ps1   # Pester tests for GCP
```

### Running tests

```bash
cd sizing/sizing_scripts

# Unit tests (default — no cloud credentials needed)
./run_sizing_scripts_tests ut

# E2E tests (requires cloud credentials)
./run_sizing_scripts_tests e2e

# Both
./run_sizing_scripts_tests all

# Specific PowerShell version
./run_sizing_scripts_tests ut --ps-version 7.4.5
```

Tests run in Docker. Stub functions replace cloud cmdlets to prevent real API
calls. Coverage report: `coverage/coverage.xml`.

### Test pattern

Each test file provides **global stub functions** for cloud cmdlets, then uses
Pester `Mock` on those stubs to verify sizing script logic (CSV output, schema
normalization, anonymization, metric calculations, error handling).

## Common Gotchas

1. **CloudWatch v4 vs v5:** `AWS.Tools.CloudWatch` v4 uses `-UtcStartTime`/`-UtcEndTime`, v5 uses `-StartTime`/`-EndTime`. The script auto-detects via `Get-CWMetricStatisticsForAllVersion()` — do not hardcode either variant
2. **S3 Storage Lens lag:** CurrentVersionStorageBytes metrics require a Storage Lens dashboard with CloudWatch publishing enabled, and take 24–48 hours to populate
3. **Azure network ACLs:** Storage account calls may fail with `not authorized` if the storage account has network rules restricting access. The script continues with other resources
4. **Region SCP blocks (AWS):** Service Control Policies may block API calls in certain regions. Use `-Regions` to limit to allowed regions
5. **AWS SSO region:** `Invalid grant provided` usually means wrong `-SSORegion`. Check AWS Console → SSO settings for the correct region
6. **No shared code:** Each cloud script is fully self-contained. Changes to one do not affect the others
7. **GCP interactive prompts:** `gcloud` prompts to enable disabled APIs when running in an interactive TTY. The GCP script sets `$env:CLOUDSDK_CORE_DISABLE_PROMPTS = 1` at startup to prevent this. It also proactively checks which APIs are enabled per project and logs yellow warnings for disabled ones, skipping those service blocks entirely

## Dependencies

**PowerShell 7.0+** required (cross-platform).

| Provider | Required Modules |
|----------|-----------------|
| AWS | `AWS.Tools.Common`, `.EC2`, `.S3`, `.RDS`, `.SecurityToken`, `.Organizations`, `.IdentityManagement`, `.CloudWatch`, `.ElasticFileSystem`, `.ElasticLoadBalancing`, `.ElasticLoadBalancingV2`, `.SSO`, `.SSOOIDC`, `.FSX`, `.Backup`, `.CostExplorer`, `.DynamoDBv2`, `.Route53`, `.SQS`, `.SecretsManager`, `.KeyManagementService`, `.EKS`, `.S3Control`, `.S3Tables`, `.Redshift` |
| Azure | `Az.Accounts`, `Az.Aks`, `Az.Compute`, `Az.Storage`, `Az.Sql`, `Az.SqlVirtualMachine`, `Az.ResourceGraph`, `Az.Monitor`, `Az.Resources`, `Az.RecoveryServices`, `Az.CostManagement`, `Az.CosmosDB` |
| GCP | `GoogleCloud` |

## Quick Reference

```powershell
# AWS — default profile, all regions
./Get-AWSSizingInfo.ps1

# AWS — specific profiles + regions + anonymize
./Get-AWSSizingInfo.ps1 -UserSpecifiedProfileNames "prod,staging" -Regions "us-east-1,us-west-2" -Anonymize

# AWS — org-wide with cross-account role
./Get-AWSSizingInfo.ps1 -OrgCrossAccountRoleName OrganizationAccountAccessRole

# Azure — all subscriptions
./Get-AzureSizingInfo.ps1

# Azure — skip heavy services
./Get-AzureSizingInfo.ps1 -SkipAzureBackup -SkipAKS

# GCP — all projects
./Get-GCPSizingInfo.ps1

# Consolidate multi-region outputs
./consolidate.ps1 -directoryPath "./output_directory"
```
