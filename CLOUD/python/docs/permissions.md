# Permissions

What each tool reads, and what you lose without it. The access check (see `user-guide.md`) tests these before the scan and
prints the same table, so you can run it first and see exactly what your sign-in lacks. Nothing here needs write access.

The tables list the permission each check needs and the output files it fills. A permission that is missing leaves those
files empty or partial; the rest of the scan still runs.

## AWS

Every check is a read call in each region being scanned (`ec2:DescribeInstances`, and so on), except the account-wide ones
(`iam:GetAccountSummary`, `s3:ListAllMyBuckets`, `route53:ListHostedZones`, `ce:GetCostAndUsage`).
`ce:GetCostAndUsage` is one request per account, and AWS bills Cost Explorer requests; `--no-cost` skips it.

A scan of several accounts first has to get into each one: `sts:AssumeRole` on the role in each account (`--org`,
`--cross-account-role`), the permission set assigned to you in each account (`--sso`), or working profile credentials. An
account it cannot enter has a `sign in` row in the pre-flight CSV; `--preflight-only` checks this for every account
without scanning.

| Permission | Needed to read | Output it fills |
|------------|----------------|-----------------|
| `iam:GetAccountSummary` | iam account summary | `aws_iam_info` |
| `s3:ListAllMyBuckets` | s3 buckets | `aws_s3_info` |
| `route53:ListHostedZones` | route53 hosted zones | `aws_route53_info` |
| `ce:GetCostAndUsage` | cost explorer | `aws_backup_costs`, `aws_snapshot_storage_costs` |
| `ec2:DescribeInstances` | ec2 instances | `aws_ec2_instance_info`, `aws_ec2_attached_volume_info` |
| `ec2:DescribeVolumes` | ec2 volumes | `aws_ec2_attached_volume_info`, `aws_ec2_unattached_volume_info` |
| `rds:DescribeDBInstances` | rds instances | `aws_rds_info` |
| `dynamodb:ListTables` | dynamodb tables | `aws_DynamoDB_info` |
| `elasticfilesystem:DescribeFileSystems` | efs file systems | `aws_efs_info` |
| `fsx:DescribeFileSystems` | fsx file systems | `aws_fsx_filesystem_info` |
| `fsx:DescribeVolumes` | fsx volumes | `aws_fsx_volume_info` |
| `kms:ListKeys` | kms keys | `aws_kms_numbers` |
| `secretsmanager:ListSecrets` | secrets manager secrets | `aws_secrets_numbers` |
| `sqs:ListQueues` | sqs queues | `aws_sqs_numbers` |
| `ec2:DescribeVpcs` | vpcs | `aws_vpc_info` |
| `elasticloadbalancing:DescribeLoadBalancers` | load balancers | `aws_lb_info` |
| `elasticloadbalancing:DescribeLoadBalancers` | classic load balancers | `aws_lb_info` |
| `eks:ListClusters` | eks clusters | `aws_eks_clusters_info`, `aws_eks_nodegroups_info` |
| `redshift:DescribeClusters` | redshift clusters | `aws_redshift_info` |
| `backup:ListBackupPlans` | backup plans | `BackupPlans and InBackupPlan columns` |
| `backup:ListBackupVaults` | backup vaults | `aws_backup_recovery_points` |
| `backup:ListProtectedResources` | backup protected resources | `backup protection columns` |
| `rds:DescribeDBSnapshots` | rds snapshots | `aws_rds_snapshot_info` |
| `ec2:DescribeSnapshots` | ebs snapshots | `aws_ebs_and_ami_info` |
| `ec2:DescribeImages` | machine images | `aws_ebs_and_ami_info` |
| `glue:GetDatabases` | glue databases | `aws_glue_iceberg_info` |
| `glue:GetTables` | glue tables | `aws_glue_iceberg_info` |
| `glue:GetTags` | glue table tags | `aws_glue_iceberg_info` |
| `s3tables:ListTableBuckets` | s3 table buckets | `aws_s3_tables_info` |
| `s3tables:ListTables` | s3 tables | `aws_s3_tables_info` |
| `s3tables:GetTable` | s3 table details | `aws_s3_tables_info` |
| `s3tables:GetTableMetadataLocation` | s3 table metadata location | `aws_s3_tables_info` |
| `s3tables:GetTableMaintenanceConfiguration` | s3 table maintenance settings | `aws_s3_tables_info` |
| `s3:GetObject` | s3 table metadata file | `aws_s3_tables_info` |
| `cloudformation:ListStacks` | cloudformation stacks | `iac_summary in the JSON` |
| `cloudwatch:GetMetricStatistics` | cloudwatch capacity metrics | `aws_s3_info`, `aws_rds_info`, `aws_fsx_filesystem_info`, `aws_fsx_volume_info` |

A region blocked by a service control policy, or not enabled for the account, shows as one row, `all services in region`.

**Per-table calls (S3 Tables and Glue).** The calls that read one table need a table's name, so the access check tries them
on the first table the listing finds: the first table bucket, then its first table (`s3 tables`), then that table's
details, metadata location and maintenance settings, and its metadata file; and the first Glue database, its first table
(`glue tables`) and that table's tags. They show whether the scan can read the flags, the sizes and the tags, not only
whether it can list. Where the listing finds nothing there is nothing to try and these rows are left out, not reported as
granted. Only the first bucket and database are tried, so a first bucket with no tables hides the tables of the others.
The metadata file is read with `s3:GetObject`, the action AWS documents for that call. PowerShell's policy also lists
`s3tables:GetTableData`; which of the two S3 Tables enforces for its managed bucket has not been verified.

For a scan of a whole organization, `aws/iac/` has the CloudFormation template for the role it uses (the spoke role
that `--org` deploys as a StackSet); read it for the exact permissions it grants.

## Azure

The Reader role covers all of these. Reading storage capacity needs Monitoring Reader (Reader includes it), and reading cost
needs Cost Management Reader. The names are the operation names Azure documents; they have not been checked against a
live tenant.

Each subscription named with `--subs` is read first (`Microsoft.Resources/subscriptions/read`); one that cannot be read is
left out and gets a `subscription` row in the pre-flight CSV. `--preflight-only` runs this and the checks below without
collecting anything.

| Permission | Needed to read | Output it fills |
|------------|----------------|-----------------|
| `Microsoft.Compute/virtualMachines/read` | virtual machines | `azure_vmdisk_info`, `azure_sizing_summary` |
| `Microsoft.Compute/disks/read` | managed disks | `azure_vmdisk_info` |
| `Microsoft.Compute/snapshots/read` | disk snapshots | `azure_vmdisk_info` |
| `Microsoft.Storage/storageAccounts/read` | storage accounts | `azure_storage_account_info`, `azure_file_share_info` |
| `Microsoft.Insights/Metrics/Read` | storage metrics (capacity) | `azure_storage_account_info` |
| `Microsoft.Sql/servers/read` | sql servers | `azure_sql_info` |
| `Microsoft.Sql/managedInstances/read` | sql managed instances | `azure_mi_sql_info` |
| `Microsoft.DBforPostgreSQL/flexibleServers/read` | postgresql flexible servers | `azure_postgres_info`, `azure_sizing_summary` |
| `Microsoft.DBforMySQL/flexibleServers/read` | mysql flexible servers | `azure_sizing_summary` |
| `Microsoft.RecoveryServices/vaults/read` | backup vaults | `azure_backup_vault_info`, `azure_sizing_summary` |
| `Microsoft.DataProtection/backupVaults/read` | data protection backup vaults | `azure_backup_data_protection_vaults`, `azure_backup_data_protection_policies`, `azure_backup_data_protection_items`, `azure_storage_account_info`, `azure_postgres_info` |
| `Microsoft.CostManagement/dimensions/read` | cost management | `azure_backup_costs`, `azure_sizing_summary` |
| `Microsoft.Resources/subscriptions/resources/read` | aks clusters | `azure_aks_info` |
| `Microsoft.Resources/subscriptions/resources/read` | cosmos db accounts | `azure_cosmos_db` |
| `Microsoft.Resources/subscriptions/tagNames/read` | tag names | `azure_vmdisk_info`, `azure_storage_account_info`, `azure_sql_info`, `azure_mi_sql_info`, `azure_aks_info`, `azure_cosmos_db` |
| `Microsoft.Security/pricings/read` | microsoft defender | `security posture in the JSON` |
| `Microsoft.Purview/accounts/read` | microsoft purview | `Purview accounts in the JSON` |
| `Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read` | blob containers | `azure_storage_account_container_info` |
| `Microsoft.KeyVault/vaults/read` | key vaults | `azure_key_vault` |
| `Microsoft.KeyVault/vaults/certificates/read` | key vault contents | `azure_key_vault` |

The last three are checked and used only with `--get-container-details` and `--get-key-vault-amounts`, and they are
outside Reader: blob listing is a data role (Storage Blob Data Reader), and counting a vault's certificates, secrets and
keys needs Key Vault Reader, or the List permission in the vault's access policies. PowerShell's `-GetContainerDetails`
reads blobs with the storage account key instead, which needs `listKeys` (for example Reader and Data Access).

## GCP

The Viewer role on a project covers the read permissions below except where noted. The tool's own messages name the roles
`roles/cloudasset.viewer` (asset inventory), `roles/compute.viewer`, `roles/storage.objectViewer`, and, for `--security`,
`roles/securitycenter.findingsViewer` at organization level. The names are the permissions Google documents; they have not
been checked against a live project.

Each project named with `--projects` or `--project-file` is read first (`resourcemanager.projects.get`); one that cannot be
read is left out and gets a `project` row in the pre-flight CSV. `--preflight-only` runs this and the checks below without
collecting anything.

| Permission | Needed to read | Output it fills |
|------------|----------------|-----------------|
| `cloudasset.assets.listResource` | cloud asset inventory | `asset inventory in the JSON` |
| `compute.instances.list` | compute instances | `gce_vm_info`, `gce_attached_disk_info` |
| `compute.disks.list` | compute disks | `gce_attached_disk_info`, `gce_unattached_disk_info` |
| `storage.buckets.list` | cloud storage buckets | `Cloud Storage buckets in the JSON` |
| `cloudsql.instances.list` | cloud sql instances | `gce_cloudsql_info` |
| `spanner.instances.list` | spanner instances | `gce_spanner_info` |
| `alloydb.clusters.list` | alloydb clusters | `AlloyDB clusters in the JSON` |
| `bigtable.instances.list` | bigtable instances | `Bigtable instances in the JSON` |
| `bigquery.datasets.get` | bigquery datasets | `gce_bigquery_info` |
| `backupdr.backupPlans.list` | backup and dr plans | `gce_vm_info` |
| `backupdr.backupPlanAssociations.list` | backup and dr associations | `gce_vm_info` |

Google charges every call to the quota project of your sign-in, which the access check prints first. Besides these
permissions in the scanned projects, the sign-in needs `serviceusage.services.use` in the quota project (Service Usage
Consumer), and some APIs (Spanner, Bigtable, Cloud Asset) must be on there, with billing on for those that need it. When
the quota project refuses a call, the row is `could not be checked` (`Detail` starting with `QuotaProject`) in every
project, and the problem is reported once: see `troubleshooting.md#gcp-api-disabled-in-billing-project`,
`troubleshooting.md#gcp-quota-project-billing-disabled` and `troubleshooting.md#gcp-quota-project-denied`. A row that is
`not enabled` means the API or billing is off in the scanned project itself.
