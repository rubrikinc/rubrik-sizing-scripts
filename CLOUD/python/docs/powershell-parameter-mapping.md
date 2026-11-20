# PowerShell to Python parameter mapping (task B5)

Maps every parameter of the PowerShell sizing scripts to the Python CLI flag that
covers it, or marks it missing with the task that closes the gap. It is the input for
flag aliases (see the task list) and for the README.

- PowerShell source: `Get-AWSSizingInfo.ps1`, `Get-AzureSizingInfo.ps1`, `Get-GCPSizingInfo.ps1`
  under `sizing_scripts/cloud/`.
- Python source: `aws/main.py`, `azure/main.py`, `gcp/main.py` (flags read from the argparse definitions).
- Status: **Same** = equivalent behavior, **Differs** = flag exists but behavior or name differs,
  **Missing** = no Python equivalent, **Python-only** = no PowerShell counterpart.
- Task IDs refer to the discovery parity task list. "No task" means the gap is not covered by any task yet.

## AWS

PowerShell parameter sets are mutually exclusive modes. Python has one flag per mode, and they
are mutually exclusive too: `--org`, `--sso`, `--cross-account-role`, `--all-profiles` and
`--profiles`; with none of them it scans the current credentials only.

### Modes and authentication

| PowerShell | Parameter set | Python | Status | Notes / task |
|---|---|---|---|---|
| `-DefaultProfile` | DefaultProfile (default) | no flag (current credentials) | Same | Default in both. |
| `-AllLocalProfiles` | AllLocalProfiles | `--all-profiles` | Same | Every profile boto3 finds in the credentials and config files. |
| `-UserSpecifiedProfileNames a,b` | UserSpecifiedProfiles | `--profiles a,b` | Same | A profile that does not exist is an error. Two profiles for one account give one result. |
| `-ProfileLocation path` | any | `--profile-location path` | Same | Sets the credentials file boto3 reads. |
| `-OrgCrossAccountRoleName name` (default `OrganizationAccountAccessRole`) | AWSOrganization | `--org` with `--role-name` or its alias `--org-role-name` (default `RubrikDiscoveryRole`) | Differs | The mode (`--org`) is separate from the role name. The default role name stays `RubrikDiscoveryRole`, the role the StackSet deploys; pass `--org-role-name OrganizationAccountAccessRole` for PowerShell's default. |
| `-CrossAccountRoleName name` with `-UserSpecifiedAccounts` | CrossAccountRole | `--cross-account-role name` with `--accounts` or `--accounts-file` | Same | Runs the org scan on the given accounts without calling Organizations (`--org --accounts ids --role-name name` is the same). The accounts are required. |
| `-SSOParameterSetName name` | AWSSSO | `--sso` with `--role-name` (permission set name) | Differs | Same meaning (permission set), different flag shape; required with `--sso`, as in PowerShell. Python uses the `aws sso login` token if one is cached, and otherwise signs in itself with the device flow like PowerShell (needs `--sso-start-url`). |
| `-SSOStartURL url` | AWSSSO | `--sso-start-url url` | Same | |
| `-SSORegion region` (default `us-east-1`) | AWSSSO | `--sso-region region` | Same | Default: the region of the cached login, else `us-east-1`. |
| `-UserSpecifiedAccounts a,b` | SSO, CrossAccountRole, Org | `--accounts a,b` | Same | Only honored with `--org` or `--sso`. Ignored in single-account mode. |
| `-UserSpecifiedAccountsFile file` | SSO, CrossAccountRole, Org | `--accounts-file file` | Same | One id per line; giving it together with `--accounts` is an error, as in PowerShell. |
| none | none | `--assume-role ROLE_ARN` | Python-only | Assume a role before scanning. |

### Scope and partition

| PowerShell | Python | Status | Notes / task |
|---|---|---|---|
| `-Regions a,b` | `--regions a,b` | Same | |
| none | `--exclude-regions a,b` | Python-only | |
| `-RegionToQuery region` | `--region-to-query region` | Same | Region for account-wide calls (STS, IAM, Organizations, Route53, the region list). Default `us-east-1`, `us-gov-east-1` in GovCloud. A GovCloud or China region also selects that partition (PowerShell leaves the partition unset then). |
| `-Partition GovCloud` | `--partition govcloud` | Same | Role ARNs and resource ARNs use `arn:aws-us-gov:`, Cost Explorer is skipped, and account-wide calls use the GovCloud query region. Not run against a real GovCloud account. |
| none | `--services a,b` | Python-only | Collector subset. |

### Skips and collection options

| PowerShell | Python | Status | Notes / task |
|---|---|---|---|
| `-SkipBackupCosts` | `--no-cost` | Differs | Python flag skips all Cost Explorer collection. PowerShell still writes header-only cost CSVs; contract and CSV output pending (AWS-9, A1). |
| `-SkipBackupCapacity` | `--no-backup-capacity` | Differs | Skips the native snapshot enumeration (RDS snapshots, EBS snapshots, AMIs); otherwise it runs whatever `--services` lists. AWS Backup recovery points, FSx, DynamoDB and Redshift backups are not collected yet (AWS-10). `--no-capacity` is not equivalent, see below. |
| `-BackupRecoveryPointTimeoutMinutes n` (default 60) | `--backup-recovery-point-timeout-minutes n` | Same | Per region; on expiry sizes are lower bounds and rows get `BackupEnumerationTruncated`. |
| `-SkipBucketTags` | `--skip-bucket-tags` | Same | |
| `-DebugBucketTags` | none | Not needed | PowerShell debug output of its tag handling. |
| none | `--no-capacity` | Python-only | Skips S3 per-bucket CloudWatch sizing and drops the S3 collector. Not the same as `-SkipBackupCapacity`. |

### Anonymization

| PowerShell | Python | Status | Notes / task |
|---|---|---|---|
| `-Anonymize` | `--anonymize` | Same | Applies to the CSV files. The zip has no raw JSON; the key file (`aws_anonymized_keys_to_actual_values-<stamp>.csv`) and the real log (`output_aws_not_anonymized_<stamp>.log`) are written beside the zip. The labels are numbered one after the other: PowerShell repeats labels from the 11th distinct value of a field on. |
| `-AnonymizeFields a,b` | `--anonymize-fields a,b` | Same | Same default field list as PowerShell. |
| `-NotAnonymizeFields a,b` (`Tags` keyword) | `--not-anonymize-fields a,b` | Same | |

### Consolidation and output names

| PowerShell | Python | Status | Notes |
|---|---|---|---|
| `consolidate.ps1 -directoryPath dir` | `python -m common.consolidate dir [--output-dir dir]` | Same | Combines `<prefix>-*.csv` files, including subfolders, into `<prefix>_combined.csv`. The order of columns that a later file adds is first-seen; PowerShell's changes between runs. |
| `aws_sizing_results_<yyyy-MM-dd_HHmmss>.zip` | same name, in the `--output` directory (default: the working directory for `--org`, `--sso` and profile modes) | Same | The CSV files and the zip share one timestamp. |
| `output_aws_<stamp>.log` in the zip | same name | Same | With `--anonymize` the zip holds a one-line note instead. |

### Python-only operational flags

`--output/-o` (PowerShell writes to the working directory), `--bucket`, `--bucket-region`,
`--workers`, `--verbose/-v`, `--no-csv` (JSON only; the PowerShell-style CSV files are written by default),
`--keep-artifacts` (single-account mode: PowerShell leaves its CSV files loose beside the zip, so Python
does the same only on request; by default only the zip is left, as with Azure and GCP),
`--no-preflight` (skips the pre-flight access check; see "Pre-flight access check" in `../CLAUDE.md`).

## Azure

| PowerShell | Parameter set | Python | Status | Notes / task |
|---|---|---|---|---|
| `-AllSubscriptions` | AllSubscriptions (default) | `--all`, or no scope flag | Same | Default is all enabled subscriptions the sign-in can read. |
| `-CurrentSubscription` | CurrentSubscription | `--current-subscription` | Same | Only the subscription of `az account show`. Before AZ-1 this was the default. |
| `-SubscriptionIds a,b` | SubscriptionIds | `--subs a,b` | Same | Python `--subs` takes IDs. |
| `-Subscriptions name,name` | Subscriptions | `--subscriptions name,name` | Same | Display names, ignoring case; a name that matches no enabled subscription is reported as not scanned. |
| `-ManagementGroups a,b` | ManagementGroups | `--management-groups a,b` | Same | Subscriptions under the group at any depth, read with the ARM `descendants` call (needs Reader on the group). Not run against a real tenant. |
| `-SkipAzureVMandManagedDisks` | | `--skip-vms`, `--skip-azure-vm-and-managed-disks` | Same | No prompt. The VM collector does not run and `azure_vmdisk_info` is not written. |
| `-SkipAzureSQLandMI` | | `--skip-sql-mi`, `--skip-azure-sql-and-mi` | Same | `azure_sql_info`, `azure_mi_sql_info` and `azure_mi_db_items` are not written. Flexible servers (Python only) are still collected. |
| `-SkipAzureStorageAccounts` | | `--skip-storage-accounts`, `--skip-azure-storage-accounts` | Same | Also skips file shares. `azure_storage_account_info` and `azure_file_share_info` are not written. |
| `-SkipAzureFiles` | | `--skip-files`, `--skip-azure-files` | Same | Storage accounts are still collected; shares are not listed. |
| `-SkipAzureBackup` | | `--skip-backup`, `--skip-azure-backup` | Same | Skips Recovery Services vaults, Backup Vaults, backup items, job history and the Backup cost query. `--no-backup-jobs` still skips only job history; `--no-cost` skips the cost scan. |
| `-SkipAKS` | | `--skip-aks` | Same | `azure_aks_info` is not written. |
| `-SkipAzureCosmosDB` | | `--skip-cosmos-db`, `--skip-azure-cosmos-db` | Same | `azure_cosmos_db` is not written. |
| `-SkipAzurePostgreSQL` | | `--skip-postgresql`, `--skip-azure-postgresql` | Same | `azure_postgres_info` is not written and the summary and totals leave the Postgres section out. MySQL flexible servers (Python only) are still collected. |
| `-GetContainerDetails` | | `--get-container-details` | Differs | Same file and sums. Python reads blobs with Entra ID (Storage Blob Data Reader), PowerShell with the account key (`listKeys`). A container whose blobs cannot be listed gets empty values (PowerShell repeats the previous container's), and the totals line sums the containers (PowerShell's always says 0). |
| `-GetKeyVaultAmounts` | | `--get-key-vault-amounts` | Same | `azure_key_vault`: a count that cannot be read is blank, as in PowerShell; the run summary also says why. |
| `-Anonymize` | | `--anonymize` | Same | Applies to the CSV files. The zip has no raw JSON; `azure_anonymized_keys_to_actual_values-<stamp>.csv` and `output_azure_not_anonymized_<stamp>.log` are written beside it. |
| `-AnonymizeFields a,b` | | `--anonymize-fields a,b` | Same | Same default field list as the script's code (30 fields; its help text lists fewer). |
| `-NotAnonymizeFields a,b` (`Tags` keyword) | | `--not-anonymize-fields a,b` | Same | |

Python-only: `--config`, `--regions`, `--cloud` (AzureCloud or AzureUSGovernment), `--output`,
`--mock`, `--dry-run`, `--manifest/--audit`, `--verbose`, `--devops-orgs`, `--no-devops`,
`--no-cost`, `--no-capacity`, `--no-security`, `--no-backup-jobs`, `--keep-artifacts`, `--no-preflight`,
`--no-csv` (JSON only; the PowerShell-style CSV files are written by default).

## GCP

Python rows describe the integration branch after GCP-1 (#2697) lands. Before that,
Python has `--projects` and `--all` only, and defaults to the current project.

| PowerShell | Parameter set | Python | Status | Notes / task |
|---|---|---|---|---|
| `-GetAllProjects` | GetAllProjects (default) | default, or `--all` | Same after GCP-1 | GCP-1 |
| `-Projects a,b` | Projects | `--projects a,b` | Same | |
| `-ProjectFile file` | ProjectFile | `--project-file file` | Same after GCP-1 | GCP-1 |
| `-Anonymize` | | `--anonymize` | Same | Applies to the CSV files. The zip has no raw JSON; `gcp_anonymized_keys_to_actual_values-<stamp>.csv` and `output_gcp_not_anonymized_<stamp>.log` are written beside it. |
| `-AnonymizeFields a,b` | | `--anonymize-fields a,b` | Same | The script's 11 default fields: `Name`, `Project`, `VMName`, `DiskName`, `Id`, `DiskEncryptionKey`, `InstanceName`, `DisplayName`, and `DatasetId`, `TableId`, `ExternalSourceUri` for BigQuery (master's script; the older script has the first 8). |
| `-NotAnonymizeFields a,b` (`Tags` keyword) | | `--not-anonymize-fields a,b` | Same | `Tags` leaves the `Label/Tag:` columns alone. |
| `-SkipBigQuery` (master's script) | | `--collectors` without `bigquery` | Differs | PowerShell still writes `gce_bigquery_info`, empty. Python writes it empty too, and also does not call the BigQuery API. |

Python-only: `--config`, `--regions`, `--workers`, `--org`, `--folder`, `--output`, `--mock`,
`--dry-run`, `--security`, `--collectors`, `--inventory-only`, `--verbose`, `--no-preflight`,
`--no-sdk-check`, `--yes`, `--current-project` (added by GCP-1) and `--no-csv` (JSON only; the PowerShell-style CSV files are written by
default).

## Cross-cutting differences

- **Anonymization** is in all three Python tools now.
- **Skip flags are named differently.** PowerShell uses `-Skip<Service>`; Python uses `--no-<thing>`
  with different granularity (AWS). The Azure `-Skip*` switches are mapped by `--skip-*` flags, each
  with a PowerShell-style alias.
- **Mode flags differ in shape.** PowerShell selects a mode by which parameter you pass
  (parameter sets); Python selects it with `--org`, `--sso` or `--all`. Any alias layer needs to
  translate the PowerShell shape (for example `-CrossAccountRoleName`) into the Python flags.
- **Output location.** PowerShell writes to the working directory; Python takes `--output`.
- **Unmapped PowerShell parameter without a task:** `-DebugBucketTags` (AWS), a debug aid that is not needed.
