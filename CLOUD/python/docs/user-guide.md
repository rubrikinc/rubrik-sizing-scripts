# User guide

How to run a scan from start to finish, read what it prints, and use what it writes.

## 1. Before you start

- **Python**: 3.9 or newer for AWS, 3.10 or newer for Azure and GCP.
- **A way to sign in**: the AWS CLI, the Azure CLI (`az`), or the Google Cloud CLI (`gcloud`).
- **git** and network access to GitHub, unless you already have a checkout.
- **Read access** to what you want counted. `permissions.md` lists exactly what each tool reads and what you lose without
  it. You do not need all of it: the access check tells you what is missing before the scan starts.

## 2. Get the code

Either let a generated run script do it (it clones a small sparse checkout, about 4 MB, after asking), or clone yourself
and keep to the branch your team uses. Update an old checkout with `git pull --ff-only`. The generated scripts never
update a checkout. The AWS script prints the commit it is running and warns, asking whether to go on, if the checkout is
behind; the Azure and GCP scripts do not check yet, so pull first.

## 3. Install

```
cd aws
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Use the folder of the cloud you are scanning. The AWS requirements include `botocore[crt]`, which a session made with
`aws login` needs. A sign-in problem at the start of an AWS run (expired session, no credentials, rejected keys, an unknown
profile) ends with a short message and exit code 1 instead of a traceback; `troubleshooting.md` has the fix for each.
Azure's `requirements.txt` includes the packages of every collector, Azure Backup Vaults (Blob and PostgreSQL backup),
Microsoft Defender and Microsoft Purview included. An environment missing one of them still runs: the run says so, and
without the Backup Vault package the three Backup Vault files are not written and the Blob and PostgreSQL backup flags
stay `-` and `False`. Run `pip install -r requirements.txt` in the `azure` folder, with the tool's virtual environment
active, to add what is missing.

## 4. Sign in and choose what to scan

### AWS

The default is one account: the one your current credentials belong to (`AWS_PROFILE` picks a profile).

| To scan | Use |
|---------|-----|
| the current account | no scope option |
| every account of an organization | `--org` (assumes a role in each account; see `--role-name`) |
| accounts through IAM Identity Center | `--sso --sso-start-url URL --role-name PERMISSION_SET` |
| specific accounts | `--accounts ID,ID` or `--accounts-file FILE`, with `--cross-account-role ROLE` or `--sso` |
| local profiles | `--profiles a,b` or `--all-profiles` |
| through a role first | `--assume-role ARN` |
| GovCloud | `--partition govcloud` |

Narrow it with `--regions`, `--exclude-regions` and `--services`. A scan of several accounts runs a few at a time
(`--workers`) and keeps each finished account in an `aws-sizing-progress-*` folder, so running the same command again in
the same folder carries on where it stopped.

### Azure

Sign in with `az login`. The tool uses that sign-in (it tries the other methods the Azure SDK knows first, then the CLI).

| To scan | Use |
|---------|-----|
| the subscription of your current `az` login | no scope option |
| specific subscriptions | `--subs ID,ID` |
| every enabled subscription the sign-in can read | `--all` |
| a government cloud | `--cloud AzureUSGovernment` (sign in to that cloud first) |

The subscription shown by `az account show` is not necessarily the one `--subs` scans. The sign-in must be able to read
each subscription asked for, in the tenant the CLI is set to: if a subscription is in another tenant, run
`az account set --subscription ID` or `az login --tenant TENANT_ID`.

### GCP

Sign in with `gcloud auth application-default login`, or point `GOOGLE_APPLICATION_CREDENTIALS` at a service account key.

| To scan | Use |
|---------|-----|
| every project the sign-in can see | no scope option (or `--all`) |
| specific projects | `--projects ID,ID` or `--project-file FILE` |
| only the current gcloud project | `--current-project` |
| the assets of many projects in one sweep instead of one call per project | add `--org ID` or `--folder ID` |
| Google's own `sys-<number>` projects as well | add `--include-system-projects` |

Scanning every project leaves out the `sys-<number>` projects Google creates itself (for Apps Script and Workspace
features). They have no billing account and normally no API enabled, so there is nothing in them to size. The run says
how many it left out. A project you name with `--projects` or `--project-file` is always scanned.

The run starts with who it runs as and what it will scan:

```
Signed in as: you@example.com
Scope: the 12 project(s) you named with --projects or --project-file; 12 readable and scanned.
       WARNING: this login can also see 38 other active project(s) not in the scan (...). Pass --all to scan every
project it can see.
```

Google lists only the projects your login may read, and says nothing about the others. A project missing from an "all
projects" scan is therefore either not in the estate or not readable by this login; the run cannot tell which. If a
project you expect is missing, check what the login has on it, for example with
`gcloud policy-troubleshoot iam //cloudresourcemanager.googleapis.com/projects/PROJECT_ID --principal-email=ACCOUNT
--permission=resourcemanager.projects.get`, and grant a role such as Viewer (or Browser on the folder or organization).
`Signed in as: unknown` means the login does not name itself; run `gcloud auth application-default print-access-token`
to see which login it is. `--org` and `--folder` do not change which projects are scanned, only how their assets are
counted. The scope is also recorded in `manifest.json` as counts (no project names or account), so it survives an
anonymized run.

Google charges each call to a project (your gcloud current project, or the quota project of your login), and an API that
is off in that project fails for every project scanned. If an error says an API "has not been used in project X", X is
that project; see the troubleshooting page.

## 5. Run

```
python main.py --output ./output
```

with the scope options from the section above. Useful extras for every tool:

- `--anonymize` replaces names, IDs and tags in the CSV files (section 8).
- `--no-preflight` skips the access check.
- `--no-csv` writes only the JSON.
- `--keep-artifacts` (AWS and Azure) also leaves the loose files beside the zip.

A generated run script runs the same command after checking who you are signed in as and asking `Continue? [y/N]`.

## 6. Reading the screen

A run shows, in order:

1. **A banner** with the scope (the accounts, subscriptions or projects, and the regions).
2. **Questions about optional scans** on a terminal. AWS asks whether to scan cost. Azure asks about cost, storage
   capacity (Azure Monitor), security posture (Microsoft Defender) and backup job history. GCP asks nothing. Each question
   has a flag that answers it for you (`--no-cost`, `--no-capacity`, `--no-security`, `--no-backup-jobs`); a scan that
   cannot run, such as Defender without its package, is not offered. When the input is not a terminal nothing is asked
   and every scan not turned off by a flag runs.
3. **The access check** (below).
4. **Progress** as each account, subscription or project is collected, with warnings as they happen.
5. **A summary table** of what was found (GCP), and **the totals block** (all three tools): counts and sizes per
   resource type, worded and calculated as the PowerShell script does.
   - AWS: EC2, volumes, RDS, EFS, FSx, DynamoDB, S3 by storage type, S3 Tables, and the backup cost summary when cost
     was scanned.
   - Azure: VMs and disks, SQL databases, pools and managed instances, storage accounts, file shares, Backup vaults,
     Cosmos DB and AKS. A section is left out when its collector was skipped.
   - GCP: VMs, attached and unattached disks, disk capacity, Cloud SQL, Spanner and BigQuery.

   It is built from the same rows as the CSV files, holds no names, and is in the log.
6. **The run summary**: each distinct problem once, with its count and what to do.

### The access check

The check makes one read-only call per service it will use, in each account (and region), subscription or project. It
prints a headline and a table, the missing rows first:

| Column | Meaning |
|--------|---------|
| `SERVICE` | what was checked (for example `rds instances`) |
| `PERMISSION` | the permission the call needs, in the cloud's own words |
| `ACCESS` | `granted`; `MISSING` (denied); `API NOT ENABLED`; `NOT CHECKED` (the call failed for another reason, or, GCP, the quota project refused it, so nothing is known about the project); `not requested` (the run is not collecting it) |
| `WHERE` | how many regions or projects it is missing in, and the first two |
| `FOUND` | whether the call saw any resource: `yes`, `yes (2 of 17)`, `none`, or `-` when the call cannot say |
| `IMPACT` | the output files a missing permission leaves empty or partial; for `NOT CHECKED`, `unknown` and the error code |

A missing permission does not stop the scan; it tells you what the numbers will lack. Under the table, `Problems found by
the pre-flight check` gives the error as the cloud worded it and what to do. A scan of many accounts or subscriptions
prints the full table only for those with something blocked.

The same rows are written to `<cloud>_preflight_check-<timestamp>.csv` in the zip (columns: Owner, OwnerName, Scope,
Service, Permission, Access, Outcome, ResourcesFound, Detail, OutputFilesAffected). The CSV holds only the short error
code, never the cloud's message, because messages can name accounts and resources.

### Access to each account (AWS, several accounts)

A scan of several accounts (`--org`, `--sso`, `--cross-account-role`, `--profiles`, `--all-profiles`) accounts for every
account in the pre-flight CSV, scanned or not:

- An account the scan could not sign in to has one row with `Service` `sign in`, the permission signing in needs
  (`sts:AssumeRole` for `--org` and `--cross-account-role`, `sso:GetRoleCredentials` for `--sso`,
  `sts:GetCallerIdentity` for profiles), `Access` `access denied` or `could not be checked`, and the AWS error code in
  `Detail`.
- An account whose scan stopped on an error has one row with `Service` `scan` and the error code.
- An account held back by a service control policy keeps its access-check rows, though its results are left out of the
  zip so that the next run scans it again.

The closing box lists the accounts that were not scanned and why, for example
`ACCOUNT_ID (prod)  sign in: AccessDenied` (the first 20; the CSV has every one).

To see this for every account before a full scan, add `--preflight-only`. It signs in to each account, runs only the
access check and writes `aws_access_check_<timestamp>.zip` with the pre-flight CSV and the log. Nothing is collected, and
it neither uses nor changes an `aws-sizing-progress-*` folder, so it cannot affect a later resume. It also works for the
current account alone. Unless you add `--no-cost`, the check makes its one billed Cost Explorer request per account.

### Access to each subscription or project (Azure, GCP)

Azure and GCP run the access check for every subscription or project before they collect anything, so the pre-flight CSV
already has rows for each one in scope. On top of that:

- A subscription named with `--subs`, or a project named with `--projects` or `--project-file`, that the sign-in cannot
  read gets one row: `Service` `subscription` with `Permission` `Microsoft.Resources/subscriptions/read` (Azure), or
  `Service` `project` with `Permission` `resourcemanager.projects.get` (GCP), `Access` `access denied`, and the error
  code in `Detail` (for example `AuthorizationFailed`, `SubscriptionNotFound` or `PermissionDenied`). Azure and Google
  answer an ID that does not exist and one you may not read the same way, so a typo looks like a denial.
- A subscription whose scan stopped on an error (Azure), or a project whose collection stopped as a whole (GCP), keeps
  its access-check rows and gets one row with `Service` `scan` and the error code.

The end of the run lists them, for example `SUBSCRIPTION_ID  cannot read the subscription: AuthorizationFailed` (the first
20; the CSV has every one). If none of the IDs you named can be read, the run still stops with
`No accessible subscriptions found` or `No accessible projects found`, and the screen lists each ID and why.

With `--all` (Azure) or no scope option (GCP) the tool can only list the subscriptions or projects your sign-in can see,
so one you have no access to at all is not reported: it never appears in the list. Name the IDs with `--subs` or
`--projects` to have each one checked.

To check access without scanning, add `--preflight-only`: it resolves the scope, runs only the access check and writes
`azure_access_check_<timestamp>.zip` or `gcp_access_check_<timestamp>.zip` with the pre-flight CSV and the log. Nothing is
collected. It cannot be combined with `--no-preflight`, `--no-csv`, `--dry-run` or `--mock`.

### The run summary

The last thing printed is a list of every distinct warning and error, once each:

```
Run summary
1 distinct problem (3 warnings and errors in all):
  1. [WARNING] 3 projects: Compute collection failed for project alpha-proj-1: 403 ... Required 'compute.instances.list' ...
     Projects: alpha-proj-1, beta-proj-22, gamma-proj-3
     Fix: The identity cannot read this project. Grant a role that includes the read permission
          named in the pre-flight table (for example Viewer on the project) to the identity you
          signed in with, or leave the project out.
          (docs/troubleshooting.md#gcp-permission-denied)
```

The same failure on many accounts, regions or projects counts as one problem. For GCP, the access check and the
collector often report the same failure in different words, and they are one problem too: a problem is the fix, the
service it is about and, for an API that is off, the project Google charges, and the entry lists the projects it
affected (the example line is the first message seen). A line that begins `Run:` is a command you can copy. The final
lines naming the zip are printed after the log has been sealed into it, so they are on the screen but not in the log.

## 7. What you get

One zip, `<cloud>_sizing_results_<timestamp>.zip`, with the CSV files, the JSON record, the pre-flight CSV and the run
log. The CSV files are named `<prefix>-<timestamp>.csv`.

### AWS files

| File (before `-<timestamp>.csv`) |
|-----------------------------------|
| `aws_ec2_instance_info` |
| `aws_ec2_attached_volume_info` |
| `aws_ec2_unattached_volume_info` |
| `aws_rds_info` |
| `aws_efs_info` |
| `aws_DynamoDB_info` |
| `aws_s3_info` |
| `aws_rds_snapshot_info` |
| `aws_ebs_and_ami_info` |
| `aws_vpc_info` |
| `aws_lb_info` |
| `aws_route53_info` |
| `aws_iam_info` |
| `aws_eks_clusters_info` |
| `aws_eks_nodegroups_info` |
| `aws_kms_numbers` |
| `aws_redshift_info` |
| `aws_backup_costs` |
| `aws_snapshot_storage_costs` |
| `aws_fsx_filesystem_info` |
| `aws_fsx_volume_info` |
| `aws_s3_tables_info` |
| `aws_glue_iceberg_info` |
| `aws_backup_recovery_points` |
| `aws_secrets_numbers` |
| `aws_sqs_numbers` |

AWS also writes `aws-backup-plans-info-<timestamp>.json` (the backup plans, left out of an anonymized run) and
`aws_sizing_discovery.json`. A scan of several accounts combines them into one set of files.

### Azure files

| File (before `-<timestamp>.csv`) |
|-----------------------------------|
| `azure_vmdisk_info` |
| `azure_storage_account_info` |
| `azure_file_share_info` |
| `azure_backup_vault_info` |
| `azure_backup_costs` |
| `azure_aks_info` |
| `azure_cosmos_db` |
| `azure_backup_data_protection_vaults` |
| `azure_backup_data_protection_items` |
| `azure_backup_data_protection_policies` |
| `azure_postgres_info` |
| `azure_sizing_summary` |
| `azure_sql_info` |
| `azure_mi_sql_info` |
| `azure_mi_db_items` |
| `azure_storage_account_container_info` (only with `--get-container-details`) |
| `azure_key_vault` (only with `--get-key-vault-amounts`) |

### GCP files

| File (before `-<timestamp>.csv`) |
|-----------------------------------|
| `gce_vm_info` |
| `gce_attached_disk_info` |
| `gce_unattached_disk_info` |
| `gce_cloudsql_info` |
| `gce_spanner_info` |
| `gce_bigquery_info` |

Defender and Purview (Azure) and the asset inventory, Bigtable, AlloyDB and storage details (GCP) are in the JSON only.

## 8. Anonymizing

`--anonymize` replaces the names, IDs and tags in the CSV files with labels such as `Name-00012`. The zip then holds no
raw JSON and no real log. Two files are written beside the zip instead and must stay with you:

- `<cloud>_anonymized_keys_to_actual_values-<timestamp>.csv`, which maps every label back to the real value,
- `output_<cloud>_not_anonymized_<timestamp>.log`, the real run log.

`--anonymize-fields a,b` anonymizes more fields; `--not-anonymize-fields a,b` leaves fields alone, and `Tags` leaves every
tag column alone. The account, subscription or project in the pre-flight CSV gets the same labels as the other files.

## 9. Running again and combining runs

- **AWS** resumes a multi-account scan from its `aws-sizing-progress-*` folder (section 4).
- Several runs can be combined into one set of CSV files per file type with
  `python -m common.consolidate DIRECTORY`, run from the `python` folder, which reads every CSV under the directory and
  groups them by the part of the name before the first dash (pre-flight files included).

### If a run stops early

Ctrl-C, `kill` or closing the terminal does not lose the log. It is written line by line into the output folder as
`output_<cloud>_<timestamp>.log` (for a multi-account AWS scan without `--output`, the current folder) and stays there
when the run is cut short. Its last line says how the run ended, for example `Run ended: stopped by SIGTERM at 14:02:11`,
followed by that the results zip was not written. A log with no `Run ended` line means the process was killed outright
(`kill -9`, a power cut). No CSV files, zip or pre-flight CSV are written for a run that did not finish; the access-check
table is in the log, because it was printed at the start. An AWS multi-account scan keeps each finished account in its
`aws-sizing-progress-*` folder and says so in the last line: run the same command again to resume. The partial log is the
real log and is not anonymized.

## 10. Options

### AWS

| Option | What it does |
|--------|--------------|
| `--org` | Scan all active accounts via sts:AssumeRole |
| `--sso` | Scan accounts via IAM Identity Center (no role creation needed) |
| `--cross-account-role ROLE_NAME` | Scan the accounts given with --accounts or --accounts-file through this IAM role (PowerShell's -CrossAccountRoleName). |
| `--all-profiles` | Scan the account of every local AWS profile (PowerShell's -AllLocalProfiles) |
| `--profiles NAMES` | Comma-separated local profiles to scan (PowerShell's -UserSpecifiedProfileNames) |
| `--sso-start-url` | SSO start URL, e.g. |
| `--sso-region` | Region of the IAM Identity Center instance (default: the one in the cached SSO login, else us-east-1) |
| `--accounts` | Comma-separated account IDs to scan (skips organizations:ListAccounts) |
| `--accounts-file FILE` | File with one account ID per line (alternative to --accounts) |
| `--role-name`, `--org-role-name` | IAM role for `--org` (default: RubrikDiscoveryRole; PowerShell's is OrganizationAccountAccessRole), or the IAM Identity Center permission set for `--sso` (required) |
| `--profile-location FILE` | Read profiles from this AWS credentials file (PowerShell's -ProfileLocation) |
| `--partition` | AWS partition to scan (PowerShell's -Partition GovCloud) |
| `--region-to-query REGION` | Region used for account-wide calls such as STS, IAM and Organizations (default: us-east-1, or us-gov-east-1 with --partition govcloud) |
| `--output`, `-o` | Folder for the zip, the run log and, for several accounts, the progress folder (default: ./outputs for one account, the current folder for several) |
| `--bucket` | (Optional) S3 bucket to also upload results to |
| `--bucket-region` | Region of the S3 bucket (default: us-east-1) |
| `--regions` | Comma-separated list of regions to scan (default: all enabled regions) |
| `--exclude-regions` | Comma-separated list of regions to skip (e.g. |
| `--services` | Comma-separated subset of services to collect (default: all except iac). |
| `--no-cost` | Skip cost collection (12-month Cost Explorer backup + service spend). |
| `--no-capacity` | Skip S3 storage sizing (per-bucket CloudWatch BucketSizeBytes). |
| `--no-backup-capacity` | Skip the native snapshot enumeration (RDS snapshots, EBS snapshots, AMIs), like PowerShell's -SkipBackupCapacity. |
| `--no-csv` | Write only the JSON results, not the PowerShell-style CSV files. |
| `--no-preflight` | Skip the pre-flight access check that runs before each account is scanned. |
| `--preflight-only` | Only run the access check in each account and write `aws_access_check_<timestamp>.zip` with its CSV; nothing is collected and no progress folder is used. |
| `--keep-artifacts` | Single-account mode: also leave the loose JSON and CSV files beside the ZIP. |
| `--skip-bucket-tags` | Do not read S3 bucket tags (PowerShell's -SkipBucketTags). |
| `--backup-recovery-point-timeout-minutes N` | Time budget per region for listing AWS Backup recovery points (default: 60). |
| `--anonymize` | Anonymize names, ids and tags in the CSV files (PowerShell's -Anonymize). |
| `--anonymize-fields FIELDS` | Comma-separated extra fields to anonymize (with --anonymize) |
| `--not-anonymize-fields FIELDS` | Comma-separated fields to leave as they are (with --anonymize); 'Tags' leaves all tag columns alone |
| `--workers` | Number of accounts to scan in parallel (default: 8) |
| `--assume-role ROLE_ARN` | Assume this IAM role before scanning (useful when CloudShell identity lacks permissions) |
| `--verbose`, `-v` | Enable DEBUG logging (default level is INFO) |

### Azure

| Option | What it does |
|--------|--------------|
| `--config FILE` | Path to rubrik.yaml (see docs/config_schema.md). |
| `--subs ID,...` | Comma-separated subscription IDs to scan |
| `--all` | Scan all accessible subscriptions |
| `--regions REGION,...` | Comma-separated regions to include (default: all) |
| `--cloud NAME` | Target Azure cloud: AzureCloud (public) or AzureUSGovernment. |
| `--workers N` | Subscriptions to scan in parallel (default: 4; 1 = serial). |
| `--output DIR` | Output directory for JSON report (default: ~/clouddrive or ./output) |
| `--mock` | Development checkouts only: run against the built-in test fixtures, no Azure credentials required (not available in the public distribution) |
| `--dry-run` | Preview what the tool would collect without calling any collector APIs. |
| `--manifest`, `--audit` | Print the audit manifest (source of docs/audit.md shipped inside the installed wheel) and exit. |
| `--verbose` | Show SE-focused terminal output (environment summary, protection gap) + debug logging from collectors. |
| `--devops-orgs ORG,...` | Comma-separated Azure DevOps org names to scan. |
| `--no-devops` | Skip Azure DevOps repository discovery. |
| `--no-cost` | Skip Cost Management collection (6-month spend). |
| `--no-capacity` | Skip the storage Azure Monitor metrics pass (used-capacity AND blob/file object counts). |
| `--no-security` | Skip security-posture collection (Microsoft Defender). |
| `--no-backup-jobs` | Skip backup job-history collection (last 60 days). |
| `--get-container-details` | List every blob of every container and write `azure_storage_account_container_info` (sizes and counts per access tier). Needs Storage Blob Data Reader; can take a long time. Same as PowerShell `-GetContainerDetails`. |
| `--get-key-vault-amounts` | Count the certificates, secrets and keys in each Key Vault and write `azure_key_vault`. Needs Key Vault Reader (or the List permission in the vault's access policies). Same as PowerShell `-GetKeyVaultAmounts`. |
| `--skip-vms`, `--skip-azure-vm-and-managed-disks` | Skip virtual machines and managed disks. |
| `--skip-sql-mi`, `--skip-azure-sql-and-mi` | Skip Azure SQL databases, elastic pools and managed instances (flexible servers are still collected). |
| `--skip-storage-accounts`, `--skip-azure-storage-accounts` | Skip storage accounts, which also skips their file shares. |
| `--skip-files`, `--skip-azure-files` | Skip Azure Files shares; storage accounts are still collected. |
| `--skip-backup`, `--skip-azure-backup` | Skip Recovery Services vaults, Backup Vaults (Blob and PostgreSQL), backup items, job history and backup costs. |
| `--skip-aks` | Skip AKS clusters. |
| `--skip-cosmos-db`, `--skip-azure-cosmos-db` | Skip Cosmos DB accounts. |
| `--skip-postgresql`, `--skip-azure-postgresql` | Skip PostgreSQL flexible servers. |
| `--anonymize` | Anonymize names, ids and tags in the CSV files (PowerShell's -Anonymize). |
| `--anonymize-fields FIELDS` | Comma-separated extra fields to anonymize (with --anonymize). |
| `--not-anonymize-fields FIELDS` | Comma-separated fields to leave as they are (with --anonymize); 'Tags' leaves all tag columns alone. |
| `--no-csv` | Write only the JSON. |
| `--no-preflight` | Skip the pre-flight access check that runs before the scan. |
| `--preflight-only` | Only run the access check in each subscription and write `azure_access_check_<timestamp>.zip` with its CSV; nothing is collected. |
| `--keep-artifacts` | Leave the loose JSON / log files on disk alongside the ZIP. |

### GCP

| Option | What it does |
|--------|--------------|
| `--config FILE` | Path to rubrik.yaml (see docs/config_schema.md). |
| `--projects ID,...` | Comma-separated project IDs to scan |
| `--project-file FILE` | File with one project ID per line (blank lines and # comments ignored) |
| `--current-project` | Scan only the project from gcloud config / ADC default (default: all accessible projects) |
| `--all` | Scan all accessible projects (this is the default; kept for compatibility) |
| `--include-system-projects` | Also scan Google's auto-created sys-<number> projects when discovering all projects (default: left out; they hold nothing to size). Has no effect with --projects or --project-file, which scan what they name. |
| `--regions REGION,...` | Comma-separated regions to include (default: all) |
| `--workers N` | Parallel project-collection threads (default: 8). |
| `--org ORG_ID` | Organization ID (e.g. |
| `--folder FOLDER_ID` | Folder ID to scope the org-wide asset spine (alternative to --org). |
| `--output DIR` | Output directory for JSON discovery file (default: ~/ or ./output) |
| `--mock` | Run with built-in mock data — no GCP credentials required |
| `--dry-run` | Preview scope + GCP APIs that would be called, then exit. |
| `--security` | Enable Security Command Center findings collection (requires roles/securitycenter.findingsViewer at org level). |
| `--collectors LIST` | Comma-separated subset of core collectors to run (choices: asset,compute,storage,database,bigquery,backup; default: all). |
| `--inventory-only` | Breadth scan only: run just the Cloud Asset Inventory spine (equivalent to --collectors asset). |
| `--anonymize` | Anonymize names, ids and labels in the CSV files (PowerShell's -Anonymize). |
| `--anonymize-fields FIELDS` | Comma-separated extra fields to anonymize (with --anonymize). |
| `--not-anonymize-fields FIELDS` | Comma-separated fields to leave as they are (with --anonymize); 'Tags' leaves all label columns alone. |
| `--no-csv` | Write only the JSON. |
| `--no-preflight` | Skip the pre-flight access check that runs before the scan. |
| `--preflight-only` | Only run the access check in each project and write `gcp_access_check_<timestamp>.zip` with its CSV; nothing is collected. |
| `--verbose` | Show SE-focused terminal output + debug logging from collectors. |

## 11. What it does not do

- It is not tested on Windows (use WSL or a cloud shell).
- Azure Site Recovery is not collected: the collector builds its client the way the 1.x package expects, and the current
  package no longer works that way.
- The access check does not test calls that need a resource name (one vault's items, one database's tables), nor Azure
  DevOps or Security Command Center. The exception is AWS S3 Tables and Glue, whose per-table calls are tried on the
  first table the listing finds (see `permissions.md`).
