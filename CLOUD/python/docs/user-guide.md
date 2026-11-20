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
(`--workers`) and keeps each finished account in an `aws-sizing-progress-*` folder, so running the same command again with
`--resume` carries on where it stopped (see section 9).

### Azure

Sign in with `az login`. The tool uses that sign-in (it tries the other methods the Azure SDK knows first, then the CLI).

| To scan | Use |
|---------|-----|
| the subscription of your current `az` login | no scope option |
| specific subscriptions, by ID | `--subs ID,ID` |
| specific subscriptions, by display name (ignoring case) | `--subscriptions NAME,NAME` |
| every enabled subscription under management groups (name or ID) | `--management-groups GROUP,GROUP` |
| only the subscription of the current `az login` | `--current-subscription` |
| every enabled subscription the sign-in can read | no scope option (or `--all`) |
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
   - GCP: VMs, attached and unattached disks, disk capacity, Cloud SQL, Spanner, BigQuery and Cloud Storage buckets.

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
| `azure_backup_vault_VM_policies` |
| `azure_backup_vault_VM_SQL_policies` |
| `azure_backup_vault_Azure_SQL_Database_Policies` |
| `azure_backup_vault_Azure_Files_Policies` |
| `azure_backup_vault_VM_items` |
| `azure_backup_vault_VM_SQL_items` |
| `azure_backup_vault_Azure_SQL_Database_items` |
| `azure_backup_vault_Azure_Files_items` |
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
| `gce_storage_info` |

`gce_storage_info` has one row per Cloud Storage bucket, with its size from Cloud Monitoring and the BigQuery tables that
read it. It is the file to use for BigLake and external tables, because BigQuery reports 0 bytes for data it does not store
itself. Its columns:

- `SizeBytes` is live plus noncurrent (older version) bytes. `LiveBytes`, `NoncurrentBytes`, `SoftDeletedBytes` and
  `MultipartBytes` give the parts. Soft-deleted objects and unfinished multipart uploads are not in `SizeBytes`.
- `SizeBytes_STANDARD`, `_NEARLINE`, `_COLDLINE`, `_ARCHIVE` and `_OTHER` split `SizeBytes` by storage class (Monitoring
  reports Standard data as `REGIONAL` or `MULTI_REGIONAL`, which count as `_STANDARD`; any other class is in
  `_OTHER`), and `ObjectCount_<class>` splits `ObjectCount` the same way. They are blank when the bucket has no
  reading.
- `LiveBytes_<class>` and `NoncurrentBytes_<class>` split each `SizeBytes_<class>` into current objects and older
  versions, and the two add up to it. Older versions exist only where Object Versioning is on, so a bucket without it
  has `0` in every `NoncurrentBytes_<class>`. Use them to tell the current (front-end) data in a tier from the extra
  bytes its old versions take. The split is by bytes only: the object count has no current or non-current version in
  Cloud Monitoring, so `ObjectCount_<class>` stays one number per class. They are blank when the bucket has no
  reading.
- The bucket settings come from the bucket listing, with no extra request: `CreationTime`; `LocationType`,
  `DualRegionLocations` (the two regions of a custom dual-region bucket; a predefined pair such as `NAM4` is in
  `Location`) and `TurboReplicationEnabled` (dual-region only); `StorageClass` (the default class, which only applies
  to new objects), `AutoclassEnabled` and `AutoclassTerminalStorageClass`; `NamespaceType` (`HNS` or `Standard`);
  `VersioningEnabled`; `RetentionPolicyEnabled`, `RetentionPeriodDays` and `BucketLockState` (`locked` when the
  retention policy is locked, else `unlocked`); `SoftDeleteEnabled` and `SoftDeleteRetentionDays`; `EncryptionType`
  (`CMEK` when the bucket has a default key, else `Google-managed`) and `DefaultKmsKeyName`;
  `UniformBucketLevelAccessEnabled` and `PublicAccessPrevention`. A setting the bucket did not report is blank, not a
  guess. Bucket labels are `Label/Tag: <key>` columns. `DefaultKmsKeyName` is anonymized with `--anonymize`.
- `LifecycleDeleteDays` is the smallest age at which a lifecycle rule deletes a live object, and
  `LifecycleNoncurrentDeleteDays` the same for an older version. They are how long the bucket keeps data when a rule sets
  it, and are blank when no plain age rule does. A rule that also depends on a prefix, a suffix, a label, a number of
  newer versions or a date is counted in `LifecycleRuleCount` but not read as a retention, and a delete rule limited to
  one storage class is left out the same way. `LifecycleTransitions` lists the class changes by age, such as
  `NEARLINE@30d; ARCHIVE@365d`. `RequesterPays` says whether the reader of the bucket is billed for its reads.
- The growth columns say how much each bucket grew. A run measures growth by default, over the last 30 days; use
  `--growth-days N` for another window (up to 365) or `--no-growth` to leave it out. It costs one more Monitoring query
  per project and uses the same permission as the sizes. `GrowthStartBytes` and `GrowthEndBytes` are live plus
  noncurrent bytes at the oldest and the newest daily reading in the window, `GrowthBytes` is the difference
  (negative when the bucket shrank), and `GrowthPercent` is that difference as a percent of the start. `GrowthDays` is
  the time actually between the two readings, so a bucket younger than the window shows its own, shorter span.
- `AnnualGrowthPercent` scales `GrowthPercent` to a year in a straight line (not compounded). It is blank when the
  window is under 7 days, because a few days say little about a year, and when the bucket started at 0 bytes, which has
  no percent. Treat it as a trend, not a forecast: a one-off upload inside the window inflates it.
- `GrowthStatus` says why the growth cells are filled or blank: `measured`, `too few readings` (a new or empty bucket has
  fewer than two daily readings), `not read` (the Monitoring query failed, and the run log says why) or
  `not requested` (`--no-growth`, or the `storage` collector was not selected). Growth is blank in every one of the
  last three cases, never `0`; a bucket that did not change is `0`.
- Growth is the change in stored bytes. It does not measure how much of the data is overwritten or deleted and replaced,
  so it is not a change rate: a bucket that deletes as much as it writes shows no growth.
- `gce_bigquery_info` has an `ExternalCloud` column for tables whose data is not in Google Cloud: `S3` or `Azure Blob`
  (BigQuery Omni), and blank for everything else. These tables are not in `gce_storage_info`, because their data is in
  another cloud, so this scan cannot size it. The run summary says how many there are, and the customer needs to run
  the AWS or Azure sizing script against that storage; the table's `ExternalSourceUri` names the bucket or container.
  A table is marked from its dataset location (`aws-us-east-1` and the other `aws-` or `azure-` locations) or from its
  source URI (`s3://`, or an `azure://` address or an Azure Blob web address). Native tables and views are never
  marked, even in an `aws-` dataset, because their data is BigQuery's own. The `S3` form follows Google's
  documentation; the `Azure Blob` forms have not been checked against a real table, so treat an Azure mark as likely
  and check it. This column is not in the PowerShell script's file: `gce_bigquery_info` is otherwise the same as
  PowerShell's.
- Monitoring samples each bucket once a day and leaves out an empty bucket. A bucket with no reading has blank size
  cells and `SizeStatus` `no datapoint`; a bucket whose read failed has `not read`. A `0` is a reading of zero bytes.
- `BigQueryTables` counts the tables that read the bucket, `BigQueryExternalTables` the external ones, and
  `BigQueryConnections` the connections they read with. A table names a bucket through its source URIs or its BigLake
  storage URI. Only buckets in the scanned projects get a row, but a table in any scanned project can link to one.
- Buckets are matched to tables by name, so a bucket named in tables of two projects is linked once.

The Monitoring query is one request per project for the sizes and one for the object counts. Its window is three days,
so the latest daily reading is used even if it arrived late.

Defender and Purview (Azure) and the asset inventory, Bigtable and AlloyDB (GCP) are in the JSON only.

### Checking the bucket sizes (GCP)

The sizes in `gce_storage_info` come from Cloud Monitoring, so check them against a source that does not: the objects
themselves. Pick one or two small buckets from the file, because listing every object in a very large bucket is slow and
is billed as list operations.

1. Count the bytes in the bucket. `-s` prints one total, and `-a` adds the older versions of a bucket with Object
   Versioning on:

   ```text
   gcloud storage du -s gs://BUCKET_NAME
   gcloud storage du -s -a gs://BUCKET_NAME
   ```

   The first total should be close to `LiveBytes` and the second to `SizeBytes`. They need not match to the byte: Monitoring
   measures once a day, so anything written or deleted since then is the difference. A large gap on a bucket nobody has
   touched is worth a look.
2. For a bucket that BigQuery reads, find the table. In `gce_storage_info`, `BigQueryTables` above 0 means a table points
   at it and `BigQueryConnections` names the connection. To see a table's own view of its data:

   ```text
   bq show --format=prettyjson PROJECT:DATASET.TABLE
   ```

   `externalDataConfiguration.sourceUris` lists the `gs://` paths (the bucket should be one of them) and `connectionId` the
   connection. A BigQuery Iceberg table names its bucket folder in `biglakeConfiguration.storageUri` instead. A BigLake
   or external table reports 0 bytes in `gce_bigquery_info` because BigQuery does not store its data, so the bucket's
   size is the figure to use for it.
3. To see what the script read, open Metrics Explorer in the Cloud Console and chart the metric
   `storage.googleapis.com/storage/v2/total_bytes` for the bucket, grouped by `type`. Each type is one line per storage
   class, so add the classes up. The newest daily point for `live-object` plus `noncurrent-object` should equal
   `SizeBytes`; `soft-deleted-object` and `multipart-upload` are the two the script reports separately and leaves out of it.

A bucket with blank size cells is not zero. Its `SizeStatus` says whether Monitoring had no reading (empty or new bucket)
or the read failed; for a failed read check that the Cloud Monitoring API is enabled and the identity has
`roles/monitoring.viewer`, then run the access check again.

## 8. Anonymizing

`--anonymize` replaces the names, IDs and tags in the CSV files with labels such as `Name-00012`. The zip then holds no
raw JSON and no real log. Two files are written beside the zip instead and must stay with you:

- `<cloud>_anonymized_keys_to_actual_values-<timestamp>.csv`, which maps every label back to the real value,
- `output_<cloud>_not_anonymized_<timestamp>.log`, the real run log.

`--anonymize-fields a,b` anonymizes more fields; `--not-anonymize-fields a,b` leaves fields alone, and `Tags` leaves every
tag column alone. The account, subscription or project in the pre-flight CSV gets the same labels as the other files.

GCP only: a BigQuery table's `ExternalSourceUri` keeps its `gs://` shape, so `gs://lake/raw/*` becomes
`gs://BucketName-00000/ExternalSourceUri-00000`. The bucket gets the label that `BucketName` in `gce_storage_info` gives the
same bucket, so an anonymized run can still say which bucket a table reads. A source that is not a bucket (a Google Sheet,
Bigtable) is labelled whole. The key file maps both labels back; the path one is shown with its leading `/`.

## 9. Running again and combining runs

- **All three tools** can resume an interrupted scan from a progress folder in the output folder (see
  "Resuming an interrupted scan" below).
- Several runs can be combined into one set of CSV files per file type with
  `python -m common.consolidate DIRECTORY`, run from the `python` folder, which reads every CSV under the directory and
  groups them by the part of the name before the first dash (pre-flight files included).

### If a run stops early

Ctrl-C, `kill` or closing the terminal does not lose the log. It is written line by line into the output folder as
`output_<cloud>_<timestamp>.log` (for a multi-account AWS scan without `--output`, the current folder) and stays there
when the run is cut short. Its last line says how the run ended, for example `Run ended: stopped by SIGTERM at 14:02:11`,
followed by that the results zip was not written. A log with no `Run ended` line means the process was killed outright
(`kill -9`, a power cut). No CSV files, zip or pre-flight CSV are written for a run that did not finish; the access-check
table is in the log, because it was printed at the start. A scan keeps each finished account, subscription or project in a
progress folder and says so in the last line: run the same command again with `--resume` to carry on. The partial log is
the real log and is not anonymized.

### Resuming an interrupted scan

While a scan runs, each finished account (AWS), subscription (Azure) or project (GCP) is saved in a progress folder inside
the output folder: `aws-sizing-progress-<timestamp>`, `azure-sizing-progress-<timestamp>` or
`gcp-sizing-progress-<timestamp>`. Each one is written whole or not at all, so a run that is killed while saving does not
leave a half-written file that counts as finished. When the run finishes and every unit has a result, the folder is
removed. It is kept when something has no result yet (a scan that stopped, one that failed, or a named account,
subscription or project the sign-in could not read) and when a unit finished with gaps (see below).

To carry on, run the same command again with `--resume`. The units that are missing, and the units that finished with
gaps, are scanned; the others are read back, so the zip holds all of them, in the order a single uninterrupted run would
list them. The access check runs only for the units still to scan, and the saved ones keep the access rows they were
saved with.

### Units that finish with gaps

A unit that finished is complete as far as the scan got, not as far as the account, subscription or project goes. The
collectors keep going when one call fails, so a listing that failed, an item that was skipped or a service that was
denied leaves something out and the zip alone does not say so. The tools record this:

- **AWS:** a service that was denied or failed in a region, and a region that could not be scanned at all (a region named
  with `--regions` that is not enabled, or whose endpoint cannot be reached), are `scan_errors` in the account's JSON. A
  region that a service control policy denies is not: organizations routinely deny regions, so it is not a gap.
- **Azure:** a warning logged for the subscription during its scan (each one is something left out), or a service the
  access check found it could not read.
- **GCP:** a collector error for the project (an API that is off, a permission that is missing, a time limit reached).

Every run that has such units ends by naming them, how many there are out of how many, the first reason for each, and what
to do. A run with none says nothing. Because a resume scans these units again, a run keeps its progress folder when one of
them has gaps, even if every unit has a result. The cost is that a unit with a gap that never goes away, such as an account
that always denies a service, is scanned again on every `--resume`; `--keep-partial` stops that.

- **A run with no option and no terminal stops** and says what to do. It does not resume silently, because that could mix
  last week's results into today's scan. On a terminal you are asked whether to resume. The same applies after a run
  that finished with gaps, so a scheduled or other unattended run should pass `--fresh`, or write to a new output
  folder each time; otherwise its next run stops with exit code 2.
- **`--fresh`** deletes the unfinished run and scans everything again.
- **`--keep-partial`** (with `--resume`) keeps the units that finished with gaps as they were, instead of scanning them
  again, and the zip holds them with their gaps. Use it when a gap is known and will not go away.

A resume needs the same options as the run it continues: the collectors, regions, scans, skips and how the scope was
chosen. If they differ, the run stops and tells you, and nothing is deleted; add `--fresh` to start over. The list of
accounts, subscriptions or projects is part of that for AWS, which scans exactly the accounts it was given. For Azure
and GCP it is not: a scan of "all" run again may see a few more or fewer, and a unit that is already done stays done.

What is not saved: **Azure** saves each subscription's scan, which is the long part. What is collected after it (tag
names, AKS, Cosmos DB, Backup Vaults, containers, Key Vaults, Defender, Purview) is a few small calls per subscription and
runs again for every subscription on a resume. A **GCP** project that ends after you press Ctrl-C is not saved, because
BigQuery then returns only what it had read; it is scanned again on `--resume`. An **AWS** scan of a single account is one
unit and is not resumable.

The progress folder holds real names, like the log. Keep it with the results, and delete it if you do not resume.

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
| `--resume` | Carry on with the unfinished multi-account run in the output folder; accounts it finished are not scanned again. Needs the same options as that run. |
| `--fresh` | Delete the unfinished multi-account run in the output folder and scan everything again. |
| `--keep-partial` | With `--resume`, keep the accounts the earlier run finished with permission errors or a region it could not scan, instead of scanning them again (the default). The zip then holds them with their gaps. |
| `--assume-role ROLE_ARN` | Assume this IAM role before scanning (useful when CloudShell identity lacks permissions) |
| `--verbose`, `-v` | Enable DEBUG logging (default level is INFO) |

### Azure

| Option | What it does |
|--------|--------------|
| `--config FILE` | Path to rubrik.yaml (see docs/config_schema.md). |
| `--subs ID,...` | Comma-separated subscription IDs to scan |
| `--subscriptions NAME,...` | Comma-separated subscription display names to scan (ignoring case) |
| `--management-groups GROUP,...` | Scan every enabled subscription under these management groups (names or IDs) |
| `--current-subscription` | Scan only the subscription of the current `az login` |
| `--all` | Scan all accessible subscriptions (the default when no scope option is given) |
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
| `--resume` | Carry on with the unfinished run in the output folder; subscriptions it finished are not scanned again. Needs the same options as that run. |
| `--fresh` | Delete the unfinished run in the output folder and scan everything again. |
| `--keep-partial` | With `--resume`, keep the subscriptions the earlier run finished with errors, instead of scanning them again (the default). The zip then holds them with their gaps. |

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
| `--growth-days N` | Days of Cloud Monitoring history to measure each Cloud Storage bucket's growth over (default: 30, at most 365). Costs one extra Monitoring query per project. A bucket younger than this is measured over its own age. |
| `--no-growth` | Do not measure bucket growth: skip the extra Monitoring query and leave the growth columns of `gce_storage_info` blank. Cannot be used with `--growth-days`. |
| `--no-preflight` | Skip the pre-flight access check that runs before the scan. |
| `--no-sdk-check` | Do not stop at the start when a Google library the chosen collectors need is not installed. Those collectors then fail in every project and their data is missing. |
| `--yes` | Do not ask before scanning when the access check shows the quota project cannot serve the calls (API or billing off, or denied). Runs without a terminal never ask. |
| `--preflight-only` | Only run the access check in each project and write `gcp_access_check_<timestamp>.zip` with its CSV; nothing is collected. |
| `--resume` | Carry on with the unfinished run in the output folder; projects it finished are not scanned again. Needs the same options as that run. |
| `--fresh` | Delete the unfinished run in the output folder and scan everything again. |
| `--keep-partial` | With `--resume`, keep the projects the earlier run finished with errors (an API off, a permission missing, a time limit reached), instead of scanning them again (the default). The zip then holds them with their gaps. |
| `--verbose` | Show SE-focused terminal output + debug logging from collectors. |

## 11. What it does not do

- It is not tested on Windows (use WSL or a cloud shell).
- Azure Site Recovery is not collected: the collector builds its client the way the 1.x package expects, and the current
  package no longer works that way.
- The access check does not test calls that need a resource name (one vault's items, one database's tables), nor Azure
  DevOps or Security Command Center. The exception is AWS S3 Tables and Glue, whose per-table calls are tried on the
  first table the listing finds (see `permissions.md`).
