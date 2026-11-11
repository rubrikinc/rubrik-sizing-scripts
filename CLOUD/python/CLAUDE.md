# Cloud Sizing Scripts (Python) — CLAUDE.md

Python discovery tools for AWS, Azure and GCP, being brought to parity with the PowerShell
scripts one directory up. **The PowerShell scripts are authoritative** for output files, columns
and sizing rules; read `../CLAUDE.md` for them. Parity work is tracked as tasks (shared layer A,
contract B, per-cloud AWS/AZ/GCP, anonymizer D).

## Layout

| Path | Purpose |
|------|---------|
| `aws/`, `azure/`, `gcp/` | One tool per cloud: `main.py`, `collectors/`, `models/`, `tests/` |
| `common/` | Shared helpers: CSV writer, size units (`units.py`), retry, the pre-flight core (`preflight.py`) and the run-log core (`runlog.py`), each copied into the tools as `preflight_core.py` and `runlog_core.py`. Only those two cores are used by the tools |
| `contract/` | Per-file CSV columns extracted from the PowerShell code, plus header checks (see its README) |
| `docs/powershell-parameter-mapping.md` | Every PowerShell parameter and its Python flag, or the task that closes the gap |
| `README.md`, `docs/user-guide.md`, `docs/troubleshooting.md`, `docs/permissions.md`, `docs/logging.md` | The user-facing documentation; each tool's `tests/test_docs.py` and `tests/bootstrap/test_docs.py` fail when it drifts from the code |
| `docs/aws-vs-powershell.md`, `docs/gcp-vs-powershell.md`, `docs/azure-vs-powershell.md` | Findings from comparing each tool's output and log with the PowerShell script's |
| `docs/run-guides/` | The browser run guides and example run scripts (private: names the private repo, not mirrored) |
| `packaging/` | `make_cloud_zips.sh`: one shareable zip per cloud (tool, docs, quickstart), an alternative to cloning; `tests/bootstrap/test_packaging_zips.py` checks it |

`common/` is not importable from `aws/`, `azure/` or `gcp/` (each tool runs from its own
directory, GCP imports `collectors.*`, and an installed tool carries only its own modules), so retry
and unit logic still exist per tool. Wiring waits on the packaging decision. The pre-flight core is
the one exception: it is shipped as a byte-identical copy in each tool (see "Pre-flight access check").

## Tests

Run each tool from its own directory (the tests rely on that for imports). Live tests need cloud
credentials and are excluded.

```bash
cd sizing_scripts/cloud/python
pip install -r requirements-test.txt         # all three tools' requirements, pytest, moto
./run_tests.sh                               # every suite; or name some: ./run_tests.sh aws gcp
```

`run_tests.sh` runs `common`, `contract`, `aws`, `azure`, `gcp` and `bootstrap`, each from the
directory and with the `PYTHONPATH` its imports need, skips `tests/live`, runs every suite even
after a failure and exits 1 if any failed. `requirements-dev.txt` is a separate lint toolchain
(ruff, mypy) and is not needed for the tests. Eight Azure tests are skipped here because they
exercise SE-side packages (`analysis`, `output`) and a `docs/examples` directory that are not in
this repo; they run where those exist.

### CI (SAIL)

A change under `sizing_scripts/` matches the Rogers rule `SIZING_SCRIPTS`, which runs the Jenkins job
`ARC_Sizing_UT`. That job runs `sizing_scripts/run_sizing_scripts_tests ut`, which now runs the
PowerShell tests and then the Python tests, and fails if either fails. The Python tests run while
`sizing_scripts/tests/Dockerfile.python` builds (`docker build --target test`), on Ubuntu 22.04 with
Python 3.10, so the minimum Python version is the one under test. To run them by hand, from
`sizing_scripts/`: `./run_sizing_scripts_tests py`. Where the internal registry is not reachable,
add `--py-base-image ubuntu:22.04`.

The bootstrap suite runs against every `bash` it finds. The container has one (5.x), so macOS's
bash 3.2 is only covered when the suite is run on a Mac.

## Dependencies

Each tool's `requirements.in` lists the packages it needs, with the versions it supports; edit that
file. `./update_requirements.sh` (needs `uv`) regenerates every `requirements.txt`, which pins each
package, indirect ones too, to an exact version. Users, the run guides, the zips and CI keep running
`pip install -r requirements.txt`. `requirements-test.txt` is the pinned set the suites install; the
tools' pins agree with it, so the tests run on what users get. AWS also supports Python 3.9, so its
lock has separate 3.9 versions where a package dropped 3.9 (boto3 among them); CI runs 3.10, so check
those by hand after an upgrade (`uv venv -p 3.9`). `--upgrade` moves everything to the newest allowed
versions. `tests/bootstrap/test_requirements_locks.py` fails if a lock is loose, misses a dependency
or disagrees with the test set. The locks are ignored by `../.gitignore` (`*.txt`), so add them with
`git add -f`.

## Running locally

Run from the tool's own directory. `--mock` needs no cloud credentials and writes a ZIP:

```bash
cd sizing_scripts/cloud/python/gcp   && python main.py --mock --output /tmp/out
cd sizing_scripts/cloud/python/azure && python main.py --mock --output /tmp/out
```

AWS has no mock flag; run the collectors against a local fake AWS with moto (`pip install
"moto[all]"`) by calling `main.run(...)` with a boto3 session inside `mock_aws()`. A real run
needs credentials. The flags are listed in `docs/powershell-parameter-mapping.md` and in each
tool's `--help`:

```bash
python main.py --help
python main.py --projects my-proj-1,my-proj-2          # GCP, specific projects
python main.py --project-file projects.txt             # GCP, one ID per line
python main.py --current-project                       # GCP, default project only
python main.py --subs <subscription-id>                # Azure, specific subscription
python main.py --sso --sso-start-url <url> --role-name <permission-set>   # AWS via SSO
python main.py --org --role-name <role>                # AWS organization
python main.py --cross-account-role <role> --accounts-file ids.txt        # AWS, named accounts
python main.py --all-profiles                          # AWS, every local profile
python main.py --partition govcloud                    # AWS GovCloud
python main.py --anonymize --not-anonymize-fields Tags # AWS, anonymized files
python -m common.consolidate ./runs                    # one CSV per kind from several runs
```

### AWS modes, naming, anonymization

- **Modes** are mutually exclusive, as PowerShell's parameter sets: `--org`, `--sso`,
  `--cross-account-role`, `--all-profiles`, `--profiles`; none means the current credentials.
  `--org`, `--sso` and `--cross-account-role` take `--accounts` or `--accounts-file` (not both).
  `--org` and `--sso` and the profile modes share `main._scan_accounts` (progress folder, resume,
  SCP handling, packaging); each mode only says how to get a session. `--sso` uses the cached
  `aws sso login` token, or signs in itself with the device flow (`accounts.sso_device_login`).
  `--sso-region` defaults to the cached login's region.
- **Partition:** `collectors/context.py` holds the partition, the account-wide query region
  (`--region-to-query`; STS, IAM, Organizations, Route53, the region list) and two collection
  options. No collector may build an `arn:aws:` literal (a test enforces it); use `collectors/arns.py`.
  Cost Explorer is skipped outside the commercial partition. GovCloud is covered by tests and
  moto only, not by a real GovCloud account.
- **Names** match PowerShell: `aws_sizing_results_<yyyy-MM-dd_HHmmss>.zip` and
  `output_aws_<stamp>.log` inside it, and one stamp for the zip, the log and the CSV files.
- **Anonymization** (`aws/anonymize.py`) is applied while the CSV rows are built, in the order
  PowerShell anonymizes its lists in. It is checked against PowerShell's own functions (the tests
  extract them from `Get-AWSSizingInfo.ps1` and run them with `pwsh`). The anonymized zip has no
  raw JSON; `aws_anonymized_keys_to_actual_values-<stamp>.csv` and `output_aws_not_anonymized_<stamp>.log`
  are written beside it. Known gaps shared with PowerShell: `DatabaseName`, `Namespace`,
  `S3Location`, `S3BucketName` and `MetadataLocation` are not in the default field list, so
  Glue and S3 Tables names there stay readable unless named with `--anonymize-fields`.
- **Consolidate** (`common/consolidate.py`) ports `consolidate.ps1` for all three clouds.

## Pre-flight access check

Every run first checks what the signed-in identity can read, so the report says which output files the scan
will fill and which it will leave empty or partial. `--no-preflight` skips the check.

| Tool | One check per | Report in the zip |
|------|---------------|-------------------|
| AWS | account; regional services once per region | `aws_preflight_check-<timestamp>.csv` |
| Azure | subscription | `azure_preflight_check-<timestamp>.csv` |
| GCP | project | `gcp_preflight_check-<timestamp>.csv` |

- **What a probe is.** The first read-only call a collector makes, limited to one result (AWS, GCP) or the first
  page (Azure), through the same client the collector uses. A pass means the scan can read that service. Calls
  that need a resource name (one vault's protected items, one Spanner instance's databases) are not probed, and
  neither are Azure DevOps and Security Command Center, which are not per account, subscription or project. The one
  exception is AWS S3 Tables and Glue, whose per-table calls are tried on the first table the listing finds.
- **The report.** One row per service and scope. `Permission` is what the call needs (an IAM action, an Azure RBAC
  action or a GCP permission). `Access` is readable, access denied, not enabled, could not be checked or not
  requested; `Outcome` is captured, dropped, unknown or not requested. `OutputFilesAffected` names
  the files only when the service is not readable. `ResourcesFound` is blank when the call cannot tell (a GCP
  aggregated list, an AWS CloudWatch probe). Only the error code is kept, never the provider's message.
- **The table.** The terminal shows one row per permission: `SERVICE`, `PERMISSION`, `ACCESS` (granted, MISSING,
  API NOT ENABLED, NOT CHECKED, not requested), `WHERE` (how many regions or projects it is missing in, and the
  first two), `FOUND` (whether resources were seen) and `IMPACT` (the output files a missing permission leaves
  empty or partial; a NOT CHECKED row says `unknown` and shows its error code). Missing rows come first, and a `to fix` line follows when there is advice. AWS prints it for a
  scan of three accounts or fewer, and for any account with something blocked; Azure does the same per
  subscription; GCP prints one table across all projects. It is also written to the run log in the zip.
- **Not requested.** A service switched off by `--services`, `--collectors`, a `--skip-*` flag or a declined
  optional scan is listed as not requested and is not called.
- **AWS.** A region the scan would skip (blocked by a service control policy, or not enabled) is one row,
  `all services in region`. Cost Explorer is one billed request per account when cost data is collected, and is
  not made with `--no-cost` or in GovCloud. The check never touches the `DenialTracker`, so a run's success or
  retry behavior is unchanged. In `_scan_accounts` every account that is not scanned keeps rows in the CSV: a
  `sign in` row (`preflight.sign_in_check`, with the permission the mode's sign-in needs) or a `scan` row
  (`scan_failed_check`), and an account held back by a service control policy keeps its access-check rows although
  its discovery file is removed. They are passed to `_access_check_csv` as extra rows (never written to the progress
  folder, so a rerun reports only what is still not scanned) and listed in the closing box.
  `--preflight-only` runs `check_access()` per account instead of `run()`, writes
  `aws_access_check_<timestamp>.zip` with the CSV only, and uses no progress folder.
- **Azure.** The check includes the storage-metrics test that used to run alone; that test still runs by itself
  with `--no-preflight`. An optional scan whose SDK is missing from the environment (Defender needs
  `azure-mgmt-security`) is not offered at the prompt, prints how to install it, and shows as not requested with
  that reason.
- **GCP.** A disabled API is reported as not enabled, with the fix, and is told apart from a missing permission
  by the scan's own `classify_error`. A blocked service is one terminal line listing its projects.
  Every call is charged to the login's quota project (`auth.effective_quota_project`, printed first). An API
  or billing error that names the quota project rather than the scanned one (`preflight.attribute`), and a
  `USER_PROJECT_DENIED` or missing quota project (`preflight.classify`), is `could not be checked` with a
  `QuotaProject*` / `NoQuotaProject` code, never `not enabled`, and `runlog.quota_block` reports it once for
  all projects. The status set and CSV columns are unchanged, so `preflight_core.py` is untouched. The scan still
  runs such a collector (`switched_off_collectors` only skips `not enabled`).
- **Azure and GCP scopes not scanned.** `auth.resolve_subscriptions` / `auth.resolve_projects` take a `skipped`
  list and append `(id, exception)` for each explicit ID they could not read; `main` turns each into a row with
  `preflight.unreadable_check` (`Service` `subscription` or `project`, always `access denied` unless throttled or an
  SDK is missing, because both clouds answer a missing ID and a forbidden one alike). A subscription whose scan
  raised (Azure `_collect_all` errors) or a project whose `_collect_project` raised as a whole (GCP, through
  `_collect_and_write(failed=...)`) gets a `scan` row from `scan_failed_check`. The rows are added to the access
  rows when the CSV is written, and `_print_not_scanned` lists them before the log is sealed. `--preflight-only`
  stops after the access check and `_finish_access_check` writes `<cloud>_access_check_<stamp>.zip` (CSV, manifest,
  log; the anonymized note and key file as in a normal run). Scopes the sign-in cannot see at all (`--all`, GCP's
  default search) cannot be reported: they are never listed.
- **Never stops a scan.** A probe that raises is classified and recorded; a failure inside the check itself logs a
  warning and the scan goes on.
- **Anonymizing.** The account, subscription or project in the report gets the labels the other files use. It is
  labelled after those files are built, so it cannot change their numbering. `--no-csv` leaves the report out of
  the zip; the rows are still in the JSON (`access_check`).
- **Adding a probe.** Add an `Api` row in the tool's `preflight.py`, and its permission to that file's
  `PERMISSIONS` (the AWS test checks each name against botocore; the Azure and GCP names are as the providers
  document them and have not been checked against a live account). The tests check that every file it names is
  a real output file (or a listed non-file effect), that every output file is covered, that every collector,
  service or switch has a probe or is listed as needing a resource name, and (AWS) that each call's arguments
  match botocore's API model. A probe that needs a resource name (AWS) sets `needs` (the label of the probe whose
  finding it is made from), `from_item` (that finding to this call's arguments) and, on the probe before it,
  `stash`; `_run` runs such probes in waves and only where the earlier probe found something, so a region with
  no tables has no row for them rather than a row claiming access that was never tried.
- **AWS sign-in problems.** `aws/accounts.py` `explain_credential_error()` turns an error about the credentials
  themselves (expired session, missing `botocore[crt]` for `aws login`, no, partial or rejected credentials, an unknown
  profile) into a short message; `main()` prints it to stderr and exits 1, and any other error keeps its traceback.
  It follows the exception chain, and an access denied on one service is not matched. A sign-in problem or a bad
  option (exit code 2) discards the run log (`_discard_run_log()`), because the message is on the screen in full; any
  other run that stops keeps its log in the output folder (`_close_run_logs()`) with the error and traceback as its last
  lines.
- **The core is copied.** An installed tool cannot import `common`, so `common/preflight.py` is the tested
  original and `aws/`, `azure/` and `gcp/` each hold a byte-identical `preflight_core.py`. Edit the original, then
  copy it over the three; a test fails if they differ. Both `preflight.py` and `preflight_core.py` are listed in
  each tool's `py-modules`.

## Run log and documentation

- **The log is a transcript of the screen** plus a header and a problem summary, with no library DEBUG output and no
  `--debug-log`. `common/runlog.py` is the original; each tool holds a byte-identical `runlog_core.py` (a test fails
  if they differ) and its own `runlog.py` with that cloud's fixes. Read `docs/logging.md` before changing it.
- **A run that stops still has its log.** The log is streamed into the output folder (AWS and Azure open it there; GCP
  opens a temp file and `_move_run_log()` moves it once the config says where the output goes, not for `--dry-run`), flushed
  on every line, and removed only after it is in the zip. Every way a run ends writes one `Run ended: ...` line through
  `runlog_core` (`finished()` after the digest, `crashed()` from the `main()` wrapper, and the signal handlers from
  `install_stop_handlers()` for Ctrl-C, `SIGTERM` and `SIGHUP`, which exit with `os._exit(128 + signal)` because
  `sys.exit` waits for worker threads). A log with no `Run ended` line was killed outright. AWS sets a stop hint with the
  progress folder so a multi-account scan can be resumed. The tests send real signals to a child process.
- **Adding a fix for an error.** Add a `Solution` to the tool's `runlog.py` and a section with a matching
  `<a id="..."></a>` anchor to `docs/troubleshooting.md`; the tool's `tests/test_docs.py` fails without the section.
- **Adding an option, permission or output file** means adding it to `docs/user-guide.md` or `docs/permissions.md`;
  the same tests fail until it is there. The tables were generated from the code but are edited by hand now.
- The docs must stay free of the deny-list strings, real IDs and unwrapped prose (`tests/bootstrap/test_docs.py`).

## Style

Existing code is black at 100 columns with isort (`--profile black`). Format new files the same
way before opening a PR.

## Conventions

- Import cloud SDKs lazily inside collector methods, never at module top level in `common/`.
- Credentials are created in `main.py` and passed to collectors.
- Record failures instead of turning them into zeros: add to the collector's `errors` (GCP, Azure)
  or the `DenialTracker` (AWS). Use `if tracker is not None:`, never `if tracker:`: an empty
  `DenialTracker` is falsy.
- Sizes: existing `*_gb` / `*_tb` fields are binary (GiB/TiB). Decimal GB/TB are separate
  fields (`*_decimal` in Azure). GCP is decimal throughout.

## Known limitations

- **GCP Spanner database counts** cost one `list_databases` call per instance. Instances within
  a project are processed sequentially (projects run in parallel), and each call can retry for up
  to 10 minutes. `database_count` is 0 both when an instance has no databases and when the
  listing failed; the failure shows up in the project's `errors` as `database:spanner_databases`.
- **Azure storage capacity** is the latest hourly maximum of the last day, the last data point PowerShell reads
  (a daily point only when there is no hourly one: it is the day's largest value). When an account has no
  `UsedCapacity` point in the last day, Python falls back to the sum of its blob, file, table and queue
  capacity metrics (PowerShell reads only the first two, and has no fallback), so an account whose
  account-level metric is missing can show a real `0` in `UsedCapacityBytes` where PowerShell leaves the cell
  blank. It is blank only when none of those metrics returns a point. Seen on a real subscription with two
  empty accounts; nothing else differed.
- **`common.csv_writer.write_csv`** (not used by the AWS exporter, which has its own PowerShell-style
  writer) writes a blank cell for a missing key and only rejects keys
  outside the columns. It does not check required columns; do that against the contract when the
  emitters are added.
- **Azure collector packages.** Azure Backup Vaults (`azure-mgmt-dataprotection`, written to CSV files),
  Microsoft Defender and Microsoft Purview (JSON only) are in `requirements.txt` and the `pyproject.toml`
  dependencies. An environment without one of them still runs and skips that collector.
  `azure/requirements-parity.txt` and the `parity` extra remain, empty, for older scripts. Site Recovery is not in
  `requirements.txt`: its
  collector builds the client with the vault in the constructor, as the 1.x SDK does, and the current 2.x client
  takes only the credential and the subscription, so the collector fails with it. That needs a change in the
  collector, checked against both SDK generations.
- **Tests run in CI** through `run_tests.sh` (the SAIL unit-test job, on Python 3.10). The suites that need
  `pwsh`, `git` history or a browser skip when it is missing, so the comparisons with the PowerShell scripts
  run only on a machine that has them.

## Output contract

`contract/columns.json` is generated from the PowerShell scripts with their parser (`pwsh`):

```bash
cd sizing_scripts/cloud/python
python -m contract.build_columns           # regenerate
python -m contract.build_columns --check   # fail if out of date
```

Regenerate it whenever a PowerShell script's output columns change. Emitters should check
their output with `contract.contract.assert_conforms`.

## CSV output (AWS)

`aws/csv_export.py` writes the PowerShell script's files, with the same names, column names
and order, inside the results ZIP. Use `--no-csv` for JSON only. In `--org` and `--sso` runs
one set of CSVs covers all accounts and is added to the ZIP.

A single-account run leaves **only the ZIP** in the output folder, as Azure and GCP do: the CSV
files are built straight into it and the loose JSON is removed once the ZIP is written (it is not
removed if building or writing the ZIP fails). `--keep-artifacts` keeps the loose JSON and also
writes the CSV files next to the ZIP, the way PowerShell leaves them. An `--anonymize` run
leaves the ZIP, the key file and the real log, and no raw JSON, which holds the real names; with
`--keep-artifacts` the loose JSON is kept, real names included, because you asked for it. The
multi-account modes write only the ZIP and ignore `--keep-artifacts`.

- **Written:** `aws_ec2_instance_info`, `aws_ec2_attached_volume_info`,
  `aws_ec2_unattached_volume_info`, `aws_rds_info`, `aws_efs_info`, `aws_DynamoDB_info`,
  `aws_s3_info`, `aws_secrets_numbers`, `aws_sqs_numbers`, `aws_rds_snapshot_info`,
  `aws_ebs_and_ami_info`, `aws_vpc_info`, `aws_lb_info`, `aws_eks_clusters_info`,
  `aws_eks_nodegroups_info`, `aws_kms_numbers`, `aws_route53_info`, `aws_iam_info`,
  `aws_redshift_info`, `aws_backup_costs`, `aws_snapshot_storage_costs`,
  `aws_fsx_filesystem_info`, `aws_fsx_volume_info`, `aws_s3_tables_info`,
  `aws_glue_iceberg_info`, `aws_backup_recovery_points`.
- **Not written:** `iac` has no PowerShell equivalent.
- **Backup plans file** (`aws-backup-plans-info-<stamp>.json`): every plan whose details could be
  read, in region scan order (the API's order within a region), with the keys PowerShell writes
  with AWS.Tools 5.x in its order minus the SDK transport fields (`ResponseMetadata`,
  `ContentLength`, `HttpStatusCode`), plus `Resources` with the explicit ARNs only (resources a
  selection reaches by tag are not listed). As there, a field the API leaves out is `null`
  (`LastExecutionDate`, `CopyActions`, `RecoveryPointTags`, ...) and the newer keys
  (`ScheduledRunsPreview`, `ScanSettings`, `IndexActions`, `ScanActions`, `DeleteAfterEvent`,
  `TargetLogicallyAirGappedBackupVaultArn`) are always present. AWS.Tools 4.x wrote zeros, false
  and empty lists instead and fewer keys, as `EXAMPLES/aws-backup-plans-info-example.json` shows;
  every key of that older file is here too. `[]` when there are no plans. It is built into
  the zip with the CSVs (and written next to it with `--keep-artifacts`), also with `--no-csv`; org, SSO and profile runs read it from every
  account file in the progress folder, resumed accounts included. It is not written with
  `--anonymize` (PowerShell anonymizes it; doing the same here is a follow-up). A problem writing
  it is logged and never costs the CSV files or the zip. It is not part of
  `contract/columns.json` (JSON, not CSV). Dates are written like PowerShell's
  (`2022-06-06T23:33:40.022Z`), but PowerShell's own fractions can run to 7 digits
  (`.5729999Z`, a floating-point artifact of its date conversion), which boto3's microseconds
  cannot reproduce.
- **Iceberg** (`s3tables` and `glue` services): a table's size and file counts come from the
  current snapshot of its `metadata.json` in S3 (read requester-pays, following a cross-region
  redirect, skipped above 10 MB); the manifest count falls back to counting Avro manifest-list
  blocks. S3 Tables also read CloudWatch (7-day maximum) for the file count and as a size
  fallback, and the maintenance configuration for `CompactionEnabled`. A Glue Iceberg table's
  bytes are deducted from its bucket's storage classes (largest first) and the bucket gets
  `HasIcebergTable` = Yes; after a deduction PowerShell writes the same value in `_SizeGB` and
  `_SizeGiB`, Python keeps the two formulas. Glue only lists tables the role may see under Lake
  Formation. Empty-string versus null is kept: a null location is a bare empty field, `""` is
  quoted. Reading metadata needs `s3:GetObject` on `*/metadata/*` keys, `s3tables:GetTableData`
  and `kms:Decrypt`; cross-account buckets also need a bucket policy.
- **AWS Backup recovery points** are every COMPLETED recovery point of every vault, with the plan
  name looked up by id; composite parents are listed but not counted. Per resource the backup
  columns use the count and the latest recovery point (never a sum); `HasRecoveryPoints` and
  `BackupEnumerationTruncated` (the 60-minute per-region limit) are set on every workload row.
  Rows are ordered by region name. FSx backups (not AWS Backup ones), DynamoDB on-demand backups
  plus a PITR upper bound, and Redshift snapshots (decimal MB) are merged the same way. Backup
  capacity (`snapshots`) lists recovery points always and each native source with its service.
- **FSx** usage is read from CloudWatch (largest hourly value over 7 days) by file system type:
  ONTAP `StorageUsed`, Windows `StorageCapacityUtilizationPercentage`, OpenZFS
  `UsedStorageCapacity`, Lustre `PhysicalDiskUsage`/`LogicalDiskUsage` (peak hourly sum) and
  `FreeDataStorageCapacity` (lowest hourly sum). PowerShell reads Lustre's three from an unset
  variable, so its Lustre columns are empty or stale; Python's are real values. A missing
  datapoint leaves `*Bytes` blank and the units 0, as PowerShell does. Columns are the first-seen
  union across rows, tags included (PowerShell adds later rows' columns in unstable order).
- **S3 sizes** are the largest daily value of the last 7 days for every storage class CloudWatch
  reports (`<Class>_Size*`), plus Storage Lens `CurrentVersion_<class>_Size*` and
  `CurrentVersionObjectCount_<class>` (latest day) when a dashboard publishing to CloudWatch
  covers the bucket. Columns are the union across buckets, first seen first; blanks are 0.
  `StandardStorage` and `AllStorageTypes` are always present (PowerShell omits them for a bucket
  without data). Needs `cloudwatch:ListMetrics` and the two `s3:*StorageLens*` read actions;
  without them the run records the failure and keeps the Standard totals.
- **Cost files** need Cost Explorer (`ce:GetCostAndUsage`, `ce:GetDimensionValues`) and are
  header-only with `--no-cost`, on GovCloud, or when Cost Explorer fails (the failure is added to
  `scan_errors`). They cover the first of the month 12 months ago up to today. The snapshot file
  covers USAGE_TYPEs matching the PowerShell keyword list, minus types other services count.
- **Services:** without `--services` everything runs except `iac` (Python-only, opt in with
  `--services ...,iac`). Route53 and IAM are account-wide and run once, not per region.
- **Row order:** accounts, then regions in scan order (AWS's order, as PowerShell), then API order.
  Tag columns are first-seen order, so they repeat between runs only if AWS returns resources in the same order
  each time (not checked); PowerShell's own order there comes from a hashtable and varies, so tag column order
  is the one expected difference from a PowerShell file.
- **Backup columns** (`HasBackups`, `BackupCount`, `BackupSources`, `LatestBackup*`) are filled
  from native backups: RDS DB and cluster snapshots and EBS snapshots and AMIs. This runs by
  default whatever `--services` lists, for whichever of `rds` (snapshots) and `ec2` (EBS snapshots
  and AMIs) are collected; `--no-backup-capacity` skips it. Per resource: the number of backups, the sources
  and the latest backup's date and size, never a sum. Snapshots AWS Backup made, unavailable
  ones and DocumentDB/Neptune are skipped. The `snapshots` service needs `ec2:DescribeImages`,
  `ec2:DescribeSnapshots`, `rds:DescribeDBSnapshots` and `rds:DescribeDBClusterSnapshots`.
  Recovery points, FSx, DynamoDB and Redshift backups still show the PowerShell defaults
  (AWS-10).
- **Backup plans** (`BackupPlans`, `InBackupPlan`) are decided from the plans' selections, as
  PowerShell does, not from what AWS Backup lists as protected. `collectors/backup.py` keeps each
  selection of a plan apart (`BackupSelection`: `Resources`, `NotResources`, `ListOfTags`,
  `Conditions`), `backup_plan_membership.py` ports PowerShell's matching and
  `csv_export._with_plan_membership` stamps the result on copies of the records.
  `BackupPlans` is the names of the plans that select the row, joined with `, ` in plan order;
  `InBackupPlan` is true when one does. The discovery JSON's `in_backup_plan` and the summary
  totals in `main.py` still mean "AWS Backup lists it as protected" (and native RDS backups,
  DynamoDB PITR), so they can differ from the CSV flag; PowerShell's totals use the CSV flag.
  - **Matching** is per selection and per (account, region). `ListOfTags` (`STRINGEQUALS` only)
    are OR-ed, `StringEquals`/`StringLike` AND-ed, `StringNotEquals`/`StringNotLike` disqualify. A
    selection with only negations therefore selects every row that lacks the tag, DynamoDB rows
    included (they have no tag columns). Everything ignores case and `-like` follows PowerShell
    (`[!a]` is a literal set, not negation). `NotResources` strips the plan from the listed rows
    of this and every earlier (account, region) group, never later ones, because PowerShell's
    lists grow while it scans.
  - **PowerShell quirks kept on purpose** so the files agree (fix them in PowerShell first):
    explicit ARNs are split per type as PowerShell splits them, so `arn:aws:s3:::bucket` and
    `.../bucket/*` select no bucket (only `arn:aws:s3:::*` does); a DynamoDB ARN selects tables
    only through a trailing `*`, except that one with no `/` selects all of them; `rds` reads the
    id segment whatever the resource type before it says; unattached EBS volumes never match
    (PowerShell compares raw SDK objects), so they stay empty and false; `aws:ResourceTag/Name`
    matches S3 and S3 Tables rows only (the other kinds drop the `Name` tag).
  - **Not copied from PowerShell:** a selection that cannot be read contributes nothing
    (PowerShell reuses the previous selection's data); a failed `get_backup_plan` or an invalid
    wildcard (PowerShell throws) does not stop the region's remaining plans, the wildcard just
    matches nothing; plan names are a list (PowerShell splits its comma-joined string, so a
    name containing a comma splits there).
  - **Fallback:** a group (account, region) with no plans, a plan without `selections` (discovery
    files from before this existed) or a plan marked incomplete keeps the older signal:
    `InBackupPlan` from AWS Backup's protected-resource list and an empty `BackupPlans`.
    PowerShell writes false and empty there. It is silent for a region without plans and warns
    once per account when the answer can change.
  - **Failures:** `fetch_backup_plans` records every failed plan or selection read as one
    `scan_errors` entry per region. An SCP denial on any of them also marks the account denied
    (it is retried on resume). A throttle only lands in `scan_errors`: the account counts as done
    and stays on the fallback until it is scanned again. A plan whose details cannot be read stays in the list as
    an incomplete placeholder, so its group falls back instead of trusting the other plans.
  - **Anonymization:** plan names are numbered in plan-list order first
    (`Anonymizer.pre_label`), as PowerShell anonymizes the plan list first. Only that numbering
    is matched: PowerShell's pass also labels plan ids, ARNs, version ids, rule ids and names,
    vault names and `Resources`, so an ARN or vault name that also appears in a later file can
    carry the plan-list label there. The key file lists plans that cover no row (as PowerShell's
    does). `--anonymize-fields BackupPlans` labels the whole cell and does not reuse the
    plan-name labels.
  - **Known gaps:** the CSV `Tag:` columns drop only a tag named exactly `Name` while PowerShell
    drops it ignoring case, so a tag named `name` is a column that never matches. The
    `aws_s3_tables_info` file lacks the `Tag: Name` column PowerShell writes
    (`FileSpec.tag_name` is false), though its rows can match on `Name`. RDS clusters have no
    rows here, so an `rds` `*` selection cannot mark them as it does in PowerShell.
- **Format:** every value quoted, a null as a bare empty field, LF line ends, UTF-8, no BOM.
  `InBackupPlan` means a backup plan's selection covers the row (see Backup plans); native RDS
  backups and DynamoDB PITR are not counted.
- **Empty files:** a file with no rows is a zero-byte file, as PowerShell's bare `Export-Csv`
  leaves it, not a header-only file. Six files have a fallback PowerShell writes by hand, and
  `csv_export._EMPTY_FILE_TEXT` copies each byte for byte: `aws_backup_recovery_points` gets its
  quoted header; `aws_backup_costs` a `#TYPE System.Management.Automation.PSCustomObject` line and
  a quoted header; `aws_snapshot_storage_costs`, `aws_ebs_and_ami_info`, `aws_rds_snapshot_info`
  and `aws_redshift_info` one unquoted header line. The Redshift line lists `ResourceArn` after
  `ManualSnapshotRetentionPeriod` although its rows put it after `ClusterIdentifier`; the literal
  is kept as PowerShell has it. The header-only check in `contract` therefore does not apply to
  an empty file; `common.consolidate` already skips empty files.
- **Tags:** `Tag: <key>` columns with the key sanitized the PowerShell way; the `Name` tag is
  left out except for S3. Tag column order follows row order, so it can differ from a
  PowerShell run; the set of columns is the same.
- **Not copied from PowerShell:** a bucket whose tag lookup fails (`NoSuchTagSet`) gets no tags.
  PowerShell reuses the previous bucket's tags in that case.
- **Numbers:** `[math]::round(x, n)` scales by 10^n, rounds half to even and scales back, so 12.345
  gives 12.34, where Python's `round(x, n)` gives 12.35. A double is written positionally below 1e17 and
  as `1E+17` from there. `csv_export._ps_round` and `_format_float` copy .NET; they were checked
  against `ConvertTo-SizeUnits` and `ConvertTo-Csv` in `pwsh` on 12,104 cells.
- **Compare with a PowerShell run:** match rows by ID and compare cells. Differences you should
  expect are the backup columns and any resource types listed above.
- **Checked against real PowerShell output** (one account, all regions, run with no plans, with
  plans, and with a full set of workloads): EC2, EBS, RDS, DynamoDB, EFS, FSx (file system and
  volumes), S3, S3 Tables, Glue Iceberg, EKS, KMS, VPC, IAM and both cost files matched cell for
  cell apart from the differences below; `BackupPlans` and `InBackupPlan` matched on every row,
  covering explicit ARNs, wildcards, tags (including a mixed-case key), `StringEquals`,
  `StringLike`, `StringNotEquals` and `NotResources`; the empty files matched byte for byte.
  Not checked against real data: Redshift, organization-policy plans, the org, SSO and
  cross-account modes, and tag-based matches on resources with many tags. AWS Backup rejects FSx
  OpenZFS in a selection, so FSx rows only get plan names through tags.
- **Differences found in those runs**
  - PowerShell bugs, not copied: the secrets and SQS counts are read with the ambient credentials
    (the calls have no `-Credential`), so for a named profile they can belong to another account,
    while the Python counts are the scanned account's; an EKS cluster or node group with exactly
    one tag gets the first character of the value (`t` for `true`), because
    `Tags.Values.Split('\n')[0]` indexes a bare string when there is a single value; and S3 Tables
    `CompactionEnabled` and `SnapshotManagementEnabled` are empty, because the maintenance
    configuration is a dictionary and the script reads it as an object.
  - Fixed here: S3 Tables maintenance status was compared with `"ENABLED"` but the API returns
    `"enabled"`, so every table with maintenance on was written as off.
  - Machine-dependent: the `AM`/`PM` separator in date cells (see Dates under Azure): PowerShell
    on macOS 26 with .NET 9.0.10 wrote U+202F, runs on other machines a plain space, and Python
    writes a plain space.

## CSV output (Azure)

`azure/csv_export.py` writes the PowerShell script's files into the results ZIP, with the same
names, column names and order, as `<prefix>-<yyyy-MM-dd_HHmm>.csv`. The ZIP is
`azure_sizing_results_<yyyy-MM-dd_HHmm>.zip`, the log `output_azure_<yyyy-MM-dd_HHmmss>.log`; the
JSON keeps its `rubrik-discovery-<stamp>.json` name. Use `--no-csv` for JSON only.

- **Written:** `azure_vmdisk_info`, `azure_storage_account_info`, `azure_file_share_info`,
  `azure_backup_vault_info`, `azure_backup_costs`, `azure_aks_info`, `azure_cosmos_db`,
  `azure_postgres_info`, `azure_sql_info`, `azure_mi_sql_info`, `azure_sizing_summary`, and, when
  `azure-mgmt-dataprotection` is installed, the three `azure_backup_data_protection_*` files, plus the
  JSON `azure_mi_db_items`; with `--get-container-details`, `azure_storage_account_container_info`, and with
  `--get-key-vault-amounts`, `azure_key_vault`. Not written yet: the Recovery Services item CSVs and policy
  JSON files.
- **`azure_mi_db_items`:** each managed-instance database with its short-term (`STR`) and long-term
  (`LTR`) retention policies, nested tenant, subscription, instance. The record is built at collection
  time by `az_managed_database`: the 28 keys of `Get-AzSqlInstanceDatabase` in its order, dates as
  PowerShell's JSON writes them (a fraction only as far as it is not zero), `STR` then `LTR` after them
  when read. Both policies are read in one `try`, as PowerShell does, so a stopped database keeps `STR`
  and has no `LTR`. One database is an object, not a one-item array, and a subscription with no instance
  is `{}`, both as PowerShell writes them. The file is left out of an anonymized run, because
  PowerShell's own anonymizing of the nested hashtable is doubtful and real names must not leak.
  An instance whose database listing succeeded but returned none is written as `[]`; PowerShell may
  write `null`, which no real run has shown.
- **`azure_postgres_info`:** one row per PostgreSQL flexible server (MySQL servers are collected but
  not written). Written only when there is a server, as PowerShell does. `Region` is the location as
  Azure returns it (`Canada Central`); `Utilized_Bytes` is the highest non-null `storage_used`
  datapoint of the last day, and the `Utilized_*` columns use four decimals; size, usage and
  `DatabaseCount` are blank, not 0, when Azure gives no value; tags are looked up case sensitively and
  an empty value is kept as `""`. `BackupPolicies` and `InBackupPolicy` come from the Backup Vault
  items (the server's resource id is rebuilt from subscription, resource group and name and matched
  without regard to case) and are `-` and `False` without `azure-mgmt-dataprotection`. The totals print
  `N4` capacity (`162.0670`).
- **Storage and file share `BackupPolicies` / `InBackupPolicy`:** filled from the Azure Files items of
  Recovery Services vaults (the account from the item's source resource id, the share from its friendly
  name, else the last `;` part of its name), as `Set-AzureStorageBackupProtection`. Blob protection
  comes from Backup Vault items, listed first, and flags the account only, not its shares.
- **Backup Vault files:** `collectors/data_protection.py` lists the Backup Vaults of a subscription, their
  Blob and PostgreSQL policies and backup instances (`get_in_subscription`, `backup_policies.list`,
  `backup_instances.list`). A datasource type is Blob on an exact match and PostgreSQL on the
  `Microsoft.DBforPostgreSQL/` prefix; anything else is counted and left out. The files are written only
  when they have rows, and only when the vaults were collected (`result["data_protection"]` is not
  `None`): `--skip-backup` or a missing package leaves them out, and the totals lines with them. The
  policies file is JSON built by `csv_export.az_policy_property`, whose tables follow what a real
  PostgreSQL policy shows (singular array names, `DataStore`, `Schedule`, `TagInfo` and
  `SourceDataStore` only flattened, `BackupParameter`, `Trigger` and `DeleteAfter` kept and copied up,
  keys alphabetical). Blob policy shapes are not compared. The package floor is 1.0.0 because 1.x models
  are read through `serialize` and 2.x ones as mappings; neither has been run against real Azure.
- **Tags:** one `Tag: <name>` column per tag name the subscriptions define (`Get-AzTag`), on every
  row, whether or not a row carries it. Names are sorted ignoring case. PowerShell sorts with the
  current culture, so names with punctuation can order differently, and which spelling of a name
  that differs only by case is kept is unspecified there.
- **Tenant:** the tenant display name; an empty field when it has none.
- **Empty files:** a file with no rows is empty, with no header, like `Export-Csv`.
- **Row order:** PowerShell fills a hashtable for VMs, so its VM order is not stable. Python
  writes subscriptions in scan order and rows in API order.
- **VM `BackupPolicies`:** joined from Recovery Services items of the VM workload on subscription,
  VM name and the vault's region. SQL-in-VM items are not joined yet (PowerShell matches them by
  server name).
- **VM `Status`:** PowerShell writes `$vm.StatusCode` of `Get-AzVM`, written here as `0`. Check
  that against a PowerShell run.
- **Disks:** `Disks` and the sizes count the managed disks attached to the VM. PowerShell counts
  the OS and data disks in the VM's storage profile, so unmanaged and ephemeral disks can differ.
- **Storage metrics:** the latest hourly maximum of the last day of `UsedCapacity`, `BlobCapacity`, `FileCapacity`,
  `ContainerCount`, `BlobCount`, `FileShareCount` and `FileCount`. When `UsedCapacity` is missing
  the JSON falls back to the sum of the per-service capacities, which PowerShell does not do.
- **Numbers:** a missing metric is an empty `...Bytes` cell and 0 in the unit columns, as in
  PowerShell. Doubles print positionally below 1e17 and in scientific form from there.
- **Rounding:** `[math]::round(x, n)` scales by 10^n, rounds half to even and scales back, so
  12.345 gives 12.34. Python's `round(x, n)` gives 12.35 and differs on about 2% of tie-prone
  values. `csv_export._ps_round` copies .NET.
- **Dates:** the PowerShell scripts set the thread culture to `en-US` while they run, so a
  `[datetime]` is `M/d/yyyy h:mm:ss AM` on any machine. The real runs we have use a plain space
  before `AM`; builds on newer ICU versions write U+202F there instead, which is the only
  machine-dependent part left.
- **File shares:** a row per share of every account that holds Azure Files (`StorageV2` and
  `Storage` accounts on a non-premium SKU, `FileStorage` on `Premium_LRS` or `Premium_ZRS`, the same
  test as `Get-AzureFileSAs`). Usage is the `stats` expansion of a get per share, skipped with
  `--no-capacity`. The file has no tag columns. PowerShell re-emits the previous account's shares
  under an account that does not support Azure Files; Python does not. A share whose usage cannot
  be read keeps its quota and an empty usage; PowerShell drops all shares of that account when
  any call fails.
- **Backup vaults:** `ImmutabilitySettings` is PowerShell's own object, written as
  `ImmutabilityState: Disabled`, `Unlocked`, `Locked` (or `0` for a state it cannot parse), and empty
  when the vault reports no immutability settings. The file has no tag columns.
- **Backup costs:** the monthly spend of the `Backup` service over the last 11 months and the
  current one (query type `Usage`, `PreTaxCostUSD` and `CostUSD`, as `"$" + round(x, 2)`). The
  columns are found by name; PowerShell reads them by position. It is a separate Cost Management
  query run after the main one, skipped with `--no-cost`, and not repeated when the main query was
  throttled, denied, not registered or failed on the server.
- **AKS and Cosmos DB** are read as ARM JSON through the existing `azure-mgmt-resource` client (a
  list by resource type, then a get at a pinned api-version: AKS `2024-05-01`, Cosmos
  `2024-05-15`), so no SDK package is added. Values are the API's own text, so a Cosmos
  `Location` is `West US 2` as the API returns it. Both run on every scan; there are no skip
  switches until the `-Skip*` mapping (AZ-6). Tag lookups are case sensitive, as the Az models
  keep tags in a `Dictionary<string,string>`.
- **AKS node pools:** the pools come from the cluster's `agentPoolProfiles`. `NodePoolCount` is the
  number of pools. For a cluster with one pool PowerShell writes that pool's node count instead,
  because `Get-AzAksNodePool` then returns a single object and `.Count` reads its `Count`
  property. Missing values become `-` as in the script; the node pool columns are `""` when a
  cluster has no pools.
- **Cosmos backup policy:** periodic accounts fill the interval, retention and redundancy columns,
  continuous accounts only the tier, and both fill `BackupPolicyBackupType`. The five metrics are
  the latest hourly Maximum over a day and are skipped with `--no-capacity`.
  `NameDatabaseAccountOfferType` is empty in PowerShell, which reads a property the Az model does
  not have; Python writes the account's offer type (`Standard`).
- **Row order:** PowerShell lists Cosmos accounts resource group by resource group; Python uses
  the order the resource list returns.
- **Anonymization** (`azure/anonymize.py`): `--anonymize`, `--anonymize-fields` and
  `--not-anonymize-fields` (`Tags` leaves the tag columns alone) port the script's `-Anonymize`. A
  value of a listed field becomes `<Field>-<number>`; the mapping is shared by all files, matches
  without regard to case, and keeps the first spelling in the key file. Tag columns are renamed
  `Tag:TagName-<n>` (no space after `Tag:`, unlike AWS) and moved to the end. An empty string is a
  value and gets a label, null does not. Labels are numbered in the script's file order (VMs, SQL,
  MI, storage accounts, file shares, vaults, costs, Cosmos DB, AKS), and the summary is not
  anonymized. The ZIP has no raw JSON and holds a note in place of the log; the key file
  (`azure_anonymized_keys_to_actual_values-<yyyy-MM-dd_HHmmss>.csv`) and the real log
  (`output_azure_not_anonymized_<stamp>.log`) are written beside it. `--keep-artifacts` also keeps
  the raw JSON. PowerShell's counter repeats from the 11th distinct value of a field (`Name-00000`
  is given to the 1st and the 11th); Python numbers on, which is the same for the first ten.
  PowerShell also anonymizes the policy and item JSON files, which are not written yet.
- **Skip switches:** `--skip-vms`, `--skip-sql-mi`, `--skip-storage-accounts`, `--skip-files`,
  `--skip-backup`, `--skip-aks` and `--skip-cosmos-db` (each also as the PowerShell name in kebab
  case, such as `--skip-azure-vm-and-managed-disks`) map the `-Skip*` switches. A skipped collector
  does not run, there is no prompt, its CSV file is not written (the summary file always is, and
  leaves out that section), and the JSON lists it in `skipped`. Skipping the backup removes the
  vault list the protection gap and Site Recovery lookups use. Skipping VMs leaves the backup
  coverage figures without a VM count.
- **Summary:** `azure_sizing_summary_<stamp>.csv` (an underscore before the stamp, unlike the other
  files) is built from the rows of the other files: VMs (a block each for `HasMSSQL = Yes` and
  `No`), storage accounts (blob capacity), file shares, SQL databases (without `DataWarehouse`),
  managed instances and AKS, each with an `All Regions` line and one line per region. Sums are a
  plain running total of the already-rounded cell values, like `Measure-Object -Sum`, so
  `0.1 + 0.2 + 0.3` is `0.6000000000000001`; a group whose values are all null sums to 0.
  Regions group ignoring case, keep the first spelling and come sorted (PowerShell 7.6; Windows
  PowerShell and older 7.x list them in first-seen order). PowerShell's VM section is broken in two
  ways that are not copied: its per-region rows are one blank-region row repeating the total, and a
  group with a single VM gets that VM's hashtable key count as its count.
- **SQL rows:** a database row per user database, and for a server with a database in an elastic
  pool, a pool row for each pool of that server in place of that database (first time only).
  PowerShell skips a pool whose name another server already used; Python lists each server's pools.
  `Export-Csv` takes its columns from the first row, so PowerShell drops the database-only
  columns (`Allocated_Bytes` to `DiffBackupFrequency (Hours)`) when a pool comes first; Python
  always writes them.
- **SQL empty cells:** `Database`, `Server`, `ElasticPool`, `ManagedInstance` and `DatabaseID` are
  `""` when empty. Pool rows have no `Status` or tags (the pool model has neither) and MI rows have
  no `Status` (the MI model has none), so those cells are empty or `-`. Pool and MI `Subscription`
  and `Tenant` fall back to the subscription id and the tenant id when the name is empty.
- **SQL tags:** the lookup is case sensitive, as the SQL models keep tags in a
  `Dictionary<string,string>`. `Tag:` values are the database's own tags, not the server's.
- **SQL metrics:** `Allocated_Bytes`, `Utilized_Bytes` and `storage_space_used_mb` are the latest
  hourly Maximum over one day; PowerShell reads the last Maximum at the default grain.
- **MI `Databases`:** the number of databases the list call returns; empty when the call fails
  (PowerShell writes 0 then).
- **Retention:** the `LTR*` cells are the API's ISO 8601 durations (`P1W`, `PT0S`), `PITR (Days)` and
  `DiffBackupFrequency (Hours)` come from the short-term policy; a failed lookup leaves them empty.
- **Compare with a PowerShell run:** match rows by name and subscription and compare cells.

## CSV output (GCP)

`gcp/csv_export.py` writes the PowerShell script's files into the results ZIP, with the same names,
column names and order, as `<prefix>-<yyyy-MM-dd_HHmmss>.csv`. The ZIP is
`gcp_sizing_results_<yyyy-MM-dd_HHmmss>.zip` and the log `output_gcp_<same stamp>.log`, with the run's
start time; the JSON keeps its `gcp-sizing-discovery-<stamp>.json` name. Use `--no-csv` for the JSON only.
`_finalise_zip` builds the CSV files from the JSON, so the mock, in-memory and streaming runs all
produce them.

- **Written:** `gce_vm_info`, `gce_attached_disk_info`, `gce_unattached_disk_info`, `gce_cloudsql_info`,
  `gce_spanner_info`, `gce_bigquery_info`.
- **Disks:** a VM's disk rows and counts cover the disks the project's disk list returned. PowerShell
  describes each attached disk and skips one it cannot, so a disk missing from the list is in no row and
  not in the VM's counts. `DiskEncryptionKey` is `True` or `False` for an attached disk, and for an
  unattached disk the key as PowerShell writes the object (`@{kmsKeyName=...; sha256=...}`), or empty. A
  regional disk's `Zone` is its region.
- **Sizes:** `SizeGb` is the Compute API `sizeGb`, which Google defines as a binary gigabyte (a GiB, 2**30
  bytes). `SizeTb` and the VM totals keep the legacy PowerShell formula, that number divided by 1000 and not
  rounded; it is neither TB nor TiB. `SizeGiB` and `SizeTiB` (and `TotalDiskSizeGiB/TiB`,
  `EncryptedDisksSizeGiB/TiB`) are the same number and that number divided by 1024, rounded to four decimals with
  .NET's half-to-even rule, as master's `ConvertTo-GCPSizeUnits` writes them. In the JSON `size_bytes_derived` is
  `size_gb * 2**30`; `size_tb` and `total_disk_tb` keep the legacy division by 1000. Cloud SQL's unit is unverified.
- **BigQuery** (`collectors/bigquery.py`, selectable as `--collectors bigquery`, on by default): one row per table,
  view, materialized view, external table and snapshot, with the logical size (`numBytes`, `numLongTermBytes`),
  row and column counts, the external source, UTC dates and labels. Master's script reads this with the `bq`
  command; Python calls the BigQuery REST API through the Google API client it already uses, so no package is
  added. Sizes here are bytes, so `Gb` and `Tb` are decimal (10**9, 10**12 bytes), `GiB` and `TiB` binary; GB and
  GiB to four decimals, TB and TiB to six. Dataset labels are `Label/Tag: dataset_<key>`, table labels
  `Label/Tag: <key>`, and a table label with the same name wins and moves to the end. A call that fails
  (API disabled, no permission) is one `collection_errors` record per kind that says how many calls failed, and
  the rest is still collected. Grant `roles/bigquery.metadataViewer` (not verified against a real project).
- **Labels:** one `Label/Tag: <key>` column per label, with every character outside `a-zA-Z0-9` in the
  key replaced by `_`. Two keys that become the same name (`a-b` and `a_b`) leave one column holding the
  later value, after the others. A label a row does not have is empty and an empty label value is `""`.
  PowerShell adds the missing labels to each row in a hashtable's order, which changes from one run to
  the next, so its label columns can be in any order; here they are in the order the rows first have them. The
  Compute API lists zones in no fixed order, so the collector sorts VMs and unattached disks by zone and name (a
  VM's own disks keep the order the VM lists them in); without that, two runs gave different label columns.
- **Cloud SQL:** the engine is the version's prefix (`POSTGRES` is PostgreSQL, `MYSQL` is MySQL, `SQLSERVER` is
  SQL Server; any other version is written as it is). `NumberOfDatabases` leaves out each engine's system
  databases, compared without regard to case. PowerShell writes 0 when the databases cannot be listed; Python
  leaves the cell empty and records `database:cloud_sql_databases` once per project. A missing disk size is 0,
  a missing backup setting is `False`, and a missing availability type is empty.
- **Cloud SQL labels** come from `settings.userLabels`, where the API keeps them. The collector read a
  top-level `userLabels` that the API does not have, so Cloud SQL labels were never collected before.
- **Spanner:** `NodeCount` and `ProcessingUnits` are 0 when the API gives none, and `NumberOfDatabases` is 0
  when the databases cannot be listed, as in PowerShell (the collector records the error).
- **Anonymization** (`gcp/anonymize.py`): `--anonymize`, `--anonymize-fields` and `--not-anonymize-fields`
  (`Tags` leaves the label columns alone) port the script's `-Anonymize`. A value of a listed field becomes
  `<Field>-<number>`; the mapping is shared by all files, matches without regard to case, and keeps the
  first spelling in the key file. The default fields are `Name`, `Project`, `VMName`, `DiskName`, `Id`,
  `DiskEncryptionKey`, `InstanceName`, `DisplayName` and, for the BigQuery file, `DatasetId`, `TableId` and
  `ExternalSourceUri`. A `Label/Tag: <key>` column becomes
  `Label/Tag:Label/TagName-<n>` (no space after `Label/Tag:`) with values `Label/TagValue-<n>`, moved to
  the end. An empty string is a value and gets a label, null does not. Labels are numbered in the script's
  file order (VMs, attached disks, unattached disks, Cloud SQL, Spanner). The ZIP has no raw JSON and holds
  a note in place of the log; the key file (`gcp_anonymized_keys_to_actual_values-<stamp>.csv`) and the real
  log (`output_gcp_not_anonymized_<stamp>.log`) are written beside it. PowerShell's counter repeats from the
  11th distinct value of a field (`Name-00000` goes to the 1st and the 11th); Python numbers on, which is
  the same for the first ten. For a value that is not text (the `True` or `False` in an attached disk's
  `DiskEncryptionKey`, or a number added with `--anonymize-fields`) PowerShell gives every row a new label
  and its key file keeps only the last one, so most labels cannot be mapped back; here a value has one
  label and the key file maps it.
- **Row order:** projects in the order they were scanned, then the collector's order within a project.
- **Compare with a PowerShell run:** match rows by project and name and compare cells.
- **Backup and DR coverage:** `backup_posture[].available` is `false` when the protected workloads could not be
  listed (Backup and DR API disabled, no permission, SDK missing). The error is in `collection_errors` (collector
  `backup`), the roll-ups then list every VM as unprotected, and the run summary shows Protected as `n/a` and
  leaves the project out of the Protected total, instead of a 0.

## Branches

Parity work lands on the integration branch `cloud_sizing_script_python`, which merges to
`master` later. Open task PRs against it, not `master`. If a PR is stacked on another, retarget
it to the integration branch before merging its parent, or GitHub merges it into the parent
branch and the change never reaches the integration branch.

## Bootstrap, packaging and publishing

How a customer installs and runs these tools (the `fetch_source` block in `aws/install.sh`,
`azure/install.sh` and `gcp/install.sh`), the public-mirror allowlist rule, the bootstrap tests in
`tests/bootstrap/`, and PR ordering for publication are in
[`docs/discovery-bootstrap.md`](docs/discovery-bootstrap.md). Read it before touching a bootstrap
script, `pyproject.toml` packaging, or adding any file that might be published. The three
`fetch_source` blocks must stay byte-identical (`tests/bootstrap/test_drift.py` enforces it).
A new top-level module in `aws/` must be added to `py-modules` in `aws/pyproject.toml`;
`aws/tests/test_packaging.py` enforces it.
