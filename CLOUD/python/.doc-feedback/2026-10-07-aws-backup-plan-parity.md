# Proposed change to cloud/python/CLAUDE.md: AWS backup plan columns and file

**Date:** 2026-10-07
**Trigger:** The AWS CSV export now decides `BackupPlans` and `InBackupPlan` from the plans'
selections and writes `aws-backup-plans-info-<stamp>.json` (branch
`taylor-aws-csv-backup-parity`).

## What was out of date

- "Not written yet: the AWS Backup plans JSON (`aws-backup-plans-info`)" in "CSV output (AWS)".
- "`InBackupPlan` means AWS Backup membership only, as in PowerShell" in the Format bullet.
  PowerShell's `InBackupPlan` is "a plan selection matched the row", and `BackupPlans` is the
  matching plan names, which the Python files left empty.

## Edits made in this change (all in `cloud/python`)

- `CLAUDE.md`, "CSV output (AWS)": replaced the "Not written yet" line, added a **Backup plans
  file** bullet and a **Backup plans** bullet (matching rules, PowerShell quirks kept on
  purpose, what is deliberately not copied, the per-group fallback, failure recording and its
  resume consequences, anonymizer scope, known gaps), and reworded the Format bullet.
- `CLAUDE.md`, "CSV output (AWS)", after the comparison with real PowerShell output: the plans
  file now follows AWS.Tools 5.x (nulls, the newer keys, region order); a new **Empty files**
  bullet (zero-byte files, and the six hand-made fallbacks copied byte for byte); and a
  **Checked against real PowerShell output** bullet that says what was compared and what was not.
- `CLAUDE.md`, "Bootstrap, packaging and publishing": one line saying a new top-level module in
  `aws/` must be added to `py-modules` (`aws/tests/test_packaging.py` enforces it).
- `docs/discovery-bootstrap.md`, "Publish Surface": the AWS `PUBLISHED` list is behind the code
  (see below). Kept out of `CLAUDE.md` because that file is mirrored publicly and this one is not.

## Why

`CLAUDE.md` is the contract reviewers and the parity comparison read. Without these entries
someone comparing a Python run with a PowerShell run would treat an empty `BackupPlans`, or an
`InBackupPlan` that disagrees with the discovery JSON's `in_backup_plan`, as a bug, and would not
know that several odd-looking matches (S3 bucket ARNs, DynamoDB ARNs, unattached volumes) are
PowerShell's own behavior that the port keeps so the files agree.

## Related observations for the owning team (not doc changes)

- **Publish allowlist.** `tests/bootstrap/test_deny_list.py` `PUBLISHED["aws"]` omits
  `accounts.py`, `anonymize.py` and `csv_export.py`, which `main.py` imports, and now also
  `backup_plan_membership.py` and `plans_json.py`. A mirror built from that list would not run.
  PR-B needs all five in the filter, the manifest and `PUBLISHED`, with sign-off.
- **Summary totals.** The summary in `aws/main.py` (`_build_summary`, ~lines 528-559) still counts
  protected resources from AWS Backup's protected-resource list and native backups, while
  PowerShell's totals use the CSV `InBackupPlan` flag. Not changed here.
- **Name tag.** `csv_export._tag_columns` drops a tag named exactly `Name`; PowerShell drops it
  ignoring case. `aws_s3_tables_info` has no `Tag: Name` column (`FileSpec.tag_name` is false)
  where PowerShell writes one. Both are small CSV fixes.
- **Blank columns to confirm against a real PowerShell run** (they may be legitimately empty):
  EC2 `ProductCode`, RDS `DBClusterIdentifier` and `EngineMode` (and whether RDS cluster rows
  should exist), DynamoDB `ProvisionedThroughputLastDecreaseDateTime` and
  `...LastIncreaseDateTime`. Python writes them empty; PowerShell fills them from the API objects.
- **Azure** (`azure/csv_export.py` ~line 663): `azure_sql_info` elastic pool rows have no `Tag:`
  values because `ElasticPoolInfo` (`collectors/database.py`) has no `tags` field, while
  PowerShell fills them from `$pool.Tags`. The pool and managed-instance `Status` columns are
  empty here; whether PowerShell's models have that property is unverified.
- **GCP:** a scan of `gcp/csv_export.py` against `Get-GCPSizingInfo.ps1` found no column that is
  hard-coded where PowerShell fills a value.
- **PowerShell secrets and SQS counts use the wrong credentials** (found by running both scripts
  on one account with `-UserSpecifiedProfileNames dev`). `Get-AWSSimpleServiceCounts`
  (`Get-AWSSizingInfo.ps1` ~2937) receives `$Credential` but calls `Get-SECSecretList -Region` and
  `Get-SQSQueue -Region` without `-Credential`, unlike `Get-KMSKeyList` and the other collectors.
  Only the `AllLocalProfiles` branch calls `Set-AWSCredential` (~5550), so in the
  `UserSpecifiedProfiles` branch, and by reading the code also the cross-account, organization and
  SSO branches, those two calls use the ambient credentials. The run reported 1 secret and 3 queues
  in us-east-2 where `aws secretsmanager list-secrets` and `aws sqs list-queues` for the scanned
  profile returned none; the Python tool, which uses the scanned account's session, reported 0 and
  0. Fix: pass `-Credential $Credential` to both calls. Which account the ambient credentials
  pointed at was not checked.
- **Other PowerShell inconsistencies seen in the same runs** (the port copies them):
  `aws_redshift_info` is written from a hand-made literal when empty whose column order
  (`ResourceArn` 13th) differs from the rows' (`ResourceArn` 5th); the empty `aws_backup_costs`
  file starts with a `#TYPE` line although a non-empty one written by PowerShell 7 has none; and
  `aws-backup-plans-info-*.json` differs between AWS.Tools 4.x (zeros, false, empty lists, fewer
  keys; the file in `EXAMPLES/`) and 5.x (nulls, six more keys), so SE tooling reading it has to
  accept both.
- **Two more PowerShell bugs from the second round of real runs** (workloads: RDS, DynamoDB, EFS,
  FSx, S3, S3 Tables, Glue, EKS), neither copied by the port:
  - `Get-AWSEKSInventory` (`Get-AWSSizingInfo.ps1` ~1590 for clusters, ~1631 for node groups)
    writes each tag value as `$eks.Tags.Values.Split('\n')[$tagCounter]`. Calling `.Split()` on the
    value collection runs it per element and flattens the result, which is a bare string, not an
    array, when there is one tag, so `[0]` is its first character: a cluster tagged
    `sizing-parity-test=true` is written as `t`. With two or more tags it works. The `'\n'` is also
    a literal backslash-n in single quotes, which only works because each element is split on its
    own. Fix: iterate `$eks.Tags.GetEnumerator()` and use `.Value`.
  - `Get-AWSS3TablesInventory` (~2321) reads `$maint.Configuration.IcebergCompaction`, but
    `Configuration` is a dictionary keyed `icebergCompaction` and `icebergSnapshotManagement`, so
    both are null and `CompactionEnabled`/`SnapshotManagementEnabled` are empty for every table
    even with maintenance on. Its status values are also lower case (`enabled`); `-eq` ignores case
    so the comparison itself is fine. Fix: `$maint.Configuration['icebergCompaction']`.
- **Machine-dependent date text.** PowerShell on macOS 26 (ICU from the OS) with .NET 9.0.10 wrote
  U+202F (narrow no-break space) before `AM`/`PM` in every date cell (6 cells differed); earlier
  runs the Python code was checked against used a plain space. The Python tool cannot know which
  the customer's machine wrote, so it keeps the plain space. Anything comparing the two should
  normalize U+202F.
- **PowerShell bugs worth fixing at the source** (the port keeps them): explicit S3 and S3 Tables
  bucket ARNs never match (`($resource -split '/')[1]` is null for `arn:aws:s3:::bucket`); a
  DynamoDB selection by table ARN compares a property DynamoDB rows do not have
  (`$ddbObj.BucketName`); a failed `Get-BakBackupSelection` re-applies the previous selection's
  data; an invalid `-like` wildcard aborts the rest of the region's plans.
