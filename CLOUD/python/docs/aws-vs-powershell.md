# AWS: Python and PowerShell output compared

What differs between the Python tool and `Get-AWSSizingInfo.ps1`, and why. It comes from running both on one account and
comparing the zips file by file, and the totals block against the PowerShell log line by line. Treat the specifics as one
account's results, not a guarantee for every account.

## Output files

| Area | Result | Why |
|------|--------|-----|
| Most files | Identical to the byte (RDS, DynamoDB, EFS, EKS, KMS, IAM, Secrets, SQS and more) | Same data and the same columns in the same order |
| Files with tags (EC2 instances, attached volumes, load balancers, VPCs) | Same rows and values; the **tag columns come in a different order** | Python lists tag columns in the order it first sees them, which follows its row order (accounts, regions in the order AWS lists them, then the order AWS returns resources in); whether that repeats between runs has not been checked. PowerShell's order comes from a hash table |
| S3 buckets | PowerShell showed tags on buckets that have none | See below |
| S3 Tables | `CompactionEnabled` and `SnapshotManagementEnabled` were blank in PowerShell and `True` in Python | See below |
| Cost files | Empty in Python when the run used `--no-cost` | The cost scan was off; run without the option to compare |
| Backup plans JSON | An empty file in PowerShell, `[]` in Python | Both mean no plans; Python's is valid JSON |
| Files only in Python | `aws_preflight_check-*.csv` and `aws_sizing_discovery.json` | The access check and the JSON record |

### S3 tags

When PowerShell cannot read a bucket's tags ("The TagSet does not exist", which is what AWS answers for a bucket with no
tags), it keeps the previous bucket's tags in a variable and writes them to the next row. In the comparison, each bucket
where PowerShell showed tags and Python did not had exactly the previous row's tags, and PowerShell had logged the failure
for each of them. Python leaves those cells blank. The Python figure is the correct one.

### S3 Tables maintenance flags

Python reads the flags from the table's maintenance configuration and reported `True` for all five tables. PowerShell left
the column blank for all five and logged no failure, so its call did not fail.

**The cause is a spelling difference in the script.** The AWS SDK returns the settings as a
`Dictionary<string, TableMaintenanceConfigurationValue>`, and the service names its keys `icebergCompaction` and
`icebergSnapshotManagement` (both checked: the type in the SDK assembly, the key names in botocore's service model). The
script reads `$maint.Configuration.IcebergCompaction` with a capital `I`. A .NET dictionary is case-sensitive, so that
lookup finds nothing, silently, and the column stays blank. With the exact spelling it returns the value. Python reads the
keys as the service spells them, so its `True` is correct. The fix is in the script: read the keys as the service spells
them, for example `$maint.Configuration['icebergCompaction']`. The lookups were run on a dictionary built from the SDK's
own type; the cmdlet itself was not run.

`CompactionEnabled` can also come from the table's metadata file when the maintenance settings are unknown, but these five
tables had no metadata location in either tool (and no CloudWatch data), so that fallback and the size, file-count and
manifest columns were not exercised by real data. `SnapshotManagementEnabled` has no fallback in either tool.

Python now prints how many tables have each flag on, off or unknown in the totals block, and names the maintenance call in
the log if it fails, so a blank cell can be explained.

### S3 sizes of buckets that hold Glue Iceberg data

Both tools take a Glue Iceberg table's bytes out of its bucket's storage classes, largest class first, so the same bytes
are not counted twice. PowerShell writes every bucket's `<class>_SizeGiB` as bytes / 2^30 / 1.073741824, but rewrites a
class it took Iceberg bytes from with bytes / 2^30, so that class's `_SizeGiB` and `_SizeTiB` come out about 7.4% higher
than the same bytes would give in any other bucket. `_SizeBytes`, `_SizeGB`, `_SizeTB` and the totals use one formula
throughout. Python writes these columns as PowerShell does: the classes it deducted from get PowerShell's second formula.
The Glue Iceberg file was empty in the comparison runs, so this follows the script, not a comparison of real data.

## Logs and the screen

| Area | PowerShell | Python |
|------|------------|--------|
| Log format | A PowerShell transcript, with machine and version details | A transcript of the screen, a header (commit, packages, options) and a closing summary |
| Line timestamps | None; start and end as `yyyyMMddHHmmss` | `HH:MM:SS` on each log line |
| Totals block | Yes | Yes, with the same wording and numbers (see below) |
| Access check | None | A table of what the sign-in can read, before the scan |
| Errors | Red "TagSet does not exist" for every untagged bucket, and one for each region where Storage Lens cannot be set up | Not reported: an untagged bucket and a region that cannot host Storage Lens are not problems. Real failures are listed once, with a fix |
| Prompts | Not logged | Each question and the answer are logged |

The totals block is built from the same rows as the CSV files. For the account compared, all 48 lines of PowerShell's
totals matched, and so did the cost lines (computed from PowerShell's own cost files). PowerShell prints sums with 15
significant digits, and Python does the same. The block adds two lines PowerShell does not have: the S3 Tables flag
counts above.

## Timestamps

The cells that hold dates have the same format in both tools. File names carry the local time of the machine that ran
the tool (`yyyy-MM-dd_HHmmss`), so a run in CloudShell and a run on a laptop in another time zone show different stamps for
runs that were minutes apart. The JSON record's `generated_at` is UTC.
