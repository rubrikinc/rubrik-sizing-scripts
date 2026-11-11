# GCP: Python and PowerShell output compared

What differs between the Python tool and `Get-GCPSizingInfo.ps1`, and why. It comes from running both on the same five
projects and comparing the zips file by file, and the totals block against the PowerShell log line by line. Treat the
specifics as one set of projects, not a guarantee for every account.

## Output files

| Area | Result | Why |
|------|--------|-----|
| VMs, attached and unattached disks, Cloud SQL | The same rows and values (two of the files byte-identical) | Same data, same columns |
| BigQuery | The same 84 rows, values and row order | Same data |
| Label columns | The same columns in a **different order** | Python lists label columns in the order it first sees them, and it lists the VMs by zone and name, so the order repeats between runs. PowerShell's order comes from a hash table and varies |
| VM and unattached disk rows | The same rows in a different order | Python lists them by zone and name, because the API returns the zones in no fixed order (two Python runs on the same projects had listed the same VMs in different orders). PowerShell keeps the order the API gave |
| Spanner | PowerShell wrote an empty file; Python wrote the one instance | See below |
| Files only in Python | `gcp_preflight_check-*.csv` and `gcp-sizing-discovery-*.json` | The access check and the JSON record |
| Empty collections | A 0-byte file with no header in both tools | Same behaviour |

### Spanner

In one project PowerShell's Spanner call was refused (`USER_PROJECT_DENIED`, which asks for permission to use the project
for billing). It then printed "Total # of Spanner instances: 0" and wrote an empty file, with nothing in the output to say
the count was not real. Python's call for the same project succeeded and found an instance, and its CSV and totals agree.
**Why the two calls differ is not established**: PowerShell runs `gcloud` as the signed-in user in Cloud Shell, and Python
uses application-default credentials, which carry a quota project. If the Spanner number matters, check the project in the
console.

### Projects PowerShell cannot list services for

When `gcloud services list` is refused for a project, PowerShell reports that the Compute, Cloud SQL, Spanner and BigQuery
APIs are "not enabled" and skips them, although the APIs may be on and only the listing is denied. Python calls each API
and tells "API not enabled" from "access denied" in the access check.

## Logs and the screen

| Area | PowerShell | Python |
|------|------------|--------|
| Log format | A PowerShell transcript, with machine and version details | A transcript of the screen, a header (commit, packages, options) and a closing summary |
| Errors | `gcloud` error dumps, with help tokens and metadata blocks | Each problem once, with the projects it affected and a fix |
| Totals block | Yes | Yes, with the same wording; the numbers matched on 13 of 14 lines and the Spanner line differs as above |
| Per-project table | None | Instances, disk, buckets, databases and protected VMs per project |
| Access check | None | A table of what the sign-in can read, before the scan |

The totals block is built from the same rows as the CSV files, so it cannot disagree with them, and it holds only counts and
sizes. PowerShell prints sums with 15 significant digits, and Python does the same.

## Timestamps

The cells that hold dates have the same format in both tools. Python names its files and its zip with the **UTC** time of
the run (`yyyy-MM-dd_HHmmss`), while the times on its log lines are local, so on a laptop outside UTC the two differ. The
JSON record's name uses a compact form (`yyyyMMdd-HHmmss`) and its `generated_at` is UTC. PowerShell stamps with the clock
of the machine it runs on, which in Cloud Shell is likely UTC. The AWS tool stamps its files in local time.
