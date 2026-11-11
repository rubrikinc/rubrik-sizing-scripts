# Azure: Python and PowerShell output compared

What differs between the Python tool and `Get-AzureSizingInfo.ps1`, and why. It comes from running both on the same
subscription and comparing the zips file by file, and the totals block against the PowerShell log line by line. Treat the
specifics as one subscription's results, not a guarantee for every tenant. PowerShell ran in Cloud Shell with a managed
identity and found two subscriptions, only one of which had resources; Python scanned that one with cost off.

## Found by the comparison and fixed

| Area | Before | Now |
|------|--------|-----|
| SQL long-term retention | The four `LTR` columns were blank for every database, with no warning | Read correctly. The SDK's call needs the policy name as a fourth argument and the tool passed three; the error was swallowed. A failure that is not a "no policy" answer is now one warning with the count |
| VM `InstanceType` | `VirtualMachineSizeTypes.STANDARD_B1_S` for 5 of 7 VMs (the SDK returns an enum member for known sizes) | `Standard_B1s` |
| VM `Status` | `0` | `OK`, as PowerShell writes `$vm.StatusCode` |
| `Tenant` | Blank (`unknown` in the SQL files), silently | The tenant's display name, read from the ARM API; a failure is a warning that says why |
| Totals block | None | Printed as PowerShell prints it (36 of 37 lines identical on a real run) |
| VM pricing warning | Always said to check the network | Says there is nothing to fix when the service answered but had no price |
| PostgreSQL flexible servers | Collected (the run log counted 44) but written nowhere: no file, no summary section, no totals lines | `azure_postgres_info`, its section of `azure_sizing_summary` and two totals lines, as `-SkipAzurePostgreSQL` controls them in PowerShell 1.0.3. PowerShell's 44 real rows, fed back in, are reproduced cell for cell (5,236 cells). The file is not written when there is no server |
| SQL `InstanceType` | `GP_S_Gen5_1` and `S0`, the REST names (5 of 210 databases matched PowerShell) | `GP_S_Gen5` and `Standard`, as Az.Sql's `SkuName` gives them: 210 of 210 databases match. A vCore name loses its trailing capacity and a DTU name becomes its tier (`S0` to `Standard`, `P1` to `Premium`). Data warehouse names (`DW100c`) are not mapped, because no real run had one; managed instances already matched |
| Backup Vaults (Blob and PostgreSQL backup) | Not collected: no `azure_backup_data_protection_vaults`, `_items` or `_policies` file, no totals lines, and the backup columns stayed `-` and `False` | Collected with `azure-mgmt-dataprotection`, which `requirements.txt` installs, as PowerShell does with `Az.DataProtection`. The vault and item columns match the ones parsed from the PowerShell script | See `BackupPolicies` and the Backup Vault policies JSON under Still different |
| MI databases JSON (`azure_mi_db_items`) | Not written | Written: every managed-instance database with its short-term and long-term retention policies, in the 28 keys and order of `Get-AzSqlInstanceDatabase`, nested by tenant, subscription and instance. The structure and the date format are those of the real file (81 databases). Not run against real Azure | See the anonymized-run row under Still different |

## Still different

| Area | PowerShell | Python | Verdict |
|------|------------|--------|---------|
| SQL system databases | Counts each server's `master` (`GP_SYSTEM`): 22 extra rows | Leaves `master`, `tempdb`, `model` and `msdb` out of the count | A deliberate difference. Which to keep is a decision for the owner; the SQL totals follow it |
| AKS tag `rk_created_at` | `10/02/2026 20:01:15` | `2026-10-02T20:01:15Z` | The tag's value as each tool formats a date; not changed |
| Cosmos DB `DocumentCount` and `DataUsage` | Up to 16 times lower for the largest account | Higher | **Unresolved.** For that account the largest physical partition is about 34 GB across 32 partitions, so Python's 592 GB is plausible and PowerShell's 37 GB is about one partition. Check one account in the portal |
| Storage `UsedCapacityBytes` | Blank for accounts with no metric | `0` | A representation difference |
| One VM's size | 0 GiB | 30 GiB | Unresolved |
| Tag column names | `Tag: environment` | `Tag: Environment` | Azure tag keys are case-insensitive; each tool names the column from one variant |
| Files only in PowerShell | A CSV and a JSON for each kind of Recovery Services vault item and policy (empty when there are no vaults) | Not written | A parity gap |
| Container details: access | Lists blobs with the storage account key (`listKeys`) | Lists blobs with Entra ID (Storage Blob Data Reader); no keys are fetched | A deliberate difference; same blobs and sums |
| Container details: a container that cannot be listed | Repeats the previous container's numbers (`$azConBlobs` is not cleared in the `catch`) | Empty values, and the reason in the run summary | A PowerShell defect, not copied |
| Container details: totals line | `Total capacity of all Azure Containers: 0 GiB or 0 GB or 0 TiB or 0 TB` always: the `AllTiers` sums are overwritten with columns a container row does not have | The sum of the `UsedCapacityAllTiers*` columns | A PowerShell defect, not copied |
| `azure_mi_db_items` in an anonymized run | Written, with `Invoke-CollectionAnonymization` applied to the nested hashtable, which handles it as one item, so the names are probably not replaced | Left out of an anonymized run, as the AWS backup plans JSON is | A deliberate difference. Not verified against a real anonymized PowerShell run |
| Backup Vault policies JSON | Az.DataProtection's own property names, with flattened copies such as `DeleteAfterDuration` | The same names for the PostgreSQL policy shape, built from the API's JSON by a fixed table of rules. Blob policy shapes are not compared | Verified for PostgreSQL only |
| `BackupPolicies` and `InBackupPolicy` | Storage accounts, file shares and Postgres servers are flagged from the Backup Vault items (Blob and Postgres) and from the Recovery Services Azure Files items | The same, with the optional `azure-mgmt-dataprotection` package installed; without it Blob and Postgres stay `-` and `False`. Neither the Backup Vault nor the Azure Files flagging has been run against real Azure | Not yet compared |
| Postgres region | `Canada Central`, as Azure returns it | The same: this file keeps the value as typed, while the other Python files use the lower-case name | Same as PowerShell |
| Files only in Python | none | `azure_preflight_check-*.csv`, the discovery JSON | New in the Python tool |
| AKS clusters | 47 | 45 | Two clusters created that day, minutes before the runs, were gone by the time Python looked; likely short-lived |

## Logs and the screen

| Area | PowerShell | Python |
|------|------------|--------|
| Log format | A PowerShell transcript, with machine and version details | A transcript of the screen, a header (commit, packages, options) and a closing summary |
| Errors | 163 error-like lines, 80 of them "Long Term Retention is not supported" for databases that cannot have a policy | Each distinct problem once, with a fix |
| Totals block | Yes | Yes, with the same wording |
| Access check | None | A table of what the sign-in can read, before the scan |

## The totals block

The block is built from the same rows as the CSV files, so it cannot disagree with them, and it holds only counts and sizes.
A section is left out when its collector was skipped, as PowerShell leaves it out. PowerShell prints raw sums with 15
significant digits and whole numbers with thousands separators, and Python does the same. Its "Azure File storage" line has a
typo that drops the `TiB` label, and Python prints the label. The backup lines count policies and protected items by
workload from the discovery JSON; Azure SQL Database backup items are not mapped by the backup collector, so that line shows
0.

## Timestamps

The cells that hold dates have the same format in both tools, except the AKS tag above. Python names its files with the
**UTC** time of the run and writes its log lines in local time. PowerShell stamps with the clock of the machine it runs on,
which in Cloud Shell is likely UTC.
