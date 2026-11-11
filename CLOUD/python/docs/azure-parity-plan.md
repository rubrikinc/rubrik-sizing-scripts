# Azure parity plan

What is done and what is left to bring `azure/` to parity with `Get-AzureSizingInfo.ps1`. Each item is its own PR
into `cloud_sizing_script_python`, like the AWS slices. Tick the box in the PR that finishes the item. Task ids
`AZ-n` are the ones in `powershell-parameter-mapping.md`; the other labels are new. The specs for AZ-2, AZ-3, AZ-8,
AZ-10 and AZ-11 are not in this repo, so their scope has to be confirmed before they are planned.

## Done

| PR | What |
|---|---|
| #2707, #2717 | AZ-4, AZ-5: storage capacity as the one-day maximum; decimal GB and TB fields |
| #2744 | SDK enum members were written as `Kind.STORAGE_V2`; collectors now write the API value (storage, VM, SQL, Defender, backup state) |
| #2745 | `azure_vmdisk_info`, `azure_storage_account_info`, tenant name, tag names, `vmId`, extra storage metrics, `--no-csv`, PowerShell zip and log names |
| #2766 | `azure_sql_info`, `azure_mi_sql_info`: pools, retention policies, `DatabaseID`, `Status`, allocated bytes, MI database count |
| #2767 | `azure_file_share_info` |
| #2768 | `azure_backup_vault_info`, `azure_backup_costs` (Backup-only monthly query); .NET rounding in the exporter |
| #2769 | `azure_aks_info`, `azure_cosmos_db`, collected as ARM JSON with no new package |
| #2770 | `azure_sizing_summary_<stamp>.csv` |
| #2771 | AZ-6: the `-Skip*` switches |

Every exporter was compared with the real PowerShell code (the row blocks of `Get-AzureSizingInfo.ps1`, run in
`pwsh` 7.6.5 with the Az cmdlets stubbed) and writes identical files, except for the differences listed below.

## Before this lands on `master`

- [ ] **AZ-P1 Package `csv_export` and `anonymize`.** `azure/pyproject.toml` (added by #2746) lists `main, auth, cloud,
  audit_manifest, config, logging_setup`. `main` imports `anonymize` when it starts, so an installed tool fails
  straight away, and it imports `csv_export` after a scan, so without that one it writes no ZIP. Add both, and a test
  that every top-level module is listed (as `aws/tests/test_packaging.py` does). `collectors/` is a package and is
  already included.
- [ ] **AZ-P2 Audit manifest.** `audit_manifest.py` (added by #2746) needs entries for the calls added since it was
  written: `tenants.list()`, `tags.list()` (`Microsoft.Resources/subscriptions/tagNames/read`), the extra storage
  metrics (blob and file capacity, container count), `file_shares.list` and `get`, the SQL elastic pool, retention
  and managed database lists, the Backup cost query, the Cosmos DB and AKS reads, and the Cosmos DB metrics.
- [ ] **AZ-P3 Real tenant run.** Run `--dry-run`, then a scan, next to `Get-AzureSizingInfo.ps1` on the same tenant
  and compare cell by cell. Open points, none checked against Azure:
  - ~~the VM `Status` value and the `Tenant` text~~ settled by a real run: `Status` is `OK` (`$vm.StatusCode`) and `Tenant`
    is the tenant's display name, now read from the ARM API (see `docs/azure-vs-powershell.md`)
  - the Cost Management response for two aggregations and the shape of its `BillingMonth` values
  - the vault `Region` text (Python lowercases it) and whether `expand="stats"` returns share usage for every account
  - that the pinned AKS and Cosmos DB api-versions exist in every cloud, and that a cluster's `agentPoolProfiles`
    match `Get-AzAksNodePool`
  - the Monitor metric names and namespaces for Cosmos DB, the SQL storage metrics, and the VM backup-policy join
- [ ] **AZ-P4 Describe it in #2719.** The Azure part of its description is out of date: CSV files, zip and log names,
  `--no-csv`, enum values, the skip switches, new API calls and the skipped tests.

## Files still missing

Each slice also adds the data the files need, and is checked against the real PowerShell lines in `pwsh`.

- [ ] **AZ-CSV-2b MI databases JSON.** `azure_mi_db_items-<stamp>.json` (tenant, subscription, instance, then each
  database with its short-term and long-term policy as `ConvertTo-Json -Depth 10` writes the Az objects).
- [ ] **AZ-CSV-3b Containers (AZ-9).** `azure_storage_account_container_info`, opt-in (`-GetContainerDetails`) and slow:
  PowerShell lists every blob. It needs a blob data-plane listing, so a new `azure-storage-blob` dependency and a blob
  data read permission; agree that first. PowerShell counts all non-snapshot blobs in `UnknownTierBlobCount`; decide
  whether to copy it.
- [ ] **AZ-CSV-4b Backup items and policies.** The four `azure_backup_vault_*_items` CSVs and the four policy JSON
  files. Their rows are raw `Az.RecoveryServices` objects, so their columns can only be defined from a real vault.
  Also join SQL-in-VM items to the VM's `BackupPolicies` (PowerShell matches `ServerName`); only VM items are
  joined today.
- [ ] **AZ-CSV-5b Key Vault (AZ-7).** `azure_key_vault` (`-GetKeyVaultAmounts`, opt-in). The three counts come from the
  data plane and list secret, key and certificate names, so they need their own permissions and switch.

## Parameters

- [ ] **AZ-1 Subscription selection.** Default to all subscriptions, add `--subscriptions` (names), `--management-groups`
  and `--current-subscription`. `--subs` already takes ids. #2746 changes subscription handling (parallel
  subscriptions), so do this after it merges.
- [x] **D-Azure Anonymization.** `-Anonymize`, `-AnonymizeFields`, `-NotAnonymizeFields`, the
  `azure_anonymized_keys_to_actual_values-<stamp>.csv` file and the not-anonymized log beside the ZIP. Reuse the
  AWS design (`aws/anonymize.py`) and check it against PowerShell's own functions in `pwsh`.

## Quality and docs

- [ ] **AZ-Q1 Parity harness in the repo.** The `pwsh` comparisons live in `/tmp` (one script per group of files, plus a
  rounding fuzz). Move them into the repo, one case per file, and run the emitters through
  `contract.contract.assert_conforms`.
- [ ] **AZ-Q2 Python tests in CI.** Only the secret scanner runs for this code today.
- [ ] **AZ-Q3 Run guide and permissions.** An Azure run guide like the AWS one, and a least-privilege role list that
  matches the audit manifest.
- [ ] **AZ-Q4 Mapping doc and `CLAUDE.md`.** Keep `powershell-parameter-mapping.md` and the Azure CSV section in
  `python/CLAUDE.md` current with every slice.
- [ ] **AZ-Q5 Other `str()` of SDK values.** #2744 fixed the enum sites found by searching; add a check that no collector
  passes an SDK enum through `str()`.
- [ ] **AZ-Q6 Tag lookup case.** SQL, AKS and Cosmos tags are looked up case sensitively (the Az models keep them in a
  `Dictionary<string,string>`; verified for SQL and Cosmos, AKS from the model, not run). The VM and storage files
  look up ignoring case; check what `Get-AzVM` and `Get-AzStorageAccount` return for `Tags`.
- [ ] **AZ-Q7 AWS number format and rounding.** The AWS exporter rounds with Python's `round` (which differs from
  .NET's `[math]::round` on ties, about 2% of tie-prone values) and switches to scientific notation at 1e15 where
  PowerShell does at 1e17. The Azure exporter has the fixes (`_ps_round`, `_format_float`).
- [ ] **AZ-Q8 PowerShell versions.** The comparisons use PowerShell 7.6.5. `Group-Object` there returns groups
  sorted; Windows PowerShell and older 7.x return them in first-seen order, which changes the order of region lines in
  the summary and file share, SQL and MI sections. Builds on newer ICU write U+202F before `AM` and `PM`.

## Differences from PowerShell, on purpose

PowerShell gets these wrong (found by running its own code), so Python does not copy them. Details are in
`python/CLAUDE.md`.

| Where | PowerShell | Python |
|---|---|---|
| File shares | an account without Azure Files re-emits the previous account's shares | not repeated |
| SQL pools | skips a pool whose name another server already used | lists each server's pools |
| AKS `NodePoolCount` | for a one-pool cluster, writes that pool's node count | the number of pools |
| Cosmos `NameDatabaseAccountOfferType` | always empty (the Az model has no such property) | the offer type |
| Summary, VM per-region rows | one blank-region row that repeats the total | the real per-region rows |
| Summary, one-VM `HasMSSQL` group | the VM hashtable's key count as the count | 1 |
| SQL columns | the first row decides the columns, so a pool first drops the database-only ones | all columns, always |
| Sums and rounding | n/a | a plain running total and .NET rounding, copied from PowerShell |

## Decisions for the owner

- VM `Status`: `OK`, as `Get-AzVM` returns it (checked against a real PowerShell run).
- Azure window: the latest hourly maximum of the last day matches PowerShell (the last data point it reads); a wider
  fallback would not.
- Tag-name order for names with punctuation, and VM row order, differ from PowerShell (see `CLAUDE.md`).
- `Disks` counts attached managed disks; PowerShell counts storage-profile entries.
- Which PR goes to `master`: #2719, or the consolidated #2746.

Decided: the SQL file writes every column (superset); dates are `M/d/yyyy h:mm:ss AM` because the scripts force the
`en-US` culture; AKS and Cosmos DB are read as ARM JSON, with no new packages.
