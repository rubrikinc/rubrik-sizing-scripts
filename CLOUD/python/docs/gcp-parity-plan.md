# GCP parity plan

What is needed to bring `gcp/` to parity with `Get-GCPSizingInfo.ps1`, in the order the work should land. Each
item is its own PR into `cloud_sizing_script_python`, like the AWS and Azure slices. Tick the box in the PR that
finishes the item. Task ids `GCP-n` are the ones in `powershell-parameter-mapping.md`; the other labels are new.
The specs for GCP-4, GCP-5, GCP-7 and GCP-8 are not in this repo, so their scope has to be confirmed first.

## Where it stands

The PowerShell script writes five CSV files and nothing else:

| File | Rows |
|---|---|
| `gce_vm_info-<stamp>.csv` | one per VM: disk counts and sizes, encrypted disk counts, status, labels |
| `gce_attached_disk_info-<stamp>.csv` | one per disk attached to a VM |
| `gce_unattached_disk_info-<stamp>.csv` | one per disk with no users |
| `gce_cloudsql_info-<stamp>.csv` | one per Cloud SQL instance |
| `gce_spanner_info-<stamp>.csv` | one per Spanner instance |

They go into `gcp_sizing_results_<yyyy-MM-dd_HHmmss>.zip` with `output_gcp_<yyyy-MM-dd_HHmmss>.log`. The script takes
`-GetAllProjects`, `-Projects`, `-ProjectFile`, `-Anonymize`, `-AnonymizeFields` and `-NotAnonymizeFields`.

The Python tool writes `gcp-sizing-discovery-<stamp>.json` (through a streaming writer for large runs) and bundles it
with the run log into `gcp-sizing-discovery-<stamp>.zip` (`_finalise_zip` in `main.py`). It has no CSV files, none of
the PowerShell file, zip or log names and no anonymization, and its models lack several of the columns above.
Project selection (GCP-1, #2697) and the disk and Spanner fixes (GCP-2, GCP-3, GCP-6) are done.

Anonymization works on the CSV files, so the CSV export has to come first. The Azure work (#2745 to #2774) is the
pattern: an exporter built from the JSON, checked against the script's own code in `pwsh`.

## Items

- [ ] **G-CSV-1 Export framework, VMs and disks.** A `gcp/csv_export.py` (rendering, empty-file rule, .NET number text
  and `[math]::round` where the script rounds) and `gce_vm_info`, `gce_attached_disk_info`, `gce_unattached_disk_info`.
  The collectors must also record:
  - the numeric disk `id`, whether the disk has an encryption key, and (for unattached disks) the key object, which the
    script writes as `@{...}` text
  - the source image's project and name (the script splits the path), and labels on unattached disks
  - per VM the number and size of encrypted disks and the disk count the script uses
- [ ] **G-CSV-2 Cloud SQL and Spanner.** `gce_cloudsql_info` and `gce_spanner_info`. Cloud SQL also needs the instance
  type, the engine derived from the version prefix, the full version string, the backup retention count and start
  time, the availability type as text (`REGIONAL`, `ZONAL`) and the number of user databases (each engine has its own
  list of system databases to leave out). Spanner already has the node count, processing units and database count.
- [ ] **G-ZIP Names, zip and log.** `_finalise_zip` writes `gcp_sizing_results_<yyyy-MM-dd_HHmmss>.zip` with
  `output_gcp_<stamp>.log`, the CSVs and the JSON inside, and `--no-csv` keeps the JSON only, as in the AWS and Azure
  tools. The runs that use the streaming writer must produce the same files.
- [ ] **G-ANON Anonymization.** `--anonymize`, `--anonymize-fields`, `--not-anonymize-fields` and the
  `gcp_anonymized_keys_to_actual_values-<stamp>.csv` file and `output_gcp_not_anonymized_<stamp>.log` beside the zip.
  The script's rules differ from the other two clouds: 8 default fields (`Name`, `Project`, `VMName`, `DiskName`, `Id`,
  `DiskEncryptionKey`, `InstanceName`, `DisplayName`), label columns named `Label/Tag: <key>` (a 10 character prefix)
  renamed to `Label/Tag:Label/TagName-<n>` with values `Label/TagValue-<n>`, files anonymized in the order VMs,
  attached disks, unattached disks, Cloud SQL, Spanner. Reuse `azure/anonymize.py` and check it against the script's
  own `Anonymize-Data` in `pwsh`.
- [ ] **G-PKG Packaging.** `gcp/pyproject.toml` lists `main, auth, config, logging_setup, streaming_writer`. Add
  `csv_export` and `anonymize` with a test that every top-level module is listed (as `aws/tests/test_packaging.py`
  does); `main` will import both.
- [ ] **G-Q1 Parity harness in the repo.** The script calls `gcloud` and parses its JSON. Stub `gcloud` in `pwsh`, run the
  script's real row builders (`Get-GCEInstancesAndDisks`, `Get-GCEUnattachedDisks`, `Get-GCPCloudSQLInstances`,
  `Get-GCPSpannerInstances`) on JSON fixtures, and compare the CSV text with the exporter.
- [ ] **G-Q2 Real project run.** Run the script and the Python tool on the same projects and compare. Open points:
  how `Label/Tag:` columns and `DiskEncryptionKey` text look in a real export, regional disks, and Cloud SQL replicas.
- [ ] **G-Q3 Describe it in #2719, and keep the mapping table and `python/CLAUDE.md` current.**

## PowerShell behavior to know about

| Where | PowerShell | Plan |
|---|---|---|
| Label columns | added only to rows that have the label; `Add-TagsToAllObjectsInList` then fills the gaps with null, in hashtable order, so the column order is not stable | columns in the order labels are first met; a missing label is empty |
| Label names | the key has every character outside `a-zA-Z0-9` replaced by `_` | the same |
| `DiskEncryptionKey` | a boolean for an attached disk, the key object's text for an unattached disk | the same, written as PowerShell writes the object |
| Sizes | `SizeTb` is the GB value divided by 1000, not rounded | the same, with .NET number text |
| `NumberOfDatabases` | 0 when the listing fails | decide: copy, or leave empty and record the error as elsewhere |
| Disks of a VM | a disk whose `describe` fails is skipped, so the VM's counts leave it out | decide |

Run in `pwsh` 7.6.5 with the script's own code: the label prefix and the leading space in the label name, the `_`
replacement, the boolean and object forms of `DiskEncryptionKey` (including an empty cell when there is no key), the
unrounded `SizeTb`, the label column order (eight separate runs gave seven different orders), and the anonymizer
(its 8 default fields, `Label/Tag:Label/TagName-00000` for a renamed label column, `Label/TagValue-00000` for its value,
a null label value left empty, and the key file holding the label name with its leading space). Read from the code
and not run: the 0 for `NumberOfDatabases` when listing fails, the skipped disk, and the order of the lists.

## Decisions for the owner

- Whether the GCP exporter writes all label columns (a union) as PowerShell does, or only labels that exist.
- Whether `NumberOfDatabases` should be empty rather than 0 when the listing fails.
- The order of the work: CSV first (G-CSV-1, G-CSV-2, G-ZIP), then anonymization.
