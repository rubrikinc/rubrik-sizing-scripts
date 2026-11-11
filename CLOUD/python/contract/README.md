# Output contract: column extraction (B1)

`columns.json` lists the columns of every file the PowerShell sizing scripts write, in order.
The PowerShell code is authoritative. The samples in `EXAMPLES/` are stale (older schema), so
do not use them as the source.

## How it is built
1. `dump_ast.ps1` parses a script with the PowerShell parser (it does not run it) and prints
   JSON facts: `[PSCustomObject]@{}` / `[ordered]@{}` row constructors, `.Add("k", ...)`,
   `["k"] = ...` and `Add-Member` calls, `Add-BackupColumnsToRow` calls, and `Export-Csv` sites.
2. `sources.json` says which constructor(s) feed which `$output*` file. A file's `"dynamic"` list adds column
   patterns a helper writes that the parser does not follow, such as BigQuery's `Add-LabelsToObject` labels.
3. `build_columns.py` joins them. Helper-added columns (`Add-BackupColumnsToRow`) are expanded
   from the helper's own body. Output names come from the `$output*` string literals.

```
cd sizing_scripts/cloud/python
python -m contract.build_columns           # regenerate columns.json (needs pwsh)
python -m contract.build_columns --check   # exit 1 if columns.json is out of date
```

## Reading columns.json
Per file: `columns` (ordered, with `optional: true` when the column is added only on some
code paths, for example per-engine FSx fields or Azure SQL database rows), `dynamic`
(patterns that depend on the data, such as `Tag: {key}`), and `sources` (function, variable
and line of the constructors). `status` is:

- `resolved`: columns fully determined from the script.
- `partial`: some columns are decided at run time (AWS S3). See `notes`.
- `unresolved`: rows are raw Azure cmdlet objects, so columns come from the module type
  (Azure backup vaults and items). These need the live parity run (B3).

Lines in `sources` and `export_line` are informational and change when the script is edited.
Order in `columns` is constructor order; the final CSV is also affected by
`Add-TagsToAllObjectsInList` (union of properties across rows), which is described by `dynamic`.

## Known limits
- Backup plans and the Azure policy dumps are JSON, not CSV, and are not covered.
- `aws_s3_info` per-storage-class columns and final order are computed at run time.
- Conditional columns use control-flow nesting, not data conditions. A column marked optional
  may be present in every real run.

## Using the contract (B2)
`contract.py` turns `columns.json` plus the file-name and value-format rules into one
checkable contract:

```python
from contract.contract import Contract, assert_conforms

c = Contract.load()
c.spec("aws_rds_info").file_name("2025-01-31_093015")   # aws_rds_info-2025-01-31_093015.csv
assert_conforms(c, produced_file_name, produced_header)  # for emitter tests
```

- File names: `{prefix}{separator}{timestamp}.{ext}`. AWS and GCP use `yyyy-MM-dd_HHmmss`,
  Azure `yyyy-MM-dd_HHmm`. The separator is whatever the PowerShell script uses; the Azure
  summary file uses an underscore, which is open decision DEC-8. Open decisions are data: set
  `"decision"` on the file in `sources.json`; it is carried into `columns.json` and `FileSpec.decision`.
- Headers: no duplicates; every column is a known static column or matches a dynamic pattern;
  required columns present; present static columns in contract order. Dynamic columns
  (`Tag: {key}`) may sit anywhere. `partial` files skip the order check, `unresolved` files accept
  any header. `Contract.strict_gaps()` lists them.
- Values: `VALUE_FORMAT` describes the cell rules (all fields quoted, null as empty, `True`/`False`,
  `.` decimals, header-only file when empty). Per-column value formats (rounding precision per
  unit column) are not in the contract yet.
