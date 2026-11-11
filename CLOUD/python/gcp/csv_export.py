"""PowerShell-compatible CSV export of the GCP discovery results.

Writes files that ``Get-GCPSizingInfo.ps1`` writes, with the same names, column names and column
order. This module covers the VM, attached disk, unattached disk, Cloud SQL and Spanner files.

Rows are built from the discovery JSON, so the same code serves a live run, a mock run and a saved
result. Quoting follows ``Export-Csv``: every value is quoted except a null, which is an empty,
unquoted field (an empty string is ``""``), and a file with no rows is empty (no header), as
PowerShell writes it. Files use ``\\n`` line ends, UTF-8 and no BOM.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from anonymize import Anonymizer, file_rank

FILE_TIMESTAMP_FORMAT = "%Y-%m-%d_%H%M%S"

LABEL_PREFIX = "Label/Tag: "
_NOT_ALPHANUMERIC = re.compile(r"[^a-zA-Z0-9]")


def _format(value: Any) -> str:
    if isinstance(value, bool):
        return "True" if value else "False"
    if isinstance(value, float):
        return _format_float(value)
    return str(value)


def _format_float(value: float) -> str:
    """A double as .NET writes it: positional below 1e17, scientific (``1E-05``) from there."""
    text = repr(value)
    if "e" not in text:
        return text[:-2] if text.endswith(".0") else text
    mantissa, exponent = text.split("e")
    if 0 < int(exponent) < 17:
        digits = mantissa.replace("-", "").replace(".", "")
        sign = "-" if value < 0 else ""
        return sign + digits + "0" * (int(exponent) + 1 - len(digits))
    return text.replace("e", "E")


def render(columns: list[str], rows: list[dict[str, Any]]) -> str:
    """CSV text for ``rows`` under ``columns``; a missing key is a null. No rows gives ``""``."""
    if not rows:
        return ""

    def quote(text: str) -> str:
        return '"' + text.replace('"', '""') + '"'

    lines = [",".join(quote(c) for c in columns)]
    for row in rows:
        lines.append(
            ",".join("" if row.get(c) is None else quote(_format(row[c])) for c in columns)
        )
    return "\n".join(lines) + "\n"


def _ps_sum(values: list[float]) -> float:
    """A running total in order, as ``$total += $value`` adds (``sum()`` is compensated)."""
    total = 0.0
    for value in values:
        total += value
    return total


def _ps_round(value: float, digits: int) -> float:
    """``[math]::Round($value, $digits)``.

    .NET scales by 10**digits, rounds half to even and scales back, so it is not Python's
    ``round(value, digits)``: 12.345 gives 12.34 here (12.35 in Python) because 12.345 * 100 is
    exactly 1234.5.
    """
    if abs(value) < 1e16:
        power = 10.0**digits
        return round(value * power) / power
    return value


def _gib_tib(gib: float, prefix: str) -> dict[str, float]:
    """The ``{prefix}GiB`` and ``{prefix}TiB`` cells of ``ConvertTo-GCPSizeUnits -InputUnit GiB``.

    Compute Engine's ``sizeGb`` is a binary gigabyte (1 GB = 2**30 bytes), so it is already GiB and
    a TiB is 1024 of them. Both are rounded to four decimals.
    """
    return {f"{prefix}GiB": _ps_round(gib, 4), f"{prefix}TiB": _ps_round(gib / 1024, 4)}


def _short(path: Optional[str]) -> Optional[str]:
    """The last segment of a resource path: ``zones/us-central1-a`` -> ``us-central1-a``."""
    return path.split("/")[-1] if path else None


def _label_cells(
    labels: Optional[dict[str, str]],
    prefix: str = LABEL_PREFIX,
    cells: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """``Label/Tag: <key>`` cells; every character outside ``a-zA-Z0-9`` in a key becomes ``_``.

    Two keys that become the same name (``a-b`` and ``a_b``) leave one column that holds the later
    value and sits after the others: ``Add-Member -Force`` removes the old member and adds the new
    one at the end. GCP label keys are lowercase, so names never differ by case.

    ``cells`` is the row to add to, as ``Add-LabelsToObject`` adds to an object: a label whose column
    already exists there (a dataset label and a table label with the same name) moves to the end.
    """
    cells = {} if cells is None else cells
    for key, value in (labels or {}).items():
        name = f"{prefix}{_NOT_ALPHANUMERIC.sub('_', key)}"
        cells.pop(name, None)
        cells[name] = value
    return cells


def _object_text(fields: Optional[dict[str, str]]) -> Optional[str]:
    """How PowerShell writes a custom object in a cell: ``@{a=1; b=2}``."""
    if not fields:
        return None
    return "@{" + "; ".join(f"{k}={v}" for k, v in fields.items()) + "}"


def _image_parts(source_image: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    """The image's project and name: ``split('/')[-4]`` and ``[-1]`` of its path."""
    parts = (source_image or "").split("/")
    return (parts[-4], parts[-1]) if len(parts) >= 4 else (None, None)


def _compute_entries(result: dict) -> list[dict]:
    """The per-project compute inventories, in the order the projects were scanned."""
    order = {pid: i for i, pid in enumerate(result.get("projects_scanned") or [])}
    entries = result.get("compute") or []
    return sorted(entries, key=lambda e: order.get(e.get("project_id"), len(order)))


def _resolved(instance: dict) -> list[dict]:
    """The attached disks the project's disk list returned. PowerShell skips the others, so
    they are in no row and not in the VM's counts.
    """
    return [d for d in instance.get("disks") or [] if d.get("disk_id")]


# ── gce_vm_info ───────────────────────────────────────────────────────────────

_VM_COLUMNS = [
    "Project",
    "Zone",
    "Name",
    "TotalDiskCount",
    "TotalDiskSizeGb",
    "TotalDiskSizeTb",
    "TotalDiskSizeGiB",
    "TotalDiskSizeTiB",
    "EncryptedDisksCount",
    "EncryptedDisksSizeGb",
    "EncryptedDisksSizeTb",
    "EncryptedDisksSizeGiB",
    "EncryptedDisksSizeTiB",
    "Status",
]


def _vm_rows(result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in _compute_entries(result):
        for instance in entry.get("instances") or []:
            disks = _resolved(instance)
            encrypted = [d for d in disks if d.get("encrypted")]
            size = _ps_sum([float(d.get("size_gb") or 0) for d in disks])
            encrypted_size = _ps_sum([float(d.get("size_gb") or 0) for d in encrypted])
            rows.append(
                {
                    "Project": entry.get("project_id"),
                    "Zone": _short(instance.get("zone")),
                    "Name": instance.get("name"),
                    "TotalDiskCount": len(disks),
                    "TotalDiskSizeGb": size,
                    "TotalDiskSizeTb": size / 1000,
                    **_gib_tib(size, "TotalDiskSize"),
                    "EncryptedDisksCount": len(encrypted),
                    "EncryptedDisksSizeGb": encrypted_size,
                    "EncryptedDisksSizeTb": encrypted_size / 1000,
                    **_gib_tib(encrypted_size, "EncryptedDisksSize"),
                    "Status": instance.get("status"),
                    **_label_cells(instance.get("labels")),
                }
            )
    return rows


# ── gce_attached_disk_info and gce_unattached_disk_info ───────────────────────

_ATTACHED_COLUMNS = [
    "Project",
    "Zone",
    "VMName",
    "DiskName",
    "Id",
    "SizeGb",
    "SizeTb",
    "SizeGiB",
    "SizeTiB",
    "DiskEncryptionKey",
    "SourceImageSource",
    "SourceImageName",
]

_UNATTACHED_COLUMNS = [c for c in _ATTACHED_COLUMNS if c != "VMName"]


def _disk_row(project: Optional[str], disk: dict, key: Any, vm: Optional[str]) -> dict[str, Any]:
    size = float(disk.get("size_gb") or 0)
    image_project, image_name = _image_parts(disk.get("source_image"))
    row: dict[str, Any] = {"Project": project, "Zone": _short(disk.get("zone"))}
    if vm is not None:
        row["VMName"] = vm
    row.update(
        {
            "DiskName": disk.get("name"),
            "Id": disk.get("disk_id"),
            "SizeGb": size,
            "SizeTb": size / 1000,
            **_gib_tib(size, "Size"),
            "DiskEncryptionKey": key,
            "SourceImageSource": image_project,
            "SourceImageName": image_name,
            **_label_cells(disk.get("labels")),
        }
    )
    return row


def _attached_rows(result: dict) -> list[dict[str, Any]]:
    """One row per disk of a VM; the key column is whether the disk has an encryption key."""
    return [
        _disk_row(entry.get("project_id"), disk, bool(disk.get("encrypted")), instance.get("name"))
        for entry in _compute_entries(result)
        for instance in entry.get("instances") or []
        for disk in _resolved(instance)
    ]


def _unattached_rows(result: dict) -> list[dict[str, Any]]:
    """One row per disk nothing uses; the key column is the key object's text, or empty."""
    return [
        _disk_row(entry.get("project_id"), disk, _object_text(disk.get("encryption_key")), None)
        for entry in _compute_entries(result)
        for disk in entry.get("unattached_disks") or []
    ]


# ── gce_cloudsql_info and gce_spanner_info ────────────────────────────────────

_CLOUDSQL_COLUMNS = [
    "Project",
    "InstanceName",
    "InstanceType",
    "DatabaseEngine",
    "EngineVersion",
    "Region",
    "Tier",
    "StorageSizeGb",
    "StorageSizeTb",
    "StorageType",
    "State",
    "NumberOfDatabases",
    "BackupEnabled",
    "BackupRetentionCount",
    "BackupStartTime",
    "AvailabilityType",
]

_ENGINES = (("POSTGRES", "PostgreSQL"), ("MYSQL", "MySQL"), ("SQLSERVER", "SQL Server"))


def _engine(database_version: Optional[str]) -> Optional[str]:
    """The script's ``switch -Regex`` on the database version prefix; any other version is
    written as it is.
    """
    version = database_version or ""
    for prefix, engine in _ENGINES:
        if version.upper().startswith(prefix):
            return engine
    return database_version or None


def _database_entries(result: dict) -> list[dict]:
    """The per-project database inventories, in the order the projects were scanned."""
    order = {pid: i for i, pid in enumerate(result.get("projects_scanned") or [])}
    entries = result.get("databases") or []
    return sorted(entries, key=lambda e: order.get(e.get("project_id"), len(order)))


def _cloudsql_rows(result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in _database_entries(result):
        for sql in entry.get("cloud_sql_instances") or []:
            size = sql.get("data_disk_size_gb")
            rows.append(
                {
                    "Project": entry.get("project_id"),
                    "InstanceName": sql.get("name"),
                    "InstanceType": sql.get("instance_type") or None,
                    "DatabaseEngine": _engine(sql.get("database_version")),
                    "EngineVersion": sql.get("database_version") or None,
                    "Region": sql.get("region") or None,
                    "Tier": sql.get("tier") or None,
                    "StorageSizeGb": float(size) if size else 0,
                    "StorageSizeTb": float(size) / 1000 if size else 0,
                    "StorageType": sql.get("storage_type") or None,
                    "State": sql.get("state") or None,
                    "NumberOfDatabases": sql.get("number_of_databases"),
                    "BackupEnabled": bool(sql.get("automated_backup_enabled")),
                    "BackupRetentionCount": sql.get("backup_retention_count"),
                    "BackupStartTime": sql.get("backup_start_time"),
                    "AvailabilityType": sql.get("availability_type"),
                    **_label_cells(sql.get("labels")),
                }
            )
    return rows


_SPANNER_COLUMNS = [
    "Project",
    "InstanceName",
    "DisplayName",
    "Config",
    "State",
    "NumberOfDatabases",
    "NodeCount",
    "ProcessingUnits",
]


def _spanner_rows(result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in _database_entries(result):
        for spanner in entry.get("spanner_instances") or []:
            rows.append(
                {
                    "Project": entry.get("project_id"),
                    "InstanceName": spanner.get("name"),
                    "DisplayName": spanner.get("display_name") or None,
                    "Config": spanner.get("config") or None,
                    "State": spanner.get("state"),
                    "NumberOfDatabases": spanner.get("database_count", 0),
                    "NodeCount": spanner.get("node_count") or 0,
                    "ProcessingUnits": spanner.get("processing_units") or 0,
                    **_label_cells(spanner.get("labels")),
                }
            )
    return rows


# ── files ─────────────────────────────────────────────────────────────────────


# ── gce_bigquery_info ─────────────────────────────────────────────────────────

_BIGQUERY_SIZES = ("TotalLogicalSize", "ActiveLogicalSize", "LongTermLogicalSize")
_BIGQUERY_COLUMNS = [
    "Project",
    "DatasetId",
    "Location",
    "TableId",
    "TableType",
    "NumRows",
    "NumberOfColumns",
    *[
        f"{prefix}{suffix}"
        for prefix in _BIGQUERY_SIZES
        for suffix in ("Bytes", "Gb", "Tb", "GiB", "TiB")
    ],
    "ExternalSourceFormat",
    "ExternalSourceUri",
    "CreationTime",
    "LastModifiedTime",
]


def _bigquery_entries(result: dict) -> list[dict]:
    """The per-project BigQuery inventories, in the order the projects were scanned."""
    order = {pid: i for i, pid in enumerate(result.get("projects_scanned") or [])}
    entries = result.get("bigquery") or []
    return sorted(entries, key=lambda e: order.get(e.get("project_id"), len(order)))


def _bytes_units(num_bytes: float, prefix: str) -> dict[str, float]:
    """``ConvertTo-GCPSizeUnits -InputUnit Bytes`` as the BigQuery rows call it.

    GiB and GB are written to four decimals, TiB and TB to six. GB and TB are decimal (10**9 and
    10**12 bytes); GiB and TiB are binary (2**30 and 2**40 bytes).
    """
    gib = num_bytes / 1073741824
    gb = num_bytes / 1000000000
    return {
        f"{prefix}Gb": _ps_round(gb, 4),
        f"{prefix}Tb": _ps_round(gb / 1000, 6),
        f"{prefix}GiB": _ps_round(gib, 4),
        f"{prefix}TiB": _ps_round(gib / 1024, 6),
    }


def _bigquery_rows(result: dict) -> list[dict[str, Any]]:
    rows = []
    for entry in _bigquery_entries(result):
        for table in entry.get("tables") or []:
            total = int(table.get("total_logical_bytes") or 0)
            long_term = int(table.get("long_term_logical_bytes") or 0)
            active = max(0, total - long_term)
            row: dict[str, Any] = {
                "Project": entry.get("project_id"),
                "DatasetId": table.get("dataset_id"),
                "Location": table.get("location"),
                "TableId": table.get("table_id"),
                "TableType": table.get("table_type"),
                "NumRows": int(table.get("num_rows") or 0),
                "NumberOfColumns": int(table.get("number_of_columns") or 0),
            }
            for prefix, size in zip(_BIGQUERY_SIZES, (total, active, long_term)):
                row[f"{prefix}Bytes"] = size
                row.update(_bytes_units(size, prefix))
            row.update(
                {
                    "ExternalSourceFormat": table.get("external_source_format"),
                    "ExternalSourceUri": table.get("external_source_uri"),
                    "CreationTime": table.get("creation_time"),
                    "LastModifiedTime": table.get("last_modified_time"),
                }
            )
            _label_cells(table.get("dataset_labels"), f"{LABEL_PREFIX}dataset_", row)
            _label_cells(table.get("labels"), LABEL_PREFIX, row)
            rows.append(row)
    return rows


@dataclass(frozen=True)
class FileSpec:
    """One output file: its name prefix, fixed columns and row builder."""

    prefix: str
    columns: list[str]
    rows: Callable[[dict], list[dict[str, Any]]]


FILES: list[FileSpec] = [
    FileSpec("gce_vm_info", _VM_COLUMNS, _vm_rows),
    FileSpec("gce_attached_disk_info", _ATTACHED_COLUMNS, _attached_rows),
    FileSpec("gce_unattached_disk_info", _UNATTACHED_COLUMNS, _unattached_rows),
    FileSpec("gce_cloudsql_info", _CLOUDSQL_COLUMNS, _cloudsql_rows),
    FileSpec("gce_spanner_info", _SPANNER_COLUMNS, _spanner_rows),
    FileSpec("gce_bigquery_info", _BIGQUERY_COLUMNS, _bigquery_rows),
]


def _header(spec: FileSpec, rows: list[dict[str, Any]]) -> list[str]:
    """The fixed columns, then the label columns in the order the rows first have them.

    PowerShell adds the missing labels to every row in a hashtable's order, which changes from
    one run to the next; this order does not.
    """
    extra = [name for row in rows for name in row if name not in spec.columns]
    return [*spec.columns, *dict.fromkeys(extra)]


def rows_by_file(result: dict) -> dict[str, list[dict[str, Any]]]:
    """File prefix -> the row dicts that file is built from, before anonymizing.

    The same data the CSV files hold, so totals computed from it match the files.
    """
    return {spec.prefix: spec.rows(result) for spec in FILES}


def build_csv_files(
    result: dict, stamp: str, anonymizer: Optional[Anonymizer] = None
) -> dict[str, str]:
    """File name -> CSV text for every file in ``FILES``. ``stamp`` is the file name timestamp.

    With an ``anonymizer`` the values are replaced as the files are built, in the order PowerShell
    anonymizes its lists in, so the numbers in the labels follow the same order.
    """
    order = sorted(FILES, key=lambda s: file_rank(s.prefix)) if anonymizer else FILES
    texts = {}
    for spec in order:
        rows = spec.rows(result)
        if anonymizer is not None:
            rows = [anonymizer.anonymize_row(row) for row in rows]
        texts[spec.prefix] = render(_header(spec, rows), rows)
    return {f"{spec.prefix}-{stamp}.csv": texts[spec.prefix] for spec in FILES}
