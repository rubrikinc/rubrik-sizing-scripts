"""The totals block printed at the end of a run, worded as the PowerShell script words it.

Every number is a sum over the rows the CSV files are built from (``csv_export.rows_by_file``),
so the screen, the log and the files agree.
"""

from typing import Any

Rows = dict[str, list[dict[str, Any]]]


def _number(value: Any) -> str:
    """A number as PowerShell prints it: 15 significant digits, and no ``.0`` on whole numbers."""
    if isinstance(value, float):
        return format(value, ".15g")
    return str(value)


def _sum(rows: list[dict], column: str) -> Any:
    total: Any = 0
    for row in rows:
        value = row.get(column)
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            total += value
    return total


def summary_lines(
    rows: Rows, bigquery_datasets: int = 0, bigquery_failures: int = 0, bigquery_ran: bool = True
) -> list[str]:
    """The lines of the totals block, in the order the PowerShell script prints them."""
    attached = rows.get("gce_attached_disk_info", [])
    unattached = rows.get("gce_unattached_disk_info", [])
    sql = rows.get("gce_cloudsql_info", [])
    tables = rows.get("gce_bigquery_info", [])

    disk_gb = _sum(attached, "SizeGb") + _sum(unattached, "SizeGb")
    disk_tb = _sum(attached, "SizeTb") + _sum(unattached, "SizeTb")
    lines = [
        f"Total # of GCE VMs: {len(rows.get('gce_vm_info', []))}",
        f"Total # of attached disks: {len(attached)}",
        f"Total # of unattached disks: {len(unattached)}",
        f"Total capacity of all disks: {_number(disk_gb)} GB or {_number(disk_tb)} TB",
        f"Total # of Cloud SQL instances: {len(sql)}",
        f"Total Cloud SQL storage: {_number(_sum(sql, 'StorageSizeGb'))} GB or "
        f"{_number(_sum(sql, 'StorageSizeTb'))} TB",
        f"Total # of Spanner instances: {len(rows.get('gce_spanner_info', []))}",
    ]
    lines += _bigquery_lines(tables, bigquery_datasets, bigquery_failures, bigquery_ran)
    return lines


def _bigquery_lines(tables: list[dict], datasets: int, failures: int, ran: bool) -> list[str]:
    if not ran and not failures:
        return ["BigQuery was not collected, so there are no BigQuery totals."]

    def of(*kinds: str) -> list[dict]:
        return [row for row in tables if row.get("TableType") in kinds]

    protectable = of("TABLE", "MATERIALIZED_VIEW")
    terabytes = round(_sum(protectable, "TotalLogicalSizeBytes") / 1000000000000, 4)
    lines = [
        f"Total # of BigQuery datasets: {datasets}",
        f"Total # of BigQuery native tables: {len(of('TABLE'))}",
        f"Total # of BigQuery materialized views: {len(of('MATERIALIZED_VIEW'))}",
        f"Total # of BigQuery views (not protected): {len(of('VIEW'))}",
        "Total # of BigQuery external tables (not protected — data not in BQ): "
        f"{len(of('EXTERNAL'))}",
        "Total # of BigQuery table snapshots (not included in the protectable size below): "
        f"{len(of('SNAPSHOT'))}",
        "Total logical size of protectable BQ data (TABLE + MATERIALIZED_VIEW): "
        f"{_number(terabytes)} TB",
    ]
    if failures:
        lines.append(
            f"WARNING: {failures} BigQuery call(s) failed; the BigQuery totals above may be "
            "incomplete. See the warnings above."
        )
    return lines
