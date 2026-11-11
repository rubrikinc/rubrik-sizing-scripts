"""The totals block printed at the end of a run, worded as the PowerShell script words it.

Every number is a sum over the rows the CSV files are built from (``csv_export.rows_by_file``),
so the screen, the log and the files agree.
"""

import re
from decimal import Decimal, InvalidOperation
from typing import Any, Optional

Rows = dict[str, list[dict[str, Any]]]

_UNITS = (("GiB", "GiB"), ("GB", "GB"), ("TiB", "TiB"), ("TB", "TB"))
_COST_NOTE = (
    "Note: the USAGE_TYPE component includes manual snapshots and native automated backups (DLM, "
    "RDS automated, FSx automatic, etc.), not only those created by AWS Backup. The capacity "
    "columns in the per-workload CSVs attribute backups to their exact source mechanism "
    "(BackupSources column)."
)


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


def _four(rows: list[dict], prefix: str) -> str:
    return " or ".join(f"{_number(_sum(rows, prefix + suffix))} {unit}" for suffix, unit in _UNITS)


def _in_plan(rows: list[dict]) -> list[dict]:
    return [row for row in rows if row.get("InBackupPlan")]


def _latest_backup(label: str, rows: list[dict]) -> list[str]:
    backed = [row for row in rows if row.get("HasBackups")]
    sizes = " / ".join(
        f"{_number(_sum(backed, 'LatestBackupSize' + suffix))} {unit}"
        for suffix, unit in (("GiB", "GiB"), ("TiB", "TiB"), ("GB", "GB"), ("TB", "TB"))
    )
    lines = [
        f"Latest-backup logical size of {label} with backups (any source): "
        f"{len(backed)} resources, sum = {sizes}"
    ]
    sources = sorted(
        {
            part
            for row in backed
            for part in re.split(r",\s*", str(row.get("BackupSources") or ""))
            if part
        }
    )
    if sources:
        lines.append(f"  Sources observed: {', '.join(sources)}")
    return lines


def _workload(rows: list[dict], name: str, capacity: str, plans: str, label: str) -> list[str]:
    """Count, capacity, backup-plan size and latest-backup size of one backed-up workload."""
    return [
        f"Total # of {name}: {len(rows)}",
        f"Total {capacity}: {_four(rows, 'Size')}",
        f"Provisioned source size of {plans} in AWS Backup plans: {_four(_in_plan(rows), 'Size')}",
        *_latest_backup(label, rows),
    ]


def _rounded(rows: list[dict], prefix: str) -> str:
    return " or ".join(
        f"{_number(round(_sum([r for r in rows if r.get(prefix + s)], prefix + s), 4))} {unit}"
        for s, unit in _UNITS
    )


def _s3_sizes(rows: list[dict]) -> list[str]:
    columns = sorted({key for row in rows for key in row if "_SizeTB" in key})
    return [f"StorageType: {c}, Size_TB: {_sum(rows, c):,.7f}" for c in columns]


def _decimal(text: Any) -> Decimal:
    try:
        return Decimal(str(text).strip().lstrip("$").replace(",", "") or "0")
    except InvalidOperation:
        return Decimal(0)


def _money(amount: Decimal) -> str:
    return "0" if amount == 0 else format(amount.normalize(), "f")


def _flags(rows: list[dict], column: str) -> str:
    on = sum(1 for r in rows if r.get(column) is True or str(r.get(column)).lower() == "true")
    off = sum(1 for r in rows if r.get(column) is False or str(r.get(column)).lower() == "false")
    return f"{on} on, {off} off, {len(rows) - on - off} unknown"


def summary_lines(rows: Rows, cost_requested: bool = True) -> list[str]:
    """The lines of the totals block, in the order the PowerShell script prints them."""
    r = lambda prefix: rows.get(prefix, [])  # noqa: E731
    ec2, attached, unattached = (
        r("aws_ec2_instance_info"),
        r("aws_ec2_attached_volume_info"),
        r("aws_ec2_unattached_volume_info"),
    )
    efs, rds = r("aws_efs_info"), r("aws_rds_info")
    fsx_fs, fsx_vol = r("aws_fsx_filesystem_info"), r("aws_fsx_volume_info")
    ddb, s3 = r("aws_DynamoDB_info"), r("aws_s3_info")
    s3_tables, glue = r("aws_s3_tables_info"), r("aws_glue_iceberg_info")
    kms = r("aws_kms_numbers")
    backed_s3 = _in_plan(s3)

    out: list[str] = [""]
    out += [
        f"Total # of EC2 instances: {len(ec2)}",
        f"Total # of volumes: {_number(_sum(ec2, 'Volumes'))}",
        f"Total capacity of all volumes: {_four(ec2, 'Size')}",
        f"Provisioned source size of EC2 instances in AWS Backup plans: {_four(_in_plan(ec2), 'Size')}",
        *_latest_backup("EC2 instances", ec2),
        "",
        "",
    ]
    out += [
        f"Total # of EC2 attached volumes: {len(attached)}",
        f"Total capacity of all attached volumes: {_four(attached, 'Size')}",
        "Provisioned source size of attached EBS volumes in AWS Backup plans: "
        f"{_four(_in_plan(attached), 'Size')}",
        *_latest_backup("attached EBS volumes", attached),
        "",
    ]
    out += [
        f"Total # of EC2 unattached volumes: {len(unattached)}",
        f"Total capacity of all unattached volumes: {_four(unattached, 'Size')}",
        "Provisioned source size of unattached EBS volumes in AWS Backup plans: "
        f"{_four(_in_plan(unattached), 'Size')}",
        *_latest_backup("unattached EBS volumes", unattached),
        "",
    ]
    out += [
        f"Total # of RDS instances: {len(rds)}",
        f"Total provisioned capacity of all RDS instances: {_four(rds, 'Size')}",
        f"Provisioned source size of RDS instances in AWS Backup plans: {_four(_in_plan(rds), 'Size')}",
        *_latest_backup("RDS instances", rds),
        "",
        f"Total # of VPCs: {len(r('aws_vpc_info'))}",
        "",
        f"Total # of Load Balancers: {len(r('aws_lb_info'))}",
        "",
        f"Total # of Route53 hosted zones: {len(r('aws_route53_info'))}",
        "",
        f"Total # of IAM accounts profiled: {len(r('aws_iam_info'))}",
        "",
    ]
    out += [
        f"Total # of EFS file systems: {len(efs)}",
        f"Total provisioned capacity of all EFS file systems: {_four(efs, 'Size')}",
        f"Provisioned source size of EFS file systems in AWS Backup plans: {_four(_in_plan(efs), 'Size')}",
        *_latest_backup("EFS file systems", efs),
        "",
    ]
    out += [
        f"Total # of FSx FileSystems: {len(fsx_fs)}",
        f"Total storage capacity of all FSx File Systems: {_four(fsx_fs, 'StorageCapacity')}",
        "",
        "This volume data is a subset of FSX FileSystem Data above",
        f"Total # of FSx volumes: {len(fsx_vol)}",
        f"Total used storage of all FSx volumes: {_four(fsx_vol, 'StorageUsed')}",
        f"Total storage capacity of all FSx volumes: {_four(fsx_vol, 'StorageCapacity')}",
        f"Used storage of all backed up FSx volumes: {_four(_in_plan(fsx_vol), 'StorageUsed')}",
        "Storage capacity of all backed up FSx volumes: "
        f"{_four(_in_plan(fsx_vol), 'StorageCapacity')}",
        "",
    ]
    out += [
        "Total # of customer-managed KMS Keys: "
        f"{sum(1 for k in kms if k.get('KeyManager') == 'CUSTOMER')}",
        f"Total # of AWS-managed KMS Keys: {sum(1 for k in kms if k.get('KeyManager') == 'AWS')}",
        f"Total # of Secrets: {_number(_sum(r('aws_secrets_numbers'), 'Secrets'))}",
        f"Total # of SQS Queues: {_number(_sum(r('aws_sqs_numbers'), 'Queues'))}",
        "",
        f"Total # of DynamoDB Tables: {len(ddb)}",
        f"Total table size of all DynamoDB Tables: {_four(ddb, 'TableSize')}",
        "",
        f"Total # of S3 Tables (Iceberg tables): {len(s3_tables)}",
        f"Total file size of all S3 Tables: {_rounded(s3_tables, 'TotalFileSize')}",
        f"S3 Tables compaction enabled: {_flags(s3_tables, 'CompactionEnabled')}",
        f"S3 Tables snapshot management enabled: {_flags(s3_tables, 'SnapshotManagementEnabled')}",
        "",
        f"Total # of Glue Iceberg tables: {len(glue)}",
        f"Total file size of all Glue Iceberg tables: {_rounded(glue, 'TotalFileSize')}",
        "",
        f"Total # of S3 buckets: {len(s3)}",
        "Total used capacity of all S3 buckets:",
        *(_s3_sizes(s3) or ["No S3 Buckets"]),
        "",
        f"# of Backed Up S3 buckets: {len(backed_s3)}",
        "Used capacity of all backed up S3 buckets:",
        *(_s3_sizes(backed_s3) or ["No S3 Buckets backed up"]),
        "",
    ]
    out += _cost_lines(r("aws_backup_costs"), r("aws_snapshot_storage_costs"), cost_requested)
    return out


def _cost_lines(backup: list[dict], snapshots: list[dict], requested: bool) -> list[str]:
    if not requested:
        return ["Cost data was not collected (cost scan skipped), so there is no cost summary."]
    backup_total = sum(
        (_decimal(row.get("AWSBackupNetUnblendedCost")) for row in backup), Decimal(0)
    )
    # PowerShell adds the two in doubles and rounds each for display.
    backup_amount = float(backup_total)
    snapshot_amount = sum(float(_decimal(row.get("NetUnblendedCost"))) for row in snapshots)
    combined = round(backup_amount + snapshot_amount, 2)
    return [
        "Net unblended cost of AWS Backup for past 12 months + this month so far: "
        f"${_money(backup_total)}",
        "See CSV for further breakdown of cost for Backup",
        "",
        "AWS Backup cost summary (past 12 months + MTD):",
        f"  AWS Backup service (fully-managed resources)        : ${_number(round(backup_amount, 2))}",
        f"  Snapshot/backup USAGE_TYPE (source-service-billed)  : ${_number(round(snapshot_amount, 2))}",
        f"  Combined upper bound                                : ${_number(combined)}",
        _COST_NOTE,
    ]


def print_totals(rows: Rows, say: Any, cost_requested: bool = True) -> Optional[int]:
    """Send the totals block to ``say`` (the screen and the log); returns the line count."""
    lines = summary_lines(rows, cost_requested)
    for line in lines:
        say(line)
    return len(lines)
