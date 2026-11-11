"""PowerShell-compatible CSV export of the AWS discovery results.

Writes the files that ``Get-AWSSizingInfo.ps1`` writes, with the same names, column names
and column order, for the resource types this tool collects:
EC2 instances, attached and unattached EBS volumes, RDS, EFS, DynamoDB, S3, Secrets Manager
and SQS counts.

Rows are built from the discovery JSON dicts, so the same code serves a single account and
the combined output of many accounts. Columns whose data this tool does not collect yet (AWS Backup
recovery points, FSx, KMS key rows, VPC, EKS, ...) are filled with the PowerShell defaults or
left out; see ``python/docs`` and ``contract/columns.json``.

Quoting follows ``Export-Csv``: every value is quoted except a null, which is written as an
empty, unquoted field. Files use ``\\n`` line ends, UTF-8 and no BOM.
"""

from __future__ import annotations

import logging
import os
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from anonymize import BACKUP_PLAN_NAME_FIELD, Anonymizer, file_rank
from backup_plan_membership import RowView, compute_membership
from collectors import arns
from csv_injection import protect_csv_value

log = logging.getLogger(__name__)

TIMESTAMP_FORMAT = "%Y-%m-%d_%H%M%S"

# Written as a quoted empty string by PowerShell; every other empty value is a null.
_QUOTED_EMPTY = frozenset({"AwsAccountAlias", "BackupPlans", "BackupSources"})
# EC2 names come from a tag, so a missing one is an empty string rather than a null.
_EC2_QUOTED_EMPTY = _QUOTED_EMPTY | {"Name", "InstanceName"}

# The backup columns Add-BackupColumnsToRow adds, in order.
_BACKUP_COLUMNS = (
    "HasBackups",
    "HasRecoveryPoints",
    "BackupCount",
    "BackupSources",
    "LatestBackupDate",
    "LatestBackupSizeGiB",
    "LatestBackupSizeTiB",
    "LatestBackupSizeGB",
    "LatestBackupSizeTB",
    "BackupEnumerationTruncated",
)

_AWS_BACKUP = "AWS Backup"


# ── value formatting ──────────────────────────────────────────────────────────


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


def render(
    columns: list[str],
    rows: list[dict[str, Any]],
    quoted_empty: frozenset[str] = _QUOTED_EMPTY,
) -> str:
    """CSV text for ``rows`` under ``columns``; a missing key is a null."""

    def quote(text: str) -> str:
        return '"' + text.replace('"', '""') + '"'

    lines = [",".join(quote(c) for c in columns)]
    for row in rows:
        cells = []
        for column in columns:
            value = row.get(column)
            if value is None or (value == "" and column not in quoted_empty):
                cells.append("")
            else:
                cells.append(quote(_format(value)))
        lines.append(",".join(cells))
    return "\n".join(lines) + "\n"


# ── PowerShell helpers, re-implemented ────────────────────────────────────────


def _ps_round(value: float, digits: int) -> float:
    """``[math]::round($value, $digits)``.

    .NET scales by 10**digits, rounds half to even and scales back, so it is not Python's
    ``round(value, digits)``: 12.345 gives 12.34 here (12.35 in Python) because 12.345 * 100
    is exactly 1234.5.
    """
    if abs(value) < 1e16:
        power = 10.0**digits
        return round(value * power) / power
    return value


def _units_from_gib(gib: float, prefix: str = "Size", gb_precision: int = 3) -> dict[str, Any]:
    """ConvertTo-SizeUnits -InputUnit GiB (GiB, TiB and TB use 4 decimals)."""
    return {
        f"{prefix}GiB": _ps_round(gib, 4),
        f"{prefix}TiB": _ps_round(gib / 1024, 4),
        f"{prefix}GB": _ps_round(gib * 1.073741824, gb_precision),
        f"{prefix}TB": _ps_round(gib * 0.001073741824, 4),
    }


def _units_from_bytes(num_bytes: float, prefix: str = "Size") -> dict[str, Any]:
    """ConvertTo-SizeUnits -InputUnit Bytes (all four units use 4 decimals)."""
    gib = num_bytes / 1073741824
    gb = num_bytes / 1000000000
    return {
        f"{prefix}GiB": _ps_round(gib, 4),
        f"{prefix}TiB": _ps_round(gib / 1024, 4),
        f"{prefix}GB": _ps_round(gb, 4),
        f"{prefix}TB": _ps_round(gb / 1000, 4),
    }


def _ps_datetime(iso: Optional[str]) -> Optional[str]:
    """PowerShell's text for a UTC DateTime: ``10/5/2026 6:29:13 AM``."""
    if not iso:
        return None
    dt = datetime.fromisoformat(iso).astimezone(timezone.utc)
    hour = dt.hour % 12 or 12
    return f"{dt.month}/{dt.day}/{dt.year} {hour}:{dt:%M:%S} {'AM' if dt.hour < 12 else 'PM'}"


_SANITIZE = re.compile(r"[^a-zA-Z0-9]")
_SANITIZE_KEEP_HYPHEN = re.compile(r"[^a-zA-Z0-9-]")


def _tag_columns(
    tags: Optional[dict[str, str]], include_name: bool, keep_hyphen: bool = False
) -> dict[str, Any]:
    pattern = _SANITIZE_KEEP_HYPHEN if keep_hyphen else _SANITIZE
    out: dict[str, Any] = {}
    for key, value in (tags or {}).items():
        if key == "Name" and not include_name:
            continue
        out[f"Tag: {pattern.sub('_', key)}"] = protect_csv_value(value)
    return out


def _in_backup_plan(record: dict) -> bool:
    """AWS Backup membership only, as PowerShell reports it (not native backups)."""
    return _AWS_BACKUP in (record.get("backup_plans") or [])


def _head(record: dict) -> dict[str, Any]:
    return {
        "AwsAccountId": str(record.get("account_id", "")),
        "AwsAccountAlias": record.get("account_alias") or "",
    }


def _backup_columns(record: dict) -> dict[str, Any]:
    """The ten backup columns, from the merged backup summary (or PowerShell's defaults)."""
    b = record.get("backup") or {}
    sizes = _units_from_bytes(b.get("latest_backup_size_bytes") or 0, prefix="LatestBackupSize")
    return {
        "HasBackups": bool(b.get("has_backups")),
        "HasRecoveryPoints": bool(b.get("has_recovery_points")),
        "BackupCount": b.get("backup_count", 0),
        "BackupSources": b.get("backup_sources", ""),
        "LatestBackupDate": _ps_datetime(b.get("latest_backup_date")),
        **sizes,
        "BackupEnumerationTruncated": bool(b.get("backup_enumeration_truncated")),
    }


def _plan_columns(record: dict) -> dict[str, Any]:
    """``BackupPlans`` and ``InBackupPlan`` of a row.

    Records stamped by ``_with_plan_membership`` carry the plans whose selections cover them
    (``plan_names``, ``in_selected_plan``), as PowerShell decides it. A record without the stamp
    belongs to a group with no usable plan data, so it keeps the older signal: AWS Backup's
    protected-resource list for ``InBackupPlan`` and no plan names.
    """
    if "in_selected_plan" in record:
        return {
            "BackupPlans": ", ".join(record.get("plan_names") or []),
            "InBackupPlan": bool(record["in_selected_plan"]),
        }
    return {"BackupPlans": "", "InBackupPlan": _in_backup_plan(record)}


def _backup(record: dict) -> dict[str, Any]:
    return {**_plan_columns(record), **_backup_columns(record)}


def _blank_if_zero(value: Any) -> Any:
    return value if value else None


# ── per-file row builders ─────────────────────────────────────────────────────


def _ec2_instance(r: dict) -> dict[str, Any]:
    row = {
        **_head(r),
        "InstanceId": r["instance_id"],
        "ResourceArn": arns.instance_arn(r["region"], r["account_id"], r["instance_id"]),
        "Name": protect_csv_value(r.get("name")),
        "Volumes": r.get("volume_count", 0),
        **_units_from_gib(r.get("size_gib", 0)),
        "Region": r["region"],
        "InstanceType": r.get("instance_type"),
        "Platform": "Windows" if r.get("platform") == "windows" else None,
        "ProductCode": None,
    }
    row.update(_backup(r))
    return row


def _volume_arn(r: dict) -> str:
    return arns.volume_arn(r["region"], r["account_id"], r["volume_id"])


def _ebs_attached(r: dict) -> dict[str, Any]:
    row = {
        **_head(r),
        "VolumeId": r["volume_id"],
        "ResourceArn": _volume_arn(r),
        "InstanceId": r.get("instance_id"),
        "InstanceName": r.get("instance_name"),
        "Name": protect_csv_value(r.get("name")),
        "DeviceName": r.get("device_name"),
        **_units_from_gib(r.get("size_gib", 0)),
        "Region": r["region"],
        "AvailabilityZone": r.get("availability_zone"),
        "VolumeType": r.get("volume_type"),
        "State": r.get("state"),
        "Iops": _blank_if_zero(r.get("iops")),
        "Throughput": _blank_if_zero(r.get("throughput")),
        "Encrypted": bool(r.get("encrypted")),
    }
    row.update(_backup(r))
    return row


def _ebs_unattached(r: dict) -> dict[str, Any]:
    row = {
        **_head(r),
        "VolumeId": r["volume_id"],
        "ResourceArn": _volume_arn(r),
        "Name": protect_csv_value(r.get("name")),
        **_units_from_gib(r.get("size_gib", 0)),
        "Region": r["region"],
        "VolumeType": r.get("volume_type"),
    }
    row.update(_backup(r))
    return row


def _rds(r: dict) -> dict[str, Any]:
    row = {
        **_head(r),
        "DBName": r.get("db_name"),
        "DBInstanceIdentifier": r["db_instance_identifier"],
        "DBClusterIdentifier": None,
        "ResourceArn": arns.rds_db_arn(r["region"], r["account_id"], r["db_instance_identifier"]),
        **_units_from_gib(r.get("size_gib", 0)),
        "Region": r["region"],
        "InstanceType": r.get("instance_class"),
        "Engine": r.get("engine"),
        "EngineVersion": r.get("engine_version"),
        "DBInstanceStatus": r.get("db_instance_status"),
        **_plan_columns(r),
        "BackupRetentionPeriod": r.get("native_backup_retention_days", 0),
        "PreferredBackupWindow": r.get("preferred_backup_window"),
        "StorageType": r.get("storage_type"),
        "EngineMode": None,
        "InstanceCount": 1,
    }
    row.update(_backup_columns(r))
    return row


def _efs(r: dict) -> dict[str, Any]:
    row = {
        **_head(r),
        "FileSystemId": r["file_system_id"],
        "ResourceArn": arns.efs_arn(r["region"], r["account_id"], r["file_system_id"]),
        "FileSystemProtection": r.get("file_system_protection"),
        "Name": r.get("name"),
        "SizeInBytes": r.get("size_bytes", 0),
        **_units_from_bytes(r.get("size_bytes", 0)),
        "NumberOfMountTargets": r.get("mount_targets", 0),
        "OwnerId": r.get("owner_id"),
        "PerformanceMode": r.get("performance_mode"),
        "ProvisionedThroughputInMibps": _blank_if_zero(r.get("provisioned_throughput_mibps")),
        "DBInstanceIdentifier": None,
        "Region": r["region"],
        "ThroughputMode": r.get("throughput_mode"),
    }
    row.update(_backup(r))
    return row


def _dynamodb(r: dict) -> dict[str, Any]:
    row = {
        **_head(r),
        "Region": r["region"],
        "TableName": r["table_name"],
        "TableId": r.get("table_id"),
        "TableArn": r.get("table_arn"),
        "ResourceArn": r.get("table_arn"),
        "TableSizeBytes": r.get("size_bytes", 0),
        "TableStatus": r.get("status"),
        **_units_from_bytes(r.get("size_bytes", 0), prefix="TableSize"),
        "ItemCount": r.get("item_count", 0),
        "DeletionProtectionEnabled": bool(r.get("deletion_protection")),
        "GlobalTableVersion": r.get("global_table_version"),
        "ProvisionedThroughputLastDecreaseDateTime": None,
        "ProvisionedThroughputLastIncreaseDateTime": None,
        "ProvisionedThroughput.NumberOfDecreasesToday": r.get("number_of_decreases_today", 0),
        "ProvisionedThroughputReadCapacityUnits": r.get("read_capacity_units", 0),
        "ProvisionedThroughputWriteCapacityUnits": r.get("write_capacity_units", 0),
        **_plan_columns(r),
        "PITREnabled": bool(r.get("pitr_enabled")),
    }
    row.update(_backup_columns(r))
    return row


def _s3_size_columns(
    prefix: str, num_bytes: Any, with_bytes_first: bool, iceberg_adjusted: bool = False
) -> dict[str, Any]:
    """Size columns for one storage class; labels are swapped as in PowerShell (GB holds GiB).

    A class reduced by Glue Iceberg data is recomputed as PowerShell recomputes it after the
    deduction, where GiB and TiB use the GB value without the 1.073741824 division.
    """
    value = float(num_bytes or 0)
    gb = value / 1073741824
    gib = gb if iceberg_adjusted else gb / 1.073741824
    sizes = {
        f"{prefix}_SizeGB": _ps_round(gb, 3),
        f"{prefix}_SizeTB": _ps_round(gb / 1000, 4),
        f"{prefix}_SizeGiB": _ps_round(gib, 3),
        f"{prefix}_SizeTiB": _ps_round(gib / 1024, 4),
    }
    raw = {f"{prefix}_SizeBytes": num_bytes or 0}
    return {**raw, **sizes} if with_bytes_first else {**sizes, **raw}


def _s3(r: dict) -> dict[str, Any]:
    """One bucket row. Class columns follow the classes CloudWatch reported for the bucket."""
    sizes = r.get("storage_class_bytes")
    objects = r.get("storage_class_objects")
    if not sizes:  # discovery files from before per-class sizes
        sizes = {"StandardStorage": r.get("size_bytes") or 0}
    if not objects:
        objects = {"AllStorageTypes": r.get("object_count") or 0}
    row = {
        **_head(r),
        "BucketName": r["bucket_name"],
        "ResourceArn": arns.s3_arn(r["region"], r["bucket_name"]),
        "Region": r["region"],
        **_plan_columns(r),
    }
    row.update(_backup_columns(r))
    adjusted = set(r.get("iceberg_adjusted_classes") or [])
    for storage_class, num_bytes in sizes.items():
        row.update(
            _s3_size_columns(
                storage_class,
                num_bytes,
                with_bytes_first=False,
                iceberg_adjusted=storage_class in adjusted,
            )
        )
    for storage_class, count in objects.items():
        row[f"NumberOfObjects-{storage_class}"] = count or 0
    for storage_class, num_bytes in (r.get("current_version_bytes") or {}).items():
        row.update(_s3_size_columns(f"CurrentVersion_{storage_class}", num_bytes, True))
    for storage_class, count in (r.get("current_version_objects") or {}).items():
        row[f"CurrentVersionObjectCount_{storage_class}"] = count or 0
    row["HasIcebergTable"] = "Yes" if r.get("has_iceberg_table") else "No"
    return row


def _blank_means_zero(column: str) -> bool:
    lowered = column.lower()
    return (
        "_size" in lowered
        or lowered.startswith("numberofobjects")
        or lowered.startswith("currentversionobjectcount_")
    )


def _rds_snapshot(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "Region": r["region"],
        "Source": r.get("source"),
        "Engine": r.get("engine"),
        "SnapshotIdentifier": r.get("snapshot_identifier"),
        "ResourceArn": r.get("resource_arn"),
        "SnapshotArn": r.get("snapshot_arn"),
        "SizeBytes": r.get("size_bytes", 0),
        "SizeGiB": _ps_round((r.get("size_bytes") or 0) / 1073741824, 4),
        "CreationDate": _ps_datetime(r.get("creation_date")),
        "SnapshotType": r.get("snapshot_type"),
        "Status": r.get("status"),
        "ClusterIdentifier": r.get("cluster_identifier", ""),
    }


def _ebs_and_ami(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "Region": r["region"],
        "Source": r.get("source"),
        "ImageId": r.get("image_id", ""),
        "SnapshotId": r.get("snapshot_id", ""),
        "ResourceArn": r.get("resource_arn"),
        "SizeBytes": r.get("size_bytes", 0),
        "SizeGiB": _ps_round((r.get("size_bytes") or 0) / 1073741824, 4),
        "CreationDate": _ps_datetime(r.get("creation_date")),
        "Name": r.get("name", ""),
        "Description": protect_csv_value(r.get("description")),
        "State": r.get("state"),
    }


def _vpc(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "Region": r["region"],
        "VpcId": r.get("vpc_id"),
        "OwnerId": r.get("owner_id"),
        "CidrBlock": r.get("cidr_block"),
        "State": r.get("state"),
        "IsDefault": bool(r.get("is_default")),
    }


def _load_balancer(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "Region": r["region"],
        "LoadBalancerName": r.get("name"),
        "Type": r.get("type"),
        "Scheme": r.get("scheme"),
        "VpcId": r.get("vpc_id"),
        "DNSName": r.get("dns_name"),
        "Arn": r.get("arn"),
    }


def _eks_cluster(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "Name": r.get("name"),
        "Version": r.get("version"),
        "PlatformVersion": r.get("platform_version"),
        "Status": r.get("status"),
        "Arn": r.get("arn"),
        "RoleArn": r.get("role_arn"),
        "Region": r["region"],
    }


def _eks_nodegroup(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "NodegroupName": r.get("nodegroup_name"),
        "ClusterName": r.get("cluster_name"),
        "DiskSize": r.get("disk_size"),
        "CapacityType": r.get("capacity_type"),
        "AmiType": r.get("ami_type"),
        "NodegroupArn": r.get("nodegroup_arn"),
        "NodeRole": r.get("node_role"),
        "Status": r.get("status"),
        "ReleaseVersion": r.get("release_version"),
        "Version": r.get("version"),
        "Region": r["region"],
    }


def _kms_key(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "Region": r["region"],
        "Alias": r.get("alias"),
        "KeyId": r.get("key_id"),
        "Arn": r.get("arn"),
        "KeyManager": r.get("key_manager"),
        "KeyState": r.get("key_state"),
        "CreationDate": r.get("creation_date"),
    }


def _route53(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "HostedZoneId": r.get("hosted_zone_id"),
        "Name": r.get("name"),
        "PrivateZone": bool(r.get("private_zone")),
        "ResourceRecordSetCount": r.get("resource_record_set_count", 0),
    }


def _iam(r: dict) -> dict[str, Any]:
    return {
        **_head(r),
        "Users": r.get("users", 0),
        "Roles": r.get("roles", 0),
        "CustomerManagedPolicies": r.get("customer_managed_policies", 0),
    }


def _redshift(r: dict) -> dict[str, Any]:
    row = {
        **_head(r),
        "Region": r["region"],
        "ClusterIdentifier": r["cluster_identifier"],
        "ResourceArn": arns.redshift_arn(r["region"], r["account_id"], r["cluster_identifier"]),
        "NodeType": r.get("node_type"),
        "NumberOfNodes": r.get("number_of_nodes", 0),
        "ClusterStatus": r.get("cluster_status"),
        "MasterUsername": r.get("master_username"),
        "DBName": r.get("db_name"),
        "ClusterCreateTime": _ps_datetime(r.get("cluster_create_time")),
        "AutomatedSnapshotRetentionPeriod": r.get("automated_snapshot_retention_period", 0),
        "ManualSnapshotRetentionPeriod": r.get("manual_snapshot_retention_period", 0),
    }
    row.update(_backup_columns(r))
    return row


_COST_METRICS = (
    "AmortizedCost",
    "BlendedCost",
    "NetAmortizedCost",
    "NetUnblendedCost",
    "NormalizedUsageAmount",
    "UnblendedCost",
    "UsageQuantity",
)


def _money(amount: float) -> str:
    return "$" + _format(_ps_round(float(amount or 0), 2))


def _backup_cost(r: dict) -> dict[str, Any]:
    amounts = r.get("amounts") or {}
    row: dict[str, Any] = {
        **_head(r),
        "Time-Period-Start": r.get("period_start"),
        "Time-Period-End": r.get("period_end"),
    }
    for metric in _COST_METRICS:
        amount = amounts.get(metric, 0)
        text = (
            _money(amount) if metric.endswith("Cost") else _format(_ps_round(float(amount or 0), 3))
        )
        row[f"AWSBackup{metric}"] = text
    return row


def _snapshot_storage_cost(r: dict) -> dict[str, Any]:
    amounts = r.get("amounts") or {}
    return {
        **_head(r),
        "Time-Period-Start": r.get("period_start"),
        "Time-Period-End": r.get("period_end"),
        "Service": r.get("service"),
        "UsageType": r.get("usage_type"),
        "UsageQuantity": _ps_round(float(amounts.get("UsageQuantity") or 0), 4),
        "UsageUnit": r.get("usage_unit") or "",
        "AmortizedCost": _money(amounts.get("AmortizedCost", 0)),
        "BlendedCost": _money(amounts.get("BlendedCost", 0)),
        "NetAmortizedCost": _money(amounts.get("NetAmortizedCost", 0)),
        "NetUnblendedCost": _money(amounts.get("NetUnblendedCost", 0)),
        "UnblendedCost": _money(amounts.get("UnblendedCost", 0)),
        "NormalizedUsageAmount": _ps_round(float(amounts.get("NormalizedUsageAmount") or 0), 3),
    }


_FSX_FILE_SYSTEM_COLUMNS = (
    "AwsAccountId",
    "AwsAccountAlias",
    "Region",
    "FileSystemId",
    "ResourceArn",
    "FileSystemDNSName",
    "FileSystemType",
    "FileSystemTypeVersion",
    "FileSystemOwnerId",
    "FileSystemStorageType",
    "Name",
    "OnTapType",
    "WindowsType",
    "LustreType",
    "OpenZFSType",
    "StorageCapacityBytes",
    "StorageCapacityGiB",
    "StorageCapacityTiB",
    "StorageCapacityGB",
    "StorageCapacityTB",
    "BackupPlans",
    "InBackupPlan",
    *_BACKUP_COLUMNS,
)
_FSX_VOLUME_COLUMNS = (
    "AwsAccountId",
    "AwsAccountAlias",
    "Region",
    "FileSystemId",
    "FileSystemDNSName",
    "FileSystemType",
    "FileSystemTypeVersion",
    "FileSystemOwnerId",
    "FileSystemStorageType",
    "Name",
    "VolumeId",
    "ResourceArn",
    "VolumeType",
    "LifeCycle",
    "StorageUsedBytes",
    "StorageUsedGiB",
    "StorageUsedTiB",
    "StorageUsedGB",
    "StorageUsedTB",
    "StorageCapacityBytes",
    "StorageCapacityGiB",
    "StorageCapacityTiB",
    "StorageCapacityGB",
    "StorageCapacityTB",
    "BackupPlans",
    "InBackupPlan",
    *_BACKUP_COLUMNS,
)


def _bytes_columns(prefix: str, value: Any) -> dict[str, Any]:
    """``<prefix>Bytes`` plus the four units; no datapoint leaves Bytes blank and units 0."""
    row: dict[str, Any] = {f"{prefix}Bytes": value}
    row.update(_units_from_bytes(float(value or 0), prefix))
    return row


def _fsx_file_system(r: dict) -> dict[str, Any]:
    config = r.get("config_type") or ""
    gib = int(r.get("storage_capacity_gib") or 0)
    row: dict[str, Any] = {
        **_head(r),
        "Region": r["region"],
        "FileSystemId": r["file_system_id"],
        "ResourceArn": arns.fsx_file_system_arn(r["region"], r["account_id"], r["file_system_id"]),
        "FileSystemDNSName": r.get("dns_name"),
        "FileSystemType": r.get("file_system_type"),
        "FileSystemTypeVersion": r.get("file_system_type_version"),
        "FileSystemOwnerId": r.get("owner_id"),
        "FileSystemStorageType": r.get("storage_type"),
        "Name": protect_csv_value((r.get("tags") or {}).get("Name")),
        "OnTapType": config == "ontap",
        "WindowsType": config == "windows",
        "LustreType": config == "lustre",
        "OpenZFSType": config == "openzfs",
        "StorageCapacityBytes": gib * 1073741824,
        **_units_from_gib(gib, "StorageCapacity", gb_precision=4),
        **_plan_columns(r),
    }
    row.update(_backup_columns(r))
    for prefix, value in (r.get("usage_metrics") or {}).items():
        if prefix == "StorageCapacityUtilizationPercentage":
            row[prefix] = value
        else:
            row.update(_bytes_columns(prefix, value))
    return row


def _fsx_volume(r: dict) -> dict[str, Any]:
    row: dict[str, Any] = {
        **_head(r),
        "Region": r["region"],
        "FileSystemId": r.get("file_system_id"),
        "FileSystemDNSName": r.get("file_system_dns_name"),
        "FileSystemType": r.get("file_system_type"),
        "FileSystemTypeVersion": r.get("file_system_type_version"),
        "FileSystemOwnerId": r.get("file_system_owner_id"),
        "FileSystemStorageType": r.get("file_system_storage_type"),
        "Name": r.get("name"),
        "VolumeId": r["volume_id"],
        "ResourceArn": arns.fsx_volume_arn(r["region"], r["account_id"], r["volume_id"]),
        "VolumeType": r.get("volume_type"),
        "LifeCycle": r.get("lifecycle"),
        **_bytes_columns("StorageUsed", r.get("storage_used_bytes")),
        **_bytes_columns("StorageCapacity", r.get("storage_capacity_bytes")),
        **_plan_columns(r),
    }
    row.update(_backup_columns(r))
    return row


_S3_TABLES_COLUMNS = (
    "AwsAccountId",
    "AwsAccountAlias",
    "Region",
    "CatalogType",
    "DatabaseName",
    "TableName",
    "TableBucketName",
    "TableBucketArn",
    "Namespace",
    "TableArn",
    "ResourceArn",
    "WarehouseLocation",
    "MetadataLocation",
    "TableType",
    "CreatedAt",
    "ModifiedAt",
    "FormatVersion",
    "StorageClass",
    "MetadataFileStorageClass",
    "TotalFileSizeGiB",
    "TotalFileSizeTiB",
    "TotalFileSizeGB",
    "TotalFileSizeTB",
    "TotalFileCount",
    "DataFileCount",
    "TotalDeleteFileCount",
    "ManifestCount",
    "TargetManifestSizeBytes",
    "ManifestBytesEstimate",
    "CompactionEnabled",
    "SnapshotManagementEnabled",
    "BackupPlans",
    "InBackupPlan",
)
_GLUE_ICEBERG_COLUMNS = (
    "AwsAccountId",
    "AwsAccountAlias",
    "Region",
    "CatalogType",
    "DatabaseName",
    "TableName",
    "S3BucketName",
    "TableType",
    "S3Location",
    "MetadataLocation",
    "CreateTime",
    "UpdateTime",
    "FormatVersion",
    "TotalFileSizeBytes",
    "TotalFileSizeGiB",
    "TotalFileSizeTiB",
    "TotalFileSizeGB",
    "TotalFileSizeTB",
    "DataFileCount",
    "TotalDeleteFileCount",
    "ManifestCount",
    "TargetManifestSizeBytes",
    "ManifestBytesEstimate",
    "CompactionEnabled",
    "MetadataFileStorageClass",
)
_NULL_FILE_SIZES = {
    "TotalFileSizeGiB": None,
    "TotalFileSizeTiB": None,
    "TotalFileSizeGB": None,
    "TotalFileSizeTB": None,
}


def _file_sizes(num_bytes: Any) -> dict[str, Any]:
    if num_bytes is None:
        return dict(_NULL_FILE_SIZES)
    return _units_from_bytes(float(num_bytes), "TotalFileSize")


def _s3_table(r: dict) -> dict[str, Any]:
    iceberg = r.get("iceberg")
    size = (iceberg or {}).get("total_file_size_bytes")
    if size is None:
        size = r.get("cloudwatch_size_bytes")
    compaction = r.get("compaction_enabled")
    if compaction is None and iceberg is not None:
        compaction = iceberg.get("compaction_enabled")
    return {
        **_head(r),
        "Region": r["region"],
        "CatalogType": "S3Tables",
        "DatabaseName": r.get("namespace"),
        "TableName": r.get("table_name"),
        "TableBucketName": r.get("table_bucket_name"),
        "TableBucketArn": r.get("table_bucket_arn"),
        "Namespace": r.get("namespace"),
        "TableArn": r.get("table_arn"),
        "ResourceArn": r.get("table_arn"),
        "WarehouseLocation": r.get("warehouse_location"),
        "MetadataLocation": r.get("metadata_location"),
        "TableType": r.get("table_type"),
        "CreatedAt": _ps_datetime(r.get("created_at")),
        "ModifiedAt": _ps_datetime(r.get("modified_at")),
        "FormatVersion": (iceberg or {}).get("format_version"),
        "StorageClass": r.get("storage_class") or "STANDARD",
        "MetadataFileStorageClass": (iceberg or {}).get("metadata_file_storage_class") or "",
        **_file_sizes(size),
        "TotalFileCount": r.get("total_file_count"),
        "DataFileCount": (iceberg or {}).get("data_file_count"),
        "TotalDeleteFileCount": (iceberg or {}).get("total_delete_file_count"),
        "ManifestCount": (iceberg or {}).get("manifest_count"),
        "TargetManifestSizeBytes": (iceberg or {}).get("target_manifest_size_bytes"),
        "ManifestBytesEstimate": (iceberg or {}).get("manifest_bytes_estimate"),
        "CompactionEnabled": compaction,
        "SnapshotManagementEnabled": r.get("snapshot_management_enabled"),
        **_plan_columns(r),
    }


def _glue_iceberg(r: dict) -> dict[str, Any]:
    iceberg = r.get("iceberg") or {}
    size = iceberg.get("total_file_size_bytes")
    return {
        **_head(r),
        "Region": r["region"],
        "CatalogType": "GlueDataCatalog",
        "DatabaseName": r.get("database_name"),
        "TableName": r.get("table_name"),
        "S3BucketName": r.get("s3_bucket_name") or "",
        "TableType": "ICEBERG",
        "S3Location": r.get("s3_location") or "",
        "MetadataLocation": r.get("metadata_location"),
        "CreateTime": _ps_datetime(r.get("create_time")),
        "UpdateTime": _ps_datetime(r.get("update_time")),
        "FormatVersion": iceberg.get("format_version"),
        "TotalFileSizeBytes": size,
        **_file_sizes(size),
        "DataFileCount": iceberg.get("data_file_count"),
        "TotalDeleteFileCount": iceberg.get("total_delete_file_count"),
        "ManifestCount": iceberg.get("manifest_count"),
        "TargetManifestSizeBytes": iceberg.get("target_manifest_size_bytes"),
        "ManifestBytesEstimate": iceberg.get("manifest_bytes_estimate"),
        "CompactionEnabled": bool(iceberg.get("compaction_enabled")),
        "MetadataFileStorageClass": iceberg.get("metadata_file_storage_class") or "",
    }


def _recovery_point(r: dict) -> dict[str, Any]:
    size = int(r.get("backup_size_bytes") or 0)
    units = _units_from_bytes(float(size), "BackupSize")
    return {
        **_head(r),
        "Region": r["region"],
        "BackupVaultName": r.get("backup_vault_name"),
        "BackupVaultArn": r.get("backup_vault_arn"),
        "RecoveryPointArn": r.get("recovery_point_arn"),
        "ResourceArn": r.get("resource_arn"),
        "ResourceId": r.get("resource_id") or "",
        "ResourceName": r.get("resource_name"),
        "ResourceType": r.get("resource_type"),
        "BackupSizeBytes": size,
        "BackupSizeGiB": units["BackupSizeGiB"],
        "BackupSizeTiB": units["BackupSizeTiB"],
        "CreationDate": _ps_datetime(r.get("creation_date")),
        "BackupPlanId": r.get("backup_plan_id") or "",
        "BackupPlanName": r.get("backup_plan_name") or "",
        "Status": r.get("status"),
        "IsParent": bool(r.get("is_parent")),
        "ParentRecoveryPointArn": r.get("parent_recovery_point_arn"),
        "Source": r.get("source") or "AWSBackup",
    }


def _secrets(r: dict) -> dict[str, Any]:
    return {**_head(r), "Region": r["region"], "Secrets": r.get("secret_count", 0)}


def _sqs(r: dict) -> dict[str, Any]:
    return {**_head(r), "Region": r["region"], "Queues": r.get("queue_count", 0)}


# ── file definitions ──────────────────────────────────────────────────────────

_BACKUP_TAIL = ["BackupPlans", "InBackupPlan", *_BACKUP_COLUMNS]
_SIZES = ["SizeGiB", "SizeTiB", "SizeGB", "SizeTB"]
_HEAD = ["AwsAccountId", "AwsAccountAlias"]


@dataclass(frozen=True)
class FileSpec:
    prefix: str
    collection: str
    columns: tuple[str, ...]
    build: Callable[[dict], dict[str, Any]]
    tags: str = "none"  # "none", "first_seen" (after the columns), "sorted" or "inline" (in-row)
    tag_name: bool = False  # include a Name tag as a "Tag: Name" column
    tag_keep_hyphen: bool = False  # tag keys keep "-" (VPCs and load balancers)
    quoted_empty: frozenset[str] = _QUOTED_EMPTY
    # Columns are the union of the rows' own columns in first-seen order (S3 storage classes);
    # ``columns`` is the header when there are no rows. Blank size and count cells become 0.
    dynamic: bool = False
    # Rows by region name rather than scan order (PowerShell merges per-region temp files by name).
    regions_by_name: bool = False


FILES: tuple[FileSpec, ...] = (
    FileSpec(
        "aws_ec2_instance_info",
        "ec2_instances",
        (
            *_HEAD,
            "InstanceId",
            "ResourceArn",
            "Name",
            "Volumes",
            *_SIZES,
            "Region",
            "InstanceType",
            "Platform",
            "ProductCode",
            *_BACKUP_TAIL,
        ),
        _ec2_instance,
        tags="first_seen",
        quoted_empty=_EC2_QUOTED_EMPTY,
    ),
    FileSpec(
        "aws_ec2_attached_volume_info",
        "ec2_attached_volumes",
        (
            *_HEAD,
            "VolumeId",
            "ResourceArn",
            "InstanceId",
            "InstanceName",
            "Name",
            "DeviceName",
            *_SIZES,
            "Region",
            "AvailabilityZone",
            "VolumeType",
            "State",
            "Iops",
            "Throughput",
            "Encrypted",
            *_BACKUP_TAIL,
        ),
        _ebs_attached,
        tags="first_seen",
        quoted_empty=_EC2_QUOTED_EMPTY,
    ),
    FileSpec(
        "aws_ec2_unattached_volume_info",
        "ec2_unattached_volumes",
        (
            *_HEAD,
            "VolumeId",
            "ResourceArn",
            "Name",
            *_SIZES,
            "Region",
            "VolumeType",
            *_BACKUP_TAIL,
        ),
        _ebs_unattached,
        tags="first_seen",
        quoted_empty=_EC2_QUOTED_EMPTY,
    ),
    FileSpec(
        "aws_rds_info",
        "rds_instances",
        (
            *_HEAD,
            "DBName",
            "DBInstanceIdentifier",
            "DBClusterIdentifier",
            "ResourceArn",
            *_SIZES,
            "Region",
            "InstanceType",
            "Engine",
            "EngineVersion",
            "DBInstanceStatus",
            "BackupPlans",
            "InBackupPlan",
            "BackupRetentionPeriod",
            "PreferredBackupWindow",
            "StorageType",
            "EngineMode",
            "InstanceCount",
            *_BACKUP_COLUMNS,
        ),
        _rds,
        tags="first_seen",
    ),
    FileSpec(
        "aws_efs_info",
        "efs_filesystems",
        (
            *_HEAD,
            "FileSystemId",
            "ResourceArn",
            "FileSystemProtection",
            "Name",
            "SizeInBytes",
            *_SIZES,
            "NumberOfMountTargets",
            "OwnerId",
            "PerformanceMode",
            "ProvisionedThroughputInMibps",
            "DBInstanceIdentifier",
            "Region",
            "ThroughputMode",
            *_BACKUP_TAIL,
        ),
        _efs,
        tags="first_seen",
    ),
    FileSpec(
        "aws_DynamoDB_info",
        "dynamodb_tables",
        (
            *_HEAD,
            "Region",
            "TableName",
            "TableId",
            "TableArn",
            "ResourceArn",
            "TableSizeBytes",
            "TableStatus",
            "TableSizeGiB",
            "TableSizeTiB",
            "TableSizeGB",
            "TableSizeTB",
            "ItemCount",
            "DeletionProtectionEnabled",
            "GlobalTableVersion",
            "ProvisionedThroughputLastDecreaseDateTime",
            "ProvisionedThroughputLastIncreaseDateTime",
            "ProvisionedThroughput.NumberOfDecreasesToday",
            "ProvisionedThroughputReadCapacityUnits",
            "ProvisionedThroughputWriteCapacityUnits",
            "BackupPlans",
            "InBackupPlan",
            "PITREnabled",
            *_BACKUP_COLUMNS,
        ),
        _dynamodb,
    ),
    FileSpec(
        "aws_s3_info",
        "s3_buckets",
        (
            *_HEAD,
            "BucketName",
            "ResourceArn",
            "Region",
            "BackupPlans",
            "InBackupPlan",
            *_BACKUP_COLUMNS,
            "StandardStorage_SizeGB",
            "StandardStorage_SizeTB",
            "StandardStorage_SizeGiB",
            "StandardStorage_SizeTiB",
            "StandardStorage_SizeBytes",
            "NumberOfObjects-AllStorageTypes",
            "HasIcebergTable",
        ),
        _s3,
        tags="sorted",
        tag_name=True,
        dynamic=True,
    ),
    FileSpec(
        "aws_rds_snapshot_info",
        "rds_snapshots",
        (
            *_HEAD,
            "Region",
            "Source",
            "Engine",
            "SnapshotIdentifier",
            "ResourceArn",
            "SnapshotArn",
            "SizeBytes",
            "SizeGiB",
            "CreationDate",
            "SnapshotType",
            "Status",
            "ClusterIdentifier",
        ),
        _rds_snapshot,
        quoted_empty=_QUOTED_EMPTY | {"ClusterIdentifier"},
    ),
    FileSpec(
        "aws_ebs_and_ami_info",
        "ebs_and_ami",
        (
            *_HEAD,
            "Region",
            "Source",
            "ImageId",
            "SnapshotId",
            "ResourceArn",
            "SizeBytes",
            "SizeGiB",
            "CreationDate",
            "Name",
            "Description",
            "State",
        ),
        _ebs_and_ami,
        quoted_empty=_QUOTED_EMPTY | {"ImageId", "SnapshotId", "Name"},
    ),
    FileSpec(
        "aws_vpc_info",
        "vpcs",
        (*_HEAD, "Region", "VpcId", "OwnerId", "CidrBlock", "State", "IsDefault"),
        _vpc,
        tags="first_seen",
        tag_name=True,
        tag_keep_hyphen=True,
    ),
    FileSpec(
        "aws_lb_info",
        "load_balancers",
        (*_HEAD, "Region", "LoadBalancerName", "Type", "Scheme", "VpcId", "DNSName", "Arn"),
        _load_balancer,
        tags="first_seen",
        tag_keep_hyphen=True,
    ),
    FileSpec(
        "aws_route53_info",
        "route53_zones",
        (*_HEAD, "HostedZoneId", "Name", "PrivateZone", "ResourceRecordSetCount"),
        _route53,
    ),
    FileSpec(
        "aws_iam_info",
        "iam_summaries",
        (*_HEAD, "Users", "Roles", "CustomerManagedPolicies"),
        _iam,
    ),
    FileSpec(
        "aws_eks_clusters_info",
        "eks_clusters",
        (*_HEAD, "Name", "Version", "PlatformVersion", "Status", "Arn", "RoleArn", "Region"),
        _eks_cluster,
        tags="first_seen",
        tag_name=True,
    ),
    FileSpec(
        "aws_eks_nodegroups_info",
        "eks_nodegroups",
        (
            *_HEAD,
            "NodegroupName",
            "ClusterName",
            "DiskSize",
            "CapacityType",
            "AmiType",
            "NodegroupArn",
            "NodeRole",
            "Status",
            "ReleaseVersion",
            "Version",
            "Region",
        ),
        _eks_nodegroup,
        tags="first_seen",
        tag_name=True,
    ),
    FileSpec(
        "aws_kms_numbers",
        "kms_keys",
        (*_HEAD, "Region", "Alias", "KeyId", "Arn", "KeyManager", "KeyState", "CreationDate"),
        _kms_key,
    ),
    FileSpec(
        "aws_redshift_info",
        "redshift_clusters",
        (
            *_HEAD,
            "Region",
            "ClusterIdentifier",
            "ResourceArn",
            "NodeType",
            "NumberOfNodes",
            "ClusterStatus",
            "MasterUsername",
            "DBName",
            "ClusterCreateTime",
            "AutomatedSnapshotRetentionPeriod",
            "ManualSnapshotRetentionPeriod",
            *_BACKUP_COLUMNS,
        ),
        _redshift,
    ),
    FileSpec(
        "aws_backup_costs",
        "backup_cost_months",
        (
            *_HEAD,
            "Time-Period-Start",
            "Time-Period-End",
            *(f"AWSBackup{m}" for m in _COST_METRICS),
        ),
        _backup_cost,
    ),
    FileSpec(
        "aws_snapshot_storage_costs",
        "snapshot_storage_costs",
        (
            *_HEAD,
            "Time-Period-Start",
            "Time-Period-End",
            "Service",
            "UsageType",
            "UsageQuantity",
            "UsageUnit",
            "AmortizedCost",
            "BlendedCost",
            "NetAmortizedCost",
            "NetUnblendedCost",
            "UnblendedCost",
            "NormalizedUsageAmount",
        ),
        _snapshot_storage_cost,
        quoted_empty=_QUOTED_EMPTY | {"UsageUnit"},
    ),
    FileSpec(
        "aws_fsx_filesystem_info",
        "fsx_filesystems",
        _FSX_FILE_SYSTEM_COLUMNS,
        _fsx_file_system,
        tags="inline",
        dynamic=True,
    ),
    FileSpec(
        "aws_fsx_volume_info",
        "fsx_volumes",
        _FSX_VOLUME_COLUMNS,
        _fsx_volume,
        tags="inline",
        dynamic=True,
    ),
    FileSpec(
        "aws_s3_tables_info",
        "s3_tables",
        _S3_TABLES_COLUMNS,
        _s3_table,
        tags="inline",
        dynamic=True,
        quoted_empty=_QUOTED_EMPTY
        | {"WarehouseLocation", "MetadataLocation", "MetadataFileStorageClass"},
    ),
    FileSpec(
        "aws_glue_iceberg_info",
        "glue_iceberg_tables",
        _GLUE_ICEBERG_COLUMNS,
        _glue_iceberg,
        tags="inline",
        dynamic=True,
        quoted_empty=_QUOTED_EMPTY | {"S3BucketName", "S3Location", "MetadataFileStorageClass"},
    ),
    FileSpec(
        "aws_backup_recovery_points",
        "backup_recovery_points",
        (
            "AwsAccountId",
            "AwsAccountAlias",
            "Region",
            "BackupVaultName",
            "BackupVaultArn",
            "RecoveryPointArn",
            "ResourceArn",
            "ResourceId",
            "ResourceName",
            "ResourceType",
            "BackupSizeBytes",
            "BackupSizeGiB",
            "BackupSizeTiB",
            "CreationDate",
            "BackupPlanId",
            "BackupPlanName",
            "Status",
            "IsParent",
            "ParentRecoveryPointArn",
            "Source",
        ),
        _recovery_point,
        regions_by_name=True,
        quoted_empty=_QUOTED_EMPTY | {"ResourceId", "BackupPlanId", "BackupPlanName"},
    ),
    FileSpec(
        "aws_secrets_numbers",
        "secrets_counts",
        (*_HEAD, "Region", "Secrets"),
        _secrets,
    ),
    FileSpec(
        "aws_sqs_numbers",
        "sqs_counts",
        (*_HEAD, "Region", "Queues"),
        _sqs,
    ),
)


# ── assembly ──────────────────────────────────────────────────────────────────


def _is_tag(column: str) -> bool:
    return column.casefold().startswith("tag:")


def _union(rows: list[dict[str, Any]], keep) -> list[str]:
    """Columns of ``rows`` that ``keep`` accepts, in the order they are first seen."""
    seen: dict[str, None] = {}
    for row in rows:
        for column in row:
            if keep(column):
                seen.setdefault(column)
    return list(seen)


# What PowerShell writes for a file with no rows. ``Export-Csv`` of an empty list leaves a
# zero-byte file, which is what almost every file gets. Six outputs have a fallback written by
# hand: the recovery points file seeds the same quoted header the data rows use, and the other
# five are literals copied byte for byte from the script (``Get-AWSSizingInfo.ps1``, "Export to
# CSV"): unquoted headers, with a ``#TYPE`` line first for the backup costs. The Redshift
# literal lists ``ResourceArn`` after ``ManualSnapshotRetentionPeriod`` although its rows put it
# after ``ClusterIdentifier``; the literal is copied as it is.
_HEADER_WHEN_EMPTY = frozenset({"aws_backup_recovery_points"})
_EMPTY_FILE_TEXT = {
    "aws_backup_costs": (
        "#TYPE System.Management.Automation.PSCustomObject\n"
        '"AwsAccountId","AwsAccountAlias","Time-Period-Start","Time-Period-End",'
        '"AWSBackupAmortizedCost","AWSBackupBlendedCost","AWSBackupNetAmortizedCost",'
        '"AWSBackupNetUnblendedCost","AWSBackupNormalizedUsageAmount","AWSBackupUnblendedCost",'
        '"AWSBackupUsageQuantity"\n'
    ),
    "aws_snapshot_storage_costs": (
        "AwsAccountId,AwsAccountAlias,Time-Period-Start,Time-Period-End,Service,UsageType,"
        "UsageQuantity,UsageUnit,AmortizedCost,BlendedCost,NetAmortizedCost,NetUnblendedCost,"
        "UnblendedCost,NormalizedUsageAmount\n"
    ),
    "aws_ebs_and_ami_info": (
        "AwsAccountId,AwsAccountAlias,Region,Source,ImageId,SnapshotId,ResourceArn,SizeBytes,"
        "SizeGiB,CreationDate,Name,Description,State\n"
    ),
    "aws_rds_snapshot_info": (
        "AwsAccountId,AwsAccountAlias,Region,Source,Engine,SnapshotIdentifier,ResourceArn,"
        "SnapshotArn,SizeBytes,SizeGiB,CreationDate,SnapshotType,Status,ClusterIdentifier\n"
    ),
    "aws_redshift_info": (
        "AwsAccountId,AwsAccountAlias,Region,ClusterIdentifier,NodeType,NumberOfNodes,"
        "ClusterStatus,MasterUsername,DBName,ClusterCreateTime,AutomatedSnapshotRetentionPeriod,"
        "ManualSnapshotRetentionPeriod,ResourceArn,HasBackups,HasRecoveryPoints,BackupCount,"
        "BackupSources,LatestBackupDate,LatestBackupSizeGiB,LatestBackupSizeTiB,"
        "LatestBackupSizeGB,LatestBackupSizeTB,BackupEnumerationTruncated\n"
    ),
}


def _empty_file_text(spec: FileSpec) -> str:
    """The text of ``spec``'s file when there are no rows, as PowerShell writes it."""
    if spec.prefix in _EMPTY_FILE_TEXT:
        return _EMPTY_FILE_TEXT[spec.prefix]
    if spec.prefix in _HEADER_WHEN_EMPTY:
        return render(list(spec.columns), [], spec.quoted_empty)
    return ""


def _file_content(
    spec: FileSpec, records: list[dict], anonymizer: "Anonymizer | None" = None
) -> str:
    rows: list[dict[str, Any]] = []
    for record in records:
        row = spec.build(record)
        if spec.tags != "none":
            row.update(_tag_columns(record.get("tags"), spec.tag_name, spec.tag_keep_hyphen))
        rows.append(row)
    if not rows:
        return _empty_file_text(spec)

    if spec.tags == "sorted":
        if anonymizer is not None:
            # PowerShell anonymizes the bucket rows once before it gives them all the same tag
            # columns, so the tag numbers follow the order the buckets and their tags come in.
            for row in rows:
                anonymizer.anonymize_row(dict(row))
        tag_order = sorted(_union(rows, _is_tag), key=str.lower)
        rows = [
            {
                **{c: v for c, v in row.items() if not _is_tag(c)},
                **{c: row.get(c) for c in tag_order},
            }
            for row in rows
        ]

    if anonymizer is not None:
        rows = [anonymizer.anonymize_row(row) for row in rows]

    tag_columns = _union(rows, _is_tag)
    if spec.dynamic and rows:
        plain_columns = _union(rows, lambda c: not _is_tag(c))
        for row in rows:
            for column in plain_columns:
                if column not in row and _blank_means_zero(column):
                    row[column] = 0
        header = (
            _union(rows, lambda c: True)
            if spec.tags == "inline"
            else [
                *plain_columns,
                *tag_columns,
            ]
        )
    else:
        header = [*spec.columns, *tag_columns]
    return render(header, rows, spec.quoted_empty)


def _ordered(results: list[dict], collection: str, by_name: bool = False) -> list[dict]:
    """Records by account, then region in scan order, then collection order within a region.

    PowerShell writes regions in the order AWS lists them and rows in API order, so this keeps
    rows (and the first-seen order of tag columns) the same as a PowerShell run.
    """
    entries = []
    for index, result in enumerate(results):
        rank: dict[str, int] = {}
        for region in result.get("regions_scanned") or []:
            rank.setdefault(region, len(rank))
        for position, record in enumerate(result.get(collection) or []):
            region = str(record.get("region", ""))
            entries.append(
                (
                    str(record.get("account_id", "")),
                    0 if by_name else rank.get(region, len(rank)),
                    region,
                    index,
                    position,
                    record,
                )
            )
    entries.sort(key=lambda e: e[:5])
    return [e[5] for e in entries]


# ── backup plan membership ────────────────────────────────────────────────────

# Collections a backup plan can select, with the row kind ``backup_plan_membership`` knows them
# by. Unattached volumes are left out on purpose: PowerShell never matches them to a plan.
_PLAN_KINDS = {
    "ec2_instances": "ec2_instance",
    "ec2_attached_volumes": "ebs_attached",
    "rds_instances": "rds",
    "efs_filesystems": "efs",
    "fsx_volumes": "fsx_volume",
    "fsx_filesystems": "fsx_filesystem",
    "s3_buckets": "s3",
    "dynamodb_tables": "dynamodb",
    "s3_tables": "s3_table",
}
_UNATTACHED_VOLUMES = "ec2_unattached_volumes"
# Rows whose PowerShell tag columns keep the Name tag (S3 and S3 Tables); the others drop it.
_PLAN_KEEPS_NAME_TAG = frozenset({"s3", "s3_table"})


def _scan_key(account_id: Any, region: Any) -> tuple[str, str]:
    return (str(account_id), str(region).lower())


def _plan_row(kind: str, r: dict) -> RowView:
    """What the plan matcher needs of a record. ARNs come from the same helpers as the row
    builders, so a ``NotResources`` ARN matches the ``ResourceArn`` the CSV shows."""
    region, account = r["region"], r["account_id"]
    if kind == "ec2_instance":
        ids = {"InstanceId": r["instance_id"]}
        arn = arns.instance_arn(region, account, r["instance_id"])
    elif kind == "ebs_attached":
        ids = {"VolumeId": r["volume_id"]}
        arn = _volume_arn(r)
    elif kind == "rds":
        ids = {"DBInstanceIdentifier": r["db_instance_identifier"]}
        arn = arns.rds_db_arn(region, account, r["db_instance_identifier"])
    elif kind == "efs":
        ids = {"FileSystemId": r["file_system_id"]}
        arn = arns.efs_arn(region, account, r["file_system_id"])
    elif kind == "fsx_filesystem":
        ids = {"FileSystemId": r["file_system_id"]}
        arn = arns.fsx_file_system_arn(region, account, r["file_system_id"])
    elif kind == "fsx_volume":
        ids = {"VolumeId": r["volume_id"]}
        if r.get("file_system_id") is not None:
            ids["FileSystemId"] = r["file_system_id"]
        arn = arns.fsx_volume_arn(region, account, r["volume_id"])
    elif kind == "s3":
        ids = {"BucketName": r["bucket_name"]}
        arn = arns.s3_arn(region, r["bucket_name"])
    elif kind == "dynamodb":
        ids = {"TableName": r["table_name"]}
        arn = r.get("table_arn") or ""
    else:  # s3_table
        ids = (
            {}
            if r.get("table_bucket_name") is None
            else {"TableBucketName": r["table_bucket_name"]}
        )
        arn = r.get("table_arn") or ""
    tags: dict[str, Any] = {}
    if kind != "dynamodb":  # DynamoDB rows have no tag columns
        tags = _tag_columns(r.get("tags"), kind in _PLAN_KEEPS_NAME_TAG)
        if kind not in _PLAN_KEEPS_NAME_TAG:
            # PowerShell drops the Name tag ignoring case; _tag_columns only drops "Name"
            tags = {c: v for c, v in tags.items() if c.lower() != "tag: name"}
    return RowView(kind, str(account), region, ids, arn, tags)


@dataclass
class _PlanInputs:
    plans: list[dict]
    rows: list[RowView]
    where: list[tuple[int, str, int]]  # per row: result index, collection, record position
    group_order: list[tuple[str, str]]  # (account, region) groups in scan order


def _plan_inputs(results: list[dict]) -> _PlanInputs:
    """The plans and matchable rows of ``results`` and the scan order of their groups.

    The order is ``_ordered``'s: accounts by id, then regions in each result's scan order. It
    decides how far a ``NotResources`` entry reaches, so it must agree with the row order.
    """
    plans: list[dict] = []
    rows: list[RowView] = []
    where: list[tuple[int, str, int]] = []
    order_keys: dict[tuple[str, str], tuple] = {}

    def note(index: int, ranks: dict[str, int], account_id: Any, region: Any) -> None:
        key = _scan_key(account_id, region)
        candidate = (str(account_id), ranks.get(region, len(ranks)), str(region), index)
        if key not in order_keys or candidate < order_keys[key]:
            order_keys[key] = candidate

    for index, result in enumerate(results):
        ranks: dict[str, int] = {}
        for region in result.get("regions_scanned") or []:
            ranks.setdefault(region, len(ranks))
        for plan in result.get("backup_plans") or []:
            plans.append(plan)
            note(index, ranks, plan.get("account_id", ""), plan.get("region", ""))
        for collection, kind in _PLAN_KINDS.items():
            for position, record in enumerate(result.get(collection) or []):
                rows.append(_plan_row(kind, record))
                where.append((index, collection, position))
                note(index, ranks, record["account_id"], record["region"])
        for record in result.get(_UNATTACHED_VOLUMES) or []:
            note(index, ranks, record["account_id"], record["region"])
    group_order = [key for key, _ in sorted(order_keys.items(), key=lambda item: item[1])]
    return _PlanInputs(plans, rows, where, group_order)


def _plan_names_in_scan_order(inputs: _PlanInputs) -> list[str]:
    by_group: dict[tuple[str, str], list[str]] = defaultdict(list)
    for plan in inputs.plans:
        by_group[_scan_key(plan.get("account_id", ""), plan.get("region", ""))].append(
            str(plan.get("plan_name") or "")
        )
    return [name for key in inputs.group_order for name in by_group.get(key, [])]


def _with_plan_membership(results: list[dict], inputs: _PlanInputs) -> list[dict]:
    """``results`` with the plans that select each workload record stamped on shallow copies.

    A record gets ``plan_names`` and ``in_selected_plan`` when its (account, region) has usable
    plan data: at least one plan, every plan carrying ``selections`` (older discovery files do
    not) and none marked incomplete. Unattached volumes then get no plans, as in PowerShell.
    Any other group keeps the older signal (see ``_plan_columns``); the log says so once per
    account, and only where that can change the answer. The callers' dicts are not modified.
    """
    memberships = compute_membership(inputs.plans, inputs.rows, inputs.group_order)
    plans_by_group: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for plan in inputs.plans:
        plans_by_group[_scan_key(plan.get("account_id", ""), plan.get("region", ""))].append(plan)

    def usable(key: tuple[str, str]) -> bool:
        group_plans = plans_by_group.get(key)
        return bool(group_plans) and all(
            "selections" in plan and plan.get("selections_complete") is not False
            for plan in group_plans
        )

    copies: dict[tuple[int, str], list[dict]] = {}

    def stamp(index: int, collection: str, position: int, plan_names: list[str], in_plan: bool):
        if (index, collection) not in copies:
            copies[(index, collection)] = list(results[index][collection])
        record = results[index][collection][position]
        copies[(index, collection)][position] = {
            **record,
            "plan_names": plan_names,
            "in_selected_plan": in_plan,
        }

    degraded: dict[str, set[str]] = defaultdict(set)

    def note_fallback(key: tuple[str, str], record: dict) -> None:
        if plans_by_group.get(key) or _AWS_BACKUP in (record.get("backup_plans") or []):
            degraded[str(record["account_id"])].add(record["region"])

    for row, (index, collection, position), membership in zip(
        inputs.rows, inputs.where, memberships
    ):
        key = _scan_key(row.account_id, row.region)
        if usable(key):
            stamp(index, collection, position, membership.plan_names, membership.in_plan)
        else:
            note_fallback(key, results[index][collection][position])
    for index, result in enumerate(results):
        for position, record in enumerate(result.get(_UNATTACHED_VOLUMES) or []):
            key = _scan_key(record["account_id"], record["region"])
            if usable(key):
                stamp(index, _UNATTACHED_VOLUMES, position, [], False)
            else:
                note_fallback(key, record)

    for account in sorted(degraded):
        log.warning(
            "Account %s: backup plan details are missing or incomplete in %s, so InBackupPlan "
            "there comes from AWS Backup's protected resources and BackupPlans is empty",
            account,
            ", ".join(sorted(degraded[account])),
        )
    if not copies:
        return results
    return [
        {**result, **{c: v for (i, c), v in copies.items() if i == index}}
        for index, result in enumerate(results)
    ]


def rows_by_file(results: list[dict]) -> dict[str, list[dict[str, Any]]]:
    """File prefix -> the row dicts that file is built from, before anonymizing.

    This is the same data the CSV files hold, so totals computed from it match the files.
    """
    results = _with_plan_membership(results, _plan_inputs(results))
    return {
        spec.prefix: [
            spec.build(record)
            for record in _ordered(results, spec.collection, spec.regions_by_name)
        ]
        for spec in FILES
    }


def build_csv_files(
    results: list[dict],
    timestamp: Optional[str] = None,
    anonymizer: Optional[Anonymizer] = None,
) -> dict[str, str]:
    """File name -> CSV text, combining the per-account discovery dicts in ``results``.

    With an ``anonymizer`` the values are replaced as the files are built, in the order
    PowerShell anonymizes its lists in, so the numbers in the labels follow the same order.
    """
    inputs = _plan_inputs(results)
    if anonymizer is not None:
        # PowerShell anonymizes the plan list first, so plan-name labels follow the plan order.
        anonymizer.pre_label(BACKUP_PLAN_NAME_FIELD, _plan_names_in_scan_order(inputs))
    results = _with_plan_membership(results, inputs)
    stamp = timestamp or datetime.now().strftime(TIMESTAMP_FORMAT)
    specs = sorted(FILES, key=lambda s: file_rank(s.prefix)) if anonymizer else FILES
    built: dict[str, str] = {}
    for spec in specs:
        built[spec.prefix] = _file_content(
            spec, _ordered(results, spec.collection, spec.regions_by_name), anonymizer
        )
    return {f"{spec.prefix}-{stamp}.csv": built[spec.prefix] for spec in FILES}


def write_csv_files(
    results: list[dict],
    directory: str,
    timestamp: Optional[str] = None,
    anonymizer: Optional[Anonymizer] = None,
) -> list[str]:
    """Write the CSV files into ``directory`` and return their paths."""
    os.makedirs(directory, exist_ok=True)
    paths = []
    for name, text in build_csv_files(results, timestamp, anonymizer).items():
        path = os.path.join(directory, name)
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(text)
        paths.append(path)
    return paths
