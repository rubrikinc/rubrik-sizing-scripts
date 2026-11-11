"""Amazon FSx file systems and volumes. Port of ``Get-AWSFSxInventory``."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from models.discovery import FSxFileSystem, FSxVolume

from collectors import BOTO_ADAPTIVE_CFG, DenialTracker, is_scp_denial, record_metric_failures

log = logging.getLogger(__name__)

_WINDOW = timedelta(days=7)
_PERIOD = 3600

# Per file system type: (column prefix, CloudWatch metric, statistic, how to reduce the hourly
# datapoints). PowerShell reads Lustre's three metrics from an unset variable, so its Lustre
# columns are empty or stale; here physical and logical usage are their peak hourly sum and free
# capacity is the lowest hourly sum, which is what the variable names say it intended.
_Reduce = Callable[[list[float]], float]
_METRICS: dict[str, tuple[tuple[str, str, str, _Reduce], ...]] = {
    "ontap": (("StorageUsed", "StorageUsed", "Maximum", max),),
    "windows": (
        (
            "StorageCapacityUtilizationPercentage",
            "StorageCapacityUtilization",
            "Maximum",
            max,
        ),
    ),
    "lustre": (
        ("PhysicalDiskUsage", "PhysicalDiskUsage", "Sum", max),
        ("LogicalDiskUsage", "LogicalDiskUsage", "Sum", max),
        ("FreeDataStorageCapacity", "FreeDataStorageCapacity", "Sum", min),
    ),
    "openzfs": (("UsedStorageCapacity", "UsedStorageCapacity", "Maximum", max),),
}


def _tags_to_dict(tag_list: list) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def _record(tracker: "DenialTracker | None", region: str, what: str, exc: Exception) -> None:
    if is_scp_denial(exc):
        if tracker is not None:
            tracker.record("fsx")
        log.debug("%s in %s (SCP denied)", what, region)
    elif tracker is not None:
        tracker.record_permission_error("fsx", region, exc)
        log.warning("%s in %s: %s", what, region, exc)
    else:
        log.warning("%s in %s: %s", what, region, exc)


def _config_type(fs: dict) -> str:
    for key, name in (
        ("OntapConfiguration", "ontap"),
        ("WindowsConfiguration", "windows"),
        ("LustreConfiguration", "lustre"),
        ("OpenZFSConfiguration", "openzfs"),
    ):
        if fs.get(key) is not None:
            return name
    return ""


def _statistic(
    cw_client,
    metric_name: str,
    dimensions: list[dict],
    statistic: str,
    reduce: _Reduce,
    errors: list[Exception],
) -> Optional[float]:
    """The reduced hourly datapoints of the last 7 days; None without datapoints or on failure."""
    end = datetime.now(timezone.utc)
    try:
        resp = cw_client.get_metric_statistics(
            Namespace="AWS/FSx",
            MetricName=metric_name,
            Dimensions=dimensions,
            StartTime=end - _WINDOW,
            EndTime=end,
            Period=_PERIOD,
            Statistics=[statistic],
        )
    except Exception as exc:
        errors.append(exc)
        return None
    values = [float(dp[statistic]) for dp in resp.get("Datapoints", []) if statistic in dp]
    return reduce(values) if values else None


def fetch_fsx(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    tracker: "DenialTracker | None" = None,
) -> list[FSxFileSystem]:
    """All FSx file systems with their capacity and the usage metrics of their type."""
    client = session.client("fsx", region_name=region)
    cw_client = session.client("cloudwatch", region_name=region, config=BOTO_ADAPTIVE_CFG)
    filesystems: list[FSxFileSystem] = []
    metric_errors: list[Exception] = []

    try:
        for page in client.get_paginator("describe_file_systems").paginate():
            for fs in page.get("FileSystems", []):
                fs_id = fs.get("FileSystemId", "")
                fs_type = fs.get("FileSystemType", "")
                storage_gib = int(fs.get("StorageCapacity") or 0)
                resource_arn = fs.get("ResourceARN", "")
                backup_plans = ["AWS Backup"] if resource_arn in protected_arns else []
                tags = _tags_to_dict(fs.get("Tags"))
                config = _config_type(fs)
                dimensions = [{"Name": "FileSystemId", "Value": fs_id}]
                usage = {
                    prefix: _statistic(cw_client, metric, dimensions, stat, reduce, metric_errors)
                    for prefix, metric, stat, reduce in _METRICS.get(config, ())
                }
                filesystems.append(
                    FSxFileSystem(
                        account_id=account_id,
                        account_alias=account_alias,
                        file_system_id=fs_id,
                        file_system_type=fs_type,
                        name=tags.get("Name", ""),
                        storage_capacity_gib=storage_gib,
                        storage_capacity_tb=round(storage_gib / 1024, 4),
                        storage_capacity_bytes_derived=storage_gib * 1024**3,
                        storage_type=str(fs.get("StorageType", "")),
                        lifecycle=str(fs.get("Lifecycle", "")),
                        region=region,
                        dns_name=str(fs.get("DNSName", "")),
                        in_backup_plan=bool(backup_plans),
                        backup_plans=backup_plans,
                        tags=tags,
                        file_system_type_version=str(fs.get("FileSystemTypeVersion") or ""),
                        owner_id=str(fs.get("OwnerId") or ""),
                        config_type=config,
                        usage_metrics=usage,
                    )
                )
    except Exception as exc:
        _record(tracker, region, "Could not fetch FSx file systems", exc)

    record_metric_failures(tracker, region, "FSx CloudWatch metrics", metric_errors)
    return filesystems


def fetch_fsx_volumes(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    file_systems: list[FSxFileSystem],
    tracker: "DenialTracker | None" = None,
) -> list[FSxVolume]:
    """ONTAP and OpenZFS volumes with their storage used and capacity (largest hourly maximum
    over 7 days). Parent file system details come from ``file_systems``, collected for the
    same region, so no extra API call is made per volume.
    """
    client = session.client("fsx", region_name=region)
    cw_client = session.client("cloudwatch", region_name=region, config=BOTO_ADAPTIVE_CFG)
    parents = {fs.file_system_id: fs for fs in file_systems}
    volumes: list[FSxVolume] = []
    metric_errors: list[Exception] = []

    try:
        for page in client.get_paginator("describe_volumes").paginate():
            for vol in page.get("Volumes", []):
                volume_id = vol.get("VolumeId", "")
                fs_id = vol.get("FileSystemId", "")
                dimensions = [
                    {"Name": "FileSystemId", "Value": fs_id},
                    {"Name": "VolumeId", "Value": volume_id},
                ]
                used, capacity = (
                    _statistic(cw_client, metric, dimensions, "Maximum", max, metric_errors)
                    for metric in ("StorageUsed", "StorageCapacity")
                )
                resource_arn = vol.get("ResourceARN", "")
                backup_plans = ["AWS Backup"] if resource_arn in protected_arns else []
                parent = parents.get(fs_id)
                volumes.append(
                    FSxVolume(
                        account_id=account_id,
                        account_alias=account_alias,
                        region=region,
                        file_system_id=fs_id,
                        volume_id=volume_id,
                        name=str(vol.get("Name") or ""),
                        volume_type=str(vol.get("VolumeType") or ""),
                        lifecycle=str(vol.get("Lifecycle") or ""),
                        resource_arn=resource_arn,
                        storage_used_bytes=used,
                        storage_capacity_bytes=capacity,
                        in_backup_plan=bool(backup_plans),
                        backup_plans=backup_plans,
                        file_system_dns_name=parent.dns_name if parent else "",
                        file_system_type=parent.file_system_type if parent else "",
                        file_system_type_version=parent.file_system_type_version if parent else "",
                        file_system_owner_id=parent.owner_id if parent else "",
                        file_system_storage_type=parent.storage_type if parent else "",
                        tags=_tags_to_dict(vol.get("Tags")),
                    )
                )
    except Exception as exc:
        _record(tracker, region, "Could not fetch FSx volumes", exc)

    record_metric_failures(tracker, region, "FSx volume CloudWatch metrics", metric_errors)
    return volumes
