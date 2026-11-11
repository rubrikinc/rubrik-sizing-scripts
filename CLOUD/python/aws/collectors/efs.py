"""EFS file system collector."""

from __future__ import annotations

import logging

from models.discovery import EFSFileSystem

from collectors import DenialTracker, is_scp_denial
from collectors.arns import efs_arn


def _tags_to_dict(tag_list: list) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def _round4(v: float) -> float:
    return round(v, 4)


def fetch_efs(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    tracker: "DenialTracker | None" = None,
) -> list[EFSFileSystem]:
    """Fetch all EFS file systems and their sizing metadata."""
    client = session.client("efs", region_name=region)
    systems: list[EFSFileSystem] = []

    try:
        paginator = client.get_paginator("describe_file_systems")
        for page in paginator.paginate():
            for fs in page.get("FileSystems", []):
                fs_id = fs.get("FileSystemId", "")
                size_bytes = (fs.get("SizeInBytes") or {}).get("Value", 0)
                size_gib = _round4(size_bytes / (1024**3))
                size_tb = _round4(size_gib / 1024)

                fs_arn = fs.get("FileSystemArn", efs_arn(region, account_id, fs_id))
                backup_plans = ["AWS Backup"] if fs_arn in protected_arns else []

                tags = _tags_to_dict(fs.get("Tags"))
                name = tags.get("Name", "")

                systems.append(
                    EFSFileSystem(
                        account_id=account_id,
                        account_alias=account_alias,
                        file_system_id=fs_id,
                        name=name,
                        size_bytes=size_bytes,
                        size_gib=size_gib,
                        size_tb=size_tb,
                        mount_targets=fs.get("NumberOfMountTargets") or 0,
                        owner_id=fs.get("OwnerId") or "",
                        performance_mode=str(fs.get("PerformanceMode", "")),
                        throughput_mode=str(fs.get("ThroughputMode", "")),
                        provisioned_throughput_mibps=float(
                            fs.get("ProvisionedThroughputInMibps") or 0
                        ),
                        region=region,
                        in_backup_plan=bool(backup_plans),
                        backup_plans=backup_plans,
                        tags=tags,
                        file_system_protection=str(
                            (fs.get("FileSystemProtection") or {}).get(
                                "ReplicationOverwriteProtection", ""
                            )
                        ),
                    )
                )
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("efs")
            logging.debug("Could not fetch EFS file systems in %s (SCP denied)", region)
        else:
            if tracker is not None:
                tracker.record_permission_error("efs", region, exc)
            logging.warning("Could not fetch EFS file systems in %s: %s", region, exc)

    return systems
