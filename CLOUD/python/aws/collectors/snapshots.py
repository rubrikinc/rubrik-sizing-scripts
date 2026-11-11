"""Native (non-AWS-Backup) backups: RDS snapshots, EBS snapshots and AMIs.

Port of ``Get-AWSRDSSnapshotInventory``, ``Get-AWSEBSAndAMIInventory`` and the native part of
``Merge-BackupAggregates`` in ``Get-AWSSizingInfo.ps1``. Each collector returns the backups to
merge into the per-resource backup columns and the per-snapshot detail rows for the
``aws_rds_snapshot_info`` and ``aws_ebs_and_ami_info`` files.

Rules kept from the PowerShell script:
  * only completed backups count (RDS ``available``, EBS ``completed``, AMI ``available``);
  * snapshots AWS Backup created are skipped (RDS ``awsbackup:job-`` prefix, EBS
    ``aws:backup:source-resource`` tag) because the recovery-point path counts them;
  * DocumentDB and Neptune are skipped (unsupported);
  * the size of the latest backup is used, never a sum.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from models.discovery import BackupSummary, DynamoDBTable, RecoveryPointAggregate

from collectors import DenialTracker, is_scp_denial, record_metric_failures
from collectors.arns import (
    fsx_file_system_arn,
    fsx_volume_arn,
    image_arn,
    instance_arn,
    rds_cluster_arn,
    rds_db_arn,
    redshift_arn,
    snapshot_arn,
    volume_arn,
)

log = logging.getLogger(__name__)

_GIB = 1024**3
_UNSUPPORTED_ENGINES = ("docdb", "neptune")
_CREATE_IMAGE_RE = re.compile(r"CreateImage\((i-[0-9a-f]+)\)")
_INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]+$")


@dataclass
class NativeBackup:
    account_id: str
    region: str
    resource_arn: str
    source: str
    size_bytes: int
    creation_date: Optional[str]  # ISO 8601, UTC


@dataclass
class RDSSnapshotRow:
    account_id: str
    account_alias: str
    region: str
    source: str
    engine: str
    snapshot_identifier: str
    resource_arn: str
    snapshot_arn: str
    size_bytes: int
    creation_date: Optional[str]
    snapshot_type: str
    status: str
    cluster_identifier: str


@dataclass
class EbsAmiRow:
    account_id: str
    account_alias: str
    region: str
    source: str
    image_id: str
    snapshot_id: str
    resource_arn: str
    size_bytes: int
    creation_date: Optional[str]
    name: str
    description: str
    state: str


def _iso(value: Any) -> Optional[str]:
    """ISO 8601 UTC text for a datetime or an ISO/EC2 timestamp string."""
    if value is None or value == "":
        return None
    if isinstance(value, str):
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _record_failure(
    tracker: "DenialTracker | None", region: str, what: str, exc: Exception
) -> None:
    if is_scp_denial(exc):
        if tracker is not None:
            tracker.record("snapshots")
        log.debug("%s in %s (SCP denied)", what, region)
    else:
        record_metric_failures(tracker, region, what, [exc], service="snapshots")


def _paginate(client, operation: str, key: str, **kwargs) -> list[dict]:
    items: list[dict] = []
    for page in client.get_paginator(operation).paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def _unsupported(engine: Any) -> bool:
    text = str(engine or "").lower()
    return any(name in text for name in _UNSUPPORTED_ENGINES)


# ── RDS ───────────────────────────────────────────────────────────────────────


def fetch_rds_snapshots(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> tuple[list[NativeBackup], list[RDSSnapshotRow]]:
    """Available DB and cluster snapshots, minus AWS Backup's and unsupported engines'."""
    client = session.client("rds", region_name=region)
    backups: list[NativeBackup] = []
    rows: list[RDSSnapshotRow] = []

    def add(snap: dict, *, cluster: bool) -> None:
        if snap.get("Status") != "available":
            return
        identifier = snap.get("DBClusterSnapshotIdentifier" if cluster else "DBSnapshotIdentifier")
        if str(identifier or "").startswith("awsbackup:job-") or _unsupported(snap.get("Engine")):
            return
        if cluster:
            # Aurora cluster snapshots report a meaningless 1 GiB; the source cluster row
            # already carries the real size, so the snapshot contributes none.
            size = 0
            arn = rds_cluster_arn(region, account_id, snap.get("DBClusterIdentifier", ""))
            snap_arn = snap.get("DBClusterSnapshotArn", "")
        else:
            size = int(snap.get("AllocatedStorage") or 0) * _GIB
            arn = rds_db_arn(region, account_id, snap.get("DBInstanceIdentifier", ""))
            snap_arn = snap.get("DBSnapshotArn", "")
        source = "RDSAutomated" if snap.get("SnapshotType") == "automated" else "RDSManual"
        created = _iso(snap.get("SnapshotCreateTime"))
        backups.append(NativeBackup(account_id, region, arn, source, size, created))
        rows.append(
            RDSSnapshotRow(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                source=source,
                engine=snap.get("Engine", ""),
                snapshot_identifier=identifier,
                resource_arn=arn,
                snapshot_arn=snap_arn,
                size_bytes=size,
                creation_date=created,
                snapshot_type=snap.get("SnapshotType", ""),
                status=snap.get("Status", ""),
                cluster_identifier=snap.get("DBClusterIdentifier", "") if cluster else "",
            )
        )

    for operation, key, cluster in (
        ("describe_db_snapshots", "DBSnapshots", False),
        ("describe_db_cluster_snapshots", "DBClusterSnapshots", True),
    ):
        try:
            for snap in _paginate(client, operation, key):
                add(snap, cluster=cluster)
        except Exception as exc:
            _record_failure(tracker, region, f"RDS {operation}", exc)
    return backups, rows


# ── EBS snapshots and AMIs ────────────────────────────────────────────────────


def _snapshot_size(snap: dict) -> int:
    full = snap.get("FullSnapshotSizeInBytes")
    if full is not None:
        return int(full)
    if snap.get("VolumeSize") is not None:
        return int(snap["VolumeSize"]) * _GIB
    return 0


def fetch_ebs_and_ami(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> tuple[list[NativeBackup], list[EbsAmiRow]]:
    """Completed EBS snapshots (minus AMI-backing and AWS Backup ones) and available AMIs.

    AMIs are attributed to the instance they were created from (found through the
    ``CreateImage(i-...)`` text in their snapshots' descriptions, then the
    ``ec2:source-instance-id`` tag); otherwise to the AMI itself.
    """
    client = session.client("ec2", region_name=region)
    backups: list[NativeBackup] = []
    rows: list[EbsAmiRow] = []

    images: list[dict] = []
    try:
        images = client.describe_images(Owners=["self"]).get("Images", [])
    except Exception as exc:
        _record_failure(tracker, region, "EC2 describe_images", exc)

    snapshots: list[dict] = []
    try:
        snapshots = _paginate(client, "describe_snapshots", "Snapshots", OwnerIds=["self"])
    except Exception as exc:
        _record_failure(tracker, region, "EC2 describe_snapshots", exc)

    snap_to_instance: dict[str, str] = {}
    snap_size: dict[str, int] = {}
    for snap in snapshots:
        match = _CREATE_IMAGE_RE.search(str(snap.get("Description") or ""))
        if match:
            snap_to_instance[snap["SnapshotId"]] = match.group(1)
        snap_size[snap["SnapshotId"]] = _snapshot_size(snap)

    ami_snapshot_ids: set[str] = set()
    for image in images:
        if image.get("State") != "available":
            continue
        ids = [
            bdm["Ebs"]["SnapshotId"]
            for bdm in image.get("BlockDeviceMappings", [])
            if (bdm.get("Ebs") or {}).get("SnapshotId")
        ]
        ami_snapshot_ids.update(ids)

        source_instance = next((snap_to_instance[i] for i in ids if i in snap_to_instance), None)
        if not source_instance:
            for tag in image.get("Tags", []):
                if tag.get("Key") == "ec2:source-instance-id" and _INSTANCE_ID_RE.match(
                    str(tag.get("Value", ""))
                ):
                    source_instance = tag["Value"]
                    break
        arn = (
            instance_arn(region, account_id, source_instance)
            if source_instance
            else image_arn(region, account_id, image["ImageId"])
        )
        size = sum(snap_size.get(i, 0) for i in ids)
        created = _iso(image.get("CreationDate"))
        backups.append(NativeBackup(account_id, region, arn, "AMI", size, created))
        rows.append(
            EbsAmiRow(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                source="AMI",
                image_id=image["ImageId"],
                snapshot_id="",
                resource_arn=arn,
                size_bytes=size,
                creation_date=created,
                name=image.get("Name", ""),
                description=image.get("Description", ""),
                state=image.get("State", ""),
            )
        )

    for snap in snapshots:
        if snap.get("State") != "completed" or snap["SnapshotId"] in ami_snapshot_ids:
            continue
        if any(t.get("Key") == "aws:backup:source-resource" for t in snap.get("Tags", [])):
            continue  # AWS Backup created it; the recovery-point path counts it
        volume_id = snap.get("VolumeId")
        arn = (
            volume_arn(region, account_id, volume_id)
            if volume_id
            else snapshot_arn(region, snap["SnapshotId"])
        )
        size = snap_size.get(snap["SnapshotId"], 0)
        created = _iso(snap.get("StartTime"))
        backups.append(NativeBackup(account_id, region, arn, "EBSNative", size, created))
        rows.append(
            EbsAmiRow(
                account_id=account_id,
                account_alias=account_alias,
                region=region,
                source="EBSNative",
                image_id="",
                snapshot_id=snap["SnapshotId"],
                resource_arn=arn,
                size_bytes=size,
                creation_date=created,
                name="",
                description=snap.get("Description", ""),
                state=snap.get("State", ""),
            )
        )
    return backups, rows


# ── merge ─────────────────────────────────────────────────────────────────────


# ── FSx, DynamoDB and Redshift ────────────────────────────────────────────────


def fetch_fsx_backups(
    session, region: str, account_id: str, tracker: "DenialTracker | None" = None
) -> list[NativeBackup]:
    """Available FSx backups other than the ones AWS Backup made.

    Each is attributed to its source file system or volume by rebuilding that resource's ARN;
    the backup's own ``ResourceARN`` is the backup, not its source.
    """
    client = session.client("fsx", region_name=region)
    try:
        backups = _paginate(client, "describe_backups", "Backups")
    except Exception as exc:
        _record_failure(tracker, region, "FSx backup listing", exc)
        return []
    found: list[NativeBackup] = []
    for backup in backups:
        kind = str(backup.get("Type", ""))
        # Backups still being created have no size yet and must not replace an earlier one.
        if kind == "AWS_BACKUP" or backup.get("Lifecycle") != "AVAILABLE":
            continue
        file_system = (backup.get("FileSystem") or {}).get("FileSystemId")
        volume = (backup.get("Volume") or {}).get("VolumeId")
        if file_system:
            arn = fsx_file_system_arn(region, account_id, file_system)
        elif volume:
            arn = fsx_volume_arn(region, account_id, volume)
        else:
            arn = str(backup.get("ResourceARN") or "")
        found.append(
            NativeBackup(
                account_id=account_id,
                region=region,
                resource_arn=arn,
                source="FSxAutomatic" if kind == "AUTOMATIC" else "FSxUserInitiated",
                size_bytes=int(backup.get("SizeInBytes") or 0),
                creation_date=_iso(backup.get("CreationTime")),
            )
        )
    return found


def fetch_dynamodb_backups(
    session,
    region: str,
    account_id: str,
    tables: list[DynamoDBTable],
    tracker: "DenialTracker | None" = None,
) -> list[NativeBackup]:
    """Available on-demand DynamoDB backups, plus one entry per table with point-in-time
    recovery on, sized at the table's current size (an upper bound; PITR has no backup size).
    """
    client = session.client("dynamodb", region_name=region)
    found: list[NativeBackup] = []
    try:
        summaries = _paginate(client, "list_backups", "BackupSummaries")
    except Exception as exc:
        _record_failure(tracker, region, "DynamoDB backup listing", exc)
        summaries = []
    for backup in summaries:
        if backup.get("BackupStatus") != "AVAILABLE":
            continue
        found.append(
            NativeBackup(
                account_id=account_id,
                region=region,
                resource_arn=str(backup.get("TableArn") or ""),
                source="DDBOnDemand",
                size_bytes=int(backup.get("BackupSizeBytes") or 0),
                creation_date=_iso(backup.get("BackupCreationDateTime")),
            )
        )
    for table in tables:
        if table.region == region and table.account_id == account_id and table.pitr_enabled:
            found.append(
                NativeBackup(
                    account_id=account_id,
                    region=region,
                    resource_arn=table.table_arn,
                    source="DDBPITR",
                    size_bytes=int(table.size_bytes or 0),
                    creation_date=None,
                )
            )
    return found


def fetch_redshift_snapshots(
    session, region: str, account_id: str, tracker: "DenialTracker | None" = None
) -> list[NativeBackup]:
    """Available Redshift snapshots owned by this account (all native: AWS Backup has no
    Redshift support). Redshift reports decimal megabytes, so one MB is 10^6 bytes here."""
    client = session.client("redshift", region_name=region)
    try:
        snapshots = _paginate(client, "describe_cluster_snapshots", "Snapshots")
    except Exception as exc:
        _record_failure(tracker, region, "Redshift snapshot listing", exc)
        return []
    found: list[NativeBackup] = []
    for snap in snapshots:
        if snap.get("Status") != "available":
            continue
        if snap.get("OwnerAccount") and str(snap["OwnerAccount"]) != account_id:
            continue
        megabytes = snap.get("TotalBackupSizeInMegaBytes")
        found.append(
            NativeBackup(
                account_id=account_id,
                region=region,
                resource_arn=redshift_arn(region, account_id, snap.get("ClusterIdentifier", "")),
                source=(
                    "RedshiftAutomated"
                    if snap.get("SnapshotType") == "automated"
                    else "RedshiftManual"
                ),
                size_bytes=int(float(megabytes) * 1_000_000) if megabytes is not None else 0,
                creation_date=_iso(snap.get("SnapshotCreateTime")),
            )
        )
    return found


def backup_key(account_id: str, region: str, arn: str) -> str:
    return f"{account_id}|{region}|{arn}"


def _newer(candidate: Optional[str], current: str) -> bool:
    return bool(candidate) and (
        not current or datetime.fromisoformat(candidate) > datetime.fromisoformat(current)
    )


def merge_backups(
    backups: list[NativeBackup],
    recovery_points: Optional[list[RecoveryPointAggregate]] = None,
) -> dict[str, BackupSummary]:
    """Per resource: how many backups, which sources, and the latest one's date and size.

    AWS Backup recovery points come first (one entry per resource: its count, and its latest
    recovery point), then each native backup. The latest backup is the one with the newest
    creation date; its size is kept (never a sum). A backup without a date can only raise the
    size.
    """
    sources: dict[str, set[str]] = {}
    merged: dict[str, BackupSummary] = {}

    def state_for(account_id: str, region: str, arn: str) -> tuple[str, BackupSummary]:
        key = backup_key(account_id, region, arn)
        return key, merged.setdefault(key, BackupSummary())

    for entry in recovery_points or []:
        if not entry.resource_arn:
            continue
        key, state = state_for(entry.account_id, entry.region, entry.resource_arn)
        sources.setdefault(key, set()).add("AWSBackup")
        state.has_backups = True
        state.backup_count += entry.recovery_point_count
        if _newer(entry.latest_recovery_point_date, state.latest_backup_date):
            state.latest_backup_date = entry.latest_recovery_point_date or ""
            state.latest_backup_size_bytes = int(entry.latest_recovery_point_size_bytes or 0)

    for b in backups:
        if not b.resource_arn:
            continue
        key, state = state_for(b.account_id, b.region, b.resource_arn)
        sources.setdefault(key, set()).add(b.source)
        state.has_backups = True
        state.backup_count += 1
        size = int(b.size_bytes or 0)
        if _newer(b.creation_date, state.latest_backup_date):
            state.latest_backup_date = b.creation_date or ""
            state.latest_backup_size_bytes = size
        elif not b.creation_date and size > state.latest_backup_size_bytes:
            state.latest_backup_size_bytes = size
    for key, state in merged.items():
        state.backup_sources = ", ".join(sorted(sources[key], key=str.lower))
    return merged


def merge_native_backups(backups: list[NativeBackup]) -> dict[str, BackupSummary]:
    """``merge_backups`` for native backups alone."""
    return merge_backups(backups)


def recovery_point_keys(recovery_points: list[RecoveryPointAggregate]) -> frozenset[str]:
    """Keys of the resources that have at least one recovery point."""
    return frozenset(
        backup_key(a.account_id, a.region, a.resource_arn)
        for a in recovery_points
        if a.resource_arn
    )


def apply_backup_summaries(
    rows: list,
    merged: dict[str, BackupSummary],
    arn_of: Callable[[Any], str],
    recovery_keys: frozenset[str] = frozenset(),
    truncated_regions: frozenset[str] = frozenset(),
) -> None:
    """Set ``row.backup`` from the merged summaries.

    A row with recovery points gets ``has_recovery_points``; every row in a region whose
    recovery point listing hit the time limit gets ``backup_enumeration_truncated``, whether
    or not it has backups.
    """
    for row in rows:
        key = backup_key(row.account_id, row.region, arn_of(row))
        summary = merged.get(key)
        if summary is not None:
            row.backup = summary
        if key in recovery_keys:
            row.backup.has_recovery_points = True
        if row.region in truncated_regions:
            row.backup.backup_enumeration_truncated = True
