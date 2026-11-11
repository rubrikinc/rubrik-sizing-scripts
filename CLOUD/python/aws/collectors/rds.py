"""RDS instance collector."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from models.discovery import RDSInstance

from collectors import BOTO_ADAPTIVE_CFG, DenialTracker, is_scp_denial, record_metric_failures
from collectors.arns import rds_db_arn

# Cluster-based engines size their storage at the CLUSTER level (a shared, auto-scaling
# volume) — `describe_db_instances` reports `AllocatedStorage` for these as a meaningless
# placeholder (~1 GiB). The real consumed size is the CloudWatch `VolumeBytesUsed` metric
# on the cluster. Each engine family publishes it under its own namespace.
_CLUSTER_NAMESPACE = {
    "aurora": "AWS/RDS",
    "aurora-mysql": "AWS/RDS",
    "aurora-postgresql": "AWS/RDS",
}

# Rubrik does not support these engines; they are excluded from every RDS collection
# (instances here, snapshots when they are added), matching the PowerShell script.
UNSUPPORTED_RDS_ENGINES = frozenset({"docdb", "neptune"})


def is_unsupported_engine(engine: str) -> bool:
    return (engine or "").lower() in UNSUPPORTED_RDS_ENGINES


def _tags_to_dict(tag_list: list) -> dict[str, str]:
    return {t["Key"]: t["Value"] for t in (tag_list or [])}


def _cluster_namespace(engine: str) -> str | None:
    """CloudWatch namespace for a cluster engine's VolumeBytesUsed, or None if the
    engine isn't cluster-based (standard RDS sizes fine from AllocatedStorage)."""
    e = (engine or "").lower()
    if e in _CLUSTER_NAMESPACE:
        return _CLUSTER_NAMESPACE[e]
    if e.startswith("aurora"):  # future aurora-* variants
        return "AWS/RDS"
    return None


def _cluster_volume_gib(
    cw_client, cluster_id: str, namespace: str, errors: list[Exception] | None = None
) -> int:
    """Latest CloudWatch VolumeBytesUsed (→ GiB) for a DB cluster's shared volume.
    Returns 0 on any error or no data, so callers fall back to AllocatedStorage. Errors
    (as opposed to no data) are appended to ``errors``."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=48)
    try:
        resp = cw_client.get_metric_statistics(
            Namespace=namespace,
            MetricName="VolumeBytesUsed",
            Dimensions=[{"Name": "DBClusterIdentifier", "Value": cluster_id}],
            StartTime=start,
            EndTime=end,
            Period=86400,
            Statistics=["Average"],
        )
        datapoints = resp.get("Datapoints", [])
        if not datapoints:
            return 0
        latest = max(datapoints, key=lambda dp: dp["Timestamp"])
        return int(latest.get("Average", 0) / (1024**3))
    except Exception as exc:
        logging.debug("VolumeBytesUsed lookup failed for cluster %s: %s", cluster_id, exc)
        if errors is not None:
            errors.append(exc)
        return 0


def fetch_rds(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    protected_arns: set[str],
    tracker: "DenialTracker | None" = None,
) -> list[RDSInstance]:
    """Fetch all RDS DB instances in the region."""
    client = session.client("rds", region_name=region)
    cw_client = session.client("cloudwatch", region_name=region, config=BOTO_ADAPTIVE_CFG)
    instances: list[RDSInstance] = []
    metric_errors: list[Exception] = []

    # Cluster storage is shared across all members, so it must be counted ONCE per
    # cluster — not per instance. We look up each cluster's VolumeBytesUsed once and
    # assign the full size to the first member we see; later members of the same cluster
    # get 0 to avoid inflating the total.
    cluster_volume_gib: dict[str, int] = {}
    cluster_charged: set[str] = set()

    try:
        paginator = client.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if is_unsupported_engine(db.get("Engine") or ""):
                    continue
                db_id = db.get("DBInstanceIdentifier", "")
                db_arn = db.get("DBInstanceArn", rds_db_arn(region, account_id, db_id))
                backup_plans = ["AWS Backup"] if db_arn in protected_arns else []

                tags: dict[str, str] = {}
                try:
                    tag_resp = client.list_tags_for_resource(ResourceName=db_arn)
                    tags = _tags_to_dict(tag_resp.get("TagList", []))
                except Exception as exc:
                    logging.debug("Could not fetch tags for RDS instance %s: %s", db_id, exc)

                retention_days = int(db.get("BackupRetentionPeriod") or 0)
                native_backup_enabled = retention_days > 0

                engine = db.get("Engine") or ""
                allocated_gib = int(db.get("AllocatedStorage") or 0)
                cluster_id = db.get("DBClusterIdentifier") or ""
                namespace = _cluster_namespace(engine) if cluster_id else None

                if namespace:
                    # Cluster-based engine: size from the cluster's shared volume.
                    if cluster_id not in cluster_volume_gib:
                        cluster_volume_gib[cluster_id] = _cluster_volume_gib(
                            cw_client, cluster_id, namespace, metric_errors
                        )
                    vol = cluster_volume_gib[cluster_id]
                    if cluster_id in cluster_charged:
                        size_gib = 0  # cluster volume already counted on another member
                    else:
                        # First member carries the cluster volume (fall back to the
                        # AllocatedStorage placeholder only if CloudWatch had no data).
                        size_gib = vol or allocated_gib
                        cluster_charged.add(cluster_id)
                else:
                    size_gib = allocated_gib  # standard RDS — per-instance storage

                instances.append(
                    RDSInstance(
                        account_id=account_id,
                        account_alias=account_alias,
                        db_instance_identifier=db_id,
                        db_name=db.get("DBName") or "",
                        size_gib=size_gib,
                        size_tb=round(size_gib / 1024, 6),
                        size_bytes_derived=size_gib * 1024**3,
                        region=region,
                        engine=engine,
                        instance_class=db.get("DBInstanceClass") or "",
                        multi_az=bool(db.get("MultiAZ")),
                        storage_type=db.get("StorageType") or "",
                        native_backup_enabled=native_backup_enabled,
                        native_backup_retention_days=retention_days,
                        in_backup_plan=bool(backup_plans) or native_backup_enabled,
                        backup_plans=backup_plans,
                        tags=tags,
                        engine_version=db.get("EngineVersion") or "",
                        db_instance_status=db.get("DBInstanceStatus") or "",
                        preferred_backup_window=db.get("PreferredBackupWindow") or "",
                    )
                )
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("rds")
            logging.debug("Could not fetch RDS instances in %s (SCP denied)", region)
        else:
            if tracker is not None:
                tracker.record_permission_error("rds", region, exc)
            logging.warning("Could not fetch RDS instances in %s: %s", region, exc)

    record_metric_failures(tracker, region, "RDS cluster CloudWatch metrics", metric_errors)
    return instances
