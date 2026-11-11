"""Redshift clusters. Port of ``Get-AWSRedshiftInventory``."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from models.discovery import RedshiftCluster

from collectors import DenialTracker, is_scp_denial, record_metric_failures

log = logging.getLogger(__name__)


def _iso(value) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def fetch_redshift(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> list[RedshiftCluster]:
    client = session.client("redshift", region_name=region)
    clusters: list[RedshiftCluster] = []
    try:
        for page in client.get_paginator("describe_clusters").paginate():
            for c in page.get("Clusters", []):
                clusters.append(
                    RedshiftCluster(
                        account_id=account_id,
                        account_alias=account_alias,
                        region=region,
                        cluster_identifier=c.get("ClusterIdentifier", ""),
                        node_type=c.get("NodeType", ""),
                        number_of_nodes=int(c.get("NumberOfNodes") or 0),
                        cluster_status=c.get("ClusterStatus", ""),
                        master_username=c.get("MasterUsername", ""),
                        db_name=c.get("DBName", ""),
                        cluster_create_time=_iso(c.get("ClusterCreateTime")),
                        automated_snapshot_retention_period=int(
                            c.get("AutomatedSnapshotRetentionPeriod") or 0
                        ),
                        manual_snapshot_retention_period=int(
                            c.get("ManualSnapshotRetentionPeriod") or 0
                        ),
                    )
                )
    except Exception as exc:
        if is_scp_denial(exc):
            if tracker is not None:
                tracker.record("redshift")
            log.debug("Redshift describe_clusters in %s (SCP denied)", region)
        else:
            record_metric_failures(
                tracker, region, "Redshift describe_clusters", [exc], service="redshift"
            )
    return clusters
