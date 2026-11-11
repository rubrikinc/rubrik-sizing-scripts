"""EKS clusters and node groups. Port of ``Get-AWSEKSInventory``."""

from __future__ import annotations

import logging

from models.discovery import EKSCluster, EKSNodeGroup

from collectors import DenialTracker, is_scp_denial, record_metric_failures

log = logging.getLogger(__name__)


def _record(tracker: "DenialTracker | None", region: str, what: str, exc: Exception) -> None:
    if is_scp_denial(exc):
        if tracker is not None:
            tracker.record("eks")
        log.debug("%s in %s (SCP denied)", what, region)
    else:
        record_metric_failures(tracker, region, what, [exc], service="eks")


def fetch_eks(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> tuple[list[EKSCluster], list[EKSNodeGroup]]:
    """Every cluster, and each cluster's node groups."""
    client = session.client("eks", region_name=region)
    clusters: list[EKSCluster] = []
    nodegroups: list[EKSNodeGroup] = []
    try:
        names = [
            n
            for page in client.get_paginator("list_clusters").paginate()
            for n in page.get("clusters", [])
        ]
    except Exception as exc:
        _record(tracker, region, "EKS list_clusters", exc)
        return clusters, nodegroups

    for name in names:
        try:
            c = client.describe_cluster(name=name)["cluster"]
        except Exception as exc:
            _record(tracker, region, "EKS describe_cluster", exc)
            continue
        clusters.append(
            EKSCluster(
                account_id=account_id,
                account_alias=account_alias,
                name=c.get("name", name),
                version=c.get("version", ""),
                platform_version=c.get("platformVersion", ""),
                status=c.get("status", ""),
                arn=c.get("arn", ""),
                role_arn=c.get("roleArn", ""),
                region=region,
                tags=dict(c.get("tags") or {}),
            )
        )
        try:
            group_names = [
                g
                for page in client.get_paginator("list_nodegroups").paginate(clusterName=name)
                for g in page.get("nodegroups", [])
            ]
        except Exception as exc:
            _record(tracker, region, "EKS list_nodegroups", exc)
            continue
        for group in group_names:
            try:
                g = client.describe_nodegroup(clusterName=name, nodegroupName=group)["nodegroup"]
            except Exception as exc:
                _record(tracker, region, "EKS describe_nodegroup", exc)
                continue
            nodegroups.append(
                EKSNodeGroup(
                    account_id=account_id,
                    account_alias=account_alias,
                    nodegroup_name=g.get("nodegroupName", group),
                    cluster_name=g.get("clusterName", name),
                    disk_size=g.get("diskSize"),
                    capacity_type=g.get("capacityType", ""),
                    ami_type=g.get("amiType", ""),
                    nodegroup_arn=g.get("nodegroupArn", ""),
                    node_role=g.get("nodeRole", ""),
                    status=g.get("status", ""),
                    release_version=g.get("releaseVersion", ""),
                    version=g.get("version", ""),
                    region=region,
                    tags=dict(g.get("tags") or {}),
                )
            )
    return clusters, nodegroups
