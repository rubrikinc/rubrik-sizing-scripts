"""Route53 hosted zones and IAM object counts: once per account, not per region.

Ports of ``Get-AWSRoute53Inventory`` and ``Get-AWSIAMInventory``.
"""

from __future__ import annotations

import logging
from typing import Optional

from models.discovery import IAMSummary, Route53Zone

from collectors import DenialTracker, is_scp_denial, record_metric_failures
from collectors.context import query_region

log = logging.getLogger(__name__)


def _record(tracker: "DenialTracker | None", service: str, what: str, exc: Exception) -> None:
    if is_scp_denial(exc):
        if tracker is not None:
            tracker.record(service)
        log.debug("%s (SCP denied)", what)
    else:
        record_metric_failures(tracker, "global", what, [exc], service=service)


def fetch_route53_zones(
    session, account_id: str, account_alias: str, tracker: "DenialTracker | None" = None
) -> list[Route53Zone]:
    client = session.client("route53", region_name=query_region())
    zones: list[Route53Zone] = []
    try:
        for page in client.get_paginator("list_hosted_zones").paginate():
            for z in page.get("HostedZones", []):
                zones.append(
                    Route53Zone(
                        account_id=account_id,
                        account_alias=account_alias,
                        hosted_zone_id=z.get("Id", ""),
                        name=z.get("Name", ""),
                        private_zone=bool((z.get("Config") or {}).get("PrivateZone")),
                        resource_record_set_count=int(z.get("ResourceRecordSetCount") or 0),
                    )
                )
    except Exception as exc:
        _record(tracker, "route53", "Route53 list_hosted_zones", exc)
    return zones


def _count(client, operation: str, key: str, what: str, tracker, **kwargs) -> Optional[int]:
    try:
        return sum(len(p.get(key, [])) for p in client.get_paginator(operation).paginate(**kwargs))
    except Exception as exc:
        _record(tracker, "iam", what, exc)
        return None


def fetch_iam_summary(
    session, account_id: str, account_alias: str, tracker: "DenialTracker | None" = None
) -> Optional[IAMSummary]:
    """User, role and customer-managed policy counts.

    ``None`` when all three calls fail, so "no access" is not mistaken for "empty account".
    A call that fails on its own counts as 0, as in PowerShell.
    """
    client = session.client("iam", region_name=query_region())
    users = _count(client, "list_users", "Users", "IAM list_users", tracker)
    roles = _count(client, "list_roles", "Roles", "IAM list_roles", tracker)
    policies = _count(
        client, "list_policies", "Policies", "IAM list_policies", tracker, Scope="Local"
    )
    if users is None and roles is None and policies is None:
        return None
    return IAMSummary(account_id, account_alias, users or 0, roles or 0, policies or 0)
