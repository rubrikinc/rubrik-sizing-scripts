"""VPCs and load balancers (classic, application, network, gateway).

Port of ``Get-AWSVPCInventory`` and ``Get-AWSLoadBalancerInventory``. Tag keys keep hyphens
(the PowerShell regex here is ``[^a-zA-Z0-9-]``, unlike the other collectors); load balancers
leave the ``Name`` tag out.
"""

from __future__ import annotations

import logging
from typing import Any

from models.discovery import VPC, LoadBalancer

from collectors import DenialTracker, is_scp_denial, record_metric_failures
from collectors.arns import partition

log = logging.getLogger(__name__)

_BATCH = 20  # describe_tags accepts at most 20 load balancers per call


def _tags(items: list[dict] | None) -> dict[str, str]:
    return {t["Key"]: t.get("Value", "") for t in (items or [])}


def _record(tracker: "DenialTracker | None", region: str, what: str, exc: Exception) -> None:
    if is_scp_denial(exc):
        if tracker is not None:
            tracker.record("network")
        log.debug("%s in %s (SCP denied)", what, region)
    else:
        record_metric_failures(tracker, region, what, [exc], service="network")


def fetch_vpcs(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> list[VPC]:
    client = session.client("ec2", region_name=region)
    vpcs: list[VPC] = []
    try:
        for page in client.get_paginator("describe_vpcs").paginate():
            for v in page.get("Vpcs", []):
                vpcs.append(
                    VPC(
                        account_id=account_id,
                        account_alias=account_alias,
                        region=region,
                        vpc_id=v.get("VpcId", ""),
                        owner_id=v.get("OwnerId", ""),
                        cidr_block=v.get("CidrBlock", ""),
                        state=v.get("State", ""),
                        is_default=bool(v.get("IsDefault")),
                        tags=_tags(v.get("Tags")),
                    )
                )
    except Exception as exc:
        _record(tracker, region, "EC2 describe_vpcs", exc)
    return vpcs


def _batches(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _classic(
    client, region: str, account_id: str, account_alias: str, tracker
) -> list[LoadBalancer]:
    found: list[LoadBalancer] = []
    try:
        for page in client.get_paginator("describe_load_balancers").paginate():
            for lb in page.get("LoadBalancerDescriptions", []):
                name = lb.get("LoadBalancerName", "")
                found.append(
                    LoadBalancer(
                        account_id=account_id,
                        account_alias=account_alias,
                        region=region,
                        name=name,
                        type="classic",
                        scheme=lb.get("Scheme", ""),
                        vpc_id=lb.get("VPCId", ""),
                        dns_name=lb.get("DNSName", ""),
                        arn=(
                            f"arn:{partition(region)}:elasticloadbalancing:{region}:{account_id}"
                            f":loadbalancer/{name}"
                        ),
                    )
                )
    except Exception as exc:
        _record(tracker, region, "ELB describe_load_balancers", exc)
        return found
    by_name = {lb.name: lb for lb in found}
    for batch in _batches([lb.name for lb in found], _BATCH):
        try:
            for desc in client.describe_tags(LoadBalancerNames=batch).get("TagDescriptions", []):
                if desc.get("LoadBalancerName") in by_name:
                    by_name[desc["LoadBalancerName"]].tags = _tags(desc.get("Tags"))
        except Exception as exc:
            _record(tracker, region, "ELB describe_tags", exc)
    return found


def _v2(client, region: str, account_id: str, account_alias: str, tracker) -> list[LoadBalancer]:
    found: list[LoadBalancer] = []
    try:
        for page in client.get_paginator("describe_load_balancers").paginate():
            for lb in page.get("LoadBalancers", []):
                found.append(
                    LoadBalancer(
                        account_id=account_id,
                        account_alias=account_alias,
                        region=region,
                        name=lb.get("LoadBalancerName", ""),
                        type=lb.get("Type", ""),
                        scheme=lb.get("Scheme", ""),
                        vpc_id=lb.get("VpcId", ""),
                        dns_name=lb.get("DNSName", ""),
                        arn=lb.get("LoadBalancerArn", ""),
                    )
                )
    except Exception as exc:
        _record(tracker, region, "ELBv2 describe_load_balancers", exc)
        return found
    by_arn = {lb.arn: lb for lb in found}
    for batch in _batches([lb.arn for lb in found], _BATCH):
        try:
            for desc in client.describe_tags(ResourceArns=batch).get("TagDescriptions", []):
                if desc.get("ResourceArn") in by_arn:
                    by_arn[desc["ResourceArn"]].tags = _tags(desc.get("Tags"))
        except Exception as exc:
            _record(tracker, region, "ELBv2 describe_tags", exc)
    return found


def fetch_load_balancers(
    session,
    region: str,
    account_id: str,
    account_alias: str,
    tracker: "DenialTracker | None" = None,
) -> list[LoadBalancer]:
    """Classic load balancers first, then application, network and gateway ones."""
    classic = _classic(
        session.client("elb", region_name=region), region, account_id, account_alias, tracker
    )
    v2 = _v2(
        session.client("elbv2", region_name=region), region, account_id, account_alias, tracker
    )
    return classic + v2
