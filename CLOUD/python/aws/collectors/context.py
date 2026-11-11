"""Settings the collectors share: the partition and the region used for account-wide calls.

PowerShell calls ``-Partition GovCloud`` and ``-RegionToQuery``. The region is where account-wide
services (STS, IAM, Organizations, Route53, the region list) are called, and the partition
decides the ``arn:<partition>:`` prefix of role ARNs and whether Cost Explorer exists (it does not
in GovCloud; billing is read from the linked commercial account).
"""

from __future__ import annotations

from typing import Optional

DEFAULT_QUERY_REGIONS = {
    "aws": "us-east-1",
    "aws-us-gov": "us-gov-east-1",
    "aws-cn": "cn-north-1",
}

DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES = 60

_state = {
    "partition": "aws",
    "query_region": DEFAULT_QUERY_REGIONS["aws"],
    "recovery_point_timeout_minutes": DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES,
    "skip_bucket_tags": False,
}


def partition_of(region: str) -> str:
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def configure(
    govcloud: bool = False,
    region_to_query: Optional[str] = None,
    recovery_point_timeout_minutes: float = DEFAULT_RECOVERY_POINT_TIMEOUT_MINUTES,
    skip_bucket_tags: bool = False,
) -> None:
    """Choose the partition, the account-wide query region and two collection options.

    A query region names its own partition (``us-gov-west-1`` is GovCloud) even when
    ``govcloud`` is not set; PowerShell leaves the partition unset in that case.
    """
    if region_to_query:
        query_region = region_to_query
        partition = partition_of(region_to_query)
        if govcloud:
            partition = "aws-us-gov"
    else:
        partition = "aws-us-gov" if govcloud else "aws"
        query_region = DEFAULT_QUERY_REGIONS[partition]
    _state["partition"] = partition
    _state["query_region"] = query_region
    _state["recovery_point_timeout_minutes"] = recovery_point_timeout_minutes
    _state["skip_bucket_tags"] = skip_bucket_tags


def partition_id() -> str:
    return _state["partition"]


def query_region() -> str:
    return _state["query_region"]


def recovery_point_timeout_minutes() -> float:
    """Per-region time budget for listing AWS Backup recovery points."""
    return _state["recovery_point_timeout_minutes"]


def skip_bucket_tags() -> bool:
    return _state["skip_bucket_tags"]


def cost_explorer_available() -> bool:
    """Cost Explorer has no GovCloud (or China) endpoint."""
    return _state["partition"] == "aws"
